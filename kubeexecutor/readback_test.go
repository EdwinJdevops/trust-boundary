package kubeexecutor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/EdwinJdevops/trust-boundary/gate"
	"github.com/EdwinJdevops/trust-boundary/release"
)

func TestReadbackRejectsInjectedConfigurationAndReplacement(t *testing.T) {
	for _, attack := range []string{"environment", "uid", "post-environment"} {
		t.Run(attack, func(t *testing.T) {
			doc := document()
			env, pub := signed(t, doc)
			var posts atomic.Int32
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body := observed(doc)
				if r.Method == http.MethodPost {
					posts.Add(1)
					w.WriteHeader(201)
				}
				if r.Method != http.MethodPost || attack == "post-environment" {
					var object map[string]any
					_ = json.Unmarshal(body, &object)
					if attack == "uid" {
						object["metadata"].(map[string]any)["uid"] = "replacement"
					} else {
						pod := object["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
						pod["containers"].([]any)[0].(map[string]any)["env"] = []any{map[string]any{"name": "UNSIGNED", "value": "injected"}}
					}
					body, _ = json.Marshal(object)
				}
				_, _ = w.Write(body)
			}))
			defer s.Close()
			e, err := New(config(t, s, pub))
			if err != nil {
				t.Fatal(err)
			}
			if _, err = e.Execute(context.Background(), env, doc, imageHash); err == nil {
				t.Fatal("unsafe or replaced readback accepted")
			}
			if posts.Load() != 1 {
				t.Fatal("unexpected mutation count")
			}
		})
	}
}

func TestChangedJournalDeniedBeforeAPI(t *testing.T) {
	doc := document()
	env, pub := signed(t, doc)
	var calls atomic.Int32
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method == http.MethodPost {
			w.WriteHeader(201)
		}
		_, _ = w.Write(observed(doc))
	}))
	defer s.Close()
	c := config(t, s, pub)
	e, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.Execute(context.Background(), env, doc, imageHash); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(c.JournalDir, env.Intent.Nonce)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	baseline := calls.Load()
	attacks := map[string]func(*Record){
		"legacy unsigned record":    func(r *Record) { r.Version = 1; r.Envelope = gate.Envelope{} },
		"changed signature":         func(r *Record) { r.Envelope.Signature = strings.Repeat("0", 128) },
		"changed manifest":          func(r *Record) { r.Manifest = append(r.Manifest, ' ') },
		"nonce alias":               func(r *Record) { r.Envelope.Intent.Nonce = strings.Repeat("d", 32) },
		"changed decision":          func(r *Record) { r.Decision.IntentSHA256 = strings.Repeat("f", 64) },
		"changed resource name":     func(r *Record) { r.Name = "other" },
		"future authorization time": func(r *Record) { r.AuthorizedAt = time.Now().Add(time.Hour).Unix() },
	}
	for name, mutate := range attacks {
		t.Run(name, func(t *testing.T) {
			var r Record
			if err := json.Unmarshal(original, &r); err != nil {
				t.Fatal(err)
			}
			mutate(&r)
			b, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(path, b, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err = e.Recover(context.Background(), env.Intent.Nonce); err == nil {
				t.Fatal("altered journal accepted")
			}
			if calls.Load() != baseline {
				t.Fatal("altered journal reached API")
			}
		})
	}
	duplicate := append([]byte(`{"version":2,`), original[1:]...)
	if err = os.WriteFile(path, duplicate, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = e.Recover(context.Background(), env.Intent.Nonce); err == nil {
		t.Fatal("duplicate-key journal accepted")
	}
	if calls.Load() != baseline {
		t.Fatal("ambiguous journal reached API")
	}
}

func TestExpiredSignedRecordAllowsReadOnlyRecovery(t *testing.T) {
	doc := document()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	sum := sha256.Sum256(doc)
	env, err := gate.Sign(gate.Intent{ArtifactSHA256: imageHash, SourceSHA256: strings.Repeat("b", 64), ManifestSHA256: hex.EncodeToString(sum[:]), Issuer: "ci", Workload: "worker", Environment: "staging", Operation: "deploy", Nonce: strings.Repeat("c", 32), ExpiresAt: now.Add(-10 * time.Second).Unix()}, priv)
	if err != nil {
		t.Fatal(err)
	}
	var gets atomic.Int32
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Error("recovery attempted mutation")
			w.WriteHeader(403)
			return
		}
		gets.Add(1)
		_, _ = w.Write(observed(doc))
	}))
	defer s.Close()
	c := config(t, s, pub)
	admittedAt := now.Add(-20 * time.Second)
	c.Attestations = nil // A historical GET does not consume a deployment grant.
	decision, err := release.Verify(env, pub, c.Policy, doc, imageHash, admittedAt)
	if err != nil {
		t.Fatal(err)
	}
	r := Record{Version: 2, Envelope: env, AuthorizedAt: admittedAt.Unix(), Decision: decision, Manifest: doc, Name: "app"}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(c.JournalDir, env.Intent.Nonce), b, 0600); err != nil {
		t.Fatal(err)
	}
	e, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.Recover(context.Background(), env.Intent.Nonce); err != nil {
		t.Fatal(err)
	}
	if _, err = e.Execute(context.Background(), env, doc, imageHash); err == nil {
		t.Fatal("expired intent authorized a new mutation")
	}
	if gets.Load() != 1 {
		t.Fatal("unexpected API calls")
	}
}
