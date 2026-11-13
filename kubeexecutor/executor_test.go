package kubeexecutor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/EdwinJdevops/trust-boundary/gate"
)

const imageHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func document() []byte {
	return []byte(`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"app","namespace":"staging"},"spec":{"replicas":1,"selector":{"matchLabels":{"app":"app"}},"template":{"metadata":{"labels":{"app":"app"}},"spec":{"automountServiceAccountToken":false,"securityContext":{"runAsNonRoot":true,"seccompProfile":{"type":"RuntimeDefault"}},"containers":[{"name":"app","image":"registry.example/app@sha256:` + imageHash + `","securityContext":{"allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true,"capabilities":{"drop":["ALL"]}}}]}}}}`)
}
func signed(t *testing.T, doc []byte) (gate.Envelope, ed25519.PublicKey) {
	t.Helper()
	return signedWithNonce(t, doc, strings.Repeat("c", 32))
}

func signedWithNonce(t *testing.T, doc []byte, nonce string) (gate.Envelope, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(doc)
	e, err := gate.Sign(gate.Intent{ArtifactSHA256: imageHash, SourceSHA256: strings.Repeat("b", 64), ManifestSHA256: hex.EncodeToString(hash[:]), Workload: "worker", Environment: "staging", Operation: "deploy", Issuer: "ci", Nonce: nonce, ExpiresAt: time.Now().Add(time.Minute).Unix()}, priv)
	if err != nil {
		t.Fatal(err)
	}
	return e, pub
}
func config(t *testing.T, s *httptest.Server, pub ed25519.PublicKey) Config {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("Linux durability contract")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(dir, "credential")
	if err := os.WriteFile(token, []byte("synthetic-token"), 0600); err != nil {
		t.Fatal(err)
	}
	c := Config{ServerURL: s.URL, TokenFile: token, Namespace: "staging", JournalDir: dir, CA: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}), PublicKey: pub, Policy: gate.Policy{Issuer: "ci", Workload: "worker", Environment: "staging", Operation: "deploy"}}
	return addValidationFixture(t, c, strings.Repeat("b", 64), imageHash, time.Now())
}
func observed(doc []byte) []byte {
	var v map[string]any
	_ = json.Unmarshal(doc, &v)
	m := v["metadata"].(map[string]any)
	m["uid"] = "uid-1"
	m["resourceVersion"] = "42"
	b, _ := json.Marshal(v)
	return b
}

func TestExecuteReplayAndRestartRecovery(t *testing.T) {
	doc := document()
	env, pub := signed(t, doc)
	var posts atomic.Int32
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer synthetic-token" {
			t.Error("missing token")
		}
		if r.Method == "POST" {
			posts.Add(1)
			if r.URL.Query().Get("dryRun") != "" {
				t.Error("not a real create")
			}
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
	var wg sync.WaitGroup
	var successes atomic.Int32
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := e.Execute(context.Background(), env, doc, imageHash); err == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if posts.Load() != 1 || successes.Load() != 1 {
		t.Fatalf("posts=%d successes=%d", posts.Load(), successes.Load())
	}
	restarted, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	o, err := restarted.Recover(context.Background(), env.Intent.Nonce)
	if err != nil || o.UID != "uid-1" {
		t.Fatalf("recovery: %+v %v", o, err)
	}
	if posts.Load() != 1 {
		t.Fatal("recovery mutated cluster")
	}
}

func TestUncertainOutcomeNeverPostsAgain(t *testing.T) {
	for _, status := range []int{201, 409, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			doc := document()
			env, pub := signed(t, doc)
			var posts atomic.Int32
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "POST" {
					posts.Add(1)
					w.WriteHeader(status)
					return
				}
				_, _ = w.Write(observed(doc))
			}))
			defer s.Close()
			e, err := New(config(t, s, pub))
			if err != nil {
				t.Fatal(err)
			}
			_, _ = e.Execute(context.Background(), env, doc, imageHash)
			if _, err = e.Execute(context.Background(), env, doc, imageHash); err == nil {
				t.Fatal("replay accepted")
			}
			if _, err = e.Recover(context.Background(), env.Intent.Nonce); err != nil {
				t.Fatal(err)
			}
			if posts.Load() != 1 {
				t.Fatal("uncertain request repeated")
			}
		})
	}
}

func TestAdversarialInputsNeverReachAPI(t *testing.T) {
	doc := document()
	env, pub := signed(t, doc)
	var calls atomic.Int32
	s := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer s.Close()
	e, err := New(config(t, s, pub))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.Execute(context.Background(), env, append(doc, ' '), imageHash); err == nil {
		t.Fatal("changed manifest accepted")
	}
	if _, err = e.Execute(context.Background(), env, doc, strings.Repeat("f", 64)); err == nil {
		t.Fatal("wrong artifact accepted")
	}
	env.Signature = strings.Repeat("0", 128)
	if _, err = e.Execute(context.Background(), env, doc, imageHash); err == nil {
		t.Fatal("bad signature accepted")
	}
	if _, err = e.Recover(context.Background(), "../escape"); err == nil {
		t.Fatal("path traversal accepted")
	}
	if calls.Load() != 0 {
		t.Fatal("denied input reached API")
	}
}

func TestIncompleteJournalFailsClosed(t *testing.T) {
	doc := document()
	env, pub := signed(t, doc)
	var calls atomic.Int32
	s := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer s.Close()
	c := config(t, s, pub)
	if err := os.WriteFile(filepath.Join(c.JournalDir, env.Intent.Nonce), []byte(`{"decision":`), 0600); err != nil {
		t.Fatal(err)
	}
	e, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.Execute(context.Background(), env, doc, imageHash); err == nil {
		t.Fatal("partial record reused")
	}
	if _, err = e.Recover(context.Background(), env.Intent.Nonce); err == nil {
		t.Fatal("partial record recovered")
	}
	if calls.Load() != 0 {
		t.Fatal("partial record reached API")
	}
}

func TestLostAcknowledgementAndReadOnlyRecovery(t *testing.T) {
	doc := document()
	env, pub := signed(t, doc)
	var posts atomic.Int32
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			posts.Add(1)
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = conn.Close()
			return
		}
		_, _ = w.Write(observed(doc))
	}))
	defer s.Close()
	c := config(t, s, pub)
	e, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.Execute(context.Background(), env, doc, imageHash); err == nil {
		t.Fatal("lost response reported as successful create")
	}
	restarted, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = restarted.Recover(context.Background(), env.Intent.Nonce); err != nil {
		t.Fatal(err)
	}
	if _, err = restarted.Execute(context.Background(), env, doc, imageHash); err == nil {
		t.Fatal("lost acknowledgement allowed replay")
	}
	if posts.Load() != 1 {
		t.Fatalf("POST count %d", posts.Load())
	}
}
