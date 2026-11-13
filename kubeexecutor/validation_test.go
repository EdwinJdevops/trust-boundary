package kubeexecutor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/EdwinJdevops/trust-boundary/evidence"
)

func addValidationFixture(t *testing.T, c Config, source, artifact string, at time.Time) Config {
	t.Helper()
	digest := strings.Repeat("d", 64)
	s := evidence.Statement{
		Version: 1, Commit: strings.Repeat("e", 40), SourceSHA256: source,
		ArtifactSHA256: artifact, SuiteSHA256: digest, EnvironmentSHA256: digest,
		GoVersion: "test fixture", Platform: "linux/amd64", StartedAt: at.Add(-time.Second).Unix(), FinishedAt: at.Unix(),
	}
	for _, check := range evidence.RequiredChecks() {
		s.Checks = append(s.Checks, evidence.Check{Name: check, LogSHA256: digest})
	}
	c.ValidationPolicy = evidence.Policy{
		Commit: s.Commit, SourceSHA256: s.SourceSHA256, ArtifactSHA256: artifact,
		SuiteSHA256: s.SuiteSHA256, Keys: make(map[string]ed25519.PublicKey), Minimum: 2, MaxAge: time.Hour,
	}
	c.Attestations = nil
	for _, id := range []string{"validator-one", "validator-two"} {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		a, err := evidence.Sign(s, id, priv)
		if err != nil {
			t.Fatal(err)
		}
		c.ValidationPolicy.Keys[id] = pub
		c.Attestations = append(c.Attestations, a)
	}
	return c
}

func TestValidationDenialPrecedesJournalAndAPI(t *testing.T) {
	doc := document()
	env, pub := signed(t, doc)
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("denied validation reached the API")
		w.WriteHeader(http.StatusForbidden)
	}))
	defer s.Close()
	for label, change := range map[string]func(Config) Config{
		"missing":   func(c Config) Config { c.Attestations = nil; return c },
		"duplicate": func(c Config) Config { c.Attestations[1] = c.Attestations[0]; return c },
		"forged":    func(c Config) Config { c.Attestations[0].Signature = strings.Repeat("0", 128); return c },
		"stale":     func(c Config) Config { c.ValidationPolicy.MaxAge = time.Nanosecond; return c },
		"different source": func(c Config) Config {
			return addValidationFixture(t, c, strings.Repeat("c", 64), imageHash, time.Now())
		},
		"different artifact": func(c Config) Config {
			return addValidationFixture(t, c, env.Intent.SourceSHA256, strings.Repeat("f", 64), time.Now())
		},
	} {
		t.Run(label, func(t *testing.T) {
			c := change(config(t, s, pub))
			e, err := New(c)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = e.Execute(context.Background(), env, doc, imageHash); err == nil || !strings.Contains(err.Error(), "validation") {
				t.Fatalf("expected validation denial, got %v", err)
			}
			if _, err = os.Lstat(filepath.Join(c.JournalDir, env.Intent.Nonce)); !os.IsNotExist(err) {
				t.Fatalf("denied request consumed journal nonce: %v", err)
			}
		})
	}
}

func TestReleaseSignerCannotValidateItsOwnRelease(t *testing.T) {
	_, pub := signed(t, document())
	s := httptest.NewTLSServer(http.NotFoundHandler())
	defer s.Close()
	c := config(t, s, pub)
	c.ValidationPolicy.Keys["validator-one"] = pub
	if _, err := New(c); err == nil || !strings.Contains(err.Error(), "release signer") {
		t.Fatalf("expected shared-key rejection, got %v", err)
	}
}

func TestRestoreWithNewReleaseKeyRejectsPreRestoreGrant(t *testing.T) {
	doc := document()
	oldGrant, oldKey := signed(t, doc)
	newGrant, newKey := signedWithNonce(t, doc, strings.Repeat("d", 32))
	var posts atomic.Int32
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts.Add(1)
			w.WriteHeader(http.StatusCreated)
		}
		_, _ = w.Write(observed(doc))
	}))
	defer s.Close()
	c := config(t, s, oldKey)
	before, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = before.Execute(context.Background(), oldGrant, doc, imageHash); err != nil {
		t.Fatal(err)
	}
	// An earlier snapshot lacks the nonce written by the successful create.
	c.JournalDir = t.TempDir()
	if err := os.Chmod(c.JournalDir, 0700); err != nil {
		t.Fatal(err)
	}
	c.PublicKey = newKey
	after, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = after.Execute(context.Background(), oldGrant, doc, imageHash); err == nil || posts.Load() != 1 {
		t.Fatalf("old grant reached create after restore: posts=%d err=%v", posts.Load(), err)
	}
	if _, err = os.Stat(filepath.Join(c.JournalDir, oldGrant.Intent.Nonce)); !os.IsNotExist(err) {
		t.Fatalf("rejected grant touched restored journal: %v", err)
	}
	// Recovery against the restored journal has no record to reconcile.
	if _, err = after.Recover(context.Background(), oldGrant.Intent.Nonce); !os.IsNotExist(err) {
		t.Fatalf("expected missing record, got %v", err)
	}
	// Exercise fresh authorization on the TLS fixture after the cutover.
	if _, err = after.Execute(context.Background(), newGrant, doc, imageHash); err != nil || posts.Load() != 2 {
		t.Fatalf("fresh grant failed after cutover: posts=%d err=%v", posts.Load(), err)
	}
}

func TestValidatorReplacementRejectsRetiredSignature(t *testing.T) {
	doc := document()
	env, pub := signed(t, doc)
	var calls atomic.Int32
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
		}
		_, _ = w.Write(observed(doc))
	}))
	defer s.Close()
	c := config(t, s, pub)
	retired := c.Attestations[0]
	newPub, newPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c.ValidationPolicy.Keys[retired.SignerID] = newPub
	e, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Execute(context.Background(), env, doc, imageHash); err == nil || !strings.Contains(err.Error(), "validator signature denied") {
		t.Fatalf("expected retired signature denial, got %v", err)
	}
	if calls.Load() != 0 {
		t.Fatal("retired signature reached the API")
	}
	if _, err := os.Stat(filepath.Join(c.JournalDir, env.Intent.Nonce)); !os.IsNotExist(err) {
		t.Fatalf("retired signature consumed the nonce: %v", err)
	}
	replacement, err := evidence.Sign(retired.Statement, retired.SignerID, newPriv)
	if err != nil {
		t.Fatal(err)
	}
	c.Attestations[0] = replacement
	e, err = New(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Execute(context.Background(), env, doc, imageHash); err != nil {
		t.Fatalf("replacement quorum could not use the original grant: %v", err)
	}
}
