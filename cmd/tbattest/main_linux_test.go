package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/EdwinJdevops/trust-boundary/evidence"
	"github.com/EdwinJdevops/trust-boundary/internal/evidencefiles"
)

func TestIssueReviewedBundle(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	writeJSON := func(name string, v any) string {
		t.Helper()
		data, err := evidence.Canonical(v)
		if err != nil {
			t.Fatal(err)
		}
		return write(name, data)
	}
	source := write("source.tar", []byte("source fixture"))
	artifact := write("image.json", []byte("artifact fixture"))
	suite := write("suite.sha256", []byte("suite fixture"))
	write("environment.log", []byte("environment fixture"))
	now := time.Now()
	s := evidence.Statement{
		Version: 1, Commit: strings.Repeat("a", 40), SourceSHA256: evidence.Hash([]byte("source fixture")),
		ArtifactSHA256: evidence.Hash([]byte("artifact fixture")), SuiteSHA256: evidence.Hash([]byte("suite fixture")),
		EnvironmentSHA256: evidence.Hash([]byte("environment fixture")), GoVersion: "fixture", Platform: "linux/amd64",
		StartedAt: now.Add(-time.Minute).Unix(), FinishedAt: now.Unix(),
	}
	for _, name := range evidence.RequiredChecks() {
		write(name+".log", []byte(name))
		s.Checks = append(s.Checks, evidence.Check{Name: name, LogSHA256: evidence.Hash([]byte(name))})
	}
	statement := writeJSON("statement.json", s)
	p := evidencefiles.DiskPolicy{
		Commit: s.Commit, SourceSHA256: s.SourceSHA256, ArtifactSHA256: s.ArtifactSHA256,
		SuiteSHA256: s.SuiteSHA256, Keys: map[string]string{}, Minimum: 2, MaxAgeSeconds: 3600,
	}
	var keys []string
	ids := []string{"validator-one", "validator-two"}
	for _, id := range ids {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		p.Keys[id] = hex.EncodeToString(pub)
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, write(id+".der", der))
	}
	policy := writeJSON("policy.json", p)
	args := func(id, key string) []string {
		return []string{"--policy", policy, "--validator", id, "--key", key, "--statement", statement,
			"--source", source, "--artifact", artifact, "--suite", suite, "--logs", dir}
	}
	var quorum []evidence.Attestation
	for i, id := range ids {
		var out bytes.Buffer
		if err := run(args(id, keys[i]), &out); err != nil {
			t.Fatal(err)
		}
		var a evidence.Attestation
		if err := evidence.Decode(out.Bytes(), &a); err != nil {
			t.Fatal(err)
		}
		quorum = append(quorum, a)
	}
	trusted, err := evidencefiles.Policy(policy)
	if err != nil {
		t.Fatal(err)
	}
	if err = evidence.VerifyQuorum(quorum, trusted, time.Now()); err != nil {
		t.Fatal(err)
	}
	denied := func(key, want string) {
		t.Helper()
		var out bytes.Buffer
		if err := run(args(ids[0], key), &out); err == nil || !strings.Contains(err.Error(), want) || out.Len() != 0 {
			t.Fatalf("expected %q without attestation, got %v and %d output bytes", want, err, out.Len())
		}
	}
	denied(keys[1], "does not match")
	link := filepath.Join(dir, "link.der")
	if err := os.Symlink(keys[0], link); err != nil {
		t.Fatal(err)
	}
	denied(link, "cannot open")
	if err := os.Chmod(keys[0], 0644); err != nil {
		t.Fatal(err)
	}
	denied(keys[0], "private regular file")
	write("kubernetes.log", []byte("altered"))
	denied(keys[0], "log digest mismatch")
}
