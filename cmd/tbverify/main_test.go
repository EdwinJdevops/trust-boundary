package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/EdwinJdevops/trust-boundary/evidence"
	"github.com/EdwinJdevops/trust-boundary/internal/evidencefiles"
)

func TestRecordInspectAndTamper(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	source := write("source.tar", "source")
	artifact := write("artifact", "artifact")
	suite := write("suite.sha256", "suite")
	write("environment.log", "environment")
	args := []string{"record", "--commit", strings.Repeat("a", 40), "--source", source, "--artifact", artifact, "--suite", suite, "--logs", dir, "--go-version", "go1.26.8", "--started-at", "1800000000", "--finished-at", "1800000001"}
	for _, name := range evidence.RequiredChecks() {
		write(name+".log", name)
		args = append(args, "--check", name+"=0")
	}
	var out bytes.Buffer
	if err := run(args, &out); err != nil {
		t.Fatal(err)
	}
	p := write("statement.json", out.String())
	out.Reset()
	inspect := []string{"inspect", "--statement", p, "--logs", dir, "--source", source, "--artifact", artifact, "--suite", suite}
	if err := run(inspect, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"authentication":"not-verified"`) {
		t.Fatal("unsigned integrity confused with authentication")
	}
	write("artifact", "changed")
	if err := run(inspect, &out); err == nil {
		t.Fatal("artifact substitution accepted")
	}
	args[len(args)-1] = "kubernetes=1"
	if err := run(args, &out); err == nil {
		t.Fatal("failed check produced success statement")
	}
}
func TestVerifyRequiresExternalDistinctKeys(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	s := evidence.Statement{Version: 1, Commit: strings.Repeat("a", 40), SourceSHA256: strings.Repeat("b", 64), ArtifactSHA256: strings.Repeat("c", 64), SuiteSHA256: strings.Repeat("d", 64), EnvironmentSHA256: strings.Repeat("e", 64), GoVersion: "test-fixture", Platform: "linux/amd64", StartedAt: now.Add(-time.Minute).Unix(), FinishedAt: now.Add(-time.Second).Unix()}
	for _, name := range evidence.RequiredChecks() {
		s.Checks = append(s.Checks, evidence.Check{Name: name, LogSHA256: evidence.Hash([]byte(name))})
	}
	p := evidencefiles.DiskPolicy{Commit: s.Commit, SourceSHA256: s.SourceSHA256, ArtifactSHA256: s.ArtifactSHA256, SuiteSHA256: s.SuiteSHA256, Minimum: 2, MaxAgeSeconds: 3600, Keys: map[string]string{}}
	args := []string{"verify", "--policy", filepath.Join(dir, "policy.json")}
	var paths []string
	for i, id := range []string{"independent-a", "independent-b"} {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		p.Keys[id] = hex.EncodeToString(pub)
		a, err := evidence.Sign(s, id, priv)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := evidence.Canonical(a)
		path := filepath.Join(dir, strconv.Itoa(i)+".json")
		if err = os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
		args = append(args, "--attestation", path)
	}
	writePolicy := func() {
		b, _ := evidence.Canonical(p)
		if err := os.WriteFile(filepath.Join(dir, "policy.json"), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writePolicy()
	var out bytes.Buffer
	if err := run(args, &out); err != nil {
		t.Fatal(err)
	}
	if err := run(args[:len(args)-2], &out); err == nil {
		t.Fatal("single signer accepted")
	}
	p.Keys["independent-b"] = p.Keys["independent-a"]
	writePolicy()
	if err := run(args, &out); err == nil {
		t.Fatal("aliased trusted keys accepted")
	}
}
