package evidence

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func fixture(t *testing.T) (Statement, Policy, []Attestation, time.Time) {
	t.Helper()
	now := time.Unix(1800000000, 0)
	s := Statement{Version: 1, Commit: strings.Repeat("a", 40), SourceSHA256: strings.Repeat("b", 64), ArtifactSHA256: strings.Repeat("c", 64), SuiteSHA256: strings.Repeat("d", 64), EnvironmentSHA256: Hash([]byte("environment")), GoVersion: "go1.26.8", Platform: "linux/amd64", StartedAt: now.Add(-time.Minute).Unix(), FinishedAt: now.Add(-time.Second).Unix()}
	for _, name := range RequiredChecks() {
		s.Checks = append(s.Checks, Check{Name: name, LogSHA256: Hash([]byte(name))})
	}
	p := Policy{Commit: s.Commit, SourceSHA256: s.SourceSHA256, ArtifactSHA256: s.ArtifactSHA256, SuiteSHA256: s.SuiteSHA256, Keys: map[string]ed25519.PublicKey{}, Minimum: 2, MaxAge: time.Hour}
	var a []Attestation
	for _, id := range []string{"validator-a", "validator-b"} {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		p.Keys[id] = pub
		signed, err := Sign(s, id, priv)
		if err != nil {
			t.Fatal(err)
		}
		a = append(a, signed)
	}
	return s, p, a, now
}
func TestQuorumAndAdversarialInputs(t *testing.T) {
	_, p, a, now := fixture(t)
	if err := VerifyQuorum(a, p, now); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func([]Attestation){
		"changed commit":       func(a []Attestation) { a[0].Statement.Commit = strings.Repeat("e", 40) },
		"changed source":       func(a []Attestation) { a[0].Statement.SourceSHA256 = strings.Repeat("e", 64) },
		"changed artifact":     func(a []Attestation) { a[0].Statement.ArtifactSHA256 = strings.Repeat("e", 64) },
		"changed suite":        func(a []Attestation) { a[0].Statement.SuiteSHA256 = strings.Repeat("e", 64) },
		"unknown validator":    func(a []Attestation) { a[0].SignerID = "attacker" },
		"same validator twice": func(a []Attestation) { a[1] = a[0] },
		"invalid signature":    func(a []Attestation) { a[0].Signature = strings.Repeat("0", 128) },
		"failed check":         func(a []Attestation) { a[0].Statement.Checks[0].ExitCode = 1 },
		"missing check":        func(a []Attestation) { a[0].Statement.Checks = a[0].Statement.Checks[:6] },
		"duplicate check":      func(a []Attestation) { a[0].Statement.Checks[1] = a[0].Statement.Checks[0] },
		"altered log":          func(a []Attestation) { a[0].Statement.Checks[0].LogSHA256 = strings.Repeat("e", 64) },
		"future evidence":      func(a []Attestation) { a[0].Statement.FinishedAt = now.Add(time.Minute).Unix() },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			b, _ := json.Marshal(a)
			var copy []Attestation
			_ = json.Unmarshal(b, &copy)
			mutate(copy)
			if err := VerifyQuorum(copy, p, now); err == nil {
				t.Fatal("accepted adversarial evidence")
			}
		})
	}
	if err := VerifyQuorum(a[:1], p, now); err == nil {
		t.Fatal("single validator accepted")
	}
	if err := VerifyQuorum(a, p, now.Add(2*time.Hour)); err == nil {
		t.Fatal("stale evidence accepted")
	}
}
func TestSameKeyCannotPretendToBeIndependent(t *testing.T) {
	_, p, a, now := fixture(t)
	p.Keys["validator-b"] = p.Keys["validator-a"]
	if err := VerifyQuorum(a, p, now); err == nil {
		t.Fatal("key aliases accepted")
	}
	p.Minimum = 1
	if err := p.Validate(); err == nil {
		t.Fatal("one-signer policy accepted")
	}
}
func TestCanonicalParserRejectsAmbiguity(t *testing.T) {
	s, _, _, _ := fixture(t)
	b, _ := Canonical(s)
	var parsed Statement
	if err := Decode(b, &parsed); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{append(append([]byte{}, b...), b...), append([]byte(`{"version":1,`), b[1:]...), bytes.Replace(b, []byte(`"commit"`), []byte(`"Commit"`), 1), append([]byte(`{"unknown":1,`), b[1:]...), []byte(strings.Repeat(" ", MaxDocument+1))} {
		if err := Decode(bad, &parsed); err == nil {
			t.Fatal("ambiguous evidence accepted")
		}
	}
}
func TestLogTamperingAndSymlinks(t *testing.T) {
	s, _, _, _ := fixture(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "environment.log"), []byte("environment"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, c := range s.Checks {
		if err := os.WriteFile(filepath.Join(dir, c.Name+".log"), []byte(c.Name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := CheckLogs(s, dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "race.log"), []byte("modified"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := CheckLogs(s, dir); err == nil {
		t.Fatal("tampered log accepted")
	}
	path := filepath.Join(dir, "link")
	if os.Symlink(filepath.Join(dir, "race.log"), path) == nil {
		if _, err := HashFile(path, MaxLog); err == nil {
			t.Fatal("symlink accepted")
		}
	}
}
func TestNoDomainOrIdentitySubstitution(t *testing.T) {
	s, _, _, _ := fixture(t)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Canonical(s)
	a, err := Sign(s, "validator-b", priv)
	if err != nil {
		t.Fatal(err)
	}
	a.SignerID = "validator-a"
	if ed25519.Verify(pub, message(a.SignerID, s), mustHex(t, a.Signature)) {
		t.Fatal("identity substitution verified")
	}
	sig := ed25519.Sign(priv, b)
	if ed25519.Verify(pub, message("validator-a", s), sig) {
		t.Fatal("cross-protocol signature verified")
	}
}
