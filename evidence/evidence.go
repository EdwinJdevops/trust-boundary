// Package evidence verifies experimental commit-bound validation attestations.
// A valid signature authenticates a configured validator's assertion; it does
// not prove that a runner was uncompromised or establish SLSA compliance.
package evidence

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

const domain = "trust-boundary-validation/v1\x00"
const MaxDocument = 1 << 20
const MaxLog = 32 << 20

var digest = regexp.MustCompile(`^[a-f0-9]{64}$`)
var commit = regexp.MustCompile(`^[a-f0-9]{40}$`)
var identity = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,127}$`)

// RequiredChecks returns a fresh copy so callers cannot weaken the suite globally.
func RequiredChecks() []string {
	return []string{"format", "build", "vet", "race", "integration-compile", "archive-integrity", "kubernetes"}
}

type Check struct {
	Name      string `json:"name"`
	ExitCode  int    `json:"exit_code"`
	LogSHA256 string `json:"log_sha256"`
}
type Statement struct {
	Version           int     `json:"version"`
	Commit            string  `json:"commit"`
	SourceSHA256      string  `json:"source_sha256"`
	ArtifactSHA256    string  `json:"artifact_sha256"`
	SuiteSHA256       string  `json:"suite_sha256"`
	EnvironmentSHA256 string  `json:"environment_sha256"`
	GoVersion         string  `json:"go_version"`
	Platform          string  `json:"platform"`
	StartedAt         int64   `json:"started_at"`
	FinishedAt        int64   `json:"finished_at"`
	Checks            []Check `json:"checks"`
}
type Attestation struct {
	SignerID  string    `json:"signer_id"`
	Statement Statement `json:"statement"`
	Signature string    `json:"signature"`
}

// Policy is installed independently of untrusted bundles. Public keys supplied
// inside a bundle are never trusted. Two IDs for the same key are not a quorum.
type Policy struct {
	Commit, SourceSHA256, ArtifactSHA256, SuiteSHA256 string
	Keys                                              map[string]ed25519.PublicKey
	Minimum                                           int
	MaxAge                                            time.Duration
}

func Hash(data []byte) string         { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func Canonical(v any) ([]byte, error) { return json.Marshal(v) }

// Decode requires the exact canonical encoding emitted by this package (plus
// optional outer whitespace). This rejects duplicates, case aliases, unknown
// fields, multiple documents and alternate interpretations of signed input.
func Decode(data []byte, out any) error {
	if len(data) > MaxDocument {
		return errors.New("evidence document too large")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return errors.New("trailing evidence data")
	}
	canonical, err := Canonical(out)
	if err != nil {
		return err
	}
	if !bytes.Equal(bytes.TrimSpace(data), canonical) {
		return errors.New("noncanonical or ambiguous evidence JSON")
	}
	return nil
}

func (s Statement) Validate() error {
	if s.Version != 1 || !commit.MatchString(s.Commit) || !digest.MatchString(s.SourceSHA256) || !digest.MatchString(s.ArtifactSHA256) || !digest.MatchString(s.SuiteSHA256) || !digest.MatchString(s.EnvironmentSHA256) {
		return errors.New("invalid evidence identity")
	}
	if s.Platform != "linux/amd64" || len(s.GoVersion) == 0 || len(s.GoVersion) > 128 {
		return errors.New("unsupported or missing toolchain/platform")
	}
	if s.StartedAt <= 0 || s.FinishedAt < s.StartedAt || s.FinishedAt-s.StartedAt > 3600 {
		return errors.New("invalid evidence execution interval")
	}
	required := RequiredChecks()
	if len(s.Checks) != len(required) {
		return errors.New("incomplete validation suite")
	}
	for i, name := range required {
		c := s.Checks[i]
		if c.Name != name || c.ExitCode != 0 || !digest.MatchString(c.LogSHA256) {
			return fmt.Errorf("validation check denied: %s", name)
		}
	}
	return nil
}

func message(id string, s Statement) []byte {
	b, _ := Canonical(s)
	return append([]byte(domain+id+"\x00"), b...)
}

// Sign is for a separately controlled validator after reviewing and rerunning
// the suite. The runner CLI never holds or generates a signing key.
func Sign(s Statement, id string, key ed25519.PrivateKey) (Attestation, error) {
	if err := s.Validate(); err != nil {
		return Attestation{}, err
	}
	if !identity.MatchString(id) || len(key) != ed25519.PrivateKeySize {
		return Attestation{}, errors.New("invalid validator identity or key")
	}
	return Attestation{SignerID: id, Statement: s, Signature: hex.EncodeToString(ed25519.Sign(key, message(id, s)))}, nil
}

func (p Policy) Validate() error {
	if !commit.MatchString(p.Commit) || !digest.MatchString(p.SourceSHA256) || !digest.MatchString(p.ArtifactSHA256) || !digest.MatchString(p.SuiteSHA256) {
		return errors.New("expected identities must be pinned outside evidence")
	}
	if p.Minimum < 2 || p.Minimum > 16 || p.MaxAge <= 0 || p.MaxAge > 24*time.Hour {
		return errors.New("at least two validators and bounded freshness required")
	}
	seen := map[string]bool{}
	for id, key := range p.Keys {
		if !identity.MatchString(id) || len(key) != ed25519.PublicKeySize {
			return errors.New("invalid configured validator")
		}
		fingerprint := Hash(key)
		if seen[fingerprint] {
			return errors.New("configured validator keys must be distinct")
		}
		seen[fingerprint] = true
	}
	if len(seen) < p.Minimum {
		return errors.New("not enough configured validator keys")
	}
	return nil
}

// CheckStatement checks the identity and freshness of an unsigned statement
// against an independently configured policy before it can be signed.
func (p Policy) CheckStatement(s Statement, now time.Time) error {
	if err := p.Validate(); err != nil {
		return err
	}
	return p.checkStatement(s, now)
}

func (p Policy) checkStatement(s Statement, now time.Time) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if s.Commit != p.Commit || s.SourceSHA256 != p.SourceSHA256 || s.ArtifactSHA256 != p.ArtifactSHA256 || s.SuiteSHA256 != p.SuiteSHA256 {
		return errors.New("evidence scope differs from trusted expectations")
	}
	if s.FinishedAt > now.Unix() || now.Sub(time.Unix(s.StartedAt, 0)) > p.MaxAge {
		return errors.New("stale or future evidence")
	}
	return nil
}

// VerifyQuorum fails closed if any supplied attestation is invalid. Distinct
// trusted keys are necessary, but operational independence is an enrollment
// requirement that cryptography alone cannot prove.
func VerifyQuorum(attestations []Attestation, p Policy, now time.Time) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if len(attestations) < p.Minimum || len(attestations) > 16 {
		return errors.New("validator quorum missing or oversized")
	}
	seen := map[string]bool{}
	for _, a := range attestations {
		if err := p.checkStatement(a.Statement, now); err != nil {
			return err
		}
		s := a.Statement
		key, ok := p.Keys[a.SignerID]
		if !ok {
			return errors.New("unknown validator")
		}
		fingerprint := Hash(key)
		if seen[fingerprint] {
			return errors.New("repeated validator cannot satisfy quorum")
		}
		sig, err := hex.DecodeString(a.Signature)
		if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(key, message(a.SignerID, s), sig) {
			return errors.New("validator signature denied")
		}
		seen[fingerprint] = true
	}
	return nil
}

// CheckLogs verifies bounded regular files at fixed names, not paths selected by
// an untrusted document. Parent directories must belong to trusted staging.
func CheckLogs(s Statement, dir string) error {
	if err := s.Validate(); err != nil {
		return err
	}
	environment, err := HashFile(filepath.Join(dir, "environment.log"), MaxLog)
	if err != nil {
		return err
	}
	if environment != s.EnvironmentSHA256 {
		return errors.New("environment metadata digest mismatch")
	}
	for _, c := range s.Checks {
		hash, err := HashFile(filepath.Join(dir, c.Name+".log"), MaxLog)
		if err != nil {
			return err
		}
		if hash != c.LogSHA256 {
			return fmt.Errorf("log digest mismatch: %s", c.Name)
		}
	}
	return nil
}
func HashFile(path string, limit int64) (string, error) {
	if limit <= 0 || limit > 128<<20 {
		return "", errors.New("invalid file bound")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return "", errors.New("bounded regular file required")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, limit+1))
	if err != nil {
		return "", err
	}
	if n > limit {
		return "", errors.New("file exceeds bound")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
