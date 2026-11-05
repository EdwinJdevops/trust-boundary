package evidencefiles

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"time"

	"github.com/EdwinJdevops/trust-boundary/evidence"
)

type DiskPolicy struct {
	Commit         string            `json:"commit"`
	SourceSHA256   string            `json:"source_sha256"`
	ArtifactSHA256 string            `json:"artifact_sha256"`
	SuiteSHA256    string            `json:"suite_sha256"`
	Keys           map[string]string `json:"keys"`
	Minimum        int               `json:"minimum"`
	MaxAgeSeconds  int64             `json:"max_age_seconds"`
}

func Read(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("regular input file required")
	}
	b, err := io.ReadAll(io.LimitReader(f, evidence.MaxDocument+1))
	if err != nil {
		return nil, err
	}
	if len(b) > evidence.MaxDocument {
		return nil, errors.New("input too large")
	}
	return b, nil
}
func Statement(path string) (evidence.Statement, error) {
	var s evidence.Statement
	b, err := Read(path)
	if err != nil {
		return s, err
	}
	if err = evidence.Decode(b, &s); err != nil {
		return s, err
	}
	return s, s.Validate()
}
func sameFileHash(path, expected string) error {
	hash, err := evidence.HashFile(path, 128<<20)
	if err != nil {
		return err
	}
	if hash != expected {
		return errors.New("file differs from recorded digest")
	}
	return nil
}
func Policy(path string) (evidence.Policy, error) {
	b, err := Read(path)
	if err != nil {
		return evidence.Policy{}, err
	}
	var raw DiskPolicy
	// Policy must also use canonical JSON. It is installed independently,
	// never populated from values or keys supplied by an untrusted bundle.
	if err = evidence.Decode(b, &raw); err != nil {
		return evidence.Policy{}, err
	}
	p := evidence.Policy{Commit: raw.Commit, SourceSHA256: raw.SourceSHA256, ArtifactSHA256: raw.ArtifactSHA256, SuiteSHA256: raw.SuiteSHA256, Minimum: raw.Minimum, Keys: map[string]ed25519.PublicKey{}}
	if raw.MaxAgeSeconds < 1 || raw.MaxAgeSeconds > 86400 {
		return evidence.Policy{}, errors.New("invalid freshness policy")
	}
	p.MaxAge = time.Duration(raw.MaxAgeSeconds) * time.Second
	for id, s := range raw.Keys {
		key, err := hex.DecodeString(s)
		if err != nil {
			return evidence.Policy{}, err
		}
		p.Keys[id] = key
	}
	if err = p.Validate(); err != nil {
		return evidence.Policy{}, err
	}
	return p, nil
}
func CheckBundle(s evidence.Statement, source, artifact, suite, logs string) error {
	if err := evidence.CheckLogs(s, logs); err != nil {
		return err
	}
	for _, item := range [][2]string{{source, s.SourceSHA256}, {artifact, s.ArtifactSHA256}, {suite, s.SuiteSHA256}} {
		if err := sameFileHash(item[0], item[1]); err != nil {
			return err
		}
	}
	return nil
}
