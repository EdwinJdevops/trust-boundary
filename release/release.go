// Package release binds a signed deployment intent to its exact manifest bytes.
// It is an offline policy gate, not a Kubernetes execution or attestation service.
package release

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"example.org/trust-boundary/deploycheck"
	"example.org/trust-boundary/gate"
	"time"
)

// CheckAndAuthorize verifies manifest bytes before consuming the single-use authorization.
// trustedImageDigest must be measured independently by a trusted executor.
func CheckAndAuthorize(envelope gate.Envelope, key ed25519.PublicKey, policy gate.Policy, manifest []byte, trustedImageDigest, replayDir string, now time.Time) (gate.Decision, error) {
	if envelope.Intent.ManifestSHA256 == "" {
		return gate.Decision{}, errors.New("signed manifest digest required")
	}
	digest := sha256.Sum256(manifest)
	if hex.EncodeToString(digest[:]) != envelope.Intent.ManifestSHA256 {
		return gate.Decision{}, errors.New("deployment manifest bytes differ from signed intent")
	}
	if err := deploycheck.Check(manifest, envelope.Intent.Environment, trustedImageDigest); err != nil {
		return gate.Decision{}, err
	}
	return gate.Authorize(envelope, key, policy, trustedImageDigest, replayDir, now)
}
