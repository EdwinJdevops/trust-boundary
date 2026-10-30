package gate

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

var (
	digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
	namePattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,127}$`)
	noncePattern  = regexp.MustCompile(`^[a-f0-9]{32}$`)
)

// Intent has a fixed schema. Signatures cover the exact canonical JSON encoding of this struct.
type Intent struct {
	ArtifactSHA256 string `json:"artifact_sha256"`
	SourceSHA256   string `json:"source_sha256"`
	ManifestSHA256 string `json:"manifest_sha256,omitempty"`
	Workload       string `json:"workload"`
	Environment    string `json:"environment"`
	Operation      string `json:"operation"`
	Issuer         string `json:"issuer"`
	ExpiresAt      int64  `json:"expires_at"`
	Nonce          string `json:"nonce"`
}
type Envelope struct {
	Intent    Intent `json:"intent"`
	Signature string `json:"signature"`
}
type Policy struct {
	Issuer      string `json:"issuer"`
	Workload    string `json:"workload"`
	Environment string `json:"environment"`
	Operation   string `json:"operation"`
}
type Decision struct {
	IntentSHA256   string `json:"intent_sha256"`
	ArtifactSHA256 string `json:"artifact_sha256"`
	Operation      string `json:"operation"`
	Workload       string `json:"workload"`
	Environment    string `json:"environment"`
}

func canonical(i Intent) []byte { b, _ := json.Marshal(i); return b }
func Sign(i Intent, private ed25519.PrivateKey) (Envelope, error) {
	if err := validate(i); err != nil {
		return Envelope{}, err
	}
	if len(private) != ed25519.PrivateKeySize {
		return Envelope{}, errors.New("invalid signing key")
	}
	return Envelope{Intent: i, Signature: hex.EncodeToString(ed25519.Sign(private, canonical(i)))}, nil
}
func validate(i Intent) error {
	if !digestPattern.MatchString(i.ArtifactSHA256) || !digestPattern.MatchString(i.SourceSHA256) {
		return errors.New("invalid artifact or source digest")
	}
	for _, s := range []string{i.Workload, i.Environment, i.Operation, i.Issuer} {
		if !namePattern.MatchString(s) {
			return errors.New("invalid scope")
		}
	}
	if i.ManifestSHA256 != "" && !digestPattern.MatchString(i.ManifestSHA256) {
		return errors.New("invalid deployment manifest digest")
	}
	if !noncePattern.MatchString(i.Nonce) || i.ExpiresAt <= 0 {
		return errors.New("invalid nonce or expiry")
	}
	return nil
}

// Authorize checks a caller-supplied observed digest. The trusted executor MUST supply it, not the untrusted workload.
// Replay files make grants single use locally; this is not a distributed transaction or execution receipt.
func Authorize(env Envelope, public ed25519.PublicKey, policy Policy, observedDigest, replayDir string, now time.Time) (Decision, error) {
	i := env.Intent
	if err := validate(i); err != nil {
		return Decision{}, err
	}
	if len(public) != ed25519.PublicKeySize {
		return Decision{}, errors.New("invalid verification key")
	}
	sig, err := hex.DecodeString(env.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(public, canonical(i), sig) {
		return Decision{}, errors.New("signature denied")
	}
	t := now.Unix()
	if t >= i.ExpiresAt || i.ExpiresAt-t > 300 {
		return Decision{}, errors.New("authorization expired or excessive lifetime")
	}
	if observedDigest != i.ArtifactSHA256 {
		return Decision{}, errors.New("artifact mismatch")
	}
	if i.Issuer != policy.Issuer || i.Workload != policy.Workload || i.Environment != policy.Environment || i.Operation != policy.Operation {
		return Decision{}, errors.New("policy denied")
	}
	if replayDir == "" {
		return Decision{}, errors.New("missing replay directory")
	}
	// Directory must already exist; creating it automatically could silently weaken filesystem placement policy.
	d, err := os.Lstat(replayDir)
	if err != nil {
		return Decision{}, err
	}
	if !d.IsDir() || d.Mode()&os.ModeSymlink != 0 || d.Mode().Perm()&0077 != 0 {
		return Decision{}, errors.New("replay directory must be private")
	}
	filename := filepath.Join(replayDir, i.Nonce)
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		if os.IsExist(err) {
			return Decision{}, errors.New("replay denied")
		}
		return Decision{}, err
	}
	sum := sha256.Sum256(canonical(i))
	_, writeErr := fmt.Fprintln(f, hex.EncodeToString(sum[:]))
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return Decision{}, errors.New("replay record durability failed; deny and inspect")
	}
	dir, err := os.Open(replayDir)
	if err != nil {
		return Decision{}, err
	}
	syncErr = dir.Sync()
	closeErr = dir.Close()
	if syncErr != nil || closeErr != nil {
		return Decision{}, errors.New("replay directory durability failed; deny and inspect")
	}
	return Decision{IntentSHA256: hex.EncodeToString(sum[:]), ArtifactSHA256: i.ArtifactSHA256, Operation: i.Operation, Workload: i.Workload, Environment: i.Environment}, nil
}
