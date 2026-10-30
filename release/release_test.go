package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"example.org/trust-boundary/gate"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const imageHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func manifest() []byte {
	return []byte(`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"app","namespace":"staging"},"spec":{"replicas":1,"selector":{"matchLabels":{"app":"app"}},"template":{"metadata":{"labels":{"app":"app"}},"spec":{"automountServiceAccountToken":false,"securityContext":{"runAsNonRoot":true,"seccompProfile":{"type":"RuntimeDefault"}},"containers":[{"name":"app","image":"registry.example/app@sha256:` + imageHash + `","securityContext":{"allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true,"capabilities":{"drop":["ALL"]}}}]}}}}`)
}
func TestBoundRelease(t *testing.T) {
	doc := manifest()
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(doc)
	i := gate.Intent{ArtifactSHA256: imageHash, SourceSHA256: strings.Repeat("b", 64), ManifestSHA256: hex.EncodeToString(sum[:]), Workload: "worker", Environment: "staging", Operation: "deploy", Issuer: "ci", ExpiresAt: time.Now().Add(time.Minute).Unix(), Nonce: strings.Repeat("c", 32)}
	env, err := gate.Sign(i, private)
	if err != nil {
		t.Fatal(err)
	}
	policy := gate.Policy{Issuer: "ci", Workload: "worker", Environment: "staging", Operation: "deploy"}
	dir := filepath.Join(t.TempDir(), "replay")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	corrupt := append([]byte{}, doc...)
	corrupt = append(corrupt, ' ')
	if _, err := CheckAndAuthorize(env, pub, policy, corrupt, imageHash, dir, time.Now()); err == nil {
		t.Fatal("modified manifest accepted")
	}
	if _, err := CheckAndAuthorize(env, pub, policy, doc, strings.Repeat("f", 64), dir, time.Now()); err == nil {
		t.Fatal("untrusted image accepted")
	}
	if _, err := CheckAndAuthorize(env, pub, policy, doc, imageHash, dir, time.Now()); err != nil {
		t.Fatalf("valid release rejected: %v", err)
	}
	if _, err := CheckAndAuthorize(env, pub, policy, doc, imageHash, dir, time.Now()); err == nil {
		t.Fatal("replay accepted")
	}
	env.Intent.ManifestSHA256 = ""
	if _, err := CheckAndAuthorize(env, pub, policy, doc, imageHash, dir, time.Now()); err == nil {
		t.Fatal("unbound release accepted")
	}
}
