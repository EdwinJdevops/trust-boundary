//go:build integration

package kubeexecutor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/EdwinJdevops/trust-boundary/artifact"
	"github.com/EdwinJdevops/trust-boundary/gate"
)

// This test requires a dedicated, disposable cluster and runs as the executor
// Unix UID. The signing key is a test fixture, not a production identity issuer.
func TestRealKubernetes(t *testing.T) {
	if os.Getenv("TB_REAL_CLUSTER") != "1" {
		t.Fatal("explicit disposable-cluster opt-in required")
	}
	ca, err := os.ReadFile(os.Getenv("TB_CA"))
	if err != nil {
		t.Fatal(err)
	}
	blob, err := os.ReadFile(os.Getenv("TB_ARTIFACT"))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := artifact.Measure(bytes.NewReader(blob), 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	doc := bytes.ReplaceAll(document(), []byte("registry.example/app@sha256:"+imageHash), []byte("registry.k8s.io/pause@sha256:"+digest))
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(doc)
	id := make([]byte, 16)
	if _, err = rand.Read(id); err != nil {
		t.Fatal(err)
	}
	env, err := gate.Sign(gate.Intent{ArtifactSHA256: digest, SourceSHA256: strings.Repeat("b", 64), ManifestSHA256: hex.EncodeToString(sum[:]), Workload: "worker", Environment: "staging", Operation: "deploy", Issuer: "ci", Nonce: hex.EncodeToString(id), ExpiresAt: time.Now().Add(2 * time.Minute).Unix()}, priv)
	if err != nil {
		t.Fatal(err)
	}
	c := Config{ServerURL: os.Getenv("TB_SERVER"), CA: ca, TokenFile: os.Getenv("TB_TOKEN"), JournalDir: os.Getenv("TB_JOURNAL"), Namespace: "staging", PublicKey: pub, Policy: gate.Policy{Issuer: "ci", Workload: "worker", Environment: "staging", Operation: "deploy"}}
	c = addValidationFixture(t, c, env.Intent.SourceSHA256, digest, time.Now())
	withoutEvidence := c
	withoutEvidence.Attestations = nil
	denied, err := New(withoutEvidence)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = denied.Execute(context.Background(), env, doc, digest); err == nil || !strings.Contains(err.Error(), "validator quorum missing") {
		t.Fatalf("expected missing-evidence denial, got %v", err)
	}
	t.Log("missing validator quorum denied before creation")
	e, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.Execute(context.Background(), env, append(append([]byte{}, doc...), ' '), digest); err == nil {
		t.Fatal("tampered manifest accepted")
	}
	o, err := e.Execute(context.Background(), env, doc, digest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.Execute(context.Background(), env, doc, digest); err == nil {
		t.Fatal("replay accepted")
	}
	restarted, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := restarted.Recover(context.Background(), env.Intent.Nonce)
	if err != nil || recovered.UID != o.UID {
		t.Fatalf("restart recovery failed: %+v %v", recovered, err)
	}
	t.Logf("real Deployment UID=%s resourceVersion=%s image=%s; replay denied; read-only restart recovery verified", o.UID, o.ResourceVersion, o.Image)
}
