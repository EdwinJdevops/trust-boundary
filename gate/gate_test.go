package gate

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func fixture(t *testing.T) (Envelope, ed25519.PublicKey, Policy, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	i := Intent{ArtifactSHA256: strings.Repeat("a", 64), SourceSHA256: strings.Repeat("b", 64), Workload: "worker", Environment: "staging", Operation: "deploy", Issuer: "ci", ExpiresAt: time.Now().Unix() + 60, Nonce: strings.Repeat("c", 32)}
	e, err := Sign(i, priv)
	if err != nil {
		t.Fatal(err)
	}
	return e, pub, Policy{"ci", "worker", "staging", "deploy"}, i.ArtifactSHA256
}
func check(t *testing.T, e Envelope, pub ed25519.PublicKey, p Policy, digest string, shouldPass bool) {
	t.Helper()
	d := filepath.Join(t.TempDir(), "replay")
	if err := os.Mkdir(d, 0700); err != nil {
		t.Fatal(err)
	}
	_, err := Authorize(e, pub, p, digest, d, time.Now())
	if (err == nil) != shouldPass {
		t.Fatalf("want pass=%v, got %v", shouldPass, err)
	}
}
func TestAccepted(t *testing.T) { e, pub, p, d := fixture(t); check(t, e, pub, p, d, true) }
func TestWrongArtifact(t *testing.T) {
	e, pub, p, _ := fixture(t)
	check(t, e, pub, p, strings.Repeat("f", 64), false)
}
func TestPolicyDenied(t *testing.T) {
	e, pub, p, d := fixture(t)
	p.Environment = "production"
	check(t, e, pub, p, d, false)
}
func TestTamper(t *testing.T) {
	e, pub, p, d := fixture(t)
	e.Intent.Environment = "production"
	check(t, e, pub, p, d, false)
}
func TestExpired(t *testing.T) {
	e, pub, p, d := fixture(t)
	e.Intent.ExpiresAt = 1
	check(t, e, pub, p, d, false)
}
func TestWrongSignature(t *testing.T) {
	e, pub, p, d := fixture(t)
	e.Signature = hex.EncodeToString(make([]byte, 64))
	check(t, e, pub, p, d, false)
}
func TestReplay(t *testing.T) {
	e, pub, p, d := fixture(t)
	dir := filepath.Join(t.TempDir(), "replay")
	os.Mkdir(dir, 0700)
	if _, err := Authorize(e, pub, p, d, dir, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := Authorize(e, pub, p, d, dir, time.Now()); err == nil {
		t.Fatal("replay accepted")
	}
}
func TestConcurrentReplay(t *testing.T) {
	e, pub, p, d := fixture(t)
	dir := filepath.Join(t.TempDir(), "replay")
	os.Mkdir(dir, 0700)
	var successes atomic.Int64
	var wg sync.WaitGroup
	for k := 0; k < 24; k++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := Authorize(e, pub, p, d, dir, time.Now()); err == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("granted %d times", successes.Load())
	}
}
func TestInsecureDir(t *testing.T) {
	e, pub, p, d := fixture(t)
	dir := filepath.Join(t.TempDir(), "replay")
	os.Mkdir(dir, 0777)
	os.Chmod(dir, 0777)
	if _, err := Authorize(e, pub, p, d, dir, time.Now()); err == nil {
		t.Fatal("insecure directory accepted")
	}
}
func TestFutureGrant(t *testing.T) {
	e, pub, p, d := fixture(t)
	e.Intent.ExpiresAt = time.Now().Unix() + 900
	check(t, e, pub, p, d, false)
}
func TestInvalidNonce(t *testing.T) {
	e, pub, p, d := fixture(t)
	e.Intent.Nonce = "../escape"
	check(t, e, pub, p, d, false)
}
