package kubepreflight

import (
	"context"
	"encoding/base64"
	"fmt"

	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func valid() []byte {
	return []byte(`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"app","namespace":"staging"},"spec":{"replicas":1,"selector":{"matchLabels":{"app":"app"}},"template":{"metadata":{"labels":{"app":"app"}},"spec":{"automountServiceAccountToken":false,"securityContext":{"runAsNonRoot":true,"seccompProfile":{"type":"RuntimeDefault"}},"containers":[{"name":"app","image":"registry.example/app@sha256:` + hash + `","securityContext":{"allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true,"capabilities":{"drop":["ALL"]}}}]}}}}`)
}
func TestDryRunWithVerifiedTLS(t *testing.T) {
	calls := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "POST" || r.URL.Path != "/apis/apps/v1/namespaces/staging/deployments" || r.URL.Query().Get("dryRun") != "All" || r.URL.Query().Get("fieldManager") != "trust-boundary" || r.Header.Get("Authorization") != "Bearer synthetic-token" {
			t.Errorf("unexpected request: %s", r.URL.String())
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"kind":"Deployment","apiVersion":"apps/v1","metadata":{"name":"app","namespace":"staging"}}`))
	}))
	defer srv.Close()
	f := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(f, []byte("synthetic-token"), 0600); err != nil {
		t.Fatal(err)
	}
	cert := srv.Certificate()
	certPem := pemCert(cert.Raw)
	cli, err := New(Config{ServerURL: srv.URL, CABundlePEM: certPem, BearerTokenFile: f})
	if err != nil {
		t.Fatal(err)
	}
	if err := cli.DryRunCreate(context.Background(), valid(), "staging", hash); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("expected one request, got %d", calls)
	}
	if err := cli.DryRunCreate(context.Background(), valid(), "production", hash); err == nil {
		t.Fatal("namespace mismatch accepted")
	}
	if calls != 1 {
		t.Fatal("invalid manifest reached server")
	}
}
func pemCert(der []byte) []byte { // standard PEM encoding for httptest server certificate
	return []byte("-----BEGIN CERTIFICATE-----\n" + chunk64(der) + "-----END CERTIFICATE-----\n")
}
func chunk64(b []byte) string {
	s := base64Encode(b)
	var out strings.Builder
	for len(s) > 64 {
		out.WriteString(s[:64])
		out.WriteByte('\n')
		s = s[64:]
	}
	out.WriteString(s)
	out.WriteByte('\n')
	return out.String()
}
func base64Encode(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
func TestRejectUnsafeConnections(t *testing.T) {
	for _, host := range []string{"http://localhost:8001", "https://user:secret@host", "https://host/other", "https://host?x=1"} {
		if _, err := New(Config{ServerURL: host, CABundlePEM: []byte("invalid"), BearerTokenFile: "x"}); err == nil {
			t.Fatalf("accepted %q", host)
		}
	}
}
func TestRejectErrorAndUnexpectedResponse(t *testing.T) {
	codes := []int{200, 401, 403, 409, 500}
	for _, status := range codes {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }))
			defer srv.Close()
			f := filepath.Join(t.TempDir(), "token")
			_ = os.WriteFile(f, []byte("test"), 0600)
			cli, err := New(Config{ServerURL: srv.URL, CABundlePEM: pemCert(srv.Certificate().Raw), BearerTokenFile: f})
			if err != nil {
				t.Fatal(err)
			}
			if err := cli.DryRunCreate(context.Background(), valid(), "staging", hash); err == nil {
				t.Fatal("accepted non-created response")
			}
		})
	}
}
func TestRejectDifferentTLSCertificate(t *testing.T) {
	trusted := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer trusted.Close()
	untrusted := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(201) }))
	defer untrusted.Close()
	f := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(f, []byte("test"), 0600)
	c, err := New(Config{ServerURL: untrusted.URL, CABundlePEM: pemCert(trusted.Certificate().Raw), BearerTokenFile: f})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.DryRunCreate(context.Background(), valid(), "staging", hash); err == nil {
		t.Fatal("untrusted TLS accepted")
	}
}
