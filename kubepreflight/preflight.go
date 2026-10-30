// Package kubepreflight performs an authenticated, TLS-verified Kubernetes API
// server-side dry-run for a tightly restricted Deployment. It does not deploy.
package kubepreflight

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"example.org/trust-boundary/deploycheck"
)

type Config struct {
	ServerURL       string
	CABundlePEM     []byte
	BearerTokenFile string
}

type Client struct {
	endpoint  *url.URL
	http      *http.Client
	tokenFile string
}

func New(c Config) (*Client, error) {
	u, err := url.Parse(c.ServerURL)
	if err != nil || u == nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("Kubernetes API endpoint must be an HTTPS origin without credentials or path")
	}
	if len(c.CABundlePEM) == 0 || c.BearerTokenFile == "" {
		return nil, errors.New("explicit CA bundle and token file required")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(c.CABundlePEM) {
		return nil, errors.New("invalid Kubernetes CA")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, Proxy: nil, DisableKeepAlives: true}
	return &Client{endpoint: u, http: &http.Client{Timeout: 10 * time.Second, Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}, tokenFile: c.BearerTokenFile}, nil
}

// DryRunCreate asks Kubernetes admission to evaluate a creation without persisting it.
// Kubernetes RBAC and admission remain the authoritative policy decisions.
// No grant is consumed, and no actual cluster change is made by the request.
func (c *Client) DryRunCreate(ctx context.Context, document []byte, namespace, expectedImageDigest string) error {
	if err := deploycheck.Check(document, namespace, expectedImageDigest); err != nil {
		return fmt.Errorf("manifest denied: %w", err)
	}
	tokenBytes, err := os.ReadFile(c.tokenFile)
	if err != nil {
		return fmt.Errorf("reading service token: %w", err)
	}
	token := strings.TrimSpace(string(tokenBytes))
	if token == "" || strings.ContainsAny(token, "\r\n\t ") {
		return errors.New("invalid bearer token")
	}
	// Deployment check ensures namespace matches the document, but URLs still require escaping.
	requestURL := c.endpoint.String()
	requestURL = strings.TrimSuffix(requestURL, "/") + "/apis/apps/v1/namespaces/" + url.PathEscape(namespace) + "/deployments?dryRun=All&fieldManager=trust-boundary"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, bytes.NewReader(document))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("Kubernetes preflight unavailable: %w", err)
	}
	defer res.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(res.Body, 8193))
	if readErr != nil {
		return fmt.Errorf("Kubernetes response unreadable: %w", readErr)
	}
	if len(body) > 8192 {
		return errors.New("Kubernetes response exceeds preflight limit")
	}
	if res.StatusCode != http.StatusCreated {
		return fmt.Errorf("Kubernetes denied preflight (HTTP %d)", res.StatusCode)
	}
	var response struct {
		Kind       string `json:"kind"`
		APIVersion string `json:"apiVersion"`
		Metadata   struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return errors.New("invalid Kubernetes dry-run response")
	}
	var requested struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(document, &requested); err != nil {
		return err
	}
	if response.Kind != "Deployment" || response.APIVersion != "apps/v1" || response.Metadata.Namespace != namespace || response.Metadata.Name != requested.Metadata.Name {
		return errors.New("Kubernetes dry-run identity mismatch")
	}
	return nil
}
