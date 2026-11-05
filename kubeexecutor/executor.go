// Package kubeexecutor is an experimental, create-only protected executor.
// Its caller must run under an independently protected OS identity. Never expose
// its token, journal directory or in-process API to untrusted tooling.
package kubeexecutor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/EdwinJdevops/trust-boundary/deploycheck"
	"github.com/EdwinJdevops/trust-boundary/evidence"
	"github.com/EdwinJdevops/trust-boundary/gate"
	"github.com/EdwinJdevops/trust-boundary/release"
)

type Config struct {
	ServerURL, TokenFile, Namespace, JournalDir string
	CA                                          []byte
	PublicKey                                   ed25519.PublicKey
	Policy                                      gate.Policy
	// ValidationPolicy pins the approved release and validator keys. Only the
	// trusted operator may supply this policy.
	ValidationPolicy evidence.Policy
	Attestations     []evidence.Attestation
}
type Executor struct {
	config Config
	http   *http.Client
	origin string
}
type Record struct {
	Version      int           `json:"version"`
	Envelope     gate.Envelope `json:"envelope"`
	AuthorizedAt int64         `json:"authorized_at"`
	Decision     gate.Decision `json:"decision"`
	Manifest     []byte        `json:"manifest"`
	Name         string        `json:"name"`
}
type Observation struct{ UID, ResourceVersion, Image string }

var name = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
var nonce = regexp.MustCompile(`^[a-f0-9]{32}$`)

func New(c Config) (*Executor, error) {
	u, err := url.Parse(c.ServerURL)
	if err != nil || u == nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("explicit HTTPS API origin required")
	}
	if !name.MatchString(c.Namespace) || c.Policy.Environment != c.Namespace || c.Policy.Operation != "deploy" || len(c.PublicKey) != ed25519.PublicKeySize || c.TokenFile == "" {
		return nil, errors.New("invalid executor scope or key")
	}
	if runtime.GOOS != "linux" {
		return nil, errors.New("executor requires Linux filesystem permissions and directory sync")
	}
	d, err := os.Lstat(c.JournalDir)
	if err != nil || !d.IsDir() || d.Mode().Perm()&0077 != 0 {
		return nil, errors.New("pre-existing private journal directory required")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(c.CA) {
		return nil, errors.New("explicit API CA required")
	}
	c.PublicKey = append(ed25519.PublicKey(nil), c.PublicKey...)
	if err := c.ValidationPolicy.Validate(); err != nil {
		return nil, fmt.Errorf("invalid validation policy: %w", err)
	}
	keys := make(map[string]ed25519.PublicKey, len(c.ValidationPolicy.Keys))
	for id, key := range c.ValidationPolicy.Keys {
		if bytes.Equal(key, c.PublicKey) {
			return nil, errors.New("release signer cannot be a validator")
		}
		keys[id] = append(ed25519.PublicKey(nil), key...)
	}
	c.ValidationPolicy.Keys = keys
	if len(c.Attestations) > 16 {
		return nil, errors.New("too many validation attestations")
	}
	c.Attestations = append([]evidence.Attestation(nil), c.Attestations...)
	for i := range c.Attestations {
		s := &c.Attestations[i].Statement
		if err := s.Validate(); err != nil {
			return nil, fmt.Errorf("invalid validation statement: %w", err)
		}
		s.Checks = append([]evidence.Check(nil), s.Checks...)
	}
	return &Executor{config: c, origin: strings.TrimSuffix(c.ServerURL, "/"), http: &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

// Execute verifies an exact signed manifest, then durably records both grant
// consumption and request in one exclusive file before a single POST. Any error
// after the record is created is uncertain: never delete the record or retry POST.
// trustedDigest must come from an independent trusted artifact measurement.
func (e *Executor) Execute(ctx context.Context, env gate.Envelope, manifest []byte, trustedDigest string) (Observation, error) {
	manifest = append([]byte(nil), manifest...)
	authorizedAt := time.Now()
	decision, err := release.Verify(env, e.config.PublicKey, e.config.Policy, manifest, trustedDigest, authorizedAt)
	if err != nil {
		return Observation{}, err
	}
	p := e.config.ValidationPolicy
	if p.SourceSHA256 != env.Intent.SourceSHA256 || p.ArtifactSHA256 != trustedDigest {
		return Observation{}, errors.New("release differs from validation policy")
	}
	if err = evidence.VerifyQuorum(e.config.Attestations, p, authorizedAt); err != nil {
		return Observation{}, fmt.Errorf("deployment validation denied: %w", err)
	}
	var d deploycheck.Deployment
	if err = json.Unmarshal(manifest, &d); err != nil {
		return Observation{}, err
	}
	if !name.MatchString(d.Metadata.Name) {
		return Observation{}, errors.New("invalid Deployment name")
	}
	r := Record{Version: 2, Envelope: env, AuthorizedAt: authorizedAt.Unix(), Decision: decision, Manifest: manifest, Name: d.Metadata.Name}
	encoded, err := json.Marshal(r)
	if err != nil {
		return Observation{}, err
	}
	f, err := os.OpenFile(filepath.Join(e.config.JournalDir, env.Intent.Nonce), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return Observation{}, fmt.Errorf("grant record denied: %w", err)
	}
	_, writeErr := f.Write(encoded)
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return Observation{}, errors.New("journal durability failed; operator inspection required")
	}
	dir, err := os.Open(e.config.JournalDir)
	if err != nil {
		return Observation{}, err
	}
	syncErr = dir.Sync()
	closeErr = dir.Close()
	if syncErr != nil || closeErr != nil {
		return Observation{}, errors.New("journal directory sync failed")
	}
	// Disk writes can outlast either the release grant or the evidence window.
	beforeCreate := time.Now()
	if _, err = release.Verify(env, e.config.PublicKey, e.config.Policy, manifest, trustedDigest, beforeCreate); err != nil {
		return Observation{}, err
	}
	if err = evidence.VerifyQuorum(e.config.Attestations, p, beforeCreate); err != nil {
		return Observation{}, fmt.Errorf("deployment validation denied: %w", err)
	}
	created, err := e.request(ctx, http.MethodPost, "", manifest)
	if err != nil {
		return Observation{}, fmt.Errorf("uncertain creation; reconcile read-only: %w", err)
	}
	if err = deploycheck.CheckObserved(manifest, created, e.config.Namespace, trustedDigest); err != nil {
		return Observation{}, fmt.Errorf("created object failed policy readback; inspect cluster: %w", err)
	}
	var identity struct {
		Metadata struct {
			UID string `json:"uid"`
		} `json:"metadata"`
	}
	if json.Unmarshal(created, &identity) != nil || identity.Metadata.UID == "" {
		return Observation{}, errors.New("created object lacks a verified UID")
	}
	observation, err := e.observe(ctx, r)
	if err != nil {
		return Observation{}, err
	}
	if observation.UID != identity.Metadata.UID {
		return Observation{}, errors.New("Deployment was replaced between create and readback")
	}
	return observation, nil
}

// Recover only reads independently observed cluster state. It never repeats a
// mutation, including after expiry, a lost response, a 409, or a process restart.
// Missing/conflicting state requires trusted operator investigation and a new
// authorization; this deliberately favors safety over automated availability.
func (e *Executor) Recover(ctx context.Context, id string) (Observation, error) {
	if !nonce.MatchString(id) {
		return Observation{}, errors.New("invalid journal id")
	}
	p := filepath.Join(e.config.JournalDir, id)
	info, err := os.Lstat(p)
	if err != nil {
		return Observation{}, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 2<<20 {
		return Observation{}, errors.New("unsafe journal record")
	}
	f, err := os.Open(p)
	if err != nil {
		return Observation{}, err
	}
	b, err := io.ReadAll(io.LimitReader(f, (2<<20)+1))
	closeErr := f.Close()
	if err != nil {
		return Observation{}, err
	}
	if closeErr != nil || len(b) > 2<<20 {
		return Observation{}, errors.New("journal read failed or exceeds limit")
	}
	var r Record
	if err = json.Unmarshal(b, &r); err != nil {
		return Observation{}, errors.New("incomplete journal; no mutation permitted")
	}
	canonical, err := json.Marshal(r)
	if err != nil || !bytes.Equal(canonical, b) {
		return Observation{}, errors.New("ambiguous or noncanonical journal record")
	}
	if r.Version != 2 || r.Envelope.Intent.Nonce != id || r.AuthorizedAt <= 0 || r.AuthorizedAt > time.Now().Unix() {
		return Observation{}, errors.New("journal version, nonce or authorization time denied")
	}
	if r.Decision.Environment != e.config.Namespace || r.Decision.Workload != e.config.Policy.Workload || r.Decision.Operation != "deploy" || !name.MatchString(r.Name) {
		return Observation{}, errors.New("journal scope mismatch")
	}
	verified, err := release.Verify(r.Envelope, e.config.PublicKey, e.config.Policy, r.Manifest, r.Decision.ArtifactSHA256, time.Unix(r.AuthorizedAt, 0))
	if err != nil {
		return Observation{}, err
	}
	if verified != r.Decision {
		return Observation{}, errors.New("journal decision differs from signed authorization")
	}
	var request deploycheck.Deployment
	if json.Unmarshal(r.Manifest, &request) != nil || request.Metadata.Name != r.Name {
		return Observation{}, errors.New("journal resource name differs from signed manifest")
	}
	return e.observe(ctx, r)
}

func (e *Executor) request(ctx context.Context, method, resource string, body []byte) ([]byte, error) {
	t, err := os.ReadFile(e.config.TokenFile)
	if err != nil {
		return nil, errors.New("executor credential unavailable")
	}
	token := strings.TrimSpace(string(t))
	if token == "" || strings.ContainsAny(token, "\r\n\t ") {
		return nil, errors.New("invalid credential")
	}
	u := e.origin + "/apis/apps/v1/namespaces/" + e.config.Namespace + "/deployments" + resource
	if method == http.MethodPost {
		u += "?fieldManager=trust-boundary&fieldValidation=Strict"
	}
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	res, err := e.http.Do(req)
	if err != nil {
		return nil, errors.New("Kubernetes request failed")
	}
	defer res.Body.Close()
	want := http.StatusOK
	if method == http.MethodPost {
		want = http.StatusCreated
	}
	if res.StatusCode != want {
		return nil, fmt.Errorf("Kubernetes HTTP %d", res.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, 2<<20+1))
	if err != nil || len(b) > 2<<20 {
		return nil, errors.New("invalid API response size")
	}
	return b, nil
}

func (e *Executor) observe(ctx context.Context, r Record) (Observation, error) {
	b, err := e.request(ctx, http.MethodGet, "/"+r.Name, nil)
	if err != nil {
		return Observation{}, err
	}
	if err = deploycheck.CheckObserved(r.Manifest, b, e.config.Namespace, r.Decision.ArtifactSHA256); err != nil {
		return Observation{}, err
	}
	var requested, observed struct {
		APIVersion string                                                 `json:"apiVersion"`
		Kind       string                                                 `json:"kind"`
		Metadata   struct{ Name, Namespace, UID, ResourceVersion string } `json:"metadata"`
		Spec       struct {
			Template struct {
				Spec struct {
					Containers []struct {
						Image string `json:"image"`
					} `json:"containers"`
				} `json:"spec"`
			} `json:"template"`
		} `json:"spec"`
	}
	if json.Unmarshal(r.Manifest, &requested) != nil || json.Unmarshal(b, &observed) != nil {
		return Observation{}, errors.New("invalid observed state")
	}
	if observed.APIVersion != "apps/v1" || observed.Kind != "Deployment" || observed.Metadata.Name != r.Name || observed.Metadata.Namespace != e.config.Namespace || observed.Metadata.UID == "" || observed.Metadata.ResourceVersion == "" || len(observed.Spec.Template.Spec.Containers) != 1 {
		return Observation{}, errors.New("observed identity mismatch")
	}
	image := observed.Spec.Template.Spec.Containers[0].Image
	if image != requested.Spec.Template.Spec.Containers[0].Image {
		return Observation{}, errors.New("observed image mismatch")
	}
	return Observation{UID: observed.Metadata.UID, ResourceVersion: observed.Metadata.ResourceVersion, Image: image}, nil
}
