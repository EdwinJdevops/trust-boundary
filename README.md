# Trust Boundary — Go release-authority experiment 010

This is an experimental authorization core, **not a deployable production control plane**. It extends the Python Experiment 009 as a separate module rather than silently replacing it.

## Verified contract

- Ed25519 signature on a fixed JSON intent schema; issuer private key is not needed by verifier.
- Exact SHA-256 artifact digest, issuer, workload, target environment, operation, expiry and nonce matching.
- Fail-closed single-use local replay record using atomic exclusive file creation and filesystem sync.
- No dependencies outside Go's standard library.

## Test

`go test -race -count=1 ./...`

## Trust assumptions and current blockers

1. The `observedDigest` argument MUST be supplied by a separate trusted executor measuring real bytes. Passing an attacker-supplied value destroys artifact binding.
2. Only a private, locally controlled replay directory is supported. Filesystem durability semantics depend on filesystem/platform; NFS/distributed execution is outside scope. The verifier does not securely establish the owner of the directory or prevent a privileged adversary from altering it.
3. Recording authorization is not the same as recording successful deployment. This module doesn't execute cluster changes or recover external mutations.
4. There is no trusted launcher, no proven isolation, no SPIFFE identity, no Kubernetes adapter, no signing-key lifecycle, no audited event storage, and no protected remote protocol.
5. A local caller using a trusted executor's identity might still request authorization: real authentication, workload attestation and OS separation must be tested.
6. The verifier is suitable for engineering research and CI tests, not production authorization.

## Launch gates

A public engineering preview must clearly identify these limits. A production release must additionally demonstrate independent OS identities, confined executor, strict network policies, protected keys, trusted artifact measurement, Kubernetes mutation restrictions, state reconciliation, telemetry, and adversarial testing under real Linux isolation.

## Experiment 011 — Restricted Kubernetes Deployment JSON contract

Package `deploycheck` validates a deliberately narrow `apps/v1` Deployment JSON document before it can be submitted to a trusted executor. It refuses unknown fields, multiple containers, init containers, volumes, privileged execution, service-account-token mounts, host networking/PID/IPC, image tags, altered image digests, and wrong namespaces. Positive test: a restricted digest-pinned single-container workload with a non-root profile, no escalation, read-only root filesystem, dropped capabilities, RuntimeDefault seccomp, and matching selectors.

Run `go test -race -count=1 ./...` and `go vet ./...` from this directory. The new contract has 11 table-driven cases; the pre-existing `gate` suite is retained.

**Limitations (security critical):** This checks JSON supplied to this function, not the image actually running in Kubernetes. The digest must be independently measured and provided by a trusted executor. There is no Kubernetes client, RBAC, admission webhook, protected namespace, authentication, sandbox containment, policy distribution, or deployment reconciliation. Direct cluster access bypasses this library. This allowlist is intentionally restrictive and does not validate every Kubernetes default or mutating admission behavior. Treat it as an experimental preflight guard only. Do not use it as the sole deployment security control.

## Experiment 012 — Input hardening

A recursive strict-JSON pass rejects duplicate object keys at every nesting level, oversized deployment documents and multiple JSON documents. Image references now reject mutable tag/digest combinations, repeated `@`, and query-like suffixes. The new tests specifically exercise ambiguity and image-reference injection. This improves **preflight correctness**, not deployment authority or live cluster enforcement.

CI configuration is provided but has **not been run by GitHub**; the local test run is the current evidence. See SECURITY.md for trust assumptions and reporting.

## Experiment 012 — Signed deployment-manifest binding

The `release.CheckAndAuthorize` entry point requires an Ed25519-signed intent containing `manifest_sha256` for the *exact manifest bytes*, a matching independently measured image digest, a restricted Deployment JSON document, and a one-use replay grant. The original `gate.Authorize` API remains for earlier compatibility but does not require a manifest; **production callers must not use it as a deployment authority**. The integrity check covers the input manifest bytes; it does not attest to what the Kubernetes API ultimately admits after defaulting or mutation.

The `deploycheck` parser now rejects duplicate keys recursively and checks size limits and image reference syntax. These are defense-in-depth parser controls, not a complete OCI reference parser or a cluster security boundary.

### Verified locally

`go test -race -count=1 ./...` and `go vet ./...` on Go 1.23.2 linux/amd64. CI workflow is configured but has not been executed against GitHub. There is no real Kubernetes adapter, no workload attestation, no hardened executor, and no external penetration test. See SECURITY.md. Do not use this experimental release for production deployments.

## Experiment 013 — authenticated Kubernetes admission preflight

Package `kubepreflight` introduces an explicit TLS-verified Kubernetes API server-side `POST` with `dryRun=All` for restricted Deployment manifests. The API origin is pinned to HTTPS and an explicit PEM CA bundle; redirects and environment proxies are disabled. The bearer token is read from a file, never accepted from the untrusted manifest. A successful result requires HTTP 201 and the expected Deployment identity. The code fails closed for invalid manifests, certificate errors, API rejection, and malformed responses. Synthetic tests use `httptest.NewTLSServer`; **no real Kubernetes cluster was accessed**.

**Security constraints and remaining blockers:**

- The API server must independently enforce authentication, RBAC and admission. Kubernetes authorizes dry-run against the underlying create verb: a bearer token authorized to dry-run create may also have permission for a real create. Do **not** give this token to untrusted workloads. Secure its file with independent host identity/permissions and network separation.
- `dryRun=All` does **not** establish effective isolation or prove that a later deployment will succeed. It does not reserve admission results or prevent state/policy changes between dry-run and actual execution.
- The preflight is not integrated with the signed release grant, trusted image measurement, real cluster execution, or state reconciliation. It does not issue or consume grants.
- The synthetic API certificate and token used in tests are not production credentials. The tests establish client behavior against a fake TLS server, not Kubernetes admission behavior.
- Any production extension requires workload identity, credential protection, idempotent execution, cluster-side policy enforcement and deployment evidence. Admission and RBAC need independent out-of-band cluster configuration.

### Run verification

```sh
go test -race ./...
go vet ./...
```

### No-cost security evidence

A genuine Kubernetes validation gate requires a disposable isolated cluster and two independently authenticated principals (unprivileged caller and adapter). The acceptance test must observe `Forbidden` from a direct unprivileged Kubernetes request, accepted preflight through the adapter, and a confirmed created Deployment only after the signed authorization is independently validated. No such live-cluster result is claimed here.
