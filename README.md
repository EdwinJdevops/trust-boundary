# Trust Boundary

Experimental developer-to-deployment security control plane. **Not approved for
production infrastructure. No external audit or production-readiness claim.**

This repository continues the supplied Go v0.13 implementation and preserves all
13 historical source archives. The original handoff, README, security notes and
checksums are in [docs/history](docs/history/). Import evidence is recorded in
[docs/IMPORT.md](docs/IMPORT.md). The project is licensed under Apache-2.0 by the
owner's explicit choice.

## Implemented

- Ed25519 release intents scoped to issuer, workload, environment, operation,
  expiry and nonce, with exact artifact and manifest SHA-256 binding.
- Restricted Deployment JSON validation, duplicate-key and exact-field checks,
  immutable image references and fail-closed privilege restrictions.
- TLS-verified server-side dry-run preflight, with explicit CA, no redirects and
  no environment proxy. Dry-run is not a separate authorization boundary.
- Experimental Linux create-only executor with a protected token file,
  namespace-scoped configuration and one durable request/replay record before POST.
  Read-only recovery revalidates the signed journal and compares the supported
  admitted Deployment configuration, not only the image;
  it never retries an uncertain mutation.
- Bounded exact-byte artifact measurement. It does not authenticate a publisher
  or verify build provenance.
- Reproducible disposable-cluster fixture with independent Unix/Kubernetes caller
  and executor identities, restricted deployment credentials, Pod Security and
  fail-closed cluster admission. Configuring this fixture is not a passing result.

See [architecture and unresolved risks](docs/ARCHITECTURE.md),
[security policy](SECURITY.md), and [contribution/test instructions](CONTRIBUTING.md).

The [portable validation runner](docs/PORTABLE_VALIDATION.md) runs the full suite
against a clean exact commit and emits hash-bound, explicitly unsigned evidence.
The executor requires fresh attestations from at least two configured validator
keys before creating a deployment. The operator pins the release source and
artifact digests. The integration fixture uses temporary keys. Independent
validator enrollment remains a production gate.

## Verification

The [process-crash and rollout verification record](docs/VERIFICATION_CRASH.md)
contains the exact tested commit, passing hosted CI, real cluster results and
hash-bound local evidence. The [admitted-state record](docs/VERIFICATION_ADMITTED.md)
and earlier reports remain historical evidence.
The [release acceptance gates](docs/RELEASE_GATES.md) define the developer-preview
scope, operational recovery constraints and evidence still required for production.
The [repository settings record](docs/REPOSITORY_SETTINGS.md) documents public
visibility, protected checks, secret push protection and private security reporting.

```sh
go build ./...
go vet ./...
go test -race -count=1 ./...
go test -c -tags integration -o /tmp/tb-integration.test ./kubeexecutor
```

Linux filesystem semantics are required for authorization durability. Do not
relax directory permissions to make Windows tests pass. The module has no
third-party runtime dependencies.

On a dedicated disposable Linux host with Go, Docker, kubectl, curl and setpriv:

```sh
sudo env "PATH=$PATH" bash scripts/integration.sh
```

The test creates a dedicated kind cluster and temporary credentials, then tears
them down. It does not use an existing kubeconfig or provision cloud services.
CI runs format, build, archive checksums, vet, race/adversarial tests and integration
test compilation with read-only repository permissions and immutable action pins.
The full cluster workflow is manual to avoid unnecessary recurring resource use.
Actual executed results belong in evidence reports and Actions run links, not
assumptions derived from these commands or workflow files.

## Security limits

The executor API is trusted in-process code, not an authenticated public service.
A stolen executor token can bypass its signature gate. The journal assumes private
local Linux storage and trusted installation/parent directories. Recovery observes
matching supported Deployment state; it does not prove causal ownership of a
pre-existing object, attest resulting Pods or provide automatic rollback/exactly-once
deployment. Post-create mismatch detection cannot undo an accepted mutation.

Independent signing, provenance verification, workload attestation, kernel and
network containment, key revocation/rotation, remote tamper-evident audit,
distributed replay handling and power-loss/crash testing remain unfinished. The
historical same-UID Python adapter bypass remains documented and must not be used
as a production boundary. AWS/Azure/GCP integration is a target, not verified work.
