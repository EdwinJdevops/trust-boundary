# Security policy — experimental

No release is approved to control production infrastructure. There has been no
external audit. Report vulnerabilities privately to the repository maintainer;
use GitHub private vulnerability reporting only if it is enabled. Never put
credentials, customer data or exploit details in public issues.

The review scope includes signed authorization, replay safety, manifest ambiguity,
TLS and credential handling, scope enforcement, cluster policy, journal recovery
and bypass paths. Negative findings must be preserved even when a new layer is
added. See [architecture and threat assumptions](docs/ARCHITECTURE.md).

The trusted computing base includes the signer, protected executor OS identity,
filesystem and parent directories, cluster administrator, API server, admission
configuration, node kernel and the independent artifact measurement path. An
untrusted caller must never receive an executor token, signing key, writable
journal, host root or arbitrary code execution under the executor UID.

The Go library does not establish those identities by itself. Its workload field
is a signed assertion, not attestation. Dry-run uses the same Kubernetes create
authorization as a real create. The in-process executor is not safe to expose as
an unauthenticated remote API. Admission restricts shape but does not verify release
signatures; stolen executor credentials remain a critical bypass risk.

Historical archives are immutable research evidence, not supported deployment
packages. In particular the Python same-UID adapter bypass, unverified Bubblewrap
containment and local-only SQLite mock transaction limits remain documented.

Production consideration requires independent signing and provenance verification,
identity issuance, protected credential rotation/revocation, complete post-admission
policy verification, network/kernel isolation, tamper-evident audit, durable
operator recovery, failure injection and independent review. Passing unit tests or
a disposable kind test does not establish those properties.
