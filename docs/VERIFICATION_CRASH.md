# Process-crash and rollout verification — 2026-11-01

Tested commit: 19b53777300a20cc86d812109ffa7b8e02bf7d53 in https://github.com/EdwinJdevops/trust-boundary.
All seven portable stages exited 0 against that clean commit: format, build, vet,
race tests across eight packages, integration compilation, historical archive
checksums and real Kubernetes. The full bundle was then deliberately tampered;
source digest mismatch was rejected, and restoration passed integrity inspection.
Evidence remains unsigned and not independently authenticated.

## New acceptance checks

The Linux race suite now starts a separate executor process with an ephemeral
synthetic token and no signing private key. A TLS API fixture receives its POST
but withholds acknowledgement. The test first requires its complete signed journal,
then kills that exact child and verifies termination by SIGKILL. It separately
models persisted and absent API state. A fresh executor issues one recovery GET,
reports the appropriate observation/error, denies another create and leaves the
consumed journal byte-identical. Exactly one POST and one GET are required.
The parent uses a bounded child lifetime and cleans up only its own child.

This is actual process-death injection against a synthetic API, not a real API-server
crash, kernel crash, storage failure, filesystem power-loss or exactly-once proof.
Those remain separate production acceptance gates.

The real Kubernetes fixture now asserts runtime image identity instead of merely
printing it: exactly one nonterminating Running Pod, one ready container and an
imageID equal to the measured OCI response digest. The same actual observation
must reject an unrelated all-zero digest. These positive and negative checks passed.
This trusts the API/node report and does not establish cryptographic runtime attestation.

Cluster: tb-test-0fixrnvd; deleted by the harness. Deployment UID:
685c26bc-ae73-4d91-aba9-1a85e2efed66. Pod UID:
ce8456af-9a69-4198-bdd5-2cf97b8a3ad4. Verified imageID:
registry.k8s.io/pause@sha256:278fb9dbcca9518083ad1e11276933a2e96f23de604a3a08cc3c80002767d24c.
Separate actual caller/executor credentials, Unix token-file protection, caller
Forbidden, cluster admission denial, signed creation, replay denial, read-only
recovery and denied Secrets/RBAC/exec/cross-namespace permissions also passed.

[Hosted CI 41332858855](https://github.com/EdwinJdevops/trust-boundary/actions/runs/41332858855)
passed both Go 1.26.x and 1.27.x jobs for this exact revision. The real cluster test
was local, not executed by that hosted workflow. No cloud resources were provisioned.

## Integrity bindings

| Input | SHA-256 |
| --- | --- |
| Source archive | a03fa8b3f62917cda6c5a4fa93919fa79dbb1b25ddec567ee2905504f421fcd0 |
| Built verifier | c2be1e1322430cc2121956f05a06318f5f7a1698e2e56714ec9f02f5dbd55d8a |
| Suite | 0f49ff0ffd1fb03fff4c10261656954809c386cc7655069df1846a48aab7f560 |
| Environment | 34a2a4eee50005c4036a2848466f7f2db9af33e0ea64e3ca99172a32b8424558 |
| Statement file | 3bcac5ae168dcf1944fcc7d4b23943a25d3828f62299c39b7121171952112930 |
| Complete bundle | caaebddfadf76b6d45de66607492682c82b650d5c5ae8ee6ac2b4da2af555217 |

Raw receipts are in docs/evidence/crash-19b5377/. Full local bundle:
validation-19b53777300a20cc86d812109ffa7b8e02bf7d53.tar.gz. The worker/supervisor verifier builds matched on the
same trusted host; this is not independent build reproduction or release provenance.

## Publication review and remaining gates

Gitleaks 8.30.1 was obtained from its official GitHub release into the project-local
tool directory and its ZIP matched the release checksum list. Git history scanning
with --all --full-history reported 13 commits and no findings. Directory scanning
with archive traversal depth 4 reported approximately 879 KB and no findings.
Both used default rules, full redaction, ignored inline allow comments, no baseline
and no inherited Gitleaks config overrides. Empty JSON reports are retained.
These are bounded pattern scans, not proof of absence of credentials, a licensing
audit or external security review. Preserved research code and the historical
same-UID adapter bypass remain unsupported and documented.

The owner authorized public visibility if needed. Publication and branch protection
must be verified as actual remote settings separately; this record does not assert
they have already changed. No production release or independent validator enrollment
is implied by publication. Mandatory independent validation, signer/provenance
lifecycle, runtime containment, distributed recovery and independent review remain
unfinished. See RELEASE_GATES.md for the developer-preview scope and operator rules.
