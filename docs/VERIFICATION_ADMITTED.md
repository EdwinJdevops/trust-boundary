# Admitted-state verification record — 2026-11-01

Repository: https://github.com/EdwinJdevops/trust-boundary (private).
Tested source: 442d2fc013e1853840fbd15950b7b1b5176d6124.
Implementation commits: d4cb1d6e05a395f30ac364884143834c5bc2259b and 442d2fc013e1853840fbd15950b7b1b5176d6124.

## Implemented and exercised

The create response and subsequent GET are compared against the signed restricted
Deployment profile. Only enumerated Kubernetes defaults and informational metadata
are normalized. Unknown workload fields fail closed. Immediate readback must retain
the creation UID. Exact JSON numbers avoid floating-point equivalence errors.

Version-2 journals retain the signed envelope and authorization time. Recovery
reverifies the signed manifest, decision, scope, nonce and resource name before GET.
Legacy unsigned, altered, duplicate-key and future-time records are denied. An
expired valid signed record permits read-only recovery, never a new POST.

The exact clean commit completed all seven portable stages with exit 0: format,
build, vet, race tests (all eight Go packages), integration compilation, all 13
historical archive checksums, and real disposable Kubernetes enforcement. The worker
binary matched a supervisor rebuild on the same host. This is not independent
reproducible-build verification. The evidence is unsigned and not authenticated
by independent validators.

Adversarial tests reject privilege, environment, command, sidecar, init-container,
mount, account, token-mount, replica, scheduler and annotation changes; terminating
objects, case aliases, duplicate keys and fractional/exponent numeric aliases;
POST/GET configuration injections, replaced-object readback and altered journals.
The actual bundle was then modified: appending bytes to source.tar produced the
expected digest-mismatch rejection. Restoring it restored successful inspection.

## Actual cluster and hosted checks

The real cluster verified separate caller/executor Unix and Kubernetes identities,
caller token-file denial, caller API Forbidden, unsafe workload denial using the
actual executor token, authorized creation, replay denial, read-only recovery in a
new executor instance, successful rollout, and denied Secrets/RBAC/Pod-exec/cross-
namespace permissions. Observed Deployment UID: c9731162-3914-4353-9e6c-ae748f90fd6c.
The running imageID matched the authorized digest:
registry.k8s.io/pause@sha256:278fb9dbcca9518083ad1e11276933a2e96f23de604a3a08cc3c80002767d24c.
Cluster tb-test-ezdjxrof was deleted. The old interrupted node
tb-test-wuc0n1d6-control-plane was separately identified by its kind label and removed.
No cloud infrastructure, persistent signing keys or billing changes were created.

[Hosted CI run 41301050253](https://github.com/EdwinJdevops/trust-boundary/actions/runs/41301050253)
passed for this exact commit on both Go 1.26.x and 1.27.x. Those jobs actually ran
build, vet, race/adversarial tests, archive checks, integration compilation and shell
syntax; hosted CI did not execute the real cluster test. The cluster execution was local.

## Integrity bindings

| Input | SHA-256 |
| --- | --- |
| Source archive | 4244e6eea43af73bf937b0b30e75397e06d61f97df8b3d93ffcb8a645470f4db |
| Verifier executable | c2be1e1322430cc2121956f05a06318f5f7a1698e2e56714ec9f02f5dbd55d8a |
| Suite manifest | ec8a922736c0f35fd47f034026625690b933d024b29406c159604d6efe3e7989 |
| Environment metadata | 34a2a4eee50005c4036a2848466f7f2db9af33e0ea64e3ca99172a32b8424558 |
| Statement file | 241a736bbf02f3d5a613188149b3d713d30f6a79c18515edc6a9a002f3f0a0c6 |
| Complete local bundle | f138e707e1104ca7edb194ac2993a52709fb0484780df68631a24a177da027c3 |

Small raw logs, the unsigned statement, integrity outputs and hosted CI receipt
are retained in docs/evidence/admitted-442d2fc/. The full local bundle is
validation-442d2fc013e1853840fbd15950b7b1b5176d6124.tar.gz. It is not publisher provenance or a customer image.

## Remaining production gates

Post-create checking detects differences after acceptance; it cannot prevent or
undo an unsafe mutation already persisted. Resulting Pod mutation, continuous
runtime attestation and privileged cluster actors remain outside this check.
Recovery does not establish causal ownership after a lost acknowledgement and
does not retry, roll back or remove replay records. Root, private-store deletion,
key compromise and malicious trusted configuration remain material risks.

Independent validators are not enrolled and signed validation evidence is not yet
mandatory in the executor. Production signer lifecycle, provenance verification,
network/kernel containment, distributed replay, remote audit and power-loss/crash
failure injection remain unfinished. No external audit or production-readiness
claim is made.

The branch-protection API was rechecked and returned HTTP 403 requiring GitHub Pro
or public visibility. The repository remains private; no plan was changed.
Next enforcement work must install separately controlled trust roots and an
approved release policy before making authenticated validation mandatory in the
executor. Test keys must never be promoted to production authority.
