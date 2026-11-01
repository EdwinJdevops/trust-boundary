# Portable verification record — 2026-11-01

This records the earlier portable-verifier milestone. For the later admitted-state
and signed-journal implementation, see [the subsequent verification record](VERIFICATION_ADMITTED.md).

Tested implementation: `0aef0e7dc5c17c205c641ab13606a934f526cc4e` in
https://github.com/EdwinJdevops/trust-boundary .

The complete portable supervisor ran against that exact clean Git commit on the
existing Ubuntu/WSL environment, with ordinary checks under UID 21003 and the
reviewed root Kubernetes harness using its separate caller/executor identities.
No permanent runner, persistent signing keys, cloud infrastructure or billing changes were
created. The evidence is **unsigned**, not independently authenticated.

## Executed results

All seven required stages exited 0: format, full build, vet, race/adversarial
tests, integration compilation, historical archive checksums and actual Kubernetes
enforcement. All eight Go packages passed race tests, including the new evidence
library and tbverify command tests. Evidence package statement coverage was 83.8%;
command coverage was 75.0%. Coverage is not proof of complete security.

The worker artifact and supervisor rebuild had identical SHA-256 digests. The
recorder verified the exact source archive, binary, harness manifest, environment
metadata and fixed-name logs. After deliberately appending bytes to source.tar,
the CLI rejected the bundle with the expected digest-mismatch error. Restoring
the original archive restored successful integrity verification.

The real Kubernetes run verified actual caller/executor service-account
authentication, caller token-file denial, direct API bypass denial, cluster
admission rejection with the executor token, signed manifest acceptance, replay
denial, read-only recovery with a new executor instance and a successful rollout.
Actual-token permission checks denied Secrets, RBAC mutation, Pod exec and
cross-namespace creation. The test cluster `tb-test-ogahss0p` was deleted.

Observed Deployment UID: `678e21a8-231f-4e95-8bee-2012aa2fb77b`.
Observed Pod UID: `4f4ef32c-1a18-4275-9efa-db365356d42b`.
Authorized image and reported running imageID matched:
`registry.k8s.io/pause@sha256:278fb9dbcca9518083ad1e11276933a2e96f23de604a3a08cc3c80002767d24c`.

## Bound identities

| Input | SHA-256 |
| --- | --- |
| Source archive | 94914eb66c57cb6a730660c817fc09fb31aab46b1fffb0adb3ba7fd32a151675 |
| Built tbverify artifact | c2be1e1322430cc2121956f05a06318f5f7a1698e2e56714ec9f02f5dbd55d8a |
| Suite manifest | 79b2a8a21940ef4762d454b8a1e0be2213024717473746cccb238aec705f43d0 |
| Tool/environment metadata | 34a2a4eee50005c4036a2848466f7f2db9af33e0ea64e3ca99172a32b8424558 |
| Canonical statement | b7603825c043a31bf23e79704237a2e54b0cb0878c48f5ca51f50ef6b38e2547 |

The artifact is this project's built verifier executable, not a customer release
image or publisher provenance. The local full bundle filename is
`validation-0aef0e7dc5c17c205c641ab13606a934f526cc4e.tar.gz`, SHA-256
`aad90dde4a55dfd60705156aa3de57b4f84491f2ad7700ea4eded0797e92da74`.
The bundle is delivered locally; no remote artifact upload or storage was purchased.
The statement and small raw logs are retained under
`docs/evidence/portable-0aef0e7/` in this repository.

## Hosted CI and remaining enforcement gaps

[GitHub run 41297490492](https://github.com/EdwinJdevops/trust-boundary/actions/runs/41297490492)
completed successfully for this exact commit. Both Go 1.26.x and 1.27.x jobs
actually executed archive checks, format, build, vet, race/adversarial tests,
integration-test compilation and shell syntax. The Kubernetes workflow was not
dispatched remotely; its real execution above was local. We did not establish why
the prior billing-related refusal cleared and did not alter billing settings.

The branch-protection API still returned HTTP 403 requiring GitHub Pro or a public
repository. The repository stays private and no plan was changed.

No real independent validator identities have been enrolled. Two-key signatures,
scope/freshness policy, malformed-input rejection and key-alias attacks are tested
using temporary unit-test keys only. Distinct key bytes cannot prove operational
independence. The runner never auto-signs or generates a trust root. Signed evidence
is not yet required by the existing deployment executor; no enforced independent
deployment-approval claim is made. The original release gate remains unchanged.

Remaining work includes separately controlled signer enrollment, key revocation
and approved toolchain policy, evidence enforcement inside the protected executor,
real signing/runner separation tests, complete admitted-state verification,
provenance, kernel/network containment and power-loss recovery testing. No external
audit, SLSA level or production-readiness claim is made.
