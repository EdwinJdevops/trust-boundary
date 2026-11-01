# Architecture and threat model

## Preserved chain

Exact artifact bytes and provenance -> restricted developer execution ->
authenticated workload identity -> operation-scoped signed release -> protected
executor -> cluster admission and RBAC -> independently observed state -> durable
recovery. Each arrow is a separate trust boundary; a digest alone is not identity
or provenance. See the original handoff and archives in `history/`.

## Experiment 014: create-only executor

`release.Verify` retains the v0.13 signature, exact manifest, digest, time and scope
checks without consuming the historical standalone replay file. The new executor
combines grant consumption and the full authorized request into one exclusively
created local journal file, syncs both file and directory, rechecks expiry, and
sends one create request. Concurrent replay loses exclusive creation. A truncated
record blocks further mutation and requires operator inspection.

Recovery only GETs the previously named Deployment and checks the supported
admitted workload configuration, nonempty UID and resourceVersion. Immediate
create/readback must also retain the same UID. It never repeats POST.
An absent/conflicting object, expired request before POST or disk failure may leave
an unrecoverable operation requiring trusted investigation and a new signed grant.
There is no exactly-once or automated rollback claim. A matching pre-existing
Deployment is an observation, not proof this operation created it. Version-2
journals reverify their stored signed request before GET; root and replay-store
tampering remain outside the defended boundary. Legacy unsigned records are denied.
See [the admitted-state and journal contract](ADMITTED_STATE.md).

`artifact.Measure` hashes real bytes with bounded input. It does not verify SLSA,
Sigstore, publisher identity, source correspondence or the safety of those bytes.

## Independent principals in the cluster test

The disposable fixture uses Unix UIDs 21001 (executor) and 21002 (caller), distinct
short-lived Kubernetes service-account tokens, separate control/caller/workload
namespaces, namespace-scoped create/get Deployment RBAC, restricted Pod Security
and a fail-closed admission policy. No executor token is mounted in the workload.
The caller attempts direct mutation with its own actual token and attempts to read
the executor token file. Both must be denied. The test supervisor is trusted root
and cluster administrator; compromise of that supervisor invalidates the test.
The fixture signing key is generated in the test process, not an independent
production signing service. These service accounts are not SPIFFE attestation.

The test fixture is not a multi-tenant cluster design. Workload creation authority
is powerful; the executor token itself can bypass the Go signature gate if stolen.
Admission restricts workload shape but does not verify Ed25519 intents. Control
plane administrators, node root and privileged local users remain trusted.

## Remaining risks and gates

- The original same-UID socket bypass remains in historical Python code. Never
  expose that adapter or the Go in-process executor API to hostile same-UID code.
- Real sandbox containment, default-deny networking, syscall confinement and
  resistance to kernel/container escapes are unverified. Kind's network does not
  establish production network isolation.
- Observing the Deployment image is not attesting all admitted fields, running
  bytes or artifact provenance. Admission mutation and privileged cluster actors
  can change state. Pod imageID evidence is separately printed by the supervisor.
- No key rotation, revocation, approval quorum, tamper-evident remote audit, HA or
  distributed replay protocol. Private local Linux storage is required; no NFS.
  Parent-directory substitution/ownership must be prevented by trusted installation.
- No production cloud credentials, automatic rollout update/delete, production
  readiness, external audit or proof of safety for arbitrary forks is claimed.

Next gates: signed builder provenance verification, protected independent signer
and identity issuance, post-admission full-policy verification, adversarial CNI
network tests, subprocess-kill/power-loss failure injection and an authenticated
operator recovery protocol. Multi-cloud targets remain intended integrations,
not tested AWS/Azure/GCP accounts.
