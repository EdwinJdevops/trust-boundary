# Release scope and acceptance gates

Trust Boundary's core purpose is to stop untrusted developer tooling from inheriting
deployment authority. Its narrow implemented path verifies an exact signed restricted
Deployment, records one consumed request, sends one create and checks admitted state.
It is a library and disposable integration fixture, not an installed production service.

The defensible initial launch scope is a developer preview for evaluation in disposable
clusters. That scope must not be presented as an enterprise production control plane.
Public source, passing CI and an attractive announcement do not change the trust model.

## Acceptance evidence

| Property | Current evidence | Remaining gate |
| --- | --- | --- |
| Exact signed deployment authorization | Ed25519, manifest/artifact hashes, scope, expiry and replay tests | Independent production signing, issuance and revocation |
| Separate deployment credentials | Real caller/executor Unix UIDs and service accounts; RBAC/admission denial tests | Protected production installation and credential lifecycle |
| Admitted configuration | Supported Deployment comparison, UID replacement and mutation rejection tests | Resulting-Pod and continuous verification; prevent unsafe admission before persistence |
| Artifact integrity | Exact registry-response measurement and digest-pinned manifest | Publisher identity and approved builder provenance |
| Validation approval | Portable unsigned bundle; quorum verification with temporary test keys | Independently controlled validators and mandatory evidence enforcement in executor |
| Recovery | Exclusive signed journal; GET-only recovery; incomplete/altered journal denial; controlled SIGKILL tests | Power-loss/disk failure injection, operator protocol |
| Repository integrity | Pinned actions, read-only CI, archive checksums | Enforced protected review path and publication/history review |
| Runtime containment | Restricted workload fixture | Tested network/kernel boundaries, independent security review |

Verification reports record exact revisions and executed results. A configured test
or an unexecuted test is not evidence. The process-crash test adds controlled SIGKILL
of a real child executor at an unacknowledged POST against a synthetic TLS API,
covering both missing and persisted observations. It must pass before its receipts
can be cited; the [executed results](VERIFICATION_CRASH.md) record that pass. It is
not a real API-server crash or power-loss simulation.

## Handling uncertain creation

After a journal is created, any failure may represent an uncertain operation. Keep
the journal and original signed request. Do not remove the nonce, retry the grant,
reuse the credentials from an untrusted caller, or run a compensating mutation
automatically. Recover through the trusted executor to inspect cluster state.

A matching observation does not prove this operation created the resource. Missing,
conflicting or rejected state requires trusted operator investigation. Any later
mutation needs a fresh reviewed authorization. Legacy version-1 records lack the
required signed evidence and must not be silently migrated. Restore-from-backup
must not roll back consumed nonces; a safe distributed restoration protocol remains
unfinished. These limitations prevent approval for production infrastructure.

## Publication

The owner has authorized public visibility if needed. Before publication, inspect
the complete history and preserved archives for credentials, private material and
redistribution concerns; retain findings and verify public security reporting and
branch protection after any visibility change. Permission to publish does not
itself establish that review. Do not publish signing material or turn temporary
test keys into trust roots. Do not create paid infrastructure to satisfy a launch label.
