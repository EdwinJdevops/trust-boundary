# Admitted Deployment and signed-journal checks

The executor checks both the create response and an independent GET against the
authorized restricted Deployment. It compares the full supported workload shape,
not only the image. It also requires the GET UID to equal the UID returned by the
successful create, detecting replacement between those two requests.

## Narrow normalization contract

The input manifest must first pass the existing strict validator and exact-byte
release signature binding. Observed JSON rejects duplicate keys. Comparisons
retain all workload fields except explicitly enumerated API defaults:

| Location | Accepted default |
| --- | --- |
| Deployment | RollingUpdate, maxSurge/maxUnavailable 25%, revisionHistoryLimit 10, progressDeadlineSeconds 600, minReadySeconds 0, paused false |
| Pod template | Always restart, 30-second grace period, ClusterFirst DNS, default scheduler/account, service links true, PreemptLowerPriority |
| Container | IfNotPresent pull policy for digest references, default termination-message path/File policy, empty resources |

Optional false host flags and privileged=false, empty capability additions and
empty init/ephemeral/volume arrays are normalized consistently with the original
restricted profile. Mandatory non-root, no-escalation, read-only filesystem,
token-mount and capability-drop settings remain material. Unknown workload fields
are rejected; a different cluster's defaulting or policy may therefore fail closed.
Resource defaults from a LimitRange, custom schedulers or injected sidecars are
not silently accepted. New profiles require explicit engineering and tests.

Informational server metadata and Deployment status are excluded from the workload
comparison. Only the controller revision annotation is accepted; unexpected
annotations, owners/finalizers and a terminating Deployment are rejected. This
does not validate rollout readiness, which the integration supervisor checks
separately, or every resulting Pod's runtime state.

The default reference is the fixture's Kubernetes v1.35.8 implementation:
[core defaults](https://github.com/kubernetes/kubernetes/blob/v1.35.8/pkg/apis/core/v1/defaults.go)
and [Deployment defaults](https://github.com/kubernetes/kubernetes/blob/v1.35.8/pkg/apis/apps/v1/defaults.go).
This is an allowlist for this experimental profile, not universal Kubernetes API
compatibility.

## Journal version 2

The single exclusive durable request record now includes its version, the original
signed release envelope and authorization timestamp. Recovery requires canonical
JSON, matching nonce/filename, nonfuture authorization time, the configured
verification key and policy, exact signed manifest bytes and a recomputed matching
decision and resource name. It performs these checks before any cluster request.

Recovery verifies the signature at the recorded authorization time. An expired
grant can therefore support read-only state inspection, but cannot authorize a
new mutation. Recovery never POSTs, retries creation, removes replay records or
automatically rolls back. Duplicate keys, altered records and incomplete writes
fail closed.

Legacy version-1 records lack the original signed request and are rejected. They
are not deleted or silently migrated. A trusted operator must investigate them;
the software cannot manufacture the missing authorization evidence.

## Security boundary and remaining limits

Post-create verification is detection, not prevention of an already accepted
mutation. It cannot undo an unsafe object that an API/admission layer persisted.
Independent cluster admission and RBAC must remain authoritative. A Pod-level
webhook can alter Pods after Deployment-template verification; continuous/runtime
attestation is not implemented. All privileged cluster actors remain trusted.

Journal signatures improve request integrity but do not make local storage
tamper-evident or defeat root, deleted replay records, replaced binaries, signing
key compromise or malicious configuration. Private Linux storage and trusted
parent directories are still required. Recovery of matching state after a lost
acknowledgement does not prove this operation originally created that object.

Signer lifecycle, external validation enforcement, network/kernel containment,
power-loss durability and external review remain unresolved production gates.
