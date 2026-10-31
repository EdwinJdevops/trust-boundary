# Verification record — 2026-10-31

Repository: https://github.com/EdwinJdevops/trust-boundary (private, main).

## Source provenance

- Original handoff commit: `f9b09086a35ab1d7b3c135ba567a9399b8fa3192`.
- Unmodified v0.13 and archive import:
  `29cf351d6d1aff50645d2371173bb6c8468494e6`.
- Tested executor implementation:
  `b429842e42aaa92810e497a0683d4e7e1f72ce82`.

The accompanying evidence commit adds bounded download timeouts to the same
integration script and records these results. No Go implementation changed after
the final Linux run. All 13 historical archive hashes match the original list;
the imported latest v0.13 files matched the archived v0.13 files byte for byte.
This is internal engineering verification, not an external audit.

## Local verification

Ubuntu 26.04 under WSL, Go 1.26.8 linux/amd64, source copied onto temporary Linux
storage. The following all exited successfully:

- gofmt cleanliness, `go build ./...`, `go vet ./...`.
- `go test -race -count=1 -coverprofile=coverage.out ./...`: all six packages.
- `go test -c -tags integration ... ./kubeexecutor`.
- Bash script syntax and all 13 archived ZIP SHA-256 checks.
- Separate Windows Go 1.27.3 build and vet checks passed. Windows replay tests
  were not treated as supported durability evidence: Unix mode checks fail closed.

Package statement coverage: artifact 77.8%, deploycheck 83.7%, gate 80.3%,
kubeexecutor 75.9%, kubepreflight 76.6%, release 100.0%. Coverage does not prove
security or exhaustive path testing. Tests cover concurrent replay, manifest and
artifact substitution, invalid signatures, partial journal records, TLS trust-root
rejection, lost acknowledgements and read-only recovery. Process-kill/power-loss
durability has not been tested.

The old TLS negative test shared httptest's default certificate and could fail on
response parsing instead of TLS. It was corrected to use an unrelated CA and to
assert zero credential-bearing HTTP requests reach the untrusted server.
Exact JSON key validation now rejects case aliases that Go would otherwise decode
case-insensitively. Both changes have passing regression tests.

## Actual Kubernetes result

Docker 29.1.3, kind v0.33.0 (binary checksum verified), pinned node image:
`kindest/node:v1.35.8@sha256:07b2536e30b803ed61d1677a79df6115f798ce64c80f9e22f6ed45afd09323c0`.

The local disposable cluster `tb-test-to1i9jgt` completed the integration script
with exit status 0, including:

| Control | Observed result |
| --- | --- |
| Separate Unix identities | UID 21002 could not read UID 21001's executor token |
| Actual caller authentication | system:serviceaccount:tb-caller:caller |
| Direct caller bypass | API rejected Deployment creation as forbidden |
| Actual executor authentication | system:serviceaccount:tb-control:executor |
| Independent admission policy | Unsafe create denied even with executor's token |
| Exact manifest tampering | Rejected before valid signed creation |
| Signed release execution | Real Deployment created and independently GET-verified |
| Replay | Rejected |
| New executor instance | Read-only recovery observed the same Deployment UID |
| Workload rollout | Deployment successfully rolled out |
| Runtime image | Pod imageID matched the independently measured registry digest |
| Restricted executor RBAC | Actual-token checks denied Secrets, RBAC writes, Pod exec and cross-namespace creation |
| Teardown | kind deleted the test cluster's node |

Deployment UID: `bcb20f4f-d02f-40d4-a269-2c7540c89ee2`, observed resourceVersion `544`.
Pod UID: `b832b8df-d142-445d-9add-0b69f2b98fb9`.
Measured authorized image and reported running imageID:
`registry.k8s.io/pause@sha256:278fb9dbcca9518083ad1e11276933a2e96f23de604a3a08cc3c80002767d24c`.

Earlier harness attempts stopped on client executable/home permissions and a
case-sensitive check for kubectl's lowercase "forbidden" message. The final run
used a shared copy of the installed kubectl executable, private per-UID homes and
an explicit API-denial check. These failures were not counted as passing tests.
The image-byte measurement is not publisher authentication or build provenance.
The test signer is a generated fixture inside the test process, not an independent
production signing authority or workload attestation service.

Raw successful logs: [Linux verification](evidence/linux-final-verification.log)
and [Kubernetes integration](evidence/kubernetes-integration.log).

## GitHub checks and unresolved account restrictions

The configured main-branch Go matrix has **not executed on hosted runners**.
[Run 41203479229](https://github.com/EdwinJdevops/trust-boundary/actions/runs/41203479229)
reported failure for both matrix jobs before any steps started. GitHub's check
annotations state that recent account payments failed or the spending limit needs
to be increased. Successful Dependabot maintenance runs are not Go CI evidence.
The manual Kubernetes workflow has not been dispatched on hosted runners.

The branch-protection API returned HTTP 403 requiring GitHub Pro or a public
repository. Visibility and billing were not changed; required checks are not
server-enforced. No cloud resources were provisioned. Local downloaded images may
remain cached; test clusters and temporary credentials were removed by teardown.

Remaining security gates are in [ARCHITECTURE.md](ARCHITECTURE.md): independent
signing/attestation and provenance, protected credential lifecycle, full
post-admission verification, network/kernel isolation, remote audit integrity,
distributed replay and actual process/power-loss failure injection. The historical
same-UID bypass remains preserved. This is not production ready.
