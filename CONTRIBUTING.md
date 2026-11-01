# Contributing

This is an experimental security control-plane research project. Every change
must preserve documented negative findings and distinguish configured controls
from executed evidence. Never add production tokens, private keys or kubeconfigs.

Use a supported Go toolchain on Linux. Run `gofmt`, `go build ./...`,
`go vet ./...` and `go test -race -count=1 ./...`. The standard library is the only
runtime dependency. Compile tagged integration tests separately.

Run `sudo env "PATH=$PATH" bash scripts/integration.sh` only on a dedicated
disposable Linux test host with Docker and kubectl. The script creates an isolated
kind cluster, temporary short-lived credentials and separate Unix UIDs; its EXIT
trap tears the cluster down. It never uses an existing kubeconfig. The manual CI
workflow runs the same fixture without cloud account credentials.

Do not weaken fail-closed replay permissions to make Windows tests pass. Windows
builds are useful compile checks, not Linux durability or isolation evidence.
Record exact source revision, tool versions, commands, failures and limitations
when reporting test results. CI passing is not an external security audit.

For a complete commit-bound run and independently inspectable evidence, use
`scripts/verify-commit.sh` as described in [portable validation](docs/PORTABLE_VALIDATION.md).
Never turn local unsigned results into a claim of independent review.
