#!/usr/bin/env bash
# Trusted supervisor for REVIEWED source on a dedicated disposable Linux host.
# Tests are arbitrary code: this is UID separation, not a hardened sandbox.
set -euo pipefail
umask 077
[[ $(id -u) == 0 && $(uname -s) == Linux && $(uname -m) == x86_64 ]] || { echo 'Linux amd64 root supervisor required for the separate-UID cluster test'; exit 1; }
[[ ( $# == 2 || $# == 3 ) && $1 =~ ^[a-f0-9]{40}$ ]] || { echo 'usage: verify-commit.sh FULL_COMMIT NEW_OUTPUT_DIRECTORY [PINNED_PUBLIC_IMAGE]'; exit 1; }
expected=$1
output=$2
repo=$(cd "$(dirname "$0")/.." && pwd)
[[ $(git -c safe.directory="$repo" -C "$repo" rev-parse HEAD) == "$expected" ]] || { echo 'HEAD differs from requested commit'; exit 1; }
[[ -z $(git -c safe.directory="$repo" -C "$repo" status --porcelain --untracked-files=all) ]] || { echo 'clean committed source required'; exit 1; }
if git -c safe.directory="$repo" -C "$repo" ls-tree -r "$expected" | grep -Eq '^(120000|160000) '; then
  echo 'symlinks and submodules require a separate validation design'; exit 1
fi
for reserved in 21001 21002 21003; do
  if getent passwd "$reserved" >/dev/null || ps -eo uid= | awk -v uid="$reserved" '$1 == uid { found=1 } END { exit !found }'; then
    echo 'reserved test UIDs must not belong to existing users or active processes'; exit 1
  fi
done
[[ ! -e $output && ! -L $output ]] || { echo 'refusing to overwrite evidence'; exit 1; }
mkdir -m 700 -- "$output"
output=$(cd "$output" && pwd)
work=$(mktemp -d /tmp/trust-boundary-verify.XXXXXXXX)
cleanup() {
  local status=$?
  if [[ $status != 0 && ! -e $output/outcome.json ]]; then
    printf '{"status":"failed","phase":"supervisor","exit_code":%s}\n' "$status" > "$output/outcome.json"
  fi
  [[ $work == /tmp/trust-boundary-verify.* ]] && rm -rf -- "$work"
  return "$status"
}
trap cleanup EXIT
chmod 755 "$work"
mkdir "$work/source" "$work/worker" "$work/supervisor" "$output/logs"
chmod 755 "$work/source"
chown 21003:21003 "$work/worker"
safe_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
go_bin=$(command -v go)
kubectl_bin=$(command -v kubectl)
# Copy an existing installed tool out of a potentially private operator home.
cp "$kubectl_bin" "$work/kubectl"; chmod 755 "$work/kubectl"
git -c safe.directory="$repo" -C "$repo" archive --format=tar "$expected" > "$output/source.tar"
[[ $(stat -c %s "$output/source.tar") -le 134217728 ]] || { echo 'source archive exceeds 128 MiB'; exit 1; }
tar -C "$work/source" -xf "$output/source.tar"
chmod -R a+rX,go-w "$work/source"
# The suite binds the trusted harness, recorder/verifier, and cluster policy.
(
  cd "$repo"
  sha256sum scripts/verify-commit.sh scripts/integration.sh deploy/kubernetes/test-boundary.yaml \
    cmd/tbverify/main.go cmd/tbattest/main_linux.go internal/evidencefiles/files.go evidence/evidence.go
) > "$output/suite.sha256"
started=$(date +%s)
goversion=$(env -i PATH="$safe_path" HOME="$work/supervisor" GOENV=off GOTOOLCHAIN=local GOWORK=off "$go_bin" version)
{
  printf 'go: %s\n' "$goversion"
  git --version
  env -i PATH="$safe_path" HOME="$work/supervisor" "$work/kubectl" version --client
  timeout 30 env -i PATH="$safe_path" HOME="$work/supervisor" docker info --format 'docker: {{.ServerVersion}}'
  uname -sr
} > "$output/logs/environment.log" 2>&1
worker() {
  setpriv --reuid 21003 --regid 21003 --clear-groups env -i \
    PATH="$safe_path" HOME="$work/worker" GOCACHE="$work/worker/cache" \
    GOMODCACHE="$work/worker/modules" GOPATH="$work/worker/gopath" \
    GOENV=off GOTOOLCHAIN=local GOWORK=off GOPROXY=off GOSUMDB=off \
    "$@"
}
statuses=()
check() {
  local name=$1; shift
  printf 'Running %s\n' "$name"
  local status=0
  { printf 'check=%s commit=%s\n' "$name" "$expected"; "$@"; } 2>&1 | head -c 33554433 > "$output/logs/$name.log" || status=$?
  if [[ $(stat -c %s "$output/logs/$name.log") -gt 33554432 ]]; then status=65; fi
  statuses+=(--check "$name=$status")
  if [[ $status != 0 ]]; then
    printf 'FAILED %s exit=%s; unsigned success statement will not be produced\n' "$name" "$status"
    printf '{"status":"failed","commit":"%s","check":"%s","exit_code":%s}\n' "$expected" "$name" "$status" > "$output/outcome.json"
    cat "$output/logs/$name.log"
    exit "$status"
  fi
}
cd "$work/source"
check format worker timeout 120 bash -euo pipefail -c 'changed=$(find . -type f -name "*.go" -print0 | xargs -0 -r gofmt -l); test -z "$changed"'
check build worker timeout 600 bash -euo pipefail -c '"$1" build ./...; "$1" build -trimpath -buildvcs=false -o "$2" ./cmd/tbverify' build "$go_bin" "$work/worker/tbverify"
# The source archive is read-only to the worker; only its private build/cache
# directory is writable. No GitHub, cluster or signing credentials are supplied.
cp "$work/worker/tbverify" "$output/tbverify"
subject="$output/tbverify"
integration_args=()
if [[ $# == 3 ]]; then
  subject="$output/release-manifest.json"
  integration_args=("$3" "$subject")
fi
check vet worker timeout 600 "$go_bin" vet ./...
check race worker timeout 600 "$go_bin" test -race -count=1 -coverprofile="$work/worker/coverage.out" ./...
check integration-compile worker timeout 600 "$go_bin" test -c -tags integration -o "$work/worker/integration.test" ./kubeexecutor
check archive-integrity worker timeout 120 bash -euo pipefail -c 'sed "s#history/#docs/history/archives/#" docs/history/HISTORY_SHA256SUMS.txt | sha256sum -c -'
# The reviewed integration harness creates only a fresh kind cluster. It has no
# persistent cloud credentials. This root stage is NOT safe for arbitrary code.
check kubernetes timeout 1200 env -i PATH="$work:$safe_path" HOME="$work/supervisor" \
  GOCACHE="$work/supervisor/cache" GOMODCACHE="$work/supervisor/modules" GOPATH="$work/supervisor/gopath" \
  GOENV=off GOTOOLCHAIN=local GOWORK=off GOPROXY=off GOSUMDB=off \
  bash "$work/source/scripts/integration.sh" "${integration_args[@]}"
cp "$work/worker/coverage.out" "$output/coverage.out"
# Use a supervisor-built recorder from the reviewed source, not an executable
# potentially modified by worker tests. No private key is present in this stage.
timeout 600 env -i PATH="$safe_path" HOME="$work/supervisor" GOCACHE="$work/supervisor/cache" \
  GOENV=off GOTOOLCHAIN=local GOWORK=off GOPROXY=off GOSUMDB=off \
  "$go_bin" build -trimpath -buildvcs=false -o "$work/recorder" ./cmd/tbverify
[[ $(sha256sum "$work/recorder" | cut -d' ' -f1) == $(sha256sum "$output/tbverify" | cut -d' ' -f1) ]] || { echo 'worker artifact differs from supervisor rebuild'; exit 1; }
finished=$(date +%s)
timeout 120 "$work/recorder" record --commit "$expected" --source "$output/source.tar" \
  --artifact "$subject" --suite "$output/suite.sha256" --logs "$output/logs" \
  --go-version "$goversion" --started-at "$started" --finished-at "$finished" \
  "${statuses[@]}" > "$output/statement.json"
timeout 120 "$work/recorder" inspect --statement "$output/statement.json" --logs "$output/logs" \
  --source "$output/source.tar" --artifact "$subject" --suite "$output/suite.sha256" > "$output/integrity.json"
printf '{"status":"passed","authentication":"not-verified","commit":"%s"}\n' "$expected" > "$output/outcome.json"
echo 'PASS: complete commit-bound local validation; evidence is unsigned and not independently authenticated'
