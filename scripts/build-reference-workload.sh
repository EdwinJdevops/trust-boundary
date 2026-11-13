#!/usr/bin/env bash
set -euo pipefail
umask 077
[[ $# == 2 && $1 =~ ^[a-f0-9]{40}$ ]] || { echo 'usage: build-reference-workload.sh FULL_COMMIT NEW_OUTPUT_DIRECTORY' >&2; exit 1; }
commit=$1
output=$2
repo=$(cd "$(dirname "$0")/.." && pwd)
[[ $(git -c safe.directory="$repo" -C "$repo" rev-parse HEAD) == "$commit" ]] || { echo 'HEAD differs from requested commit' >&2; exit 1; }
[[ ! -e $output && ! -L $output ]] || { echo 'new output directory required' >&2; exit 1; }
mkdir -- "$output"
output=$(cd "$output" && pwd)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
mkdir "$work/source" "$work/image"
git -c safe.directory="$repo" -C "$repo" archive --format=tar "$commit" > "$work/source.tar"
tar -xf "$work/source.tar" -C "$work/source"
(
  cd "$work/source"
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 GOENV=off GOFLAGS= GOTOOLCHAIN=local GOWORK=off GOPROXY=off GOSUMDB=off \
    go build -trimpath -buildvcs=false -o "$work/image/tbworkload" ./cmd/tbworkload
)
cp "$work/source/deploy/reference-workload/Dockerfile" "$work/image/Dockerfile"
docker buildx build --platform linux/amd64 --provenance=false --sbom=false \
  --network=none --output "type=oci,dest=$work/image.oci.tar" "$work/image"
tar -xOf "$work/image.oci.tar" index.json > "$work/index.json"
digest=$(jq -er '.manifests | if length == 1 and .[0].mediaType == "application/vnd.oci.image.manifest.v1+json" and .[0].platform.os == "linux" and .[0].platform.architecture == "amd64" then .[0].digest else error("expected one Linux amd64 OCI manifest") end' "$work/index.json")
[[ $digest =~ ^sha256:[a-f0-9]{64}$ ]] || { echo 'invalid OCI digest' >&2; exit 1; }
tar -xOf "$work/image.oci.tar" "blobs/sha256/${digest#sha256:}" > "$work/manifest.json"
[[ $(sha256sum "$work/manifest.json" | cut -d' ' -f1) == "${digest#sha256:}" ]] || { echo 'manifest digest mismatch' >&2; exit 1; }
cp "$work/image.oci.tar" "$output/workload.oci.tar"
cp "$work/manifest.json" "$output/release-manifest.json"
jq -n --arg commit "$commit" --arg digest "$digest" \
  --arg source "$(sha256sum "$work/source.tar" | cut -d' ' -f1)" \
  --arg archive "$(sha256sum "$output/workload.oci.tar" | cut -d' ' -f1)" \
  '{commit:$commit,manifest_digest:$digest,source_sha256:$source,archive_sha256:$archive}' \
  > "$output/build-record.json"
cat "$output/build-record.json"
