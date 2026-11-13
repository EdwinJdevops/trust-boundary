#!/usr/bin/env bash
# Run as root only on a dedicated disposable Linux test host with Docker, Go,
# curl, sha256sum, setpriv and kubectl. Never uses the caller's kubeconfig.
set -euo pipefail
umask 077
[[ $(id -u) == 0 ]] || { echo 'root is required to test separate Unix UIDs'; exit 1; }
[[ $# == 0 || $# == 2 ]] || { echo 'usage: integration.sh [REGISTRY/REPOSITORY@sha256:DIGEST NEW_MANIFEST_FILE]'; exit 1; }
image=${1:-}
manifest_output=${2:-}
if [[ $# == 2 ]]; then
  [[ $image =~ ^[a-z0-9]+([.-][a-z0-9]+)+/[a-z0-9][a-z0-9._/-]*@sha256:[a-f0-9]{64}$ && $image != *..* && $image != *//* ]] || { echo 'explicit public registry image pinned by SHA-256 required'; exit 1; }
  [[ -n $manifest_output && ! -e $manifest_output && ! -L $manifest_output ]] || { echo 'new manifest output file required'; exit 1; }
fi
repo=$(cd "$(dirname "$0")/.." && pwd)
run=$(mktemp -d /tmp/trust-boundary-integration.XXXXXXXX)
cluster="tb-test-$(basename "$run" | tr '[:upper:]' '[:lower:]' | tail -c 9)"
created=0
cleanup() {
  if [[ $created == 1 ]]; then "$run/kind" delete cluster --name "$cluster"; fi
  # This exact directory was created by mktemp above, never a user supplied path.
  [[ $run == /tmp/trust-boundary-integration.* ]] && rm -rf -- "$run"
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
chmod 755 "$run"
# Reuse the installed client while making its executable accessible to both test
# UIDs; a developer's private home directory must not affect API-denial evidence.
cp "$(command -v kubectl)" "$run/kubectl"
chmod 755 "$run/kubectl"
export KUBECONFIG="$run/admin.kubeconfig"
kind_version=v0.33.0
curl --connect-timeout 15 --max-time 120 --retry 2 -fsSL "https://github.com/kubernetes-sigs/kind/releases/download/$kind_version/kind-linux-amd64" -o "$run/kind"
expected=$(curl --connect-timeout 15 --max-time 120 --retry 2 -fsSL "https://github.com/kubernetes-sigs/kind/releases/download/$kind_version/kind-linux-amd64.sha256sum" | awk '{print $1}')
printf '%s  %s\n' "$expected" "$run/kind" | sha256sum -c -
chmod 755 "$run/kind"
created=1
"$run/kind" create cluster --name "$cluster" --kubeconfig "$KUBECONFIG" --wait 180s \
  --image kindest/node:v1.35.8@sha256:07b2536e30b803ed61d1677a79df6115f798ce64c80f9e22f6ed45afd09323c0
kubectl apply -f "$repo/deploy/kubernetes/test-boundary.yaml"
# Verify policy compilation; admission-policy type warnings invalidate this gate.
warnings=$(kubectl get validatingadmissionpolicy trust-boundary-experiment -o jsonpath='{.status.typeChecking.expressionWarnings}')
[[ -z $warnings || $warnings == '[]' ]] || { printf 'Policy warnings: %s\n' "$warnings"; exit 1; }
mkdir "$run/executor" "$run/caller"
chmod 700 "$run/executor" "$run/caller"
kubectl -n tb-control create token executor --duration=10m > "$run/executor/token"
kubectl -n tb-caller create token caller --duration=10m > "$run/caller/token"
chmod 400 "$run/executor/token" "$run/caller/token"
server=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d > "$run/ca.crt"
chmod 444 "$run/ca.crt"
cat > "$run/caller/kubeconfig" <<EOF
apiVersion: v1
kind: Config
clusters:
- name: test
  cluster:
    server: $server
    certificate-authority: $run/ca.crt
users:
- name: caller
  user:
    tokenFile: $run/caller/token
contexts:
- name: test
  context: {cluster: test, user: caller, namespace: staging}
current-context: test
EOF
chown -R 21001:21001 "$run/executor"
chown -R 21002:21002 "$run/caller"
sed "s#$run/caller/token#$run/executor/token#g" "$run/caller/kubeconfig" > "$run/executor/kubeconfig"
chown 21001:21001 "$run/executor/kubeconfig"
# Positive authentication (actual credentials, no admin impersonation).
setpriv --reuid 21002 --regid 21002 --clear-groups env HOME="$run/caller" \
  "$run/kubectl" --kubeconfig "$run/caller/kubeconfig" auth whoami
if setpriv --reuid 21002 --regid 21002 --clear-groups cat "$run/executor/token" >/dev/null 2>&1; then
  echo 'FAIL: caller read executor token'; exit 1
fi
echo 'PASS: separate Unix UID cannot read executor token'
if setpriv --reuid 21002 --regid 21002 --clear-groups env HOME="$run/caller" \
  "$run/kubectl" --kubeconfig "$run/caller/kubeconfig" create deployment bypass --image=registry.k8s.io/pause:3.10.1 -n staging >"$run/denied" 2>&1; then
  echo 'FAIL: caller bypassed executor'; exit 1
fi
if ! grep -qi 'is forbidden' "$run/denied"; then cat "$run/denied"; echo 'FAIL: denial was not an API Forbidden response'; exit 1; fi
echo 'PASS: direct caller mutation rejected with Forbidden'
setpriv --reuid 21001 --regid 21001 --clear-groups env HOME="$run/executor" \
  "$run/kubectl" --kubeconfig "$run/executor/kubeconfig" auth whoami
kubectl create deployment app --image=registry.k8s.io/pause:3.10.1 -n staging --dry-run=client -o json > "$run/unsafe.json"
chmod 444 "$run/unsafe.json"
if setpriv --reuid 21001 --regid 21001 --clear-groups env HOME="$run/executor" \
  "$run/kubectl" --kubeconfig "$run/executor/kubeconfig" create -f "$run/unsafe.json" > "$run/admission-denied" 2>&1; then
  echo 'FAIL: admission accepted an unsafe executor request'; exit 1
fi
if ! grep -q trust-boundary-experiment "$run/admission-denied"; then cat "$run/admission-denied"; exit 1; fi
echo 'PASS: actual executor token cannot bypass cluster workload-shape policy'
# Measure exact OCI registry manifest/index response bytes; this is integrity,
# not a publisher signature or build provenance assertion.
manifest_url=https://registry.k8s.io/v2/pause/manifests/3.10.1
manifest_auth=()
if [[ -n $image ]]; then
  repository=${image%@*}
  manifest_url="https://${repository%%/*}/v2/${repository#*/}/manifests/${image##*@}"
  if [[ ${repository%%/*} == ghcr.io ]]; then
    token=$(curl --disable --proto '=https' --connect-timeout 15 --max-time 30 --max-filesize 65536 -fsS \
      --get --data-urlencode 'service=ghcr.io' --data-urlencode "scope=repository:${repository#*/}:pull" \
      https://ghcr.io/token | jq -er '.token | select(type == "string" and test("^[A-Za-z0-9._+/=-]+$"))')
    manifest_auth=(-H "Authorization: Bearer $token")
  fi
fi
curl --disable --proto '=https' --proto-redir '=https' --max-filesize 4194304 \
  --connect-timeout 15 --max-time 120 --retry 2 -fsSL -H 'Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json' \
  "${manifest_auth[@]}" "$manifest_url" -o "$run/artifact.json"
measured=$(sha256sum "$run/artifact.json" | cut -d' ' -f1)
if [[ -n $image ]]; then
  [[ ${image##*@} == "sha256:$measured" ]] || { echo 'registry response differs from pinned digest'; exit 1; }
else
  image="registry.k8s.io/pause@sha256:$measured"
fi
chmod 444 "$run/artifact.json"
cd "$repo"
go test -c -tags integration -o "$run/integration.test" ./kubeexecutor
chmod 755 "$run/integration.test"
setpriv --reuid 21001 --regid 21001 --clear-groups env \
  TB_REAL_CLUSTER=1 TB_SERVER="$server" TB_CA="$run/ca.crt" \
  TB_TOKEN="$run/executor/token" TB_JOURNAL="$run/executor" TB_ARTIFACT="$run/artifact.json" TB_IMAGE="$image" \
  "$run/integration.test" -test.v -test.run '^TestRealKubernetes$'
kubectl -n staging rollout status deployment/app --timeout=120s
# Printing an imageID is not a verification gate. Require exactly the expected
# fresh running Pod/container and compare the runtime-reported digest with the
# independently measured registry response bytes used by the release fixture.
expected_image=$image
observed=$(kubectl -n staging get pods -l app=app -o go-template='{{len .items}}{{"\n"}}{{range .items}}{{.metadata.uid}} {{.status.phase}} {{if .metadata.deletionTimestamp}}terminating{{else}}active{{end}} {{len .status.containerStatuses}}{{range .status.containerStatuses}} {{.ready}} {{.imageID}}{{end}}{{"\n"}}{{end}}')
check_running_pod() {
  local expected=$1 pod_uid phase lifecycle containers ready image_id extra
  local -a rows
  mapfile -t rows <<< "$observed"
  [[ ${#rows[@]} == 2 && ${rows[0]} == 1 ]] || return 1
  read -r pod_uid phase lifecycle containers ready image_id extra <<< "${rows[1]}"
  [[ -n $pod_uid && $phase == Running && $lifecycle == active && $containers == 1 && $ready == true && $image_id == "$expected" && -z $extra ]]
}
check_running_pod "$expected_image" || { echo 'FAIL: running Pod identity/readiness/image differs from authorized fixture'; exit 1; }
# Exercise this gate's negative path against the same actual runtime observation.
if check_running_pod "${image%@*}@sha256:0000000000000000000000000000000000000000000000000000000000000000"; then
  echo 'FAIL: rollout image gate accepted an unrelated artifact'; exit 1
fi
printf 'PASS: running Pod matches measured artifact; one ready container; unrelated digest rejected\n%s\n' "$observed"
# Verify that RBAC denies credentials, RBAC mutation and cross-namespace writes.
for check in 'get secrets -n staging' 'create roles -n staging' 'create deployments -n default' 'create pods/exec -n staging'; do
  read -r -a args <<< "$check"
  [[ $(setpriv --reuid 21001 --regid 21001 --clear-groups env HOME="$run/executor" "$run/kubectl" --kubeconfig "$run/executor/kubeconfig" auth can-i "${args[@]}" || true) == no ]] || exit 1
done
echo 'PASS: executor cannot read secrets, mutate RBAC, exec into Pods or create outside staging'
if [[ -n $manifest_output ]]; then
  (set -o noclobber; cat "$run/artifact.json" > "$manifest_output")
fi
echo 'PASS: disposable cluster test complete; teardown follows'
