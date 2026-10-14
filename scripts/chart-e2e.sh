#!/usr/bin/env bash
# Install the chart into a kind cluster and walk a model through the airlock.
#
#   scripts/chart-e2e.sh            (needs docker, kind, kubectl, helm, go, curl, jq, python3)
#
# It builds the release binaries and the image from this checkout, loads the
# image into the kind cluster named by KIND_CLUSTER (default "kind"), and
# installs the chart into a namespace that enforces the "restricted" Pod
# Security Standard. Then, through kubectl port-forward, the way an operator
# reaches the wizard:
#
#   - the API is healthy, its store is ready, and the wizard is served;
#   - a tiny safetensors model mounted into the pod, under a scan root, scans
#     to a withheld report, and a path outside the scan roots is refused;
#   - promotion refuses a report signed by an untrusted key, and refuses the
#     withheld one signed by the trusted key;
#   - it promotes the report re-issued with a signed acceptance, which needs
#     both trust ConfigMaps to have reached the store;
#   - the activity log's hash chain verifies.
#
# Then it turns on the read-only hub endpoint: it serves the promoted bytes,
# which hash to the attestation, and the attestation, and answers 404 for a
# hash the store does not hold; its NetworkPolicy admits a labelled pod in a
# labelled namespace and not an unlabelled one.
#
# Then it exposes the API as a Service and checks the NetworkPolicy: a pod in
# the release's namespace reaches it, a pod in another namespace does not.
# Finally it uninstalls and checks the store's claim was kept.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cluster="${KIND_CLUSTER:-kind}"
ns=socair-e2e
other=socair-e2e-other
models=socair-e2e-models
rel=intake
dep="$rel-socair"
version=0.0.0-e2e
port=18080
hubport=18081
tmp="$(mktemp -d)"
pf=""
cleanup() {
	[[ -n "$pf" ]] && kill "$pf" 2>/dev/null || true
	rm -rf "$tmp"
}
trap cleanup EXIT

step() { printf '\n== %s\n' "$*"; }
sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi | cut -d' ' -f1; }
fail() { echo "FAIL: $*" >&2; exit 1; }

step "build the release binaries and the image"
(cd "$root" && scripts/build-release.sh "$version" dist >/dev/null)
X="$root/dist/socair_${version}_$(go env GOOS)_$(go env GOARCH)"
docker build -q --build-arg VERSION="$version" -t socair:e2e "$root" >/dev/null
kind load docker-image socair:e2e --name "$cluster" >/dev/null

step "keys, a tiny model, and a restricted namespace"
(cd "$tmp" && "$X" key gen --out op --issuer "e2e operator" >/dev/null &&
	"$X" key gen --out ciso >/dev/null && "$X" key gen --out stranger >/dev/null)
python3 - "$tmp/tiny.safetensors" <<'EOF'
import json, struct, sys
hdr = json.dumps({"w": {"dtype": "F32", "shape": [2], "data_offsets": [0, 8]}}, separators=(",", ":")).encode()
hdr += b" " * ((8 - len(hdr) % 8) % 8)
open(sys.argv[1], "wb").write(struct.pack("<Q", len(hdr)) + hdr + struct.pack("<2f", 1.0, 2.0))
EOF
kubectl create namespace "$ns" >/dev/null
kubectl label namespace "$ns" pod-security.kubernetes.io/enforce=restricted >/dev/null
kubectl -n "$ns" create configmap socair-trusted-keys --from-file="$tmp/op.pub" >/dev/null
kubectl -n "$ns" create configmap socair-acceptor-keys --from-file="$tmp/ciso.pub" >/dev/null
kubectl -n "$ns" create configmap tiny-model --from-file="$tmp/tiny.safetensors" >/dev/null

step "install the chart"
helm install "$rel" "$root/charts/socair" -n "$ns" --wait --timeout 5m \
	--set image.repository=socair --set image.tag=e2e --set image.pullPolicy=Never \
	--set persistence.size=1Gi \
	--set trust.trustedKeysConfigMap=socair-trusted-keys \
	--set trust.acceptorKeysConfigMap=socair-acceptor-keys \
	--set-json 'extraVolumes=[{"name":"models","configMap":{"name":"tiny-model"}}]' \
	--set-json 'extraVolumeMounts=[{"name":"models","mountPath":"/models","readOnly":true}]' \
	--set-json 'scanRoots=["/models"]' >/dev/null
kubectl -n "$ns" exec "deploy/$dep" -c socair -- socair health

step "reach the wizard through port-forward"
kubectl -n "$ns" port-forward "deploy/$dep" "$port:8080" >/dev/null 2>&1 &
pf=$!
base="http://127.0.0.1:$port"
for _ in $(seq 1 30); do curl -fsS "$base/api/health" >/dev/null 2>&1 && break; sleep 1; done
[[ "$(curl -fsS "$base/api/health" | jq -r .store)" == ready ]] || fail "store is not ready"
[[ "$(curl -fsS "$base/api/version" | jq -r .version)" == "$version" ]] || fail "wrong version"
curl -fsS "$base/" | grep -qi '<!doctype html' || fail "the wizard is not served"

api() { # api <path> <json body file> -> body on stdout, HTTP status in $tmp/status
	curl -sS -o "$tmp/body" -w '%{http_code}' -H 'Content-Type: application/json' \
		--data-binary @"$2" "$base$1" >"$tmp/status"
	cat "$tmp/body"
}
promote() { # promote <envelope file>
	jq -n --arg a /models/tiny.safetensors --slurpfile e "$1" '{artifact: $a, attestation: $e[0]}' >"$tmp/req"
	api /api/airlock/promote "$tmp/req"
}

step "scan the mounted model"
echo '{"path":"/models/tiny.safetensors"}' >"$tmp/req"
api /api/scan "$tmp/req" | jq .report >"$tmp/r.json"
[[ "$(cat "$tmp/status")" == 200 ]] || fail "scan answered $(cat "$tmp/status"): $(cat "$tmp/body")"
[[ "$(jq -r .promotion_authorization.state "$tmp/r.json")" == withheld ]] || fail "expected a withheld report"

step "the API refuses a path outside its scan roots"
for p in /store/log.jsonl /models/../store/log.jsonl /etc/passwd; do
	jq -n --arg p "$p" '{path: $p}' >"$tmp/req"
	api /api/scan "$tmp/req" >/dev/null
	if [[ "$(cat "$tmp/status")" != 422 ]] || ! grep -q 'scan root' "$tmp/body"; then
		fail "scanning $p answered $(cat "$tmp/status"): $(cat "$tmp/body")"
	fi
done

step "the gate refuses an untrusted signer and a withheld report"
cp "$tmp/r.json" "$tmp/s.json"
(cd "$tmp" && "$X" sign --key stranger.key --report s.json >/dev/null && "$X" sign --key op.key --report r.json >/dev/null)
promote "$tmp/s.dsse.json" >/dev/null
[[ "$(cat "$tmp/status")" != 200 ]] || fail "promoted a report signed by an untrusted key"
promote "$tmp/r.dsse.json" >/dev/null
[[ "$(cat "$tmp/status")" != 200 ]] || fail "promoted a withheld report"

step "it promotes the report re-issued with a signed acceptance"
expires="$(date -u -d '+1 day' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v+1d +%Y-%m-%dT%H:%M:%SZ)"
(cd "$tmp" &&
	"$X" accept --attestation r.dsse.json --trusted op.pub --key ciso.key --by "e2e ciso" --expires "$expires" >/dev/null &&
	"$X" sign --key op.key --attestation r.dsse.json --acceptance r.acceptance.dsse.json --trusted op.pub --acceptors ciso.pub >/dev/null)
promote "$tmp/r.conditional.dsse.json" >/dev/null
[[ "$(cat "$tmp/status")" == 200 ]] || fail "promote answered $(cat "$tmp/status"): $(cat "$tmp/body")"
kubectl -n "$ns" exec "deploy/$dep" -c socair -- socair airlock log --store /store --verify

step "the hub endpoint serves the promoted model, read-only"
kill "$pf" 2>/dev/null || true
pf=""
helm upgrade "$rel" "$root/charts/socair" -n "$ns" --reuse-values --wait --timeout 5m --set hub.enabled=true >/dev/null
kubectl -n "$ns" port-forward "deploy/$dep" "$hubport:8081" >/dev/null 2>&1 &
pf=$!
hubbase="http://127.0.0.1:$hubport"
for _ in $(seq 1 30); do curl -fsS "$hubbase/api/health" >/dev/null 2>&1 && break; sleep 1; done
subject="$(jq -r .artifact.sha256 "$tmp/r.json")"
curl -fsS "$hubbase/sha256/$subject/resolve/main/tiny.safetensors" -o "$tmp/served"
[[ "$(sha256 <"$tmp/served")" == "$subject" ]] || fail "the served bytes do not hash to the attestation"
curl -fsS "$hubbase/api/socair/attestations/$subject" | jq -e '.payloadType and (.payload | length > 0)' >/dev/null ||
	fail "the attestation is not served"
unknown="$(curl -sS -o /dev/null -w '%{http_code}' "$hubbase/sha256/$(printf x | sha256)/resolve/main/x")"
[[ "$unknown" == 404 ]] || fail "a hash the store does not hold answered $unknown"
kill "$pf" 2>/dev/null || true
pf=""
hubclient() { # hubclient <namespace> <name> <pod labels>: socair health against the hub Service
	local o
	o=$(jq -nc --argjson l "$3" '{metadata: {labels: $l}, spec: {securityContext: {runAsNonRoot: true, seccompProfile: {type: "RuntimeDefault"}},
		containers: [{name: "c", image: "socair:e2e", imagePullPolicy: "Never",
			args: ["health", "--addr", "'"$dep-hub.$ns"'.svc:8081"],
			securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: ["ALL"]}}}]}}')
	kubectl -n "$1" run "$2" --image=socair:e2e --restart=Never --overrides="$o" >/dev/null
	local phase=""
	for _ in $(seq 1 90); do
		phase=$(kubectl -n "$1" get "pod/$2" -o jsonpath='{.status.phase}')
		[[ "$phase" == Succeeded || "$phase" == Failed ]] && break
		sleep 1
	done
	kubectl -n "$1" logs "pod/$2" >"$tmp/client.log" 2>&1 || true
	echo "  $1/$2 ($phase): $(tr '\n' ' ' <"$tmp/client.log")"
	[[ "$phase" == Succeeded ]]
}
kubectl create namespace "$models" >/dev/null
kubectl label namespace "$models" socair.ai/hub-client=true >/dev/null
kubectl -n "$ns" wait endpointslice -l kubernetes.io/service-name="$dep-hub" \
	--for=jsonpath='{.endpoints[0].conditions.ready}'=true --timeout=60s >/dev/null
reached=""
for i in 1 2 3 4 5; do
	if hubclient "$models" "labelled-$i" '{"socair.ai/hub-client":"true"}'; then reached=1; break; fi
	sleep 3
done
[[ -n "$reached" ]] || fail "a labelled pod in a labelled namespace could not reach the hub endpoint"
if hubclient "$models" unlabelled '{"app":"other"}'; then
	fail "an unlabelled pod reached the hub endpoint through the NetworkPolicy"
fi
grep -Eqi 'timeout|deadline' "$tmp/client.log" || fail "the unlabelled pod failed for another reason"

step "expose the API as a Service"
helm upgrade "$rel" "$root/charts/socair" -n "$ns" --reuse-values --wait --timeout 5m \
	--set service.enabled=true --set service.authenticatingProxy=true >/dev/null
client() { # client <namespace> <name>: run socair health against the Service
	local o
	o=$(jq -nc '{spec: {securityContext: {runAsNonRoot: true, seccompProfile: {type: "RuntimeDefault"}},
		containers: [{name: "c", image: "socair:e2e", imagePullPolicy: "Never",
			args: ["health", "--addr", "'"$dep.$ns"'.svc:8080"],
			securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: ["ALL"]}}}]}}')
	kubectl -n "$1" run "$2" --image=socair:e2e --restart=Never --overrides="$o" >/dev/null
	local phase=""
	for _ in $(seq 1 90); do
		phase=$(kubectl -n "$1" get "pod/$2" -o jsonpath='{.status.phase}')
		[[ "$phase" == Succeeded || "$phase" == Failed ]] && break
		sleep 1
	done
	kubectl -n "$1" logs "pod/$2" >"$tmp/client.log" 2>&1 || true
	echo "  $1/$2 ($phase): $(tr '\n' ' ' <"$tmp/client.log")"
	[[ "$phase" == Succeeded ]]
}
# A ready pod is not yet a routed Service: wait for its endpoint, then allow
# the proxy a few seconds to program it (a Service with no endpoint refuses).
kubectl -n "$ns" wait endpointslice -l kubernetes.io/service-name="$dep" \
	--for=jsonpath='{.endpoints[0].conditions.ready}'=true --timeout=60s >/dev/null
reached=""
for i in 1 2 3 4 5; do
	if client "$ns" "same-namespace-$i"; then reached=1; break; fi
	sleep 3
done
[[ -n "$reached" ]] || fail "a pod in $ns could not reach the Service"
kubectl create namespace "$other" >/dev/null
if client "$other" other-namespace; then
	fail "a pod in another namespace reached the API through the NetworkPolicy"
fi
# Refused for the right reason: the connection was dropped, not a name that
# did not resolve.
grep -Eqi 'timeout|deadline' "$tmp/client.log" || fail "the other namespace failed for another reason"

step "uninstall keeps the store"
helm uninstall "$rel" -n "$ns" >/dev/null
kubectl -n "$ns" get pvc "$dep-store" >/dev/null || fail "the store's claim was deleted"

echo
echo "chart e2e: all checks passed"
