#!/usr/bin/env bash
# Gate a cluster's model pods on Socair bindings with Kyverno, in a kind cluster.
#
#   scripts/admission-e2e.sh        (needs docker, kind, kubectl, helm, go, curl, jq, python3)
#
# It creates its own kind cluster (KIND_CLUSTER, default socair-admission-e2e)
# with a kubeconfig in a temporary directory, so it never reads or changes the
# caller's kubeconfig or contexts, and deletes the cluster and its registry on
# exit (KEEP=1 keeps them, and prints how to reach them). It refuses to start
# if a cluster or container by those names already exists.
#
# The cluster runs a zot registry on kind's network and Kyverno v1.19.1. The
# script builds socair from this checkout, scans five tiny safetensors models
# into attestations (authorized, withheld, conditional under a signed
# acceptance that expires a few minutes later, authorized but signed by an
# untrusted key, and one never attached), pushes each as a ModelPack artifact,
# and runs `socair attach`. Then, with the policies in policies/kyverno (only
# the model repository and the public key filled in):
#
#   - authorized-with-conditions admits the conditional model while its
#     acceptance holds: a pod whose init container is handed oci://<ref>
#     starts, pulls the artifact with oras, and finds the bytes the
#     attestation names;
#   - authorized admits the authorized model in that pod, which starts the
#     same way, and in every place a pod can name it (an image volume, a
#     container and init container as KServe's ModelCar does, with the tag
#     pinned to the verified digest, KServe's oci+fetch:// storage-initializer
#     arguments, an ephemeral container, a Deployment);
#   - it refuses a model with no binding, one bound by an untrusted key, a
#     withheld one, a conditional one, a reference with no digest, and an
#     artifact listing another artifact's binding as its own (the binding's
#     subject is the other digest);
#   - authorized-with-conditions refuses the conditional model once its
#     acceptance has expired;
#   - with the registry stopped, a pod naming the authorized model is refused.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cluster="${KIND_CLUSTER:-socair-admission-e2e}"
reg="$cluster-registry"
ns=socair-admission-e2e
accept_for="${ACCEPT_SECONDS:-120}"

# Pinned: the node image kind v0.33.0 lists for Kubernetes 1.35 (Kyverno 1.19
# supports 1.33 to 1.35), Kyverno's chart 3.9.1 (Kyverno v1.19.1), and the
# images the pods run.
node_image=kindest/node:v1.35.8@sha256:07b2536e30b803ed61d1677a79df6115f798ce64c80f9e22f6ed45afd09323c0
zot_image=ghcr.io/project-zot/zot:v2.1.22@sha256:96cda11459ce6f8c60da3b03f03e9f67fd11b3ae2d82c4c04c92b3c608996080
kyverno_chart=oci://ghcr.io/kyverno/charts/kyverno:3.9.1@sha256:720542b97bdbc2633535c2297332690d21cfbb944053eb1ec1f0dbe8e3895444
oras_image=ghcr.io/oras-project/oras:v1.3.4@sha256:f7bc056d54d97baa399414ed5048ecc67c3371b750d4bbce1d871827a5758179
busybox_image=busybox:1.37@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e

strict="$root/policies/kyverno/socair-model-authorized.yaml"
conditions="$root/policies/kyverno/socair-model-authorized-with-conditions.yaml"

tmp="$(mktemp -d)"
export KUBECONFIG="$tmp/kubeconfig"
made_cluster="" made_registry=""
cleanup() {
	local rc=$?
	if [[ "${KEEP:-}" == 1 ]]; then
		echo "kept: KUBECONFIG=$KUBECONFIG, kind cluster $cluster, registry container $reg"
		return
	fi
	if [[ $rc != 0 && -n "$made_cluster" ]]; then
		echo "== on failure: Kyverno's log" >&2
		kubectl -n kyverno logs deploy/kyverno-admission-controller --tail=40 >&2 2>/dev/null || true
	fi
	[[ -n "$made_cluster" ]] && kind delete cluster --name "$cluster" --kubeconfig "$KUBECONFIG" >/dev/null 2>&1 || true
	[[ -n "$made_registry" ]] && docker rm -f "$reg" >/dev/null 2>&1 || true
	rm -rf "$tmp"
}
trap cleanup EXIT

step() { printf '\n== %s\n' "$*"; }
sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi | cut -d' ' -f1; }
fail() { echo "FAIL: $*" >&2; exit 1; }
now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

step "build socair from this checkout"
(cd "$root" && GOFLAGS=-mod=vendor go build -o "$tmp/socair" ./cmd/socair)
X="$tmp/socair"

step "a kind cluster with its own kubeconfig, and a registry on its network"
kind get clusters 2>/dev/null | grep -x "$cluster" >/dev/null && fail "a kind cluster named $cluster exists; set KIND_CLUSTER"
docker inspect "$reg" >/dev/null 2>&1 && fail "a container named $reg exists; set KIND_CLUSTER"
made_cluster=1
kind create cluster --name "$cluster" --image "$node_image" --kubeconfig "$KUBECONFIG" --wait 120s >"$tmp/kind.log" 2>&1 ||
	{ cat "$tmp/kind.log" >&2; fail "kind could not create the cluster"; }
made_registry=1
docker run -d --name "$reg" --network kind -p 127.0.0.1::5000 "$zot_image" >/dev/null
# The host reaches the registry on a loopback port (socair attach speaks plain
# http only to loopback); the nodes and pods reach it at its address on
# kind's network, which is the name the pods use. Pods cannot resolve the
# container's name, and the address needs no policy change: Kyverno's
# registry client (go-containerregistry v0.21.8) falls back to plain http for
# an RFC 1918 address. The nodes' containerd is told to use http for it.
hostport="$(docker port "$reg" 5000/tcp | sed -n 1p | sed 's/.*://')"
host="127.0.0.1:$hostport"
ip="$(docker inspect -f '{{.NetworkSettings.Networks.kind.IPAddress}}' "$reg")"
[[ -n "$ip" ]] || fail "the registry has no address on kind's network"
incluster="$ip:5000"
for node in $(kind get nodes --name "$cluster"); do
	docker exec "$node" mkdir -p "/etc/containerd/certs.d/$incluster"
	printf '[host."http://%s"]\n' "$incluster" | docker exec -i "$node" cp /dev/stdin "/etc/containerd/certs.d/$incluster/hosts.toml"
done
for _ in $(seq 1 30); do curl -fsS "http://$host/v2/" >/dev/null 2>&1 && break; sleep 1; done
curl -fsS "http://$host/v2/" >/dev/null || fail "the registry does not answer"
kubectl create namespace "$ns" >/dev/null

step "install Kyverno"
helm install kyverno "$kyverno_chart" -n kyverno --create-namespace --wait --timeout 6m \
	--set backgroundController.enabled=false --set cleanupController.enabled=false \
	--set reportsController.enabled=false >/dev/null
kubectl -n kyverno get deploy kyverno-admission-controller -o jsonpath='{.spec.template.spec.containers[0].image}{"\n"}'

step "keys, five tiny models, and their attestations"
cd "$tmp"
"$X" key gen --out op --issuer "e2e operator" >/dev/null
"$X" key gen --out ciso >/dev/null
"$X" key gen --out stranger >/dev/null
model() { # model <name> <value>: a safetensors file with one F32 tensor
	python3 - "$1.safetensors" "$2" <<'EOF'
import json, struct, sys
hdr = json.dumps({"w": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}, separators=(",", ":")).encode()
hdr += b" " * ((8 - len(hdr) % 8) % 8)
open(sys.argv[1], "wb").write(struct.pack("<Q", len(hdr)) + hdr + struct.pack("<f", float(sys.argv[2])))
EOF
}
model authorized 1
model withheld 2
model conditional 3
model stranger 4
model unbound 5
# The operator's inputs that move the trust rows to PASS, so a scan can be
# authorized: a repo mirror, a denylist without this hash, and a provenance
# manifest bound to the file (an e2e fixture, not a real repository).
mkdir mirror && echo '{}' >mirror/config.json
echo '0000000000000000000000000000000000000000000000000000000000000000  e2e-known-bad' >deny.txt
scan_all_inputs() { # scan_all_inputs <name>
	jq -n --arg s "$(sha256 <"$1.safetensors")" '{artifact_sha256: $s, publisher: "e2e", signing_status: "unsigned",
		repo_url: "https://huggingface.co/e2e/fixture", commit_or_tag: "main",
		commit_sha: "71034c5d8bde858ff824298bdedc65515b97d2b9"}' >"$1.provenance.json"
	SOCAIR_REPO_MIRROR="$tmp/mirror" SOCAIR_DENYLIST="$tmp/deny.txt" SOCAIR_PROVENANCE="$tmp/$1.provenance.json" \
		"$X" scan "$1.safetensors" >"$1.json"
}
scan_all_inputs authorized
scan_all_inputs stranger
"$X" scan withheld.safetensors >withheld.json
"$X" scan conditional.safetensors >conditional.json
for want in authorized:authorized stranger:authorized withheld:withheld conditional:withheld; do
	got="$(jq -r .promotion_authorization.state "${want%%:*}.json")"
	[[ "$got" == "${want#*:}" ]] || fail "${want%%:*} scanned to $got, want ${want#*:}"
done
"$X" sign --key op.key --report authorized.json >/dev/null
"$X" sign --key op.key --report withheld.json >/dev/null
"$X" sign --key op.key --report conditional.json >/dev/null
"$X" sign --key stranger.key --report stranger.json >/dev/null
expires="$(date -u -d "+$accept_for seconds" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v+"${accept_for}"S +%Y-%m-%dT%H:%M:%SZ)"
"$X" accept --attestation conditional.dsse.json --trusted op.pub --key ciso.key --by "e2e ciso" --expires "$expires" >/dev/null
"$X" sign --key op.key --attestation conditional.dsse.json --acceptance conditional.acceptance.dsse.json \
	--trusted op.pub --acceptors ciso.pub >/dev/null
echo "conditional acceptance expires $expires"

step "push each as a ModelPack artifact and attach"
blob() { # blob <repo> <file>: upload a blob (POST then PUT), print its digest
	local d loc
	d="sha256:$(sha256 <"$2")"
	loc="$(curl -fsS -o /dev/null -D - -X POST "http://$host/v2/$1/blobs/uploads/" | tr -d '\r' |
		awk 'tolower($1)=="location:"{print $2}')"
	case "$loc" in http*) ;; *) loc="http://$host$loc" ;; esac
	case "$loc" in *\?*) loc="$loc&digest=$d" ;; *) loc="$loc?digest=$d" ;; esac
	curl -fsS -X PUT -H 'Content-Type: application/octet-stream' --data-binary @"$2" "$loc" >/dev/null
	echo "$d"
}
put_manifest() { # put_manifest <repo> <tag or digest> <file>: print the manifest's digest
	curl -fsS -X PUT -H 'Content-Type: application/vnd.oci.image.manifest.v1+json' \
		--data-binary @"$3" "http://$host/v2/$1/manifests/$2" >/dev/null
	echo "sha256:$(sha256 <"$3")"
}
push_model() { # push_model <name> <model> <tag>: models/<model>:<tag>, one raw weight layer; writes <name>.digest
	local layer cfg
	layer="$(blob "models/$2" "$2.safetensors")"
	printf '{"descriptor":{"name":"%s"}}' "$1" >"$1.config.json"
	cfg="$(blob "models/$2" "$1.config.json")"
	# Both file name annotations: ModelPack's, and the one oras pull places
	# files by.
	jq -n --arg l "$layer" --argjson ls "$(wc -c <"$2.safetensors")" --arg c "$cfg" --argjson cs "$(wc -c <"$1.config.json")" \
		--arg f "$2.safetensors" '{schemaVersion: 2, mediaType: "application/vnd.oci.image.manifest.v1+json",
		artifactType: "application/vnd.cncf.model.manifest.v1+json",
		config: {mediaType: "application/vnd.cncf.model.config.v1+json", digest: $c, size: $cs},
		layers: [{mediaType: "application/vnd.cncf.model.weight.v1.raw", digest: $l, size: $ls,
			annotations: {"org.cncf.model.filepath": $f, "org.opencontainers.image.title": $f}}]}' >"$1.manifest.json"
	put_manifest "models/$2" "$3" "$1.manifest.json" >"$1.digest"
}
digest() { cat "$tmp/$1.digest"; }
for n in authorized withheld conditional stranger unbound; do
	push_model "$n" "$n" e2e
	echo "  models/$n@$(digest "$n")"
done
"$X" attach "$host/models/authorized:e2e" --attestation authorized.dsse.json --key op.key --trusted op.pub >/dev/null
"$X" attach "$host/models/withheld:e2e" --attestation withheld.dsse.json --key op.key --trusted op.pub >/dev/null
"$X" attach "$host/models/conditional:e2e" --attestation conditional.conditional.dsse.json --key op.key \
	--trusted op.pub --acceptors ciso.pub >/dev/null
# Bound by a key the policy does not trust: the attestation and the binding
# are both signed with it.
"$X" attach "$host/models/stranger:e2e" --attestation stranger.dsse.json --key stranger.key --trusted stranger.pub >/dev/null
"$X" verify "$host/models/authorized:e2e" --trusted op.pub >verify.txt || { cat verify.txt; fail "socair verify refused the authorized artifact"; }
sed -n '1,2p' verify.txt

step "the falsification: an artifact listing another artifact's binding"
# The twin carries the authorized model's bytes under another config, so its
# manifest digest differs. The authorized artifact's Sigstore bundle referrer
# is pushed again with the twin as its subject: the registry lists it for the
# twin, but the statement it signs is about the authorized digest.
push_model twin authorized twin
bundle="$(curl -fsS "http://$host/v2/models/authorized/referrers/$(digest authorized)" |
	jq -r '[.manifests[] | select(.artifactType == "application/vnd.dev.sigstore.bundle.v0.3+json")][0].digest')"
[[ "$bundle" == sha256:* ]] || fail "the authorized artifact has no Sigstore bundle referrer"
curl -fsS -H 'Accept: application/vnd.oci.image.manifest.v1+json' "http://$host/v2/models/authorized/manifests/$bundle" >bundle.json
jq -c --arg d "$(digest twin)" --argjson s "$(wc -c <twin.manifest.json)" \
	'.subject = {mediaType: "application/vnd.oci.image.manifest.v1+json", digest: $d, size: $s}' bundle.json >moved.json
moved="$(put_manifest models/authorized "sha256:$(sha256 <moved.json)" moved.json)"
curl -fsS "http://$host/v2/models/authorized/referrers/$(digest twin)" >twin.referrers.json
jq -e --arg m "$moved" '[.manifests[] | select(.digest == $m and .artifactType == "application/vnd.dev.sigstore.bundle.v0.3+json")] | length == 1' \
	twin.referrers.json >/dev/null || fail "the registry does not list the moved binding for the twin"
echo "  models/authorized@$(digest twin) lists bundle $moved, whose statement is about $(digest authorized)"

ref() { echo "$incluster/models/$1@$(digest "$1")"; }
twin="$incluster/models/authorized@$(digest twin)"

# A policy as shipped, with the two EDIT values filled in. The check on the
# shipped values makes this fail if the file changes shape under the test.
apply_policy() { # apply_policy <file>
	local key name
	key="$(sed -n '/BEGIN PUBLIC KEY/,/END PUBLIC KEY/p' op.pub)"
	kubectl create --dry-run=client -o json -f "$1" >policy.json
	jq -e '.spec.matchImageReferences == [{glob: "registry.example/models/*"}] and
		(.spec.attestors | length == 1) and (.spec.attestors[0].cosign.key.data | contains("REPLACE-WITH"))' policy.json >/dev/null ||
		fail "$1 no longer has the EDIT values this test fills in"
	jq --arg g "$incluster/models/*" --arg k "$key"$'\n' \
		'.spec.matchImageReferences = [{glob: $g}] | .spec.attestors[0].cosign.key.data = $k' policy.json >policy.applied.json
	name="$(jq -r .metadata.name policy.applied.json)"
	kubectl delete imagevalidatingpolicies --all --wait=true >/dev/null
	kubectl apply -f policy.applied.json >/dev/null
	# Ready, and the resource webhook names this policy and no other.
	for _ in $(seq 1 60); do
		if [[ "$(kubectl get imagevalidatingpolicy "$name" -o jsonpath='{.status.conditionStatus.ready}')" == true ]] &&
			[[ "$(kubectl get validatingwebhookconfiguration kyverno-resource-validating-webhook-cfg -o json |
				jq -r '[.webhooks[].name | select(startswith("ivpol."))] | map(endswith("-" + "'"$name"'")) | all and length > 0')" == true ]]; then
			echo "  $name is ready"
			return
		fi
		sleep 1
	done
	fail "$name did not become ready"
}

# Pod shapes. Each names the model in one place a pod can.
pod_volume() { # an image volume, as KServe's oci+native:// mode and a plain Deployment mount one
	jq -n --arg r "$1" --arg b "$busybox_image" '{apiVersion: "v1", kind: "Pod", metadata: {generateName: "volume-"},
		spec: {restartPolicy: "Never", containers: [{name: "c", image: $b, command: ["true"],
			volumeMounts: [{name: "model", mountPath: "/mnt/models"}]}],
		volumes: [{name: "model", image: {reference: $r, pullPolicy: "IfNotPresent"}}]}}'
}
pod_modelcar() { # the model image as a container and an init container, as KServe's ModelCar adds it
	jq -n --arg r "$1" --arg b "$busybox_image" '{apiVersion: "v1", kind: "Pod", metadata: {generateName: "modelcar-"},
		spec: {restartPolicy: "Never", shareProcessNamespace: true,
		initContainers: [{name: "modelcar-init", image: $r}],
		containers: [{name: "kserve-container", image: $b, command: ["true"]}, {name: "modelcar", image: $r}]}}'
}
pod_fetch() { # an init container handed oci://<ref>, which pulls it with oras; the server checks the bytes
	jq -n --arg r "oci://$1" --arg f "$2" --arg want "$3" --arg o "$oras_image" --arg b "$busybox_image" '{
		apiVersion: "v1", kind: "Pod", metadata: {generateName: "fetch-"},
		spec: {restartPolicy: "Never",
		initContainers: [{name: "fetch-model", image: $o, args: [$r, "/mnt/models"],
			command: ["sh", "-c", "oras pull --plain-http \"${1#oci://}\" -o \"$2\"", "fetch"],
			volumeMounts: [{name: "models", mountPath: "/mnt/models"}]}],
		containers: [{name: "server", image: $b, env: [{name: "WANT", value: ($want + "  /mnt/models/" + $f)}],
			command: ["sh", "-c", "echo \"$WANT\" | sha256sum -c -"],
			volumeMounts: [{name: "models", mountPath: "/mnt/models", readOnly: true}]}],
		volumes: [{name: "models", emptyDir: {}}]}}'
}
pod_kserve_fetch() { # KServe's oci+fetch:// pod: its storage-initializer is given oci://<ref> and a path
	jq -n --arg r "oci://$1" --arg b "$busybox_image" '{apiVersion: "v1", kind: "Pod", metadata: {generateName: "kserve-fetch-"},
		spec: {restartPolicy: "Never",
		initContainers: [{name: "storage-initializer", image: $b, command: ["true"], args: [$r, "/mnt/models"]}],
		containers: [{name: "kserve-container", image: $b, command: ["true"]}]}}'
}

admitted() { # admitted <what> <pod json>: the API server admits it (server dry run, which runs the webhooks)
	local out
	if ! out="$(kubectl -n "$ns" create --dry-run=server -o json -f - <<<"$2" 2>&1)"; then
		fail "$1: refused: $out"
	fi
	echo "  admitted: $1"
	printf '%s' "$out" >last.json
}
refused() { # refused <what> <pod json> <reason>: refused, by Kyverno, for that reason
	local out
	if out="$(kubectl -n "$ns" create --dry-run=server -o name -f - <<<"$2" 2>&1)"; then
		fail "$1: admitted: $out"
	fi
	[[ "$out" == *"socair-model-authorized"* && "$out" == *"$3"* ]] || fail "$1: refused for another reason: $out"
	echo "  refused: $1 ($3)"
}
runs() { # runs <what> <pod json>: create it and wait for it to succeed
	local pod phase=""
	pod="$(kubectl -n "$ns" create -o name -f - <<<"$2")" || fail "$1: refused"
	for _ in $(seq 1 120); do
		phase="$(kubectl -n "$ns" get "$pod" -o jsonpath='{.status.phase}')"
		[[ "$phase" == Succeeded || "$phase" == Failed ]] && break
		sleep 1
	done
	kubectl -n "$ns" logs "$pod" --all-containers >"$tmp/pod.log" 2>&1 || true
	[[ "$phase" == Succeeded ]] || { cat "$tmp/pod.log" >&2; fail "$1: $pod is $phase"; }
	echo "  ran: $1 ($(grep -E ': OK$' "$tmp/pod.log" || true))"
}

step "authorized-with-conditions: a conditional model, while its acceptance holds"
apply_policy "$conditions"
runs "conditional model, pulled by an init container, the attested bytes" \
	"$(pod_fetch "$(ref conditional)" conditional.safetensors "$(sha256 <conditional.safetensors)")"
admitted "authorized model, image volume" "$(pod_volume "$(ref authorized)")"
refused "withheld model, image volume" "$(pod_volume "$(ref withheld)")" "is withheld"

step "authorized: the authorized model starts, wherever the pod names it"
apply_policy "$strict"
runs "authorized model, pulled by an init container, the attested bytes" \
	"$(pod_fetch "$(ref authorized)" authorized.safetensors "$(sha256 <authorized.safetensors)")"
admitted "authorized model, image volume" "$(pod_volume "$(ref authorized)")"
admitted "authorized model, as KServe's oci+fetch:// storage-initializer is given it" "$(pod_kserve_fetch "$(ref authorized)")"
admitted "authorized model by tag, as ModelCar's container and init container" \
	"$(pod_modelcar "$incluster/models/authorized:e2e")"
pinned="$(jq -r '[.spec.containers[], .spec.initContainers[] | select(.name | startswith("modelcar")) | .image] | unique | join(" ")' last.json)"
[[ "$pinned" == "$incluster/models/authorized:e2e@$(digest authorized)" ]] ||
	fail "the ModelCar tag was not pinned to the verified digest: $pinned"
echo "  pinned: the tag became $pinned"
kubectl -n "$ns" run sleeper --image="$busybox_image" --restart=Never -- sleep 600 >/dev/null
kubectl -n "$ns" wait --for=condition=Ready pod/sleeper --timeout=120s >/dev/null
kubectl -n "$ns" debug sleeper --image="$(ref authorized)" --container=model-a -- true >/dev/null ||
	fail "an ephemeral container with the authorized model was refused"
echo "  admitted: authorized model, ephemeral container (kubectl debug)"
deployment() { # deployment <name> <ref>: a plain Deployment whose pod mounts the model as an image volume
	jq -n --arg n "$1" --arg r "$2" --arg b "$busybox_image" '{apiVersion: "apps/v1", kind: "Deployment",
		metadata: {name: $n}, spec: {replicas: 1, selector: {matchLabels: {app: $n}},
		template: {metadata: {labels: {app: $n}}, spec: {containers: [{name: "c", image: $b, command: ["sleep", "600"],
			volumeMounts: [{name: "model", mountPath: "/mnt/models"}]}],
			volumes: [{name: "model", image: {reference: $r, pullPolicy: "IfNotPresent"}}]}}}}' |
		kubectl -n "$ns" apply -f - >/dev/null
}
deployment served "$(ref authorized)"
kubectl -n "$ns" rollout status deploy/served --timeout=120s >/dev/null || fail "the authorized Deployment did not roll out"
echo "  admitted: authorized model, a Deployment's pod (rolled out)"

step "authorized: everything else is refused"
refused "a model with no binding" "$(pod_volume "$(ref unbound)")" "no Socair binding signed by a trusted key"
refused "a model bound by an untrusted key" "$(pod_volume "$(ref stranger)")" "no Socair binding signed by a trusted key"
refused "a withheld model" "$(pod_volume "$(ref withheld)")" "is withheld"
refused "a conditional model" "$(pod_volume "$(ref conditional)")" "is authorized_with_conditions"
refused "the twin, listing the authorized binding (falsification)" "$(pod_volume "$twin")" \
	"no Socair binding signed by a trusted key for this manifest digest: $twin"
refused "the twin as ModelCar's containers" "$(pod_modelcar "$twin")" "no Socair binding signed by a trusted key"
refused "the twin, pulled by an init container" "$(pod_fetch "$twin" authorized.safetensors x)" "no Socair binding signed by a trusted key"
refused "the twin, given to KServe's storage-initializer" "$(pod_kserve_fetch "$twin")" "no Socair binding signed by a trusted key"
refused "an image volume naming a tag, not a digest" "$(pod_volume "$incluster/models/authorized:e2e")" "does not have a digest"
refused "an oci:// argument naming a tag, not a digest" "$(pod_fetch "$incluster/models/authorized:e2e" a x)" "does not have a digest"
if out="$(kubectl -n "$ns" debug sleeper --image="$(ref unbound)" --container=model-u -- true 2>&1)"; then
	fail "an ephemeral container with an unbound model was admitted"
fi
[[ "$out" == *"no Socair binding"* ]] || fail "the ephemeral container was refused for another reason: $out"
echo "  refused: a model with no binding, as an ephemeral container (kubectl debug)"
deployment unserved "$(ref unbound)"
reason=""
for _ in $(seq 1 60); do
	reason="$(kubectl -n "$ns" get events --field-selector reason=FailedCreate -o json |
		jq -r '[.items[] | select(.involvedObject.kind == "ReplicaSet" and (.involvedObject.name | startswith("unserved-"))) | .message][0] // ""')"
	[[ -n "$reason" ]] && break
	sleep 1
done
[[ "$reason" == *"no Socair binding"* ]] || fail "the unbound Deployment's pod was not refused for its model: $reason"
[[ "$(kubectl -n "$ns" get pods -l app=unserved -o name | wc -l | tr -d ' ')" == 0 ]] || fail "the unbound Deployment has a pod"
echo "  refused: a model with no binding, a Deployment's pod (FailedCreate on its ReplicaSet)"

step "authorized-with-conditions: the conditional model once its acceptance has expired"
apply_policy "$conditions"
until [[ "$(now)" > "$expires" ]]; do sleep 2; done
refused "the conditional model after $expires" "$(pod_volume "$(ref conditional)")" "acceptance expires $expires"
admitted "the authorized model" "$(pod_volume "$(ref authorized)")"

step "with the registry stopped, a model is refused"
docker stop "$reg" >/dev/null
refused "the authorized model, its registry unreachable" "$(pod_volume "$(ref authorized)")" "error"

echo
echo "admission e2e: all checks passed"
