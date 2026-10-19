# Running Socair on Kubernetes

The Helm chart in [`charts/socair`](../charts/socair) runs the airlock and the
wizard as one pod in a cluster: a controlled intake point where models are
staged, scanned, and promoted before anything serves them. It is the same
`socair serve --store` the [airlock](airlock.md) box runs, in a container.

## What runs

- **One pod** running `socair serve --store /store --web …`. An init container
  runs `socair airlock init /store`, which creates the store's layout on a new
  volume and changes nothing on an existing one.
- **The image** `ghcr.io/defilantech/socair:<version>` holds the release's
  `socair` and `socair-sigstore` binaries, the same bytes as the release's
  `SHA256SUMS` (the [Dockerfile](../Dockerfile) copies them, it does not
  compile them), and the wizard's static build. The base is distroless with
  no shell, and the process runs as uid 65532.
- **No private key enters the cluster.** An operator signs reports offline
  with `socair sign`, an acceptor signs acceptances with `socair accept`, and
  the operator uploads the envelope in the wizard. The cluster holds public
  keys only.

## Install

Releases publish the chart to the Helm repository at
`https://defilantech.github.io/socair`, where Defilan's other charts are, and
push the chart and the image to GHCR. Each carries a build-provenance
attestation. Fetch the chart and check both before installing:

<!-- x-release-please-start-version -->
```
V=0.1.0-rc.8
helm repo add socair https://defilantech.github.io/socair
helm pull socair/socair --version $V
gh attestation verify socair-$V.tgz --repo defilantech/socair \
  --signer-workflow defilantech/socair/.github/workflows/release.yml
gh attestation verify oci://ghcr.io/defilantech/socair:$V --repo defilantech/socair \
  --signer-workflow defilantech/socair/.github/workflows/release.yml
```
<!-- x-release-please-end -->

Then give the store its trust policy and install the chart you verified:

```
kubectl create namespace socair
kubectl label namespace socair pod-security.kubernetes.io/enforce=restricted
kubectl -n socair create configmap socair-trusted-keys --from-file=operator.pub
kubectl -n socair create configmap socair-acceptor-keys --from-file=ciso.pub
helm install intake socair-$V.tgz -n socair \
  --set trust.trustedKeysConfigMap=socair-trusted-keys \
  --set trust.acceptorKeysConfigMap=socair-acceptor-keys
kubectl -n socair port-forward deploy/intake-socair 8080:8080
```

and open <http://127.0.0.1:8080>. The chart's [README](../charts/socair/README.md)
lists every value. While releases are pre-releases, name the version: Helm
lists a pre-release only with `--devel`. The same chart is at
`oci://ghcr.io/defilantech/charts/socair` for a cluster that pulls from an
OCI registry
(`gh attestation verify oci://ghcr.io/defilantech/charts/socair:$V --repo defilantech/socair`).

## Who can reach it

The API has no authentication of its own ([api.md](api.md)), so the chart
does not put it on the network by default:

- It binds the pod's **loopback** and has **no Service**. `kubectl
  port-forward` reaches loopback inside the pod through the kubelet, so
  Kubernetes RBAC is the login: whoever may `create` on `pods/portforward` in
  the namespace may use the wizard, and nobody else can reach it. A Role for
  an intake team:

  ```yaml
  apiVersion: rbac.authorization.k8s.io/v1
  kind: Role
  metadata:
    name: socair-operator
    namespace: socair
  rules:
    - apiGroups: [""]
      resources: [pods]
      verbs: [get, list]
    - apiGroups: [""]
      resources: [pods/portforward]
      verbs: [create]
  ```

- **Exposing it as a Service is opt-in**, and the install fails unless
  `service.authenticatingProxy=true` confirms that something authenticates in
  front of it, such as an OAuth2 proxy or an ingress with authentication. The
  API then binds all of the pod's interfaces with `SOCAIR_API_ALLOW_PUBLIC=1`,
  which also turns off its loopback `Host` check; the `Origin` and
  content-type checks still apply. Set `networkPolicy.ingressFrom` to your
  proxy's pods: left empty, any pod in the namespace can reach the API.

The probes run `socair health` inside the pod, because a kubelet's HTTP probe
cannot reach a loopback address and the image has no shell or curl.

## What it reads

Whoever reaches the API names the paths a scan or a promotion reads, so the
API reads a path a request names only under a scan root
([api.md](api.md#scan-roots)). The store's staging area, `/store/incoming`,
is always one; `scanRoots` adds others, each passed as `--scan-root`. By
default there are no others, so a path anywhere else in the pod (the trust
policy, the log, the clean store, the image's own files) is refused, as is a
symlink that leads out of a root. Each entry must be an absolute path to a
directory the pod mounts, or the server does not start, and the chart refuses
`/`. Mount model shares read-only: a scan root that someone else can write to
lets them swap a checked file for a symlink between the check and the read
([api.md](api.md#scan-roots), "What the check does not close").

## Network

A NetworkPolicy denies all ingress and egress by default
(`networkPolicy.enabled`; it needs a network plugin that enforces policies).
Ingesting from a mounted volume needs no network at all, and the engine runs
with `SOCAIR_EGRESS=deny` so a pull fails even where the policy is not
enforced.

`pull.enabled=true` turns on pulling from Hugging Face: it drops
`SOCAIR_EGRESS=deny` and lets the pod resolve names and reach TCP 443 on
`pull.egressCIDRs`. `pull.endpoint` points at a hub mirror, and
`pull.tokenSecret` names a Secret whose token Socair sends to the hub's own
host only ([airlock.md](airlock.md#controlled-egress)).

## Storage

- **The store** (`/store`) is a PersistentVolumeClaim: staging, the clean
  store, the trust policy, and the append-only activity log. Size it for every
  staged model and every promoted copy. `helm uninstall` keeps the claim
  (`persistence.keep`), because the log is the store's audit trail;
  `persistence.existingClaim` reuses one.
- **Scratch** (`/scratch`, `SOCAIR_SCAN_TMP`) is where a scan snapshots the
  artifact so it checks exactly the bytes it hashed. It needs room for the
  model being scanned, and two scans can run at once. It is an emptyDir by
  default (`scratch.sizeLimit` caps it); for models larger than the node's
  disk, `scratch.ephemeral` makes it a claim created and deleted with the pod.
- **One replica**, replaced with `Recreate`: the activity log is a hash chain
  with one writer, and a ReadWriteOnce claim attaches to one node.

## Getting models in

- **From a volume**, for an air-gapped cluster: mount a share or a claim that
  holds the models read-only, name its mount path as a scan root, scan them in
  the wizard by path, sign the report offline, and promote with the signed
  envelope:

  ```yaml
  extraVolumes:
    - name: incoming
      persistentVolumeClaim:
        claimName: model-dropbox
        readOnly: true
  extraVolumeMounts:
    - name: incoming
      mountPath: /models
      readOnly: true
  scanRoots:
    - /models
  ```

- **From a hub**, with `pull.enabled=true`: the wizard's Pull stages a file or
  a whole repository at a pinned commit, each file checked against the hub's
  hash.

A signed reference feed ([feed.md](feed.md)) mounts the same way, with
`extraEnv` setting `SOCAIR_FEED` and `SOCAIR_FEED_KEYS`. The store on the kept
volume then remembers the newest feed the pod has used and refuses an older
one ([feed.md](feed.md#rollback-protection)); the console shows when the feed
will expire. An intake policy
([intake-policy.md](intake-policy.md#in-kubernetes)) mounts the same way: a
ConfigMap holding the policy file, with `extraEnv` setting
`SOCAIR_INTAKE_POLICY` to its mounted path.

## Handing models to LLMKube

LLMKube's model-attestation gate (`modelAttestation` in its chart) reads its
trusted keys from a ConfigMap of `*.pub` files, the format this chart's
`trust.trustedKeysConfigMap` mounts. Point both at the same ConfigMap, so the
keys that may promote a model here are the keys LLMKube trusts. A model
promoted with conditions (an acceptance of untested rows) passes LLMKube's
gate only with `allowConditions: true`:

```yaml
# LLMKube's values
modelAttestation:
  mode: enforce
  trustedKeysConfigMap: socair/socair-trusted-keys
  allowConditions: false
```

A promoted model sits at `/store/clean/<sha256>/<file>` on the store's claim,
with its attestation beside it. LLMKube needs the model's SHA-256 in
`spec.sha256` and the envelope in a ConfigMap in the Model's namespace; the
operator already holds the envelope they uploaded:

```
kubectl -n models create configmap qwen3-attestation \
  --from-file=attestation.dsse.json=report.conditional.dsse.json
```

LLMKube can serve the file from a claim with a `pvc://` source, but the claim
must be in the Model's namespace and mountable by the inference pods, which a
ReadWriteOnce store claim held by Socair's pod is not. Copy promoted models to
the volume LLMKube serves from, give the store a ReadWriteMany claim in
that namespace, or let the inference pods download from the hub endpoint
below. This handoff is documented, not yet tested end to end.

## Serving models to inference servers

`hub.enabled=true` adds a read-only download endpoint
([hub-endpoint.md](hub-endpoint.md)): the clean store's admitted models over
the subset of the Hugging Face Hub API that `huggingface_hub` downloads
through. vLLM, transformers, `hf download`, and KServe's `hf://` storage
initializer then download from it with `HF_ENDPOINT`:

```
helm upgrade intake socair-$V.tgz -n socair --reuse-values --set hub.enabled=true
kubectl label namespace models socair.ai/hub-client=true
```

```yaml
# in the inference pod template, in the labelled namespace
metadata:
  labels:
    socair.ai/hub-client: "true"
spec:
  containers:
    - name: vllm
      args: [serve, Qwen/Qwen3-8B]
      env:
        - name: HF_ENDPOINT
          value: http://intake-socair-hub.socair.svc:8081
```

- **A second container**, `hub`, runs `socair airlock serve-hub` in the same
  pod with the store's volume mounted **read-only**, so nothing it runs can
  change the store. It mounts the trust ConfigMaps too, because it admits a
  model by the same checks as the gate.
- **Its own Service**, `<release>-socair-hub`, ClusterIP, for the hub port
  only (`hub.port`, 8081). The read-write API is never behind it; it stays on
  loopback, and the rule that a Service for the API needs
  `service.authenticatingProxy` is unchanged.
- **The NetworkPolicy admits only `hub.ingressFrom`** to that port: by
  default, pods labelled `socair.ai/hub-client=true` in namespaces labelled
  the same way. The endpoint has no authentication, so the install fails if
  `networkPolicy.enabled` is off or `hub.ingressFrom` is empty. Narrow it
  further with your own peers, such as one namespace by
  `kubernetes.io/metadata.name`.
- `hub.authorizedOnly=true` serves authorized models only, never one promoted
  with conditions, as LLMKube's `allowConditions: false` does.

The endpoint cannot stop an inference pod from reaching huggingface.co
itself: deny that pod's egress to the internet, so the endpoint is its only
source. Unset `HF_TOKEN` in those pods; a client sends its token to
`HF_ENDPOINT`.

## Hardening

| Setting | Value |
|---|---|
| User | uid and gid 65532, `runAsNonRoot` |
| Root filesystem | read-only; `/tmp` is a 1 GiB emptyDir |
| Privileges | no privilege escalation, every capability dropped, `RuntimeDefault` seccomp |
| Pod Security Standard | passes `restricted` (CI installs into a namespace that enforces it) |
| Kubernetes API | no service account token, no Role |
| Network | default-deny NetworkPolicy; no egress unless `pull.enabled`; the hub endpoint, when enabled, only from `hub.ingressFrom` |
| Files the API reads | paths under `/store/incoming` and `scanRoots` only |
| Hub endpoint | off by default; its container mounts the store read-only |
| Keys | public keys only; signing happens offline |
| Image | distroless, pinned by digest in the Dockerfile, attested on release |

## What it does not do yet

- Run scans as Jobs or from a custom resource: the airlock is driven from the
  wizard or with `socair` commands, not from the Kubernetes API.
- Log in: the console has no login yet, so Kubernetes RBAC or your proxy is
  the only gate.
- Create LLMKube's attestation ConfigMaps or copy promoted models for it.
- Run more than one replica.

## Testing

The chart workflow (`.github/workflows/chart.yml`) lints the chart, runs its
unit tests (`helm unittest charts/socair`), validates the manifests against
the Kubernetes 1.27 and current schemas, and runs
[`scripts/chart-e2e.sh`](../scripts/chart-e2e.sh) in a kind cluster. That
script installs the image under the `restricted` Pod Security Standard and,
through port-forward, scans a model mounted into the pod under a scan root;
checks that a path outside the scan roots is refused; checks that
promotion refuses an untrusted signer and a withheld report, and promotes the
report with a signed acceptance; verifies the activity log; turns on the hub
endpoint and checks it serves the promoted bytes and their attestation, and
that its NetworkPolicy admits a labelled pod in a labelled namespace and not
an unlabelled one; checks the API Service is reachable from its own namespace
and not from another; and checks uninstall keeps the store's claim. It runs
anywhere with Docker, kind, kubectl, Helm, and Go.
