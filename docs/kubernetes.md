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

```
V=0.1.0-rc.3
helm repo add socair https://defilantech.github.io/socair
helm pull socair/socair --version $V
gh attestation verify socair-$V.tgz --repo defilantech/socair \
  --signer-workflow defilantech/socair/.github/workflows/release.yml
gh attestation verify oci://ghcr.io/defilantech/socair:$V --repo defilantech/socair \
  --signer-workflow defilantech/socair/.github/workflows/release.yml
```

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
  holds the models read-only, scan them in the wizard by path, sign the report
  offline, and promote with the signed envelope:

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
  ```

- **From a hub**, with `pull.enabled=true`: the wizard's Pull stages a file or
  a whole repository at a pinned commit, each file checked against the hub's
  hash.

A signed reference feed ([feed.md](feed.md)) mounts the same way, with
`extraEnv` setting `SOCAIR_FEED` and `SOCAIR_FEED_KEYS`.

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
the volume LLMKube serves from, or give the store a ReadWriteMany claim in
that namespace. This handoff is documented, not yet tested end to end.

## Hardening

| Setting | Value |
|---|---|
| User | uid and gid 65532, `runAsNonRoot` |
| Root filesystem | read-only; `/tmp` is a 1 GiB emptyDir |
| Privileges | no privilege escalation, every capability dropped, `RuntimeDefault` seccomp |
| Pod Security Standard | passes `restricted` (CI installs into a namespace that enforces it) |
| Kubernetes API | no service account token, no Role |
| Network | default-deny NetworkPolicy; no egress unless `pull.enabled` |
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
through port-forward, scans a model mounted into the pod; checks that
promotion refuses an untrusted signer and a withheld report, and promotes the
report with a signed acceptance; verifies the activity log; checks the
Service is reachable from its own namespace and not from another; and checks
uninstall keeps the store's claim. It runs anywhere with Docker, kind,
kubectl, Helm, and Go.
