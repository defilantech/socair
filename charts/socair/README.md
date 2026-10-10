# Socair Helm chart

Runs Socair's airlock and wizard (`socair serve --store`) as one pod: stage
open-weight models, scan them, and promote only those whose attestation a
trusted key signed.
[docs/kubernetes.md](https://github.com/defilantech/socair/blob/main/docs/kubernetes.md)
explains the design, how to reach it, and how promoted models get to LLMKube.

```
kubectl create namespace socair
kubectl -n socair create configmap socair-trusted-keys --from-file=operator.pub
helm install intake oci://ghcr.io/defilantech/charts/socair --version <version> -n socair \
  --set trust.trustedKeysConfigMap=socair-trusted-keys
kubectl -n socair port-forward deploy/intake-socair 8080:8080
```

By default the API binds the pod's loopback with no Service (it has no
authentication of its own, so `kubectl port-forward` and Kubernetes RBAC are
the gate), egress is denied, and the pod passes the `restricted` Pod Security
Standard.

## Values

| Value | Default | What it does |
|---|---|---|
| `image.repository` | `ghcr.io/defilantech/socair` | The image. |
| `image.tag` | the chart's `appVersion` | The image tag. |
| `image.digest` | `""` | Pins the image by digest; wins over `tag`. |
| `persistence.enabled` | `true` | The store on a PersistentVolumeClaim. `false` uses an emptyDir that dies with the pod. |
| `persistence.existingClaim` | `""` | Use this claim instead of creating one. |
| `persistence.size` | `200Gi` | Room for every staged model and promoted copy. |
| `persistence.storageClass` | `""` | The claim's storage class. |
| `persistence.keep` | `true` | Keep the claim on `helm uninstall`; it holds the audit log. |
| `scratch.sizeLimit` | `""` | Caps the scan-snapshot emptyDir (`SOCAIR_SCAN_TMP`). |
| `scratch.ephemeral.enabled` | `false` | A generic ephemeral claim for scratch instead, for models larger than the node's disk. |
| `scratch.ephemeral.size` | `200Gi` | Its size. |
| `pull.enabled` | `false` | Allow pulling from Hugging Face: TCP 443 and DNS egress, no `SOCAIR_EGRESS=deny`. |
| `pull.endpoint` | `""` | A hub mirror (`SOCAIR_HF_ENDPOINT`). |
| `pull.tokenSecret.name` | `""` | A Secret holding the hub token (`HF_TOKEN`). |
| `pull.egressCIDRs` | all | Where pull egress may go. |
| `trust.trustedKeysConfigMap` | `""` | A ConfigMap of `*.pub` keys whose attestations may promote. The format LLMKube's gate reads. |
| `trust.acceptorKeysConfigMap` | `""` | A ConfigMap of `*.pub` keys whose acceptances may clear untested rows. |
| `service.enabled` | `false` | Expose the API as a Service, bound on all interfaces. |
| `service.authenticatingProxy` | `false` | Required with `service.enabled`: confirms something authenticates in front of the API. |
| `networkPolicy.enabled` | `true` | Default-deny NetworkPolicy. |
| `networkPolicy.ingressFrom` | `[]` | With a Service: the peers that may reach the API. Empty means this namespace. |
| `resources` | 500m CPU, 512Mi | Requests; set limits from a scan of your largest model. |
| `extraEnv`, `extraVolumes`, `extraVolumeMounts` | `[]` | A model share to ingest from, a signed feed, and the like. |

`values.schema.json` rejects unknown keys, so a misspelled value fails the
install instead of being ignored.

## Testing

```
helm lint --strict charts/socair
helm unittest charts/socair        # the helm-unittest plugin
scripts/chart-e2e.sh               # a kind cluster, end to end
```
