# Admission: refusing a model pod without an authorized binding

A cluster can refuse a pod that names an OCI model artifact without a Socair
binding from a trusted key in an acceptable promotion state, whichever server
the pod runs (KServe, vLLM, NVIDIA NIM, or a plain Deployment's container).
The gate is Kyverno; it needs no LLMKube and no Socair component in the
cluster. What it cannot see is a model the pod does not name in its spec
([below](#where-a-pod-names-a-model)). The policies are in
[`policies/kyverno`](../policies/kyverno):

| Policy | Admits a model whose binding's promotion state is |
|---|---|
| [`socair-model-authorized.yaml`](../policies/kyverno/socair-model-authorized.yaml) | `authorized` |
| [`socair-model-authorized-with-conditions.yaml`](../policies/kyverno/socair-model-authorized-with-conditions.yaml) | `authorized`, or `authorized_with_conditions` while the acceptance has not expired |

Install one of them. Both are Kyverno `ImageValidatingPolicy` resources
(`policies.kyverno.io/v1`), tested with Kyverno v1.19.1 on Kubernetes 1.35 by
[`scripts/admission-e2e.sh`](../scripts/admission-e2e.sh) (below).

A binding is what `socair attach` pushes beside an OCI model artifact: an
in-toto statement whose subject is the artifact's manifest digest, predicate
type `https://socair.ai/oci-binding/v1`, repeating the attestation's
promotion state, in a Sigstore bundle. [oci.md](oci.md) describes it and
what `attach` checks before it signs one.

## What the policies check

On every pod create and update, and on an ephemeral container added to a pod
(`kubectl debug`), for every model reference the pod names (the next two
sections say which references count as models):

1. **A digest.** The reference must name a manifest digest. Kyverno replaces
   a container image's tag with the digest it resolves, before it verifies;
   an image volume or a fetch reference must name the digest itself, or it is
   refused.
2. **A binding from a trusted key.** Among the artifact's referrers there is
   a Sigstore bundle whose DSSE signature verifies with the configured public
   key, whose statement's subject is this artifact's manifest digest, and
   whose predicate type is `https://socair.ai/oci-binding/v1`. A binding
   listed for an artifact other than its subject is not one: cosign compares
   the statement's subject with the digest it was asked about.
3. **The promotion state.** The binding's
   `predicate.attestation.promotion_state` is `authorized`. The conditions
   variant also admits `authorized_with_conditions` when
   `predicate.attestation.acceptance_expires` is later than Kyverno's clock.
   `attach` binds a conditional attestation only when its acceptance is the
   acceptor's signed one and verifies against the acceptor keys, so a binding
   in that state carries a verified acceptance's expiry.
4. **What a container would run.** A model image the pod runs as a
   container, whose binding covers only its model root and names base layers
   (a KServe ModelCar image), is refused unless `runUnexaminedBase` is `true`
   ([KServe ModelCar images](#kserve-modelcar-images)).

Anything else is refused, and the refusal names the reference and the
reason, for example:

```
Policy socair-model-authorized failed: this policy admits only promotion state authorized:
registry.example/models/tiny@sha256:1c31… is withheld
```

The policies fail closed. `failurePolicy` is `Fail`, and Kyverno fetches each
model's manifest on every request: with the registry unreachable, a pod
naming a model is refused, even one admitted a minute before (tested). A pod
created by a Deployment, StatefulSet, Job, or any other controller is checked
as the pod; a refused pod shows as a `FailedCreate` event on its controller
(tested for a Deployment). The policies match pods only, not the controllers,
so `kubectl apply` of a Deployment succeeds and its pods do not start.

## Which images are models

A policy treats every image under the repositories in its
`matchImageReferences` as a model, in every pod, and checks nothing else.
This was chosen over a pod label or annotation that marks a model, because
whoever writes the pod sets those: a pod without the mark would not be
checked. A repository pattern does not depend on the pod's author, on
container names, or on the serving stack.

What it does not cover:

- **The same model under another name.** The pattern is matched against the
  reference as the pod writes it. The same artifact reached through another
  registry host, a mirror, an IP address, another port, or a Docker Hub short
  name is not matched. Restrict the registries pods may pull from with a
  separate policy, and keep models under one name.
- **The pattern's syntax.** Kyverno compiles the glob with no separators
  ([compiler.go](https://github.com/kyverno/kyverno/blob/v1.19.1/pkg/cel/compiler/compiler.go)),
  so `*` matches `/` too: `registry.example/models/*` covers nested
  repositories. Keep the trailing slash: `registry.example/models*` also
  matches `registry.example/models-other/…`.

## Where a pod names a model

| Field | Who puts a model there | Extracted by |
|---|---|---|
| `spec.containers[].image`, `spec.initContainers[].image` | KServe ModelCar: a `modelcar` container and a `modelcar-init` init container, both running the model image (KServe v0.21.0); any pod that runs a model image | Kyverno's defaults |
| `spec.ephemeralContainers[].image` | `kubectl debug` | Kyverno's defaults; the policies match the `pods/ephemeralcontainers` subresource it writes through |
| `spec.volumes[].image.reference` | Kubernetes image volumes (beta and on by default from 1.35, GA in 1.36); KServe's `oci+native://` mode | the policies' `volumes` extractor |
| an entry of a container's `command` or `args` that is `oci://<reference>` | a container handed a model to pull: KServe's `oci+fetch://` mode passes `oci://<reference>` and a path to its `storage-initializer` init container | the policies' `ociArgs` extractor |

The e2e admits and refuses a model in each of these places. A reference a pod
writes any other way (in an environment variable, inside a flag such as
`--model=oci://…`, in a config file) is not extracted.

Serving stacks differ in which of these they can consume, and Socair can
bind only some artifacts:

- **KServe** (v0.21.0) expects the ModelCar layout in all three of its OCI
  modes: a container image with the model under `/models` in tar layers.
  ModelCar runs the image as a container; `oci+native://` mounts it as an
  image volume with `subPath: models`; `oci+fetch://` downloads it with
  oras-py and extracts `models/` from its tar layers, skipping any layer that
  is not a tar archive
  ([kserve_storage.py](https://github.com/kserve/kserve/blob/d1482554fc4f66dd41aee70e01f5174e24f265bd/python/storage/kserve_storage/kserve_storage.py),
  `_download_oci`). `socair attach` maps the files inside such an image's tar
  layers to the attested ones ([oci.md](oci.md#images-the-files-inside-tar-layers)),
  and the policies admit it in the `oci+native://` and `oci+fetch://` modes.
  Running it as ModelCar's containers is admitted only when the operator
  says so ([below](#kserve-modelcar-images)).
- **A pod that pulls a ModelPack artifact itself** (an init container running
  oras or another OCI client into an `emptyDir`) consumes the raw layers
  Socair binds. The e2e runs one: an init container handed
  `oci://<reference>` pulls the artifact with the oras CLI, and the server
  container checks that the file hashes to the attested file. The policies
  see the reference only when it is written as an `oci://` argument.
- **Image volumes of raw-layer artifacts.** Kubernetes leaves to the runtime
  which layer media types an image volume unpacks
  ([KEP-4639](https://github.com/kubernetes/enhancements/blob/c3cbc64a900d0fc37389c2865f69e666ced74c5f/keps/sig-node/4639-oci-volume-source/README.md#filesystem-representation)).
  With containerd 2.3.4 (the kind v1.35.8 node), a ModelPack artifact with a
  raw weight layer was pulled and mounted as an empty directory: the pod
  starts and the file is not there. CRI-O was not tested.
- **vLLM and NVIDIA NIM** load a model from a path, the Hugging Face hub, or
  NGC. Unless the pod names the model in one of the places above (as a pod
  that pulls it in an init container, or KServe's, does), it is not in the
  pod spec, and the policy does not see it.

## KServe ModelCar images

`socair attach` binds a ModelCar image (`FROM busybox`, `RUN mkdir /models`,
`COPY data/ /models/`) with `match: model-root`: its `/models` holds exactly
the attested files, as containerd, CRI-O, and KServe's oci+fetch unpack it,
and its other layers are named with `role: base`
([oci.md](oci.md#what-the-binding-covers-and-what-it-does-not)). The binding
does not cover the base layers' content or the image config.

That matters only when a pod runs the image. In KServe's ModelCar mode, the
`modelcar` and `modelcar-init` containers run the model image itself (`sh -c
"ln -sf /proc/$$/root/models /mnt/models && sleep infinity"`, with a writable
root filesystem, and the config's entrypoint, if any, in front), so the base
image's programs and the image config run beside the server and can change
what it reads. The `oci+native://` mode mounts the image read-only with
`subPath: models`, and `oci+fetch://` extracts `models/` with KServe's own
storage initializer; neither runs anything from the image.

So the policies tell the cases apart. For each model image a pod names as a
container, init container, or ephemeral container, a binding whose layers
include a `base` layer is refused, unless the policy's optional value
`runUnexaminedBase` is `true`:

```
Policy socair-model-authorized failed: this pod runs a model image whose binding covers only its model root,
not the base layers and image config the container runs (set runUnexaminedBase to admit it): registry.example/models/tiny@sha256:…
```

Set `runUnexaminedBase: "true"` when you trust whoever builds your ModelCar
images for their base and config, as you trust any image you run. An
`authorized` state is still required either way; the value decides only
whether a pod may run code the binding does not cover. Images named as an
image volume or an `oci://` argument are not affected, and nor is a raw
ModelPack artifact, whose binding has no base layers. A multi-platform
ModelCar image is attached one platform manifest at a time, and the pod
names that manifest's digest.

## Install

Kyverno v1.19 supports Kubernetes 1.33 to 1.35. Install it (chart 3.9.1 is
Kyverno v1.19.1; the e2e installs it by digest,
`oci://ghcr.io/kyverno/charts/kyverno:3.9.1@sha256:720542b97bdbc2633535c2297332690d21cfbb944053eb1ec1f0dbe8e3895444`):

```
helm install kyverno oci://ghcr.io/kyverno/charts/kyverno --version 3.9.1 -n kyverno --create-namespace
```

Then fill in the two values marked `EDIT` in the policy:

- `matchImageReferences`: the repositories that hold models.
- `attestors[0].cosign.key.data`: the public key that signs bindings, the
  `--key` given to `socair attach`. A Socair `.pub` file can start with a
  `Socair-Issuer:` line; put only the PEM block in the policy:

  ```
  sed -n '/BEGIN PUBLIC KEY/,/END PUBLIC KEY/p' operator.pub
  ```

  To trust more than one key, add an attestor per key and list each in the
  `verifyAttestationSignatures` calls.

And, if pods run KServe ModelCar images, the optional value marked `EDIT
(optional)`: `variables.runUnexaminedBase`, `"false"` as shipped
([above](#kserve-modelcar-images)).

```
kubectl apply -f socair-model-authorized.yaml
kubectl get imagevalidatingpolicy socair-model-authorized   # READY true
```

A registry that needs credentials is named in the policy's `credentials`
(Kubernetes secrets in Kyverno's namespace); Kyverno does not use a pod's
`imagePullSecrets` for this ([Kyverno's documentation](https://github.com/kyverno/website/blob/77f297fdd586483469c5a963d749383c22d6634f/src/content/docs/docs/policy-types/image-validating-policy.mdx#credentials)).
Attach by digest and reference models by digest: `socair attach
registry.example/models/tiny@sha256:<manifest> …`, and the same reference in
the pod.

Settings the policies pin, and why:

- `validationActions: [Deny]`, `failurePolicy: Fail`: refuse, and refuse when
  verification cannot run.
- `validationConfigurations`: `mutateDigest`, `verifyDigest`, and `required`
  are `true` (Kyverno's defaults, written out): a container image's tag is
  replaced with the digest it resolves to, which is the digest verified; a
  reference without a digest is refused; and a matched image that no policy
  verified is refused.
- `ctlog.insecureIgnoreTlog` and `insecureIgnoreSCT`: Socair signs offline and
  writes no transparency log entry ([oci.md](oci.md#admission-verifiers)).
- `evaluation.background.enabled: false`: admission is the gate; background
  reports would re-fetch every model's referrers on a schedule and refuse
  nothing.
- `autogen.podControllers.controllers: []`: pods only, as above.
- `webhookConfiguration.timeoutSeconds: 30`, the API server's maximum: each
  model costs a few registry requests.

## What the policies do not check

- **The attestation itself.** Kyverno verifies the binding, not the Socair
  attestation's envelope. The binding's signer verified the attestation
  against its trust list when it ran `attach`, and the binding names the
  attestation by its envelope's hash. To check the attestation and the layer
  match again, run `socair verify <reference>`, which reads the other
  referrer `attach` pushed.
- **The manifest's config blob, and an image's base layers**, as in
  [oci.md](oci.md#what-is-not-checked). With `runUnexaminedBase` true, a
  ModelCar container runs both.
- **That a mounted image is read through its model root.** A pod that mounts
  a ModelCar image as a volume without `subPath: models` sees the base
  layers' files too; the binding covers only what is under `/models`.
- **Models from anywhere else**: a volume (a PersistentVolumeClaim, hostPath,
  NFS), the Hugging Face hub, NGC, a pull whose reference the pod does not
  write as an `oci://` argument, and any image outside the configured
  repositories.
- **Namespaces Kyverno excludes.** Kyverno's chart excludes `kube-system` and
  its own namespace from its webhooks by default
  ([values.yaml](https://github.com/kyverno/kyverno/blob/v1.19.1/charts/kyverno/values.yaml)).
- **Running pods.** Admission runs when a pod is created or updated. A pod
  admitted under an acceptance keeps running after the acceptance expires;
  its replacement is refused.
- **Which binding, when there are several.** An artifact attached twice has
  two bindings. Kyverno keeps one verified payload per predicate type, the
  last it verified, so the policy reads one of them and not necessarily the
  newest. A binding stays valid while its key is trusted; to withdraw one,
  delete its referrer from the registry or stop trusting the key.
- **Fresh verification on every request.** Kyverno caches a successful
  verification, and the binding it read, for up to 60 minutes per policy
  version and image (`--imageVerifyCacheTTLDuration`, enabled by default).
  Within that time a deleted binding still admits the image; changing the
  policy starts a new cache. The manifest is still fetched on every request,
  so an unreachable registry refuses.
- **When the binding was signed.** With no transparency log, `bound_utc` is
  the signer's claim.

## Offline and air-gapped clusters

From Kyverno's source: a `cosign` attestor with a `key` and
`ctlog.insecureIgnoreTlog: true` takes a path that sets up no Sigstore
infrastructure (no TUF root, Rekor, or CT log)
([opts.go](https://github.com/kyverno/kyverno/blob/v1.19.1/pkg/image/verifiers/ivpol/cosign/opts.go)),
and the admission controller sets up TUF at startup only with `--enableTuf`
([flag.go](https://github.com/kyverno/kyverno/blob/v1.19.1/cmd/internal/flag.go),
[tuf.go](https://github.com/kyverno/kyverno/blob/v1.19.1/cmd/internal/tuf.go)).
The policies need the registry and nothing else outside the cluster. The e2e
cluster had network access, so this was read, not run, in an air-gapped
cluster.

## Ed25519 keys

Socair signs with Ed25519, and Kyverno verifies it as it is: the attestor's
`key.data` is decoded with sigstore's `cryptoutils.UnmarshalPEMToPublicKey`
and `signature.LoadVerifier`, which give an Ed25519 key a plain Ed25519
verifier ([certs.go](https://github.com/kyverno/kyverno/blob/v1.19.1/pkg/image/verifiers/ivpol/cosign/certs.go)).
The e2e verifies Socair's own keys with Kyverno v1.19.1. No other signing
algorithm is needed.

## Kyverno's other policy type

Kyverno's older `ClusterPolicy` `verifyImages` rule, with `type:
SigstoreBundle`, reads the same bundle: it lists referrers whose artifact type
starts with `application/vnd.dev.sigstore.bundle` and verifies a key-signed
bundle with sigstore-go
([sigstore.go](https://github.com/kyverno/kyverno/blob/v1.19.1/pkg/image/verifiers/cpol/cosign/sigstore.go)).
A one-off trial against artifacts like the e2e's (container fields only; not
part of the e2e) admitted the authorized model and refused the unbound,
untrusted, withheld, and twin ones; its conditions read the predicate as the
root (`{{ attestation.promotion_state }}`). Without `type:
SigstoreBundle` it reads only cosign's legacy `.att` tag, which Socair does
not write. It is not shipped: `ClusterPolicy` is deprecated in Kyverno 1.19
and planned for removal in 1.20
([announcement](https://github.com/kyverno/website/blob/77f297fdd586483469c5a963d749383c22d6634f/src/content/blog/announcing-kyverno-release-1.19/index.md)).

## Sigstore policy-controller

Not served. For an authority with a key, policy-controller v0.15.1 reads only
cosign's legacy `sha256-<hex>.att` tag, and refuses the bundle format: "when
using the new bundle format, the authority must be keyless"
([validator.go](https://github.com/sigstore/policy-controller/blob/v0.15.1/pkg/webhook/validator.go)).
That is unchanged on its main branch at
[`80f7d39`](https://github.com/sigstore/policy-controller/blob/80f7d397114c443f49915cd03c8f9fff70a5924a/pkg/webhook/validator.go)
(2026-10-02), where a `TODO` notes it. Either of these would close the gap:

- policy-controller verifying a key-signed bundle, which is its open `TODO`;
  nothing on Socair's side changes;
- Socair writing cosign's legacy attestation tag too. It is cosign's tag,
  shared with every cosign attestation of the image, and appending to it
  means rewriting another tool's data, so it is not done.

Signing the binding keylessly (Fulcio and Rekor) would also satisfy
policy-controller, and would give up offline signing.

## Testing

```
scripts/admission-e2e.sh     # needs docker, kind, kubectl, helm, go, curl, jq, python3
```

It creates its own kind cluster (`KIND_CLUSTER`, default
`socair-admission-e2e`) with a kubeconfig in a temporary directory, so it
neither reads nor changes yours, and deletes the cluster and its registry
when it exits (`KEEP=1` keeps them). In it: a zot registry, Kyverno v1.19.1,
and socair built from the checkout. Pods name the registry by its private
address on kind's network, over plain http; Kyverno's registry client
(go-containerregistry v0.21.8) falls back to http for an RFC 1918 address
([registry.go](https://github.com/google/go-containerregistry/blob/v0.21.8/pkg/name/registry.go)),
so the policies need no change for it. It scans five tiny safetensors models
(authorized, withheld, conditional under a signed acceptance that expires two
minutes later, authorized but signed by an untrusted key, and one never
attached), pushes each as a ModelPack artifact with one raw weight layer, and
attaches four. Then it applies the shipped policies with the repository and
key filled in, and checks that:

- the conditions variant admits the conditional model while its acceptance
  holds, in a pod that starts and pulls it;
- the strict policy admits the authorized model in a pod that starts, whose
  init container is handed `oci://<reference>`, pulls the artifact with oras,
  and finds the attested bytes; as an image volume; by tag as ModelCar's
  container and init container, with the tag pinned to the verified digest;
  as KServe's `oci+fetch://` mode hands it to the `storage-initializer`; as an
  ephemeral container; and in a Deployment that rolls out;
- it refuses a model with no binding, a model bound by an untrusted key, a
  withheld model, a conditional model, references without a digest, an
  ephemeral container with an unbound model, and an unbound model's
  Deployment pod;
- it refuses a twin: an artifact carrying the authorized model's bytes under
  another config, to which the authorized binding's bundle is attached as a
  referrer. The registry lists the bundle for the twin, and the statement it
  signs is about the other digest (the issue's falsification);
- for KServe ModelCar images, built with `docker build` from KServe's
  documented Dockerfile (`FROM busybox` pinned by digest, `RUN mkdir /models
  && chmod 775 /models`, `COPY data/ /models/`) with the authorized model's
  file, pushed, and attached with its attestation (`attach` maps one model
  layer and two base layers): the strict policy admits the image mounted as
  `oci+native://` mounts it (`subPath: models`), in a pod that starts and
  finds the attested bytes; and handed to KServe's own storage-initializer
  image (v0.21.0, pinned by digest) as `oci+fetch://` hands it, which
  extracts the attested bytes. It refuses the image run as KServe's ModelCar
  containers (KServe's own `modelcar` and `modelcar-init` commands) while
  `runUnexaminedBase` is false; with it true, that pod starts and its server
  reads the attested bytes through KServe's `/proc` link;
- `attach` refuses three ModelCar images: one holding other bytes, one whose
  later layer rewrites the model file (`RUN printf x >/models/…`), and one
  with a link to `/models` (`RUN ln -s /models /data`); pods naming them are
  refused for having no binding;
- the conditions variant refuses the conditional model once its acceptance
  has expired;
- with the registry stopped, a pod naming the authorized model is refused.

This is KServe's own containers and images run in plain pods, not KServe:
the KServe controller and its webhook, which write those pods from an
InferenceService, are not installed.

A copy of the tree whose policies no longer read the promotion state failed
the run at the first withheld model, and one whose strict policy no longer
refuses a run ModelCar image failed at that check. CI runs the script in
`.github/workflows/admission.yml` on changes to the policies, the script, or
the code it builds.

## Sources

- Kyverno v1.19.1:
  [pkg/cel/libs/imageverify/impl.go](https://github.com/kyverno/kyverno/blob/v1.19.1/pkg/cel/libs/imageverify/impl.go)
  (`verifyAttestationSignatures`, `extractPayload`),
  [pkg/image/verifiers/ivpol/cosign/verifier.go](https://github.com/kyverno/kyverno/blob/v1.19.1/pkg/image/verifiers/ivpol/cosign/verifier.go)
  (the bundle format is used when bundles are found; one payload kept per
  predicate type),
  [opts.go](https://github.com/kyverno/kyverno/blob/v1.19.1/pkg/image/verifiers/ivpol/cosign/opts.go),
  [certs.go](https://github.com/kyverno/kyverno/blob/v1.19.1/pkg/image/verifiers/ivpol/cosign/certs.go),
  [pkg/image/verification/evaluator/policy.go](https://github.com/kyverno/kyverno/blob/v1.19.1/pkg/image/verification/evaluator/policy.go)
  (references filtered by `matchImageReferences`, the digest check, `required`,
  tag pinning of container fields only),
  [pkg/cel/compiler/images.go](https://github.com/kyverno/kyverno/blob/v1.19.1/pkg/cel/compiler/images.go)
  (the default extractors),
  [pkg/cel/compiler/compiler.go](https://github.com/kyverno/kyverno/blob/v1.19.1/pkg/cel/compiler/compiler.go)
  (the glob),
  [pkg/webhooks/resource/ivpol/handler.go](https://github.com/kyverno/kyverno/blob/v1.19.1/pkg/webhooks/resource/ivpol/handler.go)
  (an evaluation error denies under `Deny`),
  [pkg/image/verification/cache/client.go](https://github.com/kyverno/kyverno/blob/v1.19.1/pkg/image/verification/cache/client.go)
  and [cmd/internal/flag.go](https://github.com/kyverno/kyverno/blob/v1.19.1/cmd/internal/flag.go)
  (the verification cache),
  [config/crds/policies.kyverno.io/policies.kyverno.io_imagevalidatingpolicies.yaml](https://github.com/kyverno/kyverno/blob/v1.19.1/config/crds/policies.kyverno.io/policies.kyverno.io_imagevalidatingpolicies.yaml)
  (`v1` served; `v1beta1` the storage version; `v1alpha1` deprecated).
  The API types:
  [kyverno/api `fb27857` imagevalidating_policy.go](https://github.com/kyverno/api/blob/fb2785727f98db3dd0e263fc354d4b6443a8362e/api/policies.kyverno.io/v1alpha1/imagevalidating_policy.go).
  The payload store:
  [kyverno/sdk `68d74af` imagedataloader/loader.go](https://github.com/kyverno/sdk/blob/68d74afcb07a4ad8c941e8bc43e9da31d9f703b0/extensions/imagedataloader/loader.go);
  `time.now()`:
  [cel/libs/time/lib.go](https://github.com/kyverno/sdk/blob/68d74afcb07a4ad8c941e8bc43e9da31d9f703b0/extensions/cel/libs/time/lib.go).
- Kyverno documentation, website at `77f297f`:
  [ImageValidatingPolicy](https://github.com/kyverno/website/blob/77f297fdd586483469c5a963d749383c22d6634f/src/content/docs/docs/policy-types/image-validating-policy.mdx),
  [ClusterPolicy deprecation notice](https://github.com/kyverno/website/blob/77f297fdd586483469c5a963d749383c22d6634f/src/content/docs/docs/policy-types/cluster-policy/overview.md),
  [Kubernetes compatibility](https://github.com/kyverno/website/blob/77f297fdd586483469c5a963d749383c22d6634f/src/constants/version.ts)
  (1.19.x: Kubernetes 1.33 to 1.35).
- cosign v3.1.2, the version Kyverno v1.19.1 uses:
  [pkg/cosign/verify.go](https://github.com/sigstore/cosign/blob/v3.1.2/pkg/cosign/verify.go)
  (`GetBundles` lists every referrer; each bundle is checked against the
  image's digest; the legacy `.att` path),
  [pkg/policy/attestation.go](https://github.com/sigstore/cosign/blob/v3.1.2/pkg/policy/attestation.go)
  (the payload is the whole statement, hence `.predicate.…`).
- KServe v0.21.0 (`d148255`):
  [pkg/constants/constants.go](https://github.com/kserve/kserve/blob/d1482554fc4f66dd41aee70e01f5174e24f265bd/pkg/constants/constants.go)
  (`modelcar`, `modelcar-init`, `storage-initializer`),
  [pkg/utils/storage.go](https://github.com/kserve/kserve/blob/d1482554fc4f66dd41aee70e01f5174e24f265bd/pkg/utils/storage.go)
  (the ModelCar containers, `oci+<mode>://`, the native image volume with
  `subPath: models`),
  [pkg/webhook/admission/pod/oci_fetch.go](https://github.com/kserve/kserve/blob/d1482554fc4f66dd41aee70e01f5174e24f265bd/pkg/webhook/admission/pod/oci_fetch.go)
  (the fetch mode's init container arguments),
  [python/storage/kserve_storage/kserve_storage.py](https://github.com/kserve/kserve/blob/d1482554fc4f66dd41aee70e01f5174e24f265bd/python/storage/kserve_storage/kserve_storage.py)
  (`_download_oci`: tar layers only, `models/` only),
  [pkg/types/config.go](https://github.com/kserve/kserve/blob/d1482554fc4f66dd41aee70e01f5174e24f265bd/pkg/types/config.go)
  (the modes),
  [python/storage-initializer/scripts/initializer-entrypoint](https://github.com/kserve/kserve/blob/d1482554fc4f66dd41aee70e01f5174e24f265bd/python/storage-initializer/scripts/initializer-entrypoint)
  and [python/storage-initializer.Dockerfile](https://github.com/kserve/kserve/blob/d1482554fc4f66dd41aee70e01f5174e24f265bd/python/storage-initializer.Dockerfile)
  (the image the e2e runs, `kserve/storage-initializer:v0.21.0`, as uid
  1000), and the ModelCar Dockerfile in KServe's
  [OCI storage docs](https://github.com/kserve/website/blob/fb4c67f9f9cca2cd680fb26abca3499bb3c2245e/docs/model-serving/storage/providers/oci.md).
- Kubernetes: the `ImageVolume` gate in
  [v1.35.8 kube_features.go](https://github.com/kubernetes/kubernetes/blob/v1.35.8/pkg/features/kube_features.go)
  (beta, on by default) and
  [v1.36.0 kube_features.go](https://github.com/kubernetes/kubernetes/blob/v1.36.0/pkg/features/kube_features.go)
  (GA); [KEP-4639](https://github.com/kubernetes/enhancements/blob/c3cbc64a900d0fc37389c2865f69e666ced74c5f/keps/sig-node/4639-oci-volume-source/README.md);
  a webhook's timeout is between 1 and 30 seconds
  ([admissionregistration/v1 types.go](https://github.com/kubernetes/kubernetes/blob/v1.35.8/staging/src/k8s.io/api/admissionregistration/v1/types.go)).
- Sigstore policy-controller:
  [v0.15.1 validator.go](https://github.com/sigstore/policy-controller/blob/v0.15.1/pkg/webhook/validator.go).
- kind [v0.33.0](https://github.com/kubernetes-sigs/kind/releases/tag/v0.33.0)
  (node images by digest) and its
  [local registry example](https://github.com/kubernetes-sigs/kind/blob/v0.33.0/site/static/examples/kind-with-registry.sh).
