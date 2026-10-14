# Attestations on OCI model artifacts

A model packaged as an OCI artifact (a ModelPack artifact, a KitOps
ModelKit, a Docker Model Runner model) is pulled by its manifest digest, and
an admission controller checks statements about that digest. A Socair
attestation is about the model's bytes: a file's SHA-256, or for a model
directory the digest of its `socair.modeldir/v1` manifest. `socair attach`
connects the two and pushes the result into the registry beside the
artifact, as OCI referrers. `socair verify <oci-ref>` finds it there and
checks it.

```
socair attach <registry>/<repository>:<tag> --attestation r.dsse.json --key operator.key \
              (--trusted <key.pub|dir> | --store <path>) [--acceptors <key.pub|dir>]
socair verify <registry>/<repository>:<tag> (--trusted <key.pub|dir> | --store <path>) [--acceptors <key.pub|dir>]
```

A reference names its registry (a host with a dot or a port, or `localhost`)
and a tag or a digest (`@sha256:<hex>`); there is no implicit registry and no
implicit `latest`. `docker.io/<name>` is Docker Hub. `socair verify` reads its
argument as an attestation file when a file by that name exists, and as an
OCI reference otherwise.

## The binding

`attach` does not push the attestation alone. A verifier that checks an
in-toto statement against an image digest would refuse it, rightly: its
subject is the model's bytes, not the manifest. And nothing in it says which
manifest carries those bytes. So `attach`:

1. Verifies the attestation against `--trusted` (or the store's
   `trusted-keys/`), as `socair verify` does, and confirms its issuer against
   the trust list. A conditional attestation is attached only when its
   acceptance is the acceptor's signed one and verifies against
   `--acceptors` (or the store's `acceptor-keys/`), the rule the airlock
   applies at promotion. An acceptance named at scan time
   (`SOCAIR_ACCEPTED_BY`) is refused. Withheld attestations are attached: the
   state travels with them, and the admission policy decides.
2. Fetches the artifact's manifest and computes its digest from the bytes
   received (a tag is resolved here; a digest reference must match).
3. Matches the manifest's layers to the attested bytes (below). Any mismatch
   refuses the attach and names each problem.
4. Signs a **binding** with `--key`: an in-toto Statement v1 whose one subject
   is the OCI manifest digest, with predicate type
   `https://socair.ai/oci-binding/v1`.
5. Pushes the binding and the attestation as one referrer of the artifact,
   and a copy of the binding as a Sigstore bundle referrer for cosign-based
   verifiers ([Admission verifiers](#admission-verifiers)).

Nothing is pushed until steps 1 to 4 hold. If the Sigstore bundle push fails
after the Socair referrer was pushed, the command fails and says which was
pushed.

The binding's predicate:

```json
{
  "artifact": {
    "name": "registry.example/models/tiny",
    "digest": "sha256:<manifest>",
    "media_type": "application/vnd.oci.image.manifest.v1+json",
    "artifact_type": "application/vnd.cncf.model.manifest.v1+json",
    "config_media_type": "application/vnd.cncf.model.config.v1+json",
    "config_digest": "sha256:<config blob>",
    "match": "file",
    "layers": [{"digest": "sha256:<file>", "size": 4683071488,
                "media_type": "application/vnd.cncf.model.weight.v1.raw", "path": "tiny-Q4_K_M.gguf"}]
  },
  "attestation": {
    "sha256": "<sha256 of the attestation envelope's bytes>",
    "predicate_type": "https://socair.ai/attestation/v1",
    "subject_sha256": "<the file's SHA-256, or the model directory's manifest digest>",
    "subject_name": "tiny-Q4_K_M.gguf",
    "document_id": "...", "document_hash": "...", "issued_utc": "...",
    "signer_key_id": "...", "issuer": "Acme ML Platform", "check_set_version": "tier1/0.8",
    "promotion_state": "authorized_with_conditions",
    "accepted_by": "Jane Doe, CISO", "accepted_surfaces": ["Provenance"], "acceptance_expires": "..."
  },
  "bound_utc": "2026-10-12T12:00:00Z",
  "tool_version": "socair v0.9.0"
}
```

The binding names the attestation by the hash of its envelope's bytes and
repeats what an admission policy decides on (the promotion state, the
accepted surfaces and their expiry, the issue time), so a policy can read
them from the statement it verified. `match` is `file` or `model-directory`,
and `layers` lists every layer of the manifest. The binding's signer is
whoever ran `attach`; a verifier must trust that key as well as the
attestation's.

The binding asserts what `attach` saw when it ran: these layers, by digest,
are the attested bytes. It does not make the attestation say more than its
bounded statement.

## Matching layers to the attested bytes

A layer descriptor's digest is the SHA-256 of the layer blob. When the blob
is one file's bytes, unarchived and uncompressed, that digest is the file's
SHA-256, and the manifest digest covers it. So the binding needs no layer
download: the chain from the manifest digest to each file's bytes is the
registry's own content addressing.

`attach` (and `verify`, which repeats it) accepts a manifest only when:

- it is an image manifest (OCI or Docker schema 2), not an index;
- every layer's media type is one whose producer writes one file's raw bytes
  (the table below), and its digest is SHA-256;
- for a **single-file** attestation, the manifest has exactly one layer, its
  digest is the file's SHA-256, and its size is the file's size. The layer's
  file name annotation is recorded, not compared: a name does not change the
  bytes;
- for a **model directory**, every layer names its file path
  (`org.cncf.model.filepath`, its earlier name `org.cnai.model.filepath`, or
  `org.opencontainers.image.title`; two that disagree are refused), each path
  is an attested file with that SHA-256 and size, no two layers name one
  path, and every attested file is a layer. Paths are relative; one that is
  absolute or leaves the directory is refused.

A single-file attestation of a GGUF does not bind an artifact that also
carries a license or a chat-template layer: the template is something the
serving stack loads, and the attestation did not check it. Scan a model
directory holding every file the artifact carries, at the paths its layers
name, and attach that attestation instead. A layer that names no path cannot
be placed in a directory, so such an artifact can be bound only as a single
file.

| Producer | Layer media types matched | Not matched |
|---|---|---|
| CNCF ModelPack (model-spec v0.0.7; modctl builds raw layers by default) | `application/vnd.cncf.model.{weight,weight.config,doc,code,dataset}.v1.raw`, and the pre-CNCF `application/vnd.cnai.model.*.v1.raw` names modctl v0.2.2 still writes | `.tar`, `.tar+gzip`, `.tar+zstd` |
| KitOps ModelKit (v1.16.0) | `application/vnd.kitops.modelkit.{model,modelpart,dataset,code,docs,mcpb}.v1.raw` (`kit pack --layer-format raw`) | the default `.v1.tar`, and every `+gzip` or `+zstd` layer, raw included |
| Docker Model Runner (v1.2.8) | `application/vnd.docker.ai.{gguf.v3,safetensors,dduf,mmproj,license,chat.template.jinja,model.file}`, and the older `application/vnd.cncf.model.weight.v1.{gguf,safetensors}` it still reads | `application/vnd.docker.ai.dir.tar`, `application/vnd.docker.ai.vllm.config.tar` |
| KServe ModelCar (an image with the model under `/models`) | none | every layer: image layers are tar archives (`application/vnd.oci.image.layer.v1.tar+gzip`, `application/vnd.docker.image.rootfs.diff.tar.gzip`) |
| ORAS (`oras push <file>`) | a file pushed with one of the types above | the default `application/vnd.oci.image.layer.v1.tar`, which ORAS gives a plain file too: the type says tar, so a consumer may unpack it |

A tar or compressed layer is refused with the reason: a consumer unpacks or
decodes it, so the bytes it loads are not the blob's, and v1 does not unpack
layers to map the files inside them. Binding a ModelCar image, whose model
sits in tar layers on top of a base image, needs that mapping (and rules for
whiteouts, links, and later layers overwriting earlier ones); it is not built.

## What verify checks

`socair verify <oci-ref>` resolves the reference, lists the artifact's
referrers of type `application/vnd.socair.attestation.v1+json`, and for each:

1. its manifest's `subject` is this artifact's manifest digest;
2. its layers are one binding and one attestation, each a DSSE envelope;
3. the binding's signature verifies against the trusted keys, and its subject
   is this artifact's manifest digest;
4. the attestation verifies (the same checks as `socair verify <file>`) and
   its issuer is confirmed or reported as claimed;
5. the binding names this attestation by its envelope's hash, and every
   field it repeats (subject, document, issue time, signer, check set,
   promotion state, acceptance) is what the attestation says;
6. the manifest's layers match the attested bytes, checked again here rather
   than taken from the binding;
7. for a conditional attestation, with `--acceptors` (or `--store`), its
   signed acceptance verifies and is current.

It prints each referrer, verified or not and why, and whether a Sigstore
bundle carrying the same binding is present. It exits non-zero when none
verifies. A verified attestation's promotion state is printed, not judged:
`verify` says what a trusted key vouched for, and a withheld attestation
verifies as withheld.

## What the registry holds

Each `attach` pushes two image manifests whose `subject` is the artifact,
both with the OCI empty config:

- the **Socair referrer**, `artifactType`
  `application/vnd.socair.attestation.v1+json`, with two layers of media type
  `application/vnd.dsse.envelope.v1+json`: the binding and the attestation
  (each annotated `ai.socair.predicate-type`, a hint only);
- the **Sigstore bundle referrer**, `artifactType` and layer media type
  `application/vnd.dev.sigstore.bundle.v0.3+json`, annotated
  `dev.sigstore.bundle.content: dsse-envelope` and
  `dev.sigstore.bundle.predicateType: https://socair.ai/oci-binding/v1`, as
  cosign v3 writes an attestation.

On a registry with the referrers API (it answers a manifest push with
`OCI-Subject`), that is all. On one without it, each descriptor is added to
the image index tagged `sha256-<manifest hex>`, the referrers tag schema:
read, appended, and pushed back (with `If-Match` on its ETag when the
registry gives one, retried if another client changed it first). The spec
leaves races on that tag to clients; two clients without ETag support can
still overwrite each other's entry. Listing tries the referrers API and falls
back to that tag when the API answers 404. Attaching again adds new
referrers; `verify` reports every one.

## Admission verifiers

The Sigstore bundle copy is the binding's own signed statement (the same
payload and signature) in a Sigstore bundle v0.3 with a public-key
verification material and no transparency log entry. Its subject is the
manifest digest, which is what these verifiers compare with the image.

- **cosign** `verify-attestation` (v3.1.3) finds and verifies it with the
  operator's Ed25519 public key. Confirmed by running it
  (`SOCAIR_TEST_COSIGN=<cosign> go test ./internal/ociattest -run Cosign`),
  against registries with and without the referrers API; it refuses another
  key, an artifact with no binding, and a binding listed for an artifact other
  than its subject:

  ```
  cosign verify-attestation --key operator.pub --type https://socair.ai/oci-binding/v1 \
         --insecure-ignore-tlog=true registry.example/models/tiny@sha256:<manifest>
  ```

- **Kyverno** `ImageValidatingPolicy` (v1.19.1) reads the same bundle: its
  cosign verifier lists referrers for Sigstore bundles first and verifies
  with cosign's library (v3.1.2). The policy needs a `cosign` attestor with
  `key.data` and `ctlog.insecureIgnoreTlog: true`, and an `intoto`
  attestation whose type is `https://socair.ai/oci-binding/v1`. The policies
  in [`policies/kyverno`](../policies/kyverno) do this and read the promotion
  state; [admission.md](admission.md) describes them and the kind test that
  runs them against attached artifacts.
- **Sigstore policy-controller** (v0.15.1) is not served yet. For an
  authority with a key, it reads only cosign's legacy `sha256-<hex>.att` tag,
  and refuses the bundle format ("when using the new bundle format, the
  authority must be keyless"). Socair does not write that tag: it is cosign's
  own, shared with every cosign attestation of the image, and rewriting it
  risks another tool's data. [admission.md](admission.md#sigstore-policy-controller)
  says what would close the gap.

Notes for a policy author:

- **Ed25519.** cosign, and the Kyverno and policy-controller code paths read
  here, load a PEM `PUBLIC KEY` with sigstore's `LoadVerifier`, which verifies
  Ed25519 directly (no prehash). Socair's key files work as they are.
- **Key id.** The bundle's DSSE signature carries no key id, and the bundle
  gives no key hint. sigstore-go, which cosign and Kyverno verify bundles
  with, skips a signature whose key id is not its own SSH-style fingerprint of
  the key, and Socair's key id is the hex SHA-256 of the key's DER; a run with
  the key id kept fails ("accepted signatures do not match threshold"). The
  key id is not signed, so dropping it leaves the signature as it was. The
  bundle specification requires a hint, when one is given, to equal the
  envelope's key id, so none is given.
- **No transparency log.** Socair verifies offline and records nothing in a
  public log, so the verifier must be told to verify with the key and skip the
  log (`--insecure-ignore-tlog=true`, `ctlog.insecureIgnoreTlog: true`).
  That gives up what a log adds: a public record of the signature and a
  trusted signing time. The binding's `bound_utc` is the signer's claim.
- **Read the state.** A verified binding is not an approval. The policy must
  read `predicate.attestation.promotion_state` (and, for
  `authorized_with_conditions`, whether conditions are acceptable and
  `acceptance_expires`). The full report stays in the Socair referrer; a
  policy that needs it, or the attestation's own signature, can run
  `socair verify` or `socair-verify`.

## Registry access

- **Authentication.** Anonymous, HTTP Basic, or the bearer-token flow a
  registry's `WWW-Authenticate` challenge names (a token request to its realm
  with the service and a `repository:<name>:pull` or `:pull,push` scope).
  Credentials are static entries in the Docker config's `auths`
  (`$DOCKER_CONFIG/config.json`, else `~/.docker/config.json`): `auth`
  (base64 of user:password) or `username` and `password`. Docker Hub's key is
  `https://index.docker.io/v1/`. Credential helpers (`credsStore`,
  `credHelpers`) and identity tokens are not used; a 401 or 403 says which was
  the case.
- **Where a credential goes.** The password goes only to the registry host the
  reference names (for a Basic challenge) or the token realm that host's
  challenge names (Docker Hub's is `auth.docker.io`), and only over https or
  to a loopback host. A token goes only to the registry host and port. On any
  redirect to another host or port (a blob served from object storage), the
  `Authorization` header is dropped; net/http alone would keep it for a
  subdomain or another port. An https-to-http redirect is refused. Errors name
  URLs without their query string, which can be a signed storage URL.
- **Egress.** `SOCAIR_EGRESS=deny` refuses every registry request, for
  `attach` and for `verify`, as it refuses `airlock pull`. The registry is the
  one the reference names; blob redirects go to whatever host the registry
  sends them to, without credentials.
- **Transport.** https, except to a loopback host (`localhost`, `127.0.0.1`,
  `::1`), where plain http is used, as a local registry is commonly run.
- **Limits.** A manifest or index is read up to 4 MiB, an envelope blob up to
  64 MiB, and the referrers listing up to 100 pages. `verify` checks at most
  64 Socair referrers of one artifact and counts the rest, so a flood of
  referrers can make it fail but not pass. Each request has a one minute
  budget. No model layer is ever downloaded.
- **Digests.** Every manifest and blob is hashed on receipt and checked
  against the digest it was asked for. A `Docker-Content-Digest` header that
  disagrees with the bytes is an error; the header is never trusted alone.

## What is not checked

- **The manifest's config blob** (ModelPack's model config, a KitOps
  Kitfile, Docker Model Runner's config). The binding names it, but the
  attestation does not cover it. A consumer that places files by its config
  rather than by layer annotations (a Kitfile names paths) could place them
  differently from the paths matched here.
- **What the consumer does with the layers.** Docker Model Runner renames GGUF
  shards when it unpacks them; a serving stack may read files from elsewhere.
  The binding is about the bytes in the layers, at the paths the layers name.
- **That the consumer checks layer digests.** The content-addressing chain
  holds when the consumer pulls by digest and verifies blobs, as containerd
  does. An admission policy should pin the image digest.
- **A tag.** `verify` resolves a tag when it runs; the tag can move after.
  The binding is for a digest.
- **Tar or compressed layers, image indexes, and ModelCar images**: refused,
  as above.
- **Revocation.** A binding stays valid while its signing key is trusted. A
  newer attestation does not withdraw an older one; `verify` shows all, with
  their issue times.

## Testing

`internal/registry/registrytest` is an in-process registry with the subset
the client uses, with or without the referrers API, with Basic or bearer
authentication, and with blob redirects to another port. The tests cover the
fallback, a tampered envelope, an untrusted key, a referrer whose subject is
another artifact, a binding for another artifact that carries the same bytes
(the issue's falsification: it fails if the binding subject check is
removed), a binding whose layers do not carry the attested bytes, a binding
that misstates the promotion state, a re-encoded attestation envelope, and a
credential that must not follow a redirect.

Two opt-in tests need a tool or a registry:

```
SOCAIR_TEST_COSIGN=/path/to/cosign go test ./internal/ociattest -run Cosign -v
SOCAIR_TEST_REGISTRY=127.0.0.1:5000 go test ./internal/ociattest -run RealRegistry -v
```

The first runs cosign `verify-attestation` against the in-process registry.
The second pushes a small artifact to a real registry (a scratch one: it
writes to it), attaches, and verifies, and runs cosign there too when
`SOCAIR_TEST_COSIGN` is set. Both passed with cosign v3.1.3 against zot
v2.1.22 (which has the referrers API) and crane 0.22.1's registry (which does
not).

## Sources

- OCI distribution spec v1.1.1: [listing referrers](https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md#listing-referrers), [pushing manifests with subject](https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md#pushing-manifests-with-subject), [referrers tag schema](https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md#referrers-tag-schema), [unavailable referrers API](https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md#unavailable-referrers-api), [pulling manifests](https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md#pulling-manifests), [POST then PUT](https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md#post-then-put).
- OCI image spec v1.1.1: [manifest](https://github.com/opencontainers/image-spec/blob/v1.1.1/manifest.md) (`subject`, `artifactType`, the empty descriptor), [descriptor](https://github.com/opencontainers/image-spec/blob/v1.1.1/descriptor.md), [annotations](https://github.com/opencontainers/image-spec/blob/v1.1.1/annotations.md) (`org.opencontainers.image.title`).
- Token authentication: [distribution v3.0.0 token.md](https://github.com/distribution/distribution/blob/v3.0.0/docs/content/spec/auth/token.md). Docker config: [docker/cli v27.5.1 configfile/file.go](https://github.com/docker/cli/blob/v27.5.1/cli/config/configfile/file.go), [types/authconfig.go](https://github.com/docker/cli/blob/v27.5.1/cli/config/types/authconfig.go).
- cosign v3.1.3: [pkg/oci/remote/write.go](https://github.com/sigstore/cosign/blob/v3.1.3/pkg/oci/remote/write.go) (`WriteAttestationNewBundleFormat`, `WriteReferrer`), [pkg/oci/remote/signatures.go](https://github.com/sigstore/cosign/blob/v3.1.3/pkg/oci/remote/signatures.go) (bundle reader), [pkg/cosign/verify.go](https://github.com/sigstore/cosign/blob/v3.1.3/pkg/cosign/verify.go) (`GetBundles`), [pkg/oci/remote/remote.go](https://github.com/sigstore/cosign/blob/v3.1.3/pkg/oci/remote/remote.go) (the legacy `.att` tag).
- The versions cosign v3.1.3 pins: sigstore-go v1.2.2, [pkg/verify/signature.go](https://github.com/sigstore/sigstore-go/blob/v1.2.2/pkg/verify/signature.go) (the DSSE verifier is given the public key, so key ids are compared); go-securesystemslib v0.11.0, [dsse/verify.go](https://github.com/secure-systems-lab/go-securesystemslib/blob/v0.11.0/dsse/verify.go) (a signature whose key id differs from the verifier's is skipped); sigstore v1.10.8, [pkg/signature/verifier.go](https://github.com/sigstore/sigstore/blob/v1.10.8/pkg/signature/verifier.go) (an Ed25519 key gets a plain Ed25519 verifier).
- Sigstore bundle: [protobuf-specs v0.5.1 sigstore_bundle.proto](https://github.com/sigstore/protobuf-specs/blob/v0.5.1/protos/sigstore_bundle.proto) (media type v0.3, the key hint rule).
- Kyverno v1.19.1: [pkg/image/verifiers/ivpol/cosign/verifier.go](https://github.com/kyverno/kyverno/blob/v1.19.1/pkg/image/verifiers/ivpol/cosign/verifier.go) (bundle detection), [opts.go](https://github.com/kyverno/kyverno/blob/v1.19.1/pkg/image/verifiers/ivpol/cosign/opts.go) (key with the log ignored needs no Sigstore infrastructure).
- Sigstore policy-controller v0.15.1: [pkg/webhook/validator.go](https://github.com/sigstore/policy-controller/blob/v0.15.1/pkg/webhook/validator.go) (the bundle format needs a keyless authority).
- ModelPack: [model-spec v0.0.7 mediatype.go](https://github.com/modelpack/model-spec/blob/6440437b4932ef6cdd134d24a410f73181303ce7/specs-go/v1/mediatype.go), [spec.md](https://github.com/modelpack/model-spec/blob/6440437b4932ef6cdd134d24a410f73181303ce7/docs/spec.md), [annotations.md](https://github.com/modelpack/model-spec/blob/6440437b4932ef6cdd134d24a410f73181303ce7/docs/annotations.md); [modctl v0.2.2 legacy.go](https://github.com/modelpack/modctl/blob/441e8482460ff53fa8ed4c00132211b7feb3a370/pkg/backend/build/legacy.go) (the `cnai` names), [cmd/build.go](https://github.com/modelpack/modctl/blob/441e8482460ff53fa8ed4c00132211b7feb3a370/cmd/build.go) (`--raw` defaults to true).
- KitOps v1.16.0: [mediatype/kitops.go](https://github.com/kitops-ml/kitops/blob/87cabec7c8f487dc54750ee9a206cdd4c79020e7/pkg/lib/constants/mediatype/kitops.go), [cmd/pack/cmd.go](https://github.com/kitops-ml/kitops/blob/87cabec7c8f487dc54750ee9a206cdd4c79020e7/pkg/cmd/pack/cmd.go) (`--layer-format tar` and `--compression none` by default).
- Docker Model Runner v1.2.8: [pkg/distribution/types/config.go](https://github.com/docker/model-runner/blob/5a3112fdc10bcfe236a7450fcfa7e83ed3c0209e/pkg/distribution/types/config.go).
- KServe v0.21.0: [pkg/constants/constants.go](https://github.com/kserve/kserve/blob/d1482554fc4f66dd41aee70e01f5174e24f265bd/pkg/constants/constants.go) (the `modelcar` container), and the [OCI storage docs](https://github.com/kserve/website/blob/fb4c67f9f9cca2cd680fb26abca3499bb3c2245e/docs/model-serving/storage/providers/oci.md) (`FROM busybox`, `COPY data/ /models/`).
- ORAS: [oras-go v2.6.2 content/file/file.go](https://github.com/oras-project/oras-go/blob/105715ee12eac6895ec736a075285c34d9f2eeb6/content/file/file.go) (a file's default media type is `application/vnd.oci.image.layer.v1.tar`).
