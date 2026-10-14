# Attestations on OCI model artifacts

A model packaged as an OCI artifact (a ModelPack artifact, a KitOps
ModelKit, a Docker Model Runner model) or as a container image that holds it
under a directory (a KServe ModelCar image) is pulled by its manifest digest,
and an admission controller checks statements about that digest. A Socair
attestation is about the model's bytes: a file's SHA-256, or for a model
directory the digest of its `socair.modeldir/v1` manifest. `socair attach`
connects the two and pushes the result into the registry beside the
artifact, as OCI referrers. `socair verify <oci-ref>` finds it there and
checks it.

```
socair attach <registry>/<repository>:<tag> --attestation r.dsse.json --key operator.key \
              (--trusted <key.pub|dir> | --store <path>) [--acceptors <key.pub|dir>] [--model-root <dir>]
socair verify <registry>/<repository>:<tag> (--trusted <key.pub|dir> | --store <path>) [--acceptors <key.pub|dir>]
```

`--model-root` names the directory of an image that holds the model
(`models`, KServe's, by default); it applies only to an image's tar layers
([Images](#images-the-files-inside-tar-layers)).

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
3. Matches the manifest's layers to the attested bytes: raw model layers by
   their digests ([below](#matching-layers-to-the-attested-bytes)), and an
   image's tar layers by the files inside them, which it reads
   ([Images](#images-the-files-inside-tar-layers)). Any mismatch refuses the
   attach and names the problem.
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
them from the statement it verified. `match` is `file`, `model-directory`, or
`model-root`, and `layers` lists every layer of the manifest. The binding's
signer is whoever ran `attach`; a verifier must trust that key as well as the
attestation's.

For an image (`match: model-root`), the artifact also names the directory the
attested files are in and the rules its layers were mapped under, and each
layer says its role and the attested files it holds:

```json
  "artifact": {
    "name": "registry.example/models/tiny-modelcar",
    "digest": "sha256:<manifest>",
    "media_type": "application/vnd.oci.image.manifest.v1+json",
    "config_media_type": "application/vnd.oci.image.config.v1+json",
    "config_digest": "sha256:<image config>",
    "match": "model-root",
    "model_root": "models",
    "layer_rules": "socair.tar-map/v1",
    "layers": [
      {"digest": "sha256:<busybox>", "size": 2165911, "media_type": "application/vnd.oci.image.layer.v1.tar+gzip",
       "role": "base", "entries": 443},
      {"digest": "sha256:<RUN mkdir /models>", "size": 131, "media_type": "application/vnd.oci.image.layer.v1.tar+gzip",
       "role": "base", "entries": 3},
      {"digest": "sha256:<COPY data/ /models/>", "size": 3294, "media_type": "application/vnd.oci.image.layer.v1.tar+gzip",
       "role": "model", "entries": 4, "files": ["config.json", "model.safetensors"]}
    ]
  }
```

A `model` layer holds files under the model root and, outside it, nothing but
the directories above it; a `base` layer holds nothing under the model root.
`files` are paths under the model root, as the attestation lists them.
`entries` counts the layer's tar entries. The fields were added to
`oci-binding/v1`: a raw-layer binding carries none of them and reads as
before.

The binding asserts what `attach` saw when it ran: these layers, by digest,
are the attested bytes, or for an image, its model root holds exactly the
attested files. It does not make the attestation say more than its bounded
statement.

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
| KServe ModelCar (an image with the model under `/models`) | mapped file by file, [below](#images-the-files-inside-tar-layers): `application/vnd.oci.image.layer.v1.tar`, `.tar+gzip`, and `application/vnd.docker.image.rootfs.diff.tar.gzip` | `.tar+zstd`; Docker's uncompressed `application/vnd.docker.image.rootfs.diff.tar`; foreign and non-distributable layers |
| ORAS (`oras push <file>`) | a file pushed with one of the raw types above | the default `application/vnd.oci.image.layer.v1.tar`, which ORAS gives a plain file too: the type says tar, so a consumer may unpack it. It is read as an image layer and refused when its bytes are not a tar archive |

A raw layer type with compression, and the tar types of ModelPack, KitOps,
and Docker Model Runner, are refused with the reason: a consumer unpacks or
decodes them, so the bytes it loads are not the blob's, and those producers
place the files by their own rules, which are not modelled. An image's layer
types are mapped, as the next section describes. An artifact that mixes raw
model layers and image layers is refused.

## Images: the files inside tar layers

A KServe ModelCar image is a container image: a base image (KServe's
documentation builds one `FROM busybox`) with the model copied under
`/models` (`RUN mkdir /models`, `COPY data/ /models/`). KServe v0.21.0 reads
the model from the image's `/models` in all three of its OCI modes: ModelCar
runs the image as a container and links `/mnt/models` to its `/models`;
`oci+native://` mounts the image as a volume with `subPath: models`; and
`oci+fetch://` extracts the entries named `models/…` from its tar layers
([admission.md](admission.md#where-a-pod-names-a-model)). A runtime unpacks
the layers in order, each on top of the last.

For such an image, `attach` reads every layer, in order, from the registry,
and checks that the tree a consumer unpacks holds, under the model root
(`--model-root`, `models` by default), exactly the attested files: for a
model directory, each file the attestation lists, at its path, and nothing
else; for a single-file attestation, one file directly in the model root
(its name recorded, not compared). Each is a regular file whose bytes hash
to the attested SHA-256. And it refuses anything in any layer that could make
that tree differ, for any of the consumers below, from what was scanned. The
first problem is reported, naming the layer and the entry.

### How a layer is read

- Each layer blob is streamed and hashed as it is read; the read that
  reaches its end fails unless the bytes hash to the layer's digest, and
  nothing read from it is trusted before then. Nothing is written to disk,
  and no file's content is held in memory: what is kept is the tree's
  symbolic links and the paths at, in, or above the model root.
- A layer is decompressed as it is read, by its media type, and its first
  bytes must agree: containerd and CRI-O decompress by the bytes (gzip and
  zstd; containers/image also bzip2 and xz), KServe's oci+fetch by the media
  type. A gzip layer must be one gzip member and nothing after it: Python's
  tarfile, reading a layer as a stream as KServe's oci+fetch does
  (`mode="r|gz"`), stops at the end of the first member without an error,
  where containerd reads them all, so a layer split into members at an entry
  boundary unpacks fewer files in KServe (seen with Python 3.14.7; 3.11.17's
  `_Stream._read` decompresses the same way).
- Each tar archive is read by Socair's own strict reader
  (`internal/ociattest/tarwalk`), which accepts only what Go's archive/tar
  (containerd's and CRI-O's reader) and Python's tarfile (KServe's) read the
  same way, and refuses the rest. Python's tarfile also ends an archive
  silently, with no error, at a header it cannot read past the first one, so
  every header it would refuse is refused here too.
- Each entry is placed as containerd's `applyNaive` places it: its parent
  path resolved through the symbolic links already in the tree, scoped to the
  image's root. containerd's overlayfs path applies each layer to its own
  directory without following links from lower layers, so where the two
  would differ for the model root, the entry is refused.

### What is refused

| Refused | Why |
|---|---|
| A file under the model root that the attestation does not list; a directory there that holds no attested file; an attested file missing | the tree would not be the scanned model directory |
| An attested file with other bytes or another size | it is not the scanned file |
| A path under the model root that appears twice, in one layer or in two (a later layer replacing a model file) | which one a consumer keeps depends on how it applies layers; the OCI image spec forbids duplicates in one layer |
| A whiteout (`.wh.<name>`) of the model root, a path in it, or a directory above it; an opaque whiteout (`.wh..wh..opq`) on any of those; a whiteout that is not an empty regular file; AUFS names (`.wh..wh.*`); a path through a directory named `.wh.*` | containerd removes what it names, and KServe's oci+fetch does not apply whiteouts at all (it extracts them as files) |
| A symbolic link at the model root, in it, or above it; anywhere else, one whose target leads to the model root, into it, or above it, checked as written (cleaned) and as resolved through the tree, when it is read and again in the final tree | an entry written through it would land in the model root, and a consumer reading the model root would follow it elsewhere |
| An entry whose path reaches the model root through a symbolic link, or an entry in the model root whose path goes through one | containerd's two apply paths place it differently |
| A hard link at the model root, in it, or above it; a hard link to a path there; a hard link to a symbolic link | a second name for a model file, or another link that the walk does not see as one |
| A device file or FIFO at the model root, in it, or above it (outside it they are allowed: base images such as Amazon Linux 2023 and Wolfi ship `/dev` nodes) | it would replace what the model needs, and a 0/0 character device in an overlayfs layer is a whiteout |
| An absolute name; a name with a `..`, `.`, or empty part; a trailing `/` on anything but a directory; a name in the model root with a leading `./` | consumers clean names differently: containerd joins them to the root, containers/storage refuses a `..` that leaves it, KServe matches `models/<path>` on the raw name |
| A layer that holds files in the model root and anything outside it but the directories above it | its role would be ambiguous: the binding says which layers hold the model and which are the base |
| An overlayfs extended attribute (`trusted.overlay.*`, `user.overlay.*`) in a PAX record | containerd sets the archive's extended attributes, and overlayfs reads these as whiteouts, opaque directories, or redirects |
| PAX global headers, Solaris extended headers, GNU sparse files and PAX `GNU.*` records, `hdrcharset`, the NUL regular-file type flag, type 7, unknown type flags, star headers, V7 headers | Go's archive/tar and Python's tarfile read them differently, or one of the consumers does not support them |
| Two PAX headers before one entry; a PAX header and a GNU long name or link on one entry; two GNU long names or links | Go applies the last, Python the first, or each applies them in the opposite order |
| A numeric field Go and Python read differently (a NUL before the digits, a digit after a terminator, a negative or 0x81-led base-256 number); a PAX number or time that is not decimal; an empty PAX path; a NUL in a PAX key or name | Go refuses some, and Python reads others as 0 or as another number, so the two would read different sizes and lose step |
| A PAX size over a header size field that holds another size (unless the size does not fit the field) | a reader that ignores PAX records would read the data as headers ([CVE-2025-62518](https://github.com/advisories/GHSA-j5gw-2vrg-8fgx)) |
| Bytes in the padding after a PAX or GNU long-name header's data; a zero block followed by a header; anything but zeros after the end-of-archive marker; no end-of-archive marker | Python's tarfile reads the padding as part of the header and stops at a zero block, where Go's archive/tar does neither |
| `+zstd` layers; Docker's uncompressed `rootfs.diff.tar`; foreign and non-distributable layers, and any layer that names `urls` | no zstd decoder among Socair's dependencies (KServe's oci+fetch refuses zstd too); KServe's oci+fetch skips the Docker type; the others are fetched from outside the registry |

The [tar extraction vulnerabilities](#tar-extraction-vulnerabilities) these
rules answer are listed below.

### What the binding covers, and what it does not

A `model-root` binding covers the files under the model root, as containerd,
CRI-O, and KServe's oci+fetch unpack the image pinned by its manifest digest.
It does not cover:

- **The base layers' content.** Files outside the model root are checked only
  for not reaching into it: their names, link targets, and whiteouts. Their
  bytes are not examined. Each layer's `role` says which they are.
- **The image config**: its entrypoint, command, environment, user, and
  working directory. The binding names it by digest, as for any artifact.
- **What a container that runs the image does.** KServe's ModelCar runs the
  model image as a container (`sh -c "ln -sf /proc/$$/root/models /mnt/models
  && sleep infinity"`, with the image's entrypoint, if any, in front, and a
  writable root filesystem). The base image's programs, and the config's
  entrypoint, run there, and could change the files under `/models` or point
  `/mnt/models` elsewhere after the pod starts. `oci+native://` (a read-only
  image volume with `subPath: models`) and `oci+fetch://` (KServe's own
  storage initializer extracting `models/`) run nothing from the image.

So an `authorized` binding of an image says the model root holds the
authorized model; it says nothing about the base image. The shipped Kyverno
policies refuse a pod that runs such an image as a container unless the
operator says otherwise ([admission.md](admission.md#kserve-modelcar-images)).

### Limits

- At most 256 layers and 1,048,576 entries in all; a name or link target of
  at most 4,096 bytes, a name part of at most 255; a PAX header of at most
  1 MiB; at most 40 symbolic links on one path (Linux's limit; containerd
  follows up to 255, so a deeper chain is refused, not misread).
- A layer may decompress to at most 128 times its compressed size, or 64 MiB
  if that is larger.
- The registry must keep sending: a layer whose body sends nothing for a
  minute fails. There is no overall time limit, as a layer can be many
  gigabytes; `verify` reads every layer again.

### Consumers modelled

The rules come from these sources, read for this change:

- **containerd v2.3.4** (the kind v1.35.8 node's): `pkg/archive/tar.go`
  (`applyNaive`: names cleaned, parents resolved with `fs.RootPath`,
  whiteouts and opaque markers, an entry replacing what is at its path, hard
  links resolved with `hardlinkRootPath`, `SCHILY.xattr.*` set),
  `core/diff/apply/apply_linux.go` (the overlayfs path applies each layer to
  its upper directory), `pkg/archive/tar_opts_linux.go`
  (`OverlayConvertWhiteout`: a 0/0 character device, the opaque attribute),
  `pkg/archive/compression/compression.go` (decompression by the bytes).
- **CRI-O v1.35.10**, through containers/storage at
  [`b0f86df`](https://github.com/containers/container-libs/blob/b0f86df5a66598b80ddf7d4cbd88165981d3370c/storage/pkg/archive/diff.go)
  (`UnpackLayer`: Go's archive/tar, `..` that leaves the root refused, AUFS
  metadata skipped) and containers/image v5.38.0 (gzip, bzip2, xz, and zstd
  detected by the bytes).
- **KServe v0.21.0**: `kserve_storage.py` (`_download_oci`: layers by media
  type, `tarfile.open(mode="r|gz")` or `"r|"`, entries named `models/…`
  extracted with `filter="data"`, no whiteouts), on Python 3.11
  (`storage-initializer.Dockerfile`; 3.11.17 is what its base image,
  `python:3.11-slim-bookworm`, holds); `pkg/utils/storage.go` (the ModelCar
  containers' commands).
- **Python 3.11.17** `Lib/tarfile.py`: `frombuf` (the prefix field read
  whatever the magic), `nti`, `_proc_pax` (records read from the padded
  data), `_proc_gnulong`, `_apply_pax_info`, `_Stream._read` (one gzip
  member), `TarFile.next` (a header error after the first ends the archive
  silently), `data_filter`.
- **Go 1.27.1** `archive/tar` (`reader.go`, `format.go`, `strconv.go`).
- **OCI image spec v1.1.1** [`layer.md`](https://github.com/opencontainers/image-spec/blob/v1.1.1/layer.md):
  no duplicate paths in a layer, whiteouts and opaque whiteouts, sparse files
  discouraged.

The strict reader is checked against Go's archive/tar by a fuzz target, and
against Python's tarfile by an opt-in test that ran on 57,225 accepted
archives with Python 3.11.17 and 19,004 with 3.14.7 (below). The mapping is checked by a
fuzz target against models of containerd's two apply paths and of KServe's
oci+fetch: when it accepts an image, each model's tree under `/models` is
exactly the attested files. The models are written from the sources above;
they are not the consumers themselves.

### Real base images

A model layer (`COPY data/ /models/`) put on top of each of these base images
maps (`TestRealBaseImages`, linux/amd64, pulled 2026-10-14): busybox:1.37,
alpine:3.22, debian:bookworm-slim, ubuntu:24.04, python:3.11-slim-bookworm,
gcr.io/distroless/static-debian12, ubi9/ubi-micro, ubi9/ubi-minimal,
amazonlinux:2023, cgr.dev/chainguard/wolfi-base, quay.io/fedora/fedora-minimal:42,
and nvidia/cuda:12.6.3-base-ubuntu24.04. Two of them first showed rules too
strict for real images, since relaxed: ubi-minimal stores a binary
`security.capability` attribute (NUL bytes in a PAX value, which both readers
accept), and Amazon Linux 2023 and Wolfi ship `/dev` device nodes.

### Tar extraction vulnerabilities

The classes the rules answer, with an advisory each:

- path traversal by name (`..`, absolute paths): Python tarfile
  [CVE-2007-4559](https://github.com/advisories/GHSA-gw9q-c7gh-j9vm);
- escape or redirection through symbolic and hard links, including through
  the extraction filters meant to stop it: Python tarfile
  [CVE-2025-4138](https://github.com/advisories/GHSA-4g4g-fqw4-prp2),
  [CVE-2025-4330](https://github.com/advisories/GHSA-68pj-xrp5-vccj),
  [CVE-2025-4517](https://github.com/advisories/GHSA-6r6c-684h-9j7p),
  [CVE-2024-12718](https://github.com/advisories/GHSA-2pg8-h2j6-28xm);
  containerd [CVE-2021-32760](https://github.com/advisories/GHSA-c72p-9xmj-rx3w);
  docker cp [CVE-2018-15664](https://github.com/advisories/GHSA-pv79-5r2c-jrpq);
- parser differentials on headers, where two readers see different entries:
  [CVE-2025-62518](https://github.com/advisories/GHSA-j5gw-2vrg-8fgx)
  (a PAX size one reader ignores);
- unbounded reads: Go archive/tar
  [CVE-2022-2879](https://github.com/advisories/GHSA-fqpx-62jv-7r6r) (header
  size) and [CVE-2025-58183](https://github.com/advisories/GHSA-9gcr-gp5f-jw27)
  (sparse maps); containerd
  [CVE-2023-25153](https://github.com/advisories/GHSA-259w-8hf6-59c2);
  Python tarfile [CVE-2024-6232](https://github.com/advisories/GHSA-mmm5-wgvp-wp8r)
  (PAX parsing) and [CVE-2025-8194](https://github.com/advisories/GHSA-v594-44hm-2j7p).

Duplicate entries and overlay order have no advisory of their own; they are
the image-layer form of the same problem: what one consumer keeps, another
replaces.

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
   than taken from the binding, and what the binding states about them (the
   match, the model root, the layer rules, and each layer's digest, size,
   type, path, role, entries, and files) is what this check found. For an
   image, that means reading every layer again, under the model root the
   binding names; a binding made under other layer rules than this socair's
   does not verify. The result is kept for each attestation, so two
   referrers of one attestation read the layers once;
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
  budget. A raw model layer is never downloaded. An image's tar layers are
  streamed, with no overall budget, and fail when the registry sends nothing
  for a minute; they are hashed as read and never written to disk.
- **Digests.** Every manifest and blob is hashed on receipt and checked
  against the digest it was asked for. A `Docker-Content-Digest` header that
  disagrees with the bytes is an error; the header is never trusted alone.

## What is not checked

- **The manifest's config blob** (ModelPack's model config, a KitOps
  Kitfile, Docker Model Runner's config, an image's config). The binding
  names it, but the attestation does not cover it. A consumer that places
  files by its config rather than by layer annotations (a Kitfile names
  paths) could place them differently from the paths matched here; a
  container that runs an image runs its config's entrypoint.
- **An image's base layers, and what a container that runs it does**, as
  [above](#what-the-binding-covers-and-what-it-does-not).
- **What the consumer does with the layers.** Docker Model Runner renames GGUF
  shards when it unpacks them; a serving stack may read files from elsewhere.
  The binding is about the bytes in the layers, at the paths the layers name.
- **That the consumer checks layer digests.** The content-addressing chain
  holds when the consumer pulls by digest and verifies blobs, as containerd
  does. An admission policy should pin the image digest.
- **A tag.** `verify` resolves a tag when it runs; the tag can move after.
  The binding is for a digest.
- **The tar layers of ModelPack, KitOps, and Docker Model Runner, compressed
  raw layers, and image indexes**: refused, as above. A multi-platform image
  (an index, as `docker buildx` pushes) is attached one platform manifest at
  a time, and a pod must name that manifest's digest.
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

For images, the layers are built in code (a busybox-like base, the layer
`RUN mkdir /models` leaves, and `COPY data/ /models/`). A ModelCar image maps,
attaches, and verifies; each refusal in the table above has a test with an
image that differs from the ModelCar image in that one way, so each is the
falsification test of its check (`TestMapRefusals`, `TestRefusals` in
`tarwalk`). Each check was also removed in turn, and a test failed for each
(the PR records the run). A layer the registry serves with other bytes of the
same length, which would map, is refused at the end of its read
(`TestAttachRefusesALayerServedWithOtherBytes`), and a binding that misstates
its layers, its root, or its rules does not verify.

Fuzz targets: `FuzzWalk` and `FuzzWalkHeaders` (`internal/ociattest/tarwalk`)
check that whatever the strict reader accepts, Go's archive/tar reads to the
same entries and bytes; `FuzzMapLayers` (`internal/ociattest`) builds images
from a vocabulary of names, links, whiteouts, and devices that reach, cross,
or avoid the model root, and checks that whenever the mapping accepts one,
the models of containerd's two apply paths and of KServe's oci+fetch unpack
exactly the attested files under `/models`.

Opt-in tests that need a tool, a registry, or real images:

```
SOCAIR_TEST_COSIGN=/path/to/cosign go test ./internal/ociattest -run Cosign -v
SOCAIR_TEST_REGISTRY=127.0.0.1:5000 go test ./internal/ociattest -run RealRegistry -v
SOCAIR_TEST_PYTHON=python3 go test ./internal/ociattest/tarwalk -run PythonAgrees -v
SOCAIR_OCI_BASE_CORPUS=<OCI layouts> go test ./internal/ociattest -run RealBaseImages -v
```

The first runs cosign `verify-attestation` against the in-process registry.
The second pushes a small artifact to a real registry (a scratch one: it
writes to it), attaches, and verifies, and runs cosign there too when
`SOCAIR_TEST_COSIGN` is set. Both passed with cosign v3.1.3 against zot
v2.1.22 (which has the referrers API) and crane 0.22.1's registry (which does
not).

The third reads every archive the strict reader accepts, from seeds and from
mutated seeds with their checksums fixed (`SOCAIR_TEST_PYTHON_N` and
`_SEED` set how many and which), with Python's tarfile in stream mode, as
KServe's oci+fetch does, and fails on any difference. `SOCAIR_TEST_PYTHON`
may be a wrapper that runs Python in KServe's storage-initializer base image
(`docker run python:3.11-slim-bookworm python3 "$@"`, with the directories
mounted). On the rules as merged, it passed on 57,225 accepted archives
(seeds 11 to 13, 60,000 tries each) with Python 3.11.17 in that image, and
19,004 (seed 11) with Python 3.14.7. Before the padding rule, it found three
archives the two read differently.

The fourth maps each image in OCI layouts (`crane pull --format oci`) with a
model layer added on top ([Real base images](#real-base-images)).

`scripts/admission-e2e.sh` attaches a ModelCar image built with `docker
build` from KServe's documented Dockerfile and runs it in kind
([admission.md](admission.md#testing)).

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
- KServe v0.21.0: [pkg/constants/constants.go](https://github.com/kserve/kserve/blob/d1482554fc4f66dd41aee70e01f5174e24f265bd/pkg/constants/constants.go) (the `modelcar` container), [pkg/utils/storage.go](https://github.com/kserve/kserve/blob/d1482554fc4f66dd41aee70e01f5174e24f265bd/pkg/utils/storage.go) (`modelcarCommand`, `CreateModelcarContainer`, `CreateModelcarInitContainer`: `sh -c` as the image's arguments, the `/models` check, `subPath: models` for `oci+native://`), [python/storage/kserve_storage/kserve_storage.py](https://github.com/kserve/kserve/blob/d1482554fc4f66dd41aee70e01f5174e24f265bd/python/storage/kserve_storage/kserve_storage.py) (`_LAYER_MEDIA_TYPE_MODES`, `_download_oci`), [python/storage-initializer.Dockerfile](https://github.com/kserve/kserve/blob/d1482554fc4f66dd41aee70e01f5174e24f265bd/python/storage-initializer.Dockerfile) (Python 3.11), and the [OCI storage docs](https://github.com/kserve/website/blob/fb4c67f9f9cca2cd680fb26abca3499bb3c2245e/docs/model-serving/storage/providers/oci.md) (`FROM busybox`, `RUN mkdir /models && chmod 775 /models`, `COPY data/ /models/`).
- containerd v2.3.4: [pkg/archive/tar.go](https://github.com/containerd/containerd/blob/v2.3.4/pkg/archive/tar.go) (`applyNaive`, `createTarFile`, `hardlinkRootPath`, `validateWhiteout`), [pkg/archive/tar_opts_linux.go](https://github.com/containerd/containerd/blob/v2.3.4/pkg/archive/tar_opts_linux.go) (`OverlayConvertWhiteout`), [pkg/archive/tar_unix.go](https://github.com/containerd/containerd/blob/v2.3.4/pkg/archive/tar_unix.go) (devices), [core/diff/apply/apply_linux.go](https://github.com/containerd/containerd/blob/v2.3.4/core/diff/apply/apply_linux.go) (the overlayfs path), [pkg/archive/compression/compression.go](https://github.com/containerd/containerd/blob/v2.3.4/pkg/archive/compression/compression.go) (`DetectCompression`), [core/unpack/unpacker.go](https://github.com/containerd/containerd/blob/v2.3.4/core/unpack/unpacker.go) (diff IDs checked). The kind v1.35.8 node image runs it (`containerd --version` in the image).
- CRI-O [v1.35.10 go.mod](https://github.com/cri-o/cri-o/blob/v1.35.10/go.mod) (go.podman.io/storage at `b0f86df`, go.podman.io/image v5.38.0): containers/storage [pkg/archive/diff.go](https://github.com/containers/container-libs/blob/b0f86df5a66598b80ddf7d4cbd88165981d3370c/storage/pkg/archive/diff.go) (`UnpackLayer`), [pkg/archive/archive.go](https://github.com/containers/container-libs/blob/b0f86df5a66598b80ddf7d4cbd88165981d3370c/storage/pkg/archive/archive.go) (`SCHILY.xattr.` only); containers/image [pkg/compression/compression.go](https://github.com/containers/container-libs/blob/image/v5.38.0/image/pkg/compression/compression.go).
- Python 3.11.17: [Lib/tarfile.py](https://github.com/python/cpython/blob/v3.11.17/Lib/tarfile.py) (`nts`, `nti`, `TarInfo._frombuf`, `_proc_member`, `_proc_gnulong`, `_proc_pax`, `_apply_pax_info`, `_Stream._read`, `TarFile.next`, `_get_filtered_attrs`). `python:3.11-slim-bookworm` held 3.11.17 on 2026-10-14.
- Go 1.27.1: [src/archive/tar/reader.go](https://github.com/golang/go/blob/go1.27.1/src/archive/tar/reader.go) (`next`, `readHeader`, `mergePAX`, `parsePAX`), [format.go](https://github.com/golang/go/blob/go1.27.1/src/archive/tar/format.go) (`getFormat`), [strconv.go](https://github.com/golang/go/blob/go1.27.1/src/archive/tar/strconv.go) (`parseNumeric`, `parseOctal`, `parsePAXRecord`, `parsePAXTime`, `validPAXRecord`).
- OCI image spec v1.1.1: [layer.md](https://github.com/opencontainers/image-spec/blob/v1.1.1/layer.md) (duplicate paths, whiteouts, opaque whiteouts, sparse files), [media-types.md](https://github.com/opencontainers/image-spec/blob/v1.1.1/media-types.md).
- Kubernetes [KEP-4639](https://github.com/kubernetes/enhancements/blob/c3cbc64a900d0fc37389c2865f69e666ced74c5f/keps/sig-node/4639-oci-volume-source/README.md) (image volumes are read-only; the `noexec` requirement was dropped for beta).
- ORAS: [oras-go v2.6.2 content/file/file.go](https://github.com/oras-project/oras-go/blob/105715ee12eac6895ec736a075285c34d9f2eeb6/content/file/file.go) (a file's default media type is `application/vnd.oci.image.layer.v1.tar`).
