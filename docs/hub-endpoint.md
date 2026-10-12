# The hub endpoint

`socair airlock serve-hub` serves the [airlock](airlock.md)'s clean store to
inference servers over a read-only subset of the Hugging Face Hub HTTP API:
the requests `huggingface_hub` makes to download a model. A server pointed at
it with `HF_ENDPOINT` downloads the promoted bytes of the models the store
admits, and nothing else the store holds.

```
socair airlock serve-hub [--addr 127.0.0.1:8081] [--allow-public] [--authorized-only] [--store <path>]

HF_ENDPOINT=http://127.0.0.1:8081 hf download org/name
HF_ENDPOINT=http://127.0.0.1:8081 vllm serve org/name
```

It is a separate listener from `socair serve`, and a separate process. The
API there reads and writes the store; this endpoint only reads it. On
Kubernetes it runs in its own container with the store mounted read-only
([Kubernetes](#kubernetes)).

## What it serves

A model is served only while the store admits it, checked on every request
the way the console derives `approved` (`Store.Assess`, then the recheck
evidence):

- its attestation verifies against `trusted-keys/`, names this entry's hash,
  and its promotion state crosses the gate;
- a conditional promotion's signed acceptance verifies against
  `acceptor-keys/` and has not expired. Serving stops at the expiry instant.
  `--authorized-only` never serves a conditional promotion, matching LLMKube's
  `allowConditions: false`;
- no recheck has flagged it, and its `recheck.json` can be read.

A staged artifact, a withheld or escalated attestation, an expired
acceptance, an attestation that does not verify, and a flagged model are not
served. Each is answered exactly as a model that does not exist (404,
`X-Error-Code: RepoNotFound`); the reason goes to the endpoint's log only.

Of a served model, it serves the files its verified attestation lists and no
others: the single file, or every file of a model directory. A request path
is looked up among those paths and never joined to the disk. The file is then
opened beneath `clean/<hash>/` through Go's `os.Root`, so no name resolves
outside the entry, and a symlink anywhere on the way is refused even inside
it (promote writes regular files only). `incoming/`, the activity log, the
keys, and other clean entries are never reachable.

A download that started before a model was flagged, or before its acceptance
expired, runs to its end.

## Names and revisions

| Address | Which models | Example |
|---|---|---|
| `org/name` | an entry whose attestation records that repo (its `artifact.repo_url`) | `Qwen/Qwen3-8B` |
| `sha256/<hash>` | every served entry, by its hash (a file's SHA-256, a model directory's manifest digest) | `sha256/03639bb7...` |

A model pulled with `socair airlock pull` keeps its repo id, because the
pull's provenance manifest names the repo and a scan with it writes the repo
URL into the signed report. A serving configuration then changes only by
`HF_ENDPOINT`. The repo id is a label the signer vouched for, not a check:
the bytes are bound by the hash. A model promoted from a local file has no
repo id and is addressed by its hash only. Repo ids are matched exactly, as
written in the report; a one-part legacy id (`gpt2`) is not served.

| Revision | Resolves to |
|---|---|
| `main` (what clients send by default) | the repo's admitted entries, if they share one commit; refused with 409 naming each commit if not |
| a 40-hex commit | the entries whose attestation records that commit |
| the entry's 64-hex hash | that entry alone |

Any other branch, tag, or `refs/pr/...` is `RevisionNotFound`.

The commit the endpoint reports (`sha` in the model info, `X-Repo-Commit` on
files) is the commit the attestation records the bytes came from. An entry
that records none reports the first 40 hex digits of its hash, which is not a
git commit; it is shaped like one because clients pin and cache by a 40-hex
commit. A request that names an entry's hash as its revision gets that hash
back as the commit, so every request the client makes next stays on that
entry: `snapshot_download("org/name", revision=<hash>)` downloads exactly
the attested subject, or fails.

Several entries of one repo at one commit, such as single GGUF files pulled
one at a time from one repo, are listed together. Two that hold different
bytes under one path are refused with 409; address each by its hash.

## Requests

| Request | Answer |
|---|---|
| `GET /api/models/{org}/{name}` and `.../revision/{rev}` | model info: `id`, `sha`, `siblings` (with size and LFS SHA-256), and `socair.entries` |
| `GET /api/models/{org}/{name}/tree/{rev}[/{path}]` | the listing; `?recursive=true` lists every level, in one page |
| `HEAD /{org}/{name}/resolve/{rev}/{path}` | `X-Repo-Commit`, `ETag` and `X-Linked-Etag` (the file's SHA-256), `X-Linked-Size`, `Content-Length` |
| `GET /{org}/{name}/resolve/{rev}/{path}` | the bytes, `200`, never a redirect; a `Range` request gets `206` |
| `GET /api/socair/attestations/{hash}` | the entry's `attestation.dsse.json`, byte for byte |
| `GET /api/health` | `200` while the store's clean area and trust policy can be read |

A missing file of a served model is `404` with `X-Error-Code: EntryNotFound`
and `X-Repo-Commit`, which clients read as an optional file being absent
(transformers probes for several); a missing repo is `RepoNotFound`, a
missing revision `RevisionNotFound`. Every other path is `404`, and every
method but `GET` and `HEAD` is `405`.

The listing presents every file as a Git LFS file: `lfs.oid` is its SHA-256,
and `oid` is the git blob id of its LFS pointer, which is what the Hub lists
for an LFS file. A client that checks downloads against the listing
(`hf cache verify`, `HfApi.verify_repo_checksums`) therefore checks each
file's SHA-256 against the attestation's. A directory's `oid` is not a git
tree id; it is a SHA-1 over the paths and SHA-256 hashes beneath it. No
response carries Xet headers or `xetHash`, so clients download over plain
HTTP from this endpoint.

Not served: listing or searching models, commits, refs, discussions,
`paths-info`, datasets and spaces, uploads, and the OCI distribution API (a
separate piece of work, with OCI referrers).

## Integrity

`promote` placed the bytes in `clean/` only after they hashed to the
attestation while being copied. The endpoint checks them again as it sends
them:

- **A whole download is hashed as it is sent, and its last byte is sent only
  if the file hashes to the attested SHA-256.** A file that does not match
  never reaches a client complete: the connection closes one byte short of
  `Content-Length`, and the file is refused from then on while it stays the
  same file with the same size and modification time. A `HEAD` checks that
  the file opens and has the attested size, without reading it.
- **A range is served only from a file a whole pass has checked** in this
  process, unchanged since in identity, size, and modification time. The
  first range request for a file the endpoint has not sent whole waits while
  it is hashed whole.

What this leaves:

- A range read, or the tail of a resumed download, comes from a file checked
  earlier. A rewrite in place that keeps the file's identity, size, and
  modification time is not caught for ranges until the next whole download.
- Every byte but the last is sent before the hash is known. A client that
  does not check the length can keep a truncated, wrong file. huggingface_hub
  checks it and discards the download.
- The model info and the listing come from the attestation, not the disk.
- The endpoint cannot change `clean/`, but whoever can write the volume can.
  A changed file is refused at its next download; it is not detected before
  one.

## The attestation beside each model

The model info carries `socair.entries`: each entry's `subject` (its hash),
`promotion_state`, `acceptance_expires` for a conditional one, `issuer`, and
the path of its attestation. File responses carry `X-Socair-Subject` and
`X-Socair-Promotion-State`. A consumer verifies offline what it downloaded:

```
curl -fsS "$HF_ENDPOINT/api/socair/attestations/<hash>" > attestation.dsse.json
socair verify attestation.dsse.json --trusted operator.pub \
  --artifact ~/.cache/huggingface/hub/models--org--name/snapshots/<commit>
```

`--artifact` takes the snapshot directory as `snapshot_download` leaves it;
its symlinks into `blobs/` are followed, so it hashes to the subject.

## Access

The endpoint has no authentication.

- It binds loopback by default. A non-loopback address needs
  `--allow-public`; something else (on Kubernetes, the NetworkPolicy) then
  decides who reaches it.
- On loopback it answers only a loopback `Host`, so a web page cannot read it
  through DNS rebinding.
- It never writes: not the store, not the activity log. Downloads are not
  recorded in `log.jsonl`; one line per request goes to its standard error.
- A client with a Hugging Face token sends it to `HF_ENDPOINT`. The endpoint
  ignores and never logs it, but unset `HF_TOKEN` in pods that use it.
- It cannot stop a client from reaching huggingface.co itself. To make it the
  only source, set `HF_ENDPOINT` and deny the inference pods' egress to the
  internet.

## Clients

Run once, outside the test suite, against a store built with the CLI (a model
directory scanned, accepted, signed, and promoted with conditions):

- **huggingface_hub 2.2.0**: `model_info`, `resolve_revision`,
  `list_repo_files`, `file_exists`, `repo_exists`, `snapshot_download` by repo
  id, by hash, and pinned to the hash, `hf_hub_download`, `hf download
  --local-dir`, `verify_repo_checksums`, and `get_safetensors_metadata` (range
  requests). Every downloaded file hashed to the attestation. An absent repo
  and a staged hash raised `RepositoryNotFoundError`, a missing file
  `RemoteEntryNotFoundError`, and an unknown revision `RevisionNotFoundError`.
- **huggingface_hub 0.32.4**, the version KServe's storage initializer locks,
  whose `snapshot_download` lists files from the model info's `siblings`: the
  same, less the calls it does not have.
- **transformers 5.19.0**: `AutoConfig`, `GenerationConfig`, `cached_file`,
  an optional missing file (`None`), and `list_repo_templates` (an empty
  listing from an `EntryNotFound` tree).

Not run here, read from source:

- **vLLM 0.31.0** resolves the revision, lists the tree (`list_repo_files`,
  and `HfFileSystem.ls`, which reads the model info and a one-level listing),
  probes single files with `hf_hub_download`, downloads weights with
  `snapshot_download` and `allow_patterns`, and reads safetensors headers with
  range requests when `tie_word_embeddings` is set. It pins transformers
  below 5.18.
- **transformers' safetensors conversion bot** runs only for a repo with
  `.bin` weights and no safetensors. It calls the commits and discussions
  APIs, which this endpoint does not serve, and posts to
  `safetensors-convert.hf.space`, which ignores `HF_ENDPOINT`. Set
  `DISABLE_SAFETENSORS_CONVERSION=1` for such a model.
- **KServe 0.21.0** turns `hf://org/name[:revision]` into `snapshot_download`
  and passes no endpoint, so add `HF_ENDPOINT` to the storage initializer's
  environment yourself. `hf://sha256/<hash>:<hash>` pins the attested subject.

## Kubernetes

`hub.enabled=true` in the chart runs the endpoint as a second container in
the Socair pod, with the store's volume mounted read-only, behind a ClusterIP
Service for its port only. The NetworkPolicy admits only `hub.ingressFrom`:
by default, pods labelled `socair.ai/hub-client=true` in namespaces labelled
the same way. See [kubernetes.md](kubernetes.md#serving-models-to-inference-servers).

## Sources

Pinned releases, read for the requests and headers above:

- huggingface_hub v2.2.0:
  [`hf_hub_url`](https://github.com/huggingface/huggingface_hub/blob/v2.2.0/src/huggingface_hub/file_download.py#L287-L295),
  [the HEAD and the headers it reads](https://github.com/huggingface/huggingface_hub/blob/v2.2.0/src/huggingface_hub/file_download.py#L1659-L1689),
  [`X-Repo-Commit` and `ETag` required](https://github.com/huggingface/huggingface_hub/blob/v2.2.0/src/huggingface_hub/file_download.py#L1786-L1803),
  [`.no_exist` on EntryNotFound](https://github.com/huggingface/huggingface_hub/blob/v2.2.0/src/huggingface_hub/file_download.py#L1770-L1785),
  [blobs named by the ETag](https://github.com/huggingface/huggingface_hub/blob/v2.2.0/src/huggingface_hub/file_download.py#L1200),
  [resume with `Range` and the size check](https://github.com/huggingface/huggingface_hub/blob/v2.2.0/src/huggingface_hub/file_download.py#L371-L495),
  [`snapshot_download`](https://github.com/huggingface/huggingface_hub/blob/v2.2.0/src/huggingface_hub/_snapshot_download.py#L262-L298) and
  [its per-file download at the commit](https://github.com/huggingface/huggingface_hub/blob/v2.2.0/src/huggingface_hub/_snapshot_download.py#L516-L547),
  [`model_info`](https://github.com/huggingface/huggingface_hub/blob/v2.2.0/src/huggingface_hub/hf_api.py#L3175-L3191),
  [`ModelInfo`](https://github.com/huggingface/huggingface_hub/blob/v2.2.0/src/huggingface_hub/hf_api.py#L893-L989),
  [`RepoFile`](https://github.com/huggingface/huggingface_hub/blob/v2.2.0/src/huggingface_hub/hf_api.py#L691-L719),
  [`list_repo_tree`](https://github.com/huggingface/huggingface_hub/blob/v2.2.0/src/huggingface_hub/hf_api.py#L3963-L3970) and
  [its example of an LFS file's `oid`](https://github.com/huggingface/huggingface_hub/blob/v2.2.0/src/huggingface_hub/hf_api.py#L3906-L3909),
  [`get_safetensors_metadata` ranges](https://github.com/huggingface/huggingface_hub/blob/v2.2.0/src/huggingface_hub/hf_api.py#L6814-L6826),
  [`X-Error-Code`](https://github.com/huggingface/huggingface_hub/blob/v2.2.0/src/huggingface_hub/utils/_http.py#L871-L953),
  [checksum verification by LFS SHA-256](https://github.com/huggingface/huggingface_hub/blob/v2.2.0/src/huggingface_hub/utils/_verification.py#L113-L123),
  [`HF_ENDPOINT`](https://github.com/huggingface/huggingface_hub/blob/v2.2.0/src/huggingface_hub/constants.py#L67-L70).
- huggingface_hub v0.32.4:
  [`snapshot_download` from `siblings`](https://github.com/huggingface/huggingface_hub/blob/v0.32.4/src/huggingface_hub/_snapshot_download.py#L256-L268).
- Git LFS v3.8.0: [the pointer file](https://github.com/git-lfs/git-lfs/blob/v3.8.0/docs/spec.md).
- vLLM v0.31.0:
  [revision resolution](https://github.com/vllm-project/vllm/blob/v0.31.0/vllm/transformers_utils/repo_utils.py#L52-L93),
  [`list_repo_files`](https://github.com/vllm-project/vllm/blob/v0.31.0/vllm/transformers_utils/repo_utils.py#L136-L171),
  [`download_weights_from_hf`](https://github.com/vllm-project/vllm/blob/v0.31.0/vllm/model_executor/model_loader/weight_utils.py#L423-L528),
  [the transformers pin](https://github.com/vllm-project/vllm/blob/v0.31.0/requirements/common.txt#L10-L11).
- transformers v5.19.0:
  [`cached_file`](https://github.com/huggingface/transformers/blob/v5.19.0/src/transformers/utils/hub.py#L534-L564),
  [`list_repo_templates`](https://github.com/huggingface/transformers/blob/v5.19.0/src/transformers/utils/hub.py#L132-L174),
  [the conversion bot's trigger](https://github.com/huggingface/transformers/blob/v5.19.0/src/transformers/modeling_utils.py#L663-L730),
  [what it calls](https://github.com/huggingface/transformers/blob/v5.19.0/src/transformers/safetensors_conversion.py#L12-L84).
- KServe v0.21.0:
  [`_download_hf`](https://github.com/kserve/kserve/blob/v0.21.0/python/storage/kserve_storage/kserve_storage.py#L791-L852),
  [the huggingface-hub lock](https://github.com/kserve/kserve/blob/v0.21.0/python/storage/uv.lock#L742-L743).
