# The airlock

The airlock is the controlled junction between untrusted egress and the on-prem
clean store. An artifact is pulled into staging, or ingested: a local path or
an offline cache entry is resolved and logged where it lies, without a copy.
Only a promotion moves bytes across into the clean store, and only an
attestation signed by a key the store trusts, whose subject is the artifact's
own hash, is a ticket to cross.

Everything here is offline except an explicit `pull` (the CLI command, or the
API's pull route), the one airlock operation that reaches out to the network.
Outside the airlock, `socair attach` and `socair verify <oci-ref>` call the
registry they name ([oci.md](oci.md)), and the opt-in Tier 2 helper calls the
inference endpoint you configure ([tier2.md](tier2.md)). `SOCAIR_EGRESS=deny`
refuses `pull` and every registry request; Tier 2 runs only when you set
`SOCAIR_TIER2_HELPER`. `socair airlock serve-hub` listens for downloads and
fetches nothing.

A model that travels as an OCI artifact (ModelPack, KitOps, Docker Model
Runner) carries its attestation in the registry instead: `socair attach`
binds the attestation to the artifact's manifest digest and pushes it as a
referrer, and `socair verify <oci-ref>` checks it there. See
[oci.md](oci.md). Both reach the network, and `SOCAIR_EGRESS=deny` refuses
them as it refuses a pull.

## Store layout

```
<store>/
  incoming/<sha256>/<file>            staging: pulled, not trusted
  incoming/<digest>/<name>/           staging for a model directory (a whole repo)
  incoming/<sha256>/provenance.json   origin facts written by a pull
  incoming/<sha256>/report.json       an unsigned scan result (the console's scan writes it)
  incoming/<sha256>/report.dsse.json  a signed attestation (socair sign)
  incoming/<sha256>/report.acceptance.dsse.json   a signed acceptance (socair accept)
  incoming/<sha256>/report.conditional.dsse.json  the attestation re-issued with it (socair sign --acceptance)
  incoming/<sha256>/derivation.dsse.json  a converted output's signed derivation record (socair airlock convert)
  clean/<sha256>/<file>               the clean store, keyed by artifact hash
  clean/<digest>/<name>/              a promoted model directory, keyed by manifest digest
  clean/<sha256>/attestation.dsse.json  the signed attestation that let it cross
  clean/<sha256>/attestation.json     its report document, for reading
  clean/<sha256>/recheck.json         the last recheck's result (socair airlock recheck)
  trusted-keys/<key id>.pub           the trust policy: keys whose signatures admit
  acceptor-keys/<key id>.pub          keys whose signed acceptances of untested rows are honoured
  feed-record.json                    the newest signed feed the store has used (feed.md, "Rollback protection")
  log.jsonl                           append-only activity log
  .tmp/                               in-progress copies, renamed into place when verified
```

A model directory's `<digest>` is its manifest digest (`socair.modeldir/v1`,
see `docs/dev.md`): the attestation subject a directory scan computes.

The clean store is content-addressed: the hash is the ticket, so promotion is
idempotent and the store holds one identity per artifact. "In the clean store"
does not mean "clean": a conditional promotion crosses too, so a listing must
carry the attestation state, never assume a clean entry.

`<store>` resolves from `--store`, then `SOCAIR_STORE`, then `~/.socair/store`
for the `airlock` commands and `socair serve`. `socair verify`, `socair
accept`, and `socair sign --acceptance` read a store only from `--store`; they
ignore `SOCAIR_STORE`.

## Commands

```
socair airlock init [<store>]
socair airlock pull   --repo <org/name> --file <name> --sha256 <hash> [--revision main]
socair airlock pull   --repo <org/name> (--revision <commit> | --sha256 <manifest digest>)
                      [--include <glob>]... [--exclude <glob>]...
socair airlock ingest --local <file or directory> [--scan]
socair airlock ingest --cache --repo <org/name> [--file <name>] [--revision main] [--scan]
socair airlock trust add <key.pub> [--name <issuer>]
socair airlock trust add --acceptor <key.pub>
socair airlock promote <artifact or directory> --attestation <attestation.dsse.json>
socair airlock convert <checkpoint> --attestation <attestation.dsse.json> --key <operator.key>
socair airlock recheck [--rescan]
socair airlock feed accept <feed dir> --keys <key.pub|dir> --reason <why>
socair airlock log [--verify [--expect-head <head>]]
socair airlock export --out <dir> [--key <operator.key>]
socair airlock serve-hub [--addr 127.0.0.1:8081] [--allow-public] [--authorized-only]
```

Every command also takes `--store <path>`.

- `pull` fetches one artifact through controlled egress into staging, verifies
  it against the requested hash, records the pull, and writes a provenance
  manifest beside it. `--file` is a plain file name at the repo's root; for a
  file in a subfolder, pull the repo with `--include <path>`. The manifest
  names the artifact's sha256 and the immutable commit the hub resolved the
  revision to (its `X-Repo-Commit` header), so `revision: main` is never the
  only record of where the bytes came from. Scan with that manifest to fill
  the provenance row and the identity section:

  ```
  SOCAIR_PROVENANCE=<store>/incoming/<sha256>/provenance.json socair scan <store>/incoming/<sha256>/<file>
  ```

  The scan reads only the manifest named this way, never one it finds beside
  the artifact, and counts it only if it names the scanned hash. A source that
  names no commit leaves `commit_sha` empty and the row NOT_TESTED. The
  manifest is not signed: the scan counts any manifest it is pointed at that
  names the scanned hash, so it is only as trustworthy as whoever can write
  that file (for a pull, anyone who can write `incoming/`).
- `pull` without `--file` fetches a whole repo as a model directory. It must be
  pinned: `--revision` a full 40-hex commit, or `--sha256` the expected
  manifest digest, because a branch alone could deliver different bytes
  tomorrow. The revision is resolved to its commit, the file list is read from
  the hub at that commit, and every file is fetched at that commit and checked
  against the hub's own hash for it (the SHA-256 of an LFS file; for a small
  file, its git blob id, a SHA-1). A file that does not verify, a path that
  would leave the directory, two names differing only in case, or a file
  listed without a hash refuses the whole pull, and nothing is staged. Every
  request, including each page of the file list, goes through the egress
  policy. The tree lands at `incoming/<digest>/<name>/` with a provenance
  manifest bound to the digest; the command prints the scan invocation.
- The hashes a pull checks against come from the hub: the listing, for a repo
  pull, and for a single file the `--sha256` you copy from the hub's file
  page. They catch a corrupted or substituted transfer, the CDN included. They
  do not catch a compromised hub, which would list the hashes of whatever it
  serves.
- `--include` and `--exclude` narrow a whole-repo pull to the files the
  serving stack loads. Patterns match a file's path in the repo the way
  huggingface_hub's allow and ignore patterns do: `*` matches any run of
  characters, slashes included, `?` one character, `[seq]` and `[!seq]` one
  character in or not in the set, and a pattern ending in `/` everything under
  that directory. With `--include`, a file must match one; a file matching any
  `--exclude` is left out either way. Both repeat and take comma-separated
  lists. Left-out files are never fetched; the digest, and so the attestation
  subject, covers the kept files alone, and the provenance manifest
  (`selection`: the patterns and every file `left_out`) and the log name what
  was left out. The scan's provenance row says so too, so the signed report
  that travels with the bytes reads as a selection, not the whole repo. When
  the repo ships its uploader's checksum list (`SHA256SUMS`), the files it
  lists that the selection left out are noted as not compared, never flagged
  ([provenance-bundle.md](provenance-bundle.md#uploader-checksum-lists)). A
  selection that keeps nothing, a bare or empty `--include`/`--exclude`, or a
  pattern with an unclosed `[` is refused before any download. A comma inside
  `[...]` belongs to the class.
- **Pull only what you serve.** A repository often ships the same weights in
  several formats: safetensors, a PyTorch pickle, ONNX and OpenVINO exports,
  TensorFlow's `tf_model.h5`, Rust's `rust_model.ot`. A report covers every
  file pulled, so a format Socair does not read, or one you will not serve,
  is a gap that withholds the model. For a model served from safetensors
  (transformers, vLLM, TGI, sentence-transformers), this keeps the weights,
  every JSON config, the tokenizer files, chat templates, and the model card
  and license, which the License row reads:

  ```
  socair airlock pull --repo <org/name> --revision <commit> \
    --include '*.safetensors,*.safetensors.index.json,*.json,*.jinja,*.txt,*.model,README.md,LICENSE*'
  ```

  On `sentence-transformers/all-MiniLM-L6-v2` at `c9745ed`, the whole repo
  (30 files) was first withheld on five gaps: an h5 file, a TorchScript
  archive, OpenVINO weights, the known-bad hash, and the chat template.
  Socair now reads OpenVINO IR (#268, [openvino.md](openvino.md)) and Keras
  and HDF5 files (#269, [keras.md](keras.md)): the repository's two
  `openvino/` IRs and its `tf_model.h5` PASS
  ([false-positive-baseline.md](false-positive-baseline.md)), and the whole
  repo is withheld on one, the TorchScript archive `rust_model.ot`. The
  known-bad hash check needs your organization's list and the chat template
  check needs a template, which an embedding model does not ship, so neither
  runs: the report names both under Out of scope. This selection (12 files, 18
  left out) is **authorized**: every row PASSes.
  A repository whose loader imports its own code needs its `.py` files too:
  add `--include '*.py'`, and the Remote code row judges them.
- Every copy of a model checks for room first: a pull from the listing's sizes
  (or a single file's declared length), a scan's snapshot in `SOCAIR_SCAN_TMP`,
  and a promotion into the store. One that cannot fit is refused at the start,
  naming the volume, what it needs, and what is free. A file system that
  reports no free space (some network and FUSE mounts) can be waved through
  with `SOCAIR_ROOM_CHECK=off`.
- `ingest` resolves a local path (a file or a model directory) or an offline
  Hugging Face cache entry, prints the resolved path, and records it in the
  log. It does not copy the bytes into staging: a scan or a promotion reads
  them where they are. Without `--file`, `--cache` resolves the whole
  snapshot; a branch name resolves through the cache's `refs/`, as the hub
  cache stores it. With `--scan` it also runs the engine and prints the
  report, so an ingested artifact fills Sections 2 and 3 like any other.
- `promote` gates an artifact into the clean store on its attestation. For a
  directory attestation it copies every file, hashing while copying under the
  scan's rules, and renames the tree into `clean/<digest>/<name>/` only when the
  recomputed manifest digest is the attested subject. Otherwise it refuses and
  names each file added, removed, or changed. A repeat promotion replaces the
  stored tree, so an altered one is restored.
- `convert` rebuilds a PyTorch checkpoint as safetensors without unpickling
  it, from what the Pickle opcode scan's grammar read. Its attestation must
  verify against the trust policy, carry no FAIL or LEAD, and PASS the Pickle
  row, and the bytes, copied and hashed, must be the attested subject. The
  output lands in `incoming/<sha256>/` beside a derivation record signed with
  `--key` (a key the store trusts) that binds it to the input. The output is
  a new artifact, staged unscanned: scan, sign, and promote it like any
  other; the input's attestation does not admit it. See
  [derivation.md](derivation.md).
- `recheck` re-checks every model in the clean store against the current feed
  and check set, and flags the ones that would now be withheld. It moves,
  deletes, and re-signs nothing. See [Rechecking the clean
  store](#rechecking-the-clean-store).
- `feed accept` makes a verified, current feed the newest one the store has
  used, even one issued before the record, and logs it with the reason. It is
  the deliberate way back after a feed release is withdrawn, and the repair for
  a feed record that does not match the log. Every scan and recheck with the
  store refuses a feed issued before the record ([feed.md](feed.md),
  "Rollback protection").
- `log` prints the activity log; `log --verify` checks its hash chain.
- `serve-hub` serves the models the store admits, read-only, over the subset
  of the Hugging Face Hub API that `huggingface_hub` downloads through, so an
  inference server with `HF_ENDPOINT` set downloads them from the clean store.
  It serves only what `Store.Assess` admits now and no recheck has flagged,
  only the files each attestation lists, and nothing from `incoming/`. See
  [hub-endpoint.md](hub-endpoint.md).

## The promotion gate

An artifact crosses only when its attestation validates and authorizes it:

- `authorized` and `authorized_with_conditions` cross. A conditional crossing
  keeps its accepted surfaces in the stored attestation, so the amber state
  travels with the bytes.
- **A conditional attestation crosses only with the acceptor's signature.** Its
  embedded acceptance must verify against `<store>/acceptor-keys/`, be signed by
  a different key than the attestation, be for this artifact and exactly its
  untested rows, and be current. An acceptance named at scan time
  (`SOCAIR_ACCEPTED_BY`) is unsigned and refused. See `docs/provenance-bundle.md`
  for the review, accept, re-issue flow.
- `withheld`, and any state other than the two above, refuses. A FAIL or a
  LEAD is never cleared here: no acceptance clears it, and Socair has no other
  path that does. It needs a person's review outside Socair, and the artifact
  does not cross. A model whose `config.json` has an `auto_map` entry ends at a
  Remote code LEAD, so it cannot cross.
- **The bytes that cross must hash to the attestation that authorizes them.** An
  artifact that does not match its ticket is refused, so nothing crosses on
  another artifact's attestation.
- A refusal is recorded (`action: refuse`, `outcome: refused`) and returned as an
  error, never downgraded to a warning.

## Controlled egress

- Every host a pull touches must be on the allowlist: the first request and
  every redirect hop. An https-to-http redirect is refused. The default is the
  Hugging Face hub and its CDN subdomains (`huggingface.co`, `hf.co`, and any
  subdomain of either, which covers the `<region>.cdn.hf.co` and Xet hosts LFS
  downloads redirect to). An entry with a leading dot (`.hf.co`) matches
  subdomains only. `SOCAIR_EGRESS=deny` refuses everything regardless of the
  allowlist.
- Every pull has a stall budget: connecting, receiving headers, and each gap
  between body reads must finish within it. It does not cap the whole
  transfer, so a multi-GB model that keeps arriving completes, while a blocked
  or stalled egress returns an actionable error within the budget instead of
  hanging.
- The hash, repo id, revision, and file name are checked for shape before any
  path is built, and resolved paths must stay under the store or cache root.
- A denied pull names the host and says how to allow it.
- `HF_TOKEN`, when set, is sent as a bearer token to the endpoint's own host
  and port only, and only over https (or to a loopback endpoint). It is
  stripped on a redirect to any other host (net/http alone would keep it for
  the same host name at another port and for any subdomain), and it never
  appears in an error or the log. A failed or refused redirect is recorded
  without its query string, since a CDN target is a signed URL. A gated repo
  answers an anonymous request with 401 and masks its file hashes in the
  listing; both refusals name `HF_TOKEN`. Pulls through the HTTP API never
  carry the token, because the API has no auth.
- The provenance manifest records origin facts (artifact hash, repo, revision,
  resolved commit). It never asserts a signing status; an unsigned upstream
  stays unsigned.

Environment:

- `SOCAIR_STORE`: default store root.
- `SOCAIR_EGRESS`: `deny` for a hard stop, anything else follows the allowlist.
- `SOCAIR_HF_ENDPOINT`: base URL, for a mirror or a test server. Its host is
  added to the allowlist.
- `SOCAIR_EGRESS_ALLOW`: comma-separated extra hosts, such as a mirror's
  redirect targets. A leading dot matches subdomains.
- `SOCAIR_PULL_TIMEOUT`: stall budget, a Go duration such as `30s`.
- `HF_TOKEN`: a Hugging Face access token, for gated and private repos.
- `SOCAIR_ROOM_CHECK`: `off` skips the free-space check before large copies.
- `SOCAIR_SCAN_TMP`: where a scan writes its snapshot, a full copy of the
  model; put it on a volume with room (the default is the system temp dir).
- `SOCAIR_HF_CACHE` or `HF_HOME`: the offline cache root for `ingest --cache`.

## Staging evidence and stages

The four `report*` files are the names `socair scan`, `sign`, `accept`, and
`sign --acceptance` already write, so running the CLI against
`incoming/<id>/report.json` produces exactly what the console reads. Only the
console's scan writes `report.json`; `ingest --scan` prints its report and does
not. None of them changes what `promote` accepts.

A model's stage (`staged`, `scanned`, `ready`, `needs-acceptance`, `blocked`,
`approved`, `acceptance-expired`, `does-not-verify`, `flagged`) is derived from
these files by `Store.Assess`, the verification `promote` itself uses. A staging
entry's stage comes from the newest evidence file by modification time. A
clean entry whose attestation no longer verifies is `does-not-verify`. A clean
entry whose `recheck.json` flags it is `flagged` (see [Rechecking the clean
store](#rechecking-the-clean-store)). A staged envelope that does not verify
offers a rescan: the newer `report.json` supersedes it. An entry whose
report or attestation has a FAIL or a LEAD is `blocked`, signed or not, and
offers no next step: no signature or acceptance moves it toward promotion, and
it needs a person's review outside Socair. Signing its report still files what
the scan found.

`promote` leaves the staged copy in `incoming/`; nothing on the gate path
deletes. The list omits a staging entry whose id is approved in clean, or was
approved and then flagged by a recheck, and keeps it when the clean entry's
acceptance expired or it does not verify, so it can be re-scanned and
re-accepted.

Because a single-file pull is staged flat beside these files, `pull` refuses
an artifact file named like one of them (`provenance.json`, the four `report*`
names, `attestation.json`, `attestation.dsse.json`, `recheck.json`,
`derivation.dsse.json`). A whole repo is staged under its own name, so only
the repo name is checked.

The console reads attestations and does not re-hash model bytes when it shows
them. Re-running `socair airlock promote` re-verifies the bytes.

## Rechecking the clean store

```
socair airlock recheck [--rescan] [--store <path>]
```

A promoted model's attestation reflects the reference data and the check set
of its scan. A hash added to a known-bad list next month, or a check that
grades differently in a newer socair, does not touch it. `recheck` re-examines
every model in `clean/` against what a scan would use now, and flags the ones
that would now be withheld.

It reads the inputs a scan reads: `SOCAIR_FEED` with `SOCAIR_FEED_KEYS`,
`SOCAIR_DENYLIST`, and for a rescan the rest of the scan's environment (see
[feed.md](feed.md)). A configured feed that does not verify, or has expired,
stops the recheck before anything is written, as it stops a scan. So does a
feed issued before the newest one the store has used, and that refusal is
logged ([feed.md](feed.md), "Rollback protection"). A feed in the last third
of its validity is used, with a warning on stderr that names when it expires.

Two levels run for each model:

1. **Known-bad match, always.** The entry's hash, and for a model directory
   every file hash its verified attestation lists, are matched against the
   signed feed's denylist and the local `SOCAIR_DENYLIST`. No model bytes are
   read. A match flags the model.
2. **Rescan, when due.** When the attestation's `scope.check_set_version` is
   not this socair's check set, or for every model with `--rescan`, the engine
   scans the clean bytes again and compares its rows with the attestation's.
   The scan takes a snapshot and checks for room first, like any scan
   (`SOCAIR_SCAN_TMP`). The model is flagged when the rescan would withhold
   it: a FAIL or LEAD row, a NOT_TESTED row that the attestation's signed
   acceptance does not cover, or clean bytes that no longer hash to the
   attested subject. The flag names each row that changed, with its status
   before and after.

A rescan reads its inputs from the environment, like any scan, plus the
staged copy's `provenance.json` when there is one (the engine counts it only
if it names these bytes). Give a rescan the inputs the original scan had: the
repository mirror, the provenance manifest, publisher keys, and the denylist.
A row the attestation PASSed that the rescan cannot test is a new gap, and it
flags the model, because a scan run now would be withheld on it.

**What it writes.** Nothing is moved, deleted, or re-signed; signing stays
offline. Each clean entry gets `clean/<id>/recheck.json`, written to a temp
file and renamed into place, and the log gets one `recheck` entry per model.
The entry names the feed (issuer, version, issue and expiry times, signing
key), the known-bad lists, the check set and the attested one, and the
outcome:

- `flagged`: the model would now be withheld, or an earlier flag stands.
- `unchanged`: every level that was due ran and found nothing that would
  withhold it.
- `incomplete`: nothing was flagged, but a level could not run: a configured
  local list could not be read, a due rescan failed, or the attestation does
  not verify. It is not a pass. With no known-bad list configured at all, the
  known-bad level does not run and is not a gap, as at scan time: the reason
  says so.

The command prints one line per model, and exits non-zero when any model is
flagged or incomplete, so a scheduled run surfaces it.

```json
{"format":"socair.recheck/v1","id":"<64-hex>","name":"model.safetensors",
 "checked_utc":"2026-10-12T19:49:22Z","tool_version":"socair dev",
 "check_set_version":"tier1/0.8","attested_check_set_version":"tier1/0.8",
 "attestation_sha256":"<sha256 of attestation.dsse.json>","attestation":"verifies",
 "feed":{"issuer":"Example Intel","version":"2026.10.2","issued":"...","expires":"...","key_id":"..."},
 "known_bad":{"checked":true,"lists":["feed Example Intel 2026.10.2","denylist /etc/socair/deny.txt"],"hashes":1,
   "matches":[{"sha256":"<64-hex>","lists":["trojaned community upload (feed Example Intel 2026.10.2)"]}]},
 "rescan":{"due":false,"why":"not due: the attestation was scanned under this check set, tier1/0.8","ran":false,"would_withhold":false},
 "flags":[{"kind":"known-bad","reason":"its hash (...) is on a known-bad list: ...","since":"2026-10-12T19:49:22Z"}],
 "outcome":"flagged","reason":"its hash (...) is on a known-bad list: ..."}
```

A rescan also records the rescan's check set, reference data, and promotion
state, the rows that changed (`changed`, each `was` and `now`, `absent` for a
row one side lacks), and the rows that would withhold it (`withholding`).
`cleared` lists the earlier flags this recheck re-examined and found no longer
hold.

**In listings.** A flagged model's stage is `flagged`, derived from
`recheck.json` like every stage, so the API, the console, and an inventory
export show it. It is still in `clean/`, and every listing says so: the
console lists flagged models first, in red; an export lists them under
`other`, never as approved; the staged copy of a model that was approved and
is now flagged is not offered for promotion again. A flag outranks `approved`, `acceptance-expired`, and
`does-not-verify`, and keeps their reason beside its own. A `recheck.json`
that does not parse, is for another entry, or contradicts itself shows as
flagged too: a flag that cannot be read is not a cleared one. The next recheck
replaces it and says so.

**How a flag clears.** Only a later recheck that re-examines what the flag
rests on, and finds it no longer holds, clears it. A known-bad flag needs every
hash matched against every configured list, for example with a newer feed that
dropped the entry. A rescan flag needs a rescan that ran. A recheck that
covers less carries the flag forward and says why, so a run with no list
configured never clears one. The clearing recheck names the flag it cleared,
in `recheck.json` and in the log. Socair has no other way to clear a flag.

**And the gate.** `Store.Assess` and `promote` verify an attestation; they do
not read `recheck.json`. Promoting a flagged model's bytes again is admitted
on a valid ticket (it restores a copy that was deleted or altered) and leaves
the flag in place, even with a new attestation; the promotion's log entry says
the entry stays flagged. What to do with a flagged model, such as removing it
from `clean/` or re-scanning and re-signing it, is the operator's decision,
made outside Socair.

**Limits.**

- `recheck.json` is evidence, not a signature: whoever can write `clean/` can
  delete it, which clears the flag from listings. The log entry stays, under
  the hash chain (see [Activity log](#activity-log)).
- The known-bad match trusts the file hashes the attestation lists, which
  `promote` verified when the bytes crossed. `--rescan` hashes the bytes again.
- A recheck runs only when someone runs it. The Helm chart does not schedule
  it; running it on a schedule there is a later step.

## Export and inventory

```
socair airlock export --out <dir> [--key <operator.key>] [--store <path>]
socair inventory verify <dir> --trusted <key.pub|dir> [--allow-unsigned]
```

`export` writes a dated snapshot of the store for people who do not run the
airlock. It never contains model bytes or keys, refuses a non-empty `--out`,
and refuses a store whose log chain is broken.

```
<dir>/
  index.html                 approved list and the other entries; snapshot time and log head
  models/<id>/report.html    the HTML report
  models/<id>/attestation.dsse.json, attestation.json   byte-identical to clean/<id>/
  log.jsonl, log-head.txt    the activity log and its chain head
  inventory.json             the inventory statement
  inventory.dsse.json        its DSSE envelope, only with --key
```

The statement is an in-toto Statement v1, predicate type
`https://socair.ai/inventory/v1`, one subject per approved model. Its
predicate holds `generated_utc`, `log_head`, `tool_version`, `models` (id,
name, promotion state, issuer, signer key id, `attestation_sha256`, and for a
conditional entry the accepted surfaces and expiry), and `other`: the
non-approved entries, each with its stage and reason. That includes a clean
entry that does not verify, whose acceptance expired, or that a recheck
flagged. Without `--key` the
snapshot is unsigned and `index.html` says so.

`inventory verify` fails, with the reason, unless all of these hold:

1. The envelope verifies against `--trusted`, and the predicate type is
   `inventory/v1`. An unsigned snapshot fails unless `--allow-unsigned`, which
   checks the contents only.
2. The statement's subjects equal its models, and every listed attestation
   file is present and hashes to `attestation_sha256`.
3. Every attestation verifies against `--trusted` for its listed id, and its
   `promotion_state`, `signer_key_id`, and (for a conditional entry)
   accepted surfaces and expiry match the entry. A readable
   `attestation.json` beside it, when present, must decode as a report equal
   to the envelope's document.
4. `log.jsonl` verifies as a hash chain to `log_head`, which must be set when
   models are listed.

It prints the signer key, or UNSIGNED. Verification proves the snapshot is
the one that was exported, not that the store is unchanged since: record the
log head somewhere the box cannot rewrite, as for `log --verify`.

The console's export button (`POST /api/airlock/export`) returns the same
snapshot unsigned. To sign it, run the command above with `--key`.

## Signing and the trust policy

An attestation is an in-toto Statement v1 in a DSSE envelope, signed with
Ed25519: subject the artifact's SHA-256, predicate type
`https://socair.ai/attestation/v1`, predicate the report document. It verifies
offline; there is no transparency log or certificate authority to reach.

```
socair key gen --out operator --issuer "Acme ML Platform"   # operator.key (0600), operator.pub
socair scan model.gguf > report.json
socair sign --key operator.key --report report.json  # report.dsse.json
socair verify report.dsse.json --trusted operator.pub --artifact model.gguf
socair airlock trust add operator.pub [--name "Acme ML Platform"]
socair airlock promote model.gguf --attestation report.dsse.json
```

The last step succeeds only for an `authorized` report. A scan with no other
inputs is usually `withheld` on NOT_TESTED rows (provenance, and for a single
file the repository inventory; see
[provenance-bundle.md](provenance-bundle.md)), and `promote` refuses it until
those rows PASS with the inputs they need, or are accepted: the acceptor signs
with `socair accept`, the operator re-issues with `socair sign --acceptance`,
and the re-issued attestation is promoted.

**Which socair verifies it.** Verify an attestation with the Socair version
that signed it, or a newer one. A verifier accepts only fields it knows, so a
report signed by a newer socair, which may carry a field added since, is
refused by an older one, with an error that says so. The admission module
`socair-verify` reads only the fields it checks, so this does not apply to
it. Until 0.1.0 the report format can gain fields; after it, a new field
will come with a way for an older verifier to tell a newer format from a
broken one (#250).

**Who issued it.** The issuer is whoever signs. `key gen --issuer` records a
name in the key files, on a `Socair-Issuer:` line outside the PEM block, which
PEM parsers (OpenSSL included) ignore. `sign` writes that name into the
report's `issuer` section, under the signature. The trusted copy of a key in
`trusted-keys/` carries the *store's* name for it. `trust add` keeps the key
file's name, or `--name` sets your own. `promote` and `verify` refuse an
attestation whose claimed issuer contradicts that name, and log or show the
issuer as confirmed. A key the store has not named shows its issuer as
"claimed": anyone can name a key "Defilan Technologies", so when you trust a
key, check the name it carries.

`promote` checks, in order: a signature by a key in `trusted-keys/` over the
DSSE encoding; the statement and predicate types; that the subject digest is
the document's artifact hash; the recorded document hash; that the document
validates, including its promotion state against its checks; that the state
admits promotion; and, while copying, that the bytes hash to the subject.
Any failure is a logged refusal. A bare report is not a ticket.

A repeat promotion re-copies and re-verifies the artifact, so a clean copy that
was deleted or altered is restored. An artifact may not be named
`attestation.json` or `attestation.dsse.json`.

A private key file readable by other users is refused. Keep it off the
airlock box if signing happens elsewhere; the store only needs the public key.

## Activity log

One JSON object per line, append-only. The log is evidence, not state: nothing
reads it to decide a promotion. Its `feed` entries are the one place it is read
back: they witness the store's feed record, and a scan with a feed stops when
the two disagree ([feed.md](feed.md), "Where the record lives").

```json
{"ts":"2026-10-09T17:02:38.40046Z","action":"promote","outcome":"conditional","source":"airlock","sha256":"8aaff9f1...cb933953","detail":"authorized with conditions accepted by Jane Doe, CISO (signed acceptance, acceptor key 1e2c157cdc14e161) on 4 surface(s) until 2027-01-07T17:02:38Z, attestation issued by Acme ML Platform, signed by fcf1dc921efb204f","prev":"1f6c460b...163f5d19"}
```

Actions are `pull`, `ingest`, `trust`, `promote`, `refuse`, `recheck`,
`convert`, and `feed`. Outcomes are `ok`, `conditional`, `refused`, for a
recheck `flagged`, `unchanged`, `incomplete`, and for a feed `accepted` (an
operator's `feed accept`). A `convert` entry carries the output's hash when it
is `ok` and the input's when it is `refused`. A `feed` entry carries the feed
it is about in `feed` (issuer, version, issue and expiry times, key id,
statement hash), and the statement hash in `sha256`. An entry caused through
the HTTP API also carries `"actor":"local-operator"`; the CLI records no
actor.

### Hash chain

Each entry's `prev` is the sha256 of the previous line's exact bytes; the
first entry's is 64 zeros. On Unix (every release platform), appends take an
exclusive `flock`, so concurrent writers never fork the chain; elsewhere the
lock holds only within one process.

```
socair airlock log --verify
socair airlock log --verify --expect-head <head>
```

`--verify` walks the chain and exits non-zero at the first line that does not
follow: an edited, deleted, inserted, or reordered entry, or a line that is not
an entry. On success it prints the head, the hash of the last line.

The chain is unkeyed SHA-256, so it shows careless edits, not a deliberate
rewrite. Whoever can write `log.jsonl` can rewrite any entry and recompute
every link after it, and an edit to the last line leaves nothing to break. A
chain also cannot see lines cut off its end: what remains is still a valid
chain. Only a head recorded off the box catches a rewrite: record it
somewhere the airlock box cannot rewrite (a ticket, a change record, a second
machine), and pass it as `--expect-head` later. Verification then fails unless
that exact line, and so every line before it, is still in the log. Entries
after the recorded head are covered only once you record a later head. Signed
periodic checkpoints would make this automatic and are not built yet.

Entries written before chaining have no `prev`. They are counted and reported
as not covered; the chain starts from the last of them.

## Offline and air-gapped sites

- A local artifact path is ingested directly; there is no network call.
- An offline Hugging Face cache is resolved by repo, revision, and file. The
  layout is `<cache>/models--<org>--<name>/snapshots/<rev>/<file>`.
- A missing path or a cache miss is a clean, named error, never a silently empty
  report.

## Testing

The airlock tests are hermetic: an `httptest` server stands in for the hub, the
store is a temp directory, and artifacts are generated fixtures. The one real
egress test is gated:

```
SOCAIR_TEST_EGRESS=1 go test ./internal/airlock -run RealEgress -v
```

## What this is not

- A pull verifies the artifact hash, not a publisher signature.
- An operator signature says the operator ran the checks and stands behind the
  report. It is not a Defilan signature.
- The clean store is a directory of bytes and attestations, not an admission
  gate for a serving stack. `serve-hub` hands its admitted models to
  inference servers, but it cannot stop one from fetching a model elsewhere.
  On Kubernetes, LLMKube is adding an admission gate that refuses to serve a
  model without an admitted attestation. For the end-to-end deployment, see
  [intake-host.md](intake-host.md).
