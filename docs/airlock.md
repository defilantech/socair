# The airlock

The airlock is the controlled junction between untrusted egress and the on-prem
clean store. An artifact is pulled or ingested into staging; only a promotion
moves bytes across into the clean store, and only an attestation signed by a
key the store trusts, whose subject is the artifact's own hash, is a ticket to
cross.

Everything here is offline except an explicit `pull`, which is the one command
allowed to reach the network.

## Store layout

```
<store>/
  incoming/<sha256>/<file>            staging: pulled or binned, not trusted
  incoming/<digest>/<name>/           staging for a model directory (a whole repo)
  incoming/<sha256>/provenance.json   origin facts written by a pull
  incoming/<sha256>/report.json       an unsigned scan result (the console's scan writes it)
  incoming/<sha256>/report.dsse.json  a signed attestation (socair sign)
  incoming/<sha256>/report.acceptance.dsse.json   a signed acceptance (socair accept)
  incoming/<sha256>/report.conditional.dsse.json  the attestation re-issued with it (socair sign --acceptance)
  clean/<sha256>/<file>               the clean store, keyed by artifact hash
  clean/<digest>/<name>/              a promoted model directory, keyed by manifest digest
  clean/<sha256>/attestation.dsse.json  the signed attestation that let it cross
  clean/<sha256>/attestation.json     its report document, for reading
  trusted-keys/<key id>.pub           the trust policy: keys whose signatures admit
  acceptor-keys/<key id>.pub          keys whose signed acceptances of untested rows are honoured
  log.jsonl                           append-only activity log
  .tmp/                               in-progress copies, renamed into place when verified
```

A model directory's `<digest>` is its manifest digest (`socair.modeldir/v1`,
see `docs/dev.md`): the attestation subject a directory scan computes.

The clean store is content-addressed: the hash is the ticket, so promotion is
idempotent and the store holds one identity per artifact. "In the clean store"
does not mean "clean": a conditional promotion crosses too, so a listing must
carry the attestation state, never assume a clean entry.

`<store>` resolves from `--store`, then `SOCAIR_STORE`, then `~/.socair/store`.

## Commands

```
socair airlock init [<store>]
socair airlock pull   --repo <org/name> --file <name> --sha256 <hash> [--revision main]
socair airlock pull   --repo <org/name> (--revision <commit> | --sha256 <manifest digest>)
                      [--include <glob>]... [--exclude <glob>]...
socair airlock ingest --local <file or directory> [--scan]
socair airlock ingest --cache --repo <org/name> [--file <name>] [--revision main] [--scan]
socair airlock trust add <key.pub>
socair airlock promote <artifact or directory> --attestation <attestation.dsse.json>
socair airlock log
```

- `pull` fetches one artifact through controlled egress into staging, verifies
  it against the requested hash, records the pull, and writes a provenance
  manifest beside it. The manifest names the artifact's sha256 and the
  immutable commit the hub resolved the revision to (its `X-Repo-Commit`
  header), so `revision: main` is never the only record of where the bytes
  came from. Scan with that manifest to fill the provenance row and the
  identity section:

  ```
  SOCAIR_PROVENANCE=<store>/incoming/<sha256>/provenance.json socair scan <store>/incoming/<sha256>/<file>
  ```

  The scan reads only the manifest named this way, never one it finds beside
  the artifact, and counts it only if it names the scanned hash. A source that
  names no commit leaves `commit_sha` empty and the row NOT_TESTED.
- `pull` without `--file` fetches a whole repo as a model directory. It must be
  pinned: `--revision` a full 40-hex commit, or `--sha256` the expected
  manifest digest, because a branch alone could deliver different bytes
  tomorrow. The revision is resolved to its commit, the file list is read from
  the hub at that commit, and every file is fetched at that commit and checked
  against the hub's own hash for it (the SHA-256 of a large file, the git blob
  id of a small one). A file that does not verify, a path that would leave the
  directory, two names differing only in case, or a file listed without a
  hash refuses the whole pull, and nothing is staged. Every request, including
  each page of the file list, goes through the egress policy. The tree lands
  at `incoming/<digest>/<name>/` with a provenance manifest bound to the
  digest; the command prints the scan invocation.
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
  was left out. A selection that keeps nothing, or a pattern with an unclosed
  `[`, is refused before any download.
- Every copy of a model checks for room first: a pull from the listing's sizes
  (or a single file's declared length), a scan's snapshot in `SOCAIR_SCAN_TMP`,
  and a promotion into the store. One that cannot fit is refused at the start,
  naming the volume, what it needs, and what is free.
- `ingest` resolves a local path (a file or a model directory) or an offline
  Hugging Face cache entry and records it. Without `--file`, `--cache`
  resolves the whole snapshot; a branch name resolves through the cache's
  `refs/`, as the hub cache stores it. With `--scan` it also runs the engine and prints the report, so an
  ingested artifact fills Sections 2 and 3 like any other.
- `promote` gates an artifact into the clean store on its attestation. For a
  directory attestation it copies every file, hashing while copying under the
  scan's rules, and renames the tree into `clean/<digest>/<name>/` only when the
  recomputed manifest digest is the attested subject. Otherwise it refuses and
  names each file added, removed, or changed. A repeat promotion replaces the
  stored tree, so an altered one is restored.
- `log` prints the activity log; `log --verify` checks its hash chain.

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
- `withheld` and `escalated` refuse. A FAIL is never cleared here; the only path
  is escalated review.
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
  and port only. It is stripped on a redirect to any other host (net/http
  alone would keep it for the same host name at another port and for any
  subdomain), and it never appears in an error or the log. A gated repo
  answers an anonymous request with 401 and masks its file hashes in the
  listing; both refusals name `HF_TOKEN`.
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
`approved`, `acceptance-expired`, `does-not-verify`) is derived from these
files by `Store.Assess`, the verification `promote` itself uses. A staging
entry's stage comes from the newest evidence file by modification time. A
clean entry whose attestation no longer verifies is `does-not-verify`. A staged
envelope that does not verify offers a rescan: the newer `report.json`
supersedes it.

`promote` leaves the staged copy in `incoming/`; nothing on the gate path
deletes. The list omits a staging entry whose id is approved in clean, and keeps
it when the clean entry's acceptance expired or it does not verify, so it can be
re-scanned and re-accepted.

Because a single-file pull is staged flat beside these files, `pull` refuses
an artifact file named like one of them (`provenance.json`, the four `report*`
names, `attestation.json`, `attestation.dsse.json`). A whole repo is staged
under its own name, so only the repo name is checked.

The console reads attestations and does not re-hash model bytes when it shows
them. Re-running `socair airlock promote` re-verifies the bytes.

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
entry that does not verify or whose acceptance expired. Without `--key` the
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
reads it to decide a promotion.

```json
{"ts":"2026-09-29T20:29:26Z","action":"promote","outcome":"conditional","source":"airlock","repo":"","sha256":"e150...","detail":"authorized with conditions accepted by chris on 1 surface(s)"}
```

Actions are `pull`, `ingest`, `trust`, `promote`, `refuse`. Outcomes are `ok`,
`conditional`, `refused`.

### Hash chain

Each entry's `prev` is the sha256 of the previous line's exact bytes; the
first entry's is 64 zeros. Appends take an exclusive file lock, so concurrent
writers never fork the chain.

```
socair airlock log --verify
socair airlock log --verify --expect-head <head>
```

`--verify` walks the chain and exits non-zero at the first line that does not
follow: an edited, deleted, inserted, or reordered entry, or a line that is not
an entry. On success it prints the head, the hash of the last line.

A chain cannot see lines cut off its end: what remains is still a valid chain.
Record the head somewhere the airlock box cannot rewrite (a ticket, a change
record, a second machine), and pass it as `--expect-head` later; verification
then fails if that head is no longer in the log. Signed periodic checkpoints
would make this automatic and are not built yet.

Entries written before chaining have no `prev`. They are counted and reported
as not covered; the chain starts from the last of them.

## Offline and air-gapped customers

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
  report. It is not a Defilan signature; that is the paid tier (#22).
- The clean store is a directory of bytes and attestations, not an admission
  gate for a serving stack. On Kubernetes, LLMKube's gate refuses to serve a
  model without an admitted attestation. For the end-to-end deployment, see
  [intake-host.md](intake-host.md).
