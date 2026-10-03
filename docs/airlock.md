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
  incoming/<sha256>/provenance.json   origin facts written by a pull
  clean/<sha256>/<file>               the clean store, keyed by artifact hash
  clean/<sha256>/attestation.dsse.json  the signed attestation that let it cross
  clean/<sha256>/attestation.json     its report document, for reading
  trusted-keys/<key id>.pub           the trust policy: keys whose signatures admit
  log.jsonl                           append-only activity log
```

The clean store is content-addressed: the hash is the ticket, so promotion is
idempotent and the store holds one identity per artifact. "In the clean store"
does not mean "clean": a conditional promotion crosses too, so a listing must
carry the attestation state, never assume a clean entry.

`<store>` resolves from `--store`, then `SOCAIR_STORE`, then `~/.socair/store`.

## Commands

```
socair airlock init [<store>]
socair airlock pull   --repo <org/name> --file <name> --sha256 <hash> [--revision main]
socair airlock ingest --local <path> [--scan]
socair airlock ingest --cache --repo <org/name> --file <name> [--revision main] [--scan]
socair airlock trust add <key.pub>
socair airlock promote <artifact> --attestation <attestation.dsse.json>
socair airlock log
```

- `pull` fetches one artifact through controlled egress into staging, verifies
  it against the requested hash, records the pull, and writes a provenance
  manifest beside it.
- `ingest` resolves a local path or an offline Hugging Face cache entry and
  records it. With `--scan` it also runs the engine and prints the report, so an
  ingested artifact fills Sections 2 and 3 like any other.
- `promote` gates an artifact into the clean store on its attestation.
- `log` prints the append-only activity log.

## The promotion gate

An artifact crosses only when its attestation validates and authorizes it:

- `authorized` and `authorized_with_conditions` cross. A conditional crossing
  keeps its accepted surfaces in the stored attestation, so the amber state
  travels with the bytes.
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
- The provenance manifest records origin facts (repo, revision). It never
  asserts a signing status; an unsigned upstream stays unsigned.

Environment:

- `SOCAIR_STORE`: default store root.
- `SOCAIR_EGRESS`: `deny` for a hard stop, anything else follows the allowlist.
- `SOCAIR_HF_ENDPOINT`: base URL, for a mirror or a test server. Its host is
  added to the allowlist.
- `SOCAIR_EGRESS_ALLOW`: comma-separated extra hosts, such as a mirror's
  redirect targets. A leading dot matches subdomains.
- `SOCAIR_PULL_TIMEOUT`: stall budget, a Go duration such as `30s`.
- `SOCAIR_HF_CACHE` or `HF_HOME`: the offline cache root for `ingest --cache`.

## Signing and the trust policy

An attestation is an in-toto Statement v1 in a DSSE envelope, signed with
Ed25519: subject the artifact's SHA-256, predicate type
`https://socair.ai/attestation/v1`, predicate the report document. It verifies
offline; there is no transparency log or certificate authority to reach.

```
socair key gen --out operator                        # operator.key (0600), operator.pub
socair scan model.gguf > report.json
socair sign --key operator.key --report report.json  # report.dsse.json
socair verify report.dsse.json --trusted operator.pub --artifact model.gguf
socair airlock trust add operator.pub
socair airlock promote model.gguf --attestation report.dsse.json
```

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
- The clean store is a directory of bytes and attestations. It is not yet an
  admission gate for a serving stack; that is the v2 webhook.
