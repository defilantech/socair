# Provenance and trust inputs bundle spec

The trust rows (inventory, provenance, denylist) are NOT_TESTED on a bare
artifact. That is correct: we did not look, so we say so. This document is what
the airlock operator must supply to move those rows off NOT_TESTED. It is the
operational half of the product; the code reads these inputs and nothing else.

Everything here is offline. There is no network call at scan time.

## 1. Repo mirror, `SOCAIR_REPO_MIRROR`

A directory holding the model repository's file listing as delivered. The
inventory check walks it and flags real binary executables (ELF, PE, Mach-O,
archives). Scripts and config files (`.py`, `.sh`, `.js`) are inventoried, not
failed, because model repos legitimately ship them.

- Moves `File inventory and payloads` from NOT_TESTED to PASS (or FAIL on a
  binary).
- Layout: the mirror is the root; any subdirectory structure is fine.
- Absent: the repo side of the inventory note says the listing was not
  inspected, and the row stays NOT_TESTED.

## 2. Denylist, `SOCAIR_DENYLIST`

A text file of known-bad artifact hashes.

```
# one entry per line: <sha256>  <label>
13d44e37860489806f575deb0b219c6058c9421fe1982a9311a0e367c4e8f444  known-bad-example-2026
```

- Blank lines and lines starting with `#` are ignored.
- Moves `Known-bad hash match` from NOT_TESTED to PASS (no match) or FAIL (match).
- An empty file is NOT_TESTED, not a pass: "nothing was matched against" is not
  cleared.
- Absent: NOT_TESTED with "no denylist configured".

## 3. Provenance manifest, `SOCAIR_PROVENANCE`

A JSON record of where the artifact came from, written by whoever ran the
airlock. `socair airlock pull` writes one of these beside every staged artifact,
recording the repo and the revision, and never a signing status. A pull that
lands nothing writes nothing.

```json
{
  "publisher": "google",
  "signing_status": "signed",
  "repo_url": "https://huggingface.co/google/gemma-3-12b-it",
  "commit_or_tag": "main",
  "commit_sha": "abcdef123456",
  "aibom": "spdx-ref-or-path"
}
```

- `signing_status` is `signed`, `unsigned`, or empty. An unsigned upstream is
  recorded, not failed; the row says the origin rests on the supplied record
  rather than a verified signature.
- Moves `Hash, provenance, lineage` from NOT_TESTED to PASS.
- Absent: NOT_TESTED.

### Signature sidecars

Independently of the manifest, a signature sidecar next to the artifact
(`<artifact>.sigstore.json`, `.sigstore`, `.minisig`, or `.sig`) is recognised
and records provenance on its own, with the signing status taken as signed
(local sidecar).

## 3a. Publisher signatures, `SOCAIR_PUBLISHER_KEYS` and `SOCAIR_PUBLISHER_ROOTS`

When the artifact carries an OpenSSF Model Signing (OMS) signature, the scan
verifies it offline. For a directory the signature is `model.sig` at its root
(the `model_signing` default); for a single file it is `<file>.sig` beside it.
`SOCAIR_OMS_SIGNATURE` names another path.

- `SOCAIR_PUBLISHER_KEYS`: the publisher's EC public keys (P-256, P-384,
  P-521), a PEM file or a directory of them, for key-signed models.
- `SOCAIR_PUBLISHER_ROOTS`: CA certificates, a PEM file or a directory, for
  models signed with a certificate. The chain is checked at the leaf's issue
  time, and the leaf must be issued for signing.

There is no default trust (no system roots, no built-in keys): a signature
from a key you did not configure proves nothing about who made the model.

| Signature | Provenance row | `publisher_signing_status` |
|---|---|---|
| From a trusted key or root; every signed file matches | PASS | verified (OMS, signer) |
| From a trusted signer; the signature, or a file, does not match | FAIL | invalid (OMS): what differs |
| From an untrusted signer, or pre-1.0 | the manifest rules decide; the signature is named | present, not verified |
| Keyless Sigstore, with `socair-sigstore` configured | as above: verified, invalid, or not in the identity policy | as above, naming the signer's subject and issuer |
| Keyless Sigstore, no verifier configured | the manifest rules decide; the signature is named | present, not verified |

Keyless signatures (a Fulcio certificate and a Rekor log entry) are verified
by the optional `socair-sigstore` helper, a separate binary built from
`tools/socair-sigstore`, so the scanner's own build keeps its small dependency
set. Configure it with `SOCAIR_SIGSTORE_VERIFIER`, `SOCAIR_SIGSTORE_TRUSTED_ROOT`
(a Sigstore `trusted_root.json`), and `SOCAIR_SIGSTORE_IDENTITIES` (the signers
you accept, required); see `tools/socair-sigstore/README.md`. The helper
vouches for the signature; the scanner still binds the signed manifest to the
files.

A verified signature proves the files are the ones the key holder signed. It
is a statement of origin and integrity, never of safety: the other rows still
decide whether it is promoted. Files the signer excluded with
`ignore_paths` (`.gitattributes` and the like by default) are named as not
covered.

## 4. The acceptance record: review, accept, re-issue

An acceptance is the person who owns the gaps signing for them. It is what
lets a report with NOT_TESTED rows (and no FAIL or LEAD) cross the airlock as
`authorized_with_conditions`. It is signed by the acceptor, with their own key,
over the exact report they reviewed:

```
socair scan model.gguf > r.json                     # withheld: some rows NOT_TESTED
socair sign --key operator.key --report r.json      # r.dsse.json, the report to review

# the acceptor reviews r.dsse.json, then:
socair accept --attestation r.dsse.json --key ciso.key --by "Jane Doe, CISO" \
  --expires 2027-01-31T00:00:00Z --store <store> [--rationale "change 4411"]
                                                    # r.acceptance.dsse.json

socair sign --key operator.key --attestation r.dsse.json \
  --acceptance r.acceptance.dsse.json --store <store>
                                                    # r.conditional.dsse.json
```

- The acceptance (`https://socair.ai/acceptance/v1`, DSSE, Ed25519) names the
  artifact's hash, the reviewed report's document hash, exactly its NOT_TESTED
  rows, the acceptor, and an expiry no later than the report's `rescan_due`.
- The re-issued attestation is the same report as `authorized_with_conditions`,
  with the acceptance embedded (`promotion_authorization.acceptance`) and the
  reviewed document's hash. The report's acceptor, surfaces, and expiry must
  match the embedded acceptance, or it cannot be signed or verified.
- Acceptor keys are their own trust list, `<store>/acceptor-keys/`
  (`socair airlock trust add --acceptor ciso.pub`), separate from the keys
  that sign attestations, and a key may not be in both. An acceptance signed by
  the key that signed the report is refused: the operator does not accept
  their own gaps.
- `airlock promote` verifies the acceptance against the acceptor keys and
  refuses one that is unsigned, untrusted, self-signed, for another report, or
  expired. `socair verify --acceptors <dir>` shows the same check.
- A verifier that checks only the operator's signature (socair-verify,
  LLMKube's gate with `allowConditions`) admits the re-issued attestation as
  it admits any conditional one.

`SOCAIR_ACCEPTED_BY` and `SOCAIR_ACCEPTANCE_EXPIRES` still name an acceptor at
scan time, and the report says so, labelled **unsigned**. The airlock does not
promote an unsigned acceptance. `SOCAIR_RESCAN_DAYS` sets the report's
`rescan_due` (default 90).

A FAIL or a LEAD is never cleared by an acceptance; it goes to escalated
review.

## 5. A signed reference feed, `SOCAIR_FEED` and `SOCAIR_FEED_KEYS`

A feed supplies known-bad hashes, reviewed chat templates, and canonical
tokenizers as a signed bundle; see [feed.md](feed.md). Its denylist joins
`SOCAIR_DENYLIST`, and its tokenizer tables join `SOCAIR_TOKENIZER_REFERENCE`.

## 6. Canonical tokenizer tables, `SOCAIR_TOKENIZER_REFERENCE`

A table file, a publisher's `tokenizer.json`, or a directory of them (`*.json`).
The tokenizer row compares the model's vocabulary, token by token, with the
table of its family; see [feed.md](feed.md) for how a family is matched and
graded. A path that cannot be read stops the scan.

## What each input buys, in one table

| Input | Row it moves | Without it |
|---|---|---|
| `SOCAIR_REPO_MIRROR` | File inventory and payloads | NOT_TESTED |
| `SOCAIR_DENYLIST` | Known-bad hash match | NOT_TESTED |
| `SOCAIR_PROVENANCE`, or an OMS signature from a trusted publisher | Hash, provenance, lineage | NOT_TESTED |
| `SOCAIR_TOKENIZER_REFERENCE`, or tables in a feed | Tokenizer config: a changed ordinary token becomes a LEAD | PASS on internal consistency only, and the row says no reference was compared |
| A signed acceptance (`socair accept`) | the promotion state | withheld on any gap |

## Falsification

Each input is proven to drive its row: `TestHappyPathDropsOneInput` removes the
provenance input and asserts the row drops to NOT_TESTED and the promotion
state drops to withheld. The same shape holds for the mirror and the denylist:
remove the input and the row returns to NOT_TESTED.

## What this is not

- It does not verify a signature cryptographically. `signing_status` is a
  supplied claim, and the row says so when it is unsigned.
- It does not fetch anything. The manifest, the mirror, and the list are all
  local, which is what makes the whole path air-gap safe.
