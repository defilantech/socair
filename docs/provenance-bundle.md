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
airlock.

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

## 4. The acceptance record, `SOCAIR_ACCEPTED_BY` and `SOCAIR_ACCEPTANCE_EXPIRES`

These do not fill a check row. They are the human who owns the gaps, and they
are what turns a report with NOT_TESTED rows from `withheld` into
`authorized_with_conditions`.

- `SOCAIR_ACCEPTED_BY`: the person or role accepting the untested surfaces.
- `SOCAIR_ACCEPTANCE_EXPIRES`: optional expiry for the acceptance, e.g.
  `2027-01-01T00:00:00Z`.

Without `SOCAIR_ACCEPTED_BY`, an artifact with any NOT_TESTED row is `withheld`
with the reason "gaps not accepted". A FAIL is never cleared by acceptance; it
goes to escalated review.

## What each input buys, in one table

| Input | Row it moves | Without it |
|---|---|---|
| `SOCAIR_REPO_MIRROR` | File inventory and payloads | NOT_TESTED |
| `SOCAIR_DENYLIST` | Known-bad hash match | NOT_TESTED |
| `SOCAIR_PROVENANCE` or a sidecar | Hash, provenance, lineage | NOT_TESTED |
| `SOCAIR_ACCEPTED_BY` | the promotion state | withheld on any gap |

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
