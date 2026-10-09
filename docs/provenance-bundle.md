# Provenance and trust inputs bundle spec

The trust rows (inventory, provenance, denylist) are NOT_TESTED on a bare
artifact. That is correct: we did not look, so we say so. This document is what
the airlock operator must supply to move those rows off NOT_TESTED. It is the
operational half of the product; the code reads these inputs and nothing else.

Everything here is offline. There is no network call at scan time.

## 1. Repo mirror, `SOCAIR_REPO_MIRROR`

A directory holding the model repository's file listing as delivered, for a
single-file scan (a model directory scan inventories its own files). The
inventory check walks it and reads the start of every file, whatever its name:
a native executable (ELF, PE, Mach-O) is a FAIL. Scripts and config files
(`.py`, `.sh`, `.js`, `.rb`) are inventoried, not failed, because model repos
legitimately ship them; an executable named `setup.py` is still an executable.
An archive, including a zip-format PyTorch checkpoint, is named as unscanned
and leaves the row NOT_TESTED, because its contents were not inspected.

- Moves `File inventory and payloads` from NOT_TESTED to PASS (or FAIL on a
  native executable).
- Layout: the mirror is the root; any subdirectory structure is fine.
- Absent: the repo side of the inventory note says the listing was not
  inspected, and the row stays NOT_TESTED.
- Missing, empty, or not a directory: NOT_TESTED with the reason. An entry the
  walk cannot read is named and leaves the row NOT_TESTED, unless a binary
  elsewhere already FAILs it.

## 2. Denylist, `SOCAIR_DENYLIST`

A text file of known-bad artifact hashes.

```
# one entry per line: <sha256>  <label>
13d44e37860489806f575deb0b219c6058c9421fe1982a9311a0e367c4e8f444  known-bad-example-2026
```

- Blank lines and lines starting with `#` are ignored.
- Every other line must start with a SHA-256. One that does not refuses the
  whole list, as a feed is refused: the row is NOT_TESTED and names the line,
  even beside a feed's denylist, unless a listed hash matches.
- Moves `Known-bad hash match` from NOT_TESTED to PASS (no match) or FAIL (match).
- A list with no valid SHA-256 entry (empty, comments only, or malformed lines
  only) is NOT_TESTED, not a pass: "nothing was matched against" is not
  cleared.
- Absent: NOT_TESTED with "no denylist configured".

## 3. Provenance manifest, `SOCAIR_PROVENANCE`

A JSON record of where the artifact came from, written by whoever ran the
airlock. `socair airlock pull` writes one of these beside every staged artifact,
recording the hash, the repo, the revision, and the commit it resolved to, and
never a signing status. A pull that lands nothing writes nothing. Pass it to a
scan with `SOCAIR_PROVENANCE=<path>`; the scan reads only the manifest named
there, never one it finds beside the artifact.

```json
{
  "artifact_sha256": "8aaff9f15e2471e3fa038d20618b494680a6e0a2ef0655e09768fc5ecb933953",
  "publisher": "example-org",
  "signing_status": "unsigned",
  "repo_url": "https://huggingface.co/example-org/example-model",
  "commit_or_tag": "main",
  "commit_sha": "4f2c9e1a7b3d5f60812a9c4e6b0d1f3a5c7e9b2d",
  "aibom": "spdx-ref-or-path"
}
```

- `artifact_sha256` binds the record to one artifact: the file's SHA-256, or a
  model directory's manifest digest. A manifest that names no hash, or another
  artifact's, does not count, and the row says why.
- `commit_sha` must be a full commit id (40 or 64 hex). An origin recorded only
  at a branch or tag in `commit_or_tag`, which can move, leaves the row
  NOT_TESTED.
- `signing_status` is `signed`, `unsigned`, or empty. It is the manifest's
  claim, reported as such, and it never moves the row; the row says the origin
  rests on the supplied record rather than a verified signature.
- Moves `Hash, provenance, lineage` from NOT_TESTED to PASS when it binds, names
  a `repo_url`, and has a full `commit_sha`.
- Absent: NOT_TESTED.

### Signature sidecars

A signature sidecar next to the artifact (`<artifact>.sigstore.json`,
`.sigstore`, `.minisig`, or `.sig`) that is not read as an OMS signature
(section 3a) is named in the row as present and not verified. It does not move
the row: without a bound manifest, the row stays NOT_TESTED.

## 3a. Publisher signatures, `SOCAIR_PUBLISHER_KEYS` and `SOCAIR_PUBLISHER_ROOTS`

When the artifact carries an OpenSSF Model Signing (OMS) signature, the scan
verifies it offline. For a directory the signature is `model.sig` at its root
(the `model_signing` default); for a single file it is `<file>.sig` beside it.
`SOCAIR_OMS_SIGNATURE` names another path.

- `SOCAIR_PUBLISHER_KEYS`: the publisher's EC public keys (P-256, P-384,
  P-521), a PEM file or a directory of them, for key-signed models.
- `SOCAIR_PUBLISHER_ROOTS`: CA certificates, a PEM file or a directory, for
  models signed with a certificate. The chain is checked at the leaf's issue
  time, and the leaf must carry the `digitalSignature` key usage or the
  `codeSigning` extended key usage. Revocation is not checked.

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
  --expires <RFC 3339 time> --store <store> [--rationale "change 4411"]
                                                    # r.acceptance.dsse.json

socair sign --key operator.key --attestation r.dsse.json \
  --acceptance r.acceptance.dsse.json --store <store>
                                                    # r.conditional.dsse.json
```

- The acceptance (`https://socair.ai/acceptance/v1`, DSSE, Ed25519) names the
  artifact's hash, the reviewed report's document hash, exactly its NOT_TESTED
  rows, the acceptor, and an expiry. `--expires` may not be later than the
  report's `header.rescan_due`: the scan time plus 90 days, unless
  `SOCAIR_RESCAN_DAYS` set another number.
- `accept` and `sign --acceptance` read a store only from `--store`, not from
  `SOCAIR_STORE`; without one, pass `--trusted` (and `--acceptors`) instead.
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
- A verifier that checks only the operator's signature (socair-verify, as in
  the admission gate LLMKube is adding, with `allowConditions`) admits the
  re-issued attestation as it admits any conditional one.

`SOCAIR_ACCEPTED_BY` and `SOCAIR_ACCEPTANCE_EXPIRES` still name an acceptor at
scan time, and the report says so, labelled **unsigned**. The airlock does not
promote an unsigned acceptance. `SOCAIR_RESCAN_DAYS` sets the report's
`rescan_due` (default 90).

A FAIL or a LEAD is never cleared by an acceptance, and Socair has no other
path that clears one: it withholds promotion and needs a person's review
outside Socair.

## 5. A signed reference feed, `SOCAIR_FEED` and `SOCAIR_FEED_KEYS`

A feed supplies known-bad hashes, reviewed chat templates, and canonical
tokenizers as a signed bundle; see [feed.md](feed.md). Its denylist joins
`SOCAIR_DENYLIST`, its tokenizer tables join `SOCAIR_TOKENIZER_REFERENCE`, and
its reviewed template texts join `SOCAIR_TEMPLATE_REFERENCE`.

## 6. Canonical tokenizer tables, `SOCAIR_TOKENIZER_REFERENCE`

A table file, a publisher's `tokenizer.json`, or a directory of them (`*.json`).
The tokenizer row compares the model's vocabulary, token by token, with the
table of its family; see [feed.md](feed.md) for how a family is matched and
graded. A path that cannot be read stops the scan.

## 7. Reviewed chat templates, `SOCAIR_TEMPLATE_REFERENCE`

A reviewed template's text (`.jinja`), or a directory of them, each labelled by
its file name. The chat-template row renders each beside the artifact's
template on the same probe conversations: a template that renders like a
reviewed one on every standard probe but adds a content-conditional branch is
a LEAD; an identical render is noted; anything else gets no verdict. A local
reference never clears a lead; only a signed feed's `templates.txt` or the
embedded allowlist does. A path that cannot be read stops the scan.

## 8. A license policy, `SOCAIR_LICENSE_POLICY`

Every report names the license the artifact states, in its identity section
(`artifact.license`), whether or not a policy is set. The scan reads it from
the model card's front matter (`license`, `license_name`, `license_link`),
the LICENSE files at a directory's top level, and a GGUF's `general.license`
keys, and lists every statement it read and what each was identified as. A
LICENSE text is identified only when it is a license the catalogue
(`internal/checks/license/catalogue.go`) holds: a permissive license must be
its whole text with nothing added (a title and a copyright line aside), and a
model license must carry its title phrases. Anything else is reported as not
identified, with its first line, never guessed. Statements that name
different licenses are reported as a disagreement. A declared base model
(`base_model`, `general.base_model.N`) is listed too; when its publisher
releases every model under one license (Meta Llama, Google Gemma), a stated
license of another family is a disagreement.

Without a policy, none of this changes a row or the promotion state. With
one, the report adds a **License policy** row:

```
# allowed licenses, one per line: a catalogue id, an SPDX id, or a model-card tag
apache-2.0
MIT
llama3.1
```

| What the artifact states | License policy row |
|---|---|
| One license, on the list | PASS, with the license's usage-policy obligations listed and not marked met |
| One license, not on the list | FAIL (`license-not-allowed`), naming where it is stated |
| Different licenses, one of them not on the list | LEAD (`license-disagreement`): which governs needs a person |
| Different licenses, all on the list | PASS, saying they disagree |
| A license on the list beside a statement the catalogue does not recognize | NOT_TESTED: the license is not established |
| Nothing identified (no statement, only `other`, an unrecognized text, a single safetensors or pickle file) | NOT_TESTED |

- A name the catalogue does not know, or a policy that allows nothing, stops
  the scan: a misspelled id would otherwise fail every model.
- The row is not legal advice. Usage-policy obligations (Llama's acceptable
  use policy and 700-million-user clause, Gemma's prohibited use policy, a
  non-commercial term) are listed in the notes, never marked complied with.
- A disagreement is common on real repos, and a quantizer's card often names
  a different license from the original (see
  [false-positive-baseline.md](false-positive-baseline.md)), so it is a LEAD
  for review, never a FAIL.
- The report's `scope.reference_data` names the policy file and its ids.

Catalogue ids are ScanCode LicenseDB keys where ScanCode has one, and
`socair-` keys otherwise:

| Id | License | Also matched as |
|---|---|---|
| `apache-2.0`, `mit`, `bsd-new`, `bsd-simplified` | Apache 2.0, MIT, BSD 3-Clause, BSD 2-Clause | SPDX ids; `bsd-3-clause`, `bsd-2-clause` |
| `cc-by-4.0`, `cc-by-sa-4.0`, `cc-by-nc-4.0`, `cc-by-nc-sa-4.0` | Creative Commons 4.0 | SPDX ids |
| `openmdw-1.0` | OpenMDW 1.0 | `OpenMDW-1.0` |
| `llama-2-license-2023`, `socair-llama-3-license-2024`, `llama-3.1-license-2024`, `llama-3.2-license-2024`, `llama-3.3-license-2024`, `llama-4-cla-2025` | Llama 2, 3, 3.1, 3.2, 3.3, 4 community licenses | `llama2`, `llama3`, `llama3.1`, `llama3.2`, `llama3.3`, `llama4` |
| `socair-gemma-terms-of-use` | Gemma Terms of Use | `gemma` |
| `qwen-2024`, `tongyi-qianwen-2023`, `socair-qwen-research-2024` | Qwen, Tongyi Qianwen, Qwen Research licenses | `qwen`, `tongyi-qianwen`, `qwen-research` |
| `deepseek-la-1.0` | DeepSeek License Agreement 1.0 | `deepseek` |
| `socair-nvidia-open-model` | NVIDIA Open Model License | `nvidia-open-model-license` |
| `socair-mistral-research-0.1`, `socair-mistral-non-production-0.1` | Mistral AI Research, Non-Production licenses | `mrl`, `mnpl` |
| `falcon-2-11b-1.0`, `socair-tii-falcon-license` | Falcon 2 11B TII License, TII Falcon License | `falcon-llm-license` |
| `bigscience-rail-1.0`, `bigscience-open-rail-m`, `bigcode-open-rail-m-v1`, `socair-creativeml-openrail-m`, `bigscience-open-rail-m2`, `socair-openrail` | RAIL licenses (BLOOM, BigScience, BigCode, CreativeML, CreativeML RAIL++, unnamed Open RAIL) | `bigscience-bloom-rail-1.0`, `bigscience-openrail-m`, `bigcode-openrail-m`, `creativeml-openrail-m`, `openrail++`, `openrail` |
| `moonshot-ai-modified-mit-2025`, `minimax-mit-variant-2025` | Kimi and MiniMax modified MIT licenses (never identified as MIT) | |
| `socair-tencent-hunyuan-community`, `socair-glm-4` | Tencent Hunyuan Community, GLM-4 licenses | `tencent-hunyuan-community`, `glm-4` |

## What each input buys, in one table

| Input | Row it moves | Without it |
|---|---|---|
| `SOCAIR_REPO_MIRROR` | File inventory and payloads, for a single file | NOT_TESTED |
| `SOCAIR_DENYLIST`, or a denylist in a feed | Known-bad hash match | NOT_TESTED |
| `SOCAIR_PROVENANCE`, or an OMS signature from a trusted publisher | Hash, provenance, lineage | NOT_TESTED |
| `SOCAIR_TOKENIZER_REFERENCE`, or tables in a feed | Tokenizer config: a changed ordinary token becomes a LEAD | PASS on internal consistency only, and the row says no reference was compared |
| `SOCAIR_TEMPLATE_REFERENCE`, or template texts in a feed | Chat template: a reviewed template plus an added content-conditional branch becomes a LEAD | the rendered inventory only, and the row says no reviewed template text was compared |
| `SOCAIR_LICENSE_POLICY` | Adds the License policy row: PASS, FAIL, LEAD, or NOT_TESTED against your allowed list | no row; the license is still named in the identity section |
| A signed acceptance (`socair accept`) | the promotion state | withheld on any gap |
| `SOCAIR_TIER2_HELPER` and `SOCAIR_TIER2_ENDPOINT` ([tier2.md](tier2.md)) | Adds Tier 2 measurements; one that raises a LEAD or FAIL adds a row that withholds, and one that finds nothing adds no row | No Tier 2 section; its checks are listed as not run, which is not a gap |

## Falsification

Each input is proven to drive its row: `TestHappyPathDropsOneInput` removes the
provenance input and asserts the row drops to NOT_TESTED and the promotion
state drops to withheld. The same shape holds for the mirror and the denylist:
remove the input and the row returns to NOT_TESTED.

## What this is not

- It does not verify a manifest's `signing_status`: that field is the
  operator's claim, and the row says so. Publisher signatures are verified
  only as OMS bundles (section 3a), against keys and roots you configure.
- It does not fetch anything. The manifest, the mirror, and the list are all
  local, which is what makes the whole path air-gap safe. A `license_link` is
  listed, never followed.
- It does not review a license. The License policy row checks the license the
  artifact states against your list; it is not legal advice, and it does not
  check that anyone meets the license's usage terms.
