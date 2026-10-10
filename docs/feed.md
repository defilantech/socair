# Signed reference feeds

Some checks compare an artifact against reference data: known-bad artifact
hashes, reviewed known-good chat templates, and canonical tokenizers. A
**feed** delivers that data as a signed bundle, so an air-gapped site can
import it and know who vouched for it and until when.

The format is open, and so is the data: anyone can build and sign a feed with
the `socair` CLI, and the project's own reference data is built in the open.

## Using a feed

```
export SOCAIR_FEED=/opt/socair/feed            # the feed directory
export SOCAIR_FEED_KEYS=/opt/socair/feed-keys  # public key(s) the feed must be signed by
socair scan model.gguf
```

Check a feed before importing it: `socair feed verify <dir> --keys <key.pub|dir>`.

A configured feed that does not verify, or has expired, **stops the scan**: a
feed changes verdicts, so Socair never runs on unverified reference data and
never quietly drops it either. The report names the feed it used, in
`scope.reference_data`: its issuer, version, issue and expiry times, and signing
key.

## What a feed changes

| Data file | Check | Effect |
|---|---|---|
| `denylist.txt` | Known-bad hash match | Combined with any local `SOCAIR_DENYLIST`. A match is a FAIL. In a model directory, the manifest digest and every file's hash are matched. |
| `templates.txt` | Chat template | Added to the embedded reviewed-template allowlist. A template whose SHA-256 is listed clears *language* leads to PASS, and the row notes it is byte-identical to the reviewed template, by its label. It never clears structural evidence: code-execution reach still FAILs. |
| `templates/<sha256>.jinja` | Chat template | A reviewed template's text, listed in `templates.txt` under the same hash. The check renders it beside the artifact's template on the same probe conversations. A template that renders identically on every probe is noted as matching it; one that renders like it on every standard probe but adds a content-conditional branch (it renders differently only when a message carries a literal one of its own conditions tests) is a LEAD with the first difference as evidence; any other template gets no verdict from it, only a note that it matched none. `SOCAIR_TEMPLATE_REFERENCE` (a `.jinja` file or a directory of them, labelled by file name) supplies texts locally, without a feed; those are compared with but never clear a lead. |
| `tokenizers.txt` | Tokenizer config | Informational. The row notes whether the tokenizer's hash matches a canonical tokenizer, and by name. A hash alone cannot say which tokens changed, so it does not change the row's status. |
| `tokenizers/<name>.json` | Tokenizer config | A canonical tokenizer table: the family's vocabulary in id order. The check picks the table that agrees with the model's vocabulary on at least 98% of ids (anything less is another family, not compared), then compares every id. A changed ordinary token, or a vocabulary that ends early, is a LEAD with the ids as evidence. Renamed special or reserved tokens and tokens added past the table are notes: fine-tunes do both legitimately. `SOCAIR_TOKENIZER_REFERENCE` supplies the same tables locally, without a feed. |

## Format

A feed is a directory:

```
feed/
  feed.dsse.json    the signed statement
  denylist.txt      optional
  templates.txt     optional
  tokenizers.txt    optional
  tokenizers/       optional: <name>.json canonical tokenizer tables
  templates/        optional: <sha256>.jinja reviewed template texts
```

A reviewed template's text is named by its SHA-256 and must hash to its name,
and that hash must be listed in `templates.txt`, whose label names it in a
report. Like a tokenizer table, a text the signature does not cover refuses
the feed.

A tokenizer table is `{"format": "socair.tokenizer-table/v1", "name": "qwen3",
"tokens": [...]}`, the vocabulary in id order, or a publisher's
`tokenizer.json` as it ships. Table names are lowercase (`[a-z0-9._-]`), and
every table is listed in the signed statement like the other data files: a
table the signature does not cover refuses the feed. Build one from a trusted
`tokenizer.json` or GGUF:

```
socair feed tokenizer-table tokenizer.json --name qwen3 > feed/tokenizers/qwen3.json
```

Each data file holds one entry per line; blank lines and lines starting with
`#` are ignored. Signed data is held to its format: a malformed line refuses
the feed.

```
# denylist.txt: <sha256> <label>
3f1a…9c  trojaned community quant, reported 2026-09

# templates.txt: <sha256> [label]
8e0b…41  Qwen/Qwen3-8B@a1b2c3d, reviewed 2026-09

# tokenizers.txt: <sha256> <name>
c038…f2  qwen2.5
```

Template hashes are the full SHA-256 (64 hex characters) of the template text.
For a GGUF's default template, the report's `artifact.chat_template_hash`
holds it. `socair template <path>` prints only the first 16 hex characters, so
do not copy a feed line from it. For a template in its own file, such as
`chat_template.jinja`, the file's SHA-256 (`sha256sum chat_template.jinja`) is
the hash. Tokenizer hashes are what the report's `artifact.tokenizer_hash`
holds: the SHA-256 of `tokenizer.json` for a model directory, or of the
vocabulary for a GGUF.

`feed.dsse.json` is a DSSE envelope, signed with Ed25519, over an in-toto
Statement v1:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {"name": "denylist.txt", "digest": {"sha256": "…"}},
    {"name": "templates.txt", "digest": {"sha256": "…"}}
  ],
  "predicateType": "https://socair.ai/feed/v1",
  "predicate": {
    "issuer": "Example Intel",
    "version": "2026.10.1",
    "issued": "2026-10-01T00:00:00Z",
    "expires": "2026-11-01T00:00:00Z",
    "description": "optional"
  }
}
```

The feed verifies when all of these hold:
- the signature is from a key in `SOCAIR_FEED_KEYS`;
- every data file matches its subject digest;
- no data file is present that the statement does not list;
- the current time falls between `issued` and `expires` (five minutes of clock
  skew are allowed on `issued`).

## Building a feed

```
socair key gen --out feed-signer
socair feed sign ./feed --key feed-signer.key --issuer "Example Intel" \
  --version 2026.10.1 --expires <RFC 3339 time>
socair feed verify ./feed --keys feed-signer.pub
```

`--expires` is when importing sites stop accepting the feed, in RFC 3339
(`YYYY-MM-DDTHH:MM:SSZ`); a feed past it stops every scan that uses it.

`feed sign` lists every data file present in the directory and signs it. Keep
the signing key off the machines that import the feed. Those machines only need
`feed-signer.pub`.
