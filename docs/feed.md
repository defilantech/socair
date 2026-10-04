# Signed reference feeds

Some checks compare an artifact against reference data: known-bad artifact
hashes, reviewed known-good chat templates, and canonical tokenizers. A
**feed** delivers that data as a signed bundle, so an air-gapped site can
import it and know who vouched for it and until when.

The format is open. Anyone can build and sign a feed with the `socair` CLI.
Defilan Technologies publishes a curated, maintained feed as a commercial
subscription.

## Using a feed

```
SOCAIR_FEED=/opt/socair/feed            # the feed directory
SOCAIR_FEED_KEYS=/opt/socair/feed-keys  # public key(s) the feed must be signed by
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
| `templates.txt` | Chat template (hero) | Added to the embedded reviewed-template allowlist. A template whose SHA-256 is listed clears *language* leads to PASS. It never clears structural evidence: code-execution reach still FAILs. |
| `tokenizers.txt` | Tokenizer config | Informational. The row notes whether the tokenizer's hash matches a canonical tokenizer, and by name. It does not change the row's status: a fine-tune may add tokens legitimately, and judging a mismatch needs the model's family. |

## Format

A feed is a directory:

```
feed/
  feed.dsse.json    the signed statement
  denylist.txt      optional
  templates.txt     optional
  tokenizers.txt    optional
```

Each data file holds one entry per line; blank lines and lines starting with
`#` are ignored. Signed data is held to its format: a malformed line refuses
the feed.

```
# denylist.txt: <sha256> <label>
3f1a…9c  trojaned community quant, reported 2026-09

# templates.txt: <sha256> [note]
8e0b…41  Qwen3 default template, reviewed 2026-09

# tokenizers.txt: <sha256> <name>
c038…f2  qwen2.5
```

Template hashes are the SHA-256 of the template text (`socair template <path>`
prints it). Tokenizer hashes are what the report's `artifact.tokenizer_hash`
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
  --version 2026.10.1 --expires 2026-11-01T00:00:00Z
socair feed verify ./feed --keys feed-signer.pub
```

`feed sign` lists every data file present in the directory and signs it. Keep
the signing key off the machines that import the feed. Those machines only need
`feed-signer.pub`.
