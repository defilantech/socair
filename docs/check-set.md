# Check-set versions

Every report records the check-set version that produced it, in
`scope.check_set_version`. Two reports that carry the same version were graded
by the same rules, so their rows can be compared directly.

## What a version covers

The rules are the code that decides what a check detects and how it grades:
the check packages (`internal/checks/...`), including embedded data such as the
reviewed-template allowlist, and the parsers that feed them (`internal/gguf`,
`internal/safetensors`). Tests, test helpers, and testdata are not rules.

`TestCheckSetVersionTracksRules` (`internal/engine/checkset_test.go`) hashes
those sources into a rule fingerprint. Go files are hashed without their
comments, so editing a comment does not move it. The test fails until this
file has a row for the current version and fingerprint.

## When to bump

- **Bump `CheckSetVersion`** (`internal/engine/scan.go`) when a change can alter
  a verdict: a new or changed pattern, threshold, allowlist entry, status
  mapping, or parser behaviour. Re-measure the affected corpora and record
  them in `docs/false-positive-baseline.md`.
- **Keep the version** when the change cannot alter a verdict (a refactor, a
  performance change, an error message). Add a row for the same version with
  the new fingerprint, and say why it changes nothing.

Reference data from a signed feed (denylist, reviewed templates, canonical
tokenizers) is not part of the check set. The report names the feed it used
in `scope.reference_data`. An operator's license policy
(`SOCAIR_LICENSE_POLICY`) is not either, and is named there too; the license
catalogue it is matched against is, because it decides what is identified.

Tier 2 measurements are not part of the check set either. Each records its
own suite, suite version, and probe-set digest ([tier2.md](tier2.md)).

## Versions

| Version | Rule fingerprint | Date | Changes |
|---|---|---|---|
| `tier1/0.8` | `44a6c7ea7045505745cfdce6ee97756b6afede1fce9fb684f8fa25e85e01a04f` | 2026-10-09 | License (#160): a new package, `internal/checks/license`, identifies the license an artifact states (model card front matter, top-level LICENSE files, GGUF `general.license` keys, and declared base models) against an embedded catalogue, for the identity section. With `SOCAIR_LICENSE_POLICY`, a new License policy row grades it: FAIL when the statements agree on a license the policy does not allow, LEAD when they disagree and one is not allowed, NOT_TESTED when none is identified or one statement is unrecognized. Without a policy no row is added and no verdict changes. The GGUF parser now reads `general.license`, `general.license.name`, `general.license.link`, and `general.base_model.N.{name,organization,repo_url}`. Measured in `docs/false-positive-baseline.md`. |
| `tier1/0.7` | `db14f772c64f1d1a2b71038ede6594941164c28619c08b25941505f0a8e02044` | 2026-10-09 | Tokenizer config, before 0.7's first release: a negative special-token id in `config.json` or `generation_config.json` is transformers' "unset" sentinel (older `LlamaConfig` defaulted `pad_token_id` to -1), not an id outside the tokenizer, so it no longer FAILs as `special-token-out-of-range`. Found on `hf-internal-testing/tiny-random-LlamaForCausalLM`. |
| `tier1/0.7` | `e155d2d1d4c85c625eaa89a8bf30b58a05432d7a296179bdc458052eb7b4e49f` | 2026-10-09 | No rule change: a repo-binary finding reads "is a native executable (ELF)" instead of "is a ELF executable". The status is unchanged. |
| `tier1/0.7` | `91fcd2488025c742f519526e20496711c9abe6fcd8abcc7b020378a1ed19b76e` | 2026-10-09 | No rule change: the chat-template row's LEAD note says "needs review" instead of "escalate", because Socair has no escalation path. The status is unchanged. |
| `tier1/0.7` | `34575e14264dfe967a4ed0adb607be6464f6e8975141c5ecf3e055260336f5ce` | 2026-10-09 | File inventory: a repo mirror that is missing, not a directory, unreadable, or empty is NOT_TESTED with the reason (it PASSed as "repo: 0 files"); an entry the walk cannot read is named and leaves the row NOT_TESTED, while a FAIL elsewhere still stands; and every file is read for an executable or archive signature whatever its name, so an ELF named `setup.py` FAILs (`.py`, `.sh`, `.js`, and `.rb` files were counted without being read). Known-bad hash match: a local denylist line that does not start with a SHA-256 refuses the list, as the feed loader refuses a feed, so a list of `garbage` is NOT_TESTED naming the line instead of PASSing "among 1 known-bad hashes"; and a configured list that cannot be read leaves the row NOT_TESTED even when a feed's list was matched, unless that match FAILs. |
| `tier1/0.6` | `da2aa793e9863b5b430a85ec3db8313a6f4e546ed4071af1e409ae10d3fa1c41` | 2026-10-09 | No rule change: the provenance row's notes say when a pulled model directory is a selection of the repo at its commit, with the patterns and the files left out (`airlock pull --include/--exclude`). The status is unchanged. |
| `tier1/0.6` | `dc0aeeb796c93da346493228ae2600a654f114d9a8d5afbc660871f668203689` | 2026-10-04 | Tokenizer: with a canonical reference table (feed `tokenizers/<name>.json` or `SOCAIR_TOKENIZER_REFERENCE`), every token is compared with the best-matching family table; a changed ordinary token or a shortened vocabulary is a LEAD (#135). |
| `tier1/0.5` | `074eb82595b7eea04d367c17ba31def45e653e8fde3da1ff6180d1f64a4d3fa2` | 2026-10-04 | Jinja parser: `{% filter name %}` takes its first filter without a pipe, as Jinja writes it, so real filter blocks parse and are analysed instead of being reported as unreadable (#137). |
| `tier1/0.4` | `69baef5e476c3b0c39f3c60e85af83dffaec5096d323e9df25fb705b52fe6b78` | 2026-10-04 | File inventory: string-array elements of 64+ bytes in GGUF metadata are scanned for payloads (they were skipped), and an inventory cut off at its cap is NOT_TESTED instead of PASS (#135). |
| `tier1/0.3` | `e63d4be3a7e1ce5cb1631a98c46cf582e69b84a09c98d60e21cc8a6b646666a0` | 2026-10-04 | No rule change: the chat-template row's "looks for" text now says what the check inspects (#131). |
| `tier1/0.3` | `3cae86387201e2303e8dfe9d04383d6f43a15ee4824fdcc363232aad75a5247c` | 2026-10-04 | Chat template: process execution is judged from the parsed template (a module, builtin, or process function referenced in an expression), not from a regex over the raw text, so code words in prose no longer FAIL. Dunder reach was already tree-based; its raw-text regex is removed too (#130). |
| `tier1/0.2` | `23be10362de6e20be2eaf179e3d3910be6491ce71ebd37eec654ccef1f43b22c` | 2026-10-04 | First fingerprinted version. Covers every detector retune recorded in `docs/false-positive-baseline.md` up to this date. |
| `tier1/0.1` | (not fingerprinted) | before 2026-10-04 | The original Tier 1 set. Reports carrying it may come from different rules, because it was not bumped across retunes. |
