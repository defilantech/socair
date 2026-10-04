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
in `scope.reference_data`.

## Versions

| Version | Rule fingerprint | Date | Changes |
|---|---|---|---|
| `tier1/0.5` | `074eb82595b7eea04d367c17ba31def45e653e8fde3da1ff6180d1f64a4d3fa2` | 2026-10-04 | Jinja parser: `{% filter name %}` takes its first filter without a pipe, as Jinja writes it, so real filter blocks parse and are analysed instead of being reported as unreadable (#137). |
| `tier1/0.4` | `69baef5e476c3b0c39f3c60e85af83dffaec5096d323e9df25fb705b52fe6b78` | 2026-10-04 | File inventory: string-array elements of 64+ bytes in GGUF metadata are scanned for payloads (they were skipped), and an inventory cut off at its cap is NOT_TESTED instead of PASS (#135). |
| `tier1/0.3` | `e63d4be3a7e1ce5cb1631a98c46cf582e69b84a09c98d60e21cc8a6b646666a0` | 2026-10-04 | No rule change: the chat-template row's "looks for" text now says what the check inspects (#131). |
| `tier1/0.3` | `3cae86387201e2303e8dfe9d04383d6f43a15ee4824fdcc363232aad75a5247c` | 2026-10-04 | Chat template: process execution is judged from the parsed template (a module, builtin, or process function referenced in an expression), not from a regex over the raw text, so code words in prose no longer FAIL. Dunder reach was already tree-based; its raw-text regex is removed too (#130). |
| `tier1/0.2` | `23be10362de6e20be2eaf179e3d3910be6491ce71ebd37eec654ccef1f43b22c` | 2026-10-04 | First fingerprinted version. Covers every detector retune recorded in `docs/false-positive-baseline.md` up to this date. |
| `tier1/0.1` | (not fingerprinted) | before 2026-10-04 | The original Tier 1 set. Reports carrying it may come from different rules, because it was not bumped across retunes. |
