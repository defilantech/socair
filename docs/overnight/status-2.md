# Slice status: corpus baseline and renderer

Branch: `slice/corpus-and-render`. Draft PR to `main`. Nothing merged.

## What landed

| Chunk | Issue | Commit | Summary |
|---|---|---|
| 0 | #24 | (this branch) | Merged #26, Apache-2.0 LICENSE, docs |
| 1 S1 corpus baseline | #9 | ad1dc45 | Header-only sweep tool, and the hero retune |
| 2 S3 reader/quant hardening | #4, #12 | 2f0661b | Split GGUFs, mixed-width metadata, full quant enum |
| 3 S2 render | #2 | dbf2c19 | HTML attestation from the data model |
| 4 A3 demo report | #3 | dbf2c19 | `socair demo`, SAMPLE-marked |

## Verification

- `go build ./...`, `gofmt -l .`, `go test ./...` all clean.
- **Corpus baseline, 52 real GGUFs across three directories.** Before the
  retune the hero check FAILED 15 of 26 models in `~/llmkube-models`, all
  known-good. After: **zero FAILs across all 52 files.** Details in
  `docs/false-positive-baseline.md`.
- **Quant coverage** on `~/llmkube-models` went from 2 of 26 to 23 of 26, still
  zero FAILs, once the enum came from `llama.cpp/include/llama.h`.
- **Split detection on a real shard**: `MiniMax-M2.7-UD-IQ3_S-00002-of-00003.gguf`
  now reports `part 2 of 3`, and the structure note says it is one shard, not
  the whole model.
- **Render on a real artifact**: `socair render` on gemma-3-12b emits 4 PASS and
  3 neutral NOT_TESTED pills, byte-stable, HTML escaped.

## Falsification (each neutered, observed failing, restored, suite green again)

1. Hero structural detector forced to PASS:
```
--- FAIL: TestStructuralEscapeFails (0.00s)
    check_test.go:25: status = PASS, want FAIL
--- FAIL: TestProcessExecutionFails (0.00s)
    check_test.go:38: status = PASS, want FAIL
```
2. Split detection forced off (`MultiPart` returns false):
```
--- FAIL: TestSplitMetadata (0.00s)
    reader_test.go:145: a shard must be reported as part of a split model
--- FAIL: TestMixedWidthSplitMetadata (0.00s)
    reader_test.go:168: uint16 split metadata must be captured, not dropped
```
3. Quant filename parser forced empty:
```
--- FAIL: TestQuantFromFileName (0.00s)
    reader_test.go:127: QuantFromFileName("Qwen3.6-35B-A3B-UD-Q4_K_M.gguf") = "", want "Q4_K_M"
```
4. Pill class forced to "pass":
```
--- FAIL: TestNotTestedNeverLooksLikeAPass (0.00s)
    render_test.go:67: a NOT_TESTED status must never render with the pass class
```

## The honest headline

The corpus baseline did its job and found a real problem: **the hero check was
failing most known-good models on ordinary template language.** Phrase matching
cannot separate benign from malicious, so instruction language is now a
NOT_TESTED lead that escalates, and FAIL requires structural code-execution
evidence. The hero check now clears 8 of 26 real templates and flags 18 as
leads, failing none. That is honest, but it means the hero check currently
rarely *clears* a real model outright.

## Not in this slice

- S4 file inventory ("no hidden files"), the gap in the signed claim.
- PDF output (no local renderer) and SARIF (deferred, planned).
- Provenance (#5), safetensors (#6), denylist (#11).
- The airlock pull (#13), the wizard (#16), Tier 2, the reveal.

## Decisions for you

1. **The hero lead rate.** 18 of 26 real templates return a NOT_TESTED lead.
   Do you want to (a) refine leads with a template allowlist or per-family
   patterns, (b) build S4 file inventory next, or (c) move to provenance? My
   lean: (b), because "no hidden files" is in the signed sentence.
2. **PDF renderer.** Headless Chrome or a pure-Go library, when we want the
   fileable PDF rather than HTML.
3. Nothing else is blocking.
