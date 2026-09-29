# Slice status: fileable output and Tier 1 trust coverage

Branch: `slice/trust-coverage`. Draft PR to `main`. Nothing merged.

## What landed

| Chunk | Issue | Commit | Summary |
|---|---|---|---|
| 0 deps + vendoring | - | 2cc8b7d | Pure-Go PDF library, `vendor/` committed, CI builds `-mod=vendor` |
| 1 PDF + SARIF | #28 | 2cc8b7d | `socair render --pdf` and `--sarif`, from the report data model |
| 2 file inventory | #29 | 5bd808b | Artifact payload scan, conservative repo scan |
| 3 denylist | #11 | 8b6ad58 | Offline known-bad hash match |
| 4 provenance | #5 | 8b6ad58 | Offline origin from a manifest and sidecars |
| 5 hero refinement | #30 | 4326305 | Narrowed leads, reviewed-template allowlist |

Board reconciled first: closed #1, #3, #7, #8, #9, #12, #17; re-scoped #2; opened #28, #29, #30. Merged #27.

## Verification

- **Air-gap build:** `GOPROXY=off GOFLAGS=-mod=vendor go build ./...` succeeds, so the appliance build fetches nothing.
- **Tests:** 13 packages ok, `gofmt` clean.
- **Real artifact, all three formats from one scan:** HTML 9081 bytes, PDF valid (PDF 1.3, 2 pages), SARIF 2.1.0 with 8 results.
- **Corpus, zero FAILs across 52 files.** Hero on `~/llmkube-models`: **24 PASS, 0 FAIL, 2 NOT_TESTED**, up from 8 PASS / 18 leads. The 2 are the MiniMax shards, which carry no template.
- **PDF is byte-stable** for a fixed document; the creation date comes from the document, not the clock.

## Falsification (each neutered, observed failing, restored, suite green)

1. PDF status colors forced to the pass color:
```
--- FAIL: TestStatusColorsAreDistinct (0.00s)
    pdf_test.go:62: status backgrounds must be distinct: pass={230 244 234} fail={230 244 234} unt={230 244 234}
```
2. Inventory payload detector neutered:
```
--- FAIL: TestEmbeddedScriptInMetadataFails (0.00s)
    check_test.go:51: status = NOT_TESTED, want FAIL
```
3. Denylist loader forced empty:
```
--- FAIL: TestListedHashFails (0.00s)
    check_test.go:26: status = NOT_TESTED, want FAIL
```
4. Provenance forced to always NOT_TESTED:
```
--- FAIL: TestSignedAndUnsignedProduceDifferentRows (0.00s)
```
5. Hero structural detector forced to PASS:
```
--- FAIL: TestStructuralEscapeFails (0.00s)
    check_test.go:24: status = PASS, want FAIL
```
6. SARIF level mapping forced to none:
```
--- FAIL: TestSARIFLevelMapping (0.00s)
    sarif_test.go:58: level(FAIL) = none, want error
```
7. Vendor removed, air-gap build forced:
```
internal/render/pdf/pdf.go:14:2: cannot find module providing package github.com/go-pdf/fpdf: import lookup disabled by -mod=vendor
```

## The honest headline

The hero check now clears real models instead of flagging them: 24 of 26 clear, zero false positives. That came from finding two substring false positives ("do not tell the user about function calls", "requests" inside "PULL_REQUESTS") and narrowing the patterns to require context. Both are regression tests now.

The trust rows are all real but **mostly NOT_TESTED on a bare artifact**: inventory without a repo mirror, denylist without a list, provenance without a manifest. That is correct and deliberate: we did not look, so we say so. To make these rows PASS in production, the appliance must supply the mirror, the list, and the provenance manifest. That is an operational input, not code.

## Not in this slice

Safetensors reader (#6, #10), the airlock pull (#13), the wizard (#16), Tier 2, the reveal. The witnessed provenance graph: we record origin from supplied inputs, we do not verify signatures yet.

## Decisions for you

1. **Safetensors next?** The buyer's non-GGUF models are uncovered. Small reference to the inventory and quant work.
2. **The provenance inputs are operational**, not code. Do you want a documented bundle spec for what the airlock operator must supply (mirror layout, denylist path, provenance manifest), so the appliance can fill those rows?
3. Nothing else is blocking.
