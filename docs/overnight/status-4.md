# Slice status: Tier 1 complete (safetensors, promotion state, happy path)

Branch: `slice/tier1-complete`. Draft PR to `main`. Nothing merged.

## What landed

| Chunk | Issue | Commit | Summary |
|---|---|---|---|
| 1 safetensors reader | #6 | b14eb97 | JSON header parse, tensor count, metadata, hash, no tensor data read |
| 2 pickle scan + inventory | #10 | 6093a97 | Gadget global scan for pickle formats; safetensors metadata inventory |
| 3 format dispatch + promotion state | #6, #10, #32 | 788084c | Engine dispatches by format; promotion is a state |
| 4 happy path | #32 | 1de100c | All-PASS report from supplied inputs, renders all three formats |
| 5 bundle spec | #33 | 1de100c | `docs/provenance-bundle.md` |

Board first: merged #31; closed #2, #5, #11, #25, #28, #29, #30; closed M1, M2, M3; opened #32, #33.

## Verification

- **Air-gap build:** `GOPROXY=off GOFLAGS=-mod=vendor go build ./...` succeeds.
- **Tests:** 16 packages ok; `gofmt` clean.
- **Real safetensors, end to end** (`gemma-4-31b` shard): format `safetensors`, structure PASS, trust rows NOT_TESTED with no inputs, promotion `withheld` with the three surfaces named, and a 1-page PDF renders.
- **Happy path:** with a repo mirror, a denylist, and a provenance manifest supplied, a GGUF fixture yields a fully populated **all-PASS** report that validates, renders HTML/PDF/SARIF, and is `authorized`.
- **Corpus:** zero FAILs across 52 files, unchanged.

## Falsification (each neutered, observed failing, restored, suite green)

1. Pickle gadget list removed:
```
--- FAIL: TestPickleOsSystemFails (0.00s)
    check_test.go:30: status = PASS, want FAIL
```
2. Promotion state branch inverted so a FAIL would authorize:
```
--- FAIL: TestPromotionWithheldOnFail (0.00s)
    scan_test.go:58: a FAIL must withhold even with an acceptance, got state=authorized authorized=true
```
3. Acceptance check dropped so gaps would authorize:
```
--- FAIL: TestPromotionGapsWithoutAcceptanceAreWithheld (0.00s)
```
4. Condition badge mapped to the clean class:
```
--- FAIL: TestPromotionConditionBadgeIsNotClean
    render_test.go:139: the condition state must not share the clean badge class
```
5. Safetensors offset bounds check neutered:
```
--- FAIL: TestOutOfRangeOffsetsAreMalformed (0.00s)
    reader_test.go:70: offsets that exceed the data section must be recorded as malformed
```
6. Provenance input neutered so the happy path would not drop:
```
--- FAIL: TestHappyPathDropsOneInput (0.00s)
    happypath_test.go:119: without the provenance input the row must be NOT_TESTED, got PASS
```

## Two real design corrections this slice

1. **The report now lists the checks that actually ran for the format.** A fixed skeleton listed a pickle row on every GGUF as NOT_TESTED, which made `authorized` unreachable for any single artifact. A pickle row is not applicable to a GGUF, so it no longer appears. The advertised coverage of what we intend to check lives in the docs and the ceiling, not as placeholder rows on every attestation. The visible effect: "check not yet implemented" no longer appears in a CISO-facing report.
2. **Promotion is a state, not a boolean.** `authorized`, `authorized_with_conditions`, `withheld`, `escalated`. A FAIL withholds and is clearable only by escalated review. A gap (NOT_TESTED) withholds until a named acceptance is supplied, and the accepted surfaces travel with the artifact. The condition state renders amber, never the clean green. Model validation enforces the whole machine, including that the `authorized` bool agrees with the state.

Both were caught by writing the happy-path test, which is exactly what that test is for.

## Honest state of the new rows

- **Safetensors has no pickle opcodes by design.** The pickle scan applies to pickle formats. A safetensors or GGUF artifact is NOT_TESTED for that check, never a false pass, and the check names the format it looked at.
- **Pickle gadget detection is a heuristic** over qualified names. It will miss obfuscated gadgets; the check says so in its notes.
- **Provenance records supplied inputs; it does not verify signatures.** `signing_status` is a claim.
- **Safetensors shards are not surfaced as multi-part** the way GGUF shards are. A `model-00001-of-00007.safetensors` reports its own header only. Follow-up.

## Not in this slice

The airlock pull (#13) and promotion (#15), the wizard (#16), Tier 2, the reveal (#23, #24).

## Decisions for you

1. **Next slice:** the airlock (`#13` pull, `#15` promotion into the clean store), or the wizard (#16, the reveal story). The reveal stays gated on the wizard.
2. **Safetensors multi-part detection:** fold into the airlock slice or its own small issue.
