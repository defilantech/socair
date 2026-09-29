# Overnight run status

Branch: `overnight/build-1`. Draft PR to `main`. Nothing merged.

## What landed

| Chunk | Issue | Commit | Summary |
|---|---|---|
| 0 Foundation scaffold | - | f3197f7 | Go module, layout, CI (gofmt, build, test), dev docs |
| 1 B1 GGUF reader | #4 | f3197f7 | Header and metadata parse, SHA256, no execution of artifact bytes |
| 2 A2a report data model | #2 | 63c2638 | The cross-stack contract plus JSON schema and structural validation |
| 3 C1 hero check | #7 | de0d4f7 | Chat-template inspection for pre-user-input instructions |
| 4 C2 structure check | #8 | de0d4f7 | Container structure, PASS or NOT_TESTED only |
| 6 C3 tokenizer, C6 quant | #9, #12 | bd25b98 | Tokenizer family and declared-vs-observed quantization |
| glue engine | #2 | bd25b98 | `engine.Scan` fills the report; CLI gates output on validation |
| 5 A1 layout proposal | #1 | (this commit) | `docs/report-layout-proposal.md`, a proposal, not a decision |

## Verification

- `go build ./...` clean.
- `gofmt -l .` clean (CI checks this).
- `go test ./...` all packages pass.
- **Real artifact, end to end.** `socair scan` on a gemma-3-12b Q5_K_M GGUF:

```
Format and structure           PASS   [GGUF v3 parsed: 626 tensors, 44 metadata pairs]
Chat template (hero)           PASS   [no high-risk pattern matched. Heuristic; not a proof of absence]
Tokenizer config               PASS   [tokenizer family 'llama' is recognized]
Safetensors header and opcodes NOT_TESTED [check not yet implemented]
Hash, provenance, lineage      NOT_TESTED [check not yet implemented]
Known-bad hash match           NOT_TESTED [check not yet implemented]
Quant match                    NOT_TESTED [file type 17 is not in our mapping]
authorized                     False
```

- **Reader hash cross-check.** `socair inspect` SHA256 on that artifact equals `shasum -a 256` exactly: `13d44e37860489806f575deb0b219c6058c9421fe1982a9311a0e367c4e8f444`.

## Falsification (each neutered, observed failing, restored, suite green again)

1. Hero detector forced to always-PASS (`r.Status = checks.Fail` -> `checks.Pass` in `chattemplate/check.go`):
```
--- FAIL: TestHostileTemplateFails (0.00s)
    check_test.go:25: status = PASS, want FAIL
--- FAIL: TestDetectorSeparatesCleanFromHostile (0.00s)
    check_test.go:75: hostile = PASS, want FAIL
```
2. Structure check forced to always-PASS (`checks.NotTested` -> `checks.Pass` in `structure/check.go`):
```
--- FAIL: TestTruncatedDoesNotPass (0.00s)
    check_test.go:34: truncated artifact must not PASS, got PASS
```
3. Contract validation forced to accept everything (`Validate` returns nil early):
```
--- FAIL: TestValidateCatchesRemovedRequiredField (0.00s)
    model_test.go:86: blanking header.document_id must fail validation, but it passed
--- FAIL: TestValidateCatchesAlteredBoundedStatement (0.00s)
    model_test.go:103: replacing the bounded statement with an absence claim must fail validation
```

## Not attempted, on purpose

- **A2 PDF output** (#2). No Chrome, no wkhtmltopdf locally. The engine emits the report data model and validates it; HTML plus SARIF to PDF needs a renderer decision (part of A1).
- **A3 demo report** (#3). Needs the A1 layout.
- **D1 pull** (#13). Needs egress and credentials. **E1 wizard** (#16). **F Tier 2** (#18 to #22). **G reveal** (#23, #24).
- No merge to `main`, no force-push.

## Decisions needed from you

1. **LICENSE** for the OSS tier. Not chosen. Proposal: Apache-2.0. Left as a TODO in #24.
2. **A1 layout**, three questions in `docs/report-layout-proposal.md`: NOT_TESTED color, badge as word or scale, cover page or paragraph.
3. **Quant file-type mapping.** The mapping in `internal/checks/quant` lists only historically stable values (F32, F16, Q4_0, Q4_1). File type 17 (the gemma artifact) is NOT_TESTED until the mapping is verified against the current llama.cpp enum. That verification is a follow-up.

## Known limitations to review

- The hero check is a tight heuristic over a known-pattern library, and it says so in its own notes. A clean result is not a proof of absence.
- The structure check has no FAIL path by design: unreadable is ambiguity, not malice.
- Safetensors, provenance, and the denylist rows exist in the report as NOT_TESTED; they are not implemented yet (#6, #5, #11).
