# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Socair produces a signed, fileable model assurance attestation for open-weight AI model artifacts (GGUF, safetensors, pickle checkpoints) headed for on-prem or air-gapped inference. The reader is a CISO or Head of AI Ops, so the output is a graded report rather than raw scan data. The report comes first and the engine exists to fill it honestly: `docs/attestation-template.md` is the source of truth for what the scanner must produce.

## Commands

Go engine (deps are vendored; CI sets `GOFLAGS=-mod=vendor` and fetches nothing):

```
go build ./...
go test ./...
go test ./internal/checks/chattemplate -run TestName   # single test
gofmt -l cmd internal                                  # CI fails if this prints anything
go mod verify                                          # CI checks vendor/ is in sync
go run ./cmd/socair scan <path>                        # report JSON to stdout
go run ./cmd/socair render <path> > report.html
go run ./cmd/socair serve --web web/build              # API + wizard on 127.0.0.1:8080
go run ./cmd/socair key gen --out op                   # op.key (0600) + op.pub
go run ./cmd/socair sign --key op.key --report r.json  # r.dsse.json
go run ./cmd/socair verify r.dsse.json --trusted op.pub --artifact <file>
```

Opt-in tests that need real resources, skipped by default:
- `SOCAIR_TEST_MODEL=<path.gguf>` runs `internal/gguf/integration_test.go`
- `SOCAIR_TEST_EGRESS=1` runs the network pull test in `internal/airlock/integration_test.go`

Wizard (`web/`, SvelteKit 5 with runes, static adapter, Vitest):

```
cd web && npm ci
npm run check     # svelte-check
npm run test      # vitest --run
npx vitest run src/lib/run.spec.ts   # single file
npm run build     # static output in web/build
```

## Architecture

**One engine, many thin clients.** `internal/engine.ScanMode` is the only scan path. It reads the artifact (`internal/gguf` or `internal/safetensors`), runs the per-format check set, fills a `report.Document`, then computes promotion state. The CLI (`cmd/socair`), the HTTP API (`internal/api`), and the wizard (`web/`) all call that path. None of them add scan logic of their own.

**The report model is the cross-stack contract.** `internal/report` (Go) and `docs/report-schema/v1.json` define `socair.report/v1`. The engine produces it, the CLI prints it, the renderers consume it, and the TS `Document` type in `web/src/lib/api.ts` mirrors it. Do not invent a divergent shape. A shape change touches the Go model, the JSON schema, the TS types, and the golden `testdata/report.json`. `BoundedStatement` and `DoesNotCertify` in `report/model.go` are fixed wording and must not be edited per artifact.

**Checks** (`internal/checks/<name>`): one package per check, each returning `checks.Result` with `PASS`, `FAIL`, `LEAD`, or `NOT_TESTED`. FAIL requires positive evidence (a `Finding`). LEAD is a suspicious but inconclusive signal (e.g. instruction-override language); unlike NOT_TESTED, an acceptance never clears it. Anything ambiguous or unparseable is `NOT_TESTED` with a named reason. PASS only when the check inspected what it names (a recognised label is NOT_TESTED, not PASS). Never pass silently, and never report a guess as a failure. Which checks run depends on format (see `engine/scan.go`): structure/inventory/provenance/denylist always; chattemplate/tokenizer/quant for GGUF; pickle for non-GGUF, non-safetensors. The chat-template "hero check" parses Jinja (`chattemplate/jinja`, a subset parser; unsupported constructs are parse errors) and analyses the tree (`chattemplate/analyze.go`): constant folding, Unicode normalization, dunder reach (FAIL), content-conditional injection (LEAD). An unreadable template is a LEAD, not NOT_TESTED. It has an embedded reviewed-template allowlist (`known-good-templates.txt`, seeded empty on purpose) and an evasion corpus (`testdata/evasions`, `expect.txt` pins every result including known misses). False positives are a stated veto risk: any detection change must be measured with `SOCAIR_TEMPLATE_CORPUS=<dir of .jinja> go test ./internal/checks/chattemplate -run RealTemplates -v`, and recorded in `docs/false-positive-baseline.md`. Use `socair template <path>` / `socair corpus <dir>` to investigate a flag.

**Promotion state machine** (`engine.promotion`, enforced again by `report.Validate`, which recomputes it from the check rows): any FAIL or LEAD → withheld, cleared only by escalation. All PASS → authorized. Gaps (NOT_TESTED) → withheld unless `SOCAIR_ACCEPTED_BY` names an acceptor, which gives "authorized with conditions" and records the accepted surfaces. Other engine env inputs: `SOCAIR_REPO_MIRROR`, `SOCAIR_PROVENANCE`, `SOCAIR_DENYLIST`, `SOCAIR_ACCEPTANCE_EXPIRES`.

**Renderers** (`internal/render`): HTML via `html/template` (`template.html` is embedded), PDF in pure Go via vendored `go-pdf/fpdf` so it works air-gapped, and SARIF. All are deterministic and byte-stable for a fixed input, with timestamps taken from the document and not the clock. Golden tests compare against `testdata/`. `internal/demo` holds a fabricated sample report rendered with a SAMPLE mark, and it must never be presented as real.

**Signing** (`internal/attest`): an attestation is an in-toto Statement v1 (predicate type `https://socair.ai/attestation/v1`, predicate the report) in a DSSE envelope signed with Ed25519, verifiable offline. `attest.Verify` checks the signature against a keyring, statement and predicate types, subject digest = artifact hash, the recorded document hash, and `report.Validate`. Renderers mark an unsigned document UNSIGNED; a rendered report is a claim, the envelope is the proof.

**Airlock** (`internal/airlock`, `docs/airlock.md`): a content-addressed store with `incoming/<sha256>/` staging, `clean/<sha256>/` (artifact, `attestation.dsse.json`, and `attestation.json`), a trust policy in `trusted-keys/`, and an append-only `log.jsonl`. Only `promote` moves bytes into clean, and only with an envelope signed by a trusted key whose subject is that exact hash; the bytes are hashed while copied. A bare report is never a ticket. "In clean" does not mean clean, because conditional promotions also cross, so listings must carry attestation state. `pull` is the only networked operation (`SOCAIR_EGRESS=deny` blocks it; `SOCAIR_HF_ENDPOINT` overrides the hub). Store root resolves from `--store`, then `SOCAIR_STORE`, then `~/.socair/store`.

**API** (`internal/api`, `docs/api.md`): stateless and has no auth. `POST /api/scan` returns the document, and `POST /api/render` takes it back and returns HTML/PDF bytes. It binds to loopback by default, and a non-loopback bind is refused unless `SOCAIR_API_ALLOW_PUBLIC=1`. With `--web`, it serves the static wizard at `/` with an SPA fallback that never shadows `/api`.

**Wizard** (`web/`, `docs/wizard.md`): shows only state the engine returned and derives no status, count, or badge of its own. NOT_TESTED must never look like a pass. Promotion labels come from `promotion_authorization.state`. A failed scan offers no download. Tests cover these rules, so keep them passing.

## Rules

- Tests are hermetic: no network, secrets, or model files. Fixtures are generated in code (`internal/gguf/gguftest`, `internal/safetensors/safetensorstest`), not committed. The airlock tests use `httptest` for the hub and a temp dir for the store.
- Every check needs a falsification test that fails if the detector is neutered.
- `vendor/` is committed on purpose for air-gap builds. After changing deps, run `go mod vendor`.
- The CLI is a harness, not the product surface. Product behavior belongs in `internal/`.
- `docs/overnight/status*.md` are historical slice reports, not current specs.
