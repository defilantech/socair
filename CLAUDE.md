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

**One engine, many thin clients.** `internal/engine.ScanMode` is the only scan path. In full mode it first copies the artifact into a private read-only snapshot, hashing while copying (`engine/snapshot.go`), and every check reads the snapshot, so the attested hash and the checked bytes are the same bytes; `SOCAIR_SCAN_TMP` sets where snapshots go (they need the artifact's size free). Readers never hash again. It then reads the header (`internal/gguf` or `internal/safetensors`), runs the per-format check set, fills a `report.Document`, and computes promotion state. A GGUF that does not parse still gets a report (structure NOT_TESTED with the reason). The CLI (`cmd/socair`), the HTTP API (`internal/api`), and the wizard (`web/`) all call that path. None of them add scan logic of their own.

**The report model is the cross-stack contract.** `internal/report` (Go) and `docs/report-schema/v1.json` define `socair.report/v1`. The engine produces it, the CLI prints it, the renderers consume it, and the TS `Document` type in `web/src/lib/api.ts` mirrors it. Do not invent a divergent shape. A shape change touches the Go model, the JSON schema, the TS types, and the golden `testdata/report.json`. `BoundedStatement` and `DoesNotCertify` in `report/model.go` are fixed wording and must not be edited per artifact.

**Checks** (`internal/checks/<name>`): one package per check, each returning `checks.Result` with `PASS`, `FAIL`, `LEAD`, or `NOT_TESTED`. FAIL requires positive evidence (a `Finding`). LEAD is a suspicious but inconclusive signal (e.g. instruction-override language); unlike NOT_TESTED, an acceptance never clears it. Anything ambiguous or unparseable is `NOT_TESTED` with a named reason. PASS only when the check inspected what it names (a recognised label is NOT_TESTED, not PASS). Never pass silently, and never report a guess as a failure. Which checks run depends on format (see `engine/scan.go`): structure/inventory/provenance/denylist always; chattemplate/tokenizer/quant for GGUF; pickle for non-GGUF, non-safetensors. The chat-template "hero check" parses Jinja (`chattemplate/jinja`, a subset parser; unsupported constructs are parse errors) and analyses the tree (`chattemplate/analyze.go`): constant folding, Unicode normalization, dunder reach (FAIL), content-conditional injection (LEAD). An unreadable template is a LEAD, not NOT_TESTED. It has an embedded reviewed-template allowlist (`known-good-templates.txt`, seeded empty on purpose) and an evasion corpus (`testdata/evasions`, `expect.txt` pins every result including known misses). False positives are a stated veto risk: any detection change must be measured with `SOCAIR_TEMPLATE_CORPUS=<dir of .jinja> go test ./internal/checks/chattemplate -run RealTemplates -v`, and recorded in `docs/false-positive-baseline.md`. Use `socair template <path>` / `socair corpus <dir>` to investigate a flag. The same rule holds for safetensors layout (`SOCAIR_SAFETENSORS_CORPUS=<dirs> go test ./internal/checks/structure -run RealSafetensors -v`) and pickle (real checkpoints recorded in the baseline doc).

**Model directories** (`internal/modeldir`, `engine/scandir.go`): `socair scan <dir>` treats a Hugging Face repo or cache snapshot as one artifact. Every file is snapshotted and hashed; the subject is the digest of a canonical manifest (`socair.modeldir/v1`, OMS-style: one subject, per-file hashes in `artifact.files`), and `report.Validate` recomputes it from the listed files. Per-file checks merge into one row each via `checks.Merge` (worst wins, non-PASS files named). The Tokenizer row reads the HF tokenizer files (`tokenizer.InspectHF`, rules measured on 62 real tokenizers; gate: `SOCAIR_TOKENIZER_CORPUS="<dirs>" go test ./internal/checks/tokenizer -run RealHFTokenizers -v`). Adds the Remote code row (`checks/remotecode`: `auto_map` or `.py` is a LEAD) and shard-index validation (`structure.ValidateIndex`). The airlock carries directories too: `PullRepo` stages a whole repo at a pinned commit, each file verified against the hub's hash, and `Promote` places a directory only when its recomputed digest is the attested subject.

**Promotion state machine** (`engine.promotion`, enforced again by `report.Validate`, which recomputes it from the check rows): any FAIL or LEAD → withheld, cleared only by escalation. All PASS → authorized. Gaps (NOT_TESTED) → withheld until accepted. A signed acceptance (`internal/acceptance`, `socair accept`) binds the acceptor's key to the reviewed report's hash, its exact NOT_TESTED rows, and an expiry; `socair sign --acceptance` re-issues the report as "authorized with conditions" with it embedded, and `airlock promote` verifies it against `<store>/acceptor-keys/` (disjoint from `trusted-keys/`; no self-acceptance). `SOCAIR_ACCEPTED_BY` still names an acceptor at scan time, labelled unsigned, and does not cross the airlock. Other engine env inputs: `SOCAIR_REPO_MIRROR`, `SOCAIR_PROVENANCE`, `SOCAIR_DENYLIST`, `SOCAIR_ACCEPTANCE_EXPIRES`, `SOCAIR_FEED` + `SOCAIR_FEED_KEYS` (a signed reference-data feed, `internal/feed`, `docs/feed.md`: denylist, reviewed templates, canonical tokenizers; an unverified or expired feed stops the scan; the report names it in `scope.reference_data`), and for publisher signatures `SOCAIR_PUBLISHER_KEYS`, `SOCAIR_PUBLISHER_ROOTS`, `SOCAIR_OMS_SIGNATURE`, `SOCAIR_SIGSTORE_VERIFIER`, `SOCAIR_SIGSTORE_TRUSTED_ROOT`, `SOCAIR_SIGSTORE_IDENTITIES`.

**Publisher signatures** (`internal/oms`): OpenSSF Model Signing bundles signed with an EC key or a PKI certificate are verified offline, stdlib only, against operator-supplied keys and roots (no default trust). Trusted and holding → provenance PASS ("origin and integrity, not safety"); trusted and not holding (bad signature, changed/missing/unsigned file) → FAIL; untrusted or legacy → named, not judged. Keyless Sigstore bundles go to the optional helper `tools/socair-sigstore` (a separate module with its own vendor/ and CI job, invoked via `SOCAIR_SIGSTORE_VERIFIER` with a trusted root and a required identity policy); unconfigured, they are named, not judged. `testdata/interop` holds vectors made by the reference `model_signing` 1.1.1, plus its keyless test vector.

**Renderers** (`internal/render`): HTML via `html/template` (`template.html` is embedded), PDF in pure Go via vendored `go-pdf/fpdf` so it works air-gapped, and SARIF. All are deterministic and byte-stable for a fixed input, with timestamps taken from the document and not the clock. Golden tests compare against `testdata/`. `internal/demo` holds a fabricated sample report rendered with a SAMPLE mark, and it must never be presented as real.

**Signing** (`internal/attest`): an attestation is an in-toto Statement v1 (predicate type `https://socair.ai/attestation/v1`, predicate the report) in a DSSE envelope signed with Ed25519, verifiable offline. `attest.Verify` delegates the envelope, signature, statement, subject-digest, and promotion-state checks to the public module `github.com/defilantech/socair-verify` (vendored; the same code LLMKube's admission gate runs, so a format change must land there first), then adds a strict decode into `report.Document`, the recorded document hash, and `report.Validate`. Renderers mark an unsigned document UNSIGNED; a rendered report is a claim, the envelope is the proof. The issuer is whoever signs: `socair key gen --issuer <name>` records a name outside the PEM block, `attest.Sign` writes it into `issuer` under the signature, and `Verified.Issuer` confirms it against the verifier's own name for the key (trusted key files; `airlock trust add --name`), refusing a contradicting claim. An unsigned report's issuer is `report.Unissued`, never Defilan.

**Airlock** (`internal/airlock`, `docs/airlock.md`): a content-addressed store with `incoming/<sha256>/` staging, `clean/<sha256>/` (artifact, `attestation.dsse.json`, and `attestation.json`), a trust policy in `trusted-keys/`, and an append-only `log.jsonl`. Only `promote` moves bytes into clean, and only with an envelope signed by a trusted key whose subject is that exact hash; the bytes are hashed while copied. A bare report is never a ticket. "In clean" does not mean clean, because conditional promotions also cross, so listings must carry attestation state. `pull` is the only networked operation (`SOCAIR_EGRESS=deny` blocks it; `SOCAIR_HF_ENDPOINT` overrides the hub). Store root resolves from `--store`, then `SOCAIR_STORE`, then `~/.socair/store`.

**API** (`internal/api`, `docs/api.md`): stateless and has no auth. `POST /api/scan` returns the document, and `POST /api/render` takes it back and returns HTML/PDF bytes. It binds to loopback by default, and a non-loopback bind is refused unless `SOCAIR_API_ALLOW_PUBLIC=1`. With `--web`, it serves the static wizard at `/` with an SPA fallback that never shadows `/api`.

**Wizard** (`web/`, `docs/wizard.md`): shows only state the engine returned and derives no status, count, or badge of its own. NOT_TESTED must never look like a pass. Promotion labels come from `promotion_authorization.state`. A failed scan offers no download. Tests cover these rules, so keep them passing.

## Rules

- Tests are hermetic: no network, secrets, or model files. Fixtures are generated in code (`internal/gguf/gguftest`, `internal/safetensors/safetensorstest`), not committed. The airlock tests use `httptest` for the hub and a temp dir for the store.
- Every check needs a falsification test that fails if the detector is neutered.
- A rule change (check packages, GGUF/safetensors parsers) needs a row in `docs/check-set.md`, and a `CheckSetVersion` bump if it can alter a verdict; `TestCheckSetVersionTracksRules` fails until then.
- `vendor/` is committed on purpose for air-gap builds. After changing deps, run `go mod vendor`.
- The CLI is a harness, not the product surface. Product behavior belongs in `internal/`.
- `docs/overnight/status*.md` are historical slice reports, not current specs.
