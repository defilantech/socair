# AGENTS.md

This file is the guide that coding agents and contributors share: what Socair is, how to build and test it, the rules every change is held to, and how the code fits together. [CONTRIBUTING.md](CONTRIBUTING.md) is the human onboarding guide, including the DCO and the AI-assistance policy. Claude Code reads this file through `CLAUDE.md`, which imports it.

## What Socair is

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
go run ./cmd/socair serve --web web/build --scan-root <dir>   # API + wizard on 127.0.0.1:8080
go run ./cmd/socair key gen --out op                   # op.key (0600) + op.pub
go run ./cmd/socair sign --key op.key --report r.json  # r.dsse.json
go run ./cmd/socair verify r.dsse.json --trusted op.pub --artifact <file>
```

Helm chart (`charts/socair`) and image (`Dockerfile`):

```
helm lint --strict charts/socair
helm unittest charts/socair      # helm-unittest plugin; tests in charts/socair/tests
scripts/chart-e2e.sh             # kind cluster end to end (needs docker, kind, kubectl, helm, go)
```

Tier 2 probe helper (`tools/socair-probe`, Python standard library only, kept out of the Go build):

```
cd tools/socair-probe && python3 -m unittest discover -s tests -t .
```

Wizard (`web/`, SvelteKit 5 with runes, static adapter, Vitest):

```
cd web && npm ci
npm run check     # svelte-check
npm run test      # vitest --run
npx vitest run src/lib/run.spec.ts   # single file
npm run build     # static output in web/build
```

Opt-in tests that need real resources, skipped by default:

- `SOCAIR_TEST_MODEL=<path.gguf>` runs `internal/gguf/integration_test.go`.
- `SOCAIR_TEST_EGRESS=1` runs the network pull test in `internal/airlock/integration_test.go`.
- `SOCAIR_TEST_PROBE_HELPER=<path to tools/socair-probe/socair-probe>` runs the engine against the real Tier 2 probe helper (`go test ./internal/engine -run RealProbeHelper -v`).
- `SOCAIR_TEST_COSIGN=<path to cosign>` runs cosign `verify-attestation` against an attached artifact (`go test ./internal/ociattest -run Cosign -v`).
- `SOCAIR_TEST_REGISTRY=<host:port of a scratch registry>` pushes, attaches, and verifies against a real registry (`go test ./internal/ociattest -run RealRegistry -v`).

Real-corpus gates, run before and after a detection change (see "False positives" below):

- Chat templates: `SOCAIR_TEMPLATE_CORPUS=<dir of .jinja> go test ./internal/checks/chattemplate -run RealTemplates -v`
- Safetensors layout: `SOCAIR_SAFETENSORS_CORPUS=<dirs> go test ./internal/checks/structure -run RealSafetensors -v`
- HF tokenizers: `SOCAIR_TOKENIZER_CORPUS="<dirs>" go test ./internal/checks/tokenizer -run RealHFTokenizers -v`
- Pickle sniffing: `SOCAIR_PICKLE_SNIFF_CORPUS=<dirs> go test ./internal/checks/pickle -run RealSniff -v`
- License matching: `SOCAIR_LICENSE_CORPUS=<dir of repos> go test ./internal/engine -run RealLicenses -v`

## Rules

- Tests are hermetic: no network, secrets, or model files. Fixtures are generated in code (`internal/gguf/gguftest`, `internal/safetensors/safetensorstest`), not committed. The airlock tests use `httptest` for the hub and a temp dir for the store.
- Every check needs a falsification test that fails if the detector is neutered.
- The detection benchmark (`internal/benchmark`, `docs/detection-benchmark.md`) pins every case's outcome; a detection change updates the case and the doc together. Its attacks are defanged and generated in code; live malicious samples never go on a workstation.
- A rule change (check packages, GGUF/safetensors parsers) needs a row in `docs/check-set.md`, and a `CheckSetVersion` bump if it can alter a verdict; `TestCheckSetVersionTracksRules` fails until then.
- The report shape is a contract: a change touches the Go model, the JSON schema, the TS types, and the goldens together (see "The report contract").
- `vendor/` is committed on purpose for air-gap builds. After changing deps, run `go mod vendor`.
- The CLI is a harness, not the product surface. Product behavior belongs in `internal/`.
- Build output never goes in the tree: `go build -o bin/<name>` (ignored) or a scratch dir. A bare `go build` in `tools/socair-sigstore` writes a binary next to the source, which is how one was once committed.
- Commits are signed off (`git commit -s`; the `dco` check enforces it) and carry no attribution trailers. AI assistance is disclosed in the PR description, as [CONTRIBUTING.md](CONTRIBUTING.md#ai-assisted-contributions) describes.

## Architecture

### One engine, many thin clients

- `internal/engine.ScanMode` is the only scan path. The CLI (`cmd/socair`), the HTTP API (`internal/api`), and the wizard (`web/`) all call it, and none of them add scan logic of their own.
- In full mode it first copies the artifact into a private read-only snapshot, hashing while copying (`engine/snapshot.go`). Every check reads the snapshot, so the attested hash and the checked bytes are the same bytes. Readers never hash again. `SOCAIR_SCAN_TMP` sets where snapshots go (they need the artifact's size free).
- It then reads the header (`internal/gguf` or `internal/safetensors`), runs the per-format check set, fills a `report.Document`, and computes promotion state. A GGUF that does not parse still gets a report (structure NOT_TESTED with the reason).

### The report contract

- `internal/report` (Go) and `docs/report-schema/v1.json` define `socair.report/v1`. The engine produces it, the CLI prints it, the renderers consume it, and the TS `Document` type in `web/src/lib/api.ts` mirrors it. Do not invent a divergent shape.
- A shape change touches the Go model, the JSON schema, the TS types, and the goldens `testdata/report.json` and `testdata/report-tier2.json`.
- Fixed wording, never edited per artifact, in `report/model.go`: the four bounded-statement sentences (`BoundedStatementNoIndicators` and `BoundedStatementIndicators`, and for a report with a `tier2` section `BoundedStatementTier2NoIndicators` and `BoundedStatementTier2Indicators`; `BoundedStatementOf` picks one from the check rows, and `Validate` re-derives it) and `DoesNotCertify`.

### Checks

- One package per check (`internal/checks/<name>`), each returning `checks.Result` with `PASS`, `FAIL`, `LEAD`, or `NOT_TESTED`.
  - FAIL requires positive evidence (a `Finding`).
  - LEAD is a suspicious but inconclusive signal (e.g. instruction-override language); unlike NOT_TESTED, an acceptance never clears it.
  - Anything ambiguous or unparseable is `NOT_TESTED` with a named reason.
  - PASS only when the check inspected what it names (a recognised label is NOT_TESTED, not PASS).
  - Never pass silently, and never report a guess as a failure.
- Which checks run depends on format (see `engine/scan.go`): structure/inventory/provenance/denylist always; chattemplate/tokenizer/quant for GGUF; pickle for non-GGUF, non-safetensors; License policy for every format, only when `SOCAIR_LICENSE_POLICY` names an allowed list; Intake policy for every format, only when `SOCAIR_INTAKE_POLICY` names a policy.
- **License** is identity, not a check (`checks/license`, `artifact.license`). It is read from the model card front matter, LICENSE files, and GGUF `general.license`, and matched against an embedded catalogue keyed by ScanCode LicenseDB ids (a whole permissive text by an in-order shingle fingerprint in `bodies/`, generated by `checks/license/fpgen` from canonical texts that are not committed; model licenses by title phrases), never guessed. Sources that name different licenses are a disagreement, a LEAD only under a policy. Without a policy nothing about promotion changes.
- **Intake policy** (`checks/intake`, `docs/intake-policy.md`) holds an artifact to an organization's rules: allowed formats (identified from the bytes, never the name), allowed and denied publishers (read only from a provenance manifest bound to the artifact's hash, never a cache path), and publishers whose models need a verified publisher signature (the verification the provenance row reads). It can only withhold: it never changes another row or authorizes.
- **Chat template**, the "hero check":
  - It parses Jinja (`chattemplate/jinja`, a subset parser; unsupported constructs are parse errors) and analyses the tree (`chattemplate/analyze.go`): constant folding, Unicode normalization, dunder reach (FAIL), content-conditional injection (LEAD). An unreadable template is a LEAD, not NOT_TESTED.
  - A template with no code reach is then rendered (`chattemplate/render.go`) by Socair's own bounded evaluator (`jinja.Render`, modelling transformers' sandbox; never Python or another engine) on the versioned probe conversations (`ProbeSet`), plus a trigger probe per literal a content condition tests.
  - The text a render adds is listed in the notes and never judged. A condition that opens a system turn, or a near-miss of a reviewed template's text (identical on every standard probe, different under a condition it adds), is a LEAD. A construct the evaluator does not model, or a passed render bound, leaves it unrendered with the reason and the static verdict standing.
  - It has an embedded reviewed-template allowlist (`known-good-templates.txt`, seeded empty on purpose) and an evasion corpus (`testdata/evasions`, `expect.txt` pins every result including known misses).
  - Use `socair template <path>` / `socair corpus <dir>` to investigate a flag.
- **False positives are a stated veto risk.** Any detection change must be measured with the real-corpus gates under Commands and recorded in `docs/false-positive-baseline.md`; pickle is measured on real checkpoints recorded in the same doc.

### Model directories

- `socair scan <dir>` (`internal/modeldir`, `engine/scandir.go`) treats a Hugging Face repo or cache snapshot as one artifact. Every file is snapshotted and hashed; the subject is the digest of a canonical manifest (`socair.modeldir/v1`, OMS-style: one subject, per-file hashes in `artifact.files`), and `report.Validate` recomputes it from the listed files.
- Per-file checks merge into one row each via `checks.Merge` (worst wins, non-PASS files named).
- The Tokenizer row reads the HF tokenizer files (`tokenizer.InspectHF`, rules measured on 62 real tokenizers).
- A directory adds the Remote code row (`checks/remotecode`: `auto_map` or `.py` is a LEAD) and shard-index validation (`structure.ValidateIndex`).
- A file reaches the Pickle row by its extension or by its bytes (`pickle.Sniff`: a protocol 2 to 5 stream that walks, or a torch.save zip; not protocol 0/1 text, safetensors, GGUF, or TorchScript archives, which stay named as unscanned archives). A directory with no pickle says so in File inventory's notes.
- A torch.save zip the Pickle row PASSed counts as read in File inventory when every entry in it is accounted for (`pickle.InspectArchive` hands the inventory what it read, `checks.ArchiveRead`); any other entry keeps it unscanned and named.
- The airlock carries directories too: `PullRepo` stages a whole repo at a pinned commit, each file verified against the hub's hash, and `Promote` places a directory only when its recomputed digest is the attested subject.

### Promotion

- `engine.promotion` computes the state, and `report.Validate` enforces it again by recomputing it from the check rows:
  - any FAIL or LEAD → withheld; no acceptance clears it, and Socair has no override (the `escalated` state exists in the schema but nothing produces it);
  - all PASS → authorized;
  - gaps (NOT_TESTED) → withheld until accepted.
- A signed acceptance (`internal/acceptance`, `socair accept`) binds the acceptor's key to the reviewed report's hash, its exact NOT_TESTED rows, and an expiry. `socair sign --acceptance` re-issues the report as "authorized with conditions" with it embedded, and `airlock promote` verifies it against `<store>/acceptor-keys/` (disjoint from `trusted-keys/`; no self-acceptance).
- `SOCAIR_ACCEPTED_BY` still names an acceptor at scan time, labelled unsigned, and does not cross the airlock.

### Engine inputs

- `SOCAIR_REPO_MIRROR`, `SOCAIR_PROVENANCE`, `SOCAIR_DENYLIST`, `SOCAIR_ACCEPTANCE_EXPIRES`.
- `SOCAIR_FEED` + `SOCAIR_FEED_KEYS`: a signed reference-data feed (`internal/feed`, `docs/feed.md`) holding a denylist, reviewed templates and their texts, and canonical tokenizer hashes and tables. An unverified or expired feed stops the scan; the report names it in `scope.reference_data`.
- `SOCAIR_TOKENIZER_REFERENCE`: canonical tokenizer tables, diffed token by token (`tokenizer.Compare`).
- `SOCAIR_TEMPLATE_REFERENCE`: reviewed chat-template texts a render is compared with; never clears a lead.
- `SOCAIR_LICENSE_POLICY`: allowed license ids, one per line; an unknown id or an empty list stops the scan.
- `SOCAIR_INTAKE_POLICY`: a `socair.intake-policy/v1` JSON file; one that does not load stops the scan, and the report names it by file name and hash in `scope.intake_policy`.
- Tier 2, opt-in: `SOCAIR_TIER2_HELPER` + `SOCAIR_TIER2_ENDPOINT`, with optional `SOCAIR_TIER2_REFERENCE_ENDPOINT`, `SOCAIR_TIER2_PROBES`, `SOCAIR_TIER2_NODE_CLASS`, `SOCAIR_TIER2_TIMEOUT` (`internal/tier2`, `docs/tier2.md`). The probe helper runs the model and reports measurements in the report's `tier2` section; a LEAD or FAIL measurement adds a `(Tier 2)` row that withholds promotion, and nothing it finds is a PASS or authorizes.
- Publisher signatures: `SOCAIR_PUBLISHER_KEYS`, `SOCAIR_PUBLISHER_ROOTS`, `SOCAIR_OMS_SIGNATURE`, `SOCAIR_SIGSTORE_VERIFIER`, `SOCAIR_SIGSTORE_TRUSTED_ROOT`, `SOCAIR_SIGSTORE_IDENTITIES`.

### Publisher signatures

- `internal/oms` verifies OpenSSF Model Signing bundles signed with an EC key or a PKI certificate offline, stdlib only, against operator-supplied keys and roots (no default trust).
  - Trusted and holding → provenance PASS ("origin and integrity, not safety").
  - Trusted and not holding (bad signature, changed/missing/unsigned file) → FAIL.
  - Untrusted or legacy → named, not judged.
- A directory scan reads `model.sig` or NGC's `result.sigstore` at its root (with both there and `SOCAIR_OMS_SIGNATURE` naming neither, the signature is named, not judged), and a certificate chain is checked at the scan's time.
- A signed file under download-tool metadata the walk skips (`.cache/`, `.huggingface/`, which `hf download --local-dir` writes) is left out of the comparison and named as signed but not compared (`modeldir.DownloadMetadata`, `oms.Manifest.Without`, `provenance.Signature.NotCompared`), never reported missing; the PASS then says "every signed file the scan read matches".
- Keyless Sigstore bundles go to the optional helper `tools/socair-sigstore` (a separate module with its own vendor/ and CI job, invoked via `SOCAIR_SIGSTORE_VERIFIER` with a trusted root and a required identity policy); unconfigured, they are named, not judged.
- `tools/oms-conformance` adapts the OpenSSF Model Signing conformance suite to `internal/oms` (verify only; the `oms-conformance` CI job pins the suite, known failures in `xfail.txt`). `testdata/interop` holds vectors made by the reference `model_signing` 1.1.1, plus its keyless test vector.

### Renderers and framework mappings

- `internal/render`: HTML via `html/template` (`template.html` is embedded), PDF in pure Go via vendored `go-pdf/fpdf` so it works air-gapped, SARIF, and a CycloneDX 1.6 ML-BOM (`render/cyclonedx`, `docs/cyclonedx.md`: derived from the report alone, a field the report does not know left out; mapped to the G7 SBOM-for-AI minimum elements).
- All are deterministic and byte-stable for a fixed input, with timestamps taken from the document and not the clock. Golden tests compare against `testdata/`.
- `socair sign --bom` signs a BOM under predicate type `https://cyclonedx.org/bom`, which `socair verify` refuses as an attestation and `socair verify --bom` checks.
- Rows map to MITRE ATLAS and OWASP LLM entries with their editions (`report/frameworks.go`, pinned to ATLAS 2026.09 and OWASP 2025). Every ATLAS ID is checked against `report/testdata/atlas-ids.txt`, which `report/atlasgen` writes from the release's data, and `docs/control-mapping.md` says what each row is evidence for. The goldens' `maps_to` must match `report.MapsTo`.
- `internal/demo` holds a fabricated sample report rendered with a SAMPLE mark, and it must never be presented as real.

### Signing

- An attestation (`internal/attest`) is an in-toto Statement v1 (predicate type `https://socair.ai/attestation/v1`, predicate the report) in a DSSE envelope signed with Ed25519, verifiable offline.
- `attest.Verify` delegates the envelope, signature, statement, subject-digest, and promotion-state checks to the public module `github.com/defilantech/socair-verify` (vendored; the same code LLMKube's admission gate runs, so a format change must land there first), then adds a strict decode into `report.Document`, the recorded document hash, and `report.Validate`.
- Renderers mark an unsigned document UNSIGNED; a rendered report is a claim, the envelope is the proof.
- The issuer is whoever signs: `socair key gen --issuer <name>` records a name outside the PEM block, `attest.Sign` writes it into `issuer` under the signature, and `Verified.Issuer` confirms it against the verifier's own name for the key (trusted key files; `airlock trust add --name`), refusing a contradicting claim. An unsigned report's issuer is `report.Unissued`, never Defilan.

### Airlock

- `internal/airlock` (`docs/airlock.md`) is a content-addressed store: `incoming/<sha256>/` staging, `clean/<sha256>/` (artifact, `attestation.dsse.json`, and `attestation.json`), a trust policy in `trusted-keys/`, and an append-only `log.jsonl`. Store root resolves from `--store`, then `SOCAIR_STORE`, then `~/.socair/store`.
- Only `promote` moves bytes into clean, and only with an envelope signed by a trusted key whose subject is that exact hash; the bytes are hashed while copied. A bare report is never a ticket.
- "In clean" does not mean clean, because conditional promotions also cross, so listings must carry attestation state.
- `Store.Assess` is the gate's one verification, used by `Promote` and the console. A model's stage is derived from evidence files (`Store.Models`), never stored.
- `pull` is the only networked operation (`SOCAIR_EGRESS=deny` blocks it; `SOCAIR_HF_ENDPOINT` overrides the hub; `HF_TOKEN` goes to the hub's own host only, stripped on any cross-host redirect). A repo pull's `--include`/`--exclude` select files the way `hf download` patterns do; the provenance manifest records the selection and every file left out.
- Every large copy (pull, scan snapshot, promote) checks for room first via `internal/diskfree`.
- The signed inventory snapshot (`socair airlock export`, `socair inventory verify`) is `internal/inventory`.
- `socair airlock recheck` (`airlock/recheck.go`) re-examines `clean/` against what a scan would use now: every model's hashes against the feed's and the local denylist (no bytes read), and a rescan of the clean bytes when the attestation's check set is not this socair's, or with `--rescan`. A model that would now be withheld is flagged in `clean/<sha256>/recheck.json` and its stage becomes `flagged`; a flag clears only when a later recheck re-examines what it rests on.
- `socair airlock serve-hub` (`airlock/hub.go`, `docs/hub-endpoint.md`) serves admitted entries read-only over the Hugging Face Hub API for `HF_ENDPOINT`: admission is re-derived per request (`Store.AdmittedEntry`), only attested paths are served, opened through `os.Root`, and a whole download's last byte is sent only if the file hashes to the attestation.

### OCI artifacts

- `socair attach <oci-ref>` (`internal/registry`, `internal/ociattest`, `docs/oci.md`) verifies an attestation, matches the artifact's layers to the attested bytes (`MatchLayers`: raw single-file layers only, by digest, and for a directory by path; tar and compressed layers are refused), and signs a binding: an in-toto statement about the OCI manifest digest (`https://socair.ai/oci-binding/v1`) that names the attestation by hash and repeats its promotion state.
- It pushes the binding and the attestation as one referrer, and the binding again as a Sigstore bundle referrer (no DSSE key id: sigstore-go skips Socair's) that cosign and Kyverno read.
- `socair verify <oci-ref>` re-checks every link, the layer match included.
- `internal/registry` is a narrow net/http client: the referrers API with the tag-schema fallback, Docker config static auths, credentials never across a redirect, and `SOCAIR_EGRESS=deny`. `registrytest` is the in-process registry the tests use.

### API

- `internal/api` (`docs/api.md`) is stateless and has no auth. `POST /api/scan` returns the document, and `POST /api/render` takes it back and returns HTML/PDF bytes.
- It binds to loopback by default, and a non-loopback bind is refused unless `SOCAIR_API_ALLOW_PUBLIC=1`.
- A path a request names (scan, ingest's `local`, promote's `artifact`) is read only under a scan root (`--scan-root`/`SOCAIR_SCAN_ROOTS`, plus the store's `incoming/`), as written and with its symlinks resolved, and every refusal reads the same whether or not the path exists (`internal/api/roots.go`). With no root, every path is refused. A new route that takes a path goes through `Options.contain`.
- With `--web`, it serves the static wizard at `/` through an `os.Root`, with an SPA fallback that never shadows `/api`.

### Kubernetes

- One pod (`charts/socair`, `Dockerfile`, `docs/kubernetes.md`) runs `socair serve --store` with the store on a kept PVC and scan snapshots on a scratch volume.
- The image copies the release binaries from `scripts/build-release.sh` (it compiles no Go) plus the wizard build, on distroless as uid 65532.
- Because the API has no authentication, the chart binds it to the pod's loopback with no Service (operators use `kubectl port-forward`, so RBAC is the gate), probes with `socair health`, and fails the install if `service.enabled` lacks `service.authenticatingProxy`.
- A NetworkPolicy denies all traffic unless `pull.enabled` (which also drops `SOCAIR_EGRESS=deny`).
- `scanRoots` become `--scan-root` args (the install fails on `/`). `hub.enabled` (off by default) runs `airlock serve-hub` as a second container with the store mounted read-only, behind a Service for its port, and the NetworkPolicy admits only `hub.ingressFrom`.
- Trust keys can come from ConfigMaps of `*.pub`, LLMKube's format. A tag's release workflow pushes and attests the image and the chart to GHCR.
- Keep the chart's defaults safe: its unit tests pin them.

### Wizard

- `web/` (`docs/wizard.md`) shows only state the engine returned and derives no status, count, or badge of its own.
- NOT_TESTED must never look like a pass. Promotion labels come from `promotion_authorization.state`. A failed scan offers no download.
- Tests cover these rules, so keep them passing.
