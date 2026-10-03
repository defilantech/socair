# Developing Socair

## Build and test

```
go build ./...
go test ./...
```

CI runs gofmt, build, and test on every push (`.github/workflows/ci.yml`).

## Layout

- `cmd/socair`: the CLI. A thin caller of the engine, not the product surface.
- `internal/gguf`: the GGUF artifact reader. Produces an `ArtifactManifest`.
- `internal/airlock`: the controlled junction between egress and the clean store. A pull lands in staging; only a promotion crosses.
- `internal/report`: the report data model, the cross-stack contract.
- `internal/checks/...`: one package per check. Each returns PASS, FAIL, or NOT_TESTED with evidence.
- `docs/`: the product artifacts (attestation template, brand, stack) and design docs.
- `testdata/`: golden files. GGUF fixtures are generated in tests, not committed, so they cannot rot silently.

## Scanning large models

A full scan copies the artifact into a private, read-only snapshot and hashes
it while copying; every check reads the snapshot, so the hash in the
attestation is the hash of the bytes that were checked, even if the original
changes mid-scan. The snapshot needs free space equal to the artifact's size in
the temp directory; set `SOCAIR_SCAN_TMP` to a volume with room. It is removed
when the scan ends.

## Rules

- Tests are hermetic. No network, no secrets, no model files required. A check is proven with generated fixtures. The airlock tests stand an `httptest` server in for the hub and a temp directory in for the store.
- A test that needs a real model is gated by an environment variable and skipped by default. See `internal/gguf/integration_test.go` and the egress test in `internal/airlock/integration_test.go`.
- The report data model in `internal/report` and `docs/report-schema/v1.json` is the contract. No component may invent a divergent report shape.
- Every check carries a falsification: a test that fails if the detector is neutered. See each package's `_test.go`.
