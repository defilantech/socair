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
- `internal/report`: the report data model, the cross-stack contract.
- `internal/checks/...`: one package per check. Each returns PASS, FAIL, or NOT_TESTED with evidence.
- `docs/`: the product artifacts (attestation template, brand, stack) and design docs.
- `testdata/`: golden files. GGUF fixtures are generated in tests, not committed, so they cannot rot silently.

## Rules

- Tests are hermetic. No network, no secrets, no model files required. A check is proven with generated fixtures.
- A test that needs a real model is gated by an environment variable and skipped by default. See `internal/gguf/integration_test.go`.
- The report data model in `internal/report` and `docs/report-schema/v1.json` is the contract. No component may invent a divergent report shape.
- Every check carries a falsification: a test that fails if the detector is neutered. See each package's `_test.go`.
