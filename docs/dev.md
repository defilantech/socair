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
- `internal/modeldir`: reads a model directory as one artifact (walk, snapshot, manifest digest, chat templates).
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

## Scanning a model directory

`socair scan <dir>` scans a Hugging Face repo checkout or cache snapshot
(`~/.cache/huggingface/hub/models--org--name/snapshots/<commit>`) as one
artifact:

- Every file is snapshotted and hashed. Symlinks to files are followed (a
  cache snapshot is built of them); symlinked directories and tool metadata
  (`.git`, `.cache`, `__pycache__`) are excluded and named in the report.
- The subject is the digest of the canonical manifest:
  `socair.modeldir/v1\n` then `<sha256> <size> <path>\n` per file, sorted by
  path. The report lists every file with its hash and role.
  `socair verify --artifact <dir>` recomputes it and names any file added,
  removed, or changed.
- Each weight file runs the structure, inventory, and pickle checks, merged to
  one row per check: the worst result wins, and every file that did not PASS
  is named. A `*.safetensors.index.json` must agree exactly with its shards.
- The chat template comes from `tokenizer_config.json`, `chat_template.json`,
  and any `.jinja` file.
- **Remote code** is a LEAD when any config carries `auto_map` or the
  directory holds a `.py` file: code `trust_remote_code` would run.
- The tokenizer is inspected from `tokenizer.json`, `tokenizer_config.json`,
  `special_tokens_map.json`, and the special-token ids in `config.json` and
  `generation_config.json` (`tokenizer.InspectHF`): inconsistent tables FAIL,
  injected text LEADs, and a repo with no `tokenizer.json` is NOT_TESTED.
  `artifact.tokenizer_hash` is the SHA-256 of `tokenizer.json`.
- An adapter (`adapter_config.json`) names its base model as a separate
  artifact that needs its own attestation.
- `airlock pull --repo` (pinned to a commit or digest) stages a whole repo,
  verified file by file against the hub's hashes, and `airlock promote` carries
  a directory into `clean/<digest>/<name>/` (see `docs/airlock.md`).

## Rules

- Tests are hermetic. No network, no secrets, no model files required. A check is proven with generated fixtures. The airlock tests stand an `httptest` server in for the hub and a temp directory in for the store.
- A test that needs a real model is gated by an environment variable and skipped by default. See `internal/gguf/integration_test.go` and the egress test in `internal/airlock/integration_test.go`.
- The report data model in `internal/report` and `docs/report-schema/v1.json` is the contract. No component may invent a divergent report shape.
- Every check carries a falsification: a test that fails if the detector is neutered. See each package's `_test.go`.
- A change to the rules (the check packages, or the GGUF and safetensors parsers) needs a row in `docs/check-set.md`, and a version bump if it can alter a verdict. `TestCheckSetVersionTracksRules` enforces it.
