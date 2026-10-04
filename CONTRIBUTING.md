# Contributing to Socair

Thank you for helping make local models trustworthy. Socair is open source
under the Apache License 2.0 and maintained by Defilan Technologies.

## Before you start

- **Security issues** go through private reporting, never a public issue: see
  [SECURITY.md](SECURITY.md).
- For anything larger than a small fix, open an issue first so we can agree on
  the approach.

## Sign off your commits (DCO)

Every commit must carry a Developer Certificate of Origin sign-off, certifying
you wrote the change or have the right to submit it under the project's
license (<https://developercertificate.org/>):

```
git commit -s -m "Describe the change"
```

This adds `Signed-off-by: Your Name <you@example.com>`. We do not ask for a
contributor license agreement.

## Build and test

The Go build is air-gapped: dependencies are vendored and nothing is fetched.

```
go build ./...
go vet ./...
go test -race ./...
gofmt -l cmd internal          # must print nothing
```

The wizard (`web/`): `npm ci && npm run check && npm run test`. The optional
keyless verifier is its own module: `cd tools/socair-sigstore && go test ./...`.
CI also runs staticcheck, govulncheck, a vendor-drift check, and short fuzzing.

## The rules a change is held to

Socair's output is a statement a security team files, so a few rules are not
negotiable:

- **Never pass silently, never guess a failure.** A check returns PASS only
  when it inspected what it names, FAIL only with positive evidence, LEAD for a
  suspicious but inconclusive signal, and NOT_TESTED with a named reason for
  anything else.
- **Every check needs a falsification test**: a test that fails if the
  detector is disabled or neutered.
- **Measure false positives before changing a detector.** Run the relevant
  real-corpus gate (`SOCAIR_TEMPLATE_CORPUS`, `SOCAIR_SAFETENSORS_CORPUS`,
  `SOCAIR_GGUF_CORPUS`, `SOCAIR_TOKENIZER_CORPUS`) and record the result in
  `docs/false-positive-baseline.md`.
- **A rule change bumps the check-set version.** If a change can alter a
  verdict, bump `CheckSetVersion` and add a row to `docs/check-set.md`; a test
  fails until you do. See that file for when a change keeps the version.
- **Tests are hermetic**: no network, secrets, or model files. Fixtures are
  generated in code.
- **The report format is a contract** (`docs/report-schema/v1.json`): a shape
  change touches the Go model, the schema, the TypeScript types, and the golden
  report together.

`CLAUDE.md` describes the architecture in more depth.

## What belongs in this repository

This repository is the complete, open Socair: the engine and checks, the report
format, signing and verification, the airlock, and the integrations. Defilan's
commercial offerings (a curated intelligence feed, Defilan-issued attestations,
Tier 2 testing, and Socair Enterprise) are built on top of it, not inside it.
Open interfaces such as the feed format are here, so anyone can build on them.

## Code of conduct

Everyone taking part is expected to follow the
[Code of Conduct](CODE_OF_CONDUCT.md).
