<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/brand/socair-logo-dark.svg">
    <img alt="Socair" src="docs/brand/socair-logo.svg" width="360">
  </picture>
</p>

<p align="center">
  <strong>Signed assurance for open-weight AI models, before they are served on-prem or air-gapped.</strong>
</p>

<p align="center">
  <a href="https://github.com/defilantech/socair/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/defilantech/socair/actions/workflows/ci.yml/badge.svg"></a>
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-1F9E80"></a>
</p>

---

Socair inspects a model artifact (a GGUF file, safetensors, a pickle checkpoint,
or a whole Hugging Face model directory) and produces an **attestation**: a
graded report a CISO or Head of AI Ops can file, signed so anyone can verify it
offline. The report answers one question: *what was checked in this exact
artifact, what was found, and what was not tested?* It checks the file, not the
model's behavior: see what each result means, and the detection ceiling, below.

*Socair* (SUH-ker) is Irish for "at ease, settled, secure".

## What it checks

Each check returns **PASS**, **FAIL**, **LEAD**, or **NOT_TESTED**:

- **FAIL** needs positive evidence.
- **LEAD** is a suspicious but inconclusive signal. Only escalated review
  clears it.
- **NOT_TESTED** is an honest gap, with the reason named.

Nothing passes silently.

| Check | Looks for |
|---|---|
| Format and structure | Malformed containers; tensor data that does not tile the file exactly (where payloads hide); shard indexes that disagree with their shards |
| File inventory and payloads | Embedded scripts, binaries, or archives in metadata; native executables in a model directory |
| Chat template | Template code that reaches Python internals; instructions that trigger on message content; hidden or obfuscated text; override and concealment language |
| Tokenizer config | Special-token ids that name no token; tables that disagree; control tokens carrying instructions; normalizers that rewrite input into control tokens |
| Quant match | A file named for a quantization that holds none of its tensors |
| Pickle opcode scan | Code execution reachable from a pickle checkpoint |
| Remote code | Code a loader would run with `trust_remote_code` (`auto_map`, `.py` files) |
| Hash, provenance, lineage | An origin bound to this exact hash at an immutable commit, or a verified publisher signature (OpenSSF Model Signing) |
| Known-bad hash match | The artifact, or any file in it, on a known-bad list |

Every result is a bounded statement. Socair says what it inspected and lists
what it cannot see in its
[detection ceiling](docs/detection-ceiling.json). It never claims a model is
free of backdoors.

## Quickstart

Go 1.27 or later. Dependencies are vendored, so this builds air-gapped.

```
go build -o socair ./cmd/socair

socair scan model.gguf > report.json                  # the report (JSON)
socair render model.gguf > report.html                # HTML; --pdf, --sarif, --cyclonedx too
socair scan ~/.cache/huggingface/hub/models--org--name/snapshots/<commit>   # a whole model directory
```

Sign and verify:

```
socair key gen --out operator --issuer "Acme ML Platform"
socair sign --key operator.key --report report.json   # report.dsse.json
socair verify report.dsse.json --trusted operator.pub --artifact model.gguf
```

Releases are built reproducibly, with checksums and build provenance; see
[verifying a release](docs/verify-release.md).

## The trust model

- **Attestations.** The report is signed as an in-toto Statement v1 in a DSSE
  envelope, with Ed25519, and verifies offline. The issuer is whoever signs. A
  verifier confirms the issuer against its own trust list.
- **The airlock** ([docs/airlock.md](docs/airlock.md)). A content-addressed
  store with a staging area and a clean area:
  - Only an attestation from a trusted key moves an artifact into clean.
  - The bytes are hashed while they cross.
  - `pull` fetches a file or a whole repository at a pinned commit, verifying
    every file against the hub's hashes.
  - The activity log is hash-chained.
- **Signed acceptances**
  ([docs/provenance-bundle.md](docs/provenance-bundle.md)). Untested surfaces
  cross only when a named acceptor signs for exactly those surfaces of exactly
  the report they reviewed, with an expiry. The acceptor's key is separate from
  the operator's.
- **Publisher signatures.** Socair verifies
  [OpenSSF Model Signing](https://github.com/sigstore/model-transparency)
  signatures made with a key or a certificate. Keyless Sigstore signatures go
  to the optional [`socair-sigstore`](tools/socair-sigstore/README.md) helper.
- **Reference feeds** ([docs/feed.md](docs/feed.md)). Known-bad hashes,
  reviewed chat templates, and canonical tokenizers come as a signed bundle for
  air-gapped import. A feed that does not verify stops the scan.
- **Kubernetes.** [LLMKube](https://github.com/defilantech/LLMKube) can refuse
  to serve a model without an admitted Socair attestation. The verifier it
  uses is the small, dependency-free
  [`socair-verify`](https://github.com/defilantech/socair-verify) module.

## Open source and commercial

This repository is the complete, open Socair, under the Apache License 2.0:
the engine and every check, the report format, signing and verification, the
airlock, signed acceptances and feeds, the wizard, and the integrations.

Defilan Technologies is building commercial offerings on top of it:

- a **curated intelligence feed**, maintained and signed for air-gapped import;
- **Defilan-issued attestations**, with analyst review of findings, and a
  catalog of pre-attested popular models;
- **Tier 2 testing**, which exercises models on the hardware they will run on;
- **Socair Enterprise**, for multi-site fleets: a central registry, policy,
  approval workflows, and compliance reporting;
- **support** and hardened builds.

## Documentation

| | |
|---|---|
| [attestation-template.md](docs/attestation-template.md) | The attestation, section by section: the source of truth for what a report contains |
| [report-schema/v1.json](docs/report-schema/v1.json) | The report's JSON schema |
| [airlock.md](docs/airlock.md) | The airlock: pull, ingest, promote, the trust policy, the log, the signed inventory export |
| [intake-host.md](docs/intake-host.md) | Running Socair as the model intake host for an on-prem GPU cluster |
| [provenance-bundle.md](docs/provenance-bundle.md) | The inputs that move each row: mirrors, denylists, provenance, signatures, acceptances |
| [feed.md](docs/feed.md) | Signed reference feeds: format, verification, building one |
| [api.md](docs/api.md), [wizard.md](docs/wizard.md) | The local HTTP API, the click-through wizard, and the airlock console (wizard.md) |
| [false-positive-baseline.md](docs/false-positive-baseline.md) | How each detector was measured against real models |
| [dev.md](docs/dev.md), [CONTRIBUTING.md](CONTRIBUTING.md) | Building, testing, and contributing (DCO sign-off) |
| [releasing.md](docs/releasing.md), [verify-release.md](docs/verify-release.md) | Cutting and verifying a release |

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

Apache License 2.0. "Socair" and the Socair logo are trademarks of Defilan
Technologies.
