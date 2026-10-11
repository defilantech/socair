# Changelog

Each release adds an entry here. The release's page on
[GitHub Releases](https://github.com/defilantech/socair/releases) has the full
notes, install and verification commands, and the assets.

## 0.1.0-rc.3 (2026-10-10)

The first public release candidate. It is a pre-release: the report format
(`socair.report/v1`) and the check set (`tier1/0.8`) can still change before
0.1.0.

- **Checks:** format and structure, file inventory and payloads, chat
  template (Jinja analysis, and rendering with Socair's own evaluator),
  tokenizer config, quant match, pickle opcode scan (a typed grammar: a PASS
  means the pickle builds only tensors), remote code, provenance and publisher
  signatures (OpenSSF Model Signing), known-bad hashes, and an opt-in license
  policy. Each returns PASS, FAIL, LEAD, or NOT_TESTED.
- **Attestations:** an in-toto Statement v1 in a DSSE envelope, signed with
  Ed25519 and verified offline. Untested rows cross only with a signed,
  expiring acceptance from a named person. Reference data comes as signed
  feeds.
- **The airlock:** pulls models pinned to a hash or a commit, promotes only
  with a trusted attestation, and keeps a hash-chained log.
- **Reports** as JSON, HTML, PDF, SARIF, and CycloneDX.
- **The wizard and console**, and a **Helm chart and container image** for
  running the airlock on Kubernetes.
- **Tier 2 foundation:** the report section and the probe-helper protocol for
  checks that run the model on your own GPUs.
- **Distribution:** Homebrew (`brew install defilantech/tap/socair`), a Helm
  repository, and the image and chart on GHCR. Every binary, the chart, and
  the image carry a build-provenance attestation, and builds are reproducible
  from the tag.

On the [detection benchmark](docs/detection-benchmark.md), Socair detects 44
of 46 defanged reproductions of published attacks (41 without the optional
reference inputs), with the misses pinned, and flags none of the 6 benign
controls.

v0.1.0-rc.2 was tagged but never released: its chart step failed, and release
tags cannot be moved, so the fix ships in rc.3.
