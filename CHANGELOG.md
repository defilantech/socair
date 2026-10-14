# Changelog

Each release adds an entry here. The release's page on
[GitHub Releases](https://github.com/defilantech/socair/releases) has the full
notes, install and verification commands, and the assets.

From 0.1.0-rc.5 on, release-please writes each entry from the conventional
titles of the pull requests merged since the last release (docs/releasing.md).

## 0.1.0-rc.4 (2026-10-14)

The second public release candidate. The check set is `tier1/0.9`.

- **Security:** a chat-template trigger written as a tuple
  (`content in ('a', 'b')`) was missed, so such a template PASSed in rc.3
  ([GHSA-c5hh-62j2-rfm7](https://github.com/defilantech/socair/security/advisories/GHSA-c5hh-62j2-rfm7),
  High).
- **Enforcement where models are served:**
  - `socair attach` binds an attestation to an OCI artifact's manifest digest, for raw-file layers and for KServe ModelCar images.
  - A Kyverno admission policy admits only models whose binding verifies.
  - `socair airlock serve-hub` serves admitted models over the Hugging Face Hub API.
- **New tools:**
  - `socair airlock convert` (pickle to safetensors without unpickling, with a signed derivation record);
  - an organization's intake policy;
  - a signed CycloneDX ML-BOM;
  - NGC model signatures;
  - `socair airlock recheck`;
  - feed rollback protection;
  - stable SARIF fingerprints;
  - `socair render --attestation`.
- **False positives fixed on real models:**
  - Remote code is a LEAD only for the Python a loader imports;
  - standard content-part types in chat templates are not triggers;
  - torch checkpoints with new dtypes now PASS.
- **First-run fixes:**
  - PDF punctuation;
  - `--help` no longer acts;
  - conditional reports say "authorized with conditions".
- **Hardening:**
  - Reports carry no host paths.
  - The helpers get no inherited environment.
  - The API reads only under scan roots.
  - All CodeQL alerts are fixed.

rc.3 cannot verify an rc.4 attestation, so upgrade verifiers with or before
scanners. On the [detection benchmark](docs/detection-benchmark.md), Socair
detects 52 of 55 defanged reproductions of published attacks (49 without the
optional reference inputs), with the misses pinned, and flags none of the 8
benign controls.

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
