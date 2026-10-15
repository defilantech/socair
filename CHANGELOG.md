# Changelog

Each release adds an entry here. The release's page on
[GitHub Releases](https://github.com/defilantech/socair/releases) has the full
notes, install and verification commands, and the assets.

From 0.1.0-rc.5 on, release-please writes each entry from the conventional
titles of the pull requests merged since the last release (docs/releasing.md).

## [0.1.0-rc.5](https://github.com/defilantech/socair/compare/v0.1.0-rc.4...v0.1.0-rc.5) (2026-10-15)


### Features

* **checks:** a check whose input was not supplied is named, not run: known-bad needs your list, chat template needs a template ([#280](https://github.com/defilantech/socair/issues/280)) ([b13ac3b](https://github.com/defilantech/socair/commit/b13ac3b4665ea10e0910528554658d762ce4edff))
* **checks:** compare an uploader's SHA256SUMS and .sha256 lists with the bytes scanned ([#276](https://github.com/defilantech/socair/issues/276)) ([e0df1d1](https://github.com/defilantech/socair/commit/e0df1d17fee71a975d5c1c2129e02607f5d156bb))
* **checks:** read Keras models: HDF5 layout, .keras members, and code in the config ([#278](https://github.com/defilantech/socair/issues/278)) ([6c1b5e8](https://github.com/defilantech/socair/commit/6c1b5e82c7e55991cd77af894a14846d72d8cbcc))
* **checks:** read ONNX models: tensors, external data, operator domains, and metadata ([#266](https://github.com/defilantech/socair/issues/266)) ([09267c7](https://github.com/defilantech/socair/commit/09267c7f88c3b76e449efb19c27a99395a327d67))
* **checks:** read OpenVINO IR models: Const ranges in the .bin, operations, and rt_info text ([#277](https://github.com/defilantech/socair/issues/277)) ([c3c747a](https://github.com/defilantech/socair/commit/c3c747a6c34cb44dab3cf5246ec41600be5bb75b))
* **cli:** socair scan says what would close each gap; the docs say to pull only what you serve ([#272](https://github.com/defilantech/socair/issues/272)) ([f866a00](https://github.com/defilantech/socair/commit/f866a003857a3f55871d23b1fe948adefe95e062))
* **tensors:** compare a model's weights with a reviewed model, tensor by tensor ([#265](https://github.com/defilantech/socair/issues/265)) ([4923cb5](https://github.com/defilantech/socair/commit/4923cb589eee5ca75e5b646be30b965cb14f65e8))


### Fixes

* **airlock:** a staged scan with a FAIL or LEAD is blocked, not offered for signing ([#273](https://github.com/defilantech/socair/issues/273)) ([e0826af](https://github.com/defilantech/socair/commit/e0826afa370cf2d2322ec20e4766ff8fbbbc28d7))
* **checks:** configs a Python loader reads are decoded as Python's json decodes them ([#274](https://github.com/defilantech/socair/issues/274)) ([c215f09](https://github.com/defilantech/socair/commit/c215f09bad7459d2dde271f374f243d3166f3330))
* **cli:** every command refuses a flag it does not take ([#275](https://github.com/defilantech/socair/issues/275)) ([ff18a78](https://github.com/defilantech/socair/commit/ff18a7804b0891c9440666567e073cd3896ff0d8))
* **engine:** write an empty fails or not_tested list as [], as the report schema says ([#279](https://github.com/defilantech/socair/issues/279)) ([5b77c42](https://github.com/defilantech/socair/commit/5b77c42beb50f3cf911af3264f0c6d269f95d19f))
* **inventory:** a directory's listing is graded once, not with every file ([#270](https://github.com/defilantech/socair/issues/270)) ([1d4f3df](https://github.com/defilantech/socair/commit/1d4f3dfdf0dc0a436f0f89ccc98f5837e8fafa28))
* **release:** a rebuild from a tag stamps the tag's version, whatever the module cache holds ([#271](https://github.com/defilantech/socair/issues/271)) ([69d9577](https://github.com/defilantech/socair/commit/69d95779de0871d1e06cda831d51798acebf3f90))

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
