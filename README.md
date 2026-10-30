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
  <a href="https://github.com/defilantech/socair/releases"><img alt="Release" src="https://img.shields.io/github/v/release/defilantech/socair?include_prereleases&label=release"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/defilantech/socair"><img alt="OpenSSF Scorecard" src="https://api.scorecard.dev/projects/github.com/defilantech/socair/badge"></a>
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-1F9E80"></a>
</p>

---

Socair inspects a model artifact (a GGUF file, safetensors, a pickle checkpoint,
an ONNX model, an OpenVINO IR, a Keras model, or a whole Hugging Face model directory) and produces an **attestation**: a
graded report a CISO or Head of AI Ops can file, signed so anyone can verify it
offline. The report answers one question: *what was checked in this exact
artifact, what was found, and what was not tested?* It checks the file, not the
model's behavior: see what each result means, and the detection ceiling, below.

*Socair* (SUH-ker) is Irish for "at ease, settled, secure".

## What it checks

Each check returns **PASS**, **FAIL**, **LEAD**, or **NOT_TESTED**:

- **FAIL** needs positive evidence.
- **LEAD** is a suspicious but inconclusive signal that needs a person's
  review outside Socair.
- **NOT_TESTED** is an honest gap, with the reason named.

A FAIL or a LEAD withholds promotion; no acceptance clears it, and Socair has
no other path that does. A NOT_TESTED row withholds promotion until the input
it needs is supplied and it passes, or a named person signs an acceptance of
that gap. Nothing passes silently.

| Check | Looks for |
|---|---|
| Format and structure | Malformed containers; tensor data that does not tile the file exactly (where payloads hide); shard indexes that disagree with their shards; ONNX tensors whose data does not match their shape, external data that leaves the model's directory, and operators from outside ONNX and onnxruntime; OpenVINO IR constants whose size does not match their type and shape, bytes of the `.bin` no constant reads, and operations from outside OpenVINO's opsets; Keras configs that carry Python bytecode or name code from outside Keras, and HDF5 data outside its file |
| File inventory and payloads | Embedded scripts, binaries, or archives in metadata; native executables in a model directory |
| Chat template | Template code that reaches Python internals; instructions that trigger on message content; hidden or obfuscated text; override and concealment language. Renders the template with Socair's own evaluator and lists the text it adds to the prompt; compares it with reviewed templates when their text is supplied |
| Tokenizer config | Special-token ids that name no token; tables that disagree; control tokens carrying instructions; normalizers that rewrite input into control tokens |
| Quant match | A file named for a quantization that holds none of its tensors |
| Pickle opcode scan | Code execution reachable from a pickle checkpoint or a NumPy object array. A PASS means every pickle conforms to a typed grammar: it builds only tensors and plain containers, with each call's arguments checked and each storage matched to its record |
| Remote code | Python a loader would import from the repository: modules a config names (`auto_map`, `custom_pipelines`, sentence-transformers and diffusers modules), files loaders import by their path, and what those import |
| Hash, provenance, lineage | An origin bound to this exact hash at an immutable commit, or a verified publisher signature (OpenSSF Model Signing) |
| Known-bad hash match | The artifact, or any file in it, on a known-bad list |
| License policy (opt-in) | A license outside the allowed list you configure (`SOCAIR_LICENSE_POLICY`); without one, the report still names the license the artifact states and any disagreement between its model card, LICENSE file, and GGUF metadata |
| Intake policy (opt-in) | Your organization's intake rules (`SOCAIR_INTAKE_POLICY`): a model file in a format you do not allow, identified from its bytes; a publisher not on your allowed list or on your denied list; a publisher whose models must be signed, without a verified signature. It can only withhold |
| Tensor reference (opt-in) | Weights that are not, tensor for tensor, the model you reviewed (`SOCAIR_TENSOR_REFERENCE`, a manifest `socair tensors` writes): a tensor that differs, is added, or is missing, as an edit like PoisonGPT's leaves. Across file formats, or against a quantized type, it says what matched and judges nothing ([docs/tensors.md](docs/tensors.md)) |

Every result is a bounded statement. Socair says what it inspected and lists
what it cannot see in its
[detection ceiling](docs/detection-ceiling.json). It never claims a model is
free of backdoors.

**Tier 2** ([docs/tier2.md](docs/tier2.md)) is opt-in and runs the model on your
own GPUs, through a probe helper, recording what ran, on which node class, and
what it measured. A measurement can raise a LEAD, or a FAIL on deterministic
evidence, which withholds promotion like any other; it can never authorize one,
and finding nothing is not a PASS. Two Tier 2 checks run today: **trigger
confirmation** runs the model with and without the text a chat template's
hidden branch adds, and **refusal regression** compares its refusals with
those of the base model its card declares. The other checks are on the
[roadmap](docs/tier2.md#roadmap).

## Quickstart

### Install a release

With Homebrew, on macOS or Linux:

```
brew install defilantech/tap/socair
```

The formula installs the release's own `socair` binary for your platform,
checked against the release's `SHA256SUMS`, so the binary's attestation
verifies the installed copy:

```
gh attestation verify "$(brew --prefix socair)/bin/socair" --repo defilantech/socair \
  --signer-workflow defilantech/socair/.github/workflows/release.yml
```

Or download a release yourself. Releases are GitHub pre-releases for now. Each
holds `socair` and the optional `socair-sigstore` helper for linux and darwin
on amd64 and arm64, a `SHA256SUMS` file, and a build-provenance attestation
for every binary; releases after v0.1.0-rc.3 also hold an SBOM. Check the
binary before you run it:

<!-- x-release-please-start-version -->
```
V=0.1.0-rc.7
curl -LO https://github.com/defilantech/socair/releases/download/v$V/socair_${V}_linux_amd64
curl -LO https://github.com/defilantech/socair/releases/download/v$V/SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify socair_${V}_linux_amd64 --repo defilantech/socair \
  --signer-workflow defilantech/socair/.github/workflows/release.yml
chmod +x socair_${V}_linux_amd64 && mv socair_${V}_linux_amd64 socair
```
<!-- x-release-please-end -->

Use `darwin` or `arm64` in the file name for the other platforms. The
checksums come from the same release page as the binary, so they catch a
damaged download, not a tampered release; the attestation and a rebuild from
source do that. The macOS builds are not notarized: a binary downloaded with a
browser is quarantined, so after verifying it, clear that with
`xattr -d com.apple.quarantine socair`. See
[verifying a release](docs/verify-release.md).

The release binaries do not include the wizard or the airlock console. Those
are the static web app in `web/`, built with npm from a checkout; see
[docs/wizard.md](docs/wizard.md). To try the console on real models,
`scripts/demo-console.sh` builds it and fills a demo store with one model in
each state.

On Kubernetes, the Helm chart runs the airlock and the wizard from the
release's container image, `ghcr.io/defilantech/socair`, which carries the
same release binaries (`helm repo add socair https://defilantech.github.io/socair`):
see [docs/kubernetes.md](docs/kubernetes.md).

### Build from source

Go 1.27 or later. Dependencies are vendored, so this builds air-gapped.

```
go build -o socair ./cmd/socair
```

### Scan

```
./socair scan model.gguf > report.json                  # the report (JSON)
./socair render model.gguf > report.html                # HTML
./socair render model.gguf --pdf report.pdf             # or --sarif report.sarif, --cyclonedx bom.json
./socair scan ~/.cache/huggingface/hub/models--org--name/snapshots/<commit>   # a whole model directory
```

Expect a first scan of a file on disk to come back **withheld**. With no other
inputs, the provenance row is NOT_TESTED, and for a single file so is the file
inventory, which needs the repository's file listing: Socair did not look, so
it says so. A model pulled through the airlock carries its provenance. A check
that needs an input you did not give (your known-bad list; a chat template,
for a model that ships none) does not run, and the report names it under Out
of scope. `socair scan` prints, on standard error, each row that
did not PASS and what would close it, and
[provenance-bundle.md](docs/provenance-bundle.md) lists the input that moves
each row.

Through the airlock, pull only the files your serving stack loads: a report
covers every file pulled, and a repository's other exports (TensorFlow and
TorchScript files, which Socair does not read, or an OpenVINO tokenizer that
needs an extension library) are gaps in a report about weights you will not
serve ([airlock.md](docs/airlock.md), "Pull only what you serve"):

```
./socair airlock pull --repo org/name --revision <commit> \
  --include '*.safetensors,*.safetensors.index.json,*.json,*.jinja,*.txt,*.model,README.md,LICENSE*'
```

To see a complete report without a model, `./socair demo > sample.html` writes
a fabricated sample report, marked SAMPLE on every page.

Sign and verify:

```
./socair key gen --out operator --issuer "Acme ML Platform"
./socair sign --key operator.key --report report.json   # report.dsse.json
./socair verify report.dsse.json --trusted operator.pub --artifact model.gguf
./socair render --attestation report.dsse.json --trusted operator.pub --artifact model.gguf --pdf report.pdf   # the signed attestation, to file
./socair sign --key operator.key --bom --attestation report.dsse.json   # report.cdx.dsse.json, a signed CycloneDX BOM
```

`socair render <path>` scans again and writes an unsigned draft, marked
UNSIGNED. `--attestation` verifies the envelope as `verify` does and renders
what was signed; `--report report.json` renders a saved report without
scanning again, still unsigned.

For a model packaged as an OCI artifact, bind the attestation to it in the
registry and check it there ([docs/oci.md](docs/oci.md)):

```
./socair attach registry.example/models/tiny:q4 --attestation report.dsse.json --key operator.key --trusted operator.pub
./socair verify registry.example/models/tiny:q4 --trusted operator.pub
```

A cluster running Kyverno can then refuse a pod that names a model artifact
without a binding from your key in a promotion state you accept, with the
policies in [policies/kyverno](policies/kyverno);
[docs/admission.md](docs/admission.md) says which pod fields they read and
what they do not check.

## The trust model

- **Attestations.** The report is signed as an in-toto Statement v1 in a DSSE
  envelope, with Ed25519, and verifies offline. The issuer is whoever signs. A
  verifier confirms the issuer against its own trust list.
- **The airlock** ([docs/airlock.md](docs/airlock.md)). A content-addressed
  store with a staging area and a clean area:
  - Only an attestation from a trusted key that authorizes promotion moves an
    artifact into clean.
  - The bytes are hashed while they cross.
  - `pull` fetches one file pinned by its expected SHA-256, or a whole
    repository at a pinned commit with every file checked against the hub's
    own hashes (SHA-256 for LFS files, the git blob id for small ones).
  - The activity log is hash-chained; record its head off the box to detect
    a rewrite.
- **Signed acceptances**
  ([docs/provenance-bundle.md](docs/provenance-bundle.md)). Untested surfaces
  cross only when a named acceptor signs for exactly those surfaces of exactly
  the report they reviewed, with an expiry. The acceptor's key is separate from
  the operator's.
- **Publisher signatures.** Socair verifies
  [OpenSSF Model Signing](https://github.com/sigstore/model-transparency)
  signatures made with a key or a certificate. Keyless Sigstore signatures go
  to the optional [`socair-sigstore`](tools/socair-sigstore/README.md) helper.
- **Your organization's reference feed** ([docs/feed.md](docs/feed.md)). Your
  known-bad hashes, the chat templates your reviewers have read, and the
  tokenizers of models you approved, signed once by your security team and
  verified by every intake host, air-gapped or not. A feed that does not verify
  stops the scan. The Socair project publishes no feed: whoever signs is the
  issuer.
- **Kubernetes.** [LLMKube](https://github.com/defilantech/LLMKube) is adding
  an admission gate that refuses to serve a model without an admitted Socair
  attestation. The verifier it uses is the small, dependency-free
  [`socair-verify`](https://github.com/defilantech/socair-verify) module.

## Open source

Socair is open source under the Apache License 2.0, all of it: the engine and
every check, the report format, signing and verification, the airlock, signed
acceptances and feeds, the wizard and console, and the integrations. It is
free, and every check stays here. The work still to come, including checks
that run the model on your own GPUs, is built here in the open.

## Documentation

| | |
|---|---|
| [attestation-template.md](docs/attestation-template.md) | The attestation, section by section: the source of truth for what a report contains |
| [report-schema/v1.json](docs/report-schema/v1.json) | The report's JSON schema |
| [control-mapping.md](docs/control-mapping.md) | Which rows and features are evidence for which framework controls (MITRE ATLAS, OWASP LLM, NIST, AI supply-chain guidance), full or partial, and why |
| [tier2.md](docs/tier2.md) | Tier 2, opt-in: measurements made by running the model, the node-class record, the probe-helper protocol, isolation, and the roadmap |
| [airlock.md](docs/airlock.md) | The airlock: pull, ingest, promote, the trust policy, the log, the signed inventory export |
| [onnx.md](docs/onnx.md) | ONNX models: what the structure and inventory rows read, external data, operator domains, and what is not covered |
| [openvino.md](docs/openvino.md) | OpenVINO IR models: what the structure and inventory rows read of the `.xml` and its `.bin`, operations and extensions, the pickle row, and what is not covered |
| [keras.md](docs/keras.md) | Keras models (`.h5`, `tf_model.h5`, `.keras`): the HDF5 reader, the layout and archive rules, code in the config, and what is not covered |
| [oci.md](docs/oci.md) | Attestations on OCI model artifacts: attach and verify, the binding to the manifest digest, which layouts are matched, cosign and Kyverno |
| [admission.md](docs/admission.md) | Kyverno policies that refuse a model pod without an authorized binding: what they check and what they do not, KServe, image volumes, the policy-controller gap |
| [intake-host.md](docs/intake-host.md) | Running Socair as the model intake host for an on-prem GPU cluster |
| [preview.md](docs/preview.md) | The browser preview at socair.ai/try: the checks on a Hugging Face model's headers before you download it, and what a preview is not |
| [kubernetes.md](docs/kubernetes.md) | The Helm chart: the airlock and the wizard in a cluster, who can reach them, and handing promoted models to LLMKube |
| [provenance-bundle.md](docs/provenance-bundle.md) | The inputs that move each row: mirrors, denylists, provenance, signatures, a license policy, acceptances |
| [intake-policy.md](docs/intake-policy.md) | An intake policy that can only withhold: allowed formats, publisher allow and deny lists, required publisher signatures |
| [feed.md](docs/feed.md) | Signed reference feeds: format, verification, building one |
| [cyclonedx.md](docs/cyclonedx.md) | The CycloneDX ML-BOM: what each field holds and when it is left out, the G7 SBOM for AI minimum elements, and signing a BOM |
| [sarif.md](docs/sarif.md) | The SARIF log for code-scanning tools: what each result holds, how a finding's fingerprint is computed, and uploading to GitHub code scanning |
| [api.md](docs/api.md), [wizard.md](docs/wizard.md) | The local HTTP API, the click-through wizard, and the airlock console (wizard.md) |
| [threat-model.md](docs/threat-model.md) | What Socair protects, whom it trusts for what, and what it does not defend against |
| [false-positive-baseline.md](docs/false-positive-baseline.md) | How each detector was measured against real models |
| [detection-benchmark.md](docs/detection-benchmark.md) | Detection on reproductions of published attacks, misses pinned, beside picklescan, ModelScan, ModelAudit, and Fickling |
| [dev.md](docs/dev.md), [CONTRIBUTING.md](CONTRIBUTING.md) | Building, testing, and contributing (DCO sign-off) |
| [releasing.md](docs/releasing.md), [verify-release.md](docs/verify-release.md) | Cutting and verifying a release |
| [ROADMAP.md](ROADMAP.md), [CHANGELOG.md](CHANGELOG.md) | What is planned and not planned, and what each release changed |
| [GOVERNANCE.md](GOVERNANCE.md), [MAINTAINERS.md](MAINTAINERS.md) | Who decides, how the contract changes, and the project's commitments |
| [SUPPORT.md](SUPPORT.md), [TRADEMARKS.md](TRADEMARKS.md) | Where to ask questions and report problems; using the Socair name |

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

Apache License 2.0. "Socair" and the Socair logo are trademarks of Defilan
Technologies; see [TRADEMARKS.md](TRADEMARKS.md).
