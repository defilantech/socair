# Roadmap

Socair produces a signed, fileable attestation for an open-weight model
before it is served on-prem or air-gapped: what was checked in this exact
artifact, what was found, and what was not tested. The roadmap moves in two
directions. One makes that verdict enforceable wherever models are served and
fileable against the frameworks auditors use. The other widens what the checks
can see, without ever claiming more than they inspected.

## How this roadmap works

GitHub [milestones](https://github.com/defilantech/socair/milestones) and
issues are the source of truth; this page summarizes them. The order within a
section is the order we expect to work in, not a promise of dates. To work on
something, comment on its issue first ([CONTRIBUTING.md](CONTRIBUTING.md)).

## Next: enforce and file anywhere

Milestone [M9](https://github.com/defilantech/socair/milestone/11), in order:

1. **Framework mappings auditors can file**
   ([#197](https://github.com/defilantech/socair/issues/197)). Current MITRE
   ATLAS IDs in every report, and a published mapping of which report rows
   are evidence for which control (NIST SP 800-218A, NIST AI 600-1, ISO/IEC
   42001, OWASP LLM03, and others), each marked full or partial.
2. **A complete CycloneDX BOM**
   ([#198](https://github.com/defilantech/socair/issues/198)): license,
   package URL, supplier, authors, dependencies, and the tokenizer as a model
   input, to the G7 "SBOM for AI" minimum elements, and signable.
3. **NVIDIA NGC signatures out of the box**
   ([#199](https://github.com/defilantech/socair/issues/199)), and the
   OpenSSF model-signing conformance suite in CI.
4. **An admission gate for any serving stack**
   ([#200](https://github.com/defilantech/socair/issues/200)): Kyverno and
   Sigstore policy-controller policies that refuse a KServe, vLLM, NIM, or
   plain pod unless its model's attestation authorizes promotion. It needs
   attestations attached to OCI model artifacts first
   ([#74](https://github.com/defilantech/socair/issues/74)).
5. **The clean store as a read-only download endpoint**
   ([#201](https://github.com/defilantech/socair/issues/201)), Hugging Face
   API-compatible and OCI, so serving stacks can fetch only promoted bytes.
6. **An intake policy that can only withhold**
   ([#202](https://github.com/defilantech/socair/issues/202)): allowed
   formats, publisher allow and block lists, and required signatures.
7. **Re-checking the clean store**
   ([#203](https://github.com/defilantech/socair/issues/203)) when a new
   signed feed or check set arrives.
8. **A GitHub Action**
   ([#204](https://github.com/defilantech/socair/issues/204)): scan, upload
   SARIF, and gate on the promotion state, released on immutable tags.
9. **Converting a tensors-only pickle to safetensors** in the airlock
   ([#205](https://github.com/defilantech/socair/issues/205)), without
   unpickling it, with the derivation attested.

## Also open: static checks and the airlock

- **Attestations on OCI model artifacts**
  ([#74](https://github.com/defilantech/socair/issues/74)): attached to
  ModelPack, KitOps, and ModelCar artifacts as OCI referrers.
- **Sigstore signing** for Socair's own attestations
  ([#86](https://github.com/defilantech/socair/issues/86)), with a private
  Sigstore or public keyless, beside today's offline keys, which stay the
  default.
- **Ollama models** ([#76](https://github.com/defilantech/socair/issues/76)):
  resolve a model from its manifest and blobs and scan its template layer.
- **Internal LEAD review**
  ([#158](https://github.com/defilantech/socair/issues/158)): an organization
  clears a LEAD with a signed review by a named person. It shows as a
  condition, never as a PASS.
- **A community reference feed**
  ([#159](https://github.com/defilantech/socair/issues/159)): open known-bad
  hashes, canonical chat templates, and tokenizers, each entry with its
  source.
- **Weight-level analysis:** reading tensor data and dequantizing GGUF, then
  checking a model's lineage against a signed feed
  ([#162](https://github.com/defilantech/socair/issues/162)); an exact diff
  against the base model to check claims such as "adapter-only"
  ([#163](https://github.com/defilantech/socair/issues/163)); and fully
  validated payload structures hidden in tensor bytes
  ([#164](https://github.com/defilantech/socair/issues/164)).
- **More formats** ([#165](https://github.com/defilantech/socair/issues/165)):
  Keras, ONNX, config-as-code, joblib, TensorFlow SavedModel, and others.
- **Reader hardening** against the bug classes other model loaders have had
  CVEs for ([#166](https://github.com/defilantech/socair/issues/166)).
- **Windows release binaries**
  ([#191](https://github.com/defilantech/socair/issues/191)).

## Tier 2: checks that run the model

Milestone [M8](https://github.com/defilantech/socair/milestone/8). Tier 2 is
opt-in: a probe helper runs the model on your own GPUs and records
measurements in the report. A measurement can raise a LEAD, or a FAIL on
deterministic evidence, which withholds promotion. It can never authorize
promotion, and finding nothing is not a PASS. See [docs/tier2.md](docs/tier2.md).

- **Quantization differential**
  ([#155](https://github.com/defilantech/socair/issues/155)): the format a
  site serves (FP8, NVFP4, GGUF k-quants, and others) against full precision.
- **Refusal regression**
  ([#156](https://github.com/defilantech/socair/issues/156)): safety refusals
  against the model's declared lineage, so a model whose refusals were
  removed is visible.
- **Behavioral suites as measurements**
  ([#157](https://github.com/defilantech/socair/issues/157)):
  lm-evaluation-harness, Inspect, and garak.
- **A hostile sandbox** for Tier 2 runs
  ([#18](https://github.com/defilantech/socair/issues/18)), an experimental
  backdoor scanner that can only raise LEADs
  ([#19](https://github.com/defilantech/socair/issues/19)), and a
  serving-stack differential
  ([#20](https://github.com/defilantech/socair/issues/20)).

## Not planned

- **Scanning agent skills, MCP servers, or other agent artifacts.** Socair
  checks model artifacts.
- **A hosted service or a paid edition** ([GOVERNANCE.md](GOVERNANCE.md)).
- **Saying a model is free of backdoors.** Socair reports what it inspected
  and lists what it cannot see in its
  [detection ceiling](docs/detection-ceiling.json).
