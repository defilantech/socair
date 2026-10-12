# CycloneDX ML-BOM

Socair renders every report as a CycloneDX 1.6 machine-learning BOM
(`internal/render/cyclonedx`). The BOM is derived from the report and says
nothing the report does not: a field the report does not know is left out,
never filled with a guess.

```
socair scan model.gguf --format cyclonedx > bom.json        # scan, print the BOM
socair render model.gguf --cyclonedx bom.json               # scan, write the BOM
```

`POST /api/render` with `"format": "cyclonedx"` returns the same BOM for a
report document ([api.md](api.md)). A header-only report names no exact bytes and
has no BOM.

## What the BOM says

The subject (`metadata.component`) is the model, a `machine-learning-model`.
Its components are the files the report attested: the one file of a
single-file report, or every file of a model directory, each with its SHA-256,
size, and role. The model's hash is the file's SHA-256, or for a directory the
manifest digest over its files (`internal/modeldir`).

| Field | Holds | Left out when |
|---|---|---|
| `metadata.authors` | The report's issuer: whoever signed it. An unsigned report's BOM says `Unsigned: no issuer has signed this report`. | Never. |
| `metadata.tools` | `socair` and its version, from the report. | The version, when the report records none. |
| `metadata.lifecycles` | `post-build`: Socair reads a built artifact's bytes. | Never. |
| `version`, `purl` | The pinned commit, and `pkg:huggingface/<account>/<repo>@<commit>` with the commit in lower case, per the Package URL `huggingface` type. | The report records no `https://huggingface.co/<account>/<repo>` origin, or its commit is not a 40 or 64 hex commit id (a branch or tag). A mirror's URL does not show it serves the hub's repositories, so it gets neither. |
| `supplier` | The hub account the repository belongs to. It supplied the bytes; it may not have trained the model. | No huggingface.co origin. |
| `manufacturer` | Never filled: the report does not know who trained the model. | Always. |
| `publisher` | The publisher as the report records it (a provenance manifest, or a verified publisher signature's signer). | The report records none. |
| `licenses` | The license the artifact states, `declared`, by SPDX id when the SPDX list bundled with the CycloneDX 1.6 schema has it, else by name; `socair:license_id` keeps the report's catalogue id. | The report identifies no license, or its statements disagree. A disagreement is stated in `socair:license_disagreement`, never resolved. |
| `socair:license_source` | Each statement the scan read (model card, LICENSE file, GGUF `general.license`, a declared base model's publisher license), and what it named. | The report read none. |
| `pedigree.ancestors` | The base models the artifact declares, with where each is declared. The pedigree notes say they are claims, not verified lineage. | The artifact declares none. |
| `modelCard` | `modelParameters.modelArchitecture`, and as properties the declared and observed quantization and the hashes of what prepares the model's input: `socair:input:tokenizer_sha256` (for a GGUF, of the vocabulary in id order; for a directory, of `tokenizer.json`) and `socair:input:chat_template_sha256`. | Each value the report lacks. `modelParameters.inputs` and `outputs` take only a free-text format, which the report does not know, so they are left out. |
| `externalReferences` | The repository (`vcs`), the report (`static-analysis-report`, by document id and, once signed, document hash), and once signed the attestation (`attestation`). | No repository; an unsigned report has no attestation reference. |
| `dependencies` | The model depends on each attested file. | Never. |
| `compositions` | The completeness of the model's files: `complete` for a model directory, whose report lists every file; `incomplete` for one part of a split file, or for a directory scan that excluded an entry other than tool metadata (a symlinked directory, an unreadable or non-regular file); `unknown` for a single file, which may need files the report never saw. What the model needs beyond its files is always `unknown`. | Never. |
| Properties | Every check row with its status (`socair:check:<row>`), the promotion state, assurance level, check-set version, any acceptance, and the fixed "does not certify" sentence. A NOT_TESTED row reads NOT_TESTED, never as an absence of findings. | Never. |

The serial number is derived from the document, and the timestamp is the
report's issue time, so the BOM is byte-stable for a fixed report. A signed or
re-issued report has a new document hash, and so a new serial number.
`internal/render/cyclonedx/testdata/bom.cdx.json` is the BOM of
`testdata/report.json`; `go test ./internal/render/cyclonedx -run TestGoldenBOM
-update` rewrites it.

## Framework mappings

Each check row's framework entries (`maps_to`, for example MITRE ATLAS
`AML.T0051` or OWASP `LLM01`) travel as CycloneDX Attestations (CDXA), the
part of CycloneDX 1.6 made for relating claims to the requirements of a
standard. It is the format's own place for them, where a property would be a
name only Socair defines; CycloneDX publishes third-party standards such as
NIST SSDF and OWASP ASVS in the same form
([official-3rd-party-standards][cdxa-standards]).

- `definitions.standards`: one standard per framework edition, named and
  versioned as the rows record them (`maps_to[].framework` and `.version`),
  whose requirements are the entries the checks address, by identifier and
  name. Everything is read from the report's rows, never from Socair's current
  mapping table, so an older report keeps the editions it was mapped against;
  a row that records no version gives a standard with none.
- `declarations.claims`: one claim per check row that maps to anything, about
  the model, stating the row's status and what the check looks for.
- `declarations.attestations`: one attestation mapping each requirement to the
  claims of the rows that address it.

No `conformance` or `confidence` is given. A mapping says what a check
inspects, not that the model meets a requirement, and each claim carries its
row's status, so a NOT_TESTED row is mapped as not tested. A consumer that
does not read CDXA ignores both sections. [control-mapping.md](control-mapping.md)
says what each row is evidence for.

## G7 SBOM for AI minimum elements

[Software Bill of Materials for AI – Minimum Elements][g7], by the G7
Cybersecurity Working Group, published on 12 May 2026 jointly by BSI, ACN,
ANSSI, CSE, CISA, NCSC-UK, and Japan's NCO with the European Commission, lists
elements in seven clusters. Its elements "are not mandatory; do not create
requirements, standards, or legislation" (p. 1). Socair describes one model
artifact, not the AI system that serves it, so it fills the Metadata and
Models clusters as far as the report knows them; a system's BOM can include
this one. [control-mapping.md](control-mapping.md) says which report fields
are evidence for the Models elements; this table says where the BOM carries
them.

| Cluster | Element | In the BOM |
|---|---|---|
| Metadata | SBOM author | `metadata.authors`: the report's issuer. |
| | SBOM version | `version` (1) and `serialNumber`, an RFC 4122 UUID. |
| | SBOM data format name, version | `bomFormat` CycloneDX, `specVersion` 1.6. |
| | SBOM author signature | Not yet: the BOM is unsigned. The signed attestation covers the report it is derived from. |
| | SBOM tool name, version | `metadata.tools`: socair and its version. |
| | SBOM generation context | `metadata.lifecycles`: post-build. |
| | SBOM timestamp | `metadata.timestamp`: the report's issue time, RFC 3339. |
| | SBOM dependency relationship | `dependencies` (the model includes its files), `compositions`, and `pedigree.ancestors` for declared base models (derived from). |
| System level properties | All nine | Not filled: they describe an AI system, not a model artifact. |
| Models | Model name | `metadata.component.name`. |
| | Model identifier | The SHA-256 hash, and `purl` at a pinned hub commit. CPE, OmniBOR, and SWHID identifiers are not computed. |
| | Model version | `version`: the pinned commit. Absent when the report has none; CycloneDX has no "unknown" value, so the absence is the statement. |
| | Model timestamp | Not filled: the report does not record when the model was last changed. |
| | Model producer | Partly: `publisher` as the report records it, and `supplier`, the hub account. `manufacturer` is not filled: neither is known to have trained the model. |
| | Model description | Lineage only: declared base models in `pedigree`, marked as claims. No capabilities or limitations; the report has none. |
| | Model hash value, algorithm | `hashes`: SHA-256. |
| | Model properties | `modelParameters.modelArchitecture`, the quantization labels, and the size. The parameter count is not in the report. |
| | Model input-output properties | The tokenizer and chat-template hashes in `modelCard`, as input preprocessing. Modality, data types, and context length are not in the report. |
| | Model training properties | Not filled. |
| | Model license | `licenses`, declared, with each statement read in `socair:license_source`. Whether the model is open weight is not stated. |
| | Model external references | `externalReferences`: the repository, the report, the attestation. |
| Datasets properties | All ten | Not filled: the report holds nothing about training data. |
| Infrastructure | Software, hardware | Not filled: out of scope for a model artifact. |
| Security properties | Security controls, compliance, policy, vulnerability referencing | Not filled. The framework entries the checks address are carried as CDXA claims mapped to requirements, which state no compliance. |
| Key performance indicators | Security metrics | The check results, promotion state, and assurance level, as properties: what the checks found within their scope, not a robustness metric. Tier 2 measurements are not in the BOM. |
| | Operational performance KPIs | Not filled. |

## Why CycloneDX 1.6

CycloneDX 1.7 (October 2025) adds `citations`, which could attribute the
license to the statement it was read from by JSON pointer, plus TLP
distribution constraints, patents, and `isExternal`. It leaves the model
card's structure as it is in 1.6. The tests could validate 1.7 offline as they do 1.6, from
committed schemas. What decides it is what reads the BOM: Dependency-Track
added 1.7 in 5.1.0 (2026-08-27) and backported it to 4.14.4 (2026-09-14), so
earlier releases still in service do not list it as supported;
`cyclonedx-cli` added it in v0.30.0 (2026-02-10), `sbom-utility` in v0.19.0
(2026-05-18), and the OWASP AIBOM Generator writes a 1.6 and a 1.7 BOM side
by side.
Socair stays on 1.6 until 1.7 ingestion is common, and then moves the license
sources to `citations`.

## OWASP AIBOM completeness scoring

The OWASP GenAI Security Project's AIBOM Generator scores completeness from a
field registry. It treats as critical `bomFormat`, `specVersion`,
`serialNumber`, `version`, the model's name, type, and version, the supplier's
name, and `modelCard.modelParameters.task`. Socair always fills the first six;
it fills the model's version and supplier only from a huggingface.co origin
(the version only at a pinned commit), and never the task, which the report
does not know. The scorer reads the model from `components[0]`; Socair describes
the model in `metadata.component`, the BOM's subject as CycloneDX defines it,
and lists its files as the components, so that scorer reads the first file.

## Sources

- G7 Cybersecurity Working Group, [Software Bill of Materials for AI – Minimum
  Elements][g7] (May 2026), from the
  [BSI download page](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/KI/SBOM-for-AI_minimum-elements.html)
  (dated 12.05.2026); also listed by
  [CISA](https://www.cisa.gov/resources-tools/resources/software-bill-materials-ai-minimum-elements).
- CycloneDX 1.6 schema, [CycloneDX/specification](https://github.com/CycloneDX/specification/tree/1.6/schema),
  committed under `internal/render/cyclonedx/testdata/schema`; the 1.7
  release, [1.7](https://github.com/CycloneDX/specification/releases/tag/1.7).
- Package URL [`huggingface` type](https://github.com/package-url/purl-spec/blob/main/types/huggingface-definition.json):
  account as namespace and repository as name, both case sensitive; the commit
  as version, lower case.
- CycloneDX [official third-party standards][cdxa-standards] in CDXA form.
- Releases adding 1.7: Dependency-Track
  [5.1.0](https://github.com/DependencyTrack/dependency-track/releases/tag/5.1.0) and
  [4.14.4](https://github.com/DependencyTrack/dependency-track/releases/tag/4.14.4),
  [cyclonedx-cli v0.30.0](https://github.com/CycloneDX/cyclonedx-cli/releases/tag/v0.30.0),
  [sbom-utility v0.19.0](https://github.com/CycloneDX/sbom-utility/releases/tag/v0.19.0).
- OWASP AIBOM Generator, [field registry](https://github.com/GenAI-Security-Project/aibom-generator/blob/main/src/models/field_registry.json).

[g7]: https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/KI/SBOM-for-AI_minimum-elements.pdf?__blob=publicationFile&v=4
[cdxa-standards]: https://github.com/CycloneDX/official-3rd-party-standards
