# Control mapping

Which Socair evidence supports which framework control, and how far. An
auditor asks about controls by ID; this page names, for each control, the
report row or Socair feature that is evidence for it, whether that evidence is
full or partial, and why.

**A mapping is a claim about evidence, not about compliance.** Socair evidence
supports a control. It does not make anyone compliant with any framework, and
running Socair is not an audit. The controls below are an organization's
obligations; Socair produces records that an organization's process can cite.

## How to read it

- **Evidence** is a row of the report, by its name in the checks table, or a
  Socair feature: the signed attestation, the airlock, a signed acceptance, or
  the SARIF and CycloneDX outputs. A row is evidence only for what it
  inspected. A NOT_TESTED row is evidence that the check did not run, nothing
  more, and a PASS means what its fixed "PASS means" statement says and no
  more ([attestation-template.md](attestation-template.md)).
- **Full** means the evidence is what the control asks for, for the model
  artifact the report names. Who runs Socair, on what, and what they do with
  the result is still the organization's process.
- **Partial** means the evidence covers part of what the control asks. The
  last column names what it covers and what it leaves to the organization.
- Each framework has one source link. Quotes are single sentences from public
  primary texts, with the page where the text has page numbers. A framework
  whose primary text could not be read is not mapped, and the last section
  says which.
- The report's own rows carry MITRE ATLAS and OWASP LLM IDs (`maps_to`,
  [attestation-template.md](attestation-template.md)). Those name the threat a
  row inspects for. This page goes further, to the controls and mitigations
  the evidence supports.

## MITRE ATLAS 2026.09

Source: the [`atlas-data` release v2026.09](https://github.com/mitre-atlas/atlas-data/releases/tag/v2026.09),
data file `ATLAS-2026.09.yaml` (SHA-256 `935efa93e28294432d3e2f537eb94991ef8d1f8c58341cd360ea3321ddb66688`).
ATLAS data is copyright MITRE and published under the Apache License 2.0.
ATLAS has numbered its monthly content releases by year and month since
2026.05; the `dist/ATLAS.yaml` file in that repository is deprecated and
frozen at 5.6.0, so it is not the source. Every ATLAS ID on this page is
checked against the release's data by `TestDocsCiteThePinnedATLASEdition`
(`internal/report`), from a pruned list of its IDs and names in
`internal/report/testdata/atlas-ids.txt`.

ATLAS techniques are adversary behaviour, not controls. The report's rows
name the techniques they inspect for, and
[attestation-template.md](attestation-template.md) lists them. ATLAS's
controls are its mitigations:

| Mitigation | Socair evidence | Extent | Why |
|---|---|---|---|
| AML.M0014 Verify AI Artifacts | Hash, provenance, lineage; Tensor reference (with a reference); the artifact hash; the airlock's pull and promote | Full when the Hash, provenance, lineage row is PASS; partial otherwise | ATLAS: "Verify the cryptographic checksum of all AI artifacts to verify that the file was not modified by an attacker." The report's SHA-256 is of the exact bytes the checks read. The row passes only when a publisher signature from a key or root the operator trusts, or the operator's provenance manifest, binds that hash to its origin. A repo pull checks each file against the hub's hash at a pinned commit, and promote re-hashes the bytes it moves. Without a trusted reference the hash is recorded but compared with nothing the organization trusts. A checksum list the uploader ships (`SHA256SUMS`) is compared too, but it is the uploader's claim, not a trusted reference: a file that disagrees is a LEAD, and agreement is noted and never what the row passes on. The Tensor reference row checks the weights themselves against a model the organization reviewed, so a converted or re-packed copy whose file hash differs can still be shown to hold the reviewed weights. |
| AML.M0016 Vulnerability Scanning | Pickle opcode scan; File inventory and payloads; Remote code; Chat template; Format and structure | Partial | ATLAS: "These files should be scanned for potentially unsafe calls, which could be used to execute code, create new processes, or establish networking capabilities." The pickle check walks the opcodes without deserializing, so it also reads a pickle a loader would stop on; one it cannot read to the end is a LEAD, not a pass. Not covered: scanning external software dependencies and a model's outputs for known vulnerabilities, which the mitigation also names. |
| AML.M0013 Code Signing | Hash, provenance, lineage (OpenSSF Model Signing verification); the signed attestation; airlock promote | Partial | ATLAS: "Enforce binary and application integrity with digital signature verification to prevent untrusted code from executing." Socair verifies a publisher's model signature against keys and roots the operator supplies, signs its own attestation, and the airlock moves bytes into `clean/` only on an attestation signed by a trusted key. Enforcement at the runtime is outside Socair (LLMKube's admission gate can verify the same envelope), and the mitigation also covers signing the organization's own software and SBOMs. Socair signs only the BOM of a model it attested (`socair sign --bom`). |
| AML.M0023 AI Bill of Materials | The CycloneDX ML-BOM output; the artifact's file list (`artifact.files`) | Partial | ATLAS: "An AI Bill of Materials (AI BOM) contains a full listing of artifacts and resources that were used in building the AI." Socair lists the files of the artifact it attests, each with its hash, and the BOM carries the report's verdicts. It does not know the datasets, code, or other resources the model was built from. |
| AML.M0008 Validate AI Model | Tier 2 measurements (opt-in) | Partial | ATLAS: "Validate that AI models perform as intended by testing for backdoor triggers, potential for data leakage, or adversarial influence." Tier 2 runs the model on trigger probes and records measurements; a measurement can raise a LEAD or FAIL row but is never a pass ([tier2.md](tier2.md)). Tier 1 reads no weights for behaviour, and nothing in Socair monitors a model in production for drift. |

Two ATLAS 2026.07 case studies describe attacks the rows inspect for:

- AML.CS0064 Poisoned GGUF Templates: Inference-Time Supply Chain Attack. A
  chat template in a GGUF file injects instructions when a trigger appears
  (AML.T0018.003). The Chat template row parses and renders the template, and
  a condition on message content that opens a system turn is a LEAD
  ([false-positive-baseline.md](false-positive-baseline.md) records how the
  rule was measured).
- AML.CS0065 Model Namespace Reuse Supply Chain Attack. A reclaimed Hugging
  Face namespace serves a different model under an old name (AML.T0115.001),
  with a payload that runs on load (AML.T0018.002). The airlock pulls a repo
  only at a full commit or expected digest, the Hash, provenance, lineage row
  binds the hash to a repo at an immutable commit, and the Pickle opcode scan
  inspects for code a loader would run. None of these stops an organization
  from pinning the replacement model on purpose.

Reports made before Socair recorded framework editions name AML.T0058
"Publish Poisoned Models" where current ones name AML.T0115.001: ATLAS
2026.07 replaced the first with the second.

## OWASP Top 10 for LLM Applications 2025

Source: [OWASP Top 10 for LLM Applications 2025 (November 2024)](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/),
published by the OWASP GenAI Security Project under CC BY-SA 4.0. Page
numbers are the PDF's printed ones. The rows' `maps_to` name LLM01 and LLM03
with version `2025`. LLM03:2025 Supply Chain lists numbered prevention and
mitigation strategies without titles, so they are cited here by number.

| Entry | Socair evidence | Extent | Why |
|---|---|---|---|
| LLM03:2025 Supply Chain, mitigation 6 | Hash, provenance, lineage | Full when the row is PASS; partial otherwise | "Only use models from verifiable sources and use third-party model integrity checks with signing and file hashes to compensate for the lack of strong model provenance." (p. 13) The row passes only on a publisher signature from a trusted key or root, or a provenance manifest binding the hash to a repo at an immutable commit. The same item's code signing for externally supplied code is not something Socair checks. |
| LLM03:2025 Supply Chain, mitigation 5 | The artifact's identified license; License policy (with a policy) | Partial | "To mitigate AI licensing risks, create an inventory of all types of licenses involved using BOMs and conduct regular audits of all software, tools, and datasets, ensuring compliance and transparency through BOMs." (p. 13) A report identifies the model's license from its card, LICENSE file, and GGUF metadata, and the License policy row holds it to the operator's allowed list. Datasets, tools, and the audits are outside it, and a PASS is not legal advice. |
| LLM03:2025 Supply Chain, mitigation 4 | The CycloneDX ML-BOM output | Partial | "AI BOMs and ML SBOMs are an emerging area and you should evaluate options starting with OWASP CycloneDX" (p. 13). The BOM lists the model and its files with their hashes and carries every check row's status. It is an inventory of the artifact, not of the application's other components. |
| LLM03:2025 Supply Chain, mitigation 3 | Tier 2 measurements (opt-in) | Partial | "Apply comprehensive AI Red Teaming and Evaluations when selecting a third party model." (p. 13) Tier 2 runs fixed probe suites against the model and records measurements. It is not a red-team exercise, and a measurement that finds nothing is not a pass. |
| LLM03:2025 Supply Chain, risk 4, Vulnerable Pre-Trained Model | Pickle opcode scan; File inventory and payloads; Chat template; Tokenizer config; Remote code | Partial | The risk says pre-trained models "can contain hidden biases, backdoors, or other malicious features" (p. 12). Tier 1 inspects the files for code and injected instructions; biases and backdoors in the weights are outside it. |
| LLM01:2025 Prompt Injection | Chat template; Tokenizer config | Partial | A template or tokenizer shipped with the model can inject instructions into every prompt, which the Chat template and Tokenizer config rows inspect for. Prompt injection through user input or retrieved content happens at runtime, outside the artifact. |

A 2026 edition, with Supply Chain renumbered LLM04:2026, was posted on
2026-08-03, but its cover still reads "[Publication date to be set]". Socair
stays on the 2025 edition until the 2026 edition is final.

## NIST SP 800-218A

Source: [NIST SP 800-218A, Secure Software Development Practices for
Generative AI and Dual-Use Foundation Models: An SSDF Community Profile
(July 2024)](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218A.pdf).
The profile keeps the task text of SSDF 1.1 (SP 800-218) unless it marks a
task as changed, and adds AI-specific recommendations (R) and considerations
(C) to each task. SP 800-218 Rev. 1 (SSDF 1.2) was an initial public draft on
2026-10-12 and is not mapped here.

| Task | Socair evidence | Extent | Why |
|---|---|---|---|
| PW.4.4 Verify that acquired commercial, open-source, and all other third-party software components comply with the requirements, as defined by the organization, throughout their life cycles. | The signed attestation; every Tier 1 row; the airlock | Partial | R1 (p. 15): "Verify the integrity, provenance, and security of an existing AI model or any other acquired AI components — including training, testing, fine-tuning, and aligning datasets; reward models; adaptation layers; and configuration parameters — before using them." Socair verifies the model artifact's integrity and provenance (Hash, provenance, lineage) and inspects its files for the security issues its checks name, before the airlock lets it cross. It does not vet datasets or reward models, and "secure" is bounded by the detection ceiling. |
| PW.4.4 (as above) | Pickle opcode scan; File inventory and payloads; Chat template; Tokenizer config; Remote code; Tier 2 (opt-in) | Partial | R2 (p. 16): "Scan and thoroughly test acquired AI models and their components for vulnerabilities and malicious content before use." Tier 1 scans the files for malicious content. Testing behaviour is Tier 2's measurements, which are opt-in and never a pass. |
| PW.7.2 Perform the code review and/or code analysis based on the organization's secure coding standards, and record and triage all discovered issues and recommended remediations in the development team's workflow or issue tracking system. | Every Tier 1 row with its severity; the SARIF output | Partial | R1 (p. 16): "Scan all AI models for malware, vulnerabilities, backdoors, and other security issues in accordance with the organization's code review and analysis policies or guidelines." Socair scans the artifact's files for code and injected instructions, grades each FAIL and LEAD for triage, and writes SARIF that issue trackers and code-scanning tools read. Backdoors in the weights are outside Tier 1. |
| PW.6.1 Use compiler, interpreter, and build tools that offer features to improve executable security. | Pickle opcode scan; Format and structure | Partial | C1 (p. 16): "Consider using secure model serialization mechanisms that reduce or eliminate vectors for the introduction of malicious content." The report names each artifact's format, and the pickle check holds a pickle to a grammar of plain tensors. Choosing the format is the organization's decision. |
| PO.4.1 Define criteria for software security checks and track throughout the SDLC. | Signed acceptance (`socair accept`); the promotion state | Partial | C1 (p. 10): "Consider requiring review and approval from a human-in-the-loop for software security checks beyond risk-based thresholds." Any FAIL or LEAD withholds promotion and no acceptance clears it; a NOT_TESTED row crosses only with a named person's signed acceptance of exactly that row, until an expiry. The organization sets who may accept. |

Not mapped: PS.2.1 R1 ("Generate and provide cryptographic hashes or digital
signatures for an AI model and its components, artifacts, and
documentation", p. 12) is the model producer's task. Socair checks what a
producer published under it; that is not evidence the producer met it.

## NIST AI 600-1

Source: [NIST AI 600-1, Artificial Intelligence Risk Management Framework:
Generative Artificial Intelligence Profile (July 2024)](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf).
The profile's suggested actions are numbered by AI RMF subcategory. The risks
Socair's evidence bears on are Value Chain and Component Integration and
Information Security.

| Action | Socair evidence | Extent | Why |
|---|---|---|---|
| MG-3.1-002 | Pickle opcode scan; File inventory and payloads; Remote code; Chat template | Partial | "Test GAI system value chain risks (e.g., data poisoning, malware, other software and hardware vulnerabilities; labor practices; data privacy and localization compliance; geopolitical alignment)." (p. 42) Socair tests a third-party model artifact for malware and injected instructions. Data poisoning in the weights, and the other risks named, are outside it. |
| MS-2.7-001 | Every Tier 1 row; Tier 2 (opt-in) | Partial | "Apply established security measures to: Assess likelihood and magnitude of vulnerabilities and threats such as backdoors, compromised dependencies, data breaches, eavesdropping, man-in-the-middle attacks, reverse engineering, autonomous agents, model theft or exposure of model weights, AI inference, bypass, extraction, and other baseline security concerns." (p. 33) Socair records the artifact-level findings and their severity. It does not assess likelihood or magnitude, or the deployed system. |
| GV-1.6-003 | The artifact identity; Hash, provenance, lineage; the license; the airlock's signed inventory export | Partial | The action lists inventory items including "Data provenance information (e.g., source, signatures, versioning, watermarks)" (p. 16). A report records the artifact's hash, origin, publisher signature state, and license, and `socair airlock export` writes a signed inventory of the store. The other inventory items it lists are the organization's. |
| GV-1.3-002 | The promotion state; the airlock | Partial | The action begins "Establish minimum thresholds for performance or assurance criteria and review as part of deployment approval" and names go/no-go policies (p. 14). Socair's gate is fixed: any FAIL or LEAD withholds promotion, and a gap crosses only with a signed acceptance. Performance thresholds, and the policy itself, are the organization's. |
| MG-1.3-001 | Signed acceptance | Partial | "Document trade-offs, decision processes, and relevant measurement and feedback results for risks that do not surpass organizational risk tolerance, for example, in the context of model release: ..." (p. 40) An acceptance records who accepted which untested rows of which report, why, and until when. |
| MS-1.1-009 | NOT_TESTED rows; the out-of-scope section and detection ceiling | Partial | "Track and document risks or opportunities related to all GAI risks that cannot be measured quantitatively, including explanations as to why some risks cannot be measured (e.g., due to technological limitations, resource constraints, or trustworthy considerations)." (p. 29) Every check that did not run names its reason, and every report lists what Socair does not test. Risks outside the artifact are not listed. |
| GV-6.1-009 | Known-bad hash match | Partial | Among its examples: "Assess GAI vendors, open-source or proprietary GAI tools, or GAI service providers against incident or vulnerability databases." (p. 21) The row matches the artifact's hash against the configured denylist or signed feed, which catches only known files. |
| MS-2.3-003 | The signed attestation | Partial | "Share results of pre-deployment testing with relevant GAI Actors, such as those with system release approval authority." (p. 30) The attestation is the model artifact's test result, signed and verifiable offline by whoever approves release. Testing of the system the model goes into is not in it, and sharing it is the organization's act. |

## AI/ML supply chain risks and mitigations (ASD, co-sealed by NSA and others)

Source: [Artificial intelligence and machine learning: Supply chain risks and
mitigations](https://media.defense.gov/2026/Mar/04/2003882809/-1/-1/0/AI_ML_SUPPLY_CHAIN_RISKS_AND_MITIGATIONS.PDF),
by the Australian Signals Directorate, first published in October 2025 and
revised in March 2026 with the US National Security Agency, the Canadian
Centre for Cyber Security, NCSC-UK, NCSC-NZ, Singapore's CSA, Korea's NIS, and
Japan's NCO as co-sealers. It is published under CC BY 4.0. Its mitigations
have headings, not IDs; page numbers are the PDF's.

| Mitigation | Socair evidence | Extent | Why |
|---|---|---|---|
| Machine learning models: Model verification and provenance | Hash, provenance, lineage; the airlock | Partial | "Like AI data, use verification methods (such as checksums, hashes and digital signatures) to check the integrity of an ML model." (p. 12) The row checks the hash against a trusted signature or manifest. The guidance continues: "Maintain a model registry of specific model versions that have been verified, tested, and approved for use." The airlock's `clean/` store holds only artifacts whose signed attestation names their hash, but a conditional promotion also crosses, so its listings carry each attestation's state ([airlock.md](airlock.md)). |
| Machine learning models: Security tools | Every Tier 1 row | Partial | "Examples include model scanners to check for malicious content or stegomalware, and adversarial emulators to assess resilience to evasion and extraction attacks." (p. 13) Socair is a model scanner for the content its checks name. It does not look for code hidden in the weights' values, and it is not an adversarial emulator. The guidance also says users should assess a tool's effectiveness before relying on it; [detection-benchmark.md](detection-benchmark.md) and [false-positive-baseline.md](false-positive-baseline.md) publish Socair's. |
| Machine learning models: Secure file formats | Format and structure; Pickle opcode scan | Partial | "Approaches include using non-executable and weight-only formats or immutable graph formats and applying safe loading flags such as weight-only." (p. 11) The report names the format, and a pickle passes only if it builds plain tensors and containers. Choosing the format and the loader flags is the organization's. |
| Machine learning models: Mitigations (introduction) | The airlock; the promotion state | Partial | "To mitigate risks in ML models, validate them at the point of retrieval and continuously monitor their performance." (p. 11) Socair validates at intake, before promotion. Monitoring in production is outside it. |
| Overview: AI Bill of Materials | The CycloneDX ML-BOM output | Partial | Organisations should "require and maintain an AI Bill of Materials (AIBOM) and Software Bill of Materials (SBOM) or equivalent documentation for AI and ML." (p. 6) Socair writes a BOM for the artifact it attested. It does not know the training data the guidance also asks a BOM to list. |
| Machine learning models: Performance testing | Tier 2 measurements (opt-in) | Partial | "Initial and periodic testing should be performed to verify that model behaviour is as expected and consistent." (p. 11) Tier 2 measures behaviour on fixed probes when an operator runs it; periodic re-testing is the organization's schedule. |

## G7 SBOM for AI: minimum elements

Source: [Software Bill of Materials for AI – Minimum Elements (May 2026)](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/KI/SBOM-for-AI_minimum-elements.pdf?__blob=publicationFile&v=4),
by the G7 Cybersecurity Working Group, jointly published by BSI, ACN, ANSSI,
CSE, CISA, NCSC-UK, and Japan's NCO with the European Commission. Its elements
"are not mandatory; do not create requirements, standards, or legislation"
(p. 1). They are data a BOM carries, not controls, so this table says which
Models cluster elements a Socair report records for the artifact it names. The
CycloneDX output is derived from the report and adds nothing the report does
not say.

| Element | Socair evidence | Extent | Why |
|---|---|---|---|
| Model hash value; Model hash algorithm | `artifact.sha256` (and per-file hashes in `artifact.files`) | Full | The element is "The output generated from applying a cryptographic hash algorithm to an executable component artifact." (p. 14) The report records the SHA-256 of the exact bytes the checks read, and the BOM names the algorithm. |
| Model license | `artifact.license` | Partial | "This element describes the license type of the AI model." (p. 17) The report identifies the license from its stated sources, or says it could not. It does not say whether the model is open weight, open data, or open training. |
| Model producer | `artifact.publisher`, `artifact.publisher_signing_status` | Partial | "Model producer refers to the originator or manufacturer of the model." (p. 14) The report records a publisher when the scan has one, and whether a publisher signature verified against a key the operator trusts. It does not list everyone involved in training. |
| Model name; Model version; Model identifier | `artifact.name`; `artifact.repo_url`, `artifact.commit_sha` | Partial | The report records the name and, when the origin is bound to the hash, the repository and the immutable commit. For a Hugging Face repository at a pinned commit the BOM writes a PURL (`pkg:huggingface/<org>/<repo>@<commit>`), which the identifier element prefers; otherwise it writes none, and never a CPE. |
| Model description (lineage) | `artifact.base_models` | Partial | The element includes lineage, "such as information about the predecessor model on which fine tuning was done" (p. 14). The report lists the base models the artifact declares, as claims, not verified lineage. |

The Metadata cluster's "SBOM author signature" is "A digital signature
attributable to the SBOM author." (p. 7) `socair sign --bom` signs the BOM
itself, with the key that signed the attestation it is derived from, in a DSSE
envelope verified offline by `socair verify --bom` ([cyclonedx.md](cyclonedx.md)).

## Not mapped

- **ISO/IEC 42001:2023.** Its Annex A control table is not in ISO's public
  preview of the standard, and the standard is paywalled, so the control IDs
  and titles could not be read in the primary text. ISO's preview does show
  the headings of Annex B, the implementation guidance, including B.10.3
  Suppliers, B.7.5 Data provenance, and B.6.2.4 AI system verification and
  validation. An organization that holds the standard can map its Annex A
  controls from those.
- **OWASP Top 10 for LLM Applications 2026**, until it is final (see above).
- **NIST SP 800-218 Rev. 1** (SSDF 1.2), an initial public draft.
