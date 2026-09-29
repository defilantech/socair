# Model Assurance Attestation

- Template version: 0.1
- Issuer: Defilan Technologies, product Socair
- Status: v1 draft

## How to use this template

This document is the artifact a security buyer files. Fill the bracketed fields per scan and leave the fixed wording unchanged. Two elements are fixed and must not be edited per artifact:

- The bounded statement in Section 7.
- The published ceiling in Section 8.

Section references in the bounded statement point at this template's numbering.

---

## 1. Header

| Field | Value |
|---|---|
| Document ID | `[doc_id]` |
| Template version | 0.1 |
| Issuance date (UTC) | `[issued_utc]` |
| Re-scan due | `[rescan_due]` |
| Artifact (short) | `[model_name]` |
| Assurance level awarded | `[assurance_level]` |
| Signer | `[signer_name]`, `[signer_role]` |
| Signer key ID | `[key_id]` |
| Document hash | `[doc_sha256]` |

## 2. Artifact identity

| Field | Value |
|---|---|
| Model name | `[model_name]` |
| Source repository URL | `[repo_url]` |
| Commit or tag | `[commit_or_tag]` |
| Commit hash | `[commit_sha]` |
| Publisher / author | `[publisher]` |
| Publisher signing status | `[signed_openssf / unsigned]` |
| Artifact file name | `[artifact_filename]` |
| Artifact SHA256 (exact file scanned) | `[artifact_sha256]` |
| Format | `[GGUF / safetensors]` |
| File size (bytes) | `[size_bytes]` |
| Quantization, declared | `[quant_declared]` |
| Quantization, observed weight layout | `[quant_observed]` |
| Tokenizer version hash | `[tokenizer_hash]` |
| Chat-template version hash | `[chat_template_hash]` |

## 3. Scope and method

| Field | Value |
|---|---|
| Check-set version | `[checkset_version]` |
| Tools and versions | `[tool_versions]` |
| Execution context | `[Tier 1 static portable / Tier 2 node class <class>]` |
| Input path | `[airlock pull / offline cache / local path]` |
| Scan start (UTC) | `[scan_start]` |
| Scan end (UTC) | `[scan_end]` |
| Inference budget consumed | `[tier2_budget / not applicable]` |

## 4. Checks performed

Each row returns PASS, FAIL, or NOT_TESTED. An ambiguous or unverifiable result is recorded as NOT_TESTED with a named reason, never as a silent pass.

| Check | Looks for | Result | Evidence | Notes |
|---|---|---|---|
| Format and structure | Malformed GGUF/safetensors structure, unexpected tensors | `[result]` | `[evidence]` | `[notes]` |
| Chat template (hero) | Instructions in GGUF metadata that act before user input | `[result]` | `[evidence]` | `[notes]` |
| Tokenizer config | Tokenizer metadata anomalies | `[result]` | `[evidence]` | `[notes]` |
| Safetensors header and opcodes | Serialized code gadgets in headers or pickle opcodes | `[result]` | `[evidence]` | `[notes]` |
| Hash, provenance, lineage | Traceable origin and declared quantization lineage | `[result]` | `[evidence]` | `[notes]` |
| Known-bad hash match | Match against the known-bad artifact denylist | `[result]` | `[evidence]` | `[notes]` |
| Quant match | Declared quantization against observed weight layout | `[result]` | `[evidence]` | `[notes]` |
| Forward-pass trigger probes (Tier 2) | Behavior under the production serving stack | `[result / not run]` | `[evidence]` | `[notes]` |
| Serving-stack differential (Tier 2) | Same artifact behaving differently across stacks | `[result / not run]` | `[evidence]` | `[notes]` |

## 5. Results and findings

- FAIL entries: what, where, evidence, and why it matters, in plain language.

  `[fail_entries]`

- NOT_TESTED entries: what was not tested and why (unavailable, unparseable, budget, out of class).

  `[not_tested_entries]`

## 6. Assurance level

Awarded level: `[assurance_level]`

Definition: `[level_definition]`

What this level does mean: `[does_mean]`

What this level does not mean: `[does_not_mean]`

What Tier 2 would add, and whether it ran: `[tier2_note]`

## 7. Bounded statement (fixed)

> For the artifact identified by hash in Section 2, served on the node class named in Section 3, the checks listed in Section 4 found no indicators within their stated scope. Every surface outside that scope is enumerated as NOT_TESTED in Section 8.

## 8. Out of scope and NOT_TESTED (fixed ceiling)

This attestation does not certify the absence of unknown backdoors. Within the named scope, it reports what was examined and what was not. The following are outside the scope of every level below Tier 2 on the production class:

- Unknown triggers outside our probe library.
- Differential behavior across serving stacks (backdoors that are dormant on one platform and live on another), unless Tier 2 ran on the production node class.
- Sleeper or polymorphic behavior that needs more inference budget than we run.
- Artifact formats we do not parse.
- Malicious behavior that only emerges at runtime under real traffic.

Formats not parsed for this artifact: `[unparsed_formats]`

Node classes not tested for this artifact: `[untested_node_classes]`

## 9. Promotion authorization

Does this attestation authorize promotion into the clean store? `[yes / no]`

Level: `[Tier 1 only / Tier 2]`

Conditions: `[conditions]`

## 10. Escalation path

A FAIL is actionable, not terminal. This attestation explains the FAIL in Section 5 and records how the artifact can be submitted for escalated review.

Summary: `[escalation_summary]`

Available escalated review:

- Automated Tier 2 battery: forward-pass probes on the production node class. `[tier2_available]`
- Human analyst addendum: a person reviews the artifact and this report and signs an addendum. `[analyst_available]`

Service levels: `[sla_tiers]`

Escalated review is part of the paid assurance program.

## 11. Verification and reproducibility

| Field | Value |
|---|---|
| Document hash | `[doc_sha256]` |
| Signing method | `[signing_method]` |
| Signer key ID | `[key_id]` |
| Artifact SHA256 | `[artifact_sha256]` |
| How to re-run | `[rerun_instructions]` |

The artifact hash binds this attestation to one exact file. A re-pulled artifact with a different hash is not covered by this document.

## 12. Issuer and liability

Signed by: `[signer_name]`, `[signer_role]`, under the authority of Defilan Technologies.

What this signature warrants: `[warrant_scope]`

What this signature does not warrant: `[warrant_exclusions]`

---

## Appendix A. Check definitions and provenance

`[check_definitions]`

## Appendix B. Machine-readable output

Raw results: `[sarif_reference]`

## Appendix C. Glossary for the security reader

- **GGUF**: `[gguf_definition]`
- **Quantization**: `[quant_definition]`
- **Chat template**: `[chat_template_definition]`
- **NOT_TESTED**: `[not_tested_definition]`
- **Tier 1 vs Tier 2**: `[tier_definition]`
