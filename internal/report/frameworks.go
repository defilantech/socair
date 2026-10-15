package report

// Severity grades a FAIL or LEAD row so a reader can triage it. It is fixed per
// finding pattern, never per artifact: a pickle that imports os.system and a
// quantization label that does not match its tensors are both a FAIL, but not
// the same FAIL. It does not change the promotion state, which any FAIL or
// LEAD withholds.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
)

var severityRank = map[string]int{SeverityLow: 1, SeverityMedium: 2, SeverityHigh: 3, SeverityCritical: 4}

// patternSeverity is the severity of each finding pattern the checks emit.
// TestEveryPatternHasASeverity holds it to the checks' sources.
var patternSeverity = map[string]string{
	// Code a loader or template engine would execute, or a known-bad file.
	"python-object-escape":    SeverityCritical,
	"process-execution":       SeverityCritical,
	"pickle-dangerous-global": SeverityCritical,
	"pickle-nested-loader":    SeverityCritical,
	"pickle-code-argument":    SeverityCritical,
	"embedded-binary":         SeverityCritical,
	"repo-binary":             SeverityCritical,
	"denylist-match":          SeverityCritical,
	// A file write outside the save directory when the tokenizer is saved.
	"template-name-path": SeverityHigh,
	// Positive evidence of tampering, or a strong sign of a hidden payload.
	"tensor-layout":                 SeverityHigh,
	"duplicate-key":                 SeverityHigh,
	"shard-index":                   SeverityHigh,
	"embedded-script":               SeverityHigh,
	"embedded-base64-blob":          SeverityHigh,
	"pickle-dynamic-global":         SeverityHigh,
	"publisher-signature-invalid":   SeverityHigh,
	"content-conditional-injection": SeverityHigh,
	"obfuscated-literal":            SeverityHigh,
	"token-instruction":             SeverityHigh,
	"normalizer-injects-special":    SeverityHigh,
	"template-injects-token":        SeverityHigh,
	"tokenizer-token-changed":       SeverityHigh,
	"reviewed-template-mismatch":    SeverityHigh,
	"pickle-storage-layout":         SeverityHigh,
	"pickle-unaccounted-bytes":      SeverityHigh,
	"pickle-noncanonical":           SeverityHigh,
	// An ONNX tensor, or an OpenVINO IR Const, whose data does not match its
	// type and shape, or ONNX data in a field one loader reads and another
	// ignores.
	"tensor-size": SeverityHigh,
	"tensor-data": SeverityHigh,
	// An ONNX model that points a loader at a file outside its directory,
	// or at the runtime's own memory, or an HDF5 file whose data or link is
	// in another file: a read of what is not the model.
	"external-data-escape": SeverityHigh,
	"external-data-memory": SeverityHigh,
	// A Keras config that makes the loader run code: marshalled Python
	// bytecode (a Lambda), a pickled torch module, or a reference to a
	// module or Keras API that reaches code execution, files, or the network.
	"keras-lambda":              SeverityCritical,
	"keras-pickle":              SeverityCritical,
	"keras-dangerous-reference": SeverityCritical,
	// A .keras member whose name would leave the extraction directory, or
	// one Keras does not read, or a layer name that would leave the asset
	// directory: a write outside the model, or a place for a payload.
	"archive-path-escape": SeverityHigh,
	"keras-archive-entry": SeverityHigh,
	"keras-name-path":     SeverityHigh,
	// An HDF5 soft link or virtual dataset, which Keras refuses: one name
	// reading another's data, or data mapped from what the scan did not read.
	"hdf5-soft-link":       SeverityMedium,
	"hdf5-virtual-dataset": SeverityMedium,
	// Suspicious or inconsistent; needs review.
	"instruction-override":         SeverityMedium,
	"secrecy-instruction":          SeverityMedium,
	"external-access":              SeverityMedium,
	"external-url":                 SeverityMedium,
	"invisible-character":          SeverityMedium,
	"mixed-script-word":            SeverityMedium,
	"markup-injection":             SeverityMedium,
	"encoded-blob":                 SeverityMedium,
	"split-word-literal":           SeverityMedium,
	"unanalysable-template":        SeverityMedium,
	"control-token-prose":          SeverityMedium,
	"special-token-missing":        SeverityMedium,
	"special-token-out-of-range":   SeverityMedium,
	"tokenizer-bad-type":           SeverityMedium,
	"tokenizer-config-mismatch":    SeverityMedium,
	"tokenizer-duplicate-id":       SeverityMedium,
	"tokenizer-id-conflict":        SeverityMedium,
	"tokenizer-table-mismatch":     SeverityMedium,
	"tokenizer-template-mismatch":  SeverityMedium,
	"tokenizer-vocabulary-shorter": SeverityMedium,
	"pickle-unreviewed-global":     SeverityMedium,
	"pickle-unreadable":            SeverityMedium,
	"pickle-grammar":               SeverityMedium,
	"pickle-backward-hooks":        SeverityMedium,
	"pickle-reviewed-class-state":  SeverityMedium,
	"auto_map":                     SeverityMedium,
	"custom-pipeline":              SeverityMedium,
	"custom-module":                SeverityMedium,
	"custom-component":             SeverityMedium,
	"custom-generate":              SeverityMedium,
	"inference-handler":            SeverityMedium,
	"imported-code":                SeverityMedium,
	// An ONNX external data location that systems resolve differently.
	"external-data-path": SeverityMedium,
	// No longer emitted (tier1/0.9, #254): any .py file was a LEAD. Kept so
	// a report signed before it grades the same.
	"python-file": SeverityMedium,
	// A file that disagrees with its uploader's own checksum list: an
	// inconsistency a swap or a partial re-upload leaves behind, not proof
	// of either.
	"checksum-mismatch": SeverityMedium,
	// A license outside the operator's policy: a rule broken, not a
	// compromise.
	"license-not-allowed": SeverityMedium,
	// An intake rule broken: a format, a publisher, or a signature the
	// organization requires. The policy is the organization's, not evidence
	// of a compromise; the rows that read the bytes grade those.
	// Weights that are not the reference model's: a reviewed model's
	// identity broken, not evidence of how.
	"tensor-differs":               SeverityMedium,
	"tensor-not-in-reference":      SeverityMedium,
	"tensor-missing":               SeverityMedium,
	"format-not-allowed":           SeverityMedium,
	"publisher-denied":             SeverityMedium,
	"publisher-not-allowed":        SeverityMedium,
	"publisher-signature-required": SeverityMedium,
	// Integrity of a label, not of the model.
	"token-prose":          SeverityLow,
	"quant-mismatch":       SeverityLow,
	"license-disagreement": SeverityLow,
}

// PatternSeverity returns a pattern's fixed severity, or "" for a pattern
// without one.
func PatternSeverity(pattern string) string { return patternSeverity[pattern] }

// RowSeverity is the severity of a check row: the highest of its findings'
// patterns. A FAIL or LEAD whose patterns carry none falls back to high or
// medium; any other status has none.
func RowSeverity(status Status, patterns []string) string {
	if status != StatusFail && status != StatusLead {
		return ""
	}
	best := ""
	for _, p := range patterns {
		if s := patternSeverity[p]; severityRank[s] > severityRank[best] {
			best = s
		}
	}
	if best != "" {
		return best
	}
	if status == StatusFail {
		return SeverityHigh
	}
	return SeverityMedium
}

// The frameworks a check row maps to, and the editions the mappings were made
// against. ATLAS has numbered its monthly content releases YYYY.MM since
// 2026.05; every ATLAS ID and name below is checked against the pinned
// release's published data (testdata/atlas-ids.txt, written by atlasgen).
// docs/control-mapping.md maps the rows to framework controls.
const (
	FrameworkATLAS    = "MITRE ATLAS"
	FrameworkOWASPLLM = "OWASP LLM Top 10"

	ATLASVersion = "2026.09"
	OWASPVersion = "2025"

	ATLASEdition = FrameworkATLAS + " " + ATLASVersion
	OWASPEdition = "OWASP Top 10 for LLM Applications " + OWASPVersion
)

// FrameworkRef is one entry in an external framework that a check addresses.
type FrameworkRef struct {
	Framework string `json:"framework"`
	// Version is the edition of the framework the entry is from
	// (ATLASVersion, OWASPVersion), so a filed report names the entry it
	// meant after the framework renames or retires it. A report made before
	// Socair recorded it has none.
	Version string `json:"version,omitempty"`
	ID      string `json:"id"`
	Name    string `json:"name"`
}

func atlas(id, name string) FrameworkRef {
	return FrameworkRef{Framework: FrameworkATLAS, Version: ATLASVersion, ID: id, Name: name}
}

func owaspLLM(id, name string) FrameworkRef {
	return FrameworkRef{Framework: FrameworkOWASPLLM, Version: OWASPVersion, ID: id, Name: name}
}

var (
	atlasSupplyChainModel = atlas("AML.T0010.003", "AI Supply Chain Compromise: Model")
	atlasSupplyChainSW    = atlas("AML.T0010.001", "AI Supply Chain Compromise: AI Software")
	atlasUnsafeArtifacts  = atlas("AML.T0011.000", "User Execution: Unsafe AI Artifacts")
	atlasPromptInjection  = atlas("AML.T0051", "LLM Prompt Injection")
	atlasEmbedMalware     = atlas("AML.T0018.002", "Manipulate AI Model: Embed Malware")
	atlasPromptLogic      = atlas("AML.T0018.003", "Manipulate AI Model: Modify Prompt Construction Logic")
	// AML.T0115.001 replaced AML.T0058 "Publish Poisoned Models" in ATLAS
	// 2026.07.
	atlasPoisonedModels  = atlas("AML.T0115.001", "Publish Poisoned AI Artifacts: Models")
	owaspPromptInjection = owaspLLM("LLM01", "Prompt Injection")
	owaspSupplyChain     = owaspLLM("LLM03", "Supply Chain")
)

// checkMaps is what each check addresses. A mapping is a claim about what the
// check tests, so it names only what the check inspects, never the wider
// threat: the tokenizer check addresses tampered tokenizer settings, not
// poisoned weights, which no Tier 1 check reads.
var checkMaps = map[string][]FrameworkRef{
	"Format and structure": {atlasSupplyChainModel, owaspSupplyChain},
	// Scripts and executables carried in a model file's metadata.
	"File inventory and payloads": {atlasUnsafeArtifacts, atlasEmbedMalware, atlasSupplyChainModel, owaspSupplyChain},
	// ATLAS names templates and role delimiters as prompt construction logic.
	"Chat template": {atlasPromptLogic, atlasPromptInjection, atlasUnsafeArtifacts, owaspPromptInjection, owaspSupplyChain},
	// ATLAS names tokenizer settings as prompt construction logic, and
	// tokenizer metadata as an unsafe artifact's bundled component.
	"Tokenizer config": {atlasPromptLogic, atlasUnsafeArtifacts, atlasSupplyChainModel, owaspSupplyChain},
	"Quant match":      {atlasSupplyChainModel, owaspSupplyChain},
	// Code a pickle loader would run is malware embedded in a model file.
	"Pickle opcode scan":        {atlasUnsafeArtifacts, atlasEmbedMalware, atlasSupplyChainModel, owaspSupplyChain},
	"Remote code":               {atlasUnsafeArtifacts, atlasSupplyChainSW, owaspSupplyChain},
	"Hash, provenance, lineage": {atlasSupplyChainModel, atlasPoisonedModels, owaspSupplyChain},
	"Known-bad hash match":      {atlasPoisonedModels, atlasSupplyChainModel, owaspSupplyChain},
	// LLM03 names licensing risk among supply-chain vulnerabilities; no
	// ATLAS technique is a license.
	"License policy": {owaspSupplyChain},
	// LLM03's mitigations: use trusted suppliers, and models from verifiable
	// sources with signing. The policy enforces the organization's rules and
	// detects no compromise, so it maps to no ATLAS technique.
	IntakePolicyCheck: {owaspSupplyChain},
	// Weights that are not those of the model the operator reviewed: a
	// substituted or modified model, which ATLAS names as a supply-chain
	// compromise of the model and as poisoned models.
	TensorReferenceCheck: {atlasSupplyChainModel, atlasPoisonedModels, owaspSupplyChain},
}

// MapsTo returns the framework entries a check addresses, or nil.
func MapsTo(check string) []FrameworkRef {
	m := checkMaps[check]
	if m == nil {
		return nil
	}
	return append([]FrameworkRef(nil), m...)
}

// FrameworkEditions names the framework editions the rows' entries are from,
// as "<framework> <version>", in the order the rows first name them. It reads
// the document, not this package's constants, so an older report names the
// editions it was mapped against; an entry without a version adds nothing.
func FrameworkEditions(checks []CheckResult) []string {
	var out []string
	seen := map[string]bool{}
	for _, c := range checks {
		for _, m := range c.MapsTo {
			if m.Version == "" {
				continue
			}
			e := m.Framework + " " + m.Version
			if !seen[e] {
				seen[e] = true
				out = append(out, e)
			}
		}
	}
	return out
}
