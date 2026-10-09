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
	"python-file":                  SeverityMedium,
	// A license outside the operator's policy: a rule broken, not a
	// compromise.
	"license-not-allowed": SeverityMedium,
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

// Frameworks names the editions the mappings below were made against.
const (
	ATLASEdition = "MITRE ATLAS 5.6.0"
	OWASPEdition = "OWASP Top 10 for LLM Applications 2025"
)

// FrameworkRef is one entry in an external framework that a check addresses.
type FrameworkRef struct {
	Framework string `json:"framework"`
	ID        string `json:"id"`
	Name      string `json:"name"`
}

var (
	atlasSupplyChainModel = FrameworkRef{"MITRE ATLAS", "AML.T0010.003", "AI Supply Chain Compromise: Model"}
	atlasSupplyChainSW    = FrameworkRef{"MITRE ATLAS", "AML.T0010.001", "AI Supply Chain Compromise: AI Software"}
	atlasUnsafeArtifacts  = FrameworkRef{"MITRE ATLAS", "AML.T0011.000", "User Execution: Unsafe AI Artifacts"}
	atlasPromptInjection  = FrameworkRef{"MITRE ATLAS", "AML.T0051", "LLM Prompt Injection"}
	atlasPoisonedModels   = FrameworkRef{"MITRE ATLAS", "AML.T0058", "Publish Poisoned Models"}
	owaspPromptInjection  = FrameworkRef{"OWASP LLM Top 10", "LLM01", "Prompt Injection"}
	owaspSupplyChain      = FrameworkRef{"OWASP LLM Top 10", "LLM03", "Supply Chain"}
)

// checkMaps is what each check addresses. A mapping is a claim about what the
// check tests, so it names only what the check inspects, never the wider
// threat: the tokenizer check addresses a tampered artifact, not poisoned
// weights, which no Tier 1 check reads.
var checkMaps = map[string][]FrameworkRef{
	"Format and structure":        {atlasSupplyChainModel, owaspSupplyChain},
	"File inventory and payloads": {atlasUnsafeArtifacts, atlasSupplyChainModel, owaspSupplyChain},
	"Chat template (hero)":        {atlasPromptInjection, atlasUnsafeArtifacts, owaspPromptInjection, owaspSupplyChain},
	"Tokenizer config":            {atlasSupplyChainModel, owaspSupplyChain},
	"Quant match":                 {atlasSupplyChainModel, owaspSupplyChain},
	"Pickle opcode scan":          {atlasUnsafeArtifacts, atlasSupplyChainModel, owaspSupplyChain},
	"Remote code":                 {atlasUnsafeArtifacts, atlasSupplyChainSW, owaspSupplyChain},
	"Hash, provenance, lineage":   {atlasSupplyChainModel, atlasPoisonedModels, owaspSupplyChain},
	"Known-bad hash match":        {atlasPoisonedModels, atlasSupplyChainModel, owaspSupplyChain},
	// LLM03 names licensing risk among supply-chain vulnerabilities; no
	// ATLAS technique is a license.
	"License policy": {owaspSupplyChain},
}

// MapsTo returns the framework entries a check addresses, or nil.
func MapsTo(check string) []FrameworkRef {
	m := checkMaps[check]
	if m == nil {
		return nil
	}
	return append([]FrameworkRef(nil), m...)
}
