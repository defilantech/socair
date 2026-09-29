// Package report defines the Socair attestation data model.
//
// This model is the cross-stack contract. The engine produces it, the CLI
// prints it, the SvelteKit wizard renders it, and the later MCP wrapper serves
// it. No component may invent a divergent report shape. The JSON form is
// versioned; see docs/report-schema/v1.json.
package report

import (
	"fmt"
	"strings"

	"github.com/defilantech/socair/internal/gguf"
)

// SchemaVersion is the contract version this model emits.
const SchemaVersion = "socair.report/v1"

// BoundedStatement is the fixed Option A wording. It must not be edited per
// artifact.
const BoundedStatement = "For the artifact identified by hash in Section 2, served on the node class named in Section 3, the checks listed in Section 4 found no indicators within their stated scope. Every surface outside that scope is enumerated as NOT_TESTED in Section 8."

// DoesNotCertify is the fixed ceiling sentence.
const DoesNotCertify = "This attestation does not certify the absence of unknown backdoors."

// Status is a per-check result.
type Status string

const (
	StatusPass      Status = "PASS"
	StatusFail      Status = "FAIL"
	StatusNotTested Status = "NOT_TESTED"
)

// Document is one rendered attestation.
type Document struct {
	SchemaVersion          string                 `json:"schema_version"`
	Header                 Header                 `json:"header"`
	Artifact               ArtifactIdentity       `json:"artifact"`
	Scope                  Scope                  `json:"scope"`
	Checks                 []CheckResult          `json:"checks"`
	Findings               Findings               `json:"findings"`
	AssuranceLevel         AssuranceLevel         `json:"assurance_level"`
	BoundedStatement       string                 `json:"bounded_statement"`
	OutOfScope             OutOfScope             `json:"out_of_scope"`
	PromotionAuthorization PromotionAuthorization `json:"promotion_authorization"`
	Verification           Verification           `json:"verification"`
	Issuer                 Issuer                 `json:"issuer"`
	Appendices             Appendices             `json:"appendices"`
}

type Header struct {
	DocumentID            string `json:"document_id"`
	TemplateVersion       string `json:"template_version"`
	IssuedUTC             string `json:"issued_utc"`
	RescanDue             string `json:"rescan_due,omitempty"`
	ArtifactShort         string `json:"artifact_short"`
	AssuranceLevelAwarded string `json:"assurance_level_awarded"`
	SignerName            string `json:"signer_name,omitempty"`
	SignerRole            string `json:"signer_role,omitempty"`
	SignerKeyID           string `json:"signer_key_id,omitempty"`
	DocumentHash          string `json:"document_hash,omitempty"`
}

type ArtifactIdentity struct {
	Name                  string `json:"name"`
	RepoURL               string `json:"repo_url,omitempty"`
	CommitOrTag           string `json:"commit_or_tag,omitempty"`
	CommitSHA             string `json:"commit_sha,omitempty"`
	Publisher             string `json:"publisher,omitempty"`
	PublisherSigningState string `json:"publisher_signing_status,omitempty"`
	FileName              string `json:"file_name"`
	SHA256                string `json:"sha256"`
	Format                string `json:"format"`
	SizeBytes             int64  `json:"size_bytes"`
	QuantDeclared         string `json:"quant_declared,omitempty"`
	QuantObserved         string `json:"quant_observed,omitempty"`
	TokenizerHash         string `json:"tokenizer_hash,omitempty"`
	ChatTemplateHash      string `json:"chat_template_hash,omitempty"`
}

type Scope struct {
	CheckSetVersion  string `json:"check_set_version"`
	ToolVersions     string `json:"tool_versions,omitempty"`
	ExecutionContext string `json:"execution_context"`
	InputPath        string `json:"input_path"`
	ScanStartUTC     string `json:"scan_start_utc,omitempty"`
	ScanEndUTC       string `json:"scan_end_utc,omitempty"`
	InferenceBudget  string `json:"inference_budget,omitempty"`
}

type CheckResult struct {
	Name     string `json:"name"`
	LooksFor string `json:"looks_for"`
	Status   Status `json:"status"`
	Evidence string `json:"evidence,omitempty"`
	Notes    string `json:"notes,omitempty"`
}

type Findings struct {
	Fails     []string `json:"fails"`
	NotTested []string `json:"not_tested"`
}

type AssuranceLevel struct {
	Awarded     string `json:"awarded"`
	Definition  string `json:"definition,omitempty"`
	DoesMean    string `json:"does_mean,omitempty"`
	DoesNotMean string `json:"does_not_mean,omitempty"`
	Tier2Note   string `json:"tier2_note,omitempty"`
}

type OutOfScope struct {
	DoesNotCertify      string   `json:"does_not_certify"`
	Ceiling             []string `json:"ceiling"`
	UnparsedFormats     []string `json:"unparsed_formats,omitempty"`
	UntestedNodeClasses []string `json:"untested_node_classes,omitempty"`
}

type PromotionAuthorization struct {
	Authorized bool   `json:"authorized"`
	Level      string `json:"level,omitempty"`
	Conditions string `json:"conditions,omitempty"`
}

type Verification struct {
	DocumentHash      string `json:"document_hash,omitempty"`
	SigningMethod     string `json:"signing_method"`
	SignerKeyID       string `json:"signer_key_id,omitempty"`
	ArtifactSHA256    string `json:"artifact_sha256"`
	RerunInstructions string `json:"rerun_instructions,omitempty"`
}

type Issuer struct {
	SignedBy  string `json:"signed_by,omitempty"`
	Authority string `json:"authority"`
	Warrants  string `json:"warrants,omitempty"`
	Excludes  string `json:"excludes,omitempty"`
}

type Appendices struct {
	CheckDefinitions string `json:"check_definitions,omitempty"`
	SARIFReference   string `json:"sarif_reference,omitempty"`
	Glossary         string `json:"glossary,omitempty"`
}

// DefaultCeiling is the published detection ceiling, per artifact.
func DefaultCeiling() []string {
	return []string{
		"Unknown triggers outside our probe library.",
		"Differential behavior across serving stacks, unless Tier 2 ran on the production node class.",
		"Sleeper or polymorphic behavior that needs more inference budget than we run.",
		"Artifact formats we do not parse.",
		"Malicious behavior that only emerges at runtime under real traffic.",
	}
}

// NewFromManifest seeds a document from a reader manifest. Every content check
// starts NOT_TESTED, because no check has run yet. Checks turn into PASS or
// FAIL as the engine lands.
func NewFromManifest(m *gguf.Manifest) *Document {
	observed := ""
	if m.Quant.FileType != nil {
		observed = fmt.Sprintf("file_type=%d", *m.Quant.FileType)
	}
	d := &Document{
		SchemaVersion: SchemaVersion,
		Header: Header{
			TemplateVersion:       "0.1",
			ArtifactShort:         m.Name,
			AssuranceLevelAwarded: "Tier 1 (static), pending checks",
		},
		Artifact: ArtifactIdentity{
			Name:          m.Name,
			FileName:      m.FileName,
			SHA256:        m.SHA256,
			Format:        m.Format,
			SizeBytes:     m.SizeBytes,
			QuantDeclared: m.Quant.Declared,
			QuantObserved: observed,
		},
		Scope: Scope{
			CheckSetVersion:  "tier1/0.1",
			ExecutionContext: "Tier 1 static, portable",
			InputPath:        "local path",
		},
		BoundedStatement: BoundedStatement,
		OutOfScope: OutOfScope{
			DoesNotCertify: DoesNotCertify,
			Ceiling:        DefaultCeiling(),
		},
		Verification: Verification{
			SigningMethod:  "unsigned (OSS tier)",
			ArtifactSHA256: m.SHA256,
		},
		Issuer: Issuer{
			Authority: "Defilan Technologies",
		},
	}
	d.Checks = skeletonChecks()
	return d
}

func skeletonChecks() []CheckResult {
	spec := []struct {
		name     string
		looksFor string
	}{
		{"Format and structure", "Malformed GGUF structure, unexpected tensors"},
		{"Chat template (hero)", "Instructions in GGUF metadata that act before user input"},
		{"Tokenizer config", "Tokenizer metadata anomalies"},
		{"Safetensors header and opcodes", "Serialized code gadgets in headers or pickle opcodes"},
		{"Hash, provenance, lineage", "Traceable origin and declared quantization lineage"},
		{"Known-bad hash match", "Match against the known-bad artifact denylist"},
		{"Quant match", "Declared quantization against observed weight layout"},
	}
	out := make([]CheckResult, 0, len(spec))
	for _, s := range spec {
		out = append(out, CheckResult{Name: s.name, LooksFor: s.looksFor, Status: StatusNotTested, Notes: "check not yet implemented"})
	}
	return out
}

// Validate reports problems with a document that would make it un-fileable.
// It is the structural gate before render and before signing.
func Validate(d *Document) []string {
	var problems []string
	req := func(ok bool, what string) {
		if !ok {
			problems = append(problems, "missing: "+what)
		}
	}
	req(d.SchemaVersion == SchemaVersion, "schema_version")
	req(strings.TrimSpace(d.Header.DocumentID) != "", "header.document_id")
	req(strings.TrimSpace(d.Header.TemplateVersion) != "", "header.template_version")
	req(strings.TrimSpace(d.Header.IssuedUTC) != "", "header.issued_utc")
	req(strings.TrimSpace(d.Header.AssuranceLevelAwarded) != "", "header.assurance_level_awarded")
	req(strings.TrimSpace(d.Artifact.FileName) != "", "artifact.file_name")
	req(len(d.Artifact.SHA256) == 64, "artifact.sha256 (64 hex chars)")
	req(strings.TrimSpace(d.Artifact.Format) != "", "artifact.format")
	req(len(d.Checks) > 0, "checks (at least one)")
	req(d.BoundedStatement == BoundedStatement, "bounded_statement (must equal the fixed wording)")
	req(strings.TrimSpace(d.OutOfScope.DoesNotCertify) != "", "out_of_scope.does_not_certify")
	req(len(d.OutOfScope.Ceiling) > 0, "out_of_scope.ceiling")
	req(strings.TrimSpace(d.Issuer.Authority) != "", "issuer.authority")
	req(d.Verification.ArtifactSHA256 == d.Artifact.SHA256, "verification.artifact_sha256 (must match artifact.sha256)")
	for i, c := range d.Checks {
		switch c.Status {
		case StatusPass, StatusFail, StatusNotTested:
		default:
			problems = append(problems, fmt.Sprintf("checks[%d].status invalid: %q", i, c.Status))
		}
		if strings.TrimSpace(c.Name) == "" {
			problems = append(problems, fmt.Sprintf("checks[%d].name empty", i))
		}
	}
	return problems
}
