// Package report defines the Socair attestation data model.
//
// This model is the cross-stack contract. The engine produces it, the CLI
// prints it, the SvelteKit wizard renders it, and the later MCP wrapper serves
// it. No component may invent a divergent report shape. The JSON form is
// versioned; see docs/report-schema/v1.json.
package report

import (
	"fmt"
	"github.com/defilantech/socair/internal/modeldir"
	"strings"
	"time"

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
	// StatusLead is a suspicious signal that is not conclusive, such as
	// instruction-override language in a chat template. It is not a gap: an
	// acceptance clears NOT_TESTED rows, never a LEAD. Only escalation does.
	StatusLead Status = "LEAD"
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
	Architecture          string `json:"architecture,omitempty"`
	RepoURL               string `json:"repo_url,omitempty"`
	CommitOrTag           string `json:"commit_or_tag,omitempty"`
	CommitSHA             string `json:"commit_sha,omitempty"`
	Publisher             string `json:"publisher,omitempty"`
	PublisherSigningState string `json:"publisher_signing_status,omitempty"`
	FileName              string `json:"file_name"`
	SHA256                string `json:"sha256"`
	Format                string `json:"format"`
	SizeBytes             int64  `json:"size_bytes"`
	Split                 string `json:"split,omitempty"`
	QuantDeclared         string `json:"quant_declared,omitempty"`
	QuantObserved         string `json:"quant_observed,omitempty"`
	TokenizerHash         string `json:"tokenizer_hash,omitempty"`
	ChatTemplateHash      string `json:"chat_template_hash,omitempty"`
	// Files lists every file of a model directory. When present, SHA256 is
	// the digest of their canonical manifest (internal/modeldir), so each
	// file's bytes are bound to the attestation subject.
	Files []ArtifactFile `json:"files,omitempty"`
}

// ArtifactFile is one file of a model directory.
type ArtifactFile struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
	Role      string `json:"role"`
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
	Leads     []string `json:"leads,omitempty"`
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
	// NotRun lists checks of a higher level than the one awarded. They are
	// outside this attestation's scope, not gaps in it, so they do not count
	// toward promotion; they are named so a reader sees what was not done.
	NotRun []NotRunCheck `json:"not_run,omitempty"`
}

// NotRunCheck is a check that did not run at the awarded level, and why.
type NotRunCheck struct {
	Name     string `json:"name"`
	LooksFor string `json:"looks_for"`
	Reason   string `json:"reason"`
}

// Tier2NotRun is what a Tier 1 attestation says about the Tier 2 checks.
func Tier2NotRun() []NotRunCheck {
	const why = "Tier 2 (forward-pass, on the production node class) did not run; Tier 1 is static and runs no inference"
	return []NotRunCheck{
		{Name: "Forward-pass trigger probes (Tier 2)", LooksFor: "Behavior under the production serving stack", Reason: why},
		{Name: "Serving-stack differential (Tier 2)", LooksFor: "Same artifact behaving differently across stacks", Reason: why},
	}
}

// Tier1UntestedNodeClasses is the node-class statement of a static scan: it
// ran on no node class, so none is tested.
const Tier1UntestedNodeClasses = "every node class: Tier 1 is static and ran no inference on any hardware"

// Promotion states. A FAIL withholds; a gap needs a named acceptance; the
// accepted surfaces always travel with the artifact.
const (
	StateAuthorized               = "authorized"
	StateAuthorizedWithConditions = "authorized_with_conditions"
	StateWithheld                 = "withheld"
	StateEscalated                = "escalated"
)

type PromotionAuthorization struct {
	Authorized        bool     `json:"authorized"`
	State             string   `json:"state"`
	Level             string   `json:"level,omitempty"`
	Conditions        string   `json:"conditions,omitempty"`
	AcceptedSurfaces  []string `json:"accepted_surfaces,omitempty"`
	AcceptedBy        string   `json:"accepted_by,omitempty"`
	AcceptedAt        string   `json:"accepted_at,omitempty"`
	AcceptanceExpires string   `json:"acceptance_expires,omitempty"`
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

func splitLabel(m *gguf.Manifest) string {
	if !m.MultiPart() {
		return ""
	}
	return fmt.Sprintf("part %d of %d", m.Split.No+1, m.Split.Count)
}

// DefaultCeiling is the published detection ceiling, per artifact.
func DefaultCeiling() []string {
	return []string{
		"Unknown triggers outside our probe library.",
		"Differential behavior across serving stacks, unless Tier 2 ran on the production node class.",
		"Sleeper or polymorphic behavior that needs more inference budget than we run.",
		"Artifact formats we do not parse.",
		"Pickle code execution reached only through imports on the reviewed safe list.",
		"Chat-template instructions written as ordinary guidance (no override or concealment phrase, URL, hidden or obfuscated text, or condition on message content), unless the template matches a reviewed template.",
		"Malicious behavior that only emerges at runtime under real traffic.",
	}
}

// Identity is the format-neutral artifact identity every reader maps onto.
type Identity struct {
	Name               string
	Architecture       string
	FileName           string
	SHA256             string
	Format             string
	SizeBytes          int64
	QuantDeclared      string
	QuantObserved      string
	ChatTemplateSHA256 string
	Split              string
	Files              []ArtifactFile
}

// NewFromIdentity seeds a document from a reader identity. Every content check
// starts NOT_TESTED, because no check has run yet.
func NewFromIdentity(id Identity) *Document {
	d := &Document{
		SchemaVersion: SchemaVersion,
		Header: Header{
			TemplateVersion:       "0.1",
			ArtifactShort:         id.Name,
			AssuranceLevelAwarded: "Tier 1 (static), pending checks",
		},
		Artifact: ArtifactIdentity{
			Name:             id.Name,
			Architecture:     id.Architecture,
			FileName:         id.FileName,
			SHA256:           id.SHA256,
			Format:           id.Format,
			SizeBytes:        id.SizeBytes,
			QuantDeclared:    id.QuantDeclared,
			QuantObserved:    id.QuantObserved,
			ChatTemplateHash: id.ChatTemplateSHA256,
			Split:            id.Split,
			Files:            id.Files,
		},
		Scope: Scope{
			CheckSetVersion:  "tier1/0.1",
			ExecutionContext: "Tier 1 static, portable",
			InputPath:        "local path",
		},
		BoundedStatement: BoundedStatement,
		OutOfScope: OutOfScope{
			DoesNotCertify:      DoesNotCertify,
			Ceiling:             DefaultCeiling(),
			UntestedNodeClasses: []string{Tier1UntestedNodeClasses},
			NotRun:              Tier2NotRun(),
		},
		Verification: Verification{
			SigningMethod:  "unsigned (OSS tier)",
			ArtifactSHA256: id.SHA256,
		},
		Issuer: Issuer{
			Authority: "Defilan Technologies",
		},
		// A freshly seeded document has run no checks, so promotion is withheld
		// until the engine evaluates it.
		PromotionAuthorization: PromotionAuthorization{
			State:      StateWithheld,
			Level:      "Tier 1 only",
			Conditions: "Not yet evaluated.",
		},
	}
	// Checks are empty until the engine runs them. A document with no checks is
	// not fileable, which Validate enforces. The report lists the checks that
	// actually ran for this artifact's format, not a fixed skeleton with
	// placeholder rows.
	return d
}

// NewFromManifest maps a GGUF manifest onto a document.
func NewFromManifest(m *gguf.Manifest) *Document {
	observed := ""
	if m.Quant.FileType != nil {
		observed = fmt.Sprintf("file_type=%d", *m.Quant.FileType)
	}
	return NewFromIdentity(Identity{
		Name:               m.Name,
		Architecture:       m.Architecture,
		FileName:           m.FileName,
		SHA256:             m.SHA256,
		Format:             m.Format,
		SizeBytes:          m.SizeBytes,
		QuantDeclared:      m.Quant.Declared,
		QuantObserved:      observed,
		ChatTemplateSHA256: m.ChatTemplateSHA256,
		Split:              splitLabel(m),
	})
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
	problems = append(problems, validateFiles(d)...)
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
		case StatusPass, StatusFail, StatusLead, StatusNotTested:
		default:
			problems = append(problems, fmt.Sprintf("checks[%d].status invalid: %q", i, c.Status))
		}
		if strings.TrimSpace(c.Name) == "" {
			problems = append(problems, fmt.Sprintf("checks[%d].name empty", i))
		}
	}
	problems = append(problems, validatePromotion(d)...)
	return problems
}

// validatePromotion enforces the promotion state machine: a FAIL withholds, a
// gap needs a named acceptance, and the authorized bool agrees with the state.
func validatePromotion(d *Document) []string {
	var problems []string
	pa := d.PromotionAuthorization

	switch pa.State {
	case StateAuthorized, StateAuthorizedWithConditions, StateWithheld, StateEscalated:
	default:
		problems = append(problems, fmt.Sprintf("promotion_authorization.state invalid: %q", pa.State))
	}

	wantAuthorized := pa.State == StateAuthorized || pa.State == StateAuthorizedWithConditions
	if pa.Authorized != wantAuthorized {
		problems = append(problems, fmt.Sprintf("promotion_authorization.authorized (%v) disagrees with state %q",
			pa.Authorized, pa.State))
	}

	if pa.State == StateAuthorizedWithConditions {
		if strings.TrimSpace(pa.AcceptedBy) == "" {
			problems = append(problems, "promotion_authorization: authorized_with_conditions needs accepted_by")
		}
		if len(pa.AcceptedSurfaces) == 0 {
			problems = append(problems, "promotion_authorization: authorized_with_conditions needs accepted_surfaces")
		}
		// An acceptance whose expiry cannot be parsed cannot be enforced, so
		// it is not an acceptance.
		if _, err := time.Parse(time.RFC3339, pa.AcceptanceExpires); err != nil {
			problems = append(problems, fmt.Sprintf("promotion_authorization: authorized_with_conditions needs an RFC 3339 acceptance_expires, got %q", pa.AcceptanceExpires))
		}
	}
	if d.Header.RescanDue != "" {
		if _, err := time.Parse(time.RFC3339, d.Header.RescanDue); err != nil {
			problems = append(problems, fmt.Sprintf("header.rescan_due must be RFC 3339, got %q", d.Header.RescanDue))
		}
	}
	if pa.State == StateAuthorized && len(pa.AcceptedSurfaces) > 0 {
		problems = append(problems, "promotion_authorization: an authorized report must not carry accepted_surfaces")
	}
	return append(problems, validateStateAgainstChecks(d)...)
}

// validateStateAgainstChecks binds the promotion state to the check rows. The
// airlock admits a validating document, so the state must follow from the
// checks, not merely agree with its own fields: an edited state over a FAIL or
// an unaccepted gap is a forged ticket.
func validateStateAgainstChecks(d *Document) []string {
	pa := d.PromotionAuthorization
	if pa.State != StateAuthorized && pa.State != StateAuthorizedWithConditions {
		return nil
	}
	if len(d.Checks) == 0 {
		return []string{"promotion_authorization: an authorized report must carry check rows"}
	}

	var problems []string
	accepted := make(map[string]bool, len(pa.AcceptedSurfaces))
	for _, s := range pa.AcceptedSurfaces {
		accepted[s] = true
	}
	for _, c := range d.Checks {
		switch c.Status {
		case StatusFail, StatusLead:
			problems = append(problems, fmt.Sprintf(
				"promotion_authorization: state %q over %s row %q; it clears only by escalation", pa.State, c.Status, c.Name))
		case StatusNotTested:
			if pa.State == StateAuthorized {
				problems = append(problems, fmt.Sprintf(
					"promotion_authorization: state %q over NOT_TESTED row %q; a gap needs a named acceptance", pa.State, c.Name))
			} else if !accepted[c.Name] {
				problems = append(problems, fmt.Sprintf(
					"promotion_authorization: NOT_TESTED row %q is not in accepted_surfaces", c.Name))
			}
		case StatusPass:
		default:
			problems = append(problems, fmt.Sprintf(
				"promotion_authorization: state %q over row %q with unknown status %q", pa.State, c.Name, c.Status))
		}
	}
	return problems
}

// validateFiles holds a directory report to its own file list: the artifact
// hash must be the manifest digest of exactly these files, so no report lists
// one set of files under another set's hash.
func validateFiles(d *Document) []string {
	if len(d.Artifact.Files) == 0 {
		return nil
	}
	files := make([]modeldir.File, len(d.Artifact.Files))
	for i, f := range d.Artifact.Files {
		files[i] = modeldir.File{Path: f.Path, SHA256: f.SHA256, Size: f.SizeBytes, Role: f.Role}
		if i > 0 && d.Artifact.Files[i-1].Path >= f.Path {
			return []string{"artifact.files must be sorted by path with no repeats"}
		}
	}
	if got := modeldir.Digest(files); got != d.Artifact.SHA256 {
		return []string{fmt.Sprintf("artifact.sha256 %s is not the manifest digest %s of artifact.files", d.Artifact.SHA256, got)}
	}
	return nil
}
