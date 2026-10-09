// Package report defines the Socair attestation data model.
//
// This model is the cross-stack contract. The engine produces it, the CLI
// prints it, the SvelteKit wizard renders it, and the later MCP wrapper serves
// it. No component may invent a divergent report shape. The JSON form is
// versioned; see docs/report-schema/v1.json.
package report

import (
	"encoding/base64"

	"fmt"
	"github.com/defilantech/socair/internal/acceptance"
	"github.com/defilantech/socair/internal/modeldir"
	"strings"
	"time"

	"github.com/defilantech/socair/internal/gguf"
)

// SchemaVersion is the contract version this model emits.
const SchemaVersion = "socair.report/v1"

// The bounded statement is one of four fixed sentences: a pair for a Tier 1
// report and a pair for one with Tier 2 measurements, each picked from the
// check rows by BoundedStatementOf. None may be edited per artifact.
const (
	// BoundedStatementNoIndicators is the statement of a report with no FAIL
	// and no LEAD row.
	BoundedStatementNoIndicators = "For the artifact identified by its hash, the Tier 1 checks that returned PASS found no indicators within their stated scope. " +
		"Rows marked NOT_TESTED were not examined, for the reason each row gives. Tier 1 runs no inference, so no model behavior was tested. " +
		"Every surface outside that scope is listed under Out of scope."
	// BoundedStatementIndicators is the statement of a report with any FAIL
	// or LEAD row.
	BoundedStatementIndicators = "For the artifact identified by its hash, the Tier 1 checks found the indicators this report lists: " +
		"each FAIL is positive evidence, and each LEAD is a suspicious signal that needs review. " +
		"Rows marked NOT_TESTED were not examined, for the reason each row gives. Tier 1 runs no inference, so no model behavior was tested. " +
		"Every surface outside that scope is listed under Out of scope."
)

// A report that carries Tier 2 measurements has its own pair: the Tier 1
// pair says no model behavior was tested, which is no longer the whole story,
// and it would credit a Tier 2 row's indicator to the Tier 1 checks.
const (
	// BoundedStatementTier2NoIndicators is the statement of a report with
	// Tier 2 measurements and no FAIL or LEAD row.
	BoundedStatementTier2NoIndicators = "For the artifact identified by its hash, the Tier 1 checks that returned PASS found no indicators within their stated scope, and the Tier 2 measurements raised none. " +
		"Rows marked NOT_TESTED were not examined, for the reason each row gives. " +
		"Tier 2 ran the model only on the node classes and probe sets its measurements name, and a measurement that found nothing is not a PASS. " +
		"Every surface outside that scope is listed under Out of scope."
	// BoundedStatementTier2Indicators is the statement of a report with
	// Tier 2 measurements and any FAIL or LEAD row.
	BoundedStatementTier2Indicators = "For the artifact identified by its hash, the checks found the indicators this report lists: " +
		"each FAIL is positive evidence, and each LEAD is a suspicious signal that needs review; a row marked (Tier 2) was raised by a measurement made by running the model. " +
		"Rows marked NOT_TESTED were not examined, for the reason each row gives. " +
		"Tier 2 ran the model only on the node classes and probe sets its measurements name, and a measurement that found nothing is not a PASS. " +
		"Every surface outside that scope is listed under Out of scope."
)

// BoundedStatementFor picks the bounded statement for a report's check rows,
// so a report with a FAIL or a LEAD never says its checks found no indicators.
func BoundedStatementFor(checks []CheckResult) string {
	if hasIndicator(checks) {
		return BoundedStatementIndicators
	}
	return BoundedStatementNoIndicators
}

// BoundedStatementOf picks the bounded statement for a document: the Tier 2
// pair when it carries a Tier 2 section, else the Tier 1 pair, each by its
// check rows.
func BoundedStatementOf(d *Document) string {
	if d.Tier2 == nil {
		return BoundedStatementFor(d.Checks)
	}
	if hasIndicator(d.Checks) {
		return BoundedStatementTier2Indicators
	}
	return BoundedStatementTier2NoIndicators
}

func hasIndicator(checks []CheckResult) bool {
	for _, c := range checks {
		if c.Status == StatusFail || c.Status == StatusLead {
			return true
		}
	}
	return false
}

// DoesNotCertify is the fixed ceiling sentence.
const DoesNotCertify = "This attestation does not certify the absence of unknown backdoors."

// Tier1Assurance is the fixed statement of what a Tier 1 attestation means.
// Like the bounded statement, it must not be edited per artifact.
func Tier1Assurance() AssuranceLevel {
	return AssuranceLevel{
		Awarded:    "Tier 1 (static)",
		Definition: "Static checks on the artifact's bytes and metadata, run offline. No inference is run, and the weights are not evaluated for behavior.",
		DoesMean: "Each listed check ran on the exact bytes identified by the artifact hash, and each row states what its PASS means. " +
			"A FAIL carries positive evidence, a LEAD is a suspicious signal that needs a person's review, and a NOT_TESTED names why it was not tested. " +
			"A FAIL or a LEAD withholds promotion, and no acceptance clears it.",
		DoesNotMean: "It is not an assessment of the model's behavior or safety. It does not test the weights for backdoors or poisoning, " +
			"behavior that appears only after quantization or on particular hardware, or jailbreak susceptibility and harmful capability, " +
			"and it is not a legal review of the model's license.",
		Tier2Note: "Tier 2 (inference on the production node class) did not run.",
	}
}

// passMeaning is the fixed statement of what each check's PASS establishes,
// and where it stops. It is part of the report's wording, not per artifact,
// and a reader sees it beside every row.
var passMeaning = map[string]string{
	"Format and structure": "The container parsed, and its tensor data tiles the data section exactly: " +
		"no unaccounted bytes, overlapping tensors, or duplicate names.",
	"File inventory and payloads": "No script, shell command, long encoded blob, or executable signature was found in string metadata values, " +
		"including every string-array element of 64 bytes or more, and no native executable among the files. " +
		"Shorter array elements, such as vocabulary tokens, are too short to carry one and are not scanned.",
	"Chat template (hero)": "The template parsed and reaches no Python internals or process execution, " +
		"and carries no override or concealment language, URL, hidden or obfuscated text, or condition on message content. " +
		"Instructions written as ordinary guidance are not judged: when the template rendered, the notes list the text it adds " +
		"to the prompt and say whether it matches a reviewed template.",
	"Tokenizer config": "The tokenizer tables are internally consistent, and no control token carries instructions. " +
		"When a canonical reference table for its family is configured (from a feed or SOCAIR_TOKENIZER_REFERENCE), " +
		"every token was compared with it and no ordinary token differs; the notes say which reference, or that none was configured or matched.",
	"Quant match":        "At least one tensor has the base type the declared quantization requires. This checks labeling, not safety.",
	"Pickle opcode scan": "Every import the pickle makes is on the reviewed safe list.",
	"Remote code":        "No auto_map entry and no Python file: a loader would run no code from the repository.",
	"Hash, provenance, lineage": "A trusted publisher signature verified over this artifact, or an operator-supplied manifest binds this hash " +
		"to a repository at an immutable commit. The notes say which; a manifest is the operator's claim, not a signature.",
	"Known-bad hash match": "This exact hash is not on the configured denylist. Any changed byte gives a new hash, so it catches only known files.",
	"License policy": "The license the artifact states (model card, LICENSE file, or GGUF metadata) is on your allowed list. This is not legal advice: " +
		"usage-policy obligations, such as an acceptable-use policy or a user cap, are listed in the notes and not marked met.",
}

// PassMeaning returns the fixed PASS statement for a check row, or "" for a
// check without one.
func PassMeaning(check string) string { return passMeaning[check] }

// Status is a per-check result.
type Status string

const (
	StatusPass      Status = "PASS"
	StatusFail      Status = "FAIL"
	StatusNotTested Status = "NOT_TESTED"
	// StatusLead is a suspicious signal that is not conclusive, such as
	// instruction-override language in a chat template. It is not a gap: an
	// acceptance clears NOT_TESTED rows, never a LEAD. Like a FAIL, it
	// withholds promotion and needs a person's review outside Socair.
	StatusLead Status = "LEAD"
)

// Document is one rendered attestation.
type Document struct {
	SchemaVersion          string                 `json:"schema_version"`
	Header                 Header                 `json:"header"`
	Artifact               ArtifactIdentity       `json:"artifact"`
	Scope                  Scope                  `json:"scope"`
	Checks                 []CheckResult          `json:"checks"`
	Tier2                  *Tier2                 `json:"tier2,omitempty"` // absent unless Tier 2 ran (docs/tier2.md)
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
	// License is the license the artifact states, and every statement of it
	// the scan read (internal/checks/license). It is identity, not a check:
	// only a configured license policy grades it, in its own row.
	License *License `json:"license,omitempty"`
	// BaseModels are the models the artifact says it was derived from, as
	// it declares them. They are claims, not verified lineage.
	BaseModels []BaseModel `json:"base_models,omitempty"`
}

// License is the identified license. ID and Name are set when the artifact's
// statements name one license; Disagreement is set, and ID is not, when they
// name more than one. With neither, no license was identified, and Sources
// says what was read (none at all, when nothing states one).
type License struct {
	// ID is a ScanCode LicenseDB key, or a socair- key for a license
	// ScanCode does not key (internal/checks/license/catalogue.go).
	ID           string          `json:"id,omitempty"`
	Name         string          `json:"name,omitempty"`
	Sources      []LicenseSource `json:"sources,omitempty"`
	Disagreement string          `json:"disagreement,omitempty"`
}

// LicenseSource is one statement of the license and where it was read.
type LicenseSource struct {
	// Source is where: "model card license", "LICENSE", "GGUF
	// general.license", or a declared base model.
	Source string `json:"source"`
	// Value is what it said: a value, or a file's first line.
	Value string `json:"value"`
	// ID is the license it names, absent when it names none.
	ID string `json:"id,omitempty"`
	// Note says why it names none, or what kind of statement it is.
	Note string `json:"note,omitempty"`
}

// BaseModel is one declared base model.
type BaseModel struct {
	Name         string `json:"name"`
	Organization string `json:"organization,omitempty"`
	// Repo is the Hugging Face repo id, when the declaration names one.
	Repo string `json:"repo,omitempty"`
	// URL is the repository URL as a GGUF declares it.
	URL    string `json:"url,omitempty"`
	Source string `json:"source"`
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
	// ReferenceData names the reference data the checks compared against: a
	// signed feed (issuer, version, dates, key) and any local denylist.
	ReferenceData string `json:"reference_data,omitempty"`
}

type CheckResult struct {
	Name     string `json:"name"`
	LooksFor string `json:"looks_for"`
	Status   Status `json:"status"`
	Evidence string `json:"evidence,omitempty"`
	Notes    string `json:"notes,omitempty"`
	// PassMeans is the fixed statement of what this check's PASS establishes
	// and where it stops (PassMeaning). It is shown whatever the status.
	PassMeans string `json:"pass_means,omitempty"`
	// Severity grades a FAIL or LEAD row from its findings (RowSeverity). It
	// is for triage and does not change the promotion state.
	Severity string `json:"severity,omitempty"`
	// MapsTo names the external framework entries the check addresses
	// (MapsTo), for security questionnaires.
	MapsTo []FrameworkRef `json:"maps_to,omitempty"`
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
	// Acceptance is the acceptor's signed acceptance (internal/acceptance),
	// a DSSE envelope, base64-encoded. Empty means the acceptance is unsigned:
	// a name given at scan time (SOCAIR_ACCEPTED_BY), which the airlock does
	// not accept.
	Acceptance string `json:"acceptance,omitempty"`
	// ReviewedDocumentHash is the document hash of the withheld report the
	// acceptor reviewed and signed over.
	ReviewedDocumentHash string `json:"reviewed_document_hash,omitempty"`
}

// Signed reports whether the acceptance carries the acceptor's signature.
func (pa PromotionAuthorization) Signed() bool { return pa.Acceptance != "" }

// Accepted returns the surfaces an acceptance covers. Only an
// authorized_with_conditions report accepts anything, so for every other
// state it is nil whatever the document lists. Renderers print an acceptance
// only from it.
func (pa PromotionAuthorization) Accepted() []string {
	if pa.State != StateAuthorizedWithConditions {
		return nil
	}
	return pa.AcceptedSurfaces
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

// Unissued is the issuer of a report no key has signed.
const Unissued = "Unsigned: no issuer has signed this report"

func splitLabel(m *gguf.Manifest) string {
	if !m.MultiPart() {
		return ""
	}
	return fmt.Sprintf("part %d of %d", m.Split.No+1, m.Split.Count)
}

// DefaultCeiling is the published detection ceiling, per artifact.
func DefaultCeiling() []string {
	return []string{
		"Backdoors, trojans, or poisoning in the model weights. Tier 1 reads the weights' layout, never their behavior.",
		"Triggered, sleeper, or polymorphic behavior. Tier 1 runs no inference.",
		"Behavior that appears only after quantization, or only on particular hardware or serving stacks, unless Tier 2 ran on the production node class.",
		"Behavioral safety: jailbreak susceptibility, harmful capability, and bias.",
		"Malicious behavior that only emerges at runtime under real traffic.",
		"Artifact formats we do not parse.",
		"Pickle code execution reached only through imports on the reviewed safe list.",
		"Chat-template instructions written as ordinary guidance (no override or concealment phrase, URL, hidden or obfuscated text, or condition on message content): the text a rendered template adds is listed in the report, not judged, unless the template matches a reviewed template.",
		"Legal review of a license, and compliance with its usage policies. The license is identified, and checked only against a policy you configure.",
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
	// TokenizerSHA256 identifies the tokenizer: the SHA-256 of tokenizer.json
	// for a model directory, of the vocabulary (tokens in id order,
	// NUL-terminated) for a GGUF.
	TokenizerSHA256 string
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
			TokenizerHash:    id.TokenizerSHA256,
		},
		Scope: Scope{
			CheckSetVersion:  "tier1/0.1",
			ExecutionContext: "Tier 1 static, portable",
			InputPath:        "local path",
		},
		// No check has run, so no row is a FAIL or a LEAD yet; the engine
		// picks the statement again once the rows are in (BoundedStatementOf).
		BoundedStatement: BoundedStatementFor(nil),
		OutOfScope: OutOfScope{
			DoesNotCertify:      DoesNotCertify,
			Ceiling:             DefaultCeiling(),
			UntestedNodeClasses: []string{Tier1UntestedNodeClasses},
			NotRun:              Tier2NotRun(),
		},
		Verification: Verification{
			SigningMethod:  "unsigned",
			ArtifactSHA256: id.SHA256,
		},
		// No one has issued a report until a key signs it; signing names
		// the issuer (attest.Sign). Socair is the tool, not the issuer.
		Issuer: Issuer{
			Authority: Unissued,
			Excludes:  "No absence guarantee. See the bounded statement and out-of-scope ceiling.",
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
	if l := d.Artifact.License; l != nil && l.Disagreement != "" && l.ID != "" {
		problems = append(problems, "artifact.license: an identified license beside a disagreement; statements that disagree identify none")
	}
	req(len(d.Artifact.SHA256) == 64, "artifact.sha256 (64 hex chars)")
	req(strings.TrimSpace(d.Artifact.Format) != "", "artifact.format")
	req(len(d.Checks) > 0, "checks (at least one)")
	// The statement is re-derived from the rows, so neither an edited sentence
	// nor the no-indicators sentence over a FAIL or LEAD validates.
	req(d.BoundedStatement == BoundedStatementOf(d), "bounded_statement (must equal the fixed wording for these check rows)")
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
	problems = append(problems, validateTier2(d)...)
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
	problems = append(problems, validateAcceptance(d)...)
	// Only authorized_with_conditions accepts anything. A withheld report's
	// gaps are its NOT_TESTED rows; listing them as accepted surfaces would
	// tell a reader someone accepted them.
	if pa.State != StateAuthorizedWithConditions {
		if len(pa.AcceptedSurfaces) > 0 {
			problems = append(problems, fmt.Sprintf("promotion_authorization: a report in state %q must not carry accepted_surfaces; only authorized_with_conditions accepts", pa.State))
		}
		if pa.AcceptedBy != "" || pa.AcceptedAt != "" || pa.AcceptanceExpires != "" {
			problems = append(problems, fmt.Sprintf("promotion_authorization: a report in state %q must not carry accepted_by, accepted_at, or acceptance_expires", pa.State))
		}
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
				"promotion_authorization: state %q over %s row %q; a FAIL or LEAD withholds promotion, and no acceptance clears it", pa.State, c.Status, c.Name))
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

// validateAcceptance holds an embedded signed acceptance to the report that
// carries it: the same artifact and reviewed document, exactly the report's
// NOT_TESTED rows, and the same acceptor and times. Its signature is checked
// where keys are held (the airlock, socair verify); a report whose fields
// disagree with its own acceptance cannot be signed or verified at all.
func validateAcceptance(d *Document) []string {
	pa := d.PromotionAuthorization
	if pa.Acceptance == "" {
		if pa.ReviewedDocumentHash != "" {
			return []string{"promotion_authorization: reviewed_document_hash without a signed acceptance"}
		}
		return nil
	}
	if pa.State != StateAuthorizedWithConditions {
		return []string{fmt.Sprintf("promotion_authorization: a signed acceptance on a report whose state is %q", pa.State)}
	}
	raw, err := base64.StdEncoding.DecodeString(pa.Acceptance)
	if err != nil {
		return []string{"promotion_authorization.acceptance is not base64"}
	}
	a, err := acceptance.Parse(raw)
	if err != nil {
		return []string{"promotion_authorization.acceptance: " + err.Error()}
	}
	var gaps []string
	for _, c := range d.Checks {
		if c.Status == StatusNotTested {
			gaps = append(gaps, c.Name)
		}
	}
	var problems []string
	add := func(ok bool, what string) {
		if !ok {
			problems = append(problems, "promotion_authorization: the signed acceptance "+what)
		}
	}
	add(a.ArtifactSHA256 == strings.ToLower(d.Artifact.SHA256), "is for another artifact")
	add(a.ReviewedDocumentHash == pa.ReviewedDocumentHash, "names another reviewed document")
	add(acceptance.SameSurfaces(a.AcceptedSurfaces, gaps), "does not accept exactly this report's NOT_TESTED rows")
	add(acceptance.SameSurfaces(a.AcceptedSurfaces, pa.AcceptedSurfaces), "disagrees with accepted_surfaces")
	add(a.AcceptedBy == pa.AcceptedBy, "names another acceptor than accepted_by")
	add(a.AcceptedAt == pa.AcceptedAt, "disagrees with accepted_at")
	add(a.Expires == pa.AcceptanceExpires, "disagrees with acceptance_expires")
	return problems
}
