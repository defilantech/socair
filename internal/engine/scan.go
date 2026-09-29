// Package engine runs the Tier 1 checks over an artifact and produces the
// report document. It is the single path the CLI and the click-ops wizard both
// call.
package engine

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/checks/chattemplate"
	"github.com/defilantech/socair/internal/checks/denylist"
	"github.com/defilantech/socair/internal/checks/inventory"
	"github.com/defilantech/socair/internal/checks/pickle"
	"github.com/defilantech/socair/internal/checks/provenance"
	"github.com/defilantech/socair/internal/checks/quant"
	"github.com/defilantech/socair/internal/checks/structure"
	"github.com/defilantech/socair/internal/checks/tokenizer"
	"github.com/defilantech/socair/internal/gguf"
	"github.com/defilantech/socair/internal/report"
	"github.com/defilantech/socair/internal/safetensors"
)

// CheckSetVersion names the set of checks this engine runs.
const CheckSetVersion = "tier1/0.1"

// Version is the engine version, set by the CLI build.
var Version = "0.1.0-dev"

// Mode selects how much of the artifact a scan reads.
type Mode int

const (
	// ModeFull hashes the whole file. Use it for any attestation.
	ModeFull Mode = iota
	// ModeHeaders reads container metadata only. Use it for baseline sweeps
	// across many models, where hashing gigabytes per file buys nothing.
	ModeHeaders
)

// Scan reads the artifact at path and returns a filled report document, hashing
// the full file. It is the attestation path.
func Scan(path string) (*report.Document, error) { return ScanMode(path, ModeFull) }

// ScanMode reads the artifact at path in the given mode and returns a filled
// report document.
func ScanMode(path string, mode Mode) (*report.Document, error) {
	start := time.Now().UTC()

	var id report.Identity
	var chatTemplate string
	var tokenizerModel string
	var quantDeclared string
	var fileType *uint32

	if safetensors.IsSafetensors(path) {
		m, err := readSafetensors(path, mode)
		if err != nil {
			return nil, err
		}
		id = report.Identity{
			Name:      "",
			FileName:  m.FileName,
			SHA256:    m.SHA256,
			Format:    m.Format,
			SizeBytes: m.SizeBytes,
		}
	} else {
		m, err := readGGUF(path, mode)
		if err != nil {
			return nil, err
		}
		id = report.Identity{
			Name:               m.Name,
			Architecture:       m.Architecture,
			FileName:           m.FileName,
			SHA256:             m.SHA256,
			Format:             m.Format,
			SizeBytes:          m.SizeBytes,
			QuantDeclared:      m.Quant.Declared,
			ChatTemplateSHA256: m.ChatTemplateSHA256,
		}
		if m.Quant.FileType != nil {
			id.QuantObserved = fmt.Sprintf("file_type=%d", *m.Quant.FileType)
		}
		if m.MultiPart() {
			id.Split = fmt.Sprintf("part %d of %d", m.Split.No+1, m.Split.Count)
		}
		chatTemplate = m.ChatTemplate
		tokenizerModel = m.TokenizerModel
		quantDeclared = m.Quant.Declared
		fileType = m.Quant.FileType
	}

	if id.Name == "" {
		id.Name = id.FileName
	}

	d := report.NewFromIdentity(id)
	d.Header.DocumentID = fmt.Sprintf("SOCAIR-%s-%s", start.Format("20060102"), shortHashOr(id.SHA256, "headers"))
	d.Header.IssuedUTC = start.Format(time.RFC3339)
	d.Header.ArtifactShort = id.Name
	d.Header.AssuranceLevelAwarded = "Tier 1 (static)"
	d.Scope.CheckSetVersion = CheckSetVersion
	d.Scope.ScanStartUTC = start.Format(time.RFC3339)
	d.Scope.ToolVersions = "socair " + Version
	d.Verification.RerunInstructions = "socair scan <path>"

	results := []checks.Result{
		structure.Validate(path),
		chattemplate.Inspect(chatTemplate),
		tokenizer.Inspect(tokenizerModel),
		quant.Compare(quantDeclared, fileType),
		inventory.Inspect(path, inventory.Options{RepoMirror: os.Getenv("SOCAIR_REPO_MIRROR")}),
		provenance.Inspect(provenance.Options{ArtifactPath: path, ManifestPath: os.Getenv("SOCAIR_PROVENANCE")}),
		denylist.Check(id.SHA256, os.Getenv("SOCAIR_DENYLIST")),
		pickle.Inspect(path),
	}
	applyResults(d, results)

	d.Scope.ScanEndUTC = time.Now().UTC().Format(time.RFC3339)
	finalizeFindings(d)
	d.PromotionAuthorization = promotion(d, os.Getenv("SOCAIR_ACCEPTED_BY"), os.Getenv("SOCAIR_ACCEPTANCE_EXPIRES"))
	return d, nil
}

func readGGUF(path string, mode Mode) (*gguf.Manifest, error) {
	if mode == ModeHeaders {
		return gguf.ReadHeader(path)
	}
	return gguf.ReadArtifact(path)
}

func readSafetensors(path string, mode Mode) (*safetensors.Manifest, error) {
	if mode == ModeHeaders {
		return safetensors.ReadHeader(path)
	}
	return safetensors.ReadArtifact(path)
}

// promotion computes the promotion state. A FAIL withholds and is clearable
// only by escalation. A gap (NOT_TESTED) withholds until a named acceptance is
// supplied, and the accepted surfaces travel with the artifact.
func promotion(d *report.Document, acceptedBy, expires string) report.PromotionAuthorization {
	var fails, gaps []string
	for _, c := range d.Checks {
		switch c.Status {
		case report.StatusFail:
			fails = append(fails, c.Name)
		case report.StatusNotTested:
			gaps = append(gaps, c.Name)
		}
	}

	pa := report.PromotionAuthorization{Level: "Tier 1 only", AcceptedSurfaces: gaps, AcceptanceExpires: expires}

	switch {
	case len(fails) > 0:
		pa.State = report.StateWithheld
		pa.Authorized = false
		pa.Conditions = "Withheld: positive evidence on " + strings.Join(fails, ", ") +
			". A FAIL is clearable only by escalated review."
	case len(gaps) == 0:
		pa.State = report.StateAuthorized
		pa.Authorized = true
		pa.AcceptedSurfaces = nil
		pa.Conditions = "Every Tier 1 check PASSed."
	case strings.TrimSpace(acceptedBy) == "":
		pa.State = report.StateWithheld
		pa.Authorized = false
		pa.Conditions = "Withheld: " + strings.Join(gaps, ", ") +
			" are NOT_TESTED and no acceptance has been recorded (set SOCAIR_ACCEPTED_BY)."
	default:
		pa.State = report.StateAuthorizedWithConditions
		pa.Authorized = true
		pa.AcceptedBy = acceptedBy
		pa.AcceptedAt = time.Now().UTC().Format(time.RFC3339)
		pa.Conditions = "Authorized with conditions: " + strings.Join(gaps, ", ") +
			" are NOT_TESTED and were accepted by " + acceptedBy + "."
	}
	return pa
}

func applyResults(d *report.Document, results []checks.Result) {
	for _, res := range results {
		for i := range d.Checks {
			if d.Checks[i].Name != res.Name {
				continue
			}
			d.Checks[i].Status = report.Status(res.Status)
			d.Checks[i].Notes = res.Notes
			d.Checks[i].Evidence = evidence(res)
		}
	}
}

func evidence(res checks.Result) string {
	if len(res.Findings) == 0 {
		return ""
	}
	parts := make([]string, 0, len(res.Findings))
	for _, f := range res.Findings {
		s := f.Pattern
		if f.Span != "" {
			s += ": " + f.Span
		}
		if f.Detail != "" {
			s += " (" + f.Detail + ")"
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, "; ")
}

func finalizeFindings(d *report.Document) {
	d.Findings.Fails = nil
	d.Findings.NotTested = nil
	for _, c := range d.Checks {
		switch c.Status {
		case report.StatusFail:
			d.Findings.Fails = append(d.Findings.Fails, c.Name)
		case report.StatusNotTested:
			d.Findings.NotTested = append(d.Findings.NotTested, c.Name)
		}
	}
}

func shortHashOr(sha, fallback string) string {
	if len(sha) >= 8 {
		return sha[:8]
	}
	return fallback
}
