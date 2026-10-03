// Package engine runs the Tier 1 checks over an artifact and produces the
// report document. It is the single path the CLI and the click-ops wizard both
// call.
package engine

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
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

	// A full scan is an attestation, so it checks a private snapshot whose
	// bytes it hashed while copying (see snapshot). A header-only sweep
	// attests nothing and reads in place.
	original := path
	sha := ""
	if mode == ModeFull {
		snap, digest, cleanup, err := snapshot(path)
		if err != nil {
			return nil, err
		}
		defer cleanup()
		path, sha = snap, digest
		if afterSnapshot != nil {
			afterSnapshot(original)
		}
	}

	var id report.Identity
	var ggufErr error
	var chatTemplates map[string]string
	var chatTemplateNonString []string
	var tokenizerModel string
	var tok gguf.Tokenizer
	var quantDeclared string
	var fileType *uint32
	var observedTypes []gguf.TypeShare

	if safetensors.IsSafetensors(path) {
		m, err := safetensors.ReadHeader(path)
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
	} else if isGGUF, err := gguf.IsGGUF(path); err != nil {
		return nil, err
	} else if !isGGUF {
		// Not a container this engine parses: pickle checkpoints and anything
		// unrecognized. The scan still reports, so the pickle check runs on the
		// format it exists for and every unparsed surface is NOT_TESTED rather
		// than an aborted scan.
		o, err := readOpaque(path)
		if err != nil {
			return nil, err
		}
		id = o
	} else if m, err := gguf.ReadHeader(path); err != nil {
		// A GGUF that does not parse (truncated, an unsupported version, a
		// malformed header) still gets a report: the artifact is identified
		// and hashed, the structure row names the parse error, and the rows
		// that read metadata say the metadata was not read. An aborted scan
		// would leave the operator with nothing to file.
		o, oerr := readOpaque(path)
		if oerr != nil {
			return nil, oerr
		}
		o.Format = "GGUF"
		id = o
		ggufErr = err
	} else {
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
		observedTypes = m.TypeHistogram()
		if h := gguf.HistogramString(observedTypes); h != "" {
			id.QuantObserved = h + " (tensor data by type)"
		} else if m.Quant.FileType != nil {
			id.QuantObserved = fmt.Sprintf("file_type=%d (metadata label; no tensor data)", *m.Quant.FileType)
		}
		if m.MultiPart() {
			id.Split = fmt.Sprintf("part %d of %d", m.Split.No+1, m.Split.Count)
		}
		chatTemplates = m.ChatTemplates
		chatTemplateNonString = m.ChatTemplateNonString
		tokenizerModel = m.TokenizerModel
		tok = m.Tokenizer
		quantDeclared = m.Quant.Declared
		fileType = m.Quant.FileType
	}

	if id.Name == "" {
		id.Name = id.FileName
	}
	id.SHA256 = sha

	d := report.NewFromIdentity(id)
	d.Header.DocumentID = fmt.Sprintf("SOCAIR-%s-%s", start.Format("20060102"), shortHashOr(id.SHA256, "headers"))
	d.Header.IssuedUTC = start.Format(time.RFC3339)
	d.Header.ArtifactShort = id.Name
	d.Header.AssuranceLevelAwarded = "Tier 1 (static)"
	d.Scope.CheckSetVersion = CheckSetVersion
	d.Scope.ScanStartUTC = start.Format(time.RFC3339)
	d.Scope.ToolVersions = "socair " + Version
	d.Verification.RerunInstructions = "socair scan <path>"

	// The check set is per format: a GGUF carries metadata checks that a pickle
	// checkpoint does not, and vice versa. The report lists only what ran.
	results := []checks.Result{
		structure.Validate(path),
		inventory.Inspect(path, inventory.Options{RepoMirror: os.Getenv("SOCAIR_REPO_MIRROR")}),
		// Provenance reads signature sidecars beside the artifact, so it looks
		// next to the original, not the snapshot.
		provenance.Inspect(provenance.Options{ArtifactPath: original, ManifestPath: os.Getenv("SOCAIR_PROVENANCE")}),
		denylist.Check(id.SHA256, os.Getenv("SOCAIR_DENYLIST")),
	}
	if id.Format == "GGUF" {
		meta := []checks.Result{
			chattemplate.InspectAll(chatTemplates, chatTemplateNonString),
			tokenizer.InspectGGUF(tokenizerModel, tok, chatTemplates),
			quant.CompareObserved(quantDeclared, fileType, observedTypes),
		}
		if ggufErr != nil {
			for i := range meta {
				meta[i] = checks.Result{Name: meta[i].Name, LooksFor: meta[i].LooksFor, Status: checks.NotTested,
					Notes: "GGUF metadata could not be read, so this was not inspected: " + ggufErr.Error()}
			}
		}
		results = append(results, meta...)
	}
	if id.Format != "GGUF" && id.Format != "safetensors" {
		results = append(results, pickle.Inspect(path))
	}
	applyResults(d, results)

	d.Scope.ScanEndUTC = time.Now().UTC().Format(time.RFC3339)
	finalizeFindings(d)
	d.PromotionAuthorization = promotion(d, os.Getenv("SOCAIR_ACCEPTED_BY"), os.Getenv("SOCAIR_ACCEPTANCE_EXPIRES"))
	return d, nil
}

// readOpaque identifies an artifact in no container this engine parses. The
// format is named from the leading bytes, never from the extension. The hash
// comes from the snapshot, not from here.
func readOpaque(path string) (report.Identity, error) {
	f, err := os.Open(path)
	if err != nil {
		return report.Identity{}, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return report.Identity{}, err
	}
	id := report.Identity{
		FileName:  filepath.Base(path),
		SizeBytes: st.Size(),
		Format:    "unknown",
	}

	var head [4]byte
	n, _ := io.ReadFull(f, head[:])
	switch {
	case n >= 1 && head[0] == 0x80:
		id.Format = "pickle"
	case n == 4 && string(head[:]) == "PK\x03\x04":
		id.Format = "zip"
	}
	return id, nil
}

// promotion computes the promotion state. A FAIL or a LEAD withholds and is
// clearable only by escalation. A gap (NOT_TESTED) withholds until a named
// acceptance is supplied, and the accepted surfaces travel with the artifact.
func promotion(d *report.Document, acceptedBy, expires string) report.PromotionAuthorization {
	var fails, leads, gaps []string
	for _, c := range d.Checks {
		switch c.Status {
		case report.StatusFail:
			fails = append(fails, c.Name)
		case report.StatusLead:
			leads = append(leads, c.Name)
		case report.StatusNotTested:
			gaps = append(gaps, c.Name)
		}
	}

	pa := report.PromotionAuthorization{Level: "Tier 1 only", AcceptedSurfaces: gaps, AcceptanceExpires: expires}

	switch {
	case len(fails) > 0 || len(leads) > 0:
		var why []string
		if len(fails) > 0 {
			why = append(why, "positive evidence on "+strings.Join(fails, ", "))
		}
		if len(leads) > 0 {
			why = append(why, "a suspicious lead on "+strings.Join(leads, ", "))
		}
		pa.State = report.StateWithheld
		pa.Authorized = false
		pa.Conditions = "Withheld: " + strings.Join(why, "; ") +
			". A FAIL or a LEAD is clearable only by escalated review, never by an acceptance."
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
	d.Checks = make([]report.CheckResult, 0, len(results))
	for _, res := range results {
		d.Checks = append(d.Checks, report.CheckResult{
			Name:     res.Name,
			LooksFor: res.LooksFor,
			Status:   report.Status(res.Status),
			Evidence: evidence(res),
			Notes:    res.Notes,
		})
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
	d.Findings.Leads = nil
	d.Findings.NotTested = nil
	for _, c := range d.Checks {
		switch c.Status {
		case report.StatusFail:
			d.Findings.Fails = append(d.Findings.Fails, c.Name)
		case report.StatusLead:
			d.Findings.Leads = append(d.Findings.Leads, c.Name)
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
