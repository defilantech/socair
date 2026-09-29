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
	"github.com/defilantech/socair/internal/checks/inventory"
	"github.com/defilantech/socair/internal/checks/quant"
	"github.com/defilantech/socair/internal/checks/structure"
	"github.com/defilantech/socair/internal/checks/tokenizer"
	"github.com/defilantech/socair/internal/gguf"
	"github.com/defilantech/socair/internal/report"
)

// CheckSetVersion names the set of checks this engine runs.
const CheckSetVersion = "tier1/0.1"

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

	var m *gguf.Manifest
	var err error
	if mode == ModeHeaders {
		m, err = gguf.ReadHeader(path)
	} else {
		m, err = gguf.ReadArtifact(path)
	}
	if err != nil {
		return nil, err
	}

	d := report.NewFromManifest(m)
	d.Header.DocumentID = fmt.Sprintf("SOCAIR-%s-%s", start.Format("20060102"), shortHashOr(m.SHA256, "headers"))
	d.Header.IssuedUTC = start.Format(time.RFC3339)
	d.Header.AssuranceLevelAwarded = "Tier 1 (static)"
	d.Artifact.Name = m.Name
	d.Artifact.ChatTemplateHash = m.ChatTemplateSHA256
	d.Scope.CheckSetVersion = CheckSetVersion
	d.Scope.ScanStartUTC = start.Format(time.RFC3339)
	d.Scope.ToolVersions = "socair " + Version
	d.Verification.RerunInstructions = "socair scan <path>"

	results := []checks.Result{
		structure.Validate(path),
		chattemplate.Inspect(m.ChatTemplate),
		tokenizer.Inspect(m.TokenizerModel),
		quant.Compare(m.Quant.Declared, m.Quant.FileType),
		inventory.Inspect(path, inventory.Options{RepoMirror: os.Getenv("SOCAIR_REPO_MIRROR")}),
	}
	applyResults(d, results)

	d.Scope.ScanEndUTC = time.Now().UTC().Format(time.RFC3339)
	finalizeFindings(d)
	d.PromotionAuthorization = report.PromotionAuthorization{
		Authorized: allPass(d.Checks),
		Level:      "Tier 1 only",
		Conditions: "Promotion requires every Tier 1 check to PASS. Any NOT_TESTED withholds authorization.",
	}
	return d, nil
}

// Version is the engine version, set by the CLI build.
var Version = "0.1.0-dev"

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

func allPass(cs []report.CheckResult) bool {
	for _, c := range cs {
		if c.Status != report.StatusPass {
			return false
		}
	}
	return true
}

func shortHashOr(sha, fallback string) string {
	if len(sha) >= 8 {
		return sha[:8]
	}
	return fallback
}
