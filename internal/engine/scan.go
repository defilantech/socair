// Package engine runs the Tier 1 checks over an artifact and produces the
// report document. It is the single path the CLI and the click-ops wizard both
// call.
package engine

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/checks/chattemplate"
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
const CheckSetVersion = "tier1/0.6"

// Version is the socair version: "dev" in a source build, the release tag
// in a release build (scripts/build-release.sh sets it with -ldflags -X).
// Reports record it in scope.tool_versions.
var Version = "dev"

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
	// Reference data first: a feed that does not verify stops the scan before
	// any snapshot is copied.
	refs, err := loadReferences(start)
	if err != nil {
		return nil, err
	}
	if fi, err := os.Stat(path); err == nil && fi.IsDir() {
		if mode != ModeFull {
			return nil, fmt.Errorf("%s is a directory; a directory scan always reads every file in full", path)
		}
		return scanDir(path, start, refs)
	}

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
		id.TokenizerSHA256 = tokenizer.VocabHash(m.Tokenizer.Tokens)
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

	var sig *provenance.Signature
	if mode == ModeFull {
		var err error
		if sig, err = fileSignature(original, id.SHA256); err != nil {
			return nil, err
		}
	}
	d, provOpts, expires, err := begin(start, id, original, sig)
	if err != nil {
		return nil, err
	}
	d.Scope.ReferenceData = refs.scope()

	// The check set is per format: a GGUF carries metadata checks that a pickle
	// checkpoint does not, and vice versa. The report lists only what ran.
	results := []checks.Result{
		structure.Validate(path),
		inventory.Inspect(path, inventory.Options{RepoMirror: os.Getenv("SOCAIR_REPO_MIRROR")}),
		// Provenance reads signature sidecars beside the artifact, so it looks
		// next to the original, not the snapshot.
		provenance.Inspect(provOpts),
		refs.denylist(id.SHA256),
	}
	if id.Format == "GGUF" {
		tokRow := tokenizer.InspectGGUF(tokenizerModel, tok, chatTemplates)
		tokRow.Notes += refs.tokenizerNote(id.TokenizerSHA256)
		tokRow = refs.compareTokenizer(tokRow, tok.Tokens, tokenizer.GGUFSpecial(tok))
		meta := []checks.Result{
			chattemplate.InspectAllWith(chatTemplates, chatTemplateNonString, refs.reviewedTemplates()),
			tokRow,
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
	return finish(d, results, unparsedFormats(id), expires), nil
}

// begin seeds the document every scan path fills: header, re-scan policy,
// scope, and identity fields from a provenance manifest bound to id's hash.
func begin(start time.Time, id report.Identity, original string, sig *provenance.Signature) (*report.Document, provenance.Options, string, error) {
	d := report.NewFromIdentity(id)
	d.Header.DocumentID = fmt.Sprintf("SOCAIR-%s-%s", start.Format("20060102"), shortHashOr(id.SHA256, "headers"))
	d.Header.IssuedUTC = start.Format(time.RFC3339)
	rescanDue, expires, err := acceptancePolicy(start, os.Getenv("SOCAIR_RESCAN_DAYS"), os.Getenv("SOCAIR_ACCEPTANCE_EXPIRES"))
	if err != nil {
		return nil, provenance.Options{}, "", err
	}
	d.Header.RescanDue = rescanDue
	d.Header.ArtifactShort = id.Name
	d.AssuranceLevel = report.Tier1Assurance()
	d.Header.AssuranceLevelAwarded = d.AssuranceLevel.Awarded
	d.Scope.CheckSetVersion = CheckSetVersion
	d.Scope.ScanStartUTC = start.Format(time.RFC3339)
	d.Scope.ToolVersions = "socair " + Version
	d.Verification.RerunInstructions = "socair scan <path>"

	// Provenance comes only from the manifest the operator names. A
	// provenance.json found beside the artifact is not read: whoever controls
	// that directory could write one claiming any origin for these bytes.
	provOpts := provenance.Options{ArtifactPath: original, ArtifactSHA256: id.SHA256, ManifestPath: os.Getenv("SOCAIR_PROVENANCE"), Signature: sig}
	if m, unbound := provenance.Bind(provOpts); m != nil && unbound == "" {
		d.Artifact.RepoURL = m.RepoURL
		d.Artifact.CommitOrTag = m.CommitOrTag
		d.Artifact.CommitSHA = m.CommitSHA
		d.Artifact.Publisher = m.Publisher
		d.Artifact.PublisherSigningState = publisherSigning(m.SigningStatus)
		if m.Source != "" {
			d.Scope.InputPath = m.Source
		}
	}
	// A checked publisher signature outranks a manifest's claim about one.
	if sig != nil {
		d.Artifact.PublisherSigningState = signingState(sig)
		if sig.State == provenance.SignatureVerified && d.Artifact.Publisher == "" {
			d.Artifact.Publisher = sig.Signer
		}
	}

	return d, provOpts, expires, nil
}

// finish records the check rows and computes the promotion state.
func finish(d *report.Document, results []checks.Result, unparsed []string, expires string) *report.Document {
	applyResults(d, results)
	d.OutOfScope.UnparsedFormats = unparsed
	d.Scope.ScanEndUTC = time.Now().UTC().Format(time.RFC3339)
	finalizeFindings(d)
	d.PromotionAuthorization = promotion(d, os.Getenv("SOCAIR_ACCEPTED_BY"), expires)
	return d
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

// DefaultRescanDays is how long a Tier 1 result stands before the artifact is
// due a re-scan, absent SOCAIR_RESCAN_DAYS. Detectors and allowlists move.
const DefaultRescanDays = 90

// acceptancePolicy computes when the artifact is due a re-scan and when an
// acceptance of its gaps lapses. An acceptance always expires: absent
// SOCAIR_ACCEPTANCE_EXPIRES it lapses at the re-scan. A value that is not RFC
// 3339, or already past, is an error rather than an acceptance that cannot be
// enforced.
func acceptancePolicy(start time.Time, rescanDays, expiresEnv string) (rescanDue, expires string, err error) {
	days := DefaultRescanDays
	if v := strings.TrimSpace(rescanDays); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 3650 {
			return "", "", fmt.Errorf("SOCAIR_RESCAN_DAYS %q: want a whole number of days from 1 to 3650", v)
		}
		days = n
	}
	rescanDue = start.UTC().AddDate(0, 0, days).Format(time.RFC3339)

	v := strings.TrimSpace(expiresEnv)
	if v == "" {
		return rescanDue, rescanDue, nil
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return "", "", fmt.Errorf("SOCAIR_ACCEPTANCE_EXPIRES %q is not an RFC 3339 time, e.g. 2027-01-31T00:00:00Z", v)
	}
	if !t.After(start) {
		return "", "", fmt.Errorf("SOCAIR_ACCEPTANCE_EXPIRES %s is already past", t.UTC().Format(time.RFC3339))
	}
	return rescanDue, t.UTC().Format(time.RFC3339), nil
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
			" are NOT_TESTED and were accepted by " + acceptedBy + " until " + expires +
			". The acceptance is unsigned (named at scan time): the airlock promotes only an acceptance the acceptor signs (socair accept)."
	}
	return pa
}

func applyResults(d *report.Document, results []checks.Result) {
	d.Checks = make([]report.CheckResult, 0, len(results))
	for _, res := range results {
		d.Checks = append(d.Checks, report.CheckResult{
			Name:      res.Name,
			LooksFor:  res.LooksFor,
			Status:    report.Status(res.Status),
			Evidence:  evidence(res),
			Notes:     res.Notes,
			PassMeans: report.PassMeaning(res.Name),
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

// publisherSigning states a manifest's signing claim for the identity
// section. It is the manifest's claim; verifying a publisher signature is a
// separate check.
func publisherSigning(status string) string {
	switch s := strings.ToLower(strings.TrimSpace(status)); s {
	case "":
		return "not established"
	case "unsigned":
		return "unsigned"
	default:
		return s + " (claimed by the provenance manifest, not verified)"
	}
}

// unparsedFormats names what this scan did not parse: an artifact in no
// format it reads, the other shards of a split model, and, when a repo
// mirror is supplied, the model and serialization files beside the artifact.
func unparsedFormats(id report.Identity) []string {
	var out []string
	if id.Format == "unknown" {
		out = append(out, "artifact "+id.FileName+": not GGUF, safetensors, or pickle, so no format check ran")
	}
	if id.Split != "" {
		out = append(out, "the other shards of this split model (this file is "+id.Split+"); each shard needs its own attestation")
	}
	if mirror := os.Getenv("SOCAIR_REPO_MIRROR"); mirror != "" {
		if formats, err := inventory.UnparsedFormats(mirror, id.FileName); err == nil {
			out = append(out, formats...)
		}
	}
	return out
}
