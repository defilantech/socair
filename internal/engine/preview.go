package engine

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/modeldir"
	"github.com/defilantech/socair/internal/report"
)

// A preview runs the checks on a model where it sits on the hub, before
// anyone downloads it: socair.ai/try runs it in the visitor's browser
// (cmd/socair-preview), reading each file through HTTP range requests, so it
// fetches only what the checks read (docs/preview.md).
//
// It is never an attestation, and the types say so. A preview is a Preview,
// not a report.Document: it has no promotion state, assurance level,
// issuer, or bounded statement, and attest.Sign and the airlock take only a
// report.Document. Its hashes are the ones the source states, never
// computed by Socair, and a check that would read a whole file is
// NOT_TESTED. Only PreviewDir and PreviewGGUF reach the stated-hash path;
// every scan passes it nil (TestScanNeverTakesStatedHashes).

const (
	// PreviewKind names the preview's format.
	PreviewKind = "socair.preview/v1"
	// PreviewNotice is the fixed statement every preview carries.
	PreviewNotice = "A preview, not an attestation. Socair's open engine ran on this model's headers and small files, read from the hub, and read no weights. It is unsigned and decides nothing: it has no promotion state, and no one vouches for it. To approve a model, pull it through the airlock, scan it in full, and sign the report with your own key."
	// PreviewHashes says where a preview's hashes come from.
	PreviewHashes = "File hashes are as the hub states them for its large (LFS) files, and computed by the preview from the bytes it read for the small ones. Socair hashed no weights, so the digest is of the stated hashes, not one Socair computed."
	// PreviewHeadersOnly opens the note of every row the preview did not run.
	PreviewHeadersOnly = "the preview reads headers only"
	// PreviewHub is the one source a preview reads.
	PreviewHub = "huggingface.co"
)

// PreviewSource is where a previewed model sits: the hub, the repo, and the
// full commit its revision resolved to.
type PreviewSource struct {
	Hub    string `json:"hub"`
	Repo   string `json:"repo"`
	Commit string `json:"commit"`
}

// PreviewFile is one file of a previewed model, with the hash its source
// states.
type PreviewFile struct {
	Path         string `json:"path"`
	StatedSHA256 string `json:"stated_sha256"`
	SizeBytes    int64  `json:"size_bytes"`
	Role         string `json:"role,omitempty"`
}

// PreviewModel is what the preview read about the model.
type PreviewModel struct {
	Name          string             `json:"name"`
	Architecture  string             `json:"architecture,omitempty"`
	Format        string             `json:"format"`
	SizeBytes     int64              `json:"size_bytes"`
	QuantDeclared string             `json:"quant_declared,omitempty"`
	QuantObserved string             `json:"quant_observed,omitempty"`
	License       *report.License    `json:"license,omitempty"`
	BaseModels    []report.BaseModel `json:"base_models,omitempty"`
	Files         []PreviewFile      `json:"files"`
	// StatedDigest is the manifest digest of the stated hashes (one file's
	// stated hash, for a single file): what the airlock stages the same
	// files as, if the hub's hashes hold.
	StatedDigest string `json:"stated_digest"`
}

// Preview is a header-only preview of a model on the hub.
type Preview struct {
	Kind            string               `json:"kind"`
	Notice          string               `json:"notice"`
	Hashes          string               `json:"hashes"`
	Source          PreviewSource        `json:"source"`
	Model           PreviewModel         `json:"model"`
	EngineVersion   string               `json:"engine_version"`
	CheckSetVersion string               `json:"check_set_version"`
	Checks          []report.CheckResult `json:"checks"`
	NotRun          []report.NotRunCheck `json:"not_run,omitempty"`
	UnparsedFormats []string             `json:"unparsed_formats,omitempty"`
	DoesNotCertify  string               `json:"does_not_certify"`
}

var (
	previewRepo = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,95}/[A-Za-z0-9][A-Za-z0-9._-]{0,95}$`)
	commitHex   = regexp.MustCompile(`^[0-9a-f]{40}$`)
	sha256Hex   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Check refuses a source the preview cannot name exactly: another hub, a
// malformed repo id, or a revision that is not a full commit. A branch name
// could mean different bytes tomorrow, so a preview names the commit it read.
func (s PreviewSource) Check() error {
	switch {
	case s.Hub != PreviewHub:
		return fmt.Errorf("a preview reads %s only, not %q", PreviewHub, s.Hub)
	case !previewRepo.MatchString(s.Repo) || strings.Contains(s.Repo, ".."):
		return fmt.Errorf("repo %q is not an org/name repo id", s.Repo)
	case !commitHex.MatchString(s.Commit):
		return fmt.Errorf("commit %q is not a full 40-hex commit; resolve the revision first", s.Commit)
	}
	return nil
}

// PreviewDir previews the model directory dir, a mount of src at its commit,
// reading it in place. stated gives every file's SHA-256 by its path in
// dir, as src states it; a file without one stops the preview, naming it.
// No reference data and no Tier 2 run: a preview has none of an
// organization's inputs.
func PreviewDir(dir string, src PreviewSource, stated map[string]string) (*Preview, error) {
	if err := src.Check(); err != nil {
		return nil, err
	}
	if stated == nil {
		return nil, errors.New("a preview needs the hashes its source states")
	}
	d, err := scanDir(dir, time.Now().UTC(), &references{}, Inputs{noEnv: true}, nil, stated)
	if err != nil {
		return nil, err
	}
	return previewOf(d, src, d.Artifact.Files, d.Artifact.SHA256), nil
}

// PreviewGGUF previews one GGUF file, whose own metadata carries the chat
// template, tokenizer, and quant rows, read in place in header mode.
// statedSHA256 is its hash as src states it.
func PreviewGGUF(file string, src PreviewSource, statedSHA256 string) (*Preview, error) {
	if err := src.Check(); err != nil {
		return nil, err
	}
	if strings.ToLower(path.Ext(file)) != ".gguf" {
		return nil, fmt.Errorf("%s: PreviewGGUF previews a .gguf file", file)
	}
	if !sha256Hex.MatchString(statedSHA256) {
		return nil, fmt.Errorf("a preview needs the file's SHA-256 from its source; none stated for %s", path.Base(file))
	}
	d, err := scanFile(file, ModeHeaders, time.Now().UTC(), &references{}, Inputs{noEnv: true}, nil)
	if err != nil {
		return nil, err
	}
	f := report.ArtifactFile{Path: path.Base(file), SHA256: statedSHA256, SizeBytes: d.Artifact.SizeBytes, Role: modeldir.RoleWeights}
	return previewOf(d, src, []report.ArtifactFile{f}, statedSHA256), nil
}

// previewOf keeps the rows and what was read, and leaves out everything an
// attestation adds.
func previewOf(d *report.Document, src PreviewSource, files []report.ArtifactFile, digest string) *Preview {
	p := &Preview{
		Kind:   PreviewKind,
		Notice: PreviewNotice,
		Hashes: PreviewHashes,
		Source: src,
		Model: PreviewModel{
			Name:          src.Repo,
			Architecture:  d.Artifact.Architecture,
			Format:        d.Artifact.Format,
			SizeBytes:     d.Artifact.SizeBytes,
			QuantDeclared: d.Artifact.QuantDeclared,
			QuantObserved: d.Artifact.QuantObserved,
			License:       d.Artifact.License,
			BaseModels:    d.Artifact.BaseModels,
			StatedDigest:  digest,
		},
		EngineVersion:   Version,
		CheckSetVersion: d.Scope.CheckSetVersion,
		Checks:          d.Checks,
		NotRun:          d.OutOfScope.NotRun,
		UnparsedFormats: d.OutOfScope.UnparsedFormats,
		DoesNotCertify:  d.OutOfScope.DoesNotCertify,
	}
	for _, f := range files {
		p.Model.Files = append(p.Model.Files, PreviewFile{Path: f.Path, StatedSHA256: f.SHA256, SizeBytes: f.SizeBytes, Role: f.Role})
	}
	return p
}

// headersOnly is the row, or the part of a row, for a check the preview did
// not run because it reads a whole file.
func headersOnly(name, looksFor, why string) checks.Result {
	return checks.Result{Name: name, LooksFor: looksFor, Status: checks.NotTested,
		Notes: PreviewHeadersOnly + ": " + why + ". Pull the model through the airlock and scan it to run this check"}
}
