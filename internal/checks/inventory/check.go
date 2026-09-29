// Package inventory answers the signed claim "no hidden files": does the
// artifact, or the repo mirror when one is provided, carry an embedded payload
// or an unexpected executable.
//
// The artifact side is high-confidence and can FAIL. The repo side is
// deliberately conservative: model repos legitimately ship config.py and
// tokenizer files, so those are inventoried, not failed. Only a real binary
// executable in the repo is a FAIL.
package inventory

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/gguf"
	"github.com/defilantech/socair/internal/safetensors"
)

// Options configures the inventory check.
type Options struct {
	// RepoMirror is a local directory holding the source repo listing. Empty
	// means the repo side is NOT_TESTED, not a pass.
	RepoMirror string
}

// payload patterns are high-confidence indicators of an embedded executable or
// archive inside artifact metadata.
var (
	scriptTag  = regexp.MustCompile(`(?i)<script\b|#!/bin/(sh|bash)|powershell\s+-|Invoke-Expression`)
	base64Blob = regexp.MustCompile(`[A-Za-z0-9+/]{512,}={0,2}`)
)

// binaryMagics are executable or archive container headers.
var binaryMagics = [][]byte{
	{0x7f, 'E', 'L', 'F'},    // ELF
	{'M', 'Z'},               // PE
	{0x50, 0x4b, 0x03, 0x04}, // zip
	{0x1f, 0x8b},             // gzip
	{0xfe, 0xed, 0xfa, 0xce}, // Mach-O
	{0xce, 0xfa, 0xed, 0xfe}, // Mach-O
}

// Inspect runs the inventory check over an artifact and an optional repo
// mirror.
func Inspect(path string, opts Options) checks.Result {
	r := checks.Result{
		Name:     "File inventory and payloads",
		LooksFor: "Hidden files, embedded payloads, unexpected executables",
	}

	var strings []string
	var invNote string
	switch {
	case safetensors.IsSafetensors(path):
		sm, err := safetensors.ReadArtifact(path)
		if err != nil {
			r.Status = checks.NotTested
			r.Notes = "could not read safetensors header: " + err.Error()
			return r
		}
		for _, v := range sm.Metadata {
			strings = append(strings, v)
		}
		invNote = fmt.Sprintf("artifact: safetensors header, %d tensors, %d metadata keys", sm.TensorCount, len(sm.MetadataKeys))
	default:
		inv, err := gguf.Inventory(path)
		if err != nil {
			r.Status = checks.NotTested
			if errors.Is(err, gguf.ErrNotGGUF) {
				r.Notes = "not a GGUF or safetensors artifact; cannot inventory"
			} else {
				r.Notes = "could not read artifact metadata: " + err.Error()
			}
			return r
		}
		strings = inv.Strings
		invNote = fmt.Sprintf("artifact: %d metadata keys, %d string bytes", len(inv.Keys), inv.TotalStrings)
		if inv.Truncated {
			invNote += " (inventory truncated at the cap)"
		}
	}

	for _, s := range strings {
		if m := scriptTag.FindString(s); m != "" {
			r.Findings = append(r.Findings, checks.Finding{
				Pattern: "embedded-script",
				Span:    excerpt(m),
				Detail:  "artifact metadata carries script or shell content",
			})
		}
		if m := base64Blob.FindString(s); m != "" {
			r.Findings = append(r.Findings, checks.Finding{
				Pattern: "embedded-base64-blob",
				Span:    excerpt(m),
				Detail:  "artifact metadata carries a large base64 blob",
			})
		}
		for _, magic := range binaryMagics {
			if bytes.Contains([]byte(s), magic) {
				r.Findings = append(r.Findings, checks.Finding{
					Pattern: "embedded-binary",
					Detail:  fmt.Sprintf("artifact metadata contains a container header %x", magic),
				})
				break
			}
		}
	}
	if len(r.Findings) > 0 {
		r.Status = checks.Fail
		r.Notes = fmt.Sprintf("%d embedded payload indicator(s) in artifact metadata (%s)", len(r.Findings), invNote)
		return r
	}

	artifactNote := invNote + ", no payload indicator"

	if opts.RepoMirror == "" {
		r.Status = checks.NotTested
		r.Notes = artifactNote + ". Repo mirror not provided, so the repo file listing was not inspected."
		return r
	}

	repoFindings, repoNote, err := scanRepo(opts.RepoMirror)
	if err != nil {
		r.Status = checks.NotTested
		r.Notes = artifactNote + ". Could not read repo mirror: " + err.Error()
		return r
	}
	if len(repoFindings) > 0 {
		r.Status = checks.Fail
		r.Findings = repoFindings
		r.Notes = artifactNote + ". " + repoNote
		return r
	}

	r.Status = checks.Pass
	r.Notes = artifactNote + ". " + repoNote
	return r
}

// scanRepo lists a repo mirror and flags real binary executables. Scripts and
// config files are counted, not failed.
func scanRepo(root string) ([]checks.Finding, string, error) {
	var findings []checks.Finding
	var files, scripts int

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		files++
		ext := strings.ToLower(filepath.Ext(path))
		switch ext {
		case ".py", ".sh", ".js", ".rb":
			scripts++ // inventoried, not a failure: model repos ship these
			return nil
		}
		buf := make([]byte, 4)
		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		n, _ := io.ReadFull(f, buf)
		_ = f.Close()
		for _, magic := range binaryMagics {
			if n >= len(magic) && bytes.Equal(buf[:len(magic)], magic) {
				findings = append(findings, checks.Finding{
					Pattern: "repo-binary",
					Span:    d.Name(),
					Detail:  fmt.Sprintf("repo file %q has a binary container header %x", d.Name(), magic),
				})
				break
			}
		}
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	return findings, fmt.Sprintf("repo: %d files, %d scripts inventoried (scripts are expected, not a finding)", files, scripts), nil
}

func excerpt(s string) string {
	const max = 60
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
