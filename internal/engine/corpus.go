package engine

import (
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"github.com/defilantech/socair/internal/report"
)

// CorpusEntry is the outcome of scanning one artifact in a sweep. It carries
// only what a baseline report needs, not a full attestation.
type CorpusEntry struct {
	Path          string            `json:"path"`
	Name          string            `json:"name,omitempty"`
	Architecture  string            `json:"architecture,omitempty"`
	QuantDeclared string            `json:"quant_declared,omitempty"`
	Checks        map[string]string `json:"checks"`
	Fails         []string          `json:"fails,omitempty"`
	NotTested     []string          `json:"not_tested,omitempty"`
	Error         string            `json:"error,omitempty"`
}

// Corpus scans every .gguf under root. mode is normally ModeHeaders for a
// sweep. It never touches the network.
func Corpus(root string, mode Mode) ([]CorpusEntry, error) {
	var paths []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable subtrees, do not abort the sweep
		}
		if d.IsDir() {
			return nil
		}
		if strings.EqualFold(filepath.Ext(path), ".gguf") {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)

	entries := make([]CorpusEntry, 0, len(paths))
	for _, p := range paths {
		entries = append(entries, scanEntry(p, mode))
	}
	return entries, nil
}

func scanEntry(path string, mode Mode) CorpusEntry {
	e := CorpusEntry{Path: path, Checks: map[string]string{}}

	d, err := ScanMode(path, mode)
	if err != nil {
		e.Error = err.Error()
		return e
	}

	e.Name = d.Artifact.Name
	e.Architecture = d.Artifact.Architecture
	e.QuantDeclared = d.Artifact.QuantDeclared
	for _, c := range d.Checks {
		e.Checks[c.Name] = string(c.Status)
	}
	e.Fails = d.Findings.Fails
	e.NotTested = d.Findings.NotTested
	return e
}

// Counts tallies check statuses across a corpus. Useful for the baseline doc.
func Counts(entries []CorpusEntry) map[string]int {
	out := map[string]int{
		string(report.StatusPass):      0,
		string(report.StatusFail):      0,
		string(report.StatusNotTested): 0,
		"error":                        0,
	}
	for _, e := range entries {
		if e.Error != "" {
			out["error"]++
			continue
		}
		for _, s := range e.Checks {
			out[s]++
		}
	}
	return out
}
