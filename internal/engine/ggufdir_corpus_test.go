package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/gguf"
)

// TestRealQuantTemplates is the false-positive gate for the chat templates a
// directory's GGUF files carry. SOCAIR_QUANT_TEMPLATE_CORPUS names a
// directory with one subdirectory per repository, each holding index.json
// (the repository's GGUF files, each with the stub that holds its metadata)
// and stubs/: GGUF files with no tensors that keep each file's chat templates,
// vocabulary, and special tokens, as fetched by streaming only the metadata
// of every GGUF in the repository. It prints each repository's Chat template
// row, and the status each version would have on its own, so a change the
// sibling comparison makes shows; and it fails if a repository whose files
// all carry the same templates is graded differently from one of them on
// its own.
//
//	SOCAIR_QUANT_TEMPLATE_CORPUS=<dir> go test ./internal/engine -run RealQuantTemplates -v
func TestRealQuantTemplates(t *testing.T) {
	root := os.Getenv("SOCAIR_QUANT_TEMPLATE_CORPUS")
	if root == "" {
		t.Skip("set SOCAIR_QUANT_TEMPLATE_CORPUS to a directory of GGUF metadata stubs")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	tally := map[checks.Status]int{}
	diverged, siblingFindings := 0, 0
	for _, e := range entries {
		var idx struct {
			Repo   string `json:"repo"`
			Commit string `json:"commit"`
			Files  []struct {
				Path string `json:"path"`
				Stub string `json:"stub"`
			} `json:"files"`
		}
		raw, err := os.ReadFile(filepath.Join(root, e.Name(), "index.json"))
		if err != nil {
			continue
		}
		if err := json.Unmarshal(raw, &idx); err != nil {
			t.Fatal(err)
		}
		read := map[string]*gguf.Manifest{}
		var heads []ggufHeader
		for _, f := range idx.Files {
			if f.Stub == "" {
				continue
			}
			m, ok := read[f.Stub]
			if !ok {
				if m, err = gguf.ReadHeader(filepath.Join(root, e.Name(), "stubs", f.Stub)); err != nil {
					t.Fatalf("%s %s: %v", idx.Repo, f.Path, err)
				}
				read[f.Stub] = m
			}
			heads = append(heads, ggufHeader{path: f.Path, m: m})
		}
		parts, note := ggufTemplateParts(heads, &references{})
		if len(parts) == 0 {
			t.Logf("%-10s %s: no GGUF carries a chat template", "-", idx.Repo)
			continue
		}
		row := checks.Merge(parts[0].Result.Name, parts[0].Result.LooksFor, parts)
		tally[row.Status]++
		var pats, alone []string
		for _, f := range row.Findings {
			pats = append(pats, f.Pattern)
			if f.Pattern == "quant-template-mismatch" {
				siblingFindings++
			}
		}
		for _, p := range parts {
			one, _ := ggufTemplateParts([]ggufHeader{{path: p.File, m: headOf(heads, p.File)}}, &references{})
			alone = append(alone, string(one[0].Result.Status))
		}
		if note != "" {
			diverged++
		}
		sort.Strings(pats)
		t.Logf("%-10s %s @ %s: %d version(s), alone %s [%s] %s", row.Status, idx.Repo, idx.Commit[:7], len(parts),
			strings.Join(alone, "/"), strings.Join(uniqStrings(pats), ","), note)
		if len(parts) == 1 && string(row.Status) != alone[0] {
			t.Errorf("%s: one version graded %s in the directory and %s on its own", idx.Repo, row.Status, alone[0])
		}
	}
	t.Logf("PASS %d, LEAD %d, NOT_TESTED %d, FAIL %d; %d with more than one version; %d quant-template-mismatch finding(s)",
		tally[checks.Pass], tally[checks.Lead], tally[checks.NotTested], tally[checks.Fail], diverged, siblingFindings)
}

// headOf finds the manifest of the first file a part names.
func headOf(heads []ggufHeader, label string) *gguf.Manifest {
	first, _, _ := strings.Cut(label, " and ")
	for _, h := range heads {
		if h.path == first {
			return h.m
		}
	}
	return nil
}

func uniqStrings(s []string) []string {
	var out []string
	for i, x := range s {
		if i == 0 || x != s[i-1] {
			out = append(out, x)
		}
	}
	return out
}
