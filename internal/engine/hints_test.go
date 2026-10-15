package engine

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/report"
	"github.com/defilantech/socair/internal/safetensors/safetensorstest"
)

// TestNextSteps scans real artifacts with no inputs and holds each input
// rule to a row it matches, so a reworded note fails here instead of
// silently losing its hint. Falsification: drop a rule, or let a note's
// wording drift, and its row falls back to the generic review step.
func TestNextSteps(t *testing.T) {
	for _, k := range []string{"SOCAIR_FEED", "SOCAIR_DENYLIST", "SOCAIR_PROVENANCE", "SOCAIR_REPO_MIRROR", "SOCAIR_TENSOR_REFERENCE",
		"SOCAIR_LICENSE_POLICY", "SOCAIR_INTAKE_POLICY", "SOCAIR_PUBLISHER_KEYS"} {
		t.Setenv(k, "")
	}
	file := filepath.Join(t.TempDir(), "model.safetensors")
	if err := os.WriteFile(file, safetensorstest.Clean(), 0o644); err != nil {
		t.Fatal(err)
	}
	single, err := Scan(file)
	if err != nil {
		t.Fatal(err)
	}
	var zipped strings.Builder
	zw := zip.NewWriter(&zipped)
	w, _ := zw.Create("notes.txt")
	_, _ = w.Write([]byte("an archive no check reads"))
	_ = zw.Close()
	dir, err := Scan(modelRepo(t, map[string]string{
		"flax_model.msgpack":    "not read",
		"bundle.zip":            zipped.String(),
		"weights/extra.bin":     "raw tensor bytes, not a pickle",
		"tokenizer_config.json": "{}",
	}))
	if err != nil {
		t.Fatal(err)
	}
	// A known-bad list the operator supplied but that held nothing, or could
	// not be read, keeps its row and says how to fix the list.
	scanWithList := func(list string) *report.Document {
		t.Helper()
		t.Setenv("SOCAIR_DENYLIST", list)
		defer t.Setenv("SOCAIR_DENYLIST", "")
		d, err := Scan(file)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	empty := filepath.Join(t.TempDir(), "known-bad.txt")
	if err := os.WriteFile(empty, []byte("# our organization's list, empty so far\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	emptyList := scanWithList(empty)
	missingList := scanWithList(filepath.Join(t.TempDir(), "no-such-list.txt"))

	matched := map[string]bool{}
	for _, d := range []*report.Document{single, dir, emptyList, missingList} {
		for _, s := range NextSteps(d) {
			if s.Status == report.StatusPass {
				t.Errorf("%s PASSed but has a step", s.Row)
			}
			for _, r := range inputSteps {
				if s.Row == r.row && s.Next == r.next {
					matched[r.phrase] = true
					if !s.Input {
						t.Errorf("%s: an input closes it, but Input is false", s.Row)
					}
				}
			}
			if strings.Contains(s.Next, "a format Socair does not read") {
				matched["format:"+s.Row] = true
			}
		}
	}
	for _, r := range inputSteps {
		if !matched[r.phrase] {
			t.Errorf("no scan matched the %q rule (%q): has the check's note changed?", r.row, r.phrase)
		}
	}
	for _, row := range []string{"Format and structure", "File inventory and payloads", "Pickle opcode scan"} {
		if !matched["format:"+row] {
			t.Errorf("%s: a file Socair does not read got no step about leaving it out of the pull", row)
		}
	}
	// Without a known-bad list, and in a directory with no chat template,
	// those checks are named as not run: no row, so no step.
	for _, c := range []struct {
		d   *report.Document
		row string
	}{{single, "Known-bad hash match"}, {dir, "Known-bad hash match"}, {dir, "Chat template"}} {
		for _, s := range NextSteps(c.d) {
			if s.Row == c.row {
				t.Errorf("%s has a step (%q), but it did not run", c.row, s.Next)
			}
		}
		if !notRun(c.d, c.row) {
			t.Errorf("%s is not named in out_of_scope.not_run", c.row)
		}
	}

	sum := Summary(single)
	if !strings.HasPrefix(sum, "promotion: withheld; ") || !strings.Contains(sum, "for want of an input this scan was not given") {
		t.Fatalf("summary: %q", sum)
	}
	for _, c := range single.Checks {
		if c.Status == report.StatusPass && strings.Contains(sum, " "+c.Name+": ") {
			t.Errorf("the summary lists %s, which PASSed", c.Name)
		}
	}
}

// notRun reports whether a check is named in out_of_scope.not_run.
func notRun(d *report.Document, name string) bool {
	for _, c := range d.OutOfScope.NotRun {
		if c.Name == name {
			return true
		}
	}
	return false
}

// TestNextStepsNeverOfferAcceptanceForAFindings: an acceptance clears only
// NOT_TESTED, so a FAIL or a LEAD is never told to accept.
func TestNextStepsNeverOfferAcceptanceForAFinding(t *testing.T) {
	d := &report.Document{Checks: []report.CheckResult{
		{Name: "Chat template", Status: report.StatusLead},
		{Name: "Pickle opcode scan", Status: report.StatusFail},
	}}
	for _, s := range NextSteps(d) {
		if strings.Contains(s.Next, "socair accept") || !strings.Contains(s.Next, "no acceptance clears") {
			t.Errorf("%s %s: %q", s.Row, s.Status, s.Next)
		}
	}
}
