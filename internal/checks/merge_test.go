package checks

import (
	"strings"
	"testing"
)

func TestMergeWorstWinsAndNamesFiles(t *testing.T) {
	pass := Result{Status: Pass, Notes: "ok"}
	fail := Result{Status: Fail, Findings: []Finding{{Pattern: "p", Span: "s"}}, Notes: "bad"}
	gap := Result{Status: NotTested, Notes: "unread"}
	r := Merge("n", "l", []Part{{"a", pass}, {"b", gap}, {"c", fail}})
	if r.Status != Fail || r.Findings[0].Span != "c: s" {
		t.Fatalf("merged %+v", r)
	}
	if !strings.Contains(r.Notes, "b: NOT_TESTED (unread)") || !strings.Contains(r.Notes, "1 of 3 file(s) PASS") {
		t.Errorf("notes must name every non-PASS file and count the passes: %s", r.Notes)
	}
	if Merge("n", "l", []Part{{"a", pass}, {"b", gap}}).Status != NotTested {
		t.Error("a gap on one file must not merge to PASS")
	}
	if Merge("n", "l", nil).Status != NotTested {
		t.Error("no file in scope is NOT_TESTED, never PASS")
	}
}
