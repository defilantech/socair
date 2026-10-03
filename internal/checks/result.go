// Package checks holds the shared result types for Socair checks.
//
// A check returns PASS, FAIL, LEAD, or NOT_TESTED. FAIL is reserved for
// positive evidence. LEAD is a suspicious signal that is not conclusive: it is
// not a FAIL, but it is not a gap either, so only escalated review clears it.
// Anything ambiguous or unparseable is NOT_TESTED with a named reason, never a
// silent pass and never a guess dressed as a failure.
package checks

import (
	"fmt"
	"strings"
)

// Status is a per-check result.
type Status string

const (
	Pass      Status = "PASS"
	Fail      Status = "FAIL"
	NotTested Status = "NOT_TESTED"
	Lead      Status = "LEAD"
)

// Finding is one piece of positive evidence inside a check.
type Finding struct {
	Pattern string `json:"pattern"`
	Span    string `json:"span,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// Result is the outcome of one check.
type Result struct {
	Name     string    `json:"name"`
	LooksFor string    `json:"looks_for"`
	Status   Status    `json:"status"`
	Findings []Finding `json:"findings,omitempty"`
	Notes    string    `json:"notes,omitempty"`
}

// severity orders statuses for Merge: one FAIL fails the row, then a LEAD,
// then a gap; PASS only when every part passed.
var severity = map[Status]int{Pass: 0, NotTested: 1, Lead: 2, Fail: 3}

// Part is one file's result within a merged row.
type Part struct {
	File   string
	Result Result
}

// Merge combines per-file results of one check into a single row, as a
// directory scan reports one row per check. The worst status wins, every
// finding keeps its file name, and every file that did not PASS is named with
// its reason, so a PASS on one shard never hides a gap or a finding on
// another. Passing files are counted, with one example note.
func Merge(name, looksFor string, parts []Part) Result {
	r := Result{Name: name, LooksFor: looksFor, Status: Pass}
	if len(parts) == 0 {
		r.Status = NotTested
		r.Notes = "no file in scope for this check"
		return r
	}
	var notes, passed []string
	passNote := ""
	for _, p := range parts {
		if severity[p.Result.Status] > severity[r.Status] {
			r.Status = p.Result.Status
		}
		for _, f := range p.Result.Findings {
			if f.Span != "" {
				f.Span = p.File + ": " + f.Span
			} else {
				f.Span = p.File
			}
			r.Findings = append(r.Findings, f)
		}
		if p.Result.Status == Pass {
			passed = append(passed, p.File)
			if passNote == "" {
				passNote = p.Result.Notes
			}
			continue
		}
		note := p.File + ": " + string(p.Result.Status)
		if p.Result.Notes != "" {
			note += " (" + p.Result.Notes + ")"
		}
		notes = append(notes, note)
	}
	if len(passed) > 0 {
		pass := fmt.Sprintf("%d of %d file(s) PASS", len(passed), len(parts))
		if len(passed) <= 3 {
			pass += " (" + strings.Join(passed, ", ") + ")"
		}
		if passNote != "" {
			pass += "; e.g. " + passed[0] + ": " + passNote
		}
		notes = append(notes, pass)
	}
	r.Notes = strings.Join(notes, "; ")
	return r
}
