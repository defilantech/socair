package engine

import (
	"fmt"
	"strings"

	"github.com/defilantech/socair/internal/report"
)

// NextStep is what a person can do about one row that did not PASS. It is
// advice for whoever ran the scan, printed beside the report and never part of
// it: the report states what was tested, and this says how to test the rest.
type NextStep struct {
	Row    string
	Status report.Status
	// Input is set when the gap closes by giving the scan an input it did not
	// have (a feed, a provenance record, the model's directory), rather than
	// by anything about the model.
	Input bool
	Next  string
}

// inputSteps are the gaps an input closes, found by the row and a phrase of
// its notes. The phrases are the checks' own wording (TestNextSteps pins each
// to a real scan), so a reworded note fails a test rather than losing its
// hint.
var inputSteps = []struct{ row, phrase, next string }{
	{"Known-bad hash match", "no denylist configured",
		"set SOCAIR_FEED and SOCAIR_FEED_KEYS to a signed reference feed, or SOCAIR_DENYLIST to a local list of known-bad hashes (docs/feed.md)"},
	{"Hash, provenance, lineage", "no provenance input",
		"pull the model through the airlock (socair airlock pull), which records where it came from, and scan with the SOCAIR_PROVENANCE it prints; or verify the publisher's signature (SOCAIR_PUBLISHER_KEYS, docs/provenance-bundle.md)"},
	{"File inventory and payloads", "Repo mirror not provided",
		"scan the model's whole directory rather than one file, or name its repository listing with SOCAIR_REPO_MIRROR"},
}

// formatGaps are the checks' phrases for a file, or an archive's contents,
// in a format Socair does not read.
var formatGaps = []string{
	"is not a container this scanner parses",
	"Archive contents were not scanned",
	"is not a pickle opcode stream",
}

// noTemplate is the Chat template row's note for a model that ships none.
const noTemplate = "no chat template in"

// NextSteps lists, for each row that did not PASS, what would close it: an
// input the scan did not have, files left out of the pull, or a person's
// review. Rows that PASS are not listed.
func NextSteps(d *report.Document) []NextStep {
	var out []NextStep
	for _, c := range d.Checks {
		s := NextStep{Row: c.Name, Status: c.Status}
		switch c.Status {
		case report.StatusPass:
			continue
		case report.StatusFail:
			s.Next = "positive evidence: the model stays withheld, and no acceptance clears a FAIL"
		case report.StatusLead:
			s.Next = "a suspicious signal for a person to review; no acceptance clears a LEAD, so the model stays withheld under this check set"
		default:
			for _, r := range inputSteps {
				if c.Name == r.row && strings.Contains(c.Notes, r.phrase) {
					s.Input, s.Next = true, r.next
				}
			}
			for _, p := range formatGaps {
				if s.Next == "" && strings.Contains(c.Notes, p) {
					s.Next = "a file is in a format Socair does not read: leave files you will not serve out of the pull (socair airlock pull --include, docs/airlock.md), or review the gap and accept it (socair accept)"
				}
			}
			if s.Next == "" && c.Name == "Chat template" && strings.HasPrefix(c.Notes, noTemplate) {
				s.Next = "the model ships no chat template, so there was none to read; an embedding or reranking model needs none. Review the gap and accept it (socair accept)"
			}
			if s.Next == "" {
				s.Next = "review the reason in the notes; if the gap is acceptable, sign an acceptance (socair accept), which re-issues the report as authorized with conditions"
			}
		}
		out = append(out, s)
	}
	return out
}

// Summary is NextSteps for a person reading a terminal: the promotion state,
// then one line per row that did not PASS. Empty when every row passed.
func Summary(d *report.Document) string {
	steps := NextSteps(d)
	if len(steps) == 0 {
		return ""
	}
	inputs := 0
	for _, s := range steps {
		if s.Input {
			inputs++
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "promotion: %s; %d row(s) did not PASS", d.PromotionAuthorization.State, len(steps))
	if inputs > 0 {
		fmt.Fprintf(&b, ", %d of them for want of an input this scan was not given", inputs)
	}
	b.WriteString(":\n")
	for _, s := range steps {
		fmt.Fprintf(&b, "  %-10s %s: %s\n", s.Status, s.Row, s.Next)
	}
	return b.String()
}
