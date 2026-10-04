package benchmark

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/engine"
	"github.com/defilantech/socair/internal/report"
)

// outcome is what the scan did with a case: detected (FAIL or LEAD in the
// expected row), withheld as a gap (NOT_TESTED), or missed (PASS).
type outcome struct {
	c        Case
	status   report.Status
	severity string
	got      Expect
	evidence string
}

func classify(s report.Status) Expect {
	switch s {
	case report.StatusFail, report.StatusLead:
		return Detect
	case report.StatusNotTested:
		return Withheld
	}
	return KnownMiss
}

// TestDetectionBenchmark scans every defanged reproduction and holds each to
// its pinned outcome, so a regression and an unrecorded improvement both
// fail. SOCAIR_BENCHMARK_OUT=<file> writes the results table;
// SOCAIR_BENCHMARK_CORPUS=<dir> also writes the artifacts there, one
// directory per case, for running other scanners over the same files.
func TestDetectionBenchmark(t *testing.T) {
	var results []outcome
	for _, c := range Cases() {
		dir := t.TempDir()
		if out := os.Getenv("SOCAIR_BENCHMARK_CORPUS"); out != "" {
			dir = filepath.Join(out, c.ID)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		path, env, err := c.Build(dir)
		if err != nil {
			t.Fatalf("%s: build: %v", c.ID, err)
		}
		for k, v := range env {
			t.Setenv(k, v)
		}
		d, err := engine.Scan(path)
		for k := range env {
			t.Setenv(k, "")
		}
		if err != nil {
			t.Fatalf("%s: scan: %v", c.ID, err)
		}
		if c.Expect == Clean {
			o := outcome{c: c, got: Clean, status: report.StatusPass}
			for _, r := range d.Checks {
				if r.Status == report.StatusFail || r.Status == report.StatusLead {
					o.got, o.status, o.evidence = Detect, r.Status, r.Name+": "+r.Evidence
					t.Errorf("%s: benign control flagged by %s (%s): %s", c.ID, r.Name, r.Status, r.Evidence)
				}
			}
			results = append(results, o)
			continue
		}
		var row report.CheckResult
		for _, r := range d.Checks {
			if r.Name == c.Row {
				row = r
			}
		}
		if row.Name == "" {
			t.Errorf("%s: no %q row in the report", c.ID, c.Row)
			continue
		}
		o := outcome{c: c, status: row.Status, severity: row.Severity, got: classify(row.Status), evidence: row.Evidence}
		if o.evidence == "" {
			o.evidence = row.Notes
		}
		results = append(results, o)
		if o.got != c.Expect {
			t.Errorf("%s: %s row is %s (%s), pinned %s: %s", c.ID, c.Row, row.Status, o.got, c.Expect, o.evidence)
		}
		// A detection must withhold the artifact.
		if o.got == Detect && d.PromotionAuthorization.Authorized {
			t.Errorf("%s: detected but promotion is %s", c.ID, d.PromotionAuthorization.State)
		}
	}
	if len(results) < 35 {
		t.Fatalf("only %d cases; the corpus shrank", len(results))
	}
	if p := os.Getenv("SOCAIR_BENCHMARK_OUT"); p != "" {
		if err := os.WriteFile(p, []byte(table(results)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func table(rs []outcome) string {
	var b strings.Builder
	type tally struct{ n, detect, withheld, miss int }
	byRow := map[string]*tally{}
	all := &tally{}
	controls, flagged := 0, 0
	for _, r := range rs {
		if r.c.Expect == Clean {
			controls++
			if r.got != Clean {
				flagged++
			}
			continue
		}
		for _, t := range []*tally{all, byRow[r.c.Row]} {
			if t == nil {
				t = &tally{}
				byRow[r.c.Row] = t
			}
			t.n++
			switch r.got {
			case Detect:
				t.detect++
			case Withheld:
				t.withheld++
			default:
				t.miss++
			}
		}
	}
	rows := make([]string, 0, len(byRow))
	for k := range byRow {
		rows = append(rows, k)
	}
	sort.Strings(rows)
	b.WriteString("| Check row | Cases | Detected (FAIL or LEAD) | Withheld as a gap (NOT_TESTED) | Missed (PASS) |\n|---|---|---|---|---|\n")
	for _, k := range rows {
		t := byRow[k]
		fmt.Fprintf(&b, "| %s | %d | %d | %d | %d |\n", k, t.n, t.detect, t.withheld, t.miss)
	}
	fmt.Fprintf(&b, "| **All** | **%d** | **%d** | **%d** | **%d** |\n\n", all.n, all.detect, all.withheld, all.miss)
	fmt.Fprintf(&b, "Benign controls flagged (FAIL or LEAD on any row): %d of %d.\n\n", flagged, controls)
	b.WriteString("| Case | Format | Technique | Row | Result | Severity |\n|---|---|---|---|---|---|\n")
	for _, r := range rs {
		row := r.c.Row
		if r.c.Expect == Clean {
			row = "(control: every row)"
		}
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s | %s |\n", r.c.ID, r.c.Format, strings.ReplaceAll(r.c.Technique, "|", "\\|"), row, r.status, r.severity)
	}
	return b.String()
}
