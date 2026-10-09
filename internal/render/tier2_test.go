package render

import (
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/report"
	"github.com/defilantech/socair/internal/tier2/tier2test"
)

var outcomes = []string{report.OutcomeMeasured, report.OutcomeLead, report.OutcomeFail, report.OutcomeError}

// The Tier 2 section appears only when the report has one, with its fixed
// statement, the node class it ran on, and who reported that class.
func TestTier2SectionOnlyWhenPresent(t *testing.T) {
	if out := renderString(t, loadGolden(t)); strings.Contains(out, "Tier 2 measurements</h2>") {
		t.Fatal("a report without Tier 2 must not show a Tier 2 section")
	}
	d := loadGolden(t)
	tier2test.AddSection(d, outcomes...)
	out := renderString(t, d)
	nc := tier2test.NodeClass()
	for _, want := range []string{
		"Tier 2 measurements</h2>",
		report.Tier2Statement,
		nc.Hash(),
		report.NodeClassReportedByHelper,
		"gpu_model NVIDIA H100 80GB HBM3",
		"Not reported: interconnect",
		"score 0.75 (95% CI 0.3 to 0.95), n=4, agreement 0.75",
		"temperature 0, top_p 1, max_tokens 32, seed 0",
		tier2test.CanaryText,
		"Probe helper: tier2test 1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the Tier 2 section does not show %q", want)
		}
	}
	if out != renderString(t, d) {
		t.Error("a Tier 2 report must render byte-stable")
	}
}

// A measurement is never shown as a pass: one that found nothing is neutral
// and says it is not a pass, a LEAD and a FAIL keep their own looks, and one
// that did not complete takes the gap look. Falsification: map "measured" to
// the pass class and this fails.
func TestMeasurementIsNeverAPass(t *testing.T) {
	for _, o := range outcomes {
		if outcomeClass(o) == "pass" || outcomeClass(o) == statusClass(report.StatusPass) {
			t.Errorf("outcome %s renders with the pass class", o)
		}
	}
	d := loadGolden(t)
	tier2test.AddSection(d, outcomes...)
	out := renderString(t, d)
	for _, want := range []string{
		`class="pill measured">measured</span><span class="tag">not a pass</span>`,
		`class="pill lead">lead`,
		`class="pill fail">fail`,
		`class="pill not-tested">error`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s", want)
		}
	}
	if strings.Contains(out, `class="pill pass">measured`) {
		t.Error("a measurement that found nothing renders as a pass")
	}
}
