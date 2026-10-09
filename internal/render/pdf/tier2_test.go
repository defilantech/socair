package pdf

import (
	"bytes"
	"strings"
	"testing"

	"github.com/go-pdf/fpdf"

	"github.com/defilantech/socair/internal/report"
	"github.com/defilantech/socair/internal/tier2/tier2test"
)

var outcomes = []string{report.OutcomeMeasured, report.OutcomeLead, report.OutcomeFail, report.OutcomeError}

// tier2Text draws the Tier 2 section alone, uncompressed, so its text can be
// searched.
func tier2Text(t *testing.T, d *report.Document) string {
	t.Helper()
	p := fpdf.New("P", "mm", "A4", "")
	p.SetCompression(false)
	p.AddPage()
	tier2Section(p, d)
	var b bytes.Buffer
	if err := p.Output(&b); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestPDFTier2SectionOnlyWhenPresent(t *testing.T) {
	if strings.Contains(tier2Text(t, loadGolden(t)), "TIER 2 MEASUREMENTS") {
		t.Fatal("a report without Tier 2 must not draw a Tier 2 section")
	}
	d := loadGolden(t)
	tier2test.AddSection(d, outcomes...)
	out := tier2Text(t, d)
	for _, want := range []string{"TIER 2 MEASUREMENTS", "Sample probe 1 \\(Tier 2\\): measured \\(not a pass\\)", tier2test.NodeClass().Hash(), "Probe helper: tier2test 1"} {
		if !strings.Contains(out, want) {
			t.Errorf("the Tier 2 section does not draw %q", want)
		}
	}
	if !bytes.Equal(render(t, d), render(t, d)) {
		t.Error("a Tier 2 report must render byte-stable")
	}
}

// Falsification: give "measured" the pass ink and this fails.
func TestMeasurementInkIsNeverPass(t *testing.T) {
	for _, o := range outcomes {
		if outcomeInk(o) == passInk {
			t.Errorf("outcome %s is drawn in the pass ink", o)
		}
	}
	if outcomeInk(report.OutcomeLead) != leadInk || outcomeInk(report.OutcomeFail) != failInk {
		t.Error("a LEAD and a FAIL keep their own inks")
	}
}
