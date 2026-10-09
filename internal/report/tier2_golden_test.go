package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The Tier 2 golden (testdata/report-tier2.json) is the Tier 1 golden with a
// Tier 2 section: a LEAD that withholds through its row, and a measurement
// that found nothing and adds none. It validates, and a forged copy whose
// Tier 2 row reads PASS so the report could authorize does not.
func TestTier2GoldenValidates(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "report-tier2.json"))
	if err != nil {
		t.Fatal(err)
	}
	var d Document
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	if problems := Validate(&d); len(problems) != 0 {
		t.Fatalf("the Tier 2 golden does not validate: %v", problems)
	}
	want := Tier1Assurance()
	want.Tier2Note = Tier2RanNote
	if d.AssuranceLevel != want {
		t.Errorf("assurance level %+v is not the fixed wording", d.AssuranceLevel)
	}
	if d.Tier2 == nil || len(d.Tier2.Measurements) != 2 || len(Tier2Rows(d.Tier2)) != 1 {
		t.Fatalf("the golden must carry one LEAD and one measurement that found nothing: %+v", d.Tier2)
	}

	for i := range d.Checks {
		if IsTier2Check(d.Checks[i].Name) {
			d.Checks[i].Status = StatusPass
		}
	}
	d.BoundedStatement = BoundedStatementOf(&d)
	if !hasProblem(Validate(&d), "a Tier 2 row is only ever LEAD or FAIL") {
		t.Error("the golden's Tier 2 row edited to PASS must be refused")
	}
}
