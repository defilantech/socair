package engine

import (
	"testing"
	"time"

	"github.com/defilantech/socair/internal/report"
	"github.com/defilantech/socair/internal/safetensors/safetensorstest"
)

func TestAcceptancePolicy(t *testing.T) {
	start := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	due, exp, err := acceptancePolicy(start, "", "")
	if err != nil || due != "2027-01-01T12:00:00Z" || exp != due {
		t.Fatalf("defaults: due=%s exp=%s err=%v; want a 90-day re-scan and the acceptance lapsing with it", due, exp, err)
	}
	due, exp, err = acceptancePolicy(start, "30", "2026-12-01T00:00:00+01:00")
	if err != nil || due != "2026-11-02T12:00:00Z" || exp != "2026-11-30T23:00:00Z" {
		t.Fatalf("explicit: due=%s exp=%s err=%v", due, exp, err)
	}
	for _, c := range []struct{ days, exp string }{
		{"0", ""}, {"ninety", ""}, {"", "end of quarter"}, {"", "2026-12-01"}, {"", "2026-10-01T00:00:00Z"},
	} {
		if _, _, err := acceptancePolicy(start, c.days, c.exp); err == nil {
			t.Errorf("days=%q expires=%q: want an error, not an unenforceable acceptance", c.days, c.exp)
		}
	}
}

// TestAcceptedScanCarriesEnforceableExpiry: an acceptance from the engine
// always carries an RFC 3339 expiry and the report a re-scan date.
func TestAcceptedScanCarriesEnforceableExpiry(t *testing.T) {
	fixture := safetensorstest.Clean()
	supplyInputs(t)
	t.Setenv("SOCAIR_PROVENANCE", "")
	t.Setenv("SOCAIR_ACCEPTED_BY", "ciso@example.com")
	p := writeFixture(t, "fixture.safetensors", fixture)
	d, err := Scan(p)
	if err != nil {
		t.Fatal(err)
	}
	pa := d.PromotionAuthorization
	if pa.State != report.StateAuthorizedWithConditions {
		t.Fatalf("state %s, want authorized_with_conditions", pa.State)
	}
	if pa.AcceptanceExpires != d.Header.RescanDue || pa.AcceptanceExpires == "" {
		t.Fatalf("acceptance_expires %q, rescan_due %q: the acceptance must lapse at the re-scan by default", pa.AcceptanceExpires, d.Header.RescanDue)
	}
	if problems := report.Validate(d); len(problems) != 0 {
		t.Fatal(problems)
	}

	t.Setenv("SOCAIR_ACCEPTANCE_EXPIRES", "next quarter")
	if _, err := Scan(p); err == nil {
		t.Fatal("an unparseable expiry must fail the scan, not record an acceptance that cannot be enforced")
	}
}
