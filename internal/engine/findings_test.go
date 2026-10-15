package engine

import (
	"encoding/json"
	"testing"

	"github.com/defilantech/socair/internal/report"
	"github.com/defilantech/socair/internal/safetensors/safetensorstest"
)

// TestFindingsListsAreArrays: the report schema types findings.fails and
// findings.not_tested as arrays, and the wizard's Document type does too, so
// a report with no FAIL row, or no NOT_TESTED row, writes [] for that list and
// never null. Falsification: leave either list nil in finalizeFindings and
// one of these reports writes null.
func TestFindingsListsAreArrays(t *testing.T) {
	t.Run("authorized: no FAIL and no NOT_TESTED", func(t *testing.T) {
		supplyInputs(t, safetensorstest.Clean())
		d, err := Scan(writeFixture(t, "fixture.safetensors", safetensorstest.Clean()))
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		if d.PromotionAuthorization.State != report.StateAuthorized {
			t.Fatalf("state %s, want %s", d.PromotionAuthorization.State, report.StateAuthorized)
		}
		b, err := json.Marshal(d.Findings)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := string(b), `{"fails":[],"not_tested":[]}`; got != want {
			t.Errorf("findings %s, want %s", got, want)
		}
	})
	t.Run("withheld on gaps: no FAIL", func(t *testing.T) {
		d, err := Scan(writeFixture(t, "fixture.safetensors", safetensorstest.Clean()))
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		if len(d.Findings.NotTested) == 0 {
			t.Fatal("a scan without its inputs has NOT_TESTED rows")
		}
		var got map[string]json.RawMessage
		b, err := json.Marshal(d.Findings)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatal(err)
		}
		if string(got["fails"]) != "[]" {
			t.Errorf("fails %s, want []", got["fails"])
		}
	})
}
