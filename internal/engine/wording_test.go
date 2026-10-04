package engine

import (
	"testing"

	"github.com/defilantech/socair/internal/gguf/gguftest"
	"github.com/defilantech/socair/internal/report"
	"github.com/defilantech/socair/internal/safetensors/safetensorstest"
)

// TestReportsStateWhatTheyMean: every row of a real scan carries its fixed
// PASS statement, and the assurance section is the fixed Tier 1 wording, so
// a reader never has to infer what a PASS establishes (#131). Falsification:
// drop a check from report.PassMeaning, or stop filling the assurance level,
// and this fails.
func TestReportsStateWhatTheyMean(t *testing.T) {
	artifacts := map[string][]byte{
		"clean-Q5_K_M.gguf": gguftest.BuildGGUF(gguftest.Clean()),
		"model.safetensors": safetensorstest.Clean(),
	}
	for name, data := range artifacts {
		d, err := Scan(writeFixture(t, name, data))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if d.AssuranceLevel != report.Tier1Assurance() {
			t.Errorf("%s: assurance level = %+v, want the fixed Tier 1 wording", name, d.AssuranceLevel)
		}
		if d.Header.AssuranceLevelAwarded != d.AssuranceLevel.Awarded {
			t.Errorf("%s: header says %q, assurance section says %q", name, d.Header.AssuranceLevelAwarded, d.AssuranceLevel.Awarded)
		}
		for _, c := range d.Checks {
			if c.PassMeans == "" {
				t.Errorf("%s: row %q has no PASS statement", name, c.Name)
			}
		}
	}
}
