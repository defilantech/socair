package report

import (
	"strings"
	"testing"
)

// Statements that disagree identify no license, so a report that names one
// beside a disagreement does not validate.
func TestValidateLicenseDisagreement(t *testing.T) {
	d, _ := loadGolden(t)
	d.Artifact.License = &License{ID: "mit", Name: "MIT License", Sources: []LicenseSource{{Source: "LICENSE", Value: "MIT License", ID: "mit"}}}
	for _, p := range Validate(d) {
		if strings.Contains(p, "artifact.license") {
			t.Fatalf("an identified license must validate: %s", p)
		}
	}
	d.Artifact.License.Disagreement = "the sources name different licenses: ..."
	found := false
	for _, p := range Validate(d) {
		found = found || strings.Contains(p, "artifact.license")
	}
	if !found {
		t.Fatal("an identified license beside a disagreement must not validate")
	}
}

// The license row is opt-in and grades a rule the operator set, so its PASS
// says it is not legal advice and that obligations are listed, not met.
func TestLicensePolicyPassMeaning(t *testing.T) {
	pm := PassMeaning("License policy")
	for _, s := range []string{"your allowed list", "not legal advice", "not marked met"} {
		if !strings.Contains(pm, s) {
			t.Errorf("pass_means %q does not say %q", pm, s)
		}
	}
}
