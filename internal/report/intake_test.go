package report

import (
	"strings"
	"testing"
)

// The golden carries an Intake policy row and names its policy; it
// validates, with the row's fixed PASS statement and mapping.
func TestGoldenIntakePolicy(t *testing.T) {
	d, _ := loadGolden(t)
	if problems := Validate(d); len(problems) != 0 {
		t.Fatal(problems)
	}
	ref := d.Scope.IntakePolicy
	if ref == nil || ref.Name == "" || len(ref.SHA256) != 64 {
		t.Fatalf("the golden must name its intake policy: %+v", ref)
	}
	var row *CheckResult
	for i := range d.Checks {
		if d.Checks[i].Name == IntakePolicyCheck {
			row = &d.Checks[i]
		}
	}
	if row == nil || row.PassMeans != PassMeaning(IntakePolicyCheck) || len(row.MapsTo) == 0 {
		t.Fatalf("the golden's Intake policy row needs the fixed PASS statement and its mapping: %+v", row)
	}
}

// TestIntakePolicyNamesItsPolicy: a report with an Intake policy row says
// which policy, by name and hash, and a report that names a policy carries
// its row. Falsification: drop validateIntakePolicy and each forgery
// validates.
func TestIntakePolicyNamesItsPolicy(t *testing.T) {
	cases := map[string]struct {
		edit func(d *Document)
		want string
	}{
		"row without its policy": {func(d *Document) { d.Scope.IntakePolicy = nil }, "an Intake policy row needs the policy"},
		"policy without its row": {func(d *Document) {
			var kept []CheckResult
			for _, c := range d.Checks {
				if c.Name != IntakePolicyCheck {
					kept = append(kept, c)
				}
			}
			d.Checks = kept
		}, "checks has no Intake policy row"},
		"a path, not a name":      {func(d *Document) { d.Scope.IntakePolicy.Name = "/etc/socair/intake.json" }, "must be a file's base name"},
		"a Windows path":          {func(d *Document) { d.Scope.IntakePolicy.Name = `C:\socair\intake.json` }, "must be a file's base name"},
		"no name":                 {func(d *Document) { d.Scope.IntakePolicy.Name = " " }, "must be a file's base name"},
		"short hash":              {func(d *Document) { d.Scope.IntakePolicy.SHA256 = "abc" }, "64 lowercase hex"},
		"uppercase hash":          {func(d *Document) { d.Scope.IntakePolicy.SHA256 = strings.Repeat("A", 64) }, "64 lowercase hex"},
		"a hash that is not hex.": {func(d *Document) { d.Scope.IntakePolicy.SHA256 = strings.Repeat("g", 64) }, "64 lowercase hex"},
	}
	for name, c := range cases {
		d, _ := loadGolden(t)
		c.edit(d)
		d.BoundedStatement = BoundedStatementOf(d)
		if !hasProblem(Validate(d), c.want) {
			t.Errorf("%s: want a problem %q, got %v", name, c.want, Validate(d))
		}
	}
}
