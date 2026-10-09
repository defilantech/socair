package report

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// emitted finds the finding patterns the checks emit, from their sources:
// Finding{Pattern: "..."}, signal{pattern: "..."}, fail("..."), the named
// pattern tables ({name: "...", re: ...}), and the pickle grammar's
// violate(status, "...") and finding(status, "...").
var emitted = regexp.MustCompile(`(?:Pattern|pattern):\s*"([a-z0-9_-]+)"|\bfail\("([a-z0-9_-]+)"|\bname:\s*"([a-z0-9_-]+)",\s*\n\s*re:|\b(?:violate|finding)\(checks\.(?:Fail|Lead),\s*"([a-z0-9_-]+)"`)

// TestEveryPatternHasASeverity: a new finding pattern without a severity
// would grade by fallback, silently. Falsification: delete an entry from
// patternSeverity and this names it.
func TestEveryPatternHasASeverity(t *testing.T) {
	found := map[string]string{}
	err := filepath.WalkDir(filepath.Join("..", "checks"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, m := range emitted.FindAllStringSubmatch(string(b), -1) {
			for _, g := range m[1:] {
				if g != "" {
					found[g] = p
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) < 30 {
		t.Fatalf("found only %d patterns; the source scan is broken", len(found))
	}
	for p, file := range found {
		if PatternSeverity(p) == "" {
			t.Errorf("pattern %q (%s) has no severity in patternSeverity", p, file)
		}
	}
}

func TestRowSeverity(t *testing.T) {
	cases := []struct {
		status   Status
		patterns []string
		want     string
	}{
		{StatusFail, []string{"quant-mismatch"}, SeverityLow},
		{StatusFail, []string{"quant-mismatch", "pickle-dangerous-global"}, SeverityCritical},
		{StatusLead, []string{"instruction-override", "obfuscated-literal"}, SeverityHigh},
		{StatusFail, []string{"unknown-pattern"}, SeverityHigh},
		{StatusLead, nil, SeverityMedium},
		{StatusPass, []string{"pickle-dangerous-global"}, ""},
		{StatusNotTested, nil, ""},
	}
	for _, c := range cases {
		if got := RowSeverity(c.status, c.patterns); got != c.want {
			t.Errorf("%s %v = %q, want %q", c.status, c.patterns, got, c.want)
		}
	}
}

// Every check with a PASS statement also says what it addresses, and every
// mapping names a real framework entry in the editions the report cites.
func TestEveryCheckMaps(t *testing.T) {
	atlas := regexp.MustCompile(`^AML\.T\d{4}(\.\d{3})?$`)
	owasp := regexp.MustCompile(`^LLM(0[1-9]|10)$`)
	for check := range passMeaning {
		refs := MapsTo(check)
		if len(refs) == 0 {
			t.Errorf("%q maps to nothing", check)
		}
		for _, r := range refs {
			ok := (r.Framework == "MITRE ATLAS" && atlas.MatchString(r.ID)) ||
				(r.Framework == "OWASP LLM Top 10" && owasp.MatchString(r.ID))
			if !ok || r.Name == "" {
				t.Errorf("%q: bad reference %+v", check, r)
			}
		}
	}
	if MapsTo("Forward-pass trigger probes (Tier 2)") != nil {
		t.Error("a check that did not run must not claim a mapping")
	}
}
