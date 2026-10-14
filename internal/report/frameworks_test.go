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
// Finding{Pattern: "..."}, signal{pattern: "..."}, fail("..."), lead("..."), the named
// pattern tables ({name: "...", re: ...}), and the pickle grammar's
// violate(status, "...") and finding(status, "...").
var emitted = regexp.MustCompile(`(?:Pattern|pattern):\s*"([a-z0-9_-]+)"|\b(?:fail|lead)\("([a-z0-9_-]+)"|\bname:\s*"([a-z0-9_-]+)",\s*\n\s*re:|\b(?:violate|finding)\(checks\.(?:Fail|Lead),\s*"([a-z0-9_-]+)"`)

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
			ok := (r.Framework == FrameworkATLAS && r.Version == ATLASVersion && atlas.MatchString(r.ID)) ||
				(r.Framework == FrameworkOWASPLLM && r.Version == OWASPVersion && owasp.MatchString(r.ID))
			if !ok || r.Name == "" {
				t.Errorf("%q: bad reference %+v", check, r)
			}
		}
	}
	if MapsTo("Forward-pass trigger probes (Tier 2)") != nil {
		t.Error("a check that did not run must not claim a mapping")
	}
}

// atlasList is the pinned ATLAS release's IDs and names
// (testdata/atlas-ids.txt, written by atlasgen from the release's data file).
type atlasList struct {
	header map[string]string
	kind   map[string]string
	name   map[string]string
}

func loadATLASList(t *testing.T) atlasList {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "atlas-ids.txt"))
	if err != nil {
		t.Fatal(err)
	}
	l := atlasList{header: map[string]string{}, kind: map[string]string{}, name: map[string]string{}}
	field := regexp.MustCompile(`^# ([a-z0-9-]+): (.+)$`)
	for i, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		if strings.HasPrefix(line, "#") {
			if m := field.FindStringSubmatch(line); m != nil {
				l.header[m[1]] = m[2]
			}
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 3 || f[0] == "" || f[1] == "" || f[2] == "" {
			t.Fatalf("atlas-ids.txt line %d: %q is not <id>\\t<kind>\\t<name>", i+1, line)
		}
		if _, dup := l.kind[f[0]]; dup {
			t.Fatalf("atlas-ids.txt: %s appears twice", f[0])
		}
		l.kind[f[0]], l.name[f[0]] = f[1], f[2]
	}
	return l
}

// TestATLASMappingsAreInThePinnedEdition holds every ATLAS entry a check maps
// to against the published data of the release the report names: the edition
// Socair emits is the list's, and each ID is a technique or sub-technique of
// it, under its name there. Falsification: map a check to AML.T0058 (retired
// in ATLAS 2026.07), to a mitigation, or under a stale name, or change
// ATLASVersion without regenerating the list, and this fails.
func TestATLASMappingsAreInThePinnedEdition(t *testing.T) {
	l := loadATLASList(t)
	v := l.header["version"]
	if v == "" || ATLASVersion != v || ATLASEdition != "MITRE ATLAS "+v {
		t.Fatalf("Socair names %q (version %q); the pinned list is ATLAS %q", ATLASEdition, ATLASVersion, v)
	}
	if l.header["tag"] != "v"+v {
		t.Errorf("pinned list tag %q is not the release of version %s", l.header["tag"], v)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(l.header["sha256"]) || !strings.HasPrefix(l.header["source"], "https://") {
		t.Errorf("pinned list does not record its source and digest: %v", l.header)
	}
	if len(l.kind) < 300 {
		t.Fatalf("pinned list has only %d entries; it is truncated", len(l.kind))
	}
	n := 0
	for check, refs := range checkMaps {
		for _, r := range refs {
			if r.Framework != FrameworkATLAS {
				continue
			}
			n++
			switch k := l.kind[r.ID]; {
			case k == "":
				t.Errorf("%q maps to %s, which is not in %s", check, r.ID, ATLASEdition)
			case k != "technique" && k != "sub-technique":
				t.Errorf("%q maps to %s, a %s, not a technique", check, r.ID, k)
			case r.Name != l.name[r.ID]:
				t.Errorf("%q names %s %q; %s names it %q", check, r.ID, r.Name, ATLASEdition, l.name[r.ID])
			}
			if r.Version != v {
				t.Errorf("%q: %s carries version %q, want %q", check, r.ID, r.Version, v)
			}
		}
	}
	if n == 0 {
		t.Fatal("no check maps to ATLAS; the mapping table is not being read")
	}
}

// retiredATLAS are IDs the docs may still name because older reports carry
// them, each with the entry that replaced it.
var retiredATLAS = map[string]string{
	"AML.T0058": "AML.T0115.001", // Publish Poisoned Models, folded into Publish Poisoned AI Artifacts in 2026.07
}

// TestDocsCiteThePinnedATLASEdition: every ATLAS ID the mapping docs cite is
// in the pinned release, or is a retired ID named beside its replacement, and
// the docs name the edition Socair emits. Falsification: cite AML.T0058 as
// current, or a mistyped ID, in docs/control-mapping.md, and this fails.
func TestDocsCiteThePinnedATLASEdition(t *testing.T) {
	l := loadATLASList(t)
	for old, repl := range retiredATLAS {
		if l.kind[old] != "" || l.kind[repl] == "" {
			t.Errorf("retired %s must be absent from the pinned list and its replacement %s present", old, repl)
		}
	}
	id := regexp.MustCompile(`AML\.(?:TA|T|M|CS)\d{4}(?:\.\d{3})?`)
	for _, doc := range []string{"control-mapping.md", "attestation-template.md"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "docs", doc))
		if err != nil {
			t.Fatal(err)
		}
		text := string(raw)
		if !strings.Contains(text, ATLASEdition) {
			t.Errorf("%s does not name %s", doc, ATLASEdition)
		}
		for _, cited := range id.FindAllString(text, -1) {
			if strings.HasPrefix(cited, "AML.TA") {
				continue // tactics are not in the list; the docs cite none
			}
			if l.kind[cited] != "" {
				continue
			}
			if repl, ok := retiredATLAS[cited]; ok && strings.Contains(text, repl) {
				continue
			}
			t.Errorf("%s cites %s, which is not in %s", doc, cited, ATLASEdition)
		}
	}
}

// TestFrameworkEditionsReadTheDocument: the editions a renderer names come
// from the rows, so an older report is not relabelled with today's edition.
func TestFrameworkEditionsReadTheDocument(t *testing.T) {
	old := []CheckResult{{Name: "Known-bad hash match", MapsTo: []FrameworkRef{{Framework: FrameworkATLAS, ID: "AML.T0058", Name: "Publish Poisoned Models"}}}}
	if got := FrameworkEditions(old); got != nil {
		t.Errorf("a report without versions names editions %v", got)
	}
	cur := []CheckResult{{MapsTo: MapsTo("Chat template")}, {MapsTo: MapsTo("License policy")}}
	want := []string{ATLASEdition, FrameworkOWASPLLM + " " + OWASPVersion}
	if got := FrameworkEditions(cur); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("editions %v, want %v", got, want)
	}
}
