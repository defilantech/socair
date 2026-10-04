package sarif

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/defilantech/socair/internal/report"
)

func loadGolden(t *testing.T) *report.Document {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "report.json"))
	if err != nil {
		t.Fatalf("reading golden: %v", err)
	}
	var d report.Document
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatalf("unmarshal golden: %v", err)
	}
	return &d
}

func TestSARIFVersionAndShape(t *testing.T) {
	d := loadGolden(t)
	d.Checks[0].Status = report.StatusPass
	d.Checks[1].Status = report.StatusFail
	d.Checks[2].Status = report.StatusNotTested

	var b bytes.Buffer
	if err := Render(&b, d); err != nil {
		t.Fatalf("Render: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(b.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if got["version"] != "2.1.0" {
		t.Errorf("version = %v, want 2.1.0", got["version"])
	}
	runs, ok := got["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("expected one run, got %v", got["runs"])
	}
}

func TestSARIFLevelMapping(t *testing.T) {
	cases := map[report.Status]string{
		report.StatusFail:      "error",
		report.StatusLead:      "warning",
		report.StatusNotTested: "note",
		report.StatusPass:      "none",
	}
	for in, want := range cases {
		if got := level(in); got != want {
			t.Errorf("level(%s) = %s, want %s", in, got, want)
		}
	}
}

func TestSARIFIsByteStable(t *testing.T) {
	d := loadGolden(t)
	var a, b bytes.Buffer
	if err := Render(&a, d); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if err := Render(&b, d); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatal("SARIF output is not deterministic")
	}
}

func TestRuleIDFromCheckName(t *testing.T) {
	if got := ruleID("Chat template (hero)"); got != "chat-template-hero" {
		t.Errorf("ruleID = %q, want chat-template-hero", got)
	}
}

// TestSARIFCarriesSeverityAndFrameworks: code-scanning tools sort by a rule's
// security-severity and filter by its tags, so a FAIL row carries both, and a
// PASS row carries its framework tags without a severity (#132).
func TestSARIFCarriesSeverityAndFrameworks(t *testing.T) {
	d := &report.Document{Checks: []report.CheckResult{
		{Name: "Pickle opcode scan", Status: report.StatusFail, Severity: report.SeverityCritical, MapsTo: report.MapsTo("Pickle opcode scan")},
		{Name: "Quant match", Status: report.StatusPass, MapsTo: report.MapsTo("Quant match")},
	}}
	rules := Build(d).Runs[0].Tool.Driver.Rules
	fail, pass := rules[0].Properties, rules[1].Properties
	if fail == nil || fail.SecuritySeverity != "9.5" {
		t.Fatalf("critical FAIL rule properties = %+v, want security-severity 9.5", fail)
	}
	if !slices.Contains(fail.Tags, "external/atlas/AML.T0011.000") || !slices.Contains(fail.Tags, "external/owasp-llm/LLM03") {
		t.Errorf("tags = %v", fail.Tags)
	}
	if pass == nil || pass.SecuritySeverity != "" || len(pass.Tags) == 0 {
		t.Errorf("PASS rule properties = %+v, want tags and no severity", pass)
	}
}
