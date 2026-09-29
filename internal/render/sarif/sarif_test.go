package sarif

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
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
