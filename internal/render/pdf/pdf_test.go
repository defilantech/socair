package pdf

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

func render(t *testing.T, d *report.Document) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := RenderPDF(&b, d); err != nil {
		t.Fatalf("RenderPDF: %v", err)
	}
	return b.Bytes()
}

func TestPDFRenders(t *testing.T) {
	out := render(t, loadGolden(t))
	if !bytes.HasPrefix(out, []byte("%PDF-")) {
		t.Fatalf("output is not a PDF, starts with %q", out[:min(8, len(out))])
	}
	if len(out) < 1000 {
		t.Fatalf("PDF is implausibly small: %d bytes", len(out))
	}
}

func TestPDFIsByteStable(t *testing.T) {
	d := loadGolden(t)
	a := render(t, d)
	b := render(t, d)
	if !bytes.Equal(a, b) {
		t.Fatal("PDF output is not deterministic; check the creation date and producer")
	}
}

// The status styling is the falsification anchor: each status must map to a
// distinct color, or a FAIL could render as a pass.
func TestStatusColorsAreDistinct(t *testing.T) {
	passBG, passInk := statusColors(report.StatusPass)
	failBG, failInk := statusColors(report.StatusFail)
	untBG, untInk := statusColors(report.StatusNotTested)

	if passBG == failBG || passBG == untBG || failBG == untBG {
		t.Errorf("status backgrounds must be distinct: pass=%v fail=%v unt=%v", passBG, failBG, untBG)
	}
	if passInk == failInk {
		t.Errorf("pass and fail text colors must differ: %v", passInk)
	}
	if untInk == passInk {
		t.Errorf("NOT_TESTED must not share the pass text color: %v", untInk)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
