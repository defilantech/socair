package pdf

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-pdf/fpdf"

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

// coverText draws the cover block alone, uncompressed, so its text can be
// searched.
func coverText(t *testing.T, d *report.Document) string {
	t.Helper()
	p := fpdf.New("P", "mm", "A4", "")
	p.SetCompression(false)
	p.AddPage()
	cover(p, d)
	var b bytes.Buffer
	if err := p.Output(&b); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// TestAcceptedLineOnlyUnderConditions: the cover printed "Accepted, not
// tested" for any report that listed accepted surfaces, a withheld one
// included. Falsification: test the list alone and the withheld case prints
// it.
func TestAcceptedLineOnlyUnderConditions(t *testing.T) {
	for _, state := range []string{report.StateWithheld, report.StateEscalated, report.StateAuthorized} {
		d := loadGolden(t)
		d.PromotionAuthorization.State = state
		d.PromotionAuthorization.AcceptedSurfaces = d.Findings.NotTested
		d.PromotionAuthorization.AcceptedBy = "Jane Doe, CISO"
		if strings.Contains(coverText(t, d), "Accepted, not tested") {
			t.Errorf("a report in state %s must not print an acceptance", state)
		}
	}
	d := loadGolden(t)
	d.PromotionAuthorization.State = report.StateAuthorizedWithConditions
	d.PromotionAuthorization.Authorized = true
	d.PromotionAuthorization.AcceptedSurfaces = d.Findings.NotTested
	d.PromotionAuthorization.AcceptedBy = "Jane Doe, CISO"
	if !strings.Contains(coverText(t, d), "Accepted, not tested") {
		t.Error("an authorized_with_conditions report must print what was accepted")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
