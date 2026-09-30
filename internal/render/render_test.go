package render

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/report"
)

func loadGolden(t *testing.T) *report.Document {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "report.json"))
	if err != nil {
		t.Fatalf("reading golden: %v", err)
	}
	var d report.Document
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatalf("unmarshal golden: %v", err)
	}
	return &d
}

func renderString(t *testing.T, d *report.Document) string {
	t.Helper()
	var b bytes.Buffer
	if err := Render(&b, d); err != nil {
		t.Fatalf("Render: %v", err)
	}
	return b.String()
}

func TestRenderIsByteStable(t *testing.T) {
	d := loadGolden(t)
	a := renderString(t, d)
	b := renderString(t, d)
	if a != b {
		t.Fatal("rendering the same document twice produced different output")
	}
}

func TestRenderCarriesFixedLanguage(t *testing.T) {
	out := renderString(t, loadGolden(t))
	if !strings.Contains(out, report.BoundedStatement) {
		t.Error("rendered report does not carry the bounded statement")
	}
	if !strings.Contains(out, report.DoesNotCertify) {
		t.Error("rendered report does not carry the ceiling sentence")
	}
}

// A NOT_TESTED row must read as neutral, never as a pass. This is the A1
// decision, enforced as a test.
func TestNotTestedNeverLooksLikeAPass(t *testing.T) {
	out := renderString(t, loadGolden(t))
	if !strings.Contains(out, `class="pill not-tested"`) {
		t.Error("NOT_TESTED rows must render with the not-tested pill class")
	}
	if !strings.Contains(out, `<span class="tag">not tested</span>`) {
		t.Error("NOT_TESTED rows must carry the explicit 'not tested' tag")
	}
	// A row that is NOT_TESTED must not be dressed as a pass.
	if strings.Contains(out, `class="pill pass">NOT_TESTED`) {
		t.Error("a NOT_TESTED status must never render with the pass class")
	}
}

func TestFailRendersAsFail(t *testing.T) {
	d := loadGolden(t)
	d.Checks[0].Status = report.StatusFail
	d.Checks[0].Evidence = "quant-mismatch: declared Q5_K_M but observed F16"
	out := renderString(t, d)
	if !strings.Contains(out, `class="pill fail"`) {
		t.Error("a FAIL row must render with the fail class")
	}
	if !strings.Contains(out, "quant-mismatch") {
		t.Error("the FAIL evidence must appear in the report")
	}
}

// The demo build must be unmistakable as sample data.
func TestSampleMarkIsPresent(t *testing.T) {
	d := loadGolden(t)
	var b bytes.Buffer
	if err := RenderWith(&b, d, Options{Sample: true}); err != nil {
		t.Fatalf("RenderWith: %v", err)
	}
	out := b.String()
	if !strings.Contains(out, ">SAMPLE<") {
		t.Error("the sample build must carry the SAMPLE watermark")
	}
	if !strings.Contains(out, "NOT A REAL ISSUANCE") {
		t.Error("the sample build must carry the footer mark")
	}
	if !strings.Contains(out, "Sample data") {
		t.Error("the sample build must carry the header chip")
	}

	// A real issuance must carry none of it.
	var r bytes.Buffer
	if err := Render(&r, d); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if strings.Contains(r.String(), "NOT A REAL ISSUANCE") {
		t.Error("a real issuance must not carry the sample mark")
	}
}

// The condition state must never render as the clean pass badge.
func TestConditionBadgeIsNotClean(t *testing.T) {
	d := loadGolden(t)
	d.PromotionAuthorization = report.PromotionAuthorization{
		Authorized:       true,
		State:            report.StateAuthorizedWithConditions,
		AcceptedBy:       "ciso@example.com",
		AcceptedAt:       "2026-09-29T00:00:00Z",
		AcceptedSurfaces: []string{"Hash, provenance, lineage"},
	}
	out := renderString(t, d)
	if !strings.Contains(out, `class="badge promo conditions"`) {
		t.Error("the condition state must render with its own badge class")
	}
	if strings.Contains(out, `class="badge promo authorized"`) {
		t.Error("the condition state must never render with the clean authorized badge")
	}
	if !strings.Contains(out, "Accepted by ciso@example.com") {
		t.Error("the acceptance owner must appear on the report")
	}
	if !strings.Contains(out, "Hash, provenance, lineage") {
		t.Error("the accepted surfaces must appear on the report")
	}
}

func TestPromotionClassMapping(t *testing.T) {
	if promotionClass(report.StateAuthorizedWithConditions) == promotionClass(report.StateAuthorized) {
		t.Fatal("the condition state must not share the clean badge class")
	}
	if promotionClass(report.StateWithheld) == promotionClass(report.StateAuthorized) {
		t.Fatal("withheld must not share the clean badge class")
	}
}

func TestStatusClassMapping(t *testing.T) {
	cases := map[report.Status]string{
		report.StatusPass:      "pass",
		report.StatusFail:      "fail",
		report.StatusNotTested: "not-tested",
		"":                     "not-tested", // anything unknown is neutral, never a pass
	}
	for in, want := range cases {
		if got := statusClass(in); got != want {
			t.Errorf("statusClass(%q) = %q, want %q", in, got, want)
		}
	}
}

// The report links the published detection ceiling, so a reader of the
// attestation can see the same list outside the document.
func TestReportLinksTheCeiling(t *testing.T) {
	d := loadGolden(t)
	html := renderString(t, d)
	if !strings.Contains(html, CeilingURL) {
		t.Fatalf("the report must name the published ceiling %q", CeilingURL)
	}
	if !strings.Contains(html, `href="`+CeilingURL+`"`) {
		t.Errorf("the ceiling must be an anchor to %q", CeilingURL)
	}
}
