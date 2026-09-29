package engine

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/gguf/gguftest"
	"github.com/defilantech/socair/internal/render"
	"github.com/defilantech/socair/internal/render/pdf"
	"github.com/defilantech/socair/internal/render/sarif"
	"github.com/defilantech/socair/internal/report"
)

// supplyInputs sets the three operational inputs the trust rows need: a repo
// mirror, a denylist, and a provenance manifest. Without them those rows are
// NOT_TESTED, which is correct but means the all-PASS path never runs.
func supplyInputs(t *testing.T) {
	t.Helper()
	dir := t.TempDir()

	mirror := filepath.Join(dir, "mirror")
	if err := os.MkdirAll(mirror, 0o755); err != nil {
		t.Fatalf("mirror: %v", err)
	}
	if err := os.WriteFile(filepath.Join(mirror, "config.json"), []byte("{}"), 0o600); err != nil {
		t.Fatalf("mirror file: %v", err)
	}
	t.Setenv("SOCAIR_REPO_MIRROR", mirror)

	deny := filepath.Join(dir, "denylist.txt")
	// A list that is non-empty but does not contain the fixture hash.
	if err := os.WriteFile(deny, []byte("0000000000000000000000000000000000000000000000000000000000000000  known-bad\n"), 0o600); err != nil {
		t.Fatalf("denylist: %v", err)
	}
	t.Setenv("SOCAIR_DENYLIST", deny)

	prov := filepath.Join(dir, "provenance.json")
	if err := os.WriteFile(prov, []byte(`{"publisher":"example","signing_status":"signed","commit_or_tag":"main"}`), 0o600); err != nil {
		t.Fatalf("provenance: %v", err)
	}
	t.Setenv("SOCAIR_PROVENANCE", prov)
}

func TestHappyPathAllRowsPopulate(t *testing.T) {
	supplyInputs(t)

	// A fixture whose declared quant matches the metadata file type, so the
	// quant row can PASS.
	p := writeFixture(t, "fixture-Q5_K_M.gguf", gguftest.BuildGGUF(gguftest.Clean()))

	d, err := Scan(p)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if len(d.Checks) == 0 {
		t.Fatal("no checks ran")
	}
	for _, c := range d.Checks {
		if c.Status != report.StatusPass {
			t.Errorf("check %q = %s, want PASS (notes: %s)", c.Name, c.Status, c.Notes)
		}
	}
	if !d.PromotionAuthorization.Authorized || d.PromotionAuthorization.State != report.StateAuthorized {
		t.Fatalf("a fully populated report must be authorized, got state=%s authorized=%v conditions=%s",
			d.PromotionAuthorization.State, d.PromotionAuthorization.Authorized, d.PromotionAuthorization.Conditions)
	}
	if len(d.PromotionAuthorization.AcceptedSurfaces) != 0 {
		t.Errorf("a clean report must carry no accepted surfaces, got %v", d.PromotionAuthorization.AcceptedSurfaces)
	}
	if problems := report.Validate(d); len(problems) != 0 {
		t.Fatalf("happy path produced an invalid report: %v", problems)
	}

	// All three renderers must carry the populated document.
	var html, pdfBuf, sarifBuf bytes.Buffer
	if err := render.Render(&html, d); err != nil {
		t.Fatalf("render html: %v", err)
	}
	if err := pdf.RenderPDF(&pdfBuf, d); err != nil {
		t.Fatalf("render pdf: %v", err)
	}
	if err := sarif.Render(&sarifBuf, d); err != nil {
		t.Fatalf("render sarif: %v", err)
	}
	if !bytes.HasPrefix(pdfBuf.Bytes(), []byte("%PDF-")) {
		t.Error("pdf output is not a PDF")
	}
	if !strings.Contains(html.String(), `class="badge promo authorized"`) {
		t.Error("the html must show the clean authorized badge")
	}
	if !strings.Contains(sarifBuf.String(), `"socairPromotionState": "authorized"`) {
		t.Error("sarif must carry the promotion state as authorized")
	}
}

// Falsification for the happy path: remove one supplied input and the report
// must drop to the correct NOT_TESTED, not stay all-PASS.
func TestHappyPathDropsOneInput(t *testing.T) {
	supplyInputs(t)
	t.Setenv("SOCAIR_PROVENANCE", "") // remove the provenance input

	p := writeFixture(t, "fixture-Q5_K_M.gguf", gguftest.BuildGGUF(gguftest.Clean()))
	d, err := Scan(p)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	var provenance report.Status
	for _, c := range d.Checks {
		if c.Name == "Hash, provenance, lineage" {
			provenance = c.Status
		}
	}
	if provenance != report.StatusNotTested {
		t.Fatalf("without the provenance input the row must be NOT_TESTED, got %s", provenance)
	}
	if d.PromotionAuthorization.State != report.StateWithheld {
		t.Fatalf("unaccepted gaps must withhold, got %s", d.PromotionAuthorization.State)
	}
}
