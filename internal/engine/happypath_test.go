package engine

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/gguf/gguftest"
	"github.com/defilantech/socair/internal/render"
	"github.com/defilantech/socair/internal/render/pdf"
	"github.com/defilantech/socair/internal/render/sarif"
	"github.com/defilantech/socair/internal/report"
	"github.com/defilantech/socair/internal/safetensors/safetensorstest"
)

// supplyInputs sets the three operational inputs the trust rows need: a repo
// mirror, a denylist, and a provenance manifest. Without them those rows are
// NOT_TESTED, which is correct but means the all-PASS path never runs. The
// manifest binds only to the artifact whose bytes are passed, so a test that
// needs the provenance row to PASS passes its fixture.
func supplyInputs(t *testing.T, artifact ...[]byte) {
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

	sha := ""
	if len(artifact) > 0 {
		sum := sha256.Sum256(artifact[0])
		sha = hex.EncodeToString(sum[:])
	}
	prov := filepath.Join(dir, "provenance.json")
	manifest := fmt.Sprintf(`{"artifact_sha256":%q,"publisher":"example","signing_status":"signed","repo_url":"https://huggingface.co/example/model","commit_or_tag":"main","commit_sha":"71034c5d8bde858ff824298bdedc65515b97d2b9"}`, sha)
	if err := os.WriteFile(prov, []byte(manifest), 0o600); err != nil {
		t.Fatalf("provenance: %v", err)
	}
	t.Setenv("SOCAIR_PROVENANCE", prov)
}

// TestHappyPathAllRowsPopulate: with every input supplied, a safetensors
// artifact PASSes every row and reaches a clean authorization.
func TestHappyPathAllRowsPopulate(t *testing.T) {
	supplyInputs(t, safetensorstest.Clean())

	p := writeFixture(t, "fixture.safetensors", safetensorstest.Clean())

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

// TestGGUFHappyPathIsConditional: a GGUF's tokenizer row is a label-only
// NOT_TESTED, so with every input supplied the best Tier 1 outcome is an
// authorization with that one gap named and accepted, never a clean one.
func TestGGUFHappyPathIsConditional(t *testing.T) {
	supplyInputs(t, gguftest.CleanQ5KM())
	t.Setenv("SOCAIR_ACCEPTED_BY", "ciso@example.com")

	p := writeFixture(t, "fixture-Q5_K_M.gguf", gguftest.CleanQ5KM())
	d, err := Scan(p)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, c := range d.Checks {
		want := report.StatusPass
		if c.Name == "Tokenizer config" {
			want = report.StatusNotTested
		}
		if c.Status != want {
			t.Errorf("check %q = %s, want %s (notes: %s)", c.Name, c.Status, want, c.Notes)
		}
	}
	pa := d.PromotionAuthorization
	if pa.State != report.StateAuthorizedWithConditions {
		t.Fatalf("state = %s, want authorized_with_conditions", pa.State)
	}
	if len(pa.AcceptedSurfaces) != 1 || pa.AcceptedSurfaces[0] != "Tokenizer config" {
		t.Fatalf("accepted surfaces = %v, want [Tokenizer config]", pa.AcceptedSurfaces)
	}
	if problems := report.Validate(d); len(problems) != 0 {
		t.Fatalf("invalid report: %v", problems)
	}
}

// Falsification for the happy path: remove one supplied input and the report
// must drop to the correct NOT_TESTED, not stay all-PASS.
func TestHappyPathDropsOneInput(t *testing.T) {
	supplyInputs(t)
	t.Setenv("SOCAIR_PROVENANCE", "") // remove the provenance input

	p := writeFixture(t, "fixture.safetensors", safetensorstest.Clean())
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

// TestGGUFWithTokenizerAuthorizes: with the tokenizer inspected rather than
// read as a label, a GGUF whose every row PASSes reaches a clean
// authorization, which no GGUF could before (#82).
func TestGGUFWithTokenizerAuthorizes(t *testing.T) {
	// A Q5_K tensor, so the quant row judges the tensors rather than labels.
	fixture := gguftest.BuildWithTensors(append(gguftest.Clean(), gguftest.Vocab()...),
		[]gguftest.Tensor{{Name: "blk.0.attn_q.weight", Dims: []uint64{256}, Type: 13}}, 176)
	supplyInputs(t, fixture)
	p := writeFixture(t, "fixture-Q5_K_M.gguf", fixture)
	d, err := Scan(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range d.Checks {
		if c.Status != report.StatusPass {
			t.Errorf("check %q = %s (%s), want PASS", c.Name, c.Status, c.Notes)
		}
	}
	if len(d.Artifact.TokenizerHash) != 64 {
		t.Errorf("tokenizer_hash %q, want the vocabulary hash", d.Artifact.TokenizerHash)
	}
	if d.PromotionAuthorization.State != report.StateAuthorized {
		t.Fatalf("state = %s, want authorized", d.PromotionAuthorization.State)
	}
}

// TestBoundProvenanceFillsIdentity: a manifest bound to the artifact fills
// the identity section; one for another artifact fills nothing. Falsification:
// fill identity from any parsed manifest and the second half fails.
func TestBoundProvenanceFillsIdentity(t *testing.T) {
	fixture := safetensorstest.Clean()
	supplyInputs(t, fixture)
	p := writeFixture(t, "fixture.safetensors", fixture)
	d, err := Scan(p)
	if err != nil {
		t.Fatal(err)
	}
	a := d.Artifact
	if a.RepoURL == "" || a.CommitSHA != "71034c5d8bde858ff824298bdedc65515b97d2b9" || a.Publisher != "example" || a.CommitOrTag != "main" {
		t.Fatalf("a bound manifest must fill identity, got repo=%q commit=%q publisher=%q rev=%q", a.RepoURL, a.CommitSHA, a.Publisher, a.CommitOrTag)
	}
	if !strings.Contains(a.PublisherSigningState, "not verified") {
		t.Errorf("a manifest's signing claim must read as a claim, got %q", a.PublisherSigningState)
	}

	supplyInputs(t, []byte("some other artifact"))
	d, err = Scan(p)
	if err != nil {
		t.Fatal(err)
	}
	if d.Artifact.RepoURL != "" || d.Artifact.CommitSHA != "" || d.Artifact.Publisher != "" {
		t.Fatalf("another artifact's manifest must not fill identity, got %+v", d.Artifact)
	}
	for _, c := range d.Checks {
		if c.Name == "Hash, provenance, lineage" && c.Status != report.StatusNotTested {
			t.Errorf("provenance row = %s with another artifact's manifest, want NOT_TESTED", c.Status)
		}
	}
}
