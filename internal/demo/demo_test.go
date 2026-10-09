package demo

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/engine"
	"github.com/defilantech/socair/internal/gguf/gguftest"
	"github.com/defilantech/socair/internal/report"
)

func TestSampleDocumentValidates(t *testing.T) {
	d, err := Document()
	if err != nil {
		t.Fatalf("Document: %v", err)
	}
	if problems := report.Validate(d); len(problems) != 0 {
		t.Fatalf("sample report does not validate: %v", problems)
	}
	if len(d.Checks) < 5 {
		t.Errorf("sample should exercise several checks, got %d", len(d.Checks))
	}
}

// TestSampleUsesTheEngineRows: the sample carried rows the engine no longer
// produces ("Safetensors header and opcodes", a Tier 2 row as a check), so it
// showed a report no scan could produce. Its rows are now the engine's GGUF
// rows, in the engine's order and fixed wording, and its out-of-scope section
// is what a Tier 1 scan says. Falsification: rename a row or restore a stale
// one and this fails.
func TestSampleUsesTheEngineRows(t *testing.T) {
	for _, k := range []string{"SOCAIR_REPO_MIRROR", "SOCAIR_DENYLIST", "SOCAIR_PROVENANCE", "SOCAIR_ACCEPTED_BY", "SOCAIR_FEED", "SOCAIR_TOKENIZER_REFERENCE"} {
		t.Setenv(k, "")
	}
	p := filepath.Join(t.TempDir(), "clean-Q5_K_M.gguf")
	if err := os.WriteFile(p, gguftest.BuildGGUF(gguftest.Clean()), 0o600); err != nil {
		t.Fatal(err)
	}
	real, err := engine.Scan(p)
	if err != nil {
		t.Fatal(err)
	}
	d, err := Document()
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Checks) != len(real.Checks) {
		t.Fatalf("sample has %d rows, a GGUF scan has %d", len(d.Checks), len(real.Checks))
	}
	for i, c := range d.Checks {
		r := real.Checks[i]
		if c.Name != r.Name || c.LooksFor != r.LooksFor || c.PassMeans != r.PassMeans || !reflect.DeepEqual(c.MapsTo, r.MapsTo) {
			t.Errorf("sample row %d is %q (%q), the engine's is %q (%q)", i, c.Name, c.LooksFor, r.Name, r.LooksFor)
		}
	}
	if d.AssuranceLevel != real.AssuranceLevel {
		t.Errorf("sample assurance level %+v, the engine's %+v", d.AssuranceLevel, real.AssuranceLevel)
	}
	if !reflect.DeepEqual(d.OutOfScope.NotRun, real.OutOfScope.NotRun) ||
		!reflect.DeepEqual(d.OutOfScope.UntestedNodeClasses, real.OutOfScope.UntestedNodeClasses) {
		t.Errorf("sample out of scope %+v, the engine's %+v", d.OutOfScope, real.OutOfScope)
	}
}

// TestSampleIsMarkedInItsOwnFields: the HTML demo adds a SAMPLE watermark,
// but the document can also be rendered elsewhere (the API renders HTML,
// PDF, and SARIF from it), so its own fields say it is a sample, and it names
// no real issuer.
func TestSampleIsMarkedInItsOwnFields(t *testing.T) {
	d, err := Document()
	if err != nil {
		t.Fatal(err)
	}
	for field, v := range map[string]string{
		"artifact.name":               d.Artifact.Name,
		"header.artifact_short":       d.Header.ArtifactShort,
		"header.document_id":          d.Header.DocumentID,
		"issuer.authority":            d.Issuer.Authority,
		"issuer.signed_by":            d.Issuer.SignedBy,
		"verification.signing_method": d.Verification.SigningMethod,
	} {
		if !strings.Contains(strings.ToLower(v), "sample") {
			t.Errorf("%s = %q does not say it is a sample", field, v)
		}
	}
	if strings.Contains(d.Issuer.Authority+d.Issuer.SignedBy, "Defilan") {
		t.Errorf("the sample names a real issuer: %+v", d.Issuer)
	}
}
