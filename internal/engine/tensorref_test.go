package engine

import (
	"encoding/binary"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/report"
	"github.com/defilantech/socair/internal/safetensors/safetensorstest"
	"github.com/defilantech/socair/internal/tensors"
)

// writeWeights writes a safetensors file with two F32 tensors holding vals.
func writeWeights(t *testing.T, path string, vals [8]float32) {
	t.Helper()
	out := safetensorstest.Build(nil, []safetensorstest.TensorSpec{
		{Name: "layers.0.w", Dtype: "F32", Shape: []int64{2, 2}, Start: 0, End: 16},
		{Name: "layers.1.w", Dtype: "F32", Shape: []int64{2, 2}, Start: 16, End: 32},
	})
	start := 8 + int(binary.LittleEndian.Uint64(out[:8]))
	for i, v := range vals {
		binary.LittleEndian.PutUint32(out[start+4*i:], math.Float32bits(v))
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
}

func tensorRowOf(t *testing.T, d *report.Document) report.CheckResult {
	t.Helper()
	for _, c := range d.Checks {
		if c.Name == report.TensorReferenceCheck {
			return c
		}
	}
	t.Fatalf("no %s row in %v", report.TensorReferenceCheck, d.Checks)
	return report.CheckResult{}
}

// TestTensorReferenceRow: with SOCAIR_TENSOR_REFERENCE set, a scan compares
// the scanned bytes' tensors with the reference. The same weights PASS; one
// changed value is a LEAD that withholds; without the input there is no row.
// Falsification: drop the row, or compare names only, and this fails.
func TestTensorReferenceRow(t *testing.T) {
	for _, k := range []string{"SOCAIR_FEED", "SOCAIR_DENYLIST", "SOCAIR_TEMPLATE_REFERENCE", "SOCAIR_TOKENIZER_REFERENCE",
		"SOCAIR_LICENSE_POLICY", "SOCAIR_INTAKE_POLICY", "SOCAIR_PROVENANCE", "SOCAIR_TENSOR_REFERENCE"} {
		t.Setenv(k, "")
	}
	dir := t.TempDir()
	ref := filepath.Join(dir, "reviewed.safetensors")
	writeWeights(t, ref, [8]float32{1, 2, 3, 4, 5, 6, 7, 8})
	m, err := tensors.File(ref, "")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(m)
	manifestPath := filepath.Join(dir, "reviewed.tensors.json")
	if err := os.WriteFile(manifestPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	d, err := Scan(ref)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range d.Checks {
		if c.Name == report.TensorReferenceCheck {
			t.Fatal("a scan without SOCAIR_TENSOR_REFERENCE has a Tensor reference row")
		}
	}

	t.Setenv("SOCAIR_TENSOR_REFERENCE", manifestPath)
	same := filepath.Join(dir, "copy.safetensors")
	writeWeights(t, same, [8]float32{1, 2, 3, 4, 5, 6, 7, 8})
	d, err = Scan(same)
	if err != nil {
		t.Fatal(err)
	}
	if row := tensorRowOf(t, d); row.Status != report.StatusPass {
		t.Fatalf("the same weights: %s %s", row.Status, row.Notes)
	}
	if !strings.Contains(d.Scope.ReferenceData, "tensor reference reviewed.tensors.json (sha256 ") || strings.Contains(d.Scope.ReferenceData, dir) {
		t.Fatalf("reference_data %q must name the manifest by file name and hash, not its path", d.Scope.ReferenceData)
	}
	if problems := report.Validate(d); len(problems) != 0 {
		t.Fatalf("the report does not validate: %v", problems)
	}

	changed := filepath.Join(dir, "changed.safetensors")
	writeWeights(t, changed, [8]float32{1, 2, 3, 4, 5, 6, 7, 8.5})
	d, err = Scan(changed)
	if err != nil {
		t.Fatal(err)
	}
	row := tensorRowOf(t, d)
	if row.Status != report.StatusLead || !strings.Contains(row.Evidence, "layers.1.w") || strings.Contains(row.Evidence, "layers.0.w") {
		t.Fatalf("one changed value: %s %q %s", row.Status, row.Evidence, row.Notes)
	}
	if d.PromotionAuthorization.Authorized {
		t.Fatal("a LEAD on the Tensor reference row authorized promotion")
	}

	// A reference that does not load stops the scan.
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"schema":"socair.tensors/v0"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOCAIR_TENSOR_REFERENCE", bad)
	if _, err := Scan(same); err == nil || !strings.Contains(err.Error(), "SOCAIR_TENSOR_REFERENCE") {
		t.Fatalf("an unreadable reference: %v", err)
	}
}
