package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/report"
	"github.com/defilantech/socair/internal/safetensors/safetensorstest"
)

func hexSum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// A directory whose weights changed after its uploader's SHA256SUMS was
// written is a provenance LEAD and is withheld. The list compared is the one
// in the snapshot, part of the attested bytes: rewriting it on disk once the
// snapshot is taken changes nothing.
func TestDirectoryChecksumListDisagreementWithholds(t *testing.T) {
	listed := safetensorstest.Clean()
	dir := modelRepo(t, map[string]string{
		"SHA256SUMS": hexSum(listed) + "  ./model.safetensors\n",
		"model.safetensors": string(safetensorstest.Build(map[string]string{"format": "pt", "author": "re-uploaded"},
			[]safetensorstest.TensorSpec{{Name: "w", Start: 0, End: 64, Dtype: "F32", Shape: []int64{16}}})),
	})
	afterSnapshot = func(string) {
		b, _ := os.ReadFile(filepath.Join(dir, "model.safetensors"))
		_ = os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(hexSum(b)+"  ./model.safetensors\n"), 0o644)
	}
	t.Cleanup(func() { afterSnapshot = nil })
	d, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if problems := report.Validate(d); len(problems) != 0 {
		t.Fatal(problems)
	}
	r := row(d, "Hash, provenance, lineage")
	if r.Status != report.StatusLead || !strings.Contains(r.Evidence, "checksum-mismatch: model.safetensors") || r.Severity != report.SeverityMedium {
		t.Fatalf("provenance %s (%s), evidence %q", r.Status, r.Severity, r.Evidence)
	}
	if d.PromotionAuthorization.Authorized {
		t.Fatalf("a LEAD withholds: %s", d.PromotionAuthorization.State)
	}
}

// A single file's lists sit beside it: one that disagrees is a LEAD, named
// by its file name and the hash of what was read, and no host path reaches
// the report.
func TestSingleFileChecksumSidecar(t *testing.T) {
	dir := t.TempDir()
	art := filepath.Join(dir, "model.safetensors")
	if err := os.WriteFile(art, safetensorstest.Clean(), 0o644); err != nil {
		t.Fatal(err)
	}
	sidecar := []byte(strings.Repeat("0", 64) + "\n")
	if err := os.WriteFile(art+".sha256", sidecar, 0o644); err != nil {
		t.Fatal(err)
	}
	d, err := Scan(art)
	if err != nil {
		t.Fatal(err)
	}
	r := row(d, "Hash, provenance, lineage")
	if r.Status != report.StatusLead || !strings.Contains(r.Evidence, "model.safetensors.sha256 (sha256 "+hexSum(sidecar)+", beside the artifact) line 1") {
		t.Fatalf("provenance %s, evidence %q", r.Status, r.Evidence)
	}
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), dir) {
		t.Fatalf("the report names the scanning host's path %s", dir)
	}

	// The sidecar that agrees is noted and moves nothing.
	if err := os.WriteFile(art+".sha256", []byte(hexSum(safetensorstest.Clean())+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if d, err = Scan(art); err != nil {
		t.Fatal(err)
	}
	if r := row(d, "Hash, provenance, lineage"); r.Status != report.StatusNotTested || !strings.Contains(r.Notes, "Agree with the bytes the scan hashed: 1 (model.safetensors)") {
		t.Fatalf("an agreeing sidecar is noted, not graded: %s (%s)", r.Status, r.Notes)
	}
}
