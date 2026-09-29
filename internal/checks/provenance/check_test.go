package provenance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/checks"
)

func writeFile(t *testing.T, path, body string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
	return path
}

func TestNoInputNotTested(t *testing.T) {
	art := writeFile(t, filepath.Join(t.TempDir(), "model.gguf"), "not really a model")
	r := Inspect(Options{ArtifactPath: art})
	if r.Status != checks.NotTested {
		t.Fatalf("status = %s, want NOT_TESTED", r.Status)
	}
	if r.Notes == "" {
		t.Error("NOT_TESTED must carry a reason")
	}
}

func TestSignedAndUnsignedProduceDifferentRows(t *testing.T) {
	dir := t.TempDir()
	art := writeFile(t, filepath.Join(dir, "model.gguf"), "x")
	signed := writeFile(t, filepath.Join(dir, "signed.json"),
		`{"publisher":"google","signing_status":"signed","repo_url":"https://huggingface.co/google/gemma","commit_or_tag":"main","commit_sha":"abcdef123456"}`)
	unsigned := writeFile(t, filepath.Join(dir, "unsigned.json"),
		`{"publisher":"somebody","signing_status":"unsigned"}`)

	rs := Inspect(Options{ArtifactPath: art, ManifestPath: signed})
	ru := Inspect(Options{ArtifactPath: art, ManifestPath: unsigned})

	if rs.Status != checks.Pass || ru.Status != checks.Pass {
		t.Fatalf("both should record provenance: signed=%s unsigned=%s", rs.Status, ru.Status)
	}
	if rs.Notes == ru.Notes {
		t.Fatal("a signed and an unsigned upstream must not produce the same row")
	}
	if !strings.Contains(rs.Notes, "signing signed") {
		t.Errorf("signed row missing signing: %s", rs.Notes)
	}
	if !strings.Contains(ru.Notes, "not established") {
		t.Errorf("unsigned row must say the signature is not established: %s", ru.Notes)
	}
}

// Falsification anchor: a sidecar alone is enough, and removing it must flip
// the row back to NOT_TESTED.
func TestSidecarAloneRecordsProvenance(t *testing.T) {
	dir := t.TempDir()
	art := writeFile(t, filepath.Join(dir, "model.gguf"), "x")
	if got := Inspect(Options{ArtifactPath: art}).Status; got != checks.NotTested {
		t.Fatalf("no sidecar and no manifest must be NOT_TESTED, got %s", got)
	}

	writeFile(t, art+".sigstore.json", `{"note":"signature"}`)
	r := Inspect(Options{ArtifactPath: art})
	if r.Status != checks.Pass {
		t.Fatalf("a signature sidecar must record provenance, got %s", r.Status)
	}
	if !strings.Contains(r.Notes, "sidecar") {
		t.Errorf("sidecar not surfaced: %s", r.Notes)
	}
}

func TestMalformedManifestNotTested(t *testing.T) {
	dir := t.TempDir()
	art := writeFile(t, filepath.Join(dir, "model.gguf"), "x")
	bad := writeFile(t, filepath.Join(dir, "bad.json"), "{not json")
	if got := Inspect(Options{ArtifactPath: art, ManifestPath: bad}).Status; got != checks.NotTested {
		t.Fatalf("a malformed manifest must be NOT_TESTED, got %s", got)
	}
}
