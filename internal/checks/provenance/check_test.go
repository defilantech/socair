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

// artSHA is the sha256 of "x", the artifact body the tests write.
const artSHA = "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881"

const commit = "71034c5d8bde858ff824298bdedc65515b97d2b9"

func TestSignedAndUnsignedProduceDifferentRows(t *testing.T) {
	dir := t.TempDir()
	art := writeFile(t, filepath.Join(dir, "model.gguf"), "x")
	signed := writeFile(t, filepath.Join(dir, "signed.json"),
		`{"artifact_sha256":"`+artSHA+`","publisher":"google","signing_status":"signed","repo_url":"https://huggingface.co/google/gemma","commit_or_tag":"main","commit_sha":"`+commit+`"}`)
	unsigned := writeFile(t, filepath.Join(dir, "unsigned.json"),
		`{"artifact_sha256":"`+artSHA+`","publisher":"somebody","signing_status":"unsigned","repo_url":"https://huggingface.co/somebody/model","commit_or_tag":"v1","commit_sha":"`+commit+`"}`)

	rs := Inspect(Options{ArtifactPath: art, ArtifactSHA256: artSHA, ManifestPath: signed})
	ru := Inspect(Options{ArtifactPath: art, ArtifactSHA256: artSHA, ManifestPath: unsigned})

	if rs.Status != checks.Pass || ru.Status != checks.Pass {
		t.Fatalf("both record a bound, pinned origin: signed=%s (%s) unsigned=%s", rs.Status, rs.Notes, ru.Status)
	}
	if rs.Notes == ru.Notes {
		t.Fatal("a signed and an unsigned upstream must not produce the same row")
	}
	if !strings.Contains(rs.Notes, "claimed signed") || !strings.Contains(rs.Notes, "not verified") {
		t.Errorf("a manifest's signing claim must read as a claim, not a verification: %s", rs.Notes)
	}
	if !strings.Contains(ru.Notes, "not established") {
		t.Errorf("unsigned row must say the signature is not established: %s", ru.Notes)
	}
}

// TestManifestMustNameThisArtifact: a manifest for another artifact, or one
// that names none, says nothing about this one. Falsification: skip the hash
// comparison in Bind and the first two cases PASS.
func TestManifestMustNameThisArtifact(t *testing.T) {
	dir := t.TempDir()
	art := writeFile(t, filepath.Join(dir, "model.gguf"), "x")
	other := strings.Repeat("ab", 32)
	cases := map[string]struct{ manifestSHA, scanSHA string }{
		"another artifact's manifest": {other, artSHA},
		"manifest names no artifact":  {"", artSHA},
		"header-only scan, no hash":   {artSHA, ""},
	}
	for name, c := range cases {
		m := writeFile(t, filepath.Join(dir, "m.json"),
			`{"artifact_sha256":"`+c.manifestSHA+`","repo_url":"https://huggingface.co/a/b","commit_or_tag":"main","commit_sha":"`+commit+`"}`)
		r := Inspect(Options{ArtifactPath: art, ArtifactSHA256: c.scanSHA, ManifestPath: m})
		if r.Status != checks.NotTested {
			t.Errorf("%s: status %s, want NOT_TESTED", name, r.Status)
		}
		if strings.Contains(r.Notes, "huggingface.co/a/b") {
			t.Errorf("%s: an unbound manifest's origin must not be reported as this artifact's: %s", name, r.Notes)
		}
	}
}

// TestMovableRevisionIsNotTested: "main" can point at other bytes tomorrow.
// Falsification: drop the commit requirement and this PASSes.
func TestMovableRevisionIsNotTested(t *testing.T) {
	dir := t.TempDir()
	art := writeFile(t, filepath.Join(dir, "model.gguf"), "x")
	for _, c := range []string{"", "main", "abcdef123456", strings.Repeat("g", 40)} {
		m := writeFile(t, filepath.Join(dir, "m.json"),
			`{"artifact_sha256":"`+artSHA+`","repo_url":"https://huggingface.co/a/b","commit_or_tag":"main","commit_sha":"`+c+`"}`)
		r := Inspect(Options{ArtifactPath: art, ArtifactSHA256: artSHA, ManifestPath: m})
		if r.Status != checks.NotTested || !strings.Contains(r.Notes, "movable revision") {
			t.Errorf("commit %q: %s (%s), want NOT_TESTED naming the movable revision", c, r.Status, r.Notes)
		}
	}
}

// TestEmptyManifestIsNotTested: any JSON manifest used to PASS, even {}. A
// manifest that records no origin is not provenance. Falsification: PASS on
// any parsed manifest again and this fails.
func TestEmptyManifestIsNotTested(t *testing.T) {
	dir := t.TempDir()
	art := writeFile(t, filepath.Join(dir, "model.gguf"), "x")
	for _, body := range []string{`{}`, `{"publisher":"someone"}`, `{"repo_url":"https://huggingface.co/a/b"}`,
		`{"artifact_sha256":"` + artSHA + `","publisher":"someone","commit_sha":"` + commit + `"}`} {
		m := writeFile(t, filepath.Join(dir, "m.json"), body)
		r := Inspect(Options{ArtifactPath: art, ArtifactSHA256: artSHA, ManifestPath: m})
		if r.Status != checks.NotTested {
			t.Errorf("manifest %s: status = %s, want NOT_TESTED without a repo and a revision", body, r.Status)
		}
	}
}

// TestSidecarAloneIsNotVerification: a file named <artifact>.sig used to PASS
// as "signed (local sidecar)" with nothing verified. A sidecar is surfaced,
// never reported as a signature. Falsification: treat the sidecar as signed
// and this fails.
func TestSidecarAloneIsNotVerification(t *testing.T) {
	dir := t.TempDir()
	art := writeFile(t, filepath.Join(dir, "model.gguf"), "x")
	if got := Inspect(Options{ArtifactPath: art}).Status; got != checks.NotTested {
		t.Fatalf("no sidecar and no manifest must be NOT_TESTED, got %s", got)
	}

	writeFile(t, art+".sig", `anything at all`)
	r := Inspect(Options{ArtifactPath: art})
	if r.Status != checks.NotTested {
		t.Fatalf("an unverified sidecar must be NOT_TESTED, got %s", r.Status)
	}
	if !strings.Contains(r.Notes, "model.gguf.sig") || !strings.Contains(r.Notes, "not verified") {
		t.Errorf("the sidecar must be named as unverified: %s", r.Notes)
	}
	if strings.Contains(r.Notes, "signing signed") || strings.Contains(r.Notes, "signed (") {
		t.Errorf("an unverified sidecar must never read as signed: %s", r.Notes)
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
