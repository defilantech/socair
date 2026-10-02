package inventory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/gguf/gguftest"
)

func writeFixture(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	return p
}

func TestCleanArtifactWithoutMirrorIsNotTested(t *testing.T) {
	p := writeFixture(t, "clean-Q5_K_M.gguf", gguftest.BuildGGUF(gguftest.Clean()))
	r := Inspect(p, Options{})
	if r.Status != checks.NotTested {
		t.Fatalf("status = %s, want NOT_TESTED with no repo mirror", r.Status)
	}
	if r.Notes == "" {
		t.Error("NOT_TESTED must carry a reason")
	}
}

func TestCleanArtifactWithCleanMirrorPasses(t *testing.T) {
	p := writeFixture(t, "clean-Q5_K_M.gguf", gguftest.BuildGGUF(gguftest.Clean()))

	mirror := t.TempDir()
	_ = os.WriteFile(filepath.Join(mirror, "config.json"), []byte("{}"), 0o600)
	_ = os.WriteFile(filepath.Join(mirror, "tokenizer.py"), []byte("# model repo script"), 0o600)

	r := Inspect(p, Options{RepoMirror: mirror})
	if r.Status != checks.Pass {
		t.Fatalf("status = %s, want PASS (scripts inventoried, not failed): %s", r.Status, r.Notes)
	}
}

func TestEmbeddedScriptInMetadataFails(t *testing.T) {
	kvs := gguftest.WithMeta("general.name", gguftest.Str("general.name", "<script>fetch('http://x')</script>"))
	p := writeFixture(t, "payload-Q5_K_M.gguf", gguftest.BuildGGUF(kvs))

	r := Inspect(p, Options{})
	if r.Status != checks.Fail {
		t.Fatalf("status = %s, want FAIL", r.Status)
	}
	if len(r.Findings) == 0 {
		t.Fatal("expected a finding on embedded script content")
	}
}

func TestEmbeddedBase64BlobFails(t *testing.T) {
	blob := ""
	for i := 0; i < 600; i++ {
		blob += "A"
	}
	kvs := gguftest.WithMeta("general.name", gguftest.Str("general.name", blob))
	p := writeFixture(t, "blob-Q5_K_M.gguf", gguftest.BuildGGUF(kvs))

	if got := Inspect(p, Options{}).Status; got != checks.Fail {
		t.Fatalf("status = %s, want FAIL on a large base64 blob", got)
	}
}

func TestRepoBinaryFails(t *testing.T) {
	p := writeFixture(t, "clean-Q5_K_M.gguf", gguftest.BuildGGUF(gguftest.Clean()))

	mirror := t.TempDir()
	elf := append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, 16)...)
	if err := os.WriteFile(filepath.Join(mirror, "helper"), elf, 0o600); err != nil {
		t.Fatalf("writing elf: %v", err)
	}

	r := Inspect(p, Options{RepoMirror: mirror})
	if r.Status != checks.Fail {
		t.Fatalf("status = %s, want FAIL on a repo binary", r.Status)
	}
}

// TestShortMagicInTextDoesNotFail: metadata matching used bytes.Contains on
// two-byte magics, so ordinary text such as "Licensed by AMZ Corp" FAILed as an
// embedded PE. Two-byte magics now count only at the start of a value and only
// with confirming structure. Falsification: match "MZ" anywhere again and this
// FAILs.
func TestShortMagicInTextDoesNotFail(t *testing.T) {
	for _, v := range []string{"Licensed by AMZ Corp", "MZ is a common prefix", "\x1f\x8b but not gzip"} {
		p := writeFixture(t, "clean-Q5_K_M.gguf", gguftest.BuildGGUF(
			gguftest.WithMeta("general.license", gguftest.Str("general.license", v))))
		r := Inspect(p, Options{})
		if r.Status == checks.Fail {
			t.Errorf("metadata %q FAILed as an embedded binary: %+v", v, r.Findings)
		}
	}
}

// TestRealPEInMetadataFails: a value that really is a PE image still FAILs.
func TestRealPEInMetadataFails(t *testing.T) {
	pe := make([]byte, 0x80)
	copy(pe, "MZ")
	pe[0x3c] = 0x40
	copy(pe[0x40:], "PE\x00\x00")
	p := writeFixture(t, "pe-Q5_K_M.gguf", gguftest.BuildGGUF(
		gguftest.WithMeta("general.license", gguftest.Str("general.license", string(pe)))))
	r := Inspect(p, Options{})
	if r.Status != checks.Fail {
		t.Fatalf("status = %s, want FAIL on a PE image in metadata", r.Status)
	}
}

// TestRepoTorchCheckpointIsNotAFail: every PyTorch checkpoint since 1.6 is a
// zip, so the repo side FAILed any repo shipping pytorch_model.bin. An
// archive is not an executable; its contents were not scanned, so the row is
// NOT_TESTED with the checkpoint named. Falsification: treat zip as an
// executable magic again and this FAILs.
func TestRepoTorchCheckpointIsNotAFail(t *testing.T) {
	p := writeFixture(t, "clean-Q5_K_M.gguf", gguftest.BuildGGUF(gguftest.Clean()))
	mirror := t.TempDir()
	zip := append([]byte{0x50, 0x4b, 0x03, 0x04}, make([]byte, 60)...)
	if err := os.WriteFile(filepath.Join(mirror, "pytorch_model.bin"), zip, 0o600); err != nil {
		t.Fatal(err)
	}
	r := Inspect(p, Options{RepoMirror: mirror})
	if r.Status != checks.NotTested {
		t.Fatalf("status = %s, want NOT_TESTED for an unscanned checkpoint (notes: %s)", r.Status, r.Notes)
	}
	if !strings.Contains(r.Notes, "pytorch_model.bin") {
		t.Errorf("the unscanned checkpoint must be named, got %q", r.Notes)
	}
}

// TestRepoFileStartingMZIsNotAFail: a text file that happens to start "MZ" is
// not a PE.
func TestRepoFileStartingMZIsNotAFail(t *testing.T) {
	p := writeFixture(t, "clean-Q5_K_M.gguf", gguftest.BuildGGUF(gguftest.Clean()))
	mirror := t.TempDir()
	if err := os.WriteFile(filepath.Join(mirror, "NOTES"), []byte("MZ-series notes for this model"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := Inspect(p, Options{RepoMirror: mirror}); r.Status == checks.Fail {
		t.Fatalf("a text file starting MZ FAILed: %+v", r.Findings)
	}
}
