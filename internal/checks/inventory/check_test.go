package inventory

import (
	"os"
	"path/filepath"
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
