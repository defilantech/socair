package airlock

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestInitIsIdempotent(t *testing.T) {
	root := t.TempDir()
	if _, err := Init(root); err != nil {
		t.Fatalf("first Init: %v", err)
	}
	s, err := Init(root)
	if err != nil {
		t.Fatalf("second Init: %v", err)
	}
	for _, d := range []string{s.stagingRoot(), s.cleanRoot()} {
		fi, err := os.Stat(d)
		if err != nil || !fi.IsDir() {
			t.Fatalf("expected dir %s: %v", d, err)
		}
	}
}

func TestOpenUninitializedErrors(t *testing.T) {
	root := t.TempDir()
	_, err := Open(root)
	if !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("Open on a fresh dir: got %v, want ErrNotInitialized", err)
	}
}

func TestPathsNormalizeHash(t *testing.T) {
	s, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const messy = "  ABCDEF0123456789  "
	if got := s.StagingPath(messy); got != filepath.Join(s.stagingRoot(), "abcdef0123456789") {
		t.Errorf("StagingPath did not normalize: %q", got)
	}
	if got := s.CleanPath(messy); got != filepath.Join(s.cleanRoot(), "abcdef0123456789") {
		t.Errorf("CleanPath did not normalize: %q", got)
	}
}

func TestPlaceCopiesBytesAndIsIdempotent(t *testing.T) {
	s, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(t.TempDir(), "model.gguf")
	want := []byte("we are the bytes that cross")
	if err := os.WriteFile(src, want, 0o600); err != nil {
		t.Fatal(err)
	}

	dst, err := s.Place(src, s.CleanPath("AABB"))
	if err != nil {
		t.Fatalf("Place: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("placed bytes = %q, want %q", got, want)
	}

	// Re-placing the same content is idempotent: the path is unchanged and the
	// bytes still match.
	again, err := s.Place(src, s.CleanPath("AABB"))
	if err != nil {
		t.Fatalf("second Place: %v", err)
	}
	if again != dst {
		t.Errorf("second Place wrote to %q, want %q", again, dst)
	}
	got2, _ := os.ReadFile(again)
	if string(got2) != string(want) {
		t.Errorf("bytes changed on re-place: %q", got2)
	}
}

func TestWriteFileLandsWhole(t *testing.T) {
	s, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(s.CleanPath("cafe"), "attestation.json")
	if err := s.WriteFile(p, []byte(`{"ok":true}`)); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"ok":true}` {
		t.Fatalf("bytes = %q", b)
	}
	// No temp files left behind in the directory.
	entries, _ := os.ReadDir(filepath.Dir(p))
	if len(entries) != 1 {
		t.Errorf("expected only the destination file, got %d entries", len(entries))
	}
}
