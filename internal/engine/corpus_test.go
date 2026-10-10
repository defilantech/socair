package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defilantech/socair/internal/gguf/gguftest"
)

func TestCorpusSweep(t *testing.T) {
	dir := t.TempDir()
	writeFixtureAt(t, filepath.Join(dir, "clean-Q5_K_M.gguf"), gguftest.BuildGGUF(gguftest.Clean()))
	hostile := gguftest.WithMeta("tokenizer.chat_template",
		gguftest.Str("tokenizer.chat_template", "{{ ''.__globals__ }}"))
	writeFixtureAt(t, filepath.Join(dir, "hostile-Q5_K_M.gguf"), gguftest.BuildGGUF(hostile))
	// A non-GGUF file must be ignored.
	writeFixtureAt(t, filepath.Join(dir, "notes.txt"), []byte("ignore me"))

	entries, err := Corpus(dir, ModeHeaders)
	if err != nil {
		t.Fatalf("Corpus: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2 (the .txt must be ignored)", len(entries))
	}

	var hostileSeen bool
	for _, e := range entries {
		if e.Error != "" {
			t.Fatalf("unexpected scan error: %s", e.Error)
		}
		if filepath.Base(e.Path) == "hostile-Q5_K_M.gguf" {
			hostileSeen = true
			found := false
			for _, n := range e.Fails {
				if n == "Chat template" {
					found = true
				}
			}
			if !found {
				t.Fatalf("hostile fixture not flagged in the sweep: %+v", e)
			}
		}
	}
	if !hostileSeen {
		t.Fatal("hostile fixture missing from the sweep")
	}
}

func TestHeadersModeDoesNotHash(t *testing.T) {
	p := writeFixture(t, "clean-Q8_0.gguf", gguftest.BuildGGUF(gguftest.Clean()))

	dh, err := ScanMode(p, ModeHeaders)
	if err != nil {
		t.Fatalf("ScanMode headers: %v", err)
	}
	if dh.Artifact.SHA256 != "" {
		t.Errorf("headers mode must not hash, got %q", dh.Artifact.SHA256)
	}

	df, err := Scan(p)
	if err != nil {
		t.Fatalf("Scan full: %v", err)
	}
	if len(df.Artifact.SHA256) != 64 {
		t.Errorf("full mode must hash, got %q", df.Artifact.SHA256)
	}
}

func writeFixtureAt(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}
