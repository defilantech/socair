package modeldir

import (
	"os"
	"path/filepath"
	"testing"
)

func TestListStatesHashesWithoutReadingAFile(t *testing.T) {
	dir := t.TempDir()
	for rel, body := range map[string]string{"config.json": "{}", "model.safetensors": "weights"} {
		if err := os.WriteFile(filepath.Join(dir, rel), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Falsification: a file nobody can read fails any walk that opens it,
	// so List passing here shows it opens none.
	locked := filepath.Join(dir, "model.safetensors")
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o644) })
	if f, err := os.Open(locked); err == nil {
		f.Close()
		t.Skip("running as a user who reads any file")
	}
	if _, _, err := Hash(dir); err == nil {
		t.Fatal("Hash read a file no one can read; the falsification does not hold")
	}

	files, _, err := List(dir, func(rel string) string { return "stated:" + rel })
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("%d files", len(files))
	}
	for _, f := range files {
		if f.SHA256 != "stated:"+f.Path {
			t.Errorf("%s: hash %q, want the stated one", f.Path, f.SHA256)
		}
	}
	if files[1].Path != "model.safetensors" || files[1].Size != int64(len("weights")) || files[1].Role != RoleWeights {
		t.Errorf("%+v", files[1])
	}
}
