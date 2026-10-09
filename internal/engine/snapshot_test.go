package engine

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/diskfree"
	"github.com/defilantech/socair/internal/gguf/gguftest"
	"github.com/defilantech/socair/internal/safetensors/safetensorstest"
)

// TestSnapshotIsCleanedUp: a scan's snapshot is a full copy of the artifact,
// so it must not outlive the scan, on success or on a parse failure.
func TestSnapshotIsCleanedUp(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("SOCAIR_SCAN_TMP", tmp)
	for name, data := range map[string][]byte{
		"ok-Q5_K_M.gguf":     gguftest.BuildGGUF(gguftest.Clean()),
		"broken-Q5_K_M.gguf": []byte("GGUF\x63\x00\x00\x00"),
		"mystery.bin":        []byte("not a model"),
	} {
		if _, err := Scan(writeFixture(t, name, data)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	left, _ := filepath.Glob(filepath.Join(tmp, "socair-scan-*"))
	if len(left) != 0 {
		t.Fatalf("snapshots left behind: %v", left)
	}
}

func TestSnapshotDirErrorIsActionable(t *testing.T) {
	t.Setenv("SOCAIR_SCAN_TMP", filepath.Join(t.TempDir(), "does", "not", "exist"))
	_, err := Scan(writeFixture(t, "ok-Q5_K_M.gguf", gguftest.BuildGGUF(gguftest.Clean())))
	if err == nil || !strings.Contains(err.Error(), "SOCAIR_SCAN_TMP") {
		t.Fatalf("err = %v, want one naming SOCAIR_SCAN_TMP", err)
	}
}

// A scan whose snapshot cannot fit fails before it copies anything, naming
// the volume and SOCAIR_SCAN_TMP, for a file and for a model directory.
// Falsification: drop the room check in snapshot or modeldir.Snapshot and its
// case scans instead.
func TestSnapshotRefusesAShortScanVolume(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("SOCAIR_SCAN_TMP", tmp)
	prev := diskfree.Available
	diskfree.Available = func(string) (uint64, bool) { return 10, true }
	t.Cleanup(func() { diskfree.Available = prev })

	dir := t.TempDir()
	for name, body := range map[string][]byte{
		"config.json":       []byte(`{"model_type":"llama"}`),
		"model.safetensors": safetensorstest.Clean(),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for name, path := range map[string]string{
		"file":      writeFixture(t, "ok-Q5_K_M.gguf", gguftest.BuildGGUF(gguftest.Clean())),
		"directory": dir,
	} {
		_, err := Scan(path)
		var short *diskfree.ShortError
		if !errors.As(err, &short) || !strings.Contains(err.Error(), "SOCAIR_SCAN_TMP") || !strings.Contains(err.Error(), tmp) {
			t.Errorf("%s: want a refusal naming %s and SOCAIR_SCAN_TMP, got %v", name, tmp, err)
		}
	}
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Fatalf("a refused scan must not start a snapshot: %v", left)
	}
}

func TestSnapshotRefusesNonRegularFiles(t *testing.T) {
	if _, err := Scan(t.TempDir()); err == nil {
		t.Fatal("scanning a directory must fail")
	}
}
