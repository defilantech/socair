package engine

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/gguf/gguftest"
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

func TestSnapshotRefusesNonRegularFiles(t *testing.T) {
	if _, err := Scan(t.TempDir()); err == nil {
		t.Fatal("scanning a directory must fail")
	}
}
