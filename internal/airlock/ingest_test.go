package airlock

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/engine"
	"github.com/defilantech/socair/internal/gguf/gguftest"
)

// TestLocalPathFillsArtifactIdentityAndScope is the #14 acceptance: a local
// artifact path resolves and scans into a report with Section 2 (artifact
// identity) and Section 3 (scope and method) filled, not blank.
func TestLocalPathFillsArtifactIdentityAndScope(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fixture-Q5_K_M.gguf")
	if err := os.WriteFile(p, gguftest.BuildGGUF(gguftest.Clean()), 0o600); err != nil {
		t.Fatal(err)
	}
	resolved, err := IngestLocal(p)
	if err != nil {
		t.Fatalf("IngestLocal: %v", err)
	}
	d, err := engine.Scan(resolved)
	if err != nil {
		t.Fatalf("Scan of the resolved path: %v", err)
	}

	// Section 2, artifact identity.
	if len(d.Artifact.SHA256) != 64 || d.Artifact.Format == "" || d.Artifact.FileName == "" {
		t.Errorf("Section 2 is not filled from a local path: %+v", d.Artifact)
	}
	if d.Artifact.SizeBytes == 0 {
		t.Errorf("Section 2 size should be filled, got 0")
	}
	// Section 3, scope and method.
	if d.Scope.CheckSetVersion == "" || d.Scope.InputPath == "" || d.Scope.ExecutionContext == "" {
		t.Errorf("Section 3 is not filled from a local path: %+v", d.Scope)
	}
}

func TestIngestLocalMissingPathErrors(t *testing.T) {
	_, err := IngestLocal(filepath.Join(t.TempDir(), "nope.gguf"))
	if err == nil {
		t.Fatal("a missing local path must be an error, not an empty report")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("error should name the problem, got %q", err)
	}

	if _, err := IngestLocal("   "); err == nil {
		t.Error("an empty path must be an error")
	}
}

func TestIngestLocalRejectsADirectory(t *testing.T) {
	if _, err := IngestLocal(t.TempDir()); err == nil {
		t.Fatal("a directory is not an artifact and must be an error")
	}
}

func TestIngestLocalReturnsTheRealFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "model.gguf")
	if err := os.WriteFile(p, []byte("gguf"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := IngestLocal(p)
	if err != nil {
		t.Fatalf("IngestLocal: %v", err)
	}
	if !filepath.IsAbs(got) {
		t.Errorf("want an absolute path, got %q", got)
	}
	if filepath.Base(got) != "model.gguf" {
		t.Errorf("resolved the wrong file: %q", got)
	}
}

func TestResolveCacheFindsTheSnapshot(t *testing.T) {
	cache := t.TempDir()
	p := filepath.Join(cache, "models--google--gemma-3-12b-it", "snapshots", "abc123", "model.gguf")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("gguf"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := ResolveCache(cache, "google/gemma-3-12b-it", "abc123", "model.gguf")
	if err != nil {
		t.Fatalf("ResolveCache: %v", err)
	}
	if got != p {
		t.Errorf("resolved %q, want %q", got, p)
	}
}

func TestResolveCacheMissErrorsNamingRepoAndFile(t *testing.T) {
	_, err := ResolveCache(t.TempDir(), "google/gemma-3-12b-it", "main", "model.gguf")
	if err == nil {
		t.Fatal("a cache miss must be an error, never a nil path")
	}
	if !strings.Contains(err.Error(), "google/gemma-3-12b-it") || !strings.Contains(err.Error(), "model.gguf") {
		t.Errorf("a miss should name the repo and the file, got %q", err)
	}

	if _, err := ResolveCache("", "", "main", "f"); err == nil {
		t.Error("a missing repo must be an error")
	}
}

func TestRepoCacheDirMapping(t *testing.T) {
	if got := repoCacheDir("google/gemma-3-12b-it"); got != "models--google--gemma-3-12b-it" {
		t.Errorf("repoCacheDir = %q", got)
	}
}
