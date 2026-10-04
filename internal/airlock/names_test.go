package airlock

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestStagingFileRejectsTraversal: the pull destination was built from the
// caller's sha256 before anything checked it was hex, and Pull only checked
// its length. A 64-character "../" value walked out of the store, where the
// download was renamed over the target and then deleted on the hash mismatch.
// Falsification: drop the hex check and the traversal value below resolves.
func TestStagingFileRejectsTraversal(t *testing.T) {
	s, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	trav := "../../../../../../../../../../../../../../../../../../../tmp/x"
	trav += strings.Repeat("a", 64-len(trav))
	if len(trav) != 64 {
		t.Fatalf("fixture length %d, want 64", len(trav))
	}

	bad := []struct{ sha, file string }{
		{trav, "authorized_keys"},
		{strings.Repeat("g", 64), "model.gguf"},
		{strings.Repeat("a", 63), "model.gguf"},
		{strings.Repeat("a", 64), ".."},
		{strings.Repeat("a", 64), "."},
		{strings.Repeat("a", 64), ""},
		{strings.Repeat("a", 64), "sub/model.gguf"},
		{strings.Repeat("a", 64), `sub\model.gguf`},
	}
	for _, b := range bad {
		if p, err := s.StagingFile(b.sha, b.file); err == nil {
			t.Errorf("StagingFile(%q, %q) = %q, want an error", b.sha, b.file, p)
		}
	}

	good := strings.Repeat("A", 64)
	p, err := s.StagingFile(good, "model.gguf")
	if err != nil {
		t.Fatalf("a valid hash and name must resolve: %v", err)
	}
	if !strings.HasPrefix(p, s.stagingRoot()+string(filepath.Separator)) {
		t.Fatalf("staging file %q escapes the staging root", p)
	}
}

// TestPullRejectsNonHexHash: Pull is also a public entry point, so it checks
// the hash shape itself rather than trusting its callers.
func TestPullRejectsNonHexHash(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, _ := Init(filepath.Join(dir, "store"))
	_, err := Pull(context.Background(), s, victim, "org/name", "main", strings.Repeat("z", 64), EgressPolicy{Endpoint: "http://127.0.0.1:1", Allow: []string{"127.0.0.1"}})
	if err == nil {
		t.Fatal("a non-hex hash must be refused")
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep me" {
		t.Fatal("a refused pull must not touch the destination")
	}
}

func TestRepoAndRevisionShape(t *testing.T) {
	for _, r := range []string{"org/name", "gpt2", "Org-1/Name_2.5-GGUF"} {
		if err := validRepo(r); err != nil {
			t.Errorf("validRepo(%q) = %v, want ok", r, err)
		}
	}
	for _, r := range []string{"", "../x", "org/../x", "org/name/extra", "/abs", "org/na me", "org\\name", "-flag"} {
		if validRepo(r) == nil {
			t.Errorf("validRepo(%q) accepted, want an error", r)
		}
	}
	for _, r := range []string{"main", "v1.0", "refs/pr/1", strings.Repeat("a", 40)} {
		if err := validRevision(r); err != nil {
			t.Errorf("validRevision(%q) = %v, want ok", r, err)
		}
	}
	for _, r := range []string{"../main", "refs/../../x", "/abs", "a b", "a\\b"} {
		if validRevision(r) == nil {
			t.Errorf("validRevision(%q) accepted, want an error", r)
		}
	}
}

// TestResolveCacheStaysInTheCache: repo, revision, and file were joined under
// the cache root unchecked, so "../" in any of them resolved outside it.
func TestResolveCacheStaysInTheCache(t *testing.T) {
	cache := t.TempDir()
	outside := filepath.Join(filepath.Dir(cache), "outside.gguf")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(outside) })

	cases := [][3]string{
		{"org/name", "main", "../../../../outside.gguf"},
		{"org/name", "../../..", "outside.gguf"},
		{"../x", "main", "outside.gguf"},
		{"org/name", "main", "/etc/passwd"},
	}
	for _, c := range cases {
		if p, err := ResolveCache(cache, c[0], c[1], c[2]); err == nil {
			t.Errorf("ResolveCache(%q, %q, %q) = %q, want an error", c[0], c[1], c[2], p)
		}
	}
}

// TestStagingRefusesEvidenceNames: a single-file pull is staged flat, as
// incoming/<sha>/<file>, beside report.json and the attestations. An artifact
// named like evidence would be hidden from stagedArtifact and overwritten by
// the next scan or upload. Falsification: drop notEvidenceName and each name
// resolves and reaches the network.
func TestStagingRefusesEvidenceNames(t *testing.T) {
	s, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sha := strings.Repeat("a", 64)
	for _, name := range []string{StagedReport, StagedAttestation, StagedAcceptance, StagedConditional, ProvenanceFile, "attestation.json", "attestation.dsse.json"} {
		if p, err := s.StagingFile(sha, name); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("StagingFile(%q) = %q, %v; want an error naming it", name, p, err)
		}
	}
	// Pull checks the name itself, before any request: the endpoint is closed.
	_, err = Pull(context.Background(), s, filepath.Join(s.StagingPath(sha), StagedReport), "org/name", "main", sha,
		EgressPolicy{Endpoint: "http://127.0.0.1:1", Allow: []string{"127.0.0.1"}, Timeout: time.Second})
	if err == nil || !strings.Contains(err.Error(), StagedReport) || !strings.Contains(err.Error(), "evidence") {
		t.Fatalf("a pull of report.json must be refused by name: %v", err)
	}
	if _, err := os.Stat(s.StagingPath(sha)); !os.IsNotExist(err) {
		t.Error("a refused pull must stage nothing")
	}
}
