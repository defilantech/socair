package airlock

import (
	"context"
	"github.com/defilantech/socair/internal/engine"
	"github.com/defilantech/socair/internal/modeldir"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestPullRealEgress is the one networked airlock test. It is skipped by
// default so the suite stays hermetic:
//
//	SOCAIR_TEST_EGRESS=1 go test ./internal/airlock -run RealEgress -v
//
// It fetches a tiny public file, takes its hash from the bytes, and proves the
// pull then verifies that same hash, writes the manifest, and logs the pull.
func TestPullRealEgress(t *testing.T) {
	if os.Getenv("SOCAIR_TEST_EGRESS") != "1" {
		t.Skip("set SOCAIR_TEST_EGRESS=1 to exercise real egress")
	}

	const repo = "hf-internal-testing/tiny-random-gpt2"
	const file = "config.json"
	const endpoint = "https://huggingface.co"
	url := endpoint + "/" + repo + "/resolve/main/" + file

	// The test learns the hash from the bytes it fetched itself, so nothing is
	// hardcoded and a changed upstream is a loud mismatch, not a stale pass.
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("fetch for hash: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("fetch for hash: HTTP %d", resp.StatusCode)
	}
	sha, err := func() (string, error) {
		p := filepath.Join(t.TempDir(), file)
		if err := os.WriteFile(p, body, 0o600); err != nil {
			return "", err
		}
		return hashFile(p)
	}()
	if err != nil {
		t.Fatal(err)
	}

	s, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(s.StagingPath(sha), file)
	pol := EgressPolicy{Timeout: 30 * time.Second}

	e, err := Pull(context.Background(), s, dst, repo, "main", sha, pol)
	if err != nil {
		t.Fatalf("real pull: %v", err)
	}
	if e.SHA256 != sha {
		t.Errorf("event hash %q, want %q", e.SHA256, sha)
	}
	mb, err := os.ReadFile(filepath.Join(filepath.Dir(dst), "provenance.json"))
	if err != nil {
		t.Fatalf("manifest not written: %v", err)
	}
	// The real hub names the commit "main" resolved to; the manifest must
	// pin it, or the provenance row can never PASS on a real pull.
	if !regexp.MustCompile(`"commit_sha": "[0-9a-f]{40}"`).Match(mb) {
		t.Errorf("manifest records no resolved commit:\n%s", mb)
	}
	ev, _ := s.Events()
	if len(ev) != 1 || !strings.EqualFold(ev[0].Repo, repo) {
		t.Errorf("pull not logged with the repo, got %+v", ev)
	}
}

// TestPullRepoRealEgress pulls a whole small repo from the real hub at a
// pinned commit, verifying every file against the hub's own hashes, and
// checks a scan of the staged tree attests the same digest.
func TestPullRepoRealEgress(t *testing.T) {
	if os.Getenv("SOCAIR_TEST_EGRESS") == "" {
		t.Skip("set SOCAIR_TEST_EGRESS=1 to pull from huggingface.co")
	}
	t.Setenv("SOCAIR_EGRESS", "")
	s, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const commit = "71034c5d8bde858ff824298bdedc65515b97d2b9"
	e, staged, err := PullRepo(context.Background(), s, "hf-internal-testing/tiny-random-gpt2", commit, "", DefaultEgressPolicy())
	if err != nil {
		t.Fatalf("real repo pull: %v", err)
	}
	got, files, err := modeldir.Hash(staged)
	if err != nil || got != e.SHA256 {
		t.Fatalf("staged digest %s (%v), pull logged %s", got, err, e.SHA256)
	}
	t.Logf("%d files, digest %s: %s", len(files), got, e.Detail)
	t.Setenv("SOCAIR_PROVENANCE", filepath.Join(filepath.Dir(staged), "provenance.json"))
	d, err := engine.Scan(staged)
	if err != nil {
		t.Fatal(err)
	}
	if d.Artifact.SHA256 != got || d.Artifact.CommitSHA != commit {
		t.Fatalf("scan subject %s commit %q", d.Artifact.SHA256, d.Artifact.CommitSHA)
	}
	for _, c := range d.Checks {
		t.Logf("%-10s %s", c.Status, c.Name)
	}
}
