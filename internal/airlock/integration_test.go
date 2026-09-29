package airlock

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
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
	if _, err := os.Stat(filepath.Join(filepath.Dir(dst), "provenance.json")); err != nil {
		t.Errorf("manifest not written: %v", err)
	}
	ev, _ := s.Events()
	if len(ev) != 1 || !strings.EqualFold(ev[0].Repo, repo) {
		t.Errorf("pull not logged with the repo, got %+v", ev)
	}
}
