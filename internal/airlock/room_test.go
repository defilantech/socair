package airlock

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defilantech/socair/internal/diskfree"
	"github.com/defilantech/socair/internal/engine"
)

// fullDisk makes every volume report free bytes of room until the test ends.
func fullDisk(t *testing.T, free uint64) {
	t.Helper()
	prev := diskfree.Available
	diskfree.Available = func(string) (uint64, bool) { return free, true }
	t.Cleanup(func() { diskfree.Available = prev })
}

func wantShort(t *testing.T, what string, err error, dir string) {
	t.Helper()
	var short *diskfree.ShortError
	if !errors.As(err, &short) || !strings.Contains(err.Error(), dir) {
		t.Fatalf("%s: want a refusal naming %s for lack of room, got %v", what, dir, err)
	}
}

// A repo pull that cannot fit is refused from the listing's sizes, before
// any file is fetched. Falsification: drop the room check in PullRepo and the
// files are requested.
func TestPullRepoRefusesAShortStore(t *testing.T) {
	t.Setenv("SOCAIR_EGRESS", "")
	hub := newFakeHub()
	var mu sync.Mutex
	var fetched []string
	srv := hub.start(t)
	inner := srv.Config.Handler
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/resolve/") {
			mu.Lock()
			fetched = append(fetched, r.URL.Path)
			mu.Unlock()
		}
		inner.ServeHTTP(w, r)
	})
	s, _ := Init(t.TempDir())
	fullDisk(t, 3)

	_, _, err := PullRepo(context.Background(), s, "org/tiny", hubCommit, "", hubPolicy(srv))
	wantShort(t, "repo pull", err, s.Root)
	if len(fetched) != 0 {
		t.Fatalf("a pull that cannot fit must fetch nothing, fetched %v", fetched)
	}
}

// A single-file pull is refused on the response's declared length, before
// the body is written. Falsification: drop the check in Pull and the file is
// staged.
func TestPullRefusesAShortStore(t *testing.T) {
	t.Setenv("SOCAIR_EGRESS", "")
	want := []byte("model bytes that will not fit")
	sum := sha256.Sum256(want)
	sha := hex.EncodeToString(sum[:])
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(want) }))
	defer srv.Close()
	s, _ := Init(t.TempDir())
	dst, err := s.StagingFile(sha, "model.safetensors")
	if err != nil {
		t.Fatal(err)
	}
	fullDisk(t, 3)

	_, err = Pull(context.Background(), s, dst, "org/name", "main", sha, EgressPolicy{Allow: []string{"127.0.0.1"}, Endpoint: srv.URL, Timeout: 5 * time.Second})
	wantShort(t, "single-file pull", err, filepath.Dir(dst))
	if _, serr := os.Stat(dst); !os.IsNotExist(serr) {
		t.Fatal("a pull that cannot fit must stage nothing")
	}
}

// Promotion copies the artifact into the store, so a store without room is
// refused before the copy, for a file and for a model directory.
// Falsification: drop the check in placeVerified (or in modeldir.Snapshot for
// a directory) and its case promotes.
func TestPromoteRefusesAShortStore(t *testing.T) {
	artifact, d := authorizedArtifact(t)
	s := trustedStore(t)
	env := writeReport(t, d)
	fullDisk(t, 3)
	_, err := Promote(s, artifact, env)
	wantShort(t, "file promotion", err, s.Root)
	if _, serr := os.Stat(s.CleanPath(d.Artifact.SHA256)); !os.IsNotExist(serr) {
		t.Fatal("a refused promotion must not create its clean entry")
	}
}

func TestPromoteDirectoryRefusesAShortStore(t *testing.T) {
	t.Setenv("SOCAIR_EGRESS", "")
	srv := newFakeHub().start(t)
	s := trustedStore(t)
	e, staged, err := PullRepo(context.Background(), s, "org/tiny", hubCommit, "", hubPolicy(srv))
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"SOCAIR_REPO_MIRROR", "SOCAIR_DENYLIST", "SOCAIR_ACCEPTED_BY"} {
		t.Setenv(k, "")
	}
	t.Setenv("SOCAIR_PROVENANCE", filepath.Join(s.StagingPath(e.SHA256), ProvenanceFile))
	d, err := engine.Scan(staged)
	if err != nil {
		t.Fatal(err)
	}
	ticket := acceptedTicket(t, s, d, 24*time.Hour)
	fullDisk(t, 3)
	_, err = Promote(s, staged, ticket)
	wantShort(t, "directory promotion", err, s.Root)
	if _, serr := os.Stat(filepath.Join(s.CleanPath(e.SHA256), "tiny")); !os.IsNotExist(serr) {
		t.Fatal("a refused promotion must not place the tree")
	}
}
