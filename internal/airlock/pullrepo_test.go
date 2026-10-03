package airlock

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/defilantech/socair/internal/checks/provenance"
	"github.com/defilantech/socair/internal/engine"
	"github.com/defilantech/socair/internal/modeldir"
	"github.com/defilantech/socair/internal/report"
	"github.com/defilantech/socair/internal/safetensors/safetensorstest"
)

const hubCommit = "71034c5d8bde858ff824298bdedc65515b97d2b9"

// fakeHub serves a repo the way the Hugging Face hub does: the revision and
// tree APIs (two entries per page, linked), and resolve URLs, with large
// files redirected to a CDN path.
type fakeHub struct {
	files   map[string]string
	lfs     map[string]bool
	serve   map[string]string // path -> bytes served instead, to corrupt
	extra   []treeEntry       // listing entries added verbatim
	nextURL string            // overrides the Link of the first page
}

func newFakeHub() *fakeHub {
	return &fakeHub{
		files: map[string]string{
			"config.json":           `{"model_type":"llama"}`,
			"model.safetensors":     string(safetensorstest.Clean()),
			"tokenizer_config.json": `{"chat_template":"{% for m in messages %}{{ m['content'] }}{% endfor %}"}`,
			"sub/notes.txt":         "hello",
		},
		lfs:   map[string]bool{"model.safetensors": true},
		serve: map[string]string{},
	}
}

func (h *fakeHub) entries() []treeEntry {
	var out []treeEntry
	for p, body := range h.files {
		e := treeEntry{Type: "file", Path: p, Size: int64(len(body))}
		blob := sha1.Sum([]byte(fmt.Sprintf("blob %d\x00%s", len(body), body)))
		e.OID = hex.EncodeToString(blob[:])
		if h.lfs[p] {
			sum := sha256.Sum256([]byte(body))
			e.LFS = &struct {
				OID  string `json:"oid"`
				Size int64  `json:"size"`
			}{hex.EncodeToString(sum[:]), int64(len(body))}
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	out = append(out, h.extra...)
	out = append(out, treeEntry{Type: "directory", Path: "sub"})
	return out
}

func (h *fakeHub) start(t *testing.T) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/models/org/tiny/revision/"):
			json.NewEncoder(w).Encode(map[string]string{"sha": hubCommit})
		case r.URL.Path == "/api/models/org/tiny/tree/"+hubCommit:
			all := h.entries()
			page := 0
			fmt.Sscan(r.URL.Query().Get("cursor"), &page)
			end := min(page*2+2, len(all))
			if end < len(all) {
				next := fmt.Sprintf("%s%s?recursive=true&cursor=%d", srv.URL, r.URL.Path, page+1)
				if page == 0 && h.nextURL != "" {
					next = h.nextURL
				}
				w.Header().Set("Link", "<"+next+`>; rel="next"`)
			}
			json.NewEncoder(w).Encode(all[page*2 : end])
		case strings.HasPrefix(r.URL.Path, "/org/tiny/resolve/"+hubCommit+"/"):
			p := strings.TrimPrefix(r.URL.Path, "/org/tiny/resolve/"+hubCommit+"/")
			if h.lfs[p] {
				http.Redirect(w, r, "/cdn/"+p, http.StatusFound)
				return
			}
			h.write(w, p)
		case strings.HasPrefix(r.URL.Path, "/cdn/"):
			h.write(w, strings.TrimPrefix(r.URL.Path, "/cdn/"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (h *fakeHub) write(w http.ResponseWriter, p string) {
	if body, ok := h.serve[p]; ok {
		w.Write([]byte(body))
		return
	}
	body, ok := h.files[p]
	if !ok {
		http.NotFound(w, nil)
		return
	}
	w.Write([]byte(body))
}

func hubPolicy(srv *httptest.Server) EgressPolicy {
	return EgressPolicy{Allow: []string{"127.0.0.1"}, Endpoint: srv.URL, Timeout: 5 * time.Second}
}

// TestPullScanPromoteADirectory is the whole path: a pinned pull stages the
// tree with a bound provenance manifest, a scan of it attests the same
// digest, and the signed attestation carries it into clean.
func TestPullScanPromoteADirectory(t *testing.T) {
	t.Setenv("SOCAIR_EGRESS", "")
	srv := newFakeHub().start(t)
	s := trustedStore(t)

	e, staged, err := PullRepo(context.Background(), s, "org/tiny", hubCommit, "", hubPolicy(srv))
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if filepath.Base(staged) != "tiny" || filepath.Dir(staged) != s.StagingPath(e.SHA256) {
		t.Errorf("staged at %s", staged)
	}
	digest, files, err := modeldir.Hash(staged)
	if err != nil || digest != e.SHA256 || len(files) != 4 {
		t.Fatalf("staged tree digest %s (%d files, %v), pull logged %s", digest, len(files), err, e.SHA256)
	}
	manifest := filepath.Join(s.StagingPath(digest), "provenance.json")
	if r := provenance.Inspect(provenance.Options{ArtifactPath: staged, ArtifactSHA256: digest, ManifestPath: manifest}); r.Status != "PASS" {
		t.Fatalf("the pull's manifest must bind the digest at a pinned commit: %s (%s)", r.Status, r.Notes)
	}

	for _, k := range []string{"SOCAIR_REPO_MIRROR", "SOCAIR_DENYLIST"} {
		t.Setenv(k, "")
	}
	t.Setenv("SOCAIR_PROVENANCE", manifest)
	t.Setenv("SOCAIR_ACCEPTED_BY", "ciso@example.com")
	d, err := engine.Scan(staged)
	if err != nil {
		t.Fatal(err)
	}
	if d.Artifact.SHA256 != digest || d.Artifact.CommitSHA != hubCommit || d.Artifact.Name != "tiny" {
		t.Fatalf("scan subject %s commit %q name %q", d.Artifact.SHA256, d.Artifact.CommitSHA, d.Artifact.Name)
	}
	if d.PromotionAuthorization.State != report.StateAuthorizedWithConditions {
		t.Fatalf("state %s", d.PromotionAuthorization.State)
	}
	if _, err := Promote(s, staged, writeReport(t, d)); err != nil {
		t.Fatalf("promote: %v", err)
	}
	if got, _, _ := modeldir.Hash(filepath.Join(s.CleanPath(digest), "tiny")); got != digest {
		t.Fatal("the clean tree must be the pulled tree")
	}
}

// Falsification: drop either hash comparison in fetchVerified and its case
// passes.
func TestPullRepoRefusesBytesTheHubDidNotList(t *testing.T) {
	t.Setenv("SOCAIR_EGRESS", "")
	for name, corrupt := range map[string]map[string]string{
		"large file, same size": {"model.safetensors": strings.Repeat("x", len(safetensorstest.Clean()))},
		"small file, same size": {"config.json": `{"model_type":"evils"}`},
		"short body":            {"config.json": "{}"},
	} {
		hub := newFakeHub()
		hub.serve = corrupt
		srv := hub.start(t)
		s, _ := Init(t.TempDir())
		_, _, err := PullRepo(context.Background(), s, "org/tiny", hubCommit, "", hubPolicy(srv))
		for p := range corrupt {
			if err == nil || !strings.Contains(err.Error(), p) {
				t.Errorf("%s: want a refusal naming %s, got %v", name, p, err)
			}
		}
		if entries, _ := os.ReadDir(filepath.Join(s.Root, stagingDir)); len(entries) != 0 {
			t.Errorf("%s: nothing may be staged on a refusal", name)
		}
	}
}

// Each unsafe listing is refused for its own reason, before any download.
// Falsification: drop a guard and its case reaches the download instead.
func TestPullRepoRefusesUnsafeListings(t *testing.T) {
	t.Setenv("SOCAIR_EGRESS", "")
	oid := strings.Repeat("a", 40)
	for name, c := range map[string]struct {
		e    treeEntry
		want string
	}{
		"parent escape": {treeEntry{Type: "file", Path: "../evil", Size: 1, OID: oid}, "unsafe path"},
		"absolute":      {treeEntry{Type: "file", Path: "/etc/evil", Size: 1, OID: oid}, "unsafe path"},
		"dot segment":   {treeEntry{Type: "file", Path: "sub/./x", Size: 1, OID: oid}, "unsafe path"},
		"backslash":     {treeEntry{Type: "file", Path: `sub\..\x`, Size: 1, OID: oid}, "unsafe path"},
		"case fold":     {treeEntry{Type: "file", Path: "CONFIG.json", Size: 1, OID: oid}, "differ only in case"},
		"no hash":       {treeEntry{Type: "file", Path: "unhashed.bin", Size: 1}, "no hash the hub vouches for"},
		"file and dir":  {treeEntry{Type: "file", Path: "config.json/x", Size: 1, OID: oid}, "both a file and a directory"},
	} {
		hub := newFakeHub()
		hub.extra = []treeEntry{c.e}
		srv := hub.start(t)
		s, _ := Init(t.TempDir())
		_, _, err := PullRepo(context.Background(), s, "org/tiny", hubCommit, "", hubPolicy(srv))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want a refusal for %q, got %v", name, c.want, err)
		}
	}
}

func TestPullRepoMustBePinned(t *testing.T) {
	t.Setenv("SOCAIR_EGRESS", "")
	srv := newFakeHub().start(t)
	s, _ := Init(t.TempDir())
	if _, _, err := PullRepo(context.Background(), s, "org/tiny", "main", "", hubPolicy(srv)); err == nil || !strings.Contains(err.Error(), "pin") {
		t.Fatalf("a branch with no expected digest must be refused, got %v", err)
	}
	e, _, err := PullRepo(context.Background(), s, "org/tiny", hubCommit, "", hubPolicy(srv))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := PullRepo(context.Background(), s, "org/tiny", "main", e.SHA256, hubPolicy(srv)); err != nil {
		t.Fatalf("a branch pinned by digest pulls: %v", err)
	}
	if _, _, err := PullRepo(context.Background(), s, "org/tiny", "main", strings.Repeat("0", 64), hubPolicy(srv)); err == nil {
		t.Fatal("a digest the files do not have must be refused")
	}
}

// Every request, including a pagination link, goes through the policy.
func TestPullRepoFollowsPaginationOnlyWithinPolicy(t *testing.T) {
	t.Setenv("SOCAIR_EGRESS", "")
	hub := newFakeHub()
	hub.nextURL = "http://elsewhere.invalid/page2"
	srv := hub.start(t)
	s, _ := Init(t.TempDir())
	_, _, err := PullRepo(context.Background(), s, "org/tiny", hubCommit, "", hubPolicy(srv))
	if err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("a next page on another host must be denied, got %v", err)
	}
	t.Setenv("SOCAIR_EGRESS", "deny")
	if _, _, err := PullRepo(context.Background(), s, "org/tiny", hubCommit, "", hubPolicy(newFakeHub().start(t))); err == nil {
		t.Fatal("SOCAIR_EGRESS=deny must stop a repo pull")
	}
}
