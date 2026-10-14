package airlock

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/engine"
	"github.com/defilantech/socair/internal/modeldir"
	"github.com/defilantech/socair/internal/report"
	"github.com/defilantech/socair/internal/safetensors/safetensorstest"
)

// The markers planted outside the clean entries: in staging, and outside the
// store. No request may return either.
const (
	stagedSecret  = "STAGED-SECRET-BYTES-NEVER-SERVED"
	outsideSecret = "OUTSIDE-THE-STORE-NEVER-SERVED"
)

// hubFixture is a store as a pull, a scan, signing, and promotion leave it:
//   - org/tiny, a model directory pulled from a hub at hubCommit, promoted
//     with conditions (a signed acceptance of its untested rows);
//   - example/model, a single file promoted authorized;
//   - a staged artifact with its own hash that was never promoted.
type hubFixture struct {
	s       *Store
	dir     string // org/tiny's manifest digest
	file    string // example/model's SHA-256
	staged  string // the staged, unpromoted hash
	outside string // a file outside the store
	hub     *Hub
	srv     *httptest.Server
}

func newHubFixture(t *testing.T) *hubFixture {
	t.Helper()
	t.Setenv("SOCAIR_EGRESS", "")
	f := &hubFixture{s: trustedStore(t)}
	f.file = promoted(t, f.s)

	pulled := newFakeHub().start(t)
	e, staged, err := PullRepo(context.Background(), f.s, "org/tiny", hubCommit, "", hubPolicy(pulled))
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	f.dir = e.SHA256
	for _, k := range []string{"SOCAIR_REPO_MIRROR", "SOCAIR_DENYLIST"} {
		t.Setenv(k, "")
	}
	t.Setenv("SOCAIR_PROVENANCE", filepath.Join(f.s.StagingPath(f.dir), ProvenanceFile))
	t.Setenv("SOCAIR_ACCEPTED_BY", "")
	d, err := engine.Scan(staged)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Promote(f.s, staged, acceptedTicket(t, f.s, d, 24*time.Hour)); err != nil {
		t.Fatalf("promote: %v", err)
	}

	secret := []byte(stagedSecret)
	sum := sha256.Sum256(secret)
	f.staged = hex.EncodeToString(sum[:])
	p, err := f.s.StagingFile(f.staged, "model.safetensors")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, secret, 0o644); err != nil {
		t.Fatal(err)
	}
	prov := fmt.Sprintf(`{"artifact_sha256":%q,"repo_url":"https://huggingface.co/org/staged","commit_sha":%q}`, f.staged, hubCommit)
	if err := os.WriteFile(filepath.Join(filepath.Dir(p), ProvenanceFile), []byte(prov), 0o644); err != nil {
		t.Fatal(err)
	}
	f.outside = filepath.Join(t.TempDir(), "outside.bin")
	if err := os.WriteFile(f.outside, []byte(outsideSecret), 0o644); err != nil {
		t.Fatal(err)
	}

	f.hub = NewHub(f.s, HubOptions{})
	f.srv = httptest.NewServer(f.hub)
	t.Cleanup(f.srv.Close)
	return f
}

// doc is the verified document of a clean entry.
func (f *hubFixture) doc(t *testing.T, id string) *report.Document {
	t.Helper()
	a, err := f.s.AdmittedEntry(id, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return a.Document
}

// raw sends a request with its path exactly as given, unnormalized.
func raw(t *testing.T, srv *httptest.Server, method, path string, hdr ...string) (*http.Response, []byte) {
	t.Helper()
	u, _ := url.Parse(srv.URL)
	req, err := http.NewRequest(method, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.URL = &url.URL{Scheme: u.Scheme, Host: u.Host, Opaque: path}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

// hfDownload makes the requests huggingface_hub's snapshot_download makes
// (huggingface_hub v2.2.0, _snapshot_download.py and file_download.py):
// resolve the revision to a commit through the model info, list the tree at
// that commit, then for each file a HEAD on resolve/<commit>/<path>, which
// must carry X-Repo-Commit, an ETag, and the size, and a GET of the same
// URL. It returns each path's bytes and the ETag the HEAD gave it.
func hfDownload(t *testing.T, srv *httptest.Server, repo, revision string) (string, map[string][]byte, map[string]string) {
	t.Helper()
	resp, b := raw(t, srv, http.MethodGet, "/api/models/"+repo+"/revision/"+url.PathEscape(revision))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("model info: %d %s", resp.StatusCode, b)
	}
	var info struct {
		ID       string `json:"id"`
		SHA      string `json:"sha"`
		Siblings []struct {
			RFilename string `json:"rfilename"`
		} `json:"siblings"`
	}
	if err := json.Unmarshal(b, &info); err != nil || info.ID != repo || !(commitID.MatchString(info.SHA) || hexSHA256.MatchString(info.SHA)) {
		t.Fatalf("model info %s: %v", b, err)
	}
	resp, b = raw(t, srv, http.MethodGet, "/api/models/"+repo+"/tree/"+info.SHA+"?recursive=True&expand=False")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("tree: %d %s", resp.StatusCode, b)
	}
	var tree []treeEntry
	if err := json.Unmarshal(b, &tree); err != nil {
		t.Fatal(err)
	}
	var listed []string
	for _, s := range info.Siblings {
		listed = append(listed, s.RFilename)
	}
	got, etags := map[string][]byte{}, map[string]string{}
	var files []string
	for _, e := range tree {
		if e.Type != "file" {
			continue
		}
		files = append(files, e.Path)
		u := "/" + repo + "/resolve/" + info.SHA + "/" + escapePath(e.Path)
		head, _ := raw(t, srv, http.MethodHead, u, "Accept-Encoding", "identity")
		if head.StatusCode != http.StatusOK {
			t.Fatalf("HEAD %s: %d", u, head.StatusCode)
		}
		etag := head.Header.Get("X-Linked-Etag")
		if etag == "" {
			etag = head.Header.Get("ETag")
		}
		etag = strings.Trim(strings.TrimPrefix(etag, "W/"), `"`)
		size := head.Header.Get("X-Linked-Size")
		if size == "" {
			size = head.Header.Get("Content-Length")
		}
		if head.Header.Get("X-Repo-Commit") != info.SHA || etag == "" || size != fmt.Sprint(e.Size) || head.Header.Get("X-Xet-Hash") != "" {
			t.Fatalf("HEAD %s headers: %v", u, head.Header)
		}
		get, body := raw(t, srv, http.MethodGet, u)
		if get.StatusCode != http.StatusOK || fmt.Sprint(len(body)) != size {
			t.Fatalf("GET %s: %d, %d bytes", u, get.StatusCode, len(body))
		}
		got[e.Path], etags[e.Path] = body, etag
	}
	sort.Strings(listed)
	if strings.Join(listed, ",") != strings.Join(files, ",") {
		t.Fatalf("siblings %v and tree %v differ", listed, files)
	}
	return info.SHA, got, etags
}

// The issue's acceptance: a client making huggingface_hub's requests
// downloads the promoted bytes, and they match the attested hashes. Checked
// both ways a model is addressed: its own repo id and its hash.
func TestHubServesThePromotedBytes(t *testing.T) {
	f := newHubFixture(t)
	tiny := f.doc(t, f.dir)
	for _, repo := range []string{"org/tiny", HashNamespace + "/" + f.dir} {
		for _, rev := range []string{"main", hubCommit, f.dir} {
			commit, got, etags := hfDownload(t, f.srv, repo, rev)
			want := hubCommit
			if rev == f.dir {
				want = f.dir
			}
			if commit != want {
				t.Errorf("%s@%s: commit %s, want %s", repo, rev, commit, want)
			}
			if len(got) != len(tiny.Artifact.Files) {
				t.Fatalf("%s@%s: %d files, attested %d", repo, rev, len(got), len(tiny.Artifact.Files))
			}
			for _, af := range tiny.Artifact.Files {
				sum := sha256.Sum256(got[af.Path])
				if hex.EncodeToString(sum[:]) != af.SHA256 || etags[af.Path] != af.SHA256 {
					t.Errorf("%s@%s %s: bytes hash to %x, etag %s, attested %s", repo, rev, af.Path, sum, etags[af.Path], af.SHA256)
				}
			}
			var files []modeldir.File
			for p, b := range got {
				sum := sha256.Sum256(b)
				files = append(files, modeldir.File{Path: p, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(b))})
			}
			sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
			if modeldir.Digest(files) != f.dir {
				t.Errorf("%s@%s: the downloaded files are not the attested subject", repo, rev)
			}
		}
	}

	single := f.doc(t, f.file)
	for _, repo := range []string{"example/model", HashNamespace + "/" + f.file} {
		commit, got, _ := hfDownload(t, f.srv, repo, "main")
		b, ok := got[single.Artifact.FileName]
		sum := sha256.Sum256(b)
		if !ok || len(got) != 1 || hex.EncodeToString(sum[:]) != f.file || commit != single.Artifact.CommitSHA {
			t.Errorf("%s: %d files, commit %s, %s hashes to %x", repo, len(got), commit, single.Artifact.FileName, sum)
		}
	}
}

// Socair's own repo pull is an independent client of the listing: it checks
// every file against the listed SHA-256 and the tree against the expected
// manifest digest. Pulling org/tiny back out of the hub endpoint into a new
// store, pinned to the attested digest, must succeed.
func TestHubRoundTripsThroughAPull(t *testing.T) {
	f := newHubFixture(t)
	dst, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pol := EgressPolicy{Allow: []string{"127.0.0.1"}, Endpoint: f.srv.URL, Timeout: 5 * time.Second}
	e, _, err := PullRepo(context.Background(), dst, "org/tiny", "main", f.dir, pol)
	if err != nil || e.SHA256 != f.dir {
		t.Fatalf("pull from the hub endpoint: %v (%s)", err, e.SHA256)
	}
}

// A conditional entry's acceptance bounds how long it is served, checked on
// every request; --authorized-only never serves it.
func TestHubServesAConditionalModelOnlyWhileItsAcceptanceHolds(t *testing.T) {
	f := newHubFixture(t)
	path := "/org/tiny/resolve/main/config.json"
	if resp, _ := raw(t, f.srv, http.MethodGet, path); resp.StatusCode != http.StatusOK || resp.Header.Get("X-Socair-Promotion-State") != report.StateAuthorizedWithConditions {
		t.Fatalf("before expiry: %d %v", resp.StatusCode, resp.Header)
	}
	f.hub.now = func() time.Time { return time.Now().Add(25 * time.Hour) }
	if resp, _ := raw(t, f.srv, http.MethodGet, path); resp.StatusCode != http.StatusNotFound || resp.Header.Get("X-Error-Code") != "RepoNotFound" {
		t.Fatalf("after expiry: %d %v", resp.StatusCode, resp.Header)
	}
	strict := httptest.NewServer(NewHub(f.s, HubOptions{AuthorizedOnly: true}))
	defer strict.Close()
	if resp, _ := raw(t, strict, http.MethodGet, path); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("--authorized-only served a conditional model: %d", resp.StatusCode)
	}
	if resp, _ := raw(t, strict, http.MethodGet, "/api/socair/attestations/"+f.dir); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("--authorized-only served a conditional model's attestation: %d", resp.StatusCode)
	}
	if resp, _ := raw(t, strict, http.MethodGet, "/example/model/resolve/main/fixture.safetensors"); resp.StatusCode != http.StatusOK {
		t.Fatalf("--authorized-only refused an authorized model: %d", resp.StatusCode)
	}
}

// The issue's acceptance: a model that is not in clean/ returns 404, and
// nothing in staging is reachable. A clean entry the store does not admit now
// is answered exactly as one that does not exist. Falsification: serve clean
// entries without AdmittedEntry's stage check and the withheld and flagged
// cases are served.
func TestHubAnswers404ForWhatTheStoreDoesNotAdmit(t *testing.T) {
	f := newHubFixture(t)
	missing := strings.Repeat("c", 64)
	_, absent := raw(t, f.srv, http.MethodGet, "/api/models/org/absent/revision/main")

	cases := map[string]func(t *testing.T) []string{
		"not in clean": func(t *testing.T) []string {
			return []string{"/api/models/org/absent", "/org/absent/resolve/main/config.json", "/" + HashNamespace + "/" + missing + "/resolve/main/x",
				"/api/socair/attestations/" + missing}
		},
		"staged, never promoted": func(t *testing.T) []string {
			return []string{"/api/models/" + HashNamespace + "/" + f.staged, "/" + HashNamespace + "/" + f.staged + "/resolve/main/model.safetensors",
				"/api/models/org/staged/revision/main", "/org/staged/resolve/main/model.safetensors", "/api/socair/attestations/" + f.staged,
				"/example/model/resolve/" + f.staged + "/model.safetensors"}
		},
		"withheld attestation in clean": func(t *testing.T) []string {
			_, d := authorizedArtifact(t)
			withholdForGap(d)
			if err := os.WriteFile(filepath.Join(f.s.CleanPath(f.file), attestationEnvelope), envelopeFor(t, d), 0o644); err != nil {
				t.Fatal(err)
			}
			return []string{"/api/models/example/model", "/example/model/resolve/main/fixture.safetensors",
				"/" + HashNamespace + "/" + f.file + "/resolve/main/fixture.safetensors", "/api/socair/attestations/" + f.file}
		},
		"flagged by a recheck": func(t *testing.T) []string {
			if err := os.WriteFile(filepath.Join(f.s.CleanPath(f.dir), RecheckFile), []byte("not json"), 0o644); err != nil {
				t.Fatal(err)
			}
			return []string{"/api/models/org/tiny/tree/main?recursive=true", "/org/tiny/resolve/" + hubCommit + "/config.json",
				"/" + HashNamespace + "/" + f.dir + "/resolve/main/config.json", "/api/socair/attestations/" + f.dir}
		},
		"untrusted signer": func(t *testing.T) []string {
			if err := os.Remove(filepath.Join(f.s.TrustPath(), "test.pub")); err != nil {
				t.Fatal(err)
			}
			return []string{"/api/models/example/model", "/example/model/resolve/main/fixture.safetensors"}
		},
	}
	for _, name := range []string{"not in clean", "staged, never promoted", "withheld attestation in clean", "flagged by a recheck", "untrusted signer"} {
		t.Run(name, func(t *testing.T) {
			for _, p := range cases[name](t) {
				for _, m := range []string{http.MethodGet, http.MethodHead} {
					resp, b := raw(t, f.srv, m, p)
					if resp.StatusCode != http.StatusNotFound || bytes.Contains(b, []byte(stagedSecret)) {
						t.Errorf("%s %s: %d %s", m, p, resp.StatusCode, b)
					}
					if strings.HasPrefix(p, "/api/socair/") {
						continue
					}
					if code := resp.Header.Get("X-Error-Code"); code != "RepoNotFound" && code != "RevisionNotFound" {
						t.Errorf("%s %s: X-Error-Code %q", m, p, code)
					}
					if m == http.MethodGet && strings.HasPrefix(p, "/api/models/") && !bytes.Equal(b, absent) {
						t.Errorf("%s: a model that is not served must look like one that does not exist: %s", p, b)
					}
				}
			}
		})
	}
}

// A missing file of a served model is EntryNotFound with the commit, which
// clients treat as an optional file being absent (transformers probes for
// several), never as the repo missing.
func TestHubMissingFileIsEntryNotFound(t *testing.T) {
	f := newHubFixture(t)
	for _, p := range []string{"/org/tiny/resolve/main/generation_config.json", "/api/models/org/tiny/tree/main/additional_chat_templates"} {
		resp, _ := raw(t, f.srv, http.MethodGet, p)
		if resp.StatusCode != http.StatusNotFound || resp.Header.Get("X-Error-Code") != "EntryNotFound" || resp.Header.Get("X-Repo-Commit") != hubCommit {
			t.Errorf("%s: %d %v", p, resp.StatusCode, resp.Header)
		}
	}
}

// The issue's falsification: path tricks never reach incoming/ or anything
// outside the admitted entries. Every request below names, one way or
// another, the staged secret or a file outside the store. Falsification:
// join the request path to the entry's directory instead of looking it up
// among the attested paths (Hub.resolve, OpenAdmitted), or drop the decoding
// checks in repoPathFrom, and a case returns the secret.
func TestHubPathTricksNeverLeaveTheAdmittedEntries(t *testing.T) {
	f := newHubFixture(t)
	plantUnattested(t, f)
	up := strings.Repeat("../", 6)
	enc := strings.Repeat("%2e%2e/", 6)
	encSep := strings.Repeat("..%2f", 6)
	encAll := strings.Repeat("%2e%2e%2f", 6)
	back := strings.Repeat("..%5c", 6)
	staged := "incoming/" + f.staged + "/model.safetensors"
	outside := strings.TrimPrefix(f.outside, "/")
	var paths []string
	for _, repo := range []string{"org/tiny", HashNamespace + "/" + f.dir} {
		for _, trick := range []string{up, enc, encSep, encAll, back, "%252e%252e/%252e%252e/", "/", "%2f", "./"} {
			for _, target := range []string{staged, outside, "log.jsonl", "trusted-keys/test.pub", "clean/" + f.file + "/fixture.safetensors"} {
				paths = append(paths, "/"+repo+"/resolve/main/"+trick+target,
					"/api/models/"+repo+"/tree/main/"+trick+target)
			}
		}
	}
	paths = append(paths,
		"/"+HashNamespace+"/"+f.staged+"/resolve/main/model.safetensors",
		"/"+HashNamespace+"/..%2f..%2fincoming/resolve/main/"+f.staged+"/model.safetensors",
		"/org/..%2f..%2fincoming/resolve/main/x",
		"/%2e%2e/%2e%2e/resolve/main/"+staged,
		"/api/socair/attestations/..%2f..%2f"+staged,
		"/api/socair/attestations/"+f.staged,
		"/org/tiny/resolve/..%2f..%2f/config.json",
		"/org/tiny/resolve/main/sub/../../../"+staged,
		"/org/tiny/resolve/main/sub%2f..%2f..%2f..%2f"+staged,
		"/org/tiny/resolve/main/tiny/config.json",
		"/org/tiny/resolve/main/attestation.dsse.json",
		"/org/tiny/resolve/main/recheck.json",
		"/org/tiny/resolve/main/planted.bin",
		"/org/tiny/resolve/main/sub/planted.bin",
		"/api/models/org/tiny/tree/main/planted.bin",
	)
	for _, p := range paths {
		for _, m := range []string{http.MethodGet, http.MethodHead} {
			resp, b := raw(t, f.srv, m, p)
			if resp.StatusCode == http.StatusOK || bytes.Contains(b, []byte(stagedSecret)) || bytes.Contains(b, []byte(outsideSecret)) {
				t.Errorf("%s %s: %d %q", m, p, resp.StatusCode, b)
			}
		}
	}
}

// plantUnattested puts regular files the attestation does not list inside
// the clean tree of org/tiny, holding the staged secret.
func plantUnattested(t *testing.T, f *hubFixture) {
	t.Helper()
	tree := filepath.Join(f.s.CleanPath(f.dir), "tiny")
	for _, p := range []string{filepath.Join(tree, "planted.bin"), filepath.Join(tree, "sub", "planted.bin")} {
		if err := os.WriteFile(p, []byte(stagedSecret), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// Each layer under the HTTP routes holds on its own.
// Falsification: make repoPathFrom skip safeRepoPath, or OpenAdmitted open a
// path its attestation does not list, and a case here passes.
func TestHubPathGuardsHoldEachOnTheirOwn(t *testing.T) {
	for _, raw := range [][]string{
		{"..", "..", "incoming"}, {"%2e%2e", "x"}, {"..%2f..%2fincoming"}, {"a", "", "b"}, {""},
		{"%2fetc%2fpasswd"}, {"a%5c..%5cb"}, {"a%00b"}, {"sub", "..", "config.json"}, {"%zz"},
	} {
		if p, err := repoPathFrom(raw); err == nil {
			t.Errorf("repoPathFrom(%q) = %q, want a refusal", raw, p)
		}
	}
	if p, err := repoPathFrom([]string{"sub", "notes.txt"}); err != nil || p != "sub/notes.txt" {
		t.Errorf("a plain path: %q %v", p, err)
	}

	f := newHubFixture(t)
	plantUnattested(t, f)
	a, err := f.s.AdmittedEntry(f.dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"planted.bin", "sub/planted.bin", "../../../incoming/" + f.staged + "/model.safetensors", "../attestation.dsse.json", "tiny/config.json", "sub", "", f.outside} {
		if file, err := f.s.OpenAdmitted(a, p); err == nil {
			file.Close()
			t.Errorf("OpenAdmitted(%q) opened a file the attestation does not list", p)
		}
	}
}

// A symlink inside clean/ is never followed, even when it points at bytes
// that hash to the attested ones: promote writes regular files, so a link is
// not what was attested. Falsification: drop noSymlinks from OpenAdmitted and
// the in-entry link is served; open with os.Open instead of the os.Root and
// TestOpenBeneathStaysInTheEntry fails.
func TestHubNeverFollowsASymlinkInClean(t *testing.T) {
	f := newHubFixture(t)
	entry := filepath.Join(f.s.CleanPath(f.dir), "tiny")
	body, err := os.ReadFile(filepath.Join(entry, "config.json"))
	if err != nil {
		t.Fatal(err)
	}

	// Pointing out of the store, at a copy with the attested bytes.
	decoy := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(decoy, body, 0o644); err != nil {
		t.Fatal(err)
	}
	link := func(target string) {
		t.Helper()
		if err := os.Remove(filepath.Join(entry, "config.json")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(entry, "config.json")); err != nil {
			t.Fatal(err)
		}
	}
	link(decoy)
	for _, m := range []string{http.MethodGet, http.MethodHead} {
		if resp, b := raw(t, f.srv, m, "/org/tiny/resolve/main/config.json"); resp.StatusCode == http.StatusOK || bytes.Contains(b, body) {
			t.Errorf("%s followed a symlink out of clean: %d %s", m, resp.StatusCode, b)
		}
	}

	// Pointing inside the entry, at a file with the same bytes.
	inside := filepath.Join(entry, "sub", "copy.json")
	if err := os.WriteFile(inside, body, 0o644); err != nil {
		t.Fatal(err)
	}
	link(filepath.Join("sub", "copy.json"))
	if resp, b := raw(t, f.srv, http.MethodGet, "/org/tiny/resolve/main/config.json"); resp.StatusCode == http.StatusOK || bytes.Contains(b, body) {
		t.Errorf("followed a symlink inside clean: %d %s", resp.StatusCode, b)
	}
}

// The os.Root under OpenAdmitted refuses a name that resolves outside the
// entry, whatever walked it first.
func TestOpenBeneathStaysInTheEntry(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte(outsideSecret), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../../../../../../../"+strings.TrimPrefix(outside, "/"), filepath.Join(dir, "relative")); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, name := range []string{"link", "relative", "../" + filepath.Base(filepath.Dir(outside)) + "/secret"} {
		if f, err := openBeneath(root, name, nil); err == nil {
			b, _ := io.ReadAll(f)
			f.Close()
			t.Errorf("openBeneath(%q) left the root: %q", name, b)
		}
	}
}

// Every full download is hashed as it is sent, and its last byte is sent only
// when the whole file hashes to the attestation. A range is served only from
// a file a whole pass has checked. Falsification: drop the comparison in
// streamVerified, or the range check in Hub.resolve, and the tampered bytes
// arrive complete.
func TestHubSendsOnlyBytesThatMatchTheAttestation(t *testing.T) {
	f := newHubFixture(t)
	p := filepath.Join(f.s.CleanPath(f.dir), "tiny", "model.safetensors")
	good, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	u := f.srv.URL + "/org/tiny/resolve/main/model.safetensors"
	if b := get(t, u, ""); !bytes.Equal(b, good) {
		t.Fatal("the untampered file must be served whole")
	}

	// Same size, different bytes, rewritten in place.
	bad := bytes.Clone(good)
	bad[len(bad)-1] ^= 0xff
	bad[10] ^= 0xff
	// promote leaves clean files read-only; a writer with access can still
	// change them.
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	tamper := func() {
		t.Helper()
		if err := os.WriteFile(p, bad, 0o644); err != nil {
			t.Fatal(err)
		}
		later := time.Now().Add(time.Minute)
		if err := os.Chtimes(p, later, later); err != nil {
			t.Fatal(err)
		}
	}
	tamper()
	// The client never has the tampered file whole: the transfer is cut
	// short of its last byte (and a client that retries is refused).
	if resp, err := http.Get(u); err == nil {
		b, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err == nil && resp.StatusCode == http.StatusOK && bytes.Equal(b, bad) {
			t.Fatal("a file that does not hash to its attestation reached the client whole")
		}
	}
	for _, m := range []string{http.MethodGet, http.MethodHead} {
		if r, _ := raw(t, f.srv, m, "/org/tiny/resolve/main/model.safetensors"); r.StatusCode != http.StatusInternalServerError {
			t.Errorf("%s after a failed check: %d", m, r.StatusCode)
		}
	}
	if r, b := raw(t, f.srv, http.MethodGet, "/org/tiny/resolve/main/model.safetensors", "Range", "bytes=0-15"); r.StatusCode != http.StatusInternalServerError || len(b) == 16 {
		t.Errorf("a range of a failed file: %d", r.StatusCode)
	}

	// A fresh endpoint has checked nothing: a range of the tampered file is
	// checked whole first, and refused.
	fresh := httptest.NewServer(NewHub(f.s, HubOptions{}))
	defer fresh.Close()
	if r, b := raw(t, fresh, http.MethodGet, "/org/tiny/resolve/main/model.safetensors", "Range", "bytes=0-15"); r.StatusCode != http.StatusInternalServerError || len(b) == 16 {
		t.Errorf("an unchecked range of a tampered file: %d", r.StatusCode)
	}

	// Restored, a range is served once a whole pass checks it.
	if err := os.WriteFile(p, good, 0o644); err != nil {
		t.Fatal(err)
	}
	if b := get(t, fresh.URL+"/org/tiny/resolve/main/model.safetensors", "bytes=8-15"); !bytes.Equal(b, good[8:16]) {
		t.Errorf("a range of the restored file: %q", b)
	}
}

// streamVerified writes all but the last byte of a file that does not hash
// to the attestation, and all of one that does.
func TestStreamVerifiedWithholdsTheLastByte(t *testing.T) {
	good := []byte("the attested bytes")
	sum := sha256.Sum256(good)
	want := hex.EncodeToString(sum[:])
	for name, body := range map[string][]byte{"match": good, "same size, other bytes": []byte("the attested bytez")} {
		p := filepath.Join(t.TempDir(), "f")
		if err := os.WriteFile(p, body, 0o644); err != nil {
			t.Fatal(err)
		}
		file, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		ok, err := streamVerified(&out, file, int64(len(body)), want)
		file.Close()
		if err != nil {
			t.Fatal(err)
		}
		match := bytes.Equal(body, good)
		if ok != match || (match && !bytes.Equal(out.Bytes(), good)) || (!match && out.Len() != len(body)-1) {
			t.Errorf("%s: ok=%v, wrote %d of %d bytes", name, ok, out.Len(), len(body))
		}
	}
}

func get(t *testing.T, u, rng string) []byte {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	if rng != "" {
		req.Header.Set("Range", rng)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil || (resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent) {
		t.Fatalf("GET %s: %d %v", u, resp.StatusCode, err)
	}
	return b
}

// The attestation beside each model is served byte for byte and verifies
// offline against the operator's key, for exactly that subject.
func TestHubServesTheAttestation(t *testing.T) {
	f := newHubFixture(t)
	resp, b := raw(t, f.srv, http.MethodGet, "/api/models/org/tiny")
	var info struct {
		Socair struct {
			Entries []struct {
				Subject, Attestation, PromotionState string
				AcceptanceExpires                    string `json:"acceptance_expires"`
			} `json:"entries"`
		} `json:"socair"`
	}
	if resp.StatusCode != http.StatusOK || json.Unmarshal(b, &info) != nil || len(info.Socair.Entries) != 1 {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	e := info.Socair.Entries[0]
	if e.Subject != f.dir || e.AcceptanceExpires == "" {
		t.Fatalf("%+v", e)
	}
	resp, env := raw(t, f.srv, http.MethodGet, e.Attestation)
	want, _ := os.ReadFile(filepath.Join(f.s.CleanPath(f.dir), attestationEnvelope))
	if resp.StatusCode != http.StatusOK || !bytes.Equal(env, want) {
		t.Fatalf("%d: the envelope must be the clean entry's own", resp.StatusCode)
	}
	v, err := attest.Verify(env, attest.Keyring{testKeyID(t): testKey.Public().(ed25519.PublicKey)})
	if err != nil || v.SHA256 != f.dir {
		t.Fatalf("offline verify: %v", err)
	}
}

// Two admitted entries of one repo id at different commits: main is
// ambiguous and refused, each commit and each hash is served. Single files
// pulled from one repo at one commit list together.
func TestHubResolvesRevisionsWithoutGuessing(t *testing.T) {
	s := trustedStore(t)
	const other = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	q4, q4doc := authorizedFile(t, "model-Q4.safetensors", "q4", "example/quant", hubCommit)
	q8, q8doc := authorizedFile(t, "model-Q8.safetensors", "q8", "example/quant", hubCommit)
	newer, newerDoc := authorizedFile(t, "model-Q4.safetensors", "q4-newer", "example/quant", other)
	for i, a := range []string{q4, q8} {
		d := []*report.Document{q4doc, q8doc}[i]
		if _, err := Promote(s, a, writeReport(t, d)); err != nil {
			t.Fatal(err)
		}
	}
	srv := httptest.NewServer(NewHub(s, HubOptions{}))
	defer srv.Close()

	commit, got, _ := hfDownload(t, srv, "example/quant", "main")
	if commit != hubCommit || len(got) != 2 {
		t.Fatalf("two single files at one commit list together: %s %d", commit, len(got))
	}

	if _, err := Promote(s, newer, writeReport(t, newerDoc)); err != nil {
		t.Fatal(err)
	}
	fresh := httptest.NewServer(NewHub(s, HubOptions{}))
	defer fresh.Close()
	resp, b := raw(t, fresh, http.MethodGet, "/api/models/example/quant/revision/main")
	if resp.StatusCode != http.StatusConflict || !strings.Contains(string(b), other) || !strings.Contains(string(b), hubCommit) {
		t.Fatalf("main over two commits must be refused, naming both: %d %s", resp.StatusCode, b)
	}
	if r, _ := raw(t, fresh, http.MethodGet, "/example/quant/resolve/main/model-Q4.safetensors"); r.StatusCode != http.StatusConflict {
		t.Errorf("a file at main over two commits: %d", r.StatusCode)
	}
	for rev, want := range map[string]string{hubCommit: q4doc.Artifact.SHA256, other: newerDoc.Artifact.SHA256, newerDoc.Artifact.SHA256: newerDoc.Artifact.SHA256} {
		_, got, _ := hfDownload(t, fresh, "example/quant", rev)
		sum := sha256.Sum256(got["model-Q4.safetensors"])
		if hex.EncodeToString(sum[:]) != want {
			t.Errorf("revision %s served %x, want %s", rev, sum, want)
		}
	}
	if r, _ := raw(t, fresh, http.MethodGet, "/api/models/example/quant/revision/v1.0"); r.StatusCode != http.StatusNotFound || r.Header.Get("X-Error-Code") != "RevisionNotFound" {
		t.Errorf("an unknown revision: %d %v", r.StatusCode, r.Header)
	}
}

// authorizedFile scans a generated safetensors file as authorized, with a
// provenance manifest naming repo at commit, and returns it ready to promote.
func authorizedFile(t *testing.T, name, author, repo, commit string) (string, *report.Document) {
	t.Helper()
	dir := t.TempDir()
	body := safetensorstest.Build(map[string]string{"format": "pt", "author": author}, []safetensorstest.TensorSpec{
		{Name: "model.embed_tokens.weight", Start: 0, End: 64, Dtype: "F16", Shape: []int64{4, 8}},
		{Name: "model.norm.weight", Start: 64, End: 128, Dtype: "F32", Shape: []int64{16}},
	})
	sum := sha256.Sum256(body)
	mirror := filepath.Join(dir, "mirror")
	if err := os.MkdirAll(mirror, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mirror, "config.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOCAIR_REPO_MIRROR", mirror)
	deny := filepath.Join(dir, "denylist.txt")
	if err := os.WriteFile(deny, []byte(strings.Repeat("0", 64)+"  known-bad\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOCAIR_DENYLIST", deny)
	prov := filepath.Join(dir, "provenance.json")
	bound := fmt.Sprintf(`{"artifact_sha256":%q,"publisher":"example","signing_status":"signed","repo_url":"https://huggingface.co/%s","commit_or_tag":"main","commit_sha":%q}`,
		hex.EncodeToString(sum[:]), repo, commit)
	if err := os.WriteFile(prov, []byte(bound), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOCAIR_PROVENANCE", prov)
	t.Setenv("SOCAIR_ACCEPTED_BY", "")
	artifact := filepath.Join(dir, name)
	if err := os.WriteFile(artifact, body, 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := engine.Scan(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if d.PromotionAuthorization.State != report.StateAuthorized {
		t.Fatalf("%s: state %s", name, d.PromotionAuthorization.State)
	}
	return artifact, d
}

// The endpoint never writes: a whole download session leaves every file in
// the store as it was, and anything but GET and HEAD is refused.
func TestHubIsReadOnly(t *testing.T) {
	f := newHubFixture(t)
	before := storeSnapshot(t, f.s)
	hfDownload(t, f.srv, "org/tiny", "main")
	hfDownload(t, f.srv, "example/model", "main")
	raw(t, f.srv, http.MethodGet, "/api/socair/attestations/"+f.dir)
	raw(t, f.srv, http.MethodGet, "/org/tiny/resolve/main/model.safetensors", "Range", "bytes=0-7")
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		for _, p := range []string{"/org/tiny/resolve/main/config.json", "/api/models/org/tiny", "/api/models/org/tiny/paths-info/main", "/api/socair/attestations/" + f.dir} {
			if resp, _ := raw(t, f.srv, m, p); resp.StatusCode != http.StatusMethodNotAllowed && resp.StatusCode != http.StatusNotFound {
				t.Errorf("%s %s: %d", m, p, resp.StatusCode)
			}
		}
	}
	if after := storeSnapshot(t, f.s); after != before {
		t.Errorf("the store changed under a read-only endpoint:\n%s\n---\n%s", before, after)
	}
}

// storeSnapshot lists every file in the store with its size, mode, and
// modification time, and the hash of its bytes.
func storeSnapshot(t *testing.T, s *Store) string {
	t.Helper()
	var lines []string
	err := filepath.WalkDir(s.Root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		line := fmt.Sprintf("%s %v %d %s", strings.TrimPrefix(p, s.Root), fi.Mode(), fi.Size(), fi.ModTime().Format(time.RFC3339Nano))
		if fi.Mode().IsRegular() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(b)
			line += " " + hex.EncodeToString(sum[:])
		}
		lines = append(lines, line)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(lines, "\n")
}

// The endpoint has no authentication, so it binds loopback unless told
// otherwise, and while on loopback it answers only a loopback Host, so a web
// page cannot read it through DNS rebinding.
func TestHubBindsLoopbackUnlessAllowed(t *testing.T) {
	for addr, ok := range map[string]bool{"127.0.0.1:8081": true, "localhost:8081": true, "[::1]:8081": true, "0.0.0.0:8081": false, ":8081": false, "10.0.0.5:8081": false} {
		if err := CheckHubAddr(addr, false); (err == nil) != ok {
			t.Errorf("CheckHubAddr(%s): %v", addr, err)
		}
		if err := CheckHubAddr(addr, true); err != nil {
			t.Errorf("CheckHubAddr(%s, allowPublic): %v", addr, err)
		}
	}
	f := newHubFixture(t)
	resp, _ := raw(t, f.srv, http.MethodGet, "/api/health")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health: %d", resp.StatusCode)
	}
	req, _ := http.NewRequest(http.MethodGet, f.srv.URL+"/api/models/org/tiny", nil)
	req.Host = "attacker.example:8081"
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != http.StatusForbidden {
		t.Errorf("a rebinding Host on a loopback endpoint: %d", r.StatusCode)
	}
}

// A newly promoted model is served once the index refreshes, without a
// restart; admission is re-derived on every request regardless.
func TestHubSeesANewPromotionAfterRefresh(t *testing.T) {
	s := trustedStore(t)
	h := NewHub(s, HubOptions{Refresh: time.Hour})
	srv := httptest.NewServer(h)
	defer srv.Close()
	if r, _ := raw(t, srv, http.MethodGet, "/api/models/example/model"); r.StatusCode != http.StatusNotFound {
		t.Fatalf("empty store: %d", r.StatusCode)
	}
	id := promoted(t, s)
	if r, _ := raw(t, srv, http.MethodGet, "/api/models/"+HashNamespace+"/"+id); r.StatusCode != http.StatusOK {
		t.Errorf("by hash, admission is read per request: %d", r.StatusCode)
	}
	h.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if r, _ := raw(t, srv, http.MethodGet, "/api/models/example/model"); r.StatusCode != http.StatusOK {
		t.Errorf("by repo id, after the refresh: %d", r.StatusCode)
	}
}

// Two entries at one commit that hold different bytes under one path are
// never merged into one listing: the endpoint cannot know which is meant.
func TestHubRefusesConflictingFiles(t *testing.T) {
	s := trustedStore(t)
	var ids []string
	for _, author := range []string{"first", "second"} {
		a, d := authorizedFile(t, "model.safetensors", author, "example/clash", hubCommit)
		if _, err := Promote(s, a, writeReport(t, d)); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, d.Artifact.SHA256)
	}
	srv := httptest.NewServer(NewHub(s, HubOptions{}))
	defer srv.Close()
	for _, p := range []string{"/api/models/example/clash", "/example/clash/resolve/main/model.safetensors", "/example/clash/resolve/" + hubCommit + "/model.safetensors"} {
		if r, _ := raw(t, srv, http.MethodGet, p); r.StatusCode != http.StatusConflict {
			t.Errorf("%s: %d", p, r.StatusCode)
		}
	}
	for _, id := range ids {
		_, got, _ := hfDownload(t, srv, "example/clash", id)
		sum := sha256.Sum256(got["model.safetensors"])
		if hex.EncodeToString(sum[:]) != id {
			t.Errorf("revision %s served %x", id, sum)
		}
	}
}

// A repo id is read from the attested repo URL, and one in the hash
// namespace is not a repo id: an attestation cannot make another hash
// resolve to its bytes.
func TestHubRepoIDNeverShadowsAHash(t *testing.T) {
	for u, want := range map[string]string{
		"https://huggingface.co/org/name":            "org/name",
		"https://hf-mirror.internal/org/name/":       "org/name",
		"http://127.0.0.1:9000/org/name":             "org/name",
		"https://huggingface.co/org/name/tree/main":  "",
		"https://huggingface.co/name":                "",
		"https://huggingface.co/org/name?x=1":        "",
		"huggingface.co/org/name":                    "",
		"https://huggingface.co/org/..":              "",
		"https://huggingface.co/sha256/" + hubCommit: "",
		"": "",
	} {
		a := &Admitted{Document: &report.Document{Artifact: report.ArtifactIdentity{RepoURL: u}}}
		if got := a.RepoID(); got != want {
			t.Errorf("RepoID(%q) = %q, want %q", u, got, want)
		}
	}

	s := trustedStore(t)
	victim := strings.Repeat("d", 64)
	a, d := authorizedFile(t, "model.safetensors", "shadow", HashNamespace+"/"+victim, hubCommit)
	if _, err := Promote(s, a, writeReport(t, d)); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(NewHub(s, HubOptions{}))
	defer srv.Close()
	if r, _ := raw(t, srv, http.MethodGet, "/"+HashNamespace+"/"+victim+"/resolve/main/model.safetensors"); r.StatusCode != http.StatusNotFound {
		t.Errorf("an attested repo URL in the hash namespace was served as that hash: %d", r.StatusCode)
	}
}
