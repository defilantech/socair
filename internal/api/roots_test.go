package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/defilantech/socair/internal/airlock"
	"github.com/defilantech/socair/internal/report"
)

// layout is a scan root with the ways a path can try to leave it.
type layout struct {
	base     string // a temp dir holding everything below
	root     string // the scan root
	model    string // a file under the root
	outside  string // a directory beside the root
	secret   string // a file outside the root
	rootLink string // a symlink to the root, outside it
	// realModel is model with every symlink resolved, the temp dir's own
	// included (/var is /private/var on macOS).
	realModel string
}

func newLayout(t *testing.T) layout {
	t.Helper()
	base := t.TempDir()
	l := layout{
		base:     base,
		root:     filepath.Join(base, "models"),
		outside:  filepath.Join(base, "outside"),
		rootLink: filepath.Join(base, "models-link"),
	}
	l.model = filepath.Join(l.root, "model.gguf")
	l.secret = filepath.Join(l.outside, "secret.gguf")
	for _, d := range []string{filepath.Join(l.root, "sub"), l.outside, filepath.Join(base, "models-evil")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{l.model, l.secret, filepath.Join(base, "models-evil", "x.gguf")} {
		if err := os.WriteFile(f, []byte("bytes"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	links := map[string]string{
		filepath.Join(l.root, "out.gguf"):  l.secret,  // a file link that leaves the root
		filepath.Join(l.root, "outdir"):    l.outside, // a directory link that leaves the root
		filepath.Join(base, "inward.gguf"): l.model,   // a link from outside into the root
		l.rootLink:                         l.root,    // a root reached through a link
	}
	for link, target := range links {
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
	}
	real, err := filepath.EvalSymlinks(l.model)
	if err != nil {
		t.Fatal(err)
	}
	l.realModel = real
	return l
}

type rootCase struct {
	name  string
	roots []string
	path  string
	want  string // the path the engine is handed; "" means refused
}

func rootCases(l layout) []rootCase {
	roots := []string{l.root}
	return []rootCase{
		{"a file under the root", roots, l.model, l.model},
		{"the root itself", roots, l.root, l.root},
		{"a .. that stays inside", roots, l.root + "/sub/../model.gguf", l.model},
		{"a .. that climbs out", roots, l.root + "/../outside/secret.gguf", ""},
		{"an absolute path outside", roots, l.secret, ""},
		{"a missing path outside", roots, filepath.Join(l.outside, "missing.gguf"), ""},
		{"a missing path inside", roots, filepath.Join(l.root, "missing.gguf"), ""},
		{"a file symlink that leaves the root", roots, filepath.Join(l.root, "out.gguf"), ""},
		{"a directory symlink that leaves the root", roots, filepath.Join(l.root, "outdir", "secret.gguf"), ""},
		{"a sibling that shares the root's prefix", roots, filepath.Join(l.base, "models-evil", "x.gguf"), ""},
		{"a link outside that points in", roots, filepath.Join(l.base, "inward.gguf"), ""},
		{"a relative path", roots, "model.gguf", ""},
		{"the filesystem root", roots, "/", ""},
		{"through a root that is a symlink", []string{l.rootLink}, filepath.Join(l.rootLink, "model.gguf"), filepath.Join(l.rootLink, "model.gguf")},
		{"a symlinked root's resolved target", []string{l.rootLink}, l.realModel, l.realModel},
		{"a symlinked root, then a link out", []string{l.rootLink}, filepath.Join(l.rootLink, "out.gguf"), ""},
		{"a symlinked root, then a .. out", []string{l.rootLink}, l.rootLink + "/../outside/secret.gguf", ""},
		{"no roots, a real file", nil, l.model, ""},
		{"no roots, a missing file", nil, filepath.Join(l.root, "missing.gguf"), ""},
	}
}

func TestContainedPath(t *testing.T) {
	l := newLayout(t)
	for _, c := range rootCases(l) {
		got, err := containedPath(c.roots, c.path)
		switch {
		case c.want == "" && err == nil:
			t.Errorf("%s: %q was allowed as %q, want refused", c.name, c.path, got)
		case c.want != "" && err != nil:
			t.Errorf("%s: %q was refused: %v", c.name, c.path, err)
		case c.want != "" && got != c.want:
			t.Errorf("%s: %q became %q, want %q", c.name, c.path, got, c.want)
		}
	}
}

// spy stands in for the engine and the airlock and records every path the
// API hands them.
type spy struct {
	mu    sync.Mutex
	paths []string
}

func (s *spy) record(p string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.paths = append(s.paths, p)
}

func (s *spy) take() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	got := s.paths
	s.paths = nil
	return got
}

func (s *spy) readers() *pathReaders {
	return &pathReaders{
		scan: func(p string) (*report.Document, error) {
			s.record(p)
			return nil, errors.New("spy: scan not run")
		},
		ingest: func(p string) (string, error) {
			s.record(p)
			return p, nil
		},
		promote: func(_ *airlock.Store, p, _ string) (airlock.Event, error) {
			s.record(p)
			return airlock.Event{}, errors.New("spy: promote not run")
		},
	}
}

// TestRefusedPathsNeverReachTheEngine is the boundary's falsification: every
// path-taking route is sent every case, and a spy in place of the engine and
// the airlock records what reaches them. A refused path never does, and an
// allowed one arrives as the cleaned path under its root. Remove the
// containment from any route, or either half of it (as written, or once
// resolved), and a refused case reaches the spy.
func TestRefusedPathsNeverReachTheEngine(t *testing.T) {
	l := newLayout(t)
	store := t.TempDir()
	if _, err := airlock.Init(store); err != nil {
		t.Fatal(err)
	}
	routes := []struct {
		route string
		body  func(p string) map[string]any
	}{
		{"/api/scan", func(p string) map[string]any { return map[string]any{"path": p} }},
		{"/api/scan", func(p string) map[string]any { return map[string]any{"local": p} }},
		{"/api/airlock/ingest", func(p string) map[string]any { return map[string]any{"local": p} }},
		{"/api/airlock/promote", func(p string) map[string]any {
			return map[string]any{"artifact": p, "attestation": json.RawMessage(`{}`)}
		}},
	}
	for _, c := range rootCases(l) {
		sp := &spy{}
		for _, rt := range routes {
			opts := Options{ScanRoots: c.roots, readers: sp.readers()}
			if rt.route != "/api/scan" {
				// The airlock routes need a store; its staging area is a root
				// of its own, which none of these paths is under.
				opts.StoreRoot = store
			}
			ts := server(t, opts)
			code, body := post(t, ts, rt.route, rt.body(c.path))
			got := sp.take()
			if c.want == "" {
				if len(got) != 0 {
					t.Errorf("%s via %s: %q reached the engine as %q", c.name, rt.route, c.path, got)
				}
				if code != http.StatusUnprocessableEntity {
					t.Errorf("%s via %s: refusal answered %d %s, want 422", c.name, rt.route, code, body)
				}
				continue
			}
			if len(got) != 1 || got[0] != c.want {
				t.Errorf("%s via %s: the engine got %q, want [%q] (%d %s)", c.name, rt.route, got, c.want, code, body)
			}
		}
	}
}

// TestRefusalSaysNothingAboutExistence: a refusal reads the same for a file
// that exists outside the roots, one that does not, a link that leads out,
// and a missing file inside, so the API is not an oracle for the filesystem.
func TestRefusalSaysNothingAboutExistence(t *testing.T) {
	l := newLayout(t)
	ts := server(t, Options{ScanRoots: []string{l.root}})
	var first string
	for _, p := range []string{
		l.secret,
		filepath.Join(l.outside, "missing.gguf"),
		filepath.Join(l.root, "out.gguf"),
		filepath.Join(l.root, "outdir", "secret.gguf"),
		filepath.Join(l.root, "missing.gguf"),
		filepath.Join(l.root, "outdir", "missing.gguf"),
	} {
		code, body := post(t, ts, "/api/scan", map[string]string{"path": p})
		var e struct{ Error string }
		if err := json.Unmarshal(body, &e); err != nil || e.Error == "" {
			t.Fatalf("%s: no JSON error: %d %s", p, code, body)
		}
		msg := strconv.Itoa(code) + " " + strings.ReplaceAll(e.Error, strconv.Quote(p), "<path>")
		if first == "" {
			first = msg
			if !strings.Contains(msg, "<path>") || !strings.Contains(msg, "scan root") {
				t.Fatalf("the refusal should quote the path as sent and name scan roots: %s", msg)
			}
			continue
		}
		if msg != first {
			t.Errorf("refusals differ, which tells a caller something about %s:\n  %s\n  %s", p, first, msg)
		}
	}
}

// TestNoScanRootsNamesTheFlag: with no root and no store, every path is
// refused, and the refusal says how to configure one.
func TestNoScanRootsNamesTheFlag(t *testing.T) {
	ts := server(t, Options{})
	code, body := post(t, ts, "/api/scan", map[string]string{"path": fixture(t)})
	if code != http.StatusUnprocessableEntity || !strings.Contains(string(body), "--scan-root") {
		t.Fatalf("a scan with no roots = %d %s, want 422 naming --scan-root", code, body)
	}
}

// TestStoreStagingIsARoot: with a store, a staged artifact may be scanned
// and promoted with no --scan-root, and the rest of the store may not.
func TestStoreStagingIsARoot(t *testing.T) {
	root, id := consoleStore(t)
	s, err := airlock.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	sp := &spy{}
	ts := server(t, Options{StoreRoot: root, readers: sp.readers()})

	staged := filepath.Join(s.StagingPath(id), "fixture.safetensors")
	post(t, ts, "/api/scan", map[string]string{"path": staged})
	if got := sp.take(); len(got) != 1 || got[0] != staged {
		t.Fatalf("a staged artifact should reach the engine, got %q", got)
	}
	for _, p := range []string{s.LogPath(), s.TrustPath(), s.CleanPath(id), root} {
		code, body := post(t, ts, "/api/scan", map[string]string{"path": p})
		if got := sp.take(); len(got) != 0 || code != http.StatusUnprocessableEntity {
			t.Errorf("%s is outside incoming/ but reached the engine as %q (%d %s)", p, got, code, body)
		}
	}
}

func TestResolveScanRoots(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]string{{""}, {" "}, {filepath.Join(dir, "missing")}, {file}, {dir, ""}} {
		if got, err := ResolveScanRoots(bad); err == nil {
			t.Errorf("ResolveScanRoots(%q) = %q, want an error", bad, got)
		}
	}
	got, err := ResolveScanRoots([]string{dir})
	if err != nil || len(got) != 1 || got[0] != dir {
		t.Fatalf("ResolveScanRoots(%q) = %q, %v", dir, got, err)
	}
	if got, err := ResolveScanRoots(nil); err != nil || len(got) != 0 {
		t.Fatalf("no roots = %q, %v", got, err)
	}
}

// TestStaticFilesStayInTheBuild: the static handler joined the request path
// onto the build directory and followed whatever it found, so a symlink in
// the build served a file outside it. It now reads through an os.Root.
// Falsification: go back to filepath.Join and os.Stat, and the links serve
// the secret.
func TestStaticFilesStayInTheBuild(t *testing.T) {
	base := t.TempDir()
	web := filepath.Join(base, "web")
	if err := os.MkdirAll(filepath.Join(web, "_app"), 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		filepath.Join(web, "200.html"): "<!doctype html><title>shell</title>",
		filepath.Join(web, "app.js"):   "console.log('app')",
		filepath.Join(base, "secret"):  "TOPSECRET",
	}
	for p, b := range files {
		if err := os.WriteFile(p, []byte(b), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range map[string]string{
		filepath.Join(web, "leak.txt"): filepath.Join(base, "secret"),
		filepath.Join(web, "leakdir"):  base,
	} {
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
	}

	// Straight to the handler, with the path as given: no mux cleaning.
	h := spaHandler(web)
	direct := func(p string) (int, string) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.URL.Path = p
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	if code, body := direct("/app.js"); code != http.StatusOK || body != files[filepath.Join(web, "app.js")] {
		t.Fatalf("a build file: %d %q", code, body)
	}
	if code, body := direct("/scan/step-2"); code != http.StatusOK || !strings.Contains(body, "shell") {
		t.Fatalf("a client route should get the shell: %d %q", code, body)
	}
	for _, p := range []string{
		"/../secret", "/../../../../" + strings.TrimPrefix(base, "/") + "/secret",
		"/leak.txt", "/leakdir/secret", `\..\secret`, `/..\secret`, "/_app/../../secret",
	} {
		if _, body := direct(p); strings.Contains(body, "TOPSECRET") {
			t.Errorf("%q served a file outside the build", p)
		}
	}

	// Through the server, with encoded separators and dots.
	ts := server(t, Options{WebDir: web})
	for _, p := range []string{
		"/%2e%2e/secret", "/..%2fsecret", "/%2e%2e%2fsecret", "/..%5csecret", "/leak%2etxt", "/leakdir%2fsecret",
	} {
		resp, err := http.Get(ts.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if strings.Contains(string(body), "TOPSECRET") {
			t.Errorf("%q served a file outside the build", p)
		}
	}
}
