package airlock

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/defilantech/socair/internal/engine"
	"github.com/defilantech/socair/internal/modeldir"
)

// Patterns match the way huggingface_hub's allow and ignore patterns do, so
// an operator's `hf download --include` habits carry over: * crosses
// directories, and a trailing slash means everything under that directory.
func TestSelectionMatchesLikeTheHubClient(t *testing.T) {
	for _, c := range []struct {
		pattern string
		path    string
		want    bool
	}{
		{"*.py", "x.py", true},
		{"*.py", "inference/model.py", true},
		{"*.py", "x.pyc", false},
		{"inference/", "inference/model.py", true},
		{"inference/", "inference/sub/kernel.py", true},
		{"inference/", "inference.json", false},
		{"metal/*", "metal/model.bin", true},
		{"model-0000[1-2]-of-*.safetensors", "model-00002-of-00048.safetensors", true},
		{"model-0000[1-2]-of-*.safetensors", "model-00003-of-00048.safetensors", false},
		{"model-0000[!1]-of-*.safetensors", "model-00002-of-00048.safetensors", true},
		{"config.jso?", "config.json", true},
		{"a+b.json", "a+b.json", true},
		{"a+b.json", "aab.json", false},
		{"x[]]y", "x]y", true},
		{"x[^a]y", "x^y", true},
		{"x[^a]y", "xby", false},
		{"x[!^a]y", "xby", true},
		{"x[!^a]y", "x^y", false},
		{`x[\]y`, `x\y`, true},
	} {
		sel := Selection{Include: []string{c.pattern}}
		m, err := sel.compile()
		if err != nil {
			t.Fatalf("%q: %v", c.pattern, err)
		}
		if got := m.keeps(c.path); got != c.want {
			t.Errorf("include %q keeps %q = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
}

func TestSelectionExcludeWinsOverInclude(t *testing.T) {
	m, err := Selection{Include: []string{"*.safetensors", "*.json"}, Exclude: []string{"original/"}}.compile()
	if err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]bool{
		"model-00001-of-00002.safetensors":    true,
		"config.json":                         true,
		"original/model--00001.safetensors":   false,
		"original/config.json":                false,
		"README.md":                           false,
		"DeepSeek_V41_Tech_Report.pdf":        false,
		"model.safetensors.index.json":        true,
		"tokenizer_config.json":               true,
		"inference/model.py":                  false,
		"metal/model.bin":                     false,
		"original/model.safetensors.index.js": false,
	} {
		if got := m.keeps(p); got != want {
			t.Errorf("keeps %q = %v, want %v", p, got, want)
		}
	}
}

func TestSelectionRefusesUnusablePatterns(t *testing.T) {
	for _, sel := range []Selection{
		{Include: []string{""}},
		{Exclude: []string{"  "}},
		{Include: []string{"model-[12.safetensors"}},
	} {
		if _, err := sel.compile(); err == nil {
			t.Errorf("%+v must be refused", sel)
		}
	}
}

// A selected pull fetches only the kept files, stages a tree whose digest is
// theirs, and records what it left out in the provenance manifest and the
// log. Leaving out repository code that the serving stack never loads (the
// DeepSeek inference/ directory) is what lets such a repo cross without a
// Remote code LEAD. Falsification: ignore the selection in PullRepo and the
// excluded files are fetched, staged, and LEAD the scan.
func TestPullRepoSelectedLeavesOutExcludedFiles(t *testing.T) {
	t.Setenv("SOCAIR_EGRESS", "")
	hub := newFakeHub()
	hub.files["inference/model.py"] = "import os\n"
	srv := hub.start(t)
	var mu sync.Mutex
	fetched := map[string]bool{}
	inner := srv.Config.Handler
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if i := strings.Index(r.URL.Path, "/resolve/"+hubCommit+"/"); i >= 0 {
			mu.Lock()
			fetched[r.URL.Path[i+len("/resolve/"+hubCommit+"/"):]] = true
			mu.Unlock()
		}
		inner.ServeHTTP(w, r)
	})
	s := trustedStore(t)

	sel := Selection{Exclude: []string{"inference/", "*.txt"}}
	e, staged, err := PullRepoSelected(context.Background(), s, "org/tiny", hubCommit, "", sel, hubPolicy(srv))
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	for _, p := range []string{"inference/model.py", "sub/notes.txt"} {
		if fetched[p] {
			t.Errorf("%s was excluded but fetched", p)
		}
		if _, err := os.Stat(filepath.Join(staged, filepath.FromSlash(p))); !os.IsNotExist(err) {
			t.Errorf("%s was excluded but staged", p)
		}
		if !strings.Contains(e.Detail, p) {
			t.Errorf("the log must name the left-out %s: %s", p, e.Detail)
		}
	}
	digest, files, err := modeldir.Hash(staged)
	if err != nil || digest != e.SHA256 || len(files) != 3 {
		t.Fatalf("staged digest %s (%d files, %v), logged %s", digest, len(files), err, e.SHA256)
	}

	manifest := filepath.Join(s.StagingPath(digest), ProvenanceFile)
	raw, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		ArtifactSHA256 string `json:"artifact_sha256"`
		Selection      struct {
			Include []string `json:"include"`
			Exclude []string `json:"exclude"`
			LeftOut []string `json:"left_out"`
		} `json:"selection"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m.ArtifactSHA256 != digest || !reflect.DeepEqual(m.Selection.Exclude, sel.Exclude) ||
		!reflect.DeepEqual(m.Selection.LeftOut, []string{"inference/model.py", "sub/notes.txt"}) {
		t.Fatalf("the manifest must bind the digest and record the selection: %s", raw)
	}

	for _, k := range []string{"SOCAIR_REPO_MIRROR", "SOCAIR_DENYLIST", "SOCAIR_ACCEPTED_BY"} {
		t.Setenv(k, "")
	}
	t.Setenv("SOCAIR_PROVENANCE", manifest)
	d, err := engine.Scan(staged)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range d.Checks {
		if (c.Name == "Remote code" || c.Name == "Hash, provenance, lineage") && c.Status != "PASS" {
			t.Errorf("%s: %s (%s)", c.Name, c.Status, c.Notes)
		}
		if c.Name == "Hash, provenance, lineage" && !strings.Contains(c.Notes, "2 left out: inference/model.py, sub/notes.txt") {
			t.Errorf("the signed report must say the tree is a selection: %s", c.Notes)
		}
	}
}

func TestPullRepoSelectedIncludeOnly(t *testing.T) {
	t.Setenv("SOCAIR_EGRESS", "")
	srv := newFakeHub().start(t)
	s, _ := Init(t.TempDir())
	_, staged, err := PullRepoSelected(context.Background(), s, "org/tiny", hubCommit, "", Selection{Include: []string{"*.json"}}, hubPolicy(srv))
	if err != nil {
		t.Fatal(err)
	}
	_, files, err := modeldir.Hash(staged)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range files {
		got = append(got, f.Path)
	}
	if !reflect.DeepEqual(got, []string{"config.json", "tokenizer_config.json"}) {
		t.Fatalf("staged %v", got)
	}
}

func TestPullRepoSelectedRefusesAnEmptyOrUnusableSelection(t *testing.T) {
	t.Setenv("SOCAIR_EGRESS", "")
	srv := newFakeHub().start(t)
	s, _ := Init(t.TempDir())
	if _, _, err := PullRepoSelected(context.Background(), s, "org/tiny", hubCommit, "", Selection{Include: []string{"*.gguf"}}, hubPolicy(srv)); err == nil || !strings.Contains(err.Error(), "keeps none") {
		t.Errorf("a selection that keeps nothing must be refused, got %v", err)
	}
	if _, _, err := PullRepoSelected(context.Background(), s, "org/tiny", hubCommit, "", Selection{Exclude: []string{"[x"}}, hubPolicy(srv)); err == nil || !strings.Contains(err.Error(), "[x") {
		t.Errorf("an unusable pattern must be refused by name, got %v", err)
	}
	if entries, _ := os.ReadDir(filepath.Join(s.Root, stagingDir)); len(entries) != 0 {
		t.Error("nothing may be staged on a refusal")
	}
}
