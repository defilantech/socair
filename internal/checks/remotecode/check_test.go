package remotecode

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/modeldir"
)

func repo(t *testing.T, files map[string]string) (string, []modeldir.File) {
	t.Helper()
	dir := t.TempDir()
	for rel, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	snap, fs, _, cleanup, err := modeldir.Snapshot(dir, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanup)
	return snap, fs
}

func TestCleanRepoPasses(t *testing.T) {
	root, files := repo(t, map[string]string{"config.json": `{"model_type":"llama"}`, "tokenizer.json": `{"model":{}}`, "vocab.json": `["a"]`})
	if r := Inspect(root, files); r.Status != checks.Pass {
		t.Fatalf("status %s (%s)", r.Status, r.Notes)
	}
}

// Falsification: drop either detector and its case passes.
func TestRemoteCodeIsALeadNamingEveryFile(t *testing.T) {
	cases := map[string]map[string]string{
		"auto_map in config": {"config.json": `{"auto_map":{"AutoModelForCausalLM":"modeling_x.XForCausalLM"}}`},
		"auto_map in tokenizer config": {"config.json": `{}`,
			"tokenizer_config.json": `{"auto_map":{"AutoTokenizer":["tok.XTokenizer", null]}}`},
		"a python file": {"config.json": `{}`, "sub/helper.py": "import os"},
	}
	for name, files := range cases {
		root, fs := repo(t, files)
		r := Inspect(root, fs)
		if r.Status != checks.Lead {
			t.Errorf("%s: status %s, want LEAD", name, r.Status)
			continue
		}
		for rel := range files {
			if rel != "config.json" && !strings.Contains(r.Notes, rel) {
				t.Errorf("%s: the note must name %s: %s", name, rel, r.Notes)
			}
		}
	}
	root, fs := repo(t, cases["auto_map in config"])
	if r := Inspect(root, fs); !strings.Contains(r.Notes, "modeling_x.XForCausalLM") {
		t.Errorf("the auto_map target must be named: %s", r.Notes)
	}
}

func TestUnparseableConfigIsNotTested(t *testing.T) {
	root, files := repo(t, map[string]string{"config.json": `{"auto_map": `})
	if r := Inspect(root, files); r.Status != checks.NotTested {
		t.Fatalf("status %s: an unreadable config may hide an auto_map", r.Status)
	}
}
