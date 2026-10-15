package engine

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/modeldir"
	"github.com/defilantech/socair/internal/report"
)

// stated returns each file's true SHA-256, as a hub would state it.
func stated(t *testing.T, dir string) map[string]string {
	t.Helper()
	_, files, err := modeldir.Hash(dir)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]string{}
	for _, f := range files {
		m[f.Path] = f.SHA256
	}
	return m
}

func TestPreviewReadsInPlaceWithStatedHashes(t *testing.T) {
	dir := modelRepo(t, nil)
	hashes := stated(t, dir)
	// A stated hash is reported as stated: the preview never hashes a file.
	hashes["model.safetensors"] = strings.Repeat("ab", 32)
	// Falsification: a snapshot needs this volume, which does not exist.
	t.Setenv("SOCAIR_SCAN_TMP", filepath.Join(t.TempDir(), "missing"))

	d, err := PreviewDir(dir, hashes)
	if err != nil {
		t.Fatal(err)
	}
	if problems := report.Validate(d); len(problems) != 0 {
		t.Fatal(problems)
	}
	for _, f := range d.Artifact.Files {
		if f.SHA256 != hashes[f.Path] {
			t.Errorf("%s: %s, want the stated %s", f.Path, f.SHA256, hashes[f.Path])
		}
	}
	for name, want := range map[string]report.Status{
		"Format and structure": report.StatusPass, "Chat template": report.StatusPass,
		"Remote code": report.StatusPass, "Tokenizer config": report.StatusPass,
	} {
		if got := row(d, name).Status; got != want {
			t.Errorf("%s = %s (%s), want %s", name, got, row(d, name).Notes, want)
		}
	}
	if d.Artifact.Name != "org/tiny" {
		t.Errorf("name %q", d.Artifact.Name)
	}
}

func TestPreviewNeedsEveryFilesHash(t *testing.T) {
	dir := modelRepo(t, nil)
	hashes := stated(t, dir)
	delete(hashes, "config.json")
	if _, err := PreviewDir(dir, hashes); err == nil || !strings.Contains(err.Error(), "config.json") {
		t.Fatalf("a file with no stated hash must stop the preview, naming it: %v", err)
	}
}

func TestPreviewFindsWhatAScanFinds(t *testing.T) {
	dir := modelRepo(t, map[string]string{"modeling_tiny.py": "import os\n", "config.json": `{"auto_map":{"AutoModel":"modeling_tiny.TinyModel"}}`})
	full, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	d, err := PreviewDir(dir, stated(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	if d.Artifact.SHA256 != full.Artifact.SHA256 {
		t.Errorf("subject %s, a full scan's %s", d.Artifact.SHA256, full.Artifact.SHA256)
	}
	for _, c := range full.Checks {
		if got := row(d, c.Name); got.Status != c.Status {
			t.Errorf("%s: preview %s, full scan %s", c.Name, got.Status, c.Status)
		}
	}
	if row(d, "Remote code").Status != report.StatusLead {
		t.Errorf("remote code = %s, want LEAD", row(d, "Remote code").Status)
	}
}
