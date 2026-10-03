package jinja

import (
	"os"
	"path/filepath"
	"testing"
)

// TestParseCorpus parses a directory of real chat templates. It is skipped
// unless SOCAIR_TEMPLATE_CORPUS names a directory of *.jinja files, because
// third-party templates are not committed:
//
//	SOCAIR_TEMPLATE_CORPUS=/path/to/templates go test ./internal/checks/chattemplate/jinja -run Corpus -v
func TestParseCorpus(t *testing.T) {
	dir := os.Getenv("SOCAIR_TEMPLATE_CORPUS")
	if dir == "" {
		t.Skip("set SOCAIR_TEMPLATE_CORPUS to a directory of .jinja templates")
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.jinja"))
	if len(files) == 0 {
		t.Fatalf("no .jinja files under %s", dir)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Parse(string(b)); err != nil {
			t.Errorf("%s: %v", filepath.Base(f), err)
		}
	}
	t.Logf("parsed %d templates", len(files))
}
