package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// A single-file pull printed where it staged the file but not how to scan it
// with the provenance manifest it wrote, which the provenance row needs; only
// a whole-repo pull did. Both print the same invocation now.
func TestScanHintNamesTheManifestBesideTheArtifact(t *testing.T) {
	for _, staged := range []string{
		filepath.Join("store", "incoming", "abc", "model.gguf"),
		filepath.Join("store", "incoming", "def", "Qwen2.5-0.5B-Instruct"),
	} {
		got := scanHint(staged)
		want := "SOCAIR_PROVENANCE=" + filepath.Join(filepath.Dir(staged), "provenance.json") + " socair scan " + staged
		if !strings.Contains(got, want) {
			t.Errorf("scanHint(%q) = %q, want it to contain %q", staged, got, want)
		}
	}
}
