package tokenizer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/modeldir"
)

// TestRealHFTokenizers is the false-positive gate for InspectHF: every model
// directory under SOCAIR_TOKENIZER_CORPUS (space-separated directories, each
// a repo with its tokenizer files) must not FAIL or LEAD. Run it after any
// rule change and record the result in docs/false-positive-baseline.md.
func TestRealHFTokenizers(t *testing.T) {
	corpus := os.Getenv("SOCAIR_TOKENIZER_CORPUS")
	if corpus == "" {
		t.Skip("set SOCAIR_TOKENIZER_CORPUS to directories of real tokenizer files")
	}
	counts := map[checks.Status]int{}
	for _, d := range strings.Fields(corpus) {
		root, files, _, cleanup, err := modeldir.Snapshot(d, t.TempDir())
		if err != nil {
			t.Logf("%s: %v", d, err)
			continue
		}
		r := InspectHF(root, files)
		cleanup()
		counts[r.Status]++
		t.Logf("%-10s %s", r.Status, filepath.Base(filepath.Clean(d)))
		if r.Status == checks.Fail || r.Status == checks.Lead {
			t.Errorf("%s: %s on a real tokenizer: %s", d, r.Status, r.Notes)
		}
	}
	t.Logf("totals: %v", counts)
}
