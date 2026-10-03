package structure

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/checks"
)

// TestRealSafetensorsLayouts is the false-positive gate for layout
// validation: real safetensors files must not FAIL. It reads headers only, so
// it is cheap on multi-GB models, and runs only when SOCAIR_SAFETENSORS_CORPUS
// names directories (colon-separated) to search:
//
//	SOCAIR_SAFETENSORS_CORPUS=~/.cache/huggingface/hub go test ./internal/checks/structure -run RealSafetensors -v
func TestRealSafetensorsLayouts(t *testing.T) {
	dirs := os.Getenv("SOCAIR_SAFETENSORS_CORPUS")
	if dirs == "" {
		t.Skip("set SOCAIR_SAFETENSORS_CORPUS to directories holding .safetensors files")
	}
	tally := map[checks.Status]int{}
	for _, dir := range strings.Split(dirs, ":") {
		_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || !strings.HasSuffix(p, ".safetensors") {
				return nil
			}
			r := Validate(p)
			tally[r.Status]++
			if r.Status == checks.Fail {
				t.Errorf("%s: FAIL: %s", p, r.Notes)
			} else if r.Status == checks.NotTested {
				t.Logf("%s: NOT_TESTED: %s", filepath.Base(p), r.Notes)
			}
			return nil
		})
	}
	t.Logf("%d PASS, %d FAIL, %d NOT_TESTED", tally[checks.Pass], tally[checks.Fail], tally[checks.NotTested])
}
