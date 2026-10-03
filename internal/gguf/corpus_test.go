package gguf

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRealGGUFLayouts is the false-positive gate for tensor-layout validation
// and the check on the ggml type table: a real GGUF only tiles exactly if
// every type's block size and byte size is right. It reads headers only and
// runs when SOCAIR_GGUF_CORPUS names directories (colon-separated):
//
//	SOCAIR_GGUF_CORPUS=~/models go test ./internal/gguf -run RealGGUF -v
func TestRealGGUFLayouts(t *testing.T) {
	dirs := os.Getenv("SOCAIR_GGUF_CORPUS")
	if dirs == "" {
		t.Skip("set SOCAIR_GGUF_CORPUS to directories holding .gguf files")
	}
	var ok, bad, unverified, truncated int
	for _, dir := range strings.Split(dirs, ":") {
		_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || !strings.HasSuffix(p, ".gguf") {
				return nil
			}
			m, err := ReadHeader(p)
			if err != nil {
				t.Logf("%s: parse: %v", filepath.Base(p), err)
				return nil
			}
			l := m.ValidateLayout()
			switch {
			case len(l.Violations) > 0:
				bad++
				t.Errorf("%s: %v", filepath.Base(p), l.Violations[:min(3, len(l.Violations))])
			case len(l.Unverified) > 0:
				unverified++
				t.Logf("%s: unverified: %v", filepath.Base(p), l.Unverified[:1])
			case l.Truncated != "":
				truncated++
				t.Logf("%s: truncated: %s", filepath.Base(p), l.Truncated)
			default:
				ok++
				t.Logf("%s: %d tensors, %s", filepath.Base(p), len(m.Tensors), HistogramString(m.TypeHistogram()))
			}
			return nil
		})
	}
	t.Logf("%d valid, %d violations, %d unverified, %d truncated", ok, bad, unverified, truncated)
}
