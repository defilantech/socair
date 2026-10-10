package pickle

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// namedPickle are the extensions a model directory already sends to this
// check by name (engine.pickleExt).
var namedPickle = map[string]bool{".bin": true, ".pt": true, ".pth": true, ".ckpt": true, ".pkl": true,
	".pickle": true, ".joblib": true, ".npy": true, ".npz": true}

// TestRealSniff measures Sniff on real model repositories, the false-positive
// gate for finding a pickle by its bytes (#186). It runs only when
// SOCAIR_PICKLE_SNIFF_CORPUS names directories (colon-separated) to search:
//
//	SOCAIR_PICKLE_SNIFF_CORPUS=~/.cache/huggingface/hub go test ./internal/checks/pickle -run RealSniff -v
//
// Every file is sniffed; a Hugging Face cache's blobs/ directory is skipped,
// since its files have no names and are reached through snapshots/. A file
// whose name does not say pickle and that Sniff claims fails the test: in a
// real repository it is either a false positive or a renamed pickle, and both
// need a look. A file whose name says pickle and that Sniff does not claim is
// logged (raw weights in a .bin, a .npy array, or a protocol 0 or 1 pickle);
// the directory scan still sends it to the check by its name.
func TestRealSniff(t *testing.T) {
	dirs := os.Getenv("SOCAIR_PICKLE_SNIFF_CORPUS")
	if dirs == "" {
		t.Skip("set SOCAIR_PICKLE_SNIFF_CORPUS to directories holding model repositories")
	}
	var files, byName, byBytes, both int
	for _, dir := range strings.Split(dirs, ":") {
		_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if d.Name() == "blobs" || d.Name() == ".git" {
					return filepath.SkipDir
				}
				return nil
			}
			if fi, err := os.Stat(p); err != nil || !fi.Mode().IsRegular() {
				return nil
			}
			files++
			named := namedPickle[strings.ToLower(filepath.Ext(p))]
			kind := Sniff(p)
			switch {
			case named && kind != "":
				both++
			case named:
				byName++
				t.Logf("named, not sniffed: %s", p)
			case kind != "":
				byBytes++
				t.Errorf("sniffed, not named: %s (%s)", p, kind)
			}
			return nil
		})
	}
	t.Logf("%d files: %d pickles by name and bytes, %d by name only, %d by bytes only", files, both, byName, byBytes)
}
