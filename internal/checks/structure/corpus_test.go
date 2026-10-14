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

// TestRealONNXModels is the false-positive gate for the ONNX rules: real
// exports must not FAIL or LEAD. It runs only when SOCAIR_ONNX_CORPUS names
// directories (colon-separated), each read as a scanned model directory:
// every .onnx file under it is checked with its external data resolved
// inside it. Nothing is loaded or run.
//
//	SOCAIR_ONNX_CORPUS=<repo>:<repo> go test ./internal/checks/structure -run RealONNX -v
func TestRealONNXModels(t *testing.T) {
	dirs := os.Getenv("SOCAIR_ONNX_CORPUS")
	if dirs == "" {
		t.Skip("set SOCAIR_ONNX_CORPUS to model directories holding .onnx files")
	}
	tally := map[checks.Status]int{}
	for _, dir := range strings.Split(dirs, ":") {
		_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || !strings.HasSuffix(p, ".onnx") {
				return nil
			}
			rel, _ := filepath.Rel(dir, p)
			r := ValidateONNX(dir, filepath.ToSlash(rel))
			tally[r.Status]++
			switch r.Status {
			case checks.Fail, checks.Lead:
				t.Errorf("%s: %s: %v: %s", p, r.Status, r.Findings, r.Notes)
			default:
				t.Logf("%s/%s: %s: %s", filepath.Base(dir), rel, r.Status, r.Notes)
			}
			return nil
		})
	}
	t.Logf("%d PASS, %d FAIL, %d LEAD, %d NOT_TESTED", tally[checks.Pass], tally[checks.Fail], tally[checks.Lead], tally[checks.NotTested])
}

// TestRealKerasModels is the false-positive gate for the Keras rules: no
// real model's container (its HDF5 layout, its archive members) may FAIL or
// LEAD. A config detection (Lambda bytecode, a pickled module, a dangerous
// reference) is the rule doing its job, and is logged for the baseline, not
// failed. It runs only when SOCAIR_KERAS_CORPUS names directories
// (colon-separated); every .h5, .hdf5, and .keras file under them is read.
// Nothing is loaded or run.
//
//	SOCAIR_KERAS_CORPUS=<dir>:<dir> go test ./internal/checks/structure -run RealKeras -v
func TestRealKerasModels(t *testing.T) {
	dirs := os.Getenv("SOCAIR_KERAS_CORPUS")
	if dirs == "" {
		t.Skip("set SOCAIR_KERAS_CORPUS to directories holding .h5, .hdf5, or .keras files")
	}
	config := map[string]bool{"keras-lambda": true, "keras-pickle": true, "keras-dangerous-reference": true}
	tally := map[checks.Status]int{}
	for _, dir := range strings.Split(dirs, ":") {
		_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			ext := strings.ToLower(filepath.Ext(p))
			if err != nil || ext != ".h5" && ext != ".hdf5" && ext != ".keras" {
				return nil
			}
			rel, _ := filepath.Rel(dir, p)
			r, _ := ValidateKeras(dir, filepath.ToSlash(rel))
			tally[r.Status]++
			container := false
			for _, f := range r.Findings {
				container = container || !config[f.Pattern]
			}
			if container {
				t.Errorf("%s: %s: %v: %s", p, r.Status, r.Findings, r.Notes)
			} else {
				t.Logf("%s: %s: %v: %s", rel, r.Status, r.Findings, r.Notes)
			}
			return nil
		})
	}
	t.Logf("%d PASS, %d FAIL, %d LEAD, %d NOT_TESTED", tally[checks.Pass], tally[checks.Fail], tally[checks.Lead], tally[checks.NotTested])
}
