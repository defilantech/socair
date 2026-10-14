package structure

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/openvino"
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

// TestRealOpenVINOModels is the false-positive gate for the OpenVINO IR
// rules: real exports must not FAIL or LEAD. It runs only when
// SOCAIR_OPENVINO_CORPUS names directories (colon-separated), each read as a
// scanned model directory: every .xml under it whose root is <net> is
// checked with its .bin resolved beside it. A .bin may be a sparse file of
// the size the hub lists, since only its size is read. Nothing is loaded or
// run.
//
//	SOCAIR_OPENVINO_CORPUS=<repo>:<repo> go test ./internal/checks/structure -run RealOpenVINO -v
func TestRealOpenVINOModels(t *testing.T) {
	dirs := os.Getenv("SOCAIR_OPENVINO_CORPUS")
	if dirs == "" {
		t.Skip("set SOCAIR_OPENVINO_CORPUS to model directories holding OpenVINO IR files")
	}
	tally := map[checks.Status]int{}
	for _, dir := range strings.Split(dirs, ":") {
		_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || !strings.HasSuffix(p, ".xml") || !openvino.Sniff(p) {
				return nil
			}
			rel, _ := filepath.Rel(dir, p)
			r := ValidateOpenVINO(dir, filepath.ToSlash(rel))
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
