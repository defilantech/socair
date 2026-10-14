package convert

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/checks/structure"
)

// TestRealCheckpoints converts real torch.save checkpoints and compares each
// converted tensor with the original as torch loads it. It is opt-in:
//
//	SOCAIR_CONVERT_CORPUS=<dir> go test ./internal/convert -run RealCheckpoints -v
//
// It walks dir for .bin, .pt, .pth, and .ckpt files and converts each. A
// checkpoint the converter refuses is listed with the reason and does not
// fail the test; one it converts must give an output whose structure row
// PASSes and, when python3 can import torch (SOCAIR_PYTHON names another
// interpreter), whose every tensor testdata/compare_torch.py finds equal to
// torch.load's. Without torch the comparison is skipped, and the test says
// so. It downloads nothing: bring the checkpoints.
func TestRealCheckpoints(t *testing.T) {
	dir := os.Getenv("SOCAIR_CONVERT_CORPUS")
	if dir == "" {
		t.Skip("set SOCAIR_CONVERT_CORPUS to a directory of torch.save checkpoints")
	}
	python := os.Getenv("SOCAIR_PYTHON")
	if python == "" {
		python = "python3"
	}
	torch := exec.Command(python, "-c", "import torch").Run() == nil
	script, err := filepath.Abs(filepath.Join("testdata", "compare_torch.py"))
	if err != nil {
		t.Fatal(err)
	}

	var files []string
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		switch strings.ToLower(filepath.Ext(p)) {
		case ".bin", ".pt", ".pth", ".ckpt":
			if d.Type().IsRegular() {
				files = append(files, p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatalf("no .bin, .pt, .pth, or .ckpt files under %s", dir)
	}
	converted, compared := 0, 0
	for _, f := range files {
		rel, _ := filepath.Rel(dir, f)
		p, err := PlanFile(f)
		if reason, ok := IsRefused(err); ok {
			t.Logf("refused  %s: %s", rel, reason)
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", rel, err)
			continue
		}
		dst := filepath.Join(t.TempDir(), "model.safetensors")
		out, err := p.Write(dst)
		if reason, ok := IsRefused(err); ok {
			t.Logf("refused  %s: %s", rel, reason)
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", rel, err)
			continue
		}
		converted++
		if r := structure.Validate(dst); r.Status != checks.Pass {
			t.Errorf("%s: the output's structure row is %s: %s", rel, r.Status, r.Notes)
		}
		if !torch {
			t.Logf("converted %s: %d tensor(s), not compared", rel, len(out.Tensors))
			continue
		}
		cmd := exec.Command(python, script, f, dst)
		var stderr strings.Builder
		cmd.Stderr = &stderr
		b, err := cmd.Output()
		if err != nil {
			t.Errorf("%s: torch and the output differ:\n%s%s", rel, b, stderr.String())
			continue
		}
		compared++
		t.Logf("converted %s: %d tensor(s), %s", rel, len(out.Tensors), strings.TrimSpace(string(b)))
	}
	t.Logf("%d of %d checkpoint(s) converted, %d compared with torch", converted, len(files), compared)
	if !torch {
		t.Skipf("%s cannot import torch, so no output was compared with torch.load", python)
	}
}
