package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/modeldir"
	"github.com/defilantech/socair/internal/report"
	"github.com/defilantech/socair/internal/safetensors/safetensorstest"
)

// modelRepo writes a small, clean transformers-style model directory.
func modelRepo(t *testing.T, extra map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"config.json":           `{"_name_or_path":"org/tiny","architectures":["LlamaForCausalLM"],"model_type":"llama"}`,
		"model.safetensors":     string(safetensorstest.Clean()),
		"tokenizer_config.json": `{"chat_template":"{% for m in messages %}{{ m['role'] }}: {{ m['content'] }}\n{% endfor %}"}`,
		"tokenizer.json":        `{"model":{"type":"BPE"}}`,
	}
	for k, v := range extra {
		files[k] = v
	}
	for rel, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func row(d *report.Document, name string) report.CheckResult {
	for _, c := range d.Checks {
		if c.Name == name {
			return c
		}
	}
	return report.CheckResult{}
}

func TestDirectoryScanCoversEveryFile(t *testing.T) {
	dir := modelRepo(t, nil)
	d, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if problems := report.Validate(d); len(problems) != 0 {
		t.Fatal(problems)
	}
	a := d.Artifact
	digest, files, err := modeldir.Hash(dir)
	if err != nil {
		t.Fatal(err)
	}
	if a.SHA256 != digest || len(a.Files) != len(files) || a.Format != "model directory" {
		t.Fatalf("subject %s files %d format %q; want the manifest digest %s of %d files", a.SHA256, len(a.Files), a.Format, digest, len(files))
	}
	if a.Name != "org/tiny" || a.Architecture != "LlamaForCausalLM" {
		t.Errorf("identity name %q arch %q", a.Name, a.Architecture)
	}
	for name, want := range map[string]report.Status{
		"Format and structure": report.StatusPass, "Chat template (hero)": report.StatusPass,
		"Remote code": report.StatusPass, "Tokenizer config": report.StatusNotTested,
	} {
		if got := row(d, name).Status; got != want {
			t.Errorf("%s = %s (%s), want %s", name, got, row(d, name).Notes, want)
		}
	}
}

// The issue's falsification: a repo with auto_map and a .py file is not
// authorized, and no acceptance clears it, because it is a LEAD, not a gap.
func TestRemoteCodeRepoIsNotAuthorized(t *testing.T) {
	supplyInputs(t)
	t.Setenv("SOCAIR_ACCEPTED_BY", "ciso@example.com")
	dir := modelRepo(t, map[string]string{
		"config.json":   `{"model_type":"x","auto_map":{"AutoModelForCausalLM":"modeling_x.XForCausalLM"}}`,
		"modeling_x.py": "import os\nos.system('id')\n",
	})
	d, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if r := row(d, "Remote code"); r.Status != report.StatusLead || !strings.Contains(r.Notes, "modeling_x.py") {
		t.Fatalf("remote code row %s (%s)", r.Status, r.Notes)
	}
	if d.PromotionAuthorization.Authorized {
		t.Fatalf("state %s: remote code must withhold, and an acceptance must not clear it", d.PromotionAuthorization.State)
	}
}

// One bad shard withholds the directory, through the merged row.
func TestOneMalformedShardFailsTheDirectory(t *testing.T) {
	// Data bytes no tensor accounts for: where a payload hides.
	gap := safetensorstest.BuildWithDataLen(nil, []safetensorstest.TensorSpec{
		{Name: "w", Start: 0, End: 64, Dtype: "F32", Shape: []int64{16}}}, 4096)
	dir := modelRepo(t, map[string]string{"model-2.safetensors": string(gap)})
	d, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if r := row(d, "Format and structure"); r.Status != report.StatusFail || !strings.Contains(r.Evidence+r.Notes, "model-2.safetensors") {
		t.Fatalf("structure %s (%s / %s), want FAIL naming the shard", r.Status, r.Evidence, r.Notes)
	}
}

// The checks read the snapshot: bytes changed after it was taken neither
// reach a check nor the subject.
func TestDirectoryChecksReadTheSnapshot(t *testing.T) {
	dir := modelRepo(t, nil)
	before, _, _ := modeldir.Hash(dir)
	afterSnapshot = func(string) {
		_ = os.WriteFile(filepath.Join(dir, "model.safetensors"), safetensorstest.OutOfRangeOffsets(), 0o644)
		_ = os.WriteFile(filepath.Join(dir, "evil.py"), []byte("import os"), 0o644)
	}
	t.Cleanup(func() { afterSnapshot = nil })
	d, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if d.Artifact.SHA256 != before || row(d, "Format and structure").Status != report.StatusPass || row(d, "Remote code").Status != report.StatusPass {
		t.Fatalf("the report must describe the snapshot: subject %s (want %s), structure %s, remote code %s",
			d.Artifact.SHA256, before, row(d, "Format and structure").Status, row(d, "Remote code").Status)
	}
}

func TestDirectoryScanIsAlwaysFull(t *testing.T) {
	if _, err := ScanMode(modelRepo(t, nil), ModeHeaders); err == nil {
		t.Fatal("a header-only directory scan would attest nothing")
	}
}

func TestDisplayName(t *testing.T) {
	cache := filepath.Join("hub", "models--Qwen--Qwen3-0.6B", "snapshots", "c1899de")
	for dir, want := range map[string]string{cache: "Qwen/Qwen3-0.6B", "/tmp/mymodel": "mymodel"} {
		if got := displayName(dir, "/home/trainer/ckpt-final"); got != want {
			t.Errorf("%s: %q, want %q", dir, got, want)
		}
	}
	if displayName("/tmp/x", "org/model") != "org/model" {
		t.Error("a repo id in _name_or_path names the model")
	}
}

// The shard index is checked against the shards, so a set whose index sends
// the loader to a tensor no shard holds is not a clean directory.
func TestShardIndexDisagreementFailsTheDirectory(t *testing.T) {
	dir := modelRepo(t, map[string]string{
		"model.safetensors.index.json": `{"weight_map":{"model.embed_tokens.weight":"model.safetensors","model.norm.weight":"model.safetensors","lm_head.weight":"model.safetensors"}}`,
	})
	d, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if r := row(d, "Format and structure"); r.Status != report.StatusFail || !strings.Contains(r.Evidence+r.Notes, "lm_head.weight") {
		t.Fatalf("structure %s (%s / %s), want FAIL naming the phantom tensor", r.Status, r.Evidence, r.Notes)
	}
}
