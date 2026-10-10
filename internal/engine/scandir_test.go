package engine

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strconv"
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
		"tokenizer.json":        `{"model":{"type":"BPE","vocab":{"<s>":0,"</s>":1,"a":2}},"added_tokens":[{"id":0,"content":"<s>","special":true},{"id":1,"content":"</s>","special":true}]}`,
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
		"Remote code": report.StatusPass, "Tokenizer config": report.StatusPass,
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

// A directory with bound provenance is named by the repo it was pulled from,
// not by config.json's _name_or_path, which the publisher writes and can set
// to any famous repo. Without provenance the label stays the config's.
// Falsification: drop the provenance name and the claimed name shows.
func TestBoundProvenanceNamesTheDirectory(t *testing.T) {
	dir := modelRepo(t, map[string]string{
		"config.json": `{"_name_or_path":"meta-llama/Llama-3.1-8B","architectures":["LlamaForCausalLM"],"model_type":"llama"}`,
	})
	digest, _, err := modeldir.Hash(dir)
	if err != nil {
		t.Fatal(err)
	}
	prov := filepath.Join(t.TempDir(), "provenance.json")
	commit := strings.Repeat("ab", 20)
	manifest := `{"artifact_sha256":"` + digest + `","repo_url":"https://huggingface.co/someone/tiny","commit_or_tag":"` + commit + `","commit_sha":"` + commit + `","source":"airlock pull"}`
	if err := os.WriteFile(prov, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("SOCAIR_PROVENANCE", "")
	d, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if d.Artifact.Name != "meta-llama/Llama-3.1-8B" {
		t.Fatalf("without provenance the config label names it, got %q", d.Artifact.Name)
	}

	t.Setenv("SOCAIR_PROVENANCE", prov)
	d, err = Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if d.Artifact.Name != "someone/tiny" || d.Header.ArtifactShort != "someone/tiny" {
		t.Fatalf("bound provenance must name it: name %q, header %q", d.Artifact.Name, d.Header.ArtifactShort)
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

// A directory's tokenizer is inspected and identified: a clean one PASSes
// with its hash in the identity section, and one whose EOS id names no token
// FAILs the directory.
func TestDirectoryTokenizerIsInspected(t *testing.T) {
	d, err := Scan(modelRepo(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Artifact.TokenizerHash) != 64 {
		t.Errorf("tokenizer_hash %q, want the SHA-256 of tokenizer.json", d.Artifact.TokenizerHash)
	}
	bad, err := Scan(modelRepo(t, map[string]string{"config.json": `{"model_type":"llama","eos_token_id":4242}`}))
	if err != nil {
		t.Fatal(err)
	}
	if r := row(bad, "Tokenizer config"); r.Status != report.StatusFail || !strings.Contains(r.Evidence+r.Notes, "eos_token_id") {
		t.Fatalf("tokenizer row %s (%s), want FAIL naming eos_token_id", r.Status, r.Notes)
	}
	if bad.PromotionAuthorization.Authorized {
		t.Fatal("a tokenizer FAIL must withhold the directory")
	}
}

// npyBytes is a float32 .npy of n elements, its header padded as numpy pads
// it, with extra bytes after the data.
func npyBytes(n int, extra string) string {
	h := "{'descr': '<f4', 'fortran_order': False, 'shape': (" + strconv.Itoa(n) + ",), }"
	h += strings.Repeat(" ", 63-(10+len(h))%64) + "\n"
	return "\x93NUMPY\x01\x00" + string([]byte{byte(len(h)), byte(len(h) >> 8)}) + h + strings.Repeat("\x00", 4*n) + extra
}

// TestDirectoryNumPyArraysReachThePickleCheck: .npy and .npz weights were
// classed as weights but read by nothing ("not a format this scanner
// parses"). The pickle check reads them, and its grammar covers their
// pickled object data. Falsification: drop .npy from pickleExt and the row
// does not cover embeddings.npy, and the bytes after its data go unseen.
func TestDirectoryNumPyArraysReachThePickleCheck(t *testing.T) {
	d, err := Scan(modelRepo(t, map[string]string{"embeddings.npy": npyBytes(4, "")}))
	if err != nil {
		t.Fatal(err)
	}
	if r := row(d, "Pickle opcode scan"); r.Status != report.StatusPass || !strings.Contains(r.Notes, "embeddings.npy") {
		t.Fatalf("pickle row %s (%s), want PASS covering embeddings.npy", r.Status, r.Notes)
	}
	d, err = Scan(modelRepo(t, map[string]string{"embeddings.npy": npyBytes(4, "#!/bin/sh\n")}))
	if err != nil {
		t.Fatal(err)
	}
	if r := row(d, "Pickle opcode scan"); r.Status != report.StatusLead {
		t.Fatalf("pickle row %s (%s), want LEAD on bytes past the array's data", r.Status, r.Notes)
	}
}

// torchZipOf is a zip-format PyTorch checkpoint holding pkl as its data.pkl.
func torchZipOf(t *testing.T, pkl []byte) string {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for name, data := range map[string][]byte{"archive/data.pkl": pkl, "archive/version": []byte("3\n")} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// TestDirectoryFindsAPickleByItsBytes: a directory sent a file to the pickle
// check only when its extension said pickle, so a pickle named notes.txt or a
// torch zip named weights.dat was never opened and File inventory passed
// (#186). A weight file in a format Socair does not parse (model.h5) that is
// really a pickle is scanned as one too. Falsification: drop the sniff from
// scanDir and no pickle row appears.
func TestDirectoryFindsAPickleByItsBytes(t *testing.T) {
	for name, data := range map[string]string{
		"notes.txt":   string(posixSystemPickle),
		"weights.dat": torchZipOf(t, posixSystemPickle),
		"model.h5":    string(posixSystemPickle),
	} {
		d, err := Scan(modelRepo(t, map[string]string{name: data}))
		if err != nil {
			t.Fatal(err)
		}
		r := row(d, "Pickle opcode scan")
		if r.Status != report.StatusFail || !strings.Contains(r.Notes, name) {
			t.Errorf("%s: pickle row %q (%s), want FAIL naming the file", name, r.Status, r.Notes)
		}
		if !strings.Contains(r.Notes, "found by its bytes") {
			t.Errorf("%s: pickle row does not say the file was found by its bytes: %s", name, r.Notes)
		}
		if d.PromotionAuthorization.Authorized {
			t.Errorf("%s: a directory with a posix.system pickle must not be authorized", name)
		}
	}
}

// TestDirectoryWithNoPickleSaysSo: a directory with no pickle has no Pickle
// opcode scan row, and a reader could not tell "none present" from "not run".
// The inventory row now says none of its files is a pickle. Falsification:
// drop the note and this fails.
func TestDirectoryWithNoPickleSaysSo(t *testing.T) {
	d, err := Scan(modelRepo(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	if r := row(d, "Pickle opcode scan"); r.Status != "" {
		t.Fatalf("pickle row %q in a directory with no pickle", r.Status)
	}
	if inv := row(d, "File inventory and payloads"); !strings.Contains(inv.Notes, "no pickle file") {
		t.Fatalf("inventory notes do not say there is no pickle: %s", inv.Notes)
	}
}
