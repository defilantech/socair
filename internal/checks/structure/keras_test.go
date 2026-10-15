package structure

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/hdf5/hdf5test"
	"github.com/defilantech/socair/internal/keras"
	"github.com/defilantech/socair/internal/keras/kerastest"
)

func kerasFile(t *testing.T, name string, b []byte) checks.Result {
	t.Helper()
	return Validate(writeFixture(t, name, b))
}

func h5(t *testing.T, f *hdf5test.File) checks.Result {
	t.Helper()
	return kerasFile(t, "model.h5", f.Bytes())
}

func archive(t *testing.T, config string, extra ...kerastest.Member) checks.Result {
	t.Helper()
	return kerasFile(t, "model.keras", kerastest.Archive(config, kerastest.Keras3Weights().Bytes(), extra...))
}

// A weights-only HDF5 file, as Hugging Face transformers writes
// tf_model.h5, PASSes when its layout reads cleanly, and says it holds no
// config, so no code was found. Before #269 it was NOT_TESTED.
func TestKerasWeightsOnlyPasses(t *testing.T) {
	r := h5(t, kerastest.WeightsOnly())
	if r.Status != checks.Pass || !strings.Contains(r.Notes, "No model config is present") || !strings.Contains(r.Notes, "no code was found") ||
		!strings.Contains(r.Notes, "Keras weights only") {
		t.Fatalf("%s: %s", r.Status, r.Notes)
	}
	for _, c := range []string{kerastest.Functional2(kerastest.Dense2("dense"))} {
		if r := h5(t, kerastest.FullModel(c)); r.Status != checks.Pass || !strings.Contains(r.Notes, "a full Keras model") {
			t.Errorf("full model: %s: %s", r.Status, r.Notes)
		}
	}
	if r := archive(t, kerastest.Functional3(kerastest.Dense3("dense"))); r.Status != checks.Pass || !strings.Contains(r.Notes, ".keras archive") {
		t.Errorf("archive: %s: %s", r.Status, r.Notes)
	}
}

// Each config rule, falsified: neuter it and its case grades otherwise.
func TestKerasConfigRules(t *testing.T) {
	torch := `{"module": "keras.layers", "class_name": "TorchModuleWrapper", "config": {"name": "t", "module": "UEsDBBQAAAAIAA=="}}`
	getFile := `{"module": "keras.layers", "class_name": "Lambda", "config": {"name": "l", "function": {"module": "keras.utils", "class_name": "function", "config": "get_file"}}}`
	cases := []struct {
		name    string
		r       checks.Result
		status  checks.Status
		pattern string
		note    string
	}{
		{"Keras 2 Lambda bytecode in an .h5", h5(t, kerastest.FullModel(kerastest.Functional2(kerastest.Lambda2("lam", kerastest.Bytecode)))), checks.Fail, "keras-lambda", "CVE-2024-3660"},
		{"Keras 3 Lambda bytecode in a .keras", archive(t, kerastest.Functional3(kerastest.Lambda3("lam", kerastest.Bytecode))), checks.Fail, "keras-lambda", "marshalled bytecode"},
		{"a pickled torch module", archive(t, kerastest.Functional3(torch)), checks.Fail, "keras-pickle", "torch.load"},
		{"a refused Keras API", archive(t, kerastest.Functional3(getFile)), checks.Fail, "keras-dangerous-reference", "keras.utils.get_file"},
		{"a dangerous module by name", archive(t, kerastest.Functional3(kerastest.Layer3("subprocess", "run", "x"))), checks.Fail, "keras-dangerous-reference", "CVE-2025-1550"},
		{"a custom module", archive(t, kerastest.Functional3(kerastest.Layer3("tornet.models.keras.layers", "CoordConv2D", "c"))), checks.NotTested, "", "tornet.models.keras.layers.CoordConv2D"},
		{"a Keras 2 custom class", h5(t, kerastest.FullModel(kerastest.Functional2(kerastest.Layer2("EDSRModel", "e")))), checks.NotTested, "", "EDSRModel"},
		{"a SavedModel path", archive(t, kerastest.Functional3(`{"module": "keras.layers", "class_name": "TFSMLayer", "config": {"name": "t", "filepath": "yamnet_model"}}`)), checks.NotTested, "", "yamnet_model"},
		{"a KerasHub class", archive(t, kerastest.Functional3(kerastest.Layer3("keras_hub.src.models.bert.bert_backbone", "BertBackbone", "b"))), checks.Pass, "", "KerasHub"},
		{"a config that is not JSON", h5(t, kerastest.FullModel(`{"class_name": `)), checks.NotTested, "", "could not be read"},
		{"a config with Python's constants", h5(t, kerastest.FullModel(`{"class_name": "Functional", "config": {"name": "model", "layers": [{"class_name": "Dense", "config": {"name": "d", "bias": NaN, "max": Infinity}, "name": "d", "inbound_nodes": []}], "input_layers": [], "output_layers": []}, "keras_version": "2.4.0", "backend": "tensorflow"}`)), checks.Pass, "", "a full Keras model"},
		{"an RNN cell wrapper's bytecode", h5(t, kerastest.FullModel(kerastest.Functional2(`{"class_name": "RNN", "config": {"name": "r", "cell": {"class_name": "ResidualWrapper", "config": {"name": "w", "residual_fn": ["4w==", null, null], "residual_fn_type": "lambda"}}}}`))), checks.Fail, "keras-lambda", "ResidualWrapper.residual_fn"},
		{"a Lambda function named, not imported", h5(t, kerastest.FullModel(kerastest.Functional2(`{"class_name": "Lambda", "config": {"name": "l", "function": "system", "function_type": "function", "module": "os"}}`))), checks.NotTested, "", "system"},
		{"a layer name that leaves its directory", archive(t, kerastest.Functional3(kerastest.Layer3("keras.layers", "Dense", ".."))), checks.Lead, "keras-name-path", "CVE-2026-12479"},
		{"a config past the walk's depth", archive(t, strings.Repeat(`{"module": "keras.layers", "class_name": "Dense", "config": {"name": "d", "x": `, 300)+"0"+strings.Repeat("}}", 300)),
			checks.NotTested, "", "did not walk"},
	}
	for _, c := range cases {
		if c.r.Status != c.status || c.pattern != "" && !hasPattern(c.r, c.pattern) || !strings.Contains(c.r.Notes+fmtFindings(c.r), c.note) {
			t.Errorf("%s: %s %v: %s", c.name, c.r.Status, c.r.Findings, c.r.Notes)
		}
	}
}

func fmtFindings(r checks.Result) string {
	var b strings.Builder
	for _, f := range r.Findings {
		b.WriteString(f.Pattern + " " + f.Span + " " + f.Detail + "\n")
	}
	return b.String()
}

// The HDF5 storage rules, through the structure row.
func TestKerasStorageRules(t *testing.T) {
	u := func(v uint64) *uint64 { return &v }
	weights := func(d *hdf5test.Dataset) *hdf5test.File {
		f := kerastest.WeightsOnly()
		f.Root.Groups["bert"].Datasets = map[string]*hdf5test.Dataset{"extra": d}
		return f
	}
	trailing := kerastest.WeightsOnly()
	trailing.Trailing = []byte("#!/bin/sh\necho socair-benchmark\n")
	truncated := kerastest.WeightsOnly()
	truncated.EOFDelta = 1 << 20
	userBlock := kerastest.WeightsOnly()
	userBlock.UserBlock = 512
	external := kerastest.WeightsOnly()
	external.Root.External = map[string][2]string{"bert2": {"/data/other.h5", "/bert"}}
	soft := kerastest.WeightsOnly()
	soft.Root.Soft = map[string]string{"bert2": "/bert"}
	cases := []struct {
		name    string
		f       *hdf5test.File
		status  checks.Status
		pattern string
		note    string
	}{
		{"storage past the end", weights(&hdf5test.Dataset{Type: hdf5test.Float32, Dims: []uint64{1 << 20}, Data: make([]byte, 16), StoredSize: u(4 << 20)}), checks.Fail, "tensor-layout", "the HDF5 library refuses to read it"},
		{"recorded storage past the end", weights(&hdf5test.Dataset{Type: hdf5test.Float32, Dims: []uint64{4}, StoredSize: u(1 << 20)}), checks.Fail, "tensor-layout", "storage recorded as"},
		{"a stored size the shape does not need", weights(&hdf5test.Dataset{Type: hdf5test.Float32, Dims: []uint64{4}, Data: make([]byte, 4096), StoredSize: u(4096)}), checks.Fail, "tensor-size", "need 16"},
		{"bytes after the HDF5 data", trailing, checks.Fail, "tensor-layout", "after the end of the HDF5 data"},
		{"a truncated file", truncated, checks.NotTested, "", "truncated"},
		{"a user block", userBlock, checks.NotTested, "", "user block of 512 bytes"},
		{"an external link", external, checks.Fail, "external-data-escape", `"/data/other.h5:/bert"`},
		{"external storage", weights(&hdf5test.Dataset{Type: hdf5test.Float32, Dims: []uint64{4}, External: "/etc/passwd"}), checks.Fail, "external-data-escape", `"/etc/passwd"`},
		{"a soft link", soft, checks.Lead, "hdf5-soft-link", `"/bert"`},
		{"a virtual dataset", weights(&hdf5test.Dataset{Type: hdf5test.Float32, Dims: []uint64{4}, Virtual: true}), checks.Lead, "hdf5-virtual-dataset", "CVE-2026-12480"},
		{"a filtered dataset", weights(&hdf5test.Dataset{Type: hdf5test.Float32, Dims: []uint64{10}, Chunk: []uint64{5}, Deflate: true}), checks.NotTested, "", "deflate"},
		{"chunks never written", weights(&hdf5test.Dataset{Type: hdf5test.Float32, Dims: []uint64{10}, Chunk: []uint64{5}, Missing: 1}), checks.NotTested, "", "1 of its 2 chunks"},
	}
	for _, c := range cases {
		r := h5(t, c.f)
		if r.Status != c.status || c.pattern != "" && !hasPattern(r, c.pattern) || !strings.Contains(r.Notes+fmtFindings(r), c.note) {
			t.Errorf("%s: %s %v: %s", c.name, r.Status, r.Findings, r.Notes)
		}
	}
}

// The archive rules: a member Keras does not read, a repeated name, and a
// name that would leave the extraction directory are each a LEAD.
func TestKerasArchiveRules(t *testing.T) {
	config := kerastest.Functional3(kerastest.Dense3("dense"))
	cases := []struct {
		name    string
		extra   []kerastest.Member
		status  checks.Status
		pattern string
	}{
		{"a member Keras does not read", []kerastest.Member{{Name: "payload.bin", Data: []byte("x")}}, checks.Lead, "keras-archive-entry"},
		{"a repeated member", []kerastest.Member{{Name: "config.json", Data: []byte("{}")}}, checks.Lead, "keras-archive-entry"},
		{"a member that escapes", []kerastest.Member{{Name: "assets/../../../.bashrc", Data: []byte("x")}}, checks.Lead, "archive-path-escape"},
		{"a rooted member", []kerastest.Member{{Name: "/etc/cron.d/x", Data: []byte("x")}}, checks.Lead, "archive-path-escape"},
		{"an asset", []kerastest.Member{{Name: "assets/vocabulary.txt", Data: []byte("a\nb\n")}}, checks.Pass, ""},
	}
	for _, c := range cases {
		r := archive(t, config, c.extra...)
		if r.Status != c.status || c.pattern != "" && !hasPattern(r, c.pattern) {
			t.Errorf("%s: %s %v: %s", c.name, r.Status, r.Findings, r.Notes)
		}
	}
}

// A model directory's .keras archive is read entry by entry, and File
// inventory hears of it; a member left unread is named.
func TestKerasArchiveRead(t *testing.T) {
	root := t.TempDir()
	b := kerastest.Archive(kerastest.Functional3(kerastest.Dense3("dense")), kerastest.Keras3Weights().Bytes())
	if err := os.WriteFile(filepath.Join(root, "model.keras"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	r, a := ValidateKeras(root, "model.keras")
	if r.Status != checks.Pass || a == nil || len(a.Unread) != 0 || a.By != "Format and structure" {
		t.Fatalf("%s %+v: %s", r.Status, a, r.Notes)
	}
	b = kerastest.Archive(kerastest.Functional3(kerastest.Dense3("dense")), kerastest.Keras3Weights().Bytes(), kerastest.Member{Name: "x.pkl", Data: []byte("\x80\x02.")})
	if err := os.WriteFile(filepath.Join(root, "model.keras"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, a = ValidateKeras(root, "model.keras"); a == nil || len(a.Unread) != 1 {
		t.Errorf("an unread member: %+v", a)
	}
}

// A KerasHub preset's JSON configs are graded by the config rules alone.
func TestKerasConfigFile(t *testing.T) {
	v, err := keras.DecodeJSON([]byte(`{"module": "keras_hub.src.models.bert.bert_backbone", "class_name": "BertBackbone", "config": {"name": "b"}, "registered_name": "keras_hub>BertBackbone"}`))
	if err != nil || !IsKerasObject(v) {
		t.Fatal(err)
	}
	if r := KerasConfig("config.json", v); r.Status != checks.Pass || !strings.Contains(r.Notes, "KerasHub") {
		t.Errorf("%s: %s", r.Status, r.Notes)
	}
	v, _ = keras.DecodeJSON([]byte(kerastest.Functional3(kerastest.Lambda3("lam", kerastest.Bytecode))))
	if r := KerasConfig("config.json", v); r.Status != checks.Fail || !hasPattern(r, "keras-lambda") {
		t.Errorf("%s: %s", r.Status, r.Notes)
	}
	if v, _ := keras.DecodeJSON([]byte(`{"version": "1.0", "model": {}}`)); IsKerasObject(v) {
		t.Error("an HF tokenizer.json is a Keras object")
	}
}
