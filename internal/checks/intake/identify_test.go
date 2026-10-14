package intake

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/defilantech/socair/internal/gguf/gguftest"
	"github.com/defilantech/socair/internal/modeldir"
	"github.com/defilantech/socair/internal/safetensors/safetensorstest"
)

// cleanPickle is a protocol 2 pickle of an empty dict: PROTO 2, EMPTY_DICT,
// BINPUT 0, STOP.
var cleanPickle = []byte("\x80\x02}q\x00.")

var npy = []byte("\x93NUMPY\x01\x00v\x00{'descr': '<f4', 'fortran_order': False, 'shape': (1,), }" + "                                                       \n\x00\x00\x00\x00")

func zipOf(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func write(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestIdentifyReadsBytesNotNames: each format is named from its bytes, so a
// pickle named .safetensors is a pickle and safetensors named .bin is
// safetensors. Falsification: identify by extension and the renamed cases
// fail.
func TestIdentifyReadsBytesNotNames(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name   string
		body   []byte
		format string
	}{
		{"model.gguf", gguftest.BuildGGUF(gguftest.Clean()), GGUF},
		{"model.safetensors", safetensorstest.Clean(), Safetensors},
		{"weights.npy", npy, NumPy},
		{"arrays.npz", zipOf(t, map[string][]byte{"a.npy": npy, "b.npy": npy}), NumPy},
		{"model.pkl", cleanPickle, Pickle},
		{"pytorch_model.bin", zipOf(t, map[string][]byte{"archive/data.pkl": cleanPickle, "archive/data/0": {0, 0, 0, 0}}), Pickle},
		{"renamed.safetensors", cleanPickle, Pickle},
		{"renamed.bin", safetensorstest.Clean(), Safetensors},
		{"renamed.txt", gguftest.BuildGGUF(gguftest.Clean()), GGUF},
		{"model.onnx", []byte("\x08\x07\x12\x07pytorch"), ""},
		{"notes.zip", zipOf(t, map[string][]byte{"readme.txt": []byte("hello")}), ""},
		{"mixed.npz", zipOf(t, map[string][]byte{"a.npy": npy, "b.txt": []byte("x")}), ""},
		{"protocol0.pkl", []byte("(dp0\n."), ""},
	}
	for _, c := range cases {
		f := Identify(write(t, dir, c.name, c.body))
		if f.Format != c.format {
			t.Errorf("%s: format %q (%s), want %q", c.name, f.Format, f.How, c.format)
		}
		if f.How == "" || f.Path != c.name {
			t.Errorf("%s: path %q, how %q: an identification says what it read", c.name, f.Path, f.How)
		}
	}
}

// TestDirFiles: a directory's model files are its weight files, identified or
// not, and any file whose bytes are a model format whatever its name; config
// and tokenizer files are not. Falsification: skip the byte sniff on
// non-weight files and the pickle named notes.txt is missed.
func TestDirFiles(t *testing.T) {
	src := t.TempDir()
	for name, body := range map[string][]byte{
		"config.json":                    []byte(`{"model_type":"llama"}`),
		"tokenizer.json":                 []byte(`{"model":{}}`),
		"model.safetensors":              safetensorstest.Clean(),
		"training_args.bin":              cleanPickle,
		"notes.txt":                      cleanPickle,
		"onnx/model.onnx":                []byte("\x08\x07\x12\x07pytorch"),
		"lora/adapter_config.json":       []byte(`{"base_model_name_or_path":"x/y"}`),
		"lora/adapter_model.safetensors": safetensorstest.Clean(),
	} {
		write(t, src, name, body)
	}
	root, files, _, cleanup, err := modeldir.Snapshot(src, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	got := map[string]string{}
	for _, f := range DirFiles(root, files) {
		got[f.Path] = f.Format
	}
	want := map[string]string{
		"model.safetensors":              Safetensors,
		"training_args.bin":              Pickle,
		"notes.txt":                      Pickle,
		"onnx/model.onnx":                "",
		"lora/adapter_model.safetensors": Safetensors,
	}
	if len(got) != len(want) {
		t.Errorf("model files %v, want %v", got, want)
	}
	for p, f := range want {
		if g, ok := got[p]; !ok || g != f {
			t.Errorf("%s: %q (listed %v), want %q", p, g, ok, f)
		}
	}
}
