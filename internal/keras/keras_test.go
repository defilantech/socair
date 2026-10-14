package keras_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/keras"
	"github.com/defilantech/socair/internal/keras/kerastest"
)

func refs(t *testing.T, config string) []keras.Ref {
	t.Helper()
	v, err := keras.DecodeJSON([]byte(config))
	if err != nil {
		t.Fatalf("%v: %s", err, config)
	}
	return keras.Analyze(v, "config.json")
}

func kinds(rs []keras.Ref) string {
	var out []string
	for _, r := range rs {
		out = append(out, fmt.Sprintf("%d:%s", r.Kind, r.What()))
	}
	return strings.Join(out, " ")
}

// Analyze lists what a config makes a loader run or reach, and nothing for
// a model of Keras' own classes. Each case is a falsification: drop the
// rule and its reference goes unlisted.
func TestAnalyze(t *testing.T) {
	cases := []struct {
		name, config, want string
	}{
		{"Keras 3 classes only", kerastest.Functional3(kerastest.Dense3("dense")), ""},
		{"Keras 2 classes only", kerastest.Functional2(kerastest.Dense2("dense")), ""},
		{"Keras 3 Lambda bytecode", kerastest.Functional3(kerastest.Lambda3("lam", kerastest.Bytecode)), "0:__lambda__"},
		{"Keras 2 Lambda bytecode", kerastest.Functional2(kerastest.Lambda2("lam", kerastest.Bytecode)), "0:Lambda.function"},
		{"Keras 3 generic __lambda__", `{"module": "keras.layers", "class_name": "Dense", "config": {"name": "d", "activation": {"class_name": "__lambda__", "config": {"value": ["4w==", null, null]}}}}`, "0:__lambda__"},
		{"Keras 2 Lambda by name from a module", kerastest.Functional2(`{"class_name": "Lambda", "config": {"name": "l", "function": "system", "function_type": "function", "module": "os"}}`), "3:os.system"},
		{"TorchModuleWrapper", kerastest.Functional3(`{"module": "keras.layers", "class_name": "TorchModuleWrapper", "config": {"name": "t", "module": "UEsDBA=="}}`), "1:TorchModuleWrapper"},
		{"a refused Keras API", kerastest.Functional3(`{"module": "keras.layers", "class_name": "Lambda", "config": {"name": "l", "function": {"module": "keras.utils", "class_name": "function", "config": "get_file", "registered_name": "get_file"}}}`), "2:keras.utils.get_file"},
		{"a module by name", kerastest.Functional3(kerastest.Layer3("subprocess", "run", "x")), "3:subprocess.run"},
		{"a custom module", kerastest.Functional3(kerastest.Layer3("tornet.models.keras.layers", "CoordConv2D", "c")), "3:tornet.models.keras.layers.CoordConv2D"},
		{"a script's registered class", `{"module": null, "class_name": "Scale", "config": {"name": "s"}, "registered_name": "bench>Scale"}`, "3:bench>Scale"},
		{"a Keras 2 custom class", kerastest.Functional2(kerastest.Layer2("EDSRModel", "e")), "3:EDSRModel"},
		{"KerasHub", `{"module": "keras_hub.src.models.bert.bert_backbone", "class_name": "BertBackbone", "config": {"name": "b"}, "registered_name": "keras_hub>BertBackbone"}`, "5:keras_hub.src.models.bert.bert_backbone.BertBackbone"},
		{"TFSMLayer", kerastest.Functional3(`{"module": "keras.layers", "class_name": "TFSMLayer", "config": {"name": "t", "filepath": "yamnet_model"}}`), "4:TFSMLayer"},
		{"a vocabulary path", kerastest.Functional3(`{"module": "keras.layers", "class_name": "StringLookup", "config": {"name": "s", "vocabulary": "/etc/passwd"}}`), "4:StringLookup"},
		{"a TF op by name", kerastest.Functional2(`{"class_name": "TFOpLambda", "config": {"name": "op", "function": "nn.depth_to_space"}}`), ""},
		{"a Keras op by module", kerastest.Functional3(kerastest.Layer3("keras.src.ops.numpy", "Where", "w")), ""},
		{"a tensorflow function", kerastest.Functional3(`{"module": "tensorflow.python.ops.nn_ops", "class_name": "function", "config": "gelu"}`), ""},
	}
	for _, c := range cases {
		if got := kinds(refs(t, c.config)); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

// Python's json module writes NaN and Infinity, and Keras reads them; the
// decoder must too, and must refuse what json.loads refuses.
func TestDecodeJSON(t *testing.T) {
	if v, err := keras.DecodeJSON([]byte(`{"a": NaN, "b": -Infinity, "c": "NaN"}`)); err != nil || v.(map[string]any)["c"] != "NaN" {
		t.Errorf("NaN: %v %v", v, err)
	}
	for _, bad := range []string{`{"a": 1} {}`, `{"a": }`, `{'a': 1}`} {
		if _, err := keras.DecodeJSON([]byte(bad)); err == nil {
			t.Errorf("%s decoded", bad)
		}
	}
}

func readArchive(t *testing.T, b []byte) *keras.Model {
	t.Helper()
	m, err := keras.ReadFrom(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// A .keras archive is read member by member: its config, its metadata, and
// its weights as HDF5. A member Keras does not read, a repeated name, and a
// name that leaves the extraction directory are each named.
func TestReadArchive(t *testing.T) {
	weights := kerastest.Keras3Weights().Bytes()
	m := readArchive(t, kerastest.Archive(kerastest.Functional3(kerastest.Dense3("dense")), weights,
		kerastest.Member{Name: "assets/vocab.txt", Data: []byte("a\nb\n")}))
	if m.Kind != keras.Archive || m.H5 == nil || m.KerasVersion != "3.15.1" || len(m.Configs) != 1 || m.Configs[0].Err != "" ||
		len(m.Unexpected)+len(m.Duplicates)+len(m.Escapes) != 0 {
		t.Fatalf("clean archive: %+v", m)
	}
	if !contains(m.Text, "a\nb\n") || !contains(m.Text, "Functional") || !contains(m.Text, "dense") {
		t.Errorf("text %q", m.Text)
	}
	m = readArchive(t, kerastest.Archive("{}", weights,
		kerastest.Member{Name: "payload.bin", Data: []byte("x")},
		kerastest.Member{Name: "config.json", Data: []byte("{}")},
		kerastest.Member{Name: "assets/../../.bashrc", Data: []byte("x")}))
	if len(m.Unexpected) != 1 || len(m.Duplicates) != 1 || len(m.Escapes) != 1 {
		t.Errorf("unexpected %v, duplicates %v, escapes %v", m.Unexpected, m.Duplicates, m.Escapes)
	}
	m = readArchive(t, kerastest.Zip(kerastest.Member{Name: "config.json", Data: []byte("{}")},
		kerastest.Member{Name: "model.weights.h5", Data: weights, Deflate: true}))
	if m.H5 != nil || !strings.Contains(m.H5Unread, "compressed") {
		t.Errorf("deflated weights: %v %q", m.H5 != nil, m.H5Unread)
	}
	m = readArchive(t, kerastest.Zip(kerastest.Member{Name: "config.json", Data: []byte("{}")},
		kerastest.Member{Name: "model.weights.npz", Data: []byte("PK")}))
	if m.H5 != nil || !strings.Contains(m.H5Unread, "allow_pickle") {
		t.Errorf("npz weights: %q", m.H5Unread)
	}
}

// An HDF5 model's configs are its model_config and training_config
// attributes; a weights-only file has none.
func TestReadHDF5(t *testing.T) {
	b := kerastest.FullModel(kerastest.Functional2(kerastest.Dense2("dense"))).Bytes()
	m, err := keras.ReadFrom(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	if m.Kind != keras.HDF5 || len(m.Configs) != 1 || m.Configs[0].Source != "the model_config attribute" || !strings.HasPrefix(m.Layout, "a full Keras model") {
		t.Fatalf("full model: %+v", m)
	}
	b = kerastest.WeightsOnly().Bytes()
	if m, err = keras.ReadFrom(bytes.NewReader(b), int64(len(b))); err != nil {
		t.Fatal(err)
	}
	if len(m.Configs) != 0 || !strings.HasPrefix(m.Layout, "Keras weights only") || m.KerasVersion != "2.9.0" || m.ShortElements != 3 {
		t.Errorf("weights only: %+v", m)
	}
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
