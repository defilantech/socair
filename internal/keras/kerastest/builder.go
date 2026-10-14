// Package kerastest builds Keras models for tests: the HDF5 files Keras 2,
// tf.keras, and Hugging Face transformers write, and .keras archives, as
// internal/hdf5/hdf5test files and zip bytes. Configs are JSON strings in
// the shapes Keras writes; the helpers below give the layers the rules
// read.
//
// Fixtures are generated, not committed. Nothing here is ever loaded by
// Keras or run.
package kerastest

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/defilantech/socair/internal/hdf5/hdf5test"
)

// Bytecode is a marshalled Python code object, base64-encoded as Keras'
// func_dump writes it (marshal.dumps, then codecs base64 with a newline
// every 76 characters), for the function
//
//	lambda x: print('echo socair-benchmark') or x
//
// compiled by CPython 3.14.7 with the file name "<socair-benchmark>". It
// only prints the benchmark payload and returns its input; no test runs it.
const Bytecode = "4wEAAAAAAAAAAAAAAAMAAAADAAAA8ywAAACAAFwBAAAAAAAAAABSADQBAAAAAAAAOwEnAAAAAAAA\n" +
	"AGcDAAAcAB8AVAAjACkBehVlY2hvIHNvY2Fpci1iZW5jaG1hcmspAdoFcHJpbnQpAdoBeHMBAAAA\n" +
	"JtoSPHNvY2Fpci1iZW5jaG1hcms+2gg8bGFtYmRhPnIFAAAAAQAAAHMVAAAAgACMJdAQJ9MKKNcK\n" +
	"LdAKLahB0Aot8wAAAAA=\n"

// WeightsOnly is a weights-only HDF5 file as Keras 2's save_weights writes
// it, and so Hugging Face transformers' tf_model.h5: root attributes
// layer_names, backend, and keras_version, and one group per layer with
// its weight_names and datasets.
func WeightsOnly() *hdf5test.File {
	return &hdf5test.File{Root: &hdf5test.Group{
		Attrs: []hdf5test.Attr{
			{Name: "layer_names", Strings: []string{"bert"}, Array: true},
			{Name: "backend", Strings: []string{"tensorflow"}},
			{Name: "keras_version", Strings: []string{"2.9.0"}},
		},
		Groups: map[string]*hdf5test.Group{
			"bert": {
				Attrs: []hdf5test.Attr{{Name: "weight_names", Array: true,
					Strings: []string{"tf_bert_model/bert/embeddings/weight:0", "tf_bert_model/bert/pooler/dense/bias:0"}}},
				Groups: map[string]*hdf5test.Group{"tf_bert_model": {Groups: map[string]*hdf5test.Group{"bert": {Groups: map[string]*hdf5test.Group{
					"embeddings": {Datasets: map[string]*hdf5test.Dataset{"weight:0": hdf5test.Weights(32, 8)}},
					"pooler":     {Groups: map[string]*hdf5test.Group{"dense": {Datasets: map[string]*hdf5test.Dataset{"bias:0": hdf5test.Weights(8)}}}},
				}}}}},
			},
			"top_level_model_weights": {Attrs: []hdf5test.Attr{{Name: "weight_names", IsFloat: true}}},
		},
	}}
}

// FullModel is a whole model as Keras 2's model.save("x.h5") writes it:
// the model_config attribute (JSON), keras_version, backend, and the
// model_weights group.
func FullModel(config string) *hdf5test.File {
	return &hdf5test.File{Root: &hdf5test.Group{
		Attrs: []hdf5test.Attr{
			{Name: "backend", Strings: []string{"tensorflow"}},
			{Name: "keras_version", Strings: []string{"2.4.0"}},
			{Name: "model_config", Strings: []string{config}},
		},
		Groups: map[string]*hdf5test.Group{"model_weights": {
			Attrs: []hdf5test.Attr{
				{Name: "layer_names", Strings: []string{"input_1", "dense"}, Array: true},
				{Name: "backend", Strings: []string{"tensorflow"}},
				{Name: "keras_version", Strings: []string{"2.4.0"}},
			},
			Groups: map[string]*hdf5test.Group{
				"dense": {
					Attrs:  []hdf5test.Attr{{Name: "weight_names", Strings: []string{"dense/kernel:0", "dense/bias:0"}, Array: true}},
					Groups: map[string]*hdf5test.Group{"dense": {Datasets: map[string]*hdf5test.Dataset{"kernel:0": hdf5test.Weights(4, 3), "bias:0": hdf5test.Weights(3)}}},
				},
				"input_1": {Attrs: []hdf5test.Attr{{Name: "weight_names", IsFloat: true}}},
			},
		}},
	}}
}

// Keras3Weights is the model.weights.h5 a .keras archive holds:
// layers/<name>/vars with datasets "0", "1", ..., and a name attribute.
func Keras3Weights() *hdf5test.File {
	return &hdf5test.File{Root: &hdf5test.Group{
		Groups: map[string]*hdf5test.Group{
			"layers": {Groups: map[string]*hdf5test.Group{"dense": {Groups: map[string]*hdf5test.Group{"vars": {
				Attrs:    []hdf5test.Attr{{Name: "name", Strings: []string{"dense"}}},
				Datasets: map[string]*hdf5test.Dataset{"0": hdf5test.Weights(4, 3), "1": hdf5test.Weights(3)},
			}}}}},
			"vars": {},
		},
	}}
}

// Member is an archive member.
type Member struct {
	Name string
	Data []byte
	// Deflate compresses it; Keras writes every member stored.
	Deflate bool
}

// Archive writes a .keras archive: metadata.json, config.json, and
// model.weights.h5 as Keras writes them, stored, then extra members.
func Archive(config string, weights []byte, extra ...Member) []byte {
	members := []Member{
		{Name: "metadata.json", Data: []byte(`{"keras_version": "3.15.1", "date_saved": "2026-10-14@12:00:00"}`)},
		{Name: "config.json", Data: []byte(config)},
		{Name: "model.weights.h5", Data: weights},
	}
	return Zip(append(members, extra...)...)
}

// Zip writes members into a zip, in order.
func Zip(members ...Member) []byte {
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for _, m := range members {
		h := &zip.FileHeader{Name: m.Name, Method: zip.Store}
		if m.Deflate {
			h.Method = zip.Deflate
		}
		w, err := zw.CreateHeader(h)
		if err != nil {
			panic(err)
		}
		_, _ = w.Write(m.Data)
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
	return b.Bytes()
}

// Keras 3 layers, as config.json writes them.

// Dense3 is a Keras 3 Dense layer.
func Dense3(name string) string {
	return fmt.Sprintf(`{"module": "keras.layers", "class_name": "Dense", "config": {"name": %q, "trainable": true, `+
		`"dtype": {"module": "keras", "class_name": "DTypePolicy", "config": {"name": "float32"}, "registered_name": null}, "units": 3, "activation": "linear", `+
		`"kernel_initializer": {"module": "keras.initializers", "class_name": "GlorotUniform", "config": {"seed": null}, "registered_name": null}}, `+
		`"registered_name": null, "build_config": {"input_shape": [null, 4]}, "name": %q, "inbound_nodes": []}`, name, name)
}

// Lambda3 is a Keras 3 Lambda layer whose function is code, as
// _serialize_function_to_config writes it.
func Lambda3(name, code string) string {
	return fmt.Sprintf(`{"module": "keras.layers", "class_name": "Lambda", "config": {"name": %q, "trainable": true, `+
		`"function": {"class_name": "__lambda__", "config": {"code": %s, "defaults": null, "closure": null}}, "arguments": {}}, `+
		`"registered_name": null, "name": %q, "inbound_nodes": []}`, name, jsonString(code), name)
}

// Layer3 is a Keras 3 layer of any class and module.
func Layer3(module, class, name string) string {
	return fmt.Sprintf(`{"module": %q, "class_name": %q, "config": {"name": %q}, "registered_name": null, "name": %q, "inbound_nodes": []}`,
		module, class, name, name)
}

// Functional3 is a Keras 3 functional model of these layers.
func Functional3(layers ...string) string {
	return `{"module": "keras.src.models.functional", "class_name": "Functional", "config": {"name": "m", "trainable": true, "layers": [` +
		`{"module": "keras.layers", "class_name": "InputLayer", "config": {"batch_shape": [null, 4], "dtype": "float32", "name": "input_layer"}, "registered_name": null, "name": "input_layer", "inbound_nodes": []}, ` +
		strings.Join(layers, ", ") + `], "input_layers": ["input_layer", 0, 0], "output_layers": ["dense", 0, 0]}, "registered_name": "Functional", "build_config": {"input_shape": null}, "compile_config": {}}`
}

// Keras 2 layers, as model_config writes them.

// Dense2 is a Keras 2 Dense layer.
func Dense2(name string) string {
	return fmt.Sprintf(`{"class_name": "Dense", "config": {"name": %q, "trainable": true, "dtype": "float32", "units": 3, "activation": "linear", `+
		`"kernel_initializer": {"class_name": "GlorotUniform", "config": {"seed": null}}}, "name": %q, "inbound_nodes": [[["input_1", 0, 0, {}]]]}`, name, name)
}

// Lambda2 is a Keras 2 Lambda layer holding code, as its get_config writes
// it: function is func_dump's (code, defaults, closure) and function_type
// "lambda".
func Lambda2(name, code string) string {
	return fmt.Sprintf(`{"class_name": "Lambda", "config": {"name": %q, "trainable": true, "dtype": "float32", `+
		`"function": [%s, null, null], "function_type": "lambda", "module": "__main__", "output_shape": null, "output_shape_type": "raw", `+
		`"output_shape_module": null, "arguments": {}}, "name": %q, "inbound_nodes": [[["dense", 0, 0, {}]]]}`, name, jsonString(code), name)
}

// Layer2 is a Keras 2 layer of any class.
func Layer2(class, name string) string {
	return fmt.Sprintf(`{"class_name": %q, "config": {"name": %q}, "name": %q, "inbound_nodes": []}`, class, name, name)
}

// Functional2 is a Keras 2 functional model of these layers.
func Functional2(layers ...string) string {
	return `{"class_name": "Functional", "config": {"name": "model", "layers": [` +
		`{"class_name": "InputLayer", "config": {"batch_input_shape": [null, 4], "dtype": "float32", "sparse": false, "ragged": false, "name": "input_1"}, "name": "input_1", "inbound_nodes": []}, ` +
		strings.Join(layers, ", ") + `], "input_layers": [["input_1", 0, 0]], "output_layers": [["dense", 0, 0]]}, "keras_version": "2.4.0", "backend": "tensorflow"}`
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
