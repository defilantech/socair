package keras

import (
	_ "embed"
	"fmt"
	"sort"
	"strings"
)

// RefKind is what a reference in a config makes a loader do.
type RefKind int

const (
	// Bytecode is a Python function serialized as marshalled bytecode: a
	// field whose "<field>_type" is "lambda" (a Keras 2 or tf-keras Lambda's
	// function, output_shape, or mask, an RNN cell wrapper's dropout_fn or
	// residual_fn), a legacy Lambda whose function is a list (Keras 3 reads
	// it as code whatever its type says), or Keras 3's "__lambda__". The
	// loader turns it back into a function and calls it.
	Bytecode RefKind = iota
	// Pickle is a TorchModuleWrapper's module: a torch.save archive Keras
	// loads with torch.load(weights_only=False), which unpickles it.
	Pickle
	// Refused is a Keras API Keras itself refuses to deserialize
	// (NON_MODELING_APIS): a config that names one is using it as a gadget.
	Refused
	// Named is a class or function named by module, or a class name Keras
	// does not register: code from outside the file that a loader imports
	// or that the caller supplies. The checks grade it by what it names.
	Named
	// External is a path outside the file the loader opens: a TFSMLayer's
	// SavedModel, a lookup layer's vocabulary file.
	External
	// Addon is a class from KerasHub, KerasCV, or KerasNLP, the packages
	// Keras' deserializer imports besides its own.
	Addon
	// PathName is an object's name with a ".." component: Keras 3.14 and
	// earlier join a layer's name into the path of its assets when saving
	// or loading, so the name can leave the asset directory
	// (CVE-2026-12479).
	PathName
	// Unwalked is part of a config the analysis did not walk: nesting past
	// its depth, or references past its cap.
	Unwalked
)

// Ref is one reference in a config.
type Ref struct {
	Kind   RefKind
	Source string // the config it is in
	Where  string // where in it: the layer's name, or a JSON path
	// Module and Name are what a Named, Refused, or Addon reference names.
	Module, Name string
	Detail       string
}

// What names the reference for a report: module.name, or a name alone.
func (r Ref) What() string {
	if r.Module == "" {
		return r.Name
	}
	return r.Module + "." + r.Name
}

// The class names Keras registers itself: keras 3.15.1's and tf_keras
// 2.21.0's exported classes and the layer classes their deserializers
// register (classgen writes it from the two wheels). A legacy config
// (Keras 2, or Keras 3's .h5) names a class by its name alone, and Keras
// resolves that name from this registry or from objects the caller passes.
//
//go:embed keras-classes.txt
var classesText string

var builtinClasses = func() map[string]bool {
	m := map[string]bool{}
	for _, l := range strings.Split(classesText, "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			m[l] = true
		}
	}
	return m
}()

// markers are Keras 3's own serialization markers, not classes
// (serialization_lib.py, v3.15.1). __lambda__ is graded on its own.
var markers = map[string]bool{
	"__keras_tensor__": true, "__tensor__": true, "__numpy__": true, "__bytes__": true,
	"__typespec__": true, "__ellipsis__": true, "__slice__": true,
}

// refusedAPIs are the functions of NON_MODELING_APIS (serialization_lib.py,
// Keras v3.15.1, L34-L63), which Keras refuses to deserialize because a
// config that names one uses it as a gadget: get_file writes a file
// (CVE-2025-8747), enable_unsafe_deserialization turns safe_mode off
// (CVE-2025-9906). Keras 3.11.0 began refusing the loading APIs among them
// (LOADING_APIS); 3.15.1 refuses all of them. They are matched by name
// under any keras module.
var refusedAPIs = map[string]bool{
	"clear_session": true, "enable_unsafe_deserialization": true, "load_model": true,
	"model_from_json": true, "save_model": true, "image_dataset_from_directory": true,
	"load_img": true, "save_img": true, "text_dataset_from_directory": true,
	"deserialize_keras_object": true, "load_weights": true, "register_keras_serializable": true,
	"save_weights": true, "serialize_keras_object": true, "audio_dataset_from_directory": true,
	"get_file": true,
}

// addons are the packages Keras' deserializer imports besides keras
// (serialization_lib.py, v3.15.1, L880-L896: it imports a module of these
// packages and takes a KerasSaveable subclass from it).
var addons = map[string]bool{"keras_hub": true, "keras_cv": true, "keras_nlp": true}

// lookupLayers read a vocabulary from a file when it is given as a path.
var lookupLayers = map[string]bool{"StringLookup": true, "IntegerLookup": true, "IndexLookup": true, "TextVectorization": true}

// own reports a module Keras or TensorFlow defines: keras, tf_keras (to
// which tf-keras maps "keras"), and tensorflow.
func own(module string) bool {
	top, _, _ := strings.Cut(module, ".")
	return top == "keras" || top == "tf_keras" || top == "tensorflow"
}

// Analyze lists what a decoded config makes a loader run or reach: Python
// bytecode, a pickled module, a refused Keras API, classes and functions
// named from outside Keras and TensorFlow, paths outside the file, and
// classes from KerasHub, KerasCV, or KerasNLP. Classes Keras resolves
// itself are not listed.
func Analyze(v any, source string) []Ref {
	a := &analysis{source: source}
	a.walk(v, "", 0)
	if a.dropped > 0 {
		a.refs = append(a.refs, Ref{Kind: Unwalked, Source: source,
			Detail: fmt.Sprintf("%d more reference(s) past this reader's cap of %d", a.dropped, maxRefs)})
	}
	sort.SliceStable(a.refs, func(i, j int) bool { return a.refs[i].Kind < a.refs[j].Kind })
	return a.refs
}

type analysis struct {
	source  string
	refs    []Ref
	dropped int
}

func (a *analysis) add(k RefKind, where, module, name, detail string) {
	if len(a.refs) >= maxRefs {
		a.dropped++
		return
	}
	a.refs = append(a.refs, Ref{Kind: k, Source: a.source, Where: where, Module: module, Name: name, Detail: detail})
}

const maxRefs = 1 << 16

func (a *analysis) walk(v any, where string, depth int) {
	if depth > maxJSONDepth {
		a.add(Unwalked, where, "", "", fmt.Sprintf("the config nests deeper than the %d levels this reader walks", maxJSONDepth))
		return
	}
	switch x := v.(type) {
	case []any:
		for i, e := range x {
			a.walk(e, fmt.Sprintf("%s[%d]", where, i), depth+1)
		}
	case map[string]any:
		here := where
		if cn, ok := x["class_name"].(string); ok {
			here = a.object(x, cn, where)
		}
		for _, k := range sortedKeys(x) {
			a.walk(x[k], here+"."+k, depth+1)
		}
	}
}

// object grades one serialized Keras object and returns a label for where
// its members are.
func (a *analysis) object(x map[string]any, cn, where string) string {
	cfg, _ := x["config"].(map[string]any)
	if name, ok := cfg["name"].(string); ok && name != "" {
		where = strings.TrimSpace(fmt.Sprintf("%s %s %q", where, cn, clip(name, 80)))
	} else if where == "" {
		where = cn
	}
	module, hasModule := x["module"].(string)
	a.names(x, cfg, where)
	a.typedFunctions(cfg, cn, where)
	switch {
	case cn == "__lambda__":
		a.add(Bytecode, where, "", cn, "a Python function serialized as marshalled bytecode, which Keras turns back into a function and calls: "+
			"Keras 3 refuses it in safe mode, and ran it despite safe mode through a config that turned safe mode off before 3.11.0 (CVE-2025-9906)")
		return where
	case cn == "Lambda" && (!hasModule || own(module)):
		a.lambda(cfg, where)
	case cn == "TorchModuleWrapper" && (!hasModule || own(module)):
		if s, ok := cfg["module"].(string); ok && s != "" {
			a.add(Pickle, where, "", cn, fmt.Sprintf("a torch.save archive of %d base64 characters, which Keras unpickles with torch.load(weights_only=False) "+
				"when safe mode is off, and despite it in Keras 3.11.0 to 3.11.2 (CVE-2025-49655)", len(s)))
		}
	case cn == "TFSMLayer" && (!hasModule || own(module)):
		if p, ok := cfg["filepath"].(string); ok {
			a.add(External, where, "", cn, fmt.Sprintf("a TensorFlow SavedModel at %q, outside this file, which the layer loads with tf.saved_model.load (CVE-2026-1462)", clip(p, 120)))
		}
	case lookupLayers[cn] && (!hasModule || own(module)):
		if p, ok := cfg["vocabulary"].(string); ok && p != "" {
			a.add(External, where, "", cn, fmt.Sprintf("a vocabulary read from the path %q, outside this file (CVE-2025-12058)", clip(p, 120)))
		}
	}
	if !hasModule {
		// Keras 3 writes a module of null, and the name it registered the
		// class under, for a class defined in the caller's script.
		if reg, ok := x["registered_name"].(string); ok && strings.Contains(reg, ">") {
			cn = reg
		}
		if fn, ok := x["config"].(string); ok && cn == "function" {
			// A function with no module: Keras looks it up only among the
			// objects the caller registers or passes.
			a.add(Named, where, "", fn, "a function named without a module, which only the caller's code supplies")
			return where
		}
		a.legacy(cn, where)
		return where
	}
	name := cn
	switch cn {
	case "function":
		name, _ = x["config"].(string)
	case "__typespec__":
		name, _ = x["spec_name"].(string)
	default:
		if markers[cn] {
			return where
		}
	}
	a.named(module, name, where)
	return where
}

// legacy grades a class named without a module, as Keras 2 and Keras 3's
// legacy format write them: Keras resolves the name from its registry or
// from objects the caller passes, and imports nothing by name.
func (a *analysis) legacy(cn, where string) {
	switch {
	case markers[cn] || cn == "function":
	case strings.Contains(cn, ">"):
		pkg, _, _ := strings.Cut(cn, ">")
		if addons[pkg] {
			a.add(Addon, where, pkg, cn, "")
			return
		}
		a.add(Named, where, "", cn, "a class registered under "+pkg+", which the caller's code supplies")
	case !builtinClasses[cn]:
		a.add(Named, where, "", cn, "a class Keras does not register, which only the caller's custom_objects supply")
	}
}

// named grades a class or function named by module.
func (a *analysis) named(module, name, where string) {
	top, _, _ := strings.Cut(module, ".")
	switch {
	case own(module) && refusedAPIs[name]:
		a.add(Refused, where, module, name, "a Keras API Keras refuses to deserialize (NON_MODELING_APIS; the loading APIs since 3.11.0), because a config that names one uses it as a gadget")
	case own(module):
	case addons[top]:
		a.add(Addon, where, module, name, "")
	default:
		a.add(Named, where, module, name, "")
	}
}

// typedFunctions finds the functions a Keras 2 or tf-keras config writes
// with a type beside them: a field f with "f_type" of "lambda" is
// marshalled bytecode, which the loader turns back into a function
// (func_load) and calls. tf_keras 2.21.0 writes them for a Lambda's
// function, output_shape, and mask (layers/core/lambda_layer.py) and for
// the RNN cell wrappers' dropout_fn and residual_fn
// (layers/rnn/cell_wrappers.py), and reads them as code from an .h5 file
// whatever safe_mode says (saving/saving_api.py: safe_mode applies to the
// .keras format only). The rule reads any field so typed, under any class.
func (a *analysis) typedFunctions(cfg map[string]any, cn, where string) {
	for _, k := range sortedKeys(cfg) {
		field, ok := strings.CutSuffix(k, "_type")
		if !ok || cfg[k] != "lambda" || cfg[field] == nil {
			continue
		}
		a.add(Bytecode, where, "", cn+"."+field, "a Python function serialized as marshalled bytecode, which tf-keras runs from an .h5 file whatever safe_mode says, "+
			"as Keras 2 before 2.13 did from any file (CVE-2024-3660) and Keras 3 before 3.11.3 did from an .h5 file (CVE-2025-9905)")
	}
}

// lambda grades what typedFunctions does not: a legacy Lambda whose
// function is a list, which Keras 3's legacy loader turns into code
// whatever function_type says (legacy/saving/saving_utils.py, 3.15.1), and
// a function given by name ("function_type": "function"), which Keras looks
// up among the objects the caller registers or passes; the module the
// config names is not imported, only searched when already imported. Keras
// 3 writes "__lambda__" objects, which walk finds.
func (a *analysis) lambda(cfg map[string]any, where string) {
	if _, list := cfg["function"].([]any); list && cfg["function_type"] != "lambda" {
		a.add(Bytecode, where, "", "Lambda.function", "a Python function serialized as marshalled bytecode (a list, which Keras 3's legacy loader reads as code whatever function_type says)")
	}
	for _, f := range [][3]string{{"function", "function_type", "module"}, {"output_shape", "output_shape_type", "output_shape_module"}, {"mask", "mask_type", "mask_module"}} {
		name, ok := cfg[f[0]].(string)
		mod, _ := cfg[f[2]].(string)
		if ok && cfg[f[1]] == "function" && !own(mod) {
			a.add(Named, where+"."+f[0], "", name, "a function the Lambda names, which only the caller's custom_objects supply")
		}
	}
}

// names finds an object's name with a ".." component, read with both
// separators. Keras 3 refuses a "/" in a layer's name (ops/operation.py),
// not "..", and Keras 3.14 and earlier join the name into the path of the
// layer's assets in DiskIOStore when saving or loading (CVE-2026-12479).
func (a *analysis) names(x, cfg map[string]any, where string) {
	for _, n := range []any{cfg["name"], x["name"]} {
		s, ok := n.(string)
		if !ok {
			continue
		}
		for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == '/' || r == '\\' }) {
			if part == ".." {
				a.add(PathName, where, "", s, "a name with a \"..\" component, which Keras 3.14 and earlier join into the path of the layer's assets when saving or loading a .keras archive, "+
					"so it can leave the asset directory (CVE-2026-12479)")
				return
			}
		}
	}
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
