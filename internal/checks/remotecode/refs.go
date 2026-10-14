package remotecode

import (
	"fmt"
	"github.com/defilantech/socair/internal/checks/pyjson"
	"path"
	"sort"
	"strings"
)

// reference is one place a loader is told to import code: a config entry
// naming a module, or a file at a path a loader imports by convention.
type reference struct {
	pattern string // the finding's pattern
	where   string // the file, and the key in it, that names the code
	what    string // what it names, as written ("" for a file by convention)
	detail  string // how the loader reaches it
	res     resolution
	// noted: a reference whose module the directory does not contain and
	// that the loader then looks for among installed packages. It is named
	// in the notes, not judged.
	noted bool
}

const (
	maxRefsPerFile = 4096
	maxDepth       = 32
)

// loaderRefs reads the references one parsed JSON file makes. v is the
// decoded value; rel its path in the directory. all is false when the file
// holds more references than are read.
func (t *tree) loaderRefs(rel string, v any) (refs []reference, all bool) {
	var out []reference
	base := path.Base(rel)
	b := bases(rel)
	if obj, ok := v.(map[string]any); ok {
		out = append(out, t.autoMaps(rel, obj, b)...)
		out = append(out, t.customPipelines(rel, obj, b)...)
		out = append(out, t.sentenceTransformers(rel, base, obj, b)...)
		if base == "model_index.json" {
			out = append(out, t.diffusers(rel, obj)...)
		}
	}
	if list, ok := v.([]any); ok && base == "modules.json" {
		for i, m := range list {
			obj, _ := m.(map[string]any)
			if s, ok := obj["type"].(string); ok {
				out = append(out, t.stModule(fmt.Sprintf("%s: [%d] type", rel, i), s, b))
			}
		}
	}
	if len(out) > maxRefsPerFile {
		return out[:maxRefsPerFile], false
	}
	return out, true
}

// autoMaps reads every auto_map in the file, at any depth: transformers reads
// a composite model's sub-config auto_map when it builds that part
// (auto_factory.from_config), as well as the top-level one in config.json,
// tokenizer_config.json, and the processor configs, and diffusers reads one
// in a component's config.json and in modular_config.json. Each string in its
// value is a class reference ("module.Class", or "repo--module.Class"), in a
// list for a tokenizer (slow, fast) or a dict by backend for an image
// processor.
func (t *tree) autoMaps(rel string, obj map[string]any, b []string) []reference {
	var out []reference
	var walk func(prefix string, v any, depth int)
	walk = func(prefix string, v any, depth int) {
		if depth > maxDepth || len(out) > maxRefsPerFile {
			return
		}
		switch x := v.(type) {
		case map[string]any:
			for _, k := range sortedKeys(x) {
				if k == "auto_map" {
					for _, leaf := range stringLeaves("", x[k], depth) {
						where := rel + ": " + prefix + "auto_map " + leaf.key
						if prefix == "" && leaf.key != "" {
							where = rel + ": " + leaf.key
						}
						out = append(out, reference{pattern: "auto_map", where: strings.TrimSpace(where), what: leaf.s,
							detail: "imported with trust_remote_code", res: t.dynamic(leaf.s, b)})
					}
					continue
				}
				walk(prefix+k+".", x[k], depth+1)
			}
		case []any:
			for i, e := range x {
				walk(fmt.Sprintf("%s[%d].", strings.TrimSuffix(prefix, "."), i), e, depth+1)
			}
		}
	}
	walk("", obj, 0)
	return out
}

// customPipelines reads config.json's custom_pipelines: a task's "impl" is a
// class reference transformers' pipeline() imports with trust_remote_code
// (pipelines/__init__.py, v4.57.6 and v5.19.0).
func (t *tree) customPipelines(rel string, obj map[string]any, b []string) []reference {
	cp, ok := obj["custom_pipelines"].(map[string]any)
	if !ok {
		return nil
	}
	var out []reference
	for _, task := range sortedKeys(cp) {
		spec, _ := cp[task].(map[string]any)
		impl, ok := spec["impl"].(string)
		if !ok {
			continue
		}
		out = append(out, reference{pattern: "custom-pipeline", where: rel + ": custom_pipelines " + task + " impl", what: impl,
			detail: "transformers' pipeline() imports it with trust_remote_code", res: t.dynamic(impl, b)})
	}
	return out
}

// sentenceTransformers reads the class references sentence-transformers
// resolves with import_module_class or import_from_string (v6.1.0):
// a Router's types (router_config.json, or the legacy config.json with types
// and structure), a WordEmbeddings tokenizer_class, a Dense module's
// activation_function, and a CrossEncoder's activation_fn in config.json.
// modules.json is read by loaderRefs.
func (t *tree) sentenceTransformers(rel, base string, obj map[string]any, b []string) []reference {
	var out []reference
	_, hasStructure := obj["structure"].(map[string]any)
	if types, ok := obj["types"].(map[string]any); ok && (base == "router_config.json" || (base == "config.json" && hasStructure)) {
		for _, id := range sortedKeys(types) {
			if s, ok := types[id].(string); ok {
				out = append(out, t.stModule(rel+": types "+id, s, b))
			}
		}
	}
	if base == "wordembedding_config.json" {
		if s, ok := obj["tokenizer_class"].(string); ok {
			out = append(out, t.stModule(rel+": tokenizer_class", s, b))
		}
	}
	// A Dense module's config: in_features, out_features, activation_function.
	_, in := obj["in_features"]
	_, outF := obj["out_features"]
	if s, ok := obj["activation_function"].(string); ok && in && outF {
		out = append(out, t.stImport(rel+": activation_function", s, b)...)
	}
	if st, ok := obj["sentence_transformers"].(map[string]any); ok {
		if s, ok := st["activation_fn"].(string); ok {
			out = append(out, t.stImport(rel+": sentence_transformers.activation_fn", s, b)...)
		}
	}
	if s, ok := obj["sbert_ce_default_activation_function"].(string); ok {
		out = append(out, t.stImport(rel+": sbert_ce_default_activation_function", s, b)...)
	}
	return out
}

// stModule resolves a module class sentence-transformers' import_module_class
// loads: one under sentence_transformers.* is the library's own; any other is
// first looked up as repository code with transformers'
// get_class_from_dynamic_module, then imported with import_from_string from
// Python's path, which holds the directory when a process runs from it. A
// reference this directory holds no file for is noted: it comes from an
// installed package, or the load fails.
func (t *tree) stModule(where, ref string, b []string) reference {
	r := reference{pattern: "custom-module", where: where, what: ref,
		detail: "sentence-transformers imports it (with trust_remote_code from 6.0; from a local directory without it before 6.0)"}
	if !strings.HasPrefix(ref, "sentence_transformers.") {
		r.res = t.dynamic(ref, b)
	}
	imp := t.importable(ref, b)
	r.res.files = uniq(append(r.res.files, imp.files...))
	if r.res.outside == "" {
		r.res.outside = imp.outside
	}
	r.noted = true
	if strings.HasPrefix(ref, "sentence_transformers.") && len(r.res.files) == 0 && r.res.outside == "" {
		r.pattern = "" // the library's own class: not a reference to repository code
	}
	return r
}

// stImport resolves a dotted path sentence-transformers passes straight to
// import_from_string. Only a path the directory holds a file for is a
// reference; any other (torch.nn.Tanh) is an installed package's.
func (t *tree) stImport(where, ref string, b []string) []reference {
	res := t.importable(ref, b)
	if len(res.files) == 0 && res.outside == "" {
		return nil
	}
	return []reference{{pattern: "custom-module", where: where, what: ref, res: res,
		detail: "sentence-transformers imports it from Python's path"}}
}

// diffusers reads model_index.json (v0.41.0, pipelines/pipeline_loading_utils.py):
// a _class_name given as [file, class] is a custom pipeline in <file>.py, and
// a component given as [library, class] is loaded from <component>/<library>.py
// whenever that file exists, before the library of that name is imported.
func (t *tree) diffusers(rel string, obj map[string]any) []reference {
	dir := path.Dir(rel)
	if dir == "." {
		dir = ""
	}
	var out []reference
	if cn, ok := obj["_class_name"].([]any); ok && len(cn) > 0 {
		if file, ok := cn[0].(string); ok {
			out = append(out, reference{pattern: "custom-component", where: rel + ": _class_name", what: file,
				detail: "diffusers imports it as a custom pipeline with trust_remote_code", res: t.file(dir, file+".py")})
		}
	}
	for _, k := range sortedKeys(obj) {
		spec, ok := obj[k].([]any)
		if strings.HasPrefix(k, "_") || !ok || len(spec) < 2 {
			continue
		}
		lib, ok := spec[0].(string)
		if !ok {
			continue
		}
		res := t.file(dir, k+"/"+lib+".py")
		if len(res.files) == 0 && res.outside == "" {
			continue // the library of that name, not a file here
		}
		out = append(out, reference{pattern: "custom-component", where: rel + ": " + k, what: lib,
			detail: "diffusers imports it as a custom component with trust_remote_code", res: res})
	}
	return out
}

// file resolves one path relative to dir.
func (t *tree) file(dir, rel string) resolution {
	p, ok := inside(dir, rel)
	if !ok {
		return resolution{outside: rel}
	}
	return resolution{files: t.find(p)}
}

// conventions are files a loader imports by their path, with no config
// naming them.
func conventions(t *tree, paths []string) []reference {
	var out []reference
	for _, p := range paths {
		switch {
		case p == "custom_generate/generate.py" || strings.HasSuffix(p, "/custom_generate/generate.py"):
			// transformers loads it in from_pretrained (generation/utils.py
			// load_custom_generate; v4.57.6 runs it from a local directory
			// without trust_remote_code, v5.19.0 asks for it).
			out = append(out, reference{pattern: "custom-generate", where: p,
				detail: "transformers imports it by this path when it loads the model", res: resolution{files: []string{p}}})
		case p == "handler.py" || p == "pipeline.py":
			// huggingface-inference-toolkit 0.5.5, utils.py
			// check_and_register_custom_pipeline_from_directory: handler.py,
			// else the legacy pipeline.py, with the directory first on
			// Python's path and no trust_remote_code.
			out = append(out, reference{pattern: "inference-handler", where: p,
				detail: "the Hugging Face inference toolkit imports it by this path, without trust_remote_code", res: resolution{files: []string{p}}})
		case p == "code/inference.py":
			// sagemaker-inference 1.10.1 environment.py (DEFAULT_MODULE_NAME,
			// code_dir), used by sagemaker-huggingface-inference-toolkit 2.7.0.
			out = append(out, reference{pattern: "inference-handler", where: p,
				detail: "the SageMaker inference toolkit imports it by this path, without trust_remote_code", res: resolution{files: []string{p}}})
		}
	}
	return out
}

type leaf struct{ key, s string }

// stringLeaves lists the strings in v with their key path, bounded.
func stringLeaves(key string, v any, depth int) []leaf {
	if depth > maxDepth {
		return nil
	}
	switch x := v.(type) {
	case string:
		return []leaf{{key, x}}
	case []any:
		var out []leaf
		for i, e := range x {
			out = append(out, stringLeaves(fmt.Sprintf("%s[%d]", key, i), e, depth+1)...)
		}
		return out
	case map[string]any:
		var out []leaf
		for _, k := range sortedKeys(x) {
			kk := k
			if key != "" {
				kk = key + "." + k
			}
			out = append(out, stringLeaves(kk, x[k], depth+1)...)
		}
		return out
	}
	return nil
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// decodeJSON decodes a config as the loaders' Python json module does: it
// refuses trailing data, a repeated key keeps its last value, and the
// constants NaN, Infinity, and -Infinity, which Python accepts and writes
// (Nemotron-H's config.json holds Infinity), are read as values.
func decodeJSON(raw []byte) (any, error) {
	var v any
	if err := pyjson.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return v, nil
}
