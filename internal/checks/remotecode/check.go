// Package remotecode finds the Python a model loader would import from a
// model directory.
//
// A loader imports repository code when a config names it or when a file
// sits at a path it imports by convention:
//
//   - auto_map, in any JSON config at any depth (transformers' Auto classes,
//     diffusers' AutoModel and modular blocks), and config.json's
//     custom_pipelines (transformers' pipeline()): "module.Class" names
//     module.py, and "repo--module.Class" names code in another repository;
//   - sentence-transformers' module classes outside sentence_transformers.*
//     (modules.json, a Router's types, a WordEmbeddings tokenizer_class) and
//     the dotted paths it imports (a Dense activation_function, a
//     CrossEncoder activation_fn);
//   - diffusers' model_index.json: a custom pipeline in _class_name, and a
//     component whose <component>/<library>.py exists;
//   - custom_generate/generate.py (transformers), and handler.py, pipeline.py,
//     and code/inference.py at the root (the Hugging Face and SageMaker
//     inference toolkits, which import them without trust_remote_code).
//
// Each such file, and every repository file it imports, transitively (as
// transformers' get_relative_import_files does, and absolute imports of a
// file the directory holds as well), is code no weight-level check examines.
// That is not proof of malice (many architectures ship this way), so it is a
// LEAD that names every entry and file, cleared only by review. So is a
// reference to code in another repository, or to a path outside the
// directory, and an auto_map, custom_pipelines, or diffusers reference to a
// module the directory does not contain: code this artifact does not carry,
// which transformers and diffusers look for only in a repository. A
// sentence-transformers class the directory holds no file for is named and
// not judged, because the loader then imports it from an installed package
// or fails.
//
// A config can also make a loader run code with no trust_remote_code at all,
// and that is judged as the field itself:
//
//   - an attention field of config.json (_attn_implementation_internal, or
//     _attn_implementation, whose setter writes it), at any depth, naming a
//     Hub kernel repository: transformers 4.56.0 to 5.2.x download and run
//     the kernel in a plain from_pretrained once the kernels package is
//     installed (CVE-2026-4372). save_pretrained never writes either field,
//     so a kernel outside kernels-community there is a FAIL; a
//     kernels-community kernel, which 5.3.0 and later still load, is a LEAD;
//   - trust_remote_code set in config.json: transformers' LightGlue read it
//     before 5.5.0 and passed it to the nested AutoConfig.from_pretrained
//     that loads its keypoint detector, importing another repository's code
//     with trust_remote_code=False (CVE-2026-5241). Other loaders ignore it,
//     so it is a LEAD.
//
// Any other Python or script file is listed in the notes as present and
// imported by none of these, not judged: Socair does not say a loader runs a
// file no loader names. A directory with no reference PASSes. A config that
// does not parse is NOT_TESTED: it might carry a reference this check could
// not see. Configs are read as Python's json module reads them (NaN and
// Infinity included), and a path is matched without regard to case.
//
// Out of scope: loaders that import a file their caller names (SpeechBrain's
// foreign_class), configs that are code by design (HyperPyYAML, Hydra's
// _target_), a public attn_implementation (from_dict replaces a top-level one
// with the caller's own; one in a sub-config is not read here), PEFT's
// auto_mapping (an installed module), compiled or bytecode modules, and an
// environment variable that renames a handler.
package remotecode

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/modeldir"
)

const (
	resultName = "Remote code"
	looksFor   = "Python a loader would import: modules a config names (auto_map, custom_pipelines, sentence-transformers and diffusers modules), " +
		"files loaders import by their path, the repository files those import, " +
		"and config.json fields that run code without trust_remote_code (a Hub kernel as the attention implementation, trust_remote_code itself)"
)

const (
	// maxConfig bounds a config read into memory.
	maxConfig = 16 << 20
	// maxSource bounds a Python file read for its imports.
	maxSource = 8 << 20
	// maxListed bounds a list of files in the notes.
	maxListed = 20
	// maxFindings bounds the references listed one by one.
	maxFindings = 64
	// maxText bounds a config key or value quoted in the evidence.
	maxText = 200
)

// scriptExt are files listed in the notes when no loader imports them.
var scriptExt = map[string]bool{".py": true, ".pyc": true, ".pyw": true, ".ipynb": true, ".sh": true}

// Inspect reads the files of a model directory snapshot rooted at root.
func Inspect(root string, files []modeldir.File) checks.Result {
	r := checks.Result{Name: resultName, LooksFor: looksFor}
	paths := make([]string, 0, len(files))
	for _, f := range files {
		paths = append(paths, f.Path)
	}
	t := newTree(paths)

	var refs []reference
	var fields []override
	var unread []string
	configs := 0
	for _, f := range files {
		base := path.Base(f.Path)
		if path.Ext(f.Path) != ".json" {
			continue
		}
		if f.Size > maxConfig {
			if base == "modules.json" || strings.HasSuffix(base, "config.json") || base == "model_index.json" {
				unread = append(unread, f.Path+": larger than the 16 MiB a config is read to")
			}
			continue
		}
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(f.Path)))
		if err != nil {
			unread = append(unread, f.Path+": not readable")
			continue
		}
		raw = bytes.TrimSpace(raw)
		isList := len(raw) > 0 && raw[0] == '['
		if len(raw) == 0 || (raw[0] != '{' && !(isList && base == "modules.json")) {
			continue // not a config object (a vocabulary, a merges table, a list)
		}
		v, err := decodeJSON(raw)
		if err != nil {
			unread = append(unread, f.Path+": not valid JSON")
			continue
		}
		configs++
		if obj, ok := v.(map[string]any); ok {
			fields = append(fields, overrides(f.Path, obj)...)
		}
		got, all := t.loaderRefs(f.Path, v)
		if !all {
			unread = append(unread, fmt.Sprintf("%s: more than %d references, the rest not read", f.Path, maxRefsPerFile))
		}
		for _, ref := range got {
			if ref.pattern != "" {
				refs = append(refs, ref)
			}
		}
	}
	refs = append(refs, conventions(t, paths)...)

	// Entry files and what each reference names.
	var entries []string
	var leads, noted []reference
	for _, ref := range refs {
		switch {
		case len(ref.res.files) > 0:
			entries = append(entries, ref.res.files...)
			leads = append(leads, ref)
		case ref.res.outside != "":
			leads = append(leads, ref)
		case ref.noted:
			noted = append(noted, ref)
		default:
			leads = append(leads, ref) // names a module the directory does not contain
		}
	}
	reached, importedBy, unreadSrc := follow(root, t, uniq(entries))

	failed := false
	for i, o := range fields {
		if i == maxFindings {
			r.Findings = append(r.Findings, checks.Finding{Pattern: o.pattern, Span: fmt.Sprintf("and %d more field(s)", len(fields)-i),
				Detail: "not listed one by one"})
			break
		}
		r.Findings = append(r.Findings, checks.Finding{Pattern: o.pattern, Span: clip(o.where) + " -> " + clip(o.what), Detail: o.detail})
	}
	for _, o := range fields {
		failed = failed || o.fail
	}
	for i, ref := range leads {
		if i == maxFindings {
			r.Findings = append(r.Findings, checks.Finding{Pattern: ref.pattern, Span: fmt.Sprintf("and %d more reference(s)", len(leads)-i),
				Detail: "not listed one by one"})
			break
		}
		r.Findings = append(r.Findings, finding(ref))
	}
	var imported []string
	for _, p := range reached {
		if by, ok := importedBy[p]; ok {
			imported = append(imported, p+" (from "+by+")")
		}
	}
	if len(imported) > 0 {
		r.Findings = append(r.Findings, checks.Finding{Pattern: "imported-code", Span: list(imported),
			Detail: "repository files the code above imports"})
	}

	var stray []string
	for _, p := range paths {
		if scriptExt[strings.ToLower(path.Ext(p))] && !contains(reached, p) {
			stray = append(stray, p)
		}
	}

	var notes []string
	switch {
	case len(r.Findings) > 0:
		r.Status = checks.Lead
		if failed {
			r.Status = checks.Fail
		}
		if len(fields) > 0 {
			notes = append(notes, fieldNote(fields, failed))
		}
		if len(leads) > 0 || len(reached) > 0 {
			notes = append(notes, leadNote(leads, reached))
		}
		if len(unreadSrc) > 0 {
			notes = append(notes, "could not read for imports, so files they import may be unnamed: "+list(unreadSrc))
		}
		if len(unread) > 0 {
			notes = append(notes, "could not read every config, so a reference may be unseen: "+strings.Join(unread, "; "))
		}
	case len(unread) > 0:
		r.Status = checks.NotTested
		notes = append(notes, "could not read every config, so a reference to code may be unseen: "+strings.Join(unread, "; "))
	default:
		r.Status = checks.Pass
		notes = append(notes, fmt.Sprintf("no loader is told to import code: no auto_map, custom_pipelines, sentence-transformers module outside "+
			"sentence_transformers, diffusers custom component, Hub kernel named as an attention implementation, or trust_remote_code "+
			"granted in the %d JSON config(s) read, and no custom_generate/generate.py, handler.py, pipeline.py, or code/inference.py", configs))
	}
	for i, ref := range noted {
		if i == maxListed {
			notes = append(notes, fmt.Sprintf("and %d more such class(es)", len(noted)-i))
			break
		}
		notes = append(notes, fmt.Sprintf("%s names %s, which this directory holds no file for: sentence-transformers imports it from an installed package, or the load fails",
			clip(ref.where), clip(ref.what)))
	}
	if len(stray) > 0 {
		notes = append(notes, "present and imported by none of these (listed, not judged): "+list(stray))
	}
	r.Notes = strings.Join(notes, "; ")
	return r
}

// fieldNote says what the config fields that override the caller do.
func fieldNote(fields []override, failed bool) string {
	s := fmt.Sprintf("%d config field(s) make a loader run code the caller did not allow with trust_remote_code, each named in the evidence", len(fields))
	if failed {
		s += ". A Hub kernel outside kernels-community named in an attention field of config.json is the CVE-2026-4372 injection: " +
			"transformers 4.56.0 to 5.2.x run it in a plain from_pretrained once the kernels package is installed, and save_pretrained " +
			"never writes the field. Do not load this model"
	}
	return s
}

// finding is the evidence for one reference.
func finding(ref reference) checks.Finding {
	span := clip(ref.where)
	if ref.what != "" {
		span += " -> " + clip(ref.what)
	}
	var d string
	switch {
	case len(ref.res.files) > 0:
		d = "names " + list(ref.res.files) + "; " + ref.detail
	case ref.res.outside != "" && strings.Contains(ref.what, "--"):
		d = "names code in another repository, " + clip(ref.res.outside) + ", not in this artifact; " + ref.detail
	case ref.res.outside != "":
		d = "names a path outside this directory, " + clip(ref.res.outside) + "; " + ref.detail
	default:
		d = "names a module this directory does not contain: code this artifact does not carry and Socair cannot read, " +
			"which a loader given the repository's id would look for there; " + ref.detail
	}
	return checks.Finding{Pattern: ref.pattern, Span: span, Detail: d}
}

func leadNote(leads []reference, files []string) string {
	var who []string
	tags := map[string]bool{}
	elsewhere := map[string]bool{}
	for _, ref := range leads {
		tags[ref.pattern] = true
		if len(ref.res.files) == 0 {
			elsewhere[ref.where+ref.what] = true
		}
	}
	s := fmt.Sprintf("%d reference(s) tell a loader to import code: %d file(s) in this directory", len(leads), len(files))
	if len(files) > 0 {
		s += " (" + list(files) + ")"
	}
	if len(elsewhere) > 0 {
		s += fmt.Sprintf(", and %d reference(s) to code this directory does not hold", len(elsewhere))
	}
	s += ", each reference named in the evidence"
	if tags["custom-generate"] {
		who = append(who, "transformers 4.57.6 imports custom_generate/generate.py from a local directory without trust_remote_code")
	}
	if tags["custom-module"] {
		who = append(who, "sentence-transformers before 6.0 imports a custom module from a local directory without it")
	}
	if tags["inference-handler"] {
		who = append(who, "the inference toolkits import their handler without it")
	}
	s += ". Review the code before serving, or serve without trust_remote_code"
	if len(who) > 0 {
		s += ", which is not enough here: " + strings.Join(who, "; ")
	}
	return s
}

// follow walks the imports of the entry files, transitively, and returns
// every file reached (entries included), the file that first imported each
// non-entry, and the files it could not read.
//
// A relative import resolves against the importing file's package, as
// Python does, and against the entry's directory, as transformers'
// get_relative_import_files does (it joins every relative import, at any
// depth, to the first module's directory). An absolute import resolves
// against the root, the importing file's directory, and the entry's: the
// directory is on Python's path when a process runs from it, and the
// inference toolkits put the root (or code/) first on it.
func follow(root string, t *tree, entries []string) (reached []string, importedBy map[string]string, unread []string) {
	importedBy = map[string]string{}
	seen := map[string]bool{}
	type item struct{ file, entryDir string }
	var queue []item
	for _, e := range entries {
		if !seen[e] {
			seen[e] = true
			queue = append(queue, item{e, dirOf(e)})
		}
	}
	for len(queue) > 0 {
		it := queue[0]
		queue = queue[1:]
		reached = append(reached, it.file)
		if strings.ToLower(path.Ext(it.file)) != ".py" {
			continue
		}
		p := filepath.Join(root, filepath.FromSlash(it.file))
		st, err := os.Stat(p)
		if err != nil || st.Size() > maxSource {
			unread = append(unread, it.file)
			continue
		}
		src, err := os.ReadFile(p)
		if err != nil {
			unread = append(unread, it.file)
			continue
		}
		for _, c := range candidates(it.file, it.entryDir, scanImports(src)) {
			for _, hit := range t.find(c) {
				if !seen[hit] {
					seen[hit] = true
					importedBy[hit] = it.file
					queue = append(queue, item{hit, it.entryDir})
				}
			}
		}
	}
	sort.Strings(reached)
	return reached, importedBy, unread
}

// candidates lists the files the imports of file could execute.
func candidates(file, entryDir string, imps []pyImport) []string {
	here := dirOf(file)
	var out []string
	add := func(base, mod string, names []string) {
		if c, ok := moduleFiles(base, mod); ok {
			out = append(out, c...)
		}
		for _, n := range names {
			sub := n
			if mod != "" {
				sub = mod + "." + n
			}
			if c, ok := moduleFiles(base, sub); ok {
				out = append(out, c...)
			}
		}
	}
	for _, imp := range imps {
		if imp.level == 0 {
			for _, b := range []string{"", here, entryDir} {
				add(b, imp.module, imp.names)
			}
			continue
		}
		if pkg, ok := climb(here, imp.level-1); ok {
			add(pkg, imp.module, imp.names)
		}
		// transformers reads "from .<m> import" as <entry dir>/<m>.py, with
		// <m> everything after the first dot ("a.b" in "from .a.b import").
		if m := strings.Repeat(".", imp.level-1) + imp.module; m != "" {
			if p, ok := inside(entryDir, m+".py"); ok {
				out = append(out, p)
			}
		}
	}
	return out
}

// climb goes n directories up from dir, staying in the root.
func climb(dir string, n int) (string, bool) {
	for ; n > 0; n-- {
		if dir == "" {
			return "", false
		}
		dir = dirOf(dir)
	}
	return dir, true
}

func dirOf(p string) string {
	d := path.Dir(p)
	if d == "." {
		return ""
	}
	return d
}

func contains(sorted []string, s string) bool {
	i := sort.SearchStrings(sorted, s)
	return i < len(sorted) && sorted[i] == s
}

// list names files, bounded.
func list(s []string) string {
	if len(s) > maxListed {
		return strings.Join(s[:maxListed], ", ") + fmt.Sprintf(", and %d more", len(s)-maxListed)
	}
	return strings.Join(s, ", ")
}

// clip bounds text quoted from a config.
func clip(s string) string {
	if len(s) > maxText {
		return strings.ToValidUTF8(s[:maxText], "") + "..."
	}
	return s
}
