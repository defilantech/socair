package remotecode

import (
	"path"
	"sort"
	"strings"
)

// tree indexes a directory's file paths ("/"-separated, relative). A path is
// also matched without regard to case, because a loader on a case-insensitive
// file system (macOS, Windows) opens Modeling_X.py for modeling_x.
type tree struct {
	exact map[string]bool
	fold  map[string][]string
}

func newTree(paths []string) *tree {
	t := &tree{exact: map[string]bool{}, fold: map[string][]string{}}
	for _, p := range paths {
		t.exact[p] = true
		k := strings.ToLower(p)
		t.fold[k] = append(t.fold[k], p)
	}
	return t
}

// find returns the files at p: the exact path, or every path equal to it
// without regard to case.
func (t *tree) find(p string) []string {
	if t.exact[p] {
		return []string{p}
	}
	return t.fold[strings.ToLower(p)]
}

// inside joins rel onto base and reports whether the result stays in the
// directory. A rooted path, a backslash, a drive or scheme colon, a NUL, or a
// ".." that climbs out is outside: a loader would open it relative to
// something other than this directory, or not in it.
func inside(base, rel string) (string, bool) {
	if rel == "" || strings.HasPrefix(rel, "/") || strings.ContainsAny(rel, "\\:\x00") {
		return "", false
	}
	p := path.Clean(path.Join(base, rel))
	if p == ".." || strings.HasPrefix(p, "../") || strings.HasPrefix(p, "/") {
		return "", false
	}
	return p, true
}

// moduleFiles lists the files Python could execute importing the dotted module
// name relative to base: each package prefix's __init__.py and the module
// itself as a file or a package. An empty name is base itself, which names no
// file. ok is false when a candidate falls outside the directory.
func moduleFiles(base, dottedName string) (cands []string, ok bool) {
	if dottedName == "" {
		return nil, true
	}
	parts := strings.Split(dottedName, ".")
	for i := range parts {
		if parts[i] == "" {
			return nil, true // "a..b": no import resolves it
		}
		prefix := strings.Join(parts[:i+1], "/")
		for _, c := range []string{prefix + ".py", prefix + "/__init__.py"} {
			p, in := inside(base, c)
			if !in {
				return nil, false
			}
			cands = append(cands, p)
		}
	}
	return cands, true
}

// classRef is a class reference as a loader config writes it: "module.Class",
// or "repo--module.Class" for code in another repository.
type classRef struct {
	repo   string // the part before "--", when there is one
	module string // the module part, before the last "."
}

func parseClassRef(ref string) classRef {
	var r classRef
	if i := strings.Index(ref, "--"); i >= 0 {
		r.repo, ref = ref[:i], ref[i+2:]
	}
	r.module = ref
	if i := strings.LastIndex(ref, "."); i >= 0 {
		r.module = ref[:i]
	}
	return r
}

// resolution is what a reference names in the directory.
type resolution struct {
	files   []string // files in the directory it names
	outside string   // a repository or path outside the directory it names
}

// dynamic resolves a class reference the way transformers'
// get_class_from_dynamic_module does: the module part plus ".py", opened in
// the directory the loader was given (dynamic_module_utils.py, v4.57.6 and
// v5.19.0). The module part may hold "/" (a subdirectory). Its dotted form
// is resolved as a Python package path too, which no transformers release
// accepts but costs nothing to name. Each base is a directory the loader may
// have been pointed at: the config's own and the root.
func (t *tree) dynamic(ref string, bases []string) resolution {
	r := parseClassRef(ref)
	if r.repo != "" {
		return resolution{outside: r.repo}
	}
	var res resolution
	for _, b := range bases {
		p, ok := inside(b, r.module+".py")
		if !ok {
			return resolution{outside: r.module}
		}
		res.files = append(res.files, t.find(p)...)
		if strings.Contains(r.module, ".") && !strings.Contains(r.module, "/") {
			cands, ok := moduleFiles(b, strings.TrimLeft(r.module, "."))
			if !ok {
				return resolution{outside: r.module}
			}
			for _, c := range cands {
				res.files = append(res.files, t.find(c)...)
			}
		}
	}
	res.files = uniq(res.files)
	return res
}

// importable resolves a dotted path the way sentence-transformers'
// import_from_string does, with importlib.import_module: a module found on
// Python's path, which holds the directory when a process runs from it.
func (t *tree) importable(dottedPath string, bases []string) resolution {
	var res resolution
	for _, b := range bases {
		cands, ok := moduleFiles(b, strings.TrimLeft(dottedPath, "."))
		if !ok {
			return resolution{outside: dottedPath}
		}
		for _, c := range cands {
			res.files = append(res.files, t.find(c)...)
		}
	}
	res.files = uniq(res.files)
	return res
}

func uniq(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	sort.Strings(s)
	out := s[:1]
	for _, x := range s[1:] {
		if x != out[len(out)-1] {
			out = append(out, x)
		}
	}
	return out
}

// bases is the config's own directory and the root, once each.
func bases(configPath string) []string {
	d := path.Dir(configPath)
	if d == "." {
		return []string{""}
	}
	return []string{d, ""}
}
