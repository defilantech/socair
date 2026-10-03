// Package pickle scans pickle-based model files for the imports an unpickler
// would make.
//
// It never unpickles and never executes. It models the opcode stream
// (protocols 0 to 5) with a stack and memo, so a global is found however it is
// spelled: GLOBAL, INST, or STACK_GLOBAL from strings built or memoized
// earlier. Every global is then judged against a policy:
//
//   - a known code-execution or I/O module or callable is a FAIL;
//   - a global on the reviewed safe list (tensor and storage rebuilders,
//     containers, numpy reconstruction) is fine;
//   - anything else, or an import that cannot be resolved statically, is a
//     LEAD, named, because a pickle can call any global it imports.
//
// A zip (PyTorch's format since 1.6) or tar checkpoint is opened and every
// entry that is a pickle is walked, by content rather than by name. A stream
// longer than the scan budget is NOT_TESTED, not a pass on what was read.
package pickle

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/gguf"
	"github.com/defilantech/socair/internal/safetensors"
)

// maxScanBytes caps how much of one pickle stream is read. It is a variable
// so tests can exercise truncation without a quarter-gigabyte fixture.
var maxScanBytes int64 = 256 << 20

// Archive limits, so a zip bomb or a huge entry table cannot drive the scan.
const (
	maxEntries      = 10000
	maxArchiveBytes = 4 << 30
)

// dangerousModules are FAIL wherever they appear: any global from them, or a
// submodule of them, reaches code execution, the filesystem, processes, or
// the network. Matched as the module or a dotted prefix of it.
var dangerousModules = []string{
	"os", "posix", "nt", "subprocess", "commands", "pty", "runpy", "importlib",
	"ctypes", "socket", "shutil", "sys", "code", "codeop", "pdb", "bdb", "timeit",
	"webbrowser", "multiprocessing", "asyncio", "marshal", "pickle", "_pickle",
	"dill", "cloudpickle", "types", "cProfile", "profile", "pip", "setuptools",
	"distutils", "urllib", "http", "requests", "httpx", "aiohttp", "ftplib",
	"smtplib", "telnetlib", "platform", "signal", "threading", "_thread",
	"tempfile", "glob", "pathlib", "io", "zipimport", "pkgutil", "site",
	"_posixsubprocess", "_io", "builtins.__import__",
}

// dangerousNames are FAIL in modules that are otherwise benign.
var dangerousNames = map[string]map[string]bool{
	"builtins": {"eval": true, "exec": true, "execfile": true, "compile": true, "open": true,
		"__import__": true, "getattr": true, "setattr": true, "delattr": true, "globals": true,
		"locals": true, "vars": true, "input": true, "breakpoint": true, "apply": true, "help": true},
	"operator":            {"attrgetter": true, "methodcaller": true},
	"functools":           {"partial": true, "reduce": true},
	"torch":               {"load": true},
	"torch.serialization": {"load": true},
	"numpy":               {"load": true, "loads": true, "fromfile": true},
	"numpy.lib.npyio":     {"load": true},
	"joblib":              {"load": true},
}

// safeGlobals are reviewed as constructors that rebuild data and cannot reach
// arbitrary code on their own. Everything a standard PyTorch or numpy
// checkpoint imports is here.
var safeGlobals = map[string]bool{
	"collections.OrderedDict":                      true,
	"collections.defaultdict":                      true,
	"builtins.set":                                 true,
	"builtins.frozenset":                           true,
	"builtins.slice":                               true,
	"builtins.complex":                             true,
	"builtins.bytearray":                           true,
	"builtins.int":                                 true,
	"builtins.float":                               true,
	"builtins.str":                                 true,
	"builtins.bytes":                               true,
	"builtins.list":                                true,
	"builtins.dict":                                true,
	"builtins.tuple":                               true,
	"builtins.range":                               true,
	"builtins.bool":                                true,
	"_codecs.encode":                               true,
	"copyreg._reconstructor":                       true,
	"torch._utils._rebuild_tensor":                 true,
	"torch._utils._rebuild_tensor_v2":              true,
	"torch._utils._rebuild_tensor_v3":              true,
	"torch._utils._rebuild_parameter":              true,
	"torch._utils._rebuild_parameter_with_state":   true,
	"torch._utils._rebuild_qtensor":                true,
	"torch._utils._rebuild_sparse_tensor":          true,
	"torch._utils._rebuild_meta_tensor_no_storage": true,
	"torch._utils._rebuild_wrapper_subclass":       true,
	"torch._tensor._rebuild_from_type_v2":          true,
	"torch.Size":                                   true,
	"torch.device":                                 true,
	"torch.nn.parameter.Parameter":                 true,
	"numpy.core.multiarray._reconstruct":           true,
	"numpy.core.multiarray.scalar":                 true,
	"numpy._core.multiarray._reconstruct":          true,
	"numpy._core.multiarray.scalar":                true,
	"numpy.ndarray":                                true,
	"numpy.dtype":                                  true,
}

// safeTorchNames are torch attributes that name a storage type or dtype.
func safeTorchName(mod, name string) bool {
	if mod != "torch" {
		return false
	}
	return strings.HasSuffix(name, "Storage") || isDtype(name)
}

func isDtype(name string) bool {
	switch name {
	case "float16", "float32", "float64", "bfloat16", "half", "float", "double",
		"int8", "int16", "int32", "int64", "uint8", "bool", "complex64", "complex128",
		"float8_e4m3fn", "float8_e5m2", "long", "int", "short":
		return true
	}
	return false
}

// verdict classifies one global.
func verdict(g Global) string {
	mod := g.Module
	if mod == "__builtin__" {
		mod = "builtins"
	}
	for _, d := range dangerousModules {
		if mod == d || strings.HasPrefix(mod, d+".") || mod+"."+g.Name == d {
			return "dangerous"
		}
	}
	if dangerousNames[mod][g.Name] {
		return "dangerous"
	}
	if safeGlobals[mod+"."+g.Name] || safeTorchName(mod, g.Name) {
		return "safe"
	}
	return "unknown"
}

// scan accumulates what every walked stream found.
type scan struct {
	globals    []Global
	dynamic    []string
	pickles    int
	truncated  []string
	unreadable []string
	where      map[string]string // global -> where it was found
}

func (s *scan) addWalk(where string, w walkResult) {
	for _, g := range w.globals {
		if s.where == nil {
			s.where = map[string]string{}
		}
		if _, seen := s.where[g.String()]; !seen {
			s.where[g.String()] = where
		}
		s.globals = append(s.globals, g)
	}
	for _, d := range w.dynamic {
		s.dynamic = append(s.dynamic, where+": "+d)
	}
	s.pickles += w.pickles
}

// Inspect scans one artifact for pickle imports.
func Inspect(path string) checks.Result {
	r := checks.Result{
		Name:     "Pickle opcode scan",
		LooksFor: "Imports in pickle-based model files that reach code execution",
	}

	if safetensors.IsSafetensors(path) {
		r.Status = checks.NotTested
		r.Notes = "artifact is safetensors, not a pickle format; no opcode stream to scan"
		return r
	}
	if m, err := gguf.ReadHeader(path); err == nil && m.Format == "GGUF" {
		r.Status = checks.NotTested
		r.Notes = "artifact is GGUF, not a pickle format; no opcode stream to scan"
		return r
	}

	f, err := os.Open(path)
	if err != nil {
		r.Status = checks.NotTested
		r.Notes = "could not open artifact: " + err.Error()
		return r
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		r.Status = checks.NotTested
		r.Notes = "could not stat artifact: " + err.Error()
		return r
	}
	head := make([]byte, 512)
	n, _ := io.ReadFull(f, head)
	head = head[:n]
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		r.Status = checks.NotTested
		r.Notes = "could not seek artifact: " + err.Error()
		return r
	}

	var s scan
	kind := "pickle stream"
	switch {
	case bytes.HasPrefix(head, []byte("PK\x03\x04")):
		kind = "zip archive"
		scanZip(f, fi.Size(), &s)
	case isTar(head):
		kind = "tar archive"
		scanTar(f, &s)
	default:
		w, truncated := walkCapped(f)
		if errors.Is(w.err, errNotPickle) && !truncated {
			r.Status = checks.NotTested
			r.Notes = "artifact is not a pickle opcode stream or a zip/tar checkpoint; nothing to scan"
			return r
		}
		s.addWalk("stream", w)
		if truncated {
			s.truncated = append(s.truncated, fmt.Sprintf("stream (first %d bytes)", maxScanBytes))
		} else if w.err != nil && w.pickles == 0 {
			s.unreadable = append(s.unreadable, "stream: "+w.err.Error())
		}
	}
	return judge(r, kind, &s)
}

// walkCapped walks at most maxScanBytes and reports whether bytes remained.
func walkCapped(rd io.Reader) (walkResult, bool) {
	cr := &countReader{r: io.LimitReader(rd, maxScanBytes)}
	w := walk(cr)
	truncated := false
	if cr.n >= maxScanBytes && w.err != nil {
		var probe [1]byte
		if k, _ := rd.Read(probe[:]); k > 0 {
			truncated = true
		}
	}
	return w, truncated
}

type countReader struct {
	r io.Reader
	n int64
}

func (c *countReader) Read(p []byte) (int, error) {
	k, err := c.r.Read(p)
	c.n += int64(k)
	return k, err
}

func isTar(head []byte) bool {
	return len(head) >= 262 && string(head[257:262]) == "ustar"
}

// scanZip walks every entry that is a pickle. Entries are recognised by
// content, not name, because a mismatched local and central file name was a
// picklescan bypass; a ".pkl" entry that does not parse is reported, and any
// other entry counts only when it parses to a complete pickle, so raw tensor
// bytes are not misread.
func scanZip(f *os.File, size int64, s *scan) {
	zr, err := zip.NewReader(f, size)
	if err != nil {
		s.unreadable = append(s.unreadable, "zip: "+err.Error())
		return
	}
	if len(zr.File) > maxEntries {
		s.unreadable = append(s.unreadable, fmt.Sprintf("zip has %d entries, over the %d limit", len(zr.File), maxEntries))
		return
	}
	var total int64
	for _, zf := range zr.File {
		if zf.FileInfo().IsDir() {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			s.unreadable = append(s.unreadable, zf.Name+": "+err.Error())
			continue
		}
		br := bufio.NewReader(rc)
		named := strings.HasSuffix(strings.ToLower(zf.Name), ".pkl")
		if !named {
			// A tensor entry is raw bytes. Only an entry that starts with
			// PROTO, as every default-protocol pickle does, is walked, so
			// data that happens to begin with an opcode is not misread.
			if b, err := br.Peek(1); err != nil || b[0] != 0x80 {
				_ = rc.Close()
				continue
			}
		}
		w, truncated := walkCapped(br)
		_ = rc.Close()
		total += int64(zf.UncompressedSize64)
		if !named {
			w.globals = plausible(w.globals)
		}
		switch {
		case truncated:
			s.addWalk(zf.Name, w)
			s.truncated = append(s.truncated, zf.Name)
		case w.pickles > 0:
			s.addWalk(zf.Name, w)
		case named:
			s.addWalk(zf.Name, w)
			if w.err != nil {
				s.unreadable = append(s.unreadable, zf.Name+": "+w.err.Error())
			}
		}
		if total > maxArchiveBytes {
			s.truncated = append(s.truncated, fmt.Sprintf("archive beyond %d bytes", int64(maxArchiveBytes)))
			return
		}
	}
}

// identifier is a dotted Python name.
var identifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$`)

// plausible drops "globals" whose module or name is not a Python identifier.
// It applies only to entries recognised by content: an import with a
// malformed name cannot resolve, so it is noise from tensor bytes, not an
// attack.
func plausible(gs []Global) []Global {
	var out []Global
	for _, g := range gs {
		if identifier.MatchString(g.Module) && identifier.MatchString(g.Name) {
			out = append(out, g)
		}
	}
	return out
}

// scanTar walks every tar entry that parses as a pickle: the legacy torch.save
// tar layout keeps its pickles in entries named pickle, storages, and tensors.
func scanTar(f *os.File, s *scan) {
	tr := tar.NewReader(f)
	for i := 0; ; i++ {
		h, err := tr.Next()
		if err == io.EOF {
			return
		}
		if err != nil {
			s.unreadable = append(s.unreadable, "tar: "+err.Error())
			return
		}
		if i >= maxEntries {
			s.unreadable = append(s.unreadable, fmt.Sprintf("tar has more than %d entries", maxEntries))
			return
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		w, truncated := walkCapped(tr)
		if truncated {
			s.addWalk(h.Name, w)
			s.truncated = append(s.truncated, h.Name)
		} else if w.pickles > 0 {
			s.addWalk(h.Name, w)
		}
	}
}

// judge turns what the scan found into a result.
func judge(r checks.Result, kind string, s *scan) checks.Result {
	var dangerous, unknown []string
	seen := map[string]bool{}
	for _, g := range s.globals {
		k := g.String()
		if seen[k] {
			continue
		}
		seen[k] = true
		switch verdict(g) {
		case "dangerous":
			dangerous = append(dangerous, k)
		case "unknown":
			unknown = append(unknown, k)
		}
	}
	sort.Strings(dangerous)
	sort.Strings(unknown)

	if len(dangerous) > 0 {
		for _, g := range dangerous {
			r.Findings = append(r.Findings, checks.Finding{Pattern: "pickle-dangerous-global", Span: g,
				Detail: "imported in " + s.where[g] + "; reaches code execution, processes, files, or the network when unpickled"})
		}
		r.Status = checks.Fail
		r.Notes = fmt.Sprintf("%s imports %d dangerous global(s): %s. Positive evidence.", kind, len(dangerous), strings.Join(dangerous, ", "))
		return r
	}
	if len(unknown) > 0 || len(s.dynamic) > 0 || len(s.unreadable) > 0 {
		for _, g := range unknown {
			r.Findings = append(r.Findings, checks.Finding{Pattern: "pickle-unreviewed-global", Span: g,
				Detail: "imported in " + s.where[g] + "; not on the reviewed safe list, and a pickle can call any global it imports"})
		}
		for _, d := range s.dynamic {
			r.Findings = append(r.Findings, checks.Finding{Pattern: "pickle-dynamic-global", Span: excerpt(d),
				Detail: "an import that cannot be resolved statically"})
		}
		for _, u := range s.unreadable {
			r.Findings = append(r.Findings, checks.Finding{Pattern: "pickle-unreadable", Span: excerpt(u),
				Detail: "part of the checkpoint could not be read; a loader may still read it"})
		}
		r.Status = checks.Lead
		var parts []string
		if len(unknown) > 0 {
			parts = append(parts, "unreviewed global(s) "+strings.Join(unknown, ", "))
		}
		if len(s.dynamic) > 0 {
			parts = append(parts, fmt.Sprintf("%d import(s) that cannot be resolved statically", len(s.dynamic)))
		}
		if len(s.unreadable) > 0 {
			parts = append(parts, fmt.Sprintf("%d unreadable part(s)", len(s.unreadable)))
		}
		r.Notes = kind + ": " + strings.Join(parts, "; ") + ". Needs review."
		return r
	}
	if len(s.truncated) > 0 {
		r.Status = checks.NotTested
		r.Notes = fmt.Sprintf("%s scanned only in part (%s); no dangerous import in what was read", kind, strings.Join(s.truncated, ", "))
		return r
	}
	if s.pickles == 0 {
		r.Status = checks.NotTested
		r.Notes = kind + " holds no pickle stream to scan"
		return r
	}
	r.Status = checks.Pass
	r.Notes = fmt.Sprintf("%s: %d pickle(s) walked, %d distinct global(s), every one on the reviewed safe list. "+
		"A pickle is still executable code and a safe-list bypass is not excluded; safetensors carries no code.",
		kind, s.pickles, len(seen))
	return r
}

func excerpt(s string) string {
	if len(s) > 100 {
		return s[:100] + "..."
	}
	return s
}
