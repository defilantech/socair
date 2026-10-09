// Package pickle checks pickle-based model files (PyTorch checkpoints, raw
// pickles, NumPy arrays with object data) against a typed grammar.
//
// It never unpickles and never executes. Two passes read every pickle:
//
//   - the import scan models the opcode stream (protocols 0 to 5) with a
//     stack and memo, so a global is found however it is spelled: GLOBAL,
//     INST, or STACK_GLOBAL from strings built or memoized earlier, under
//     CPython's Python 2 renaming. A code-execution, I/O, or nested-loader
//     global is a FAIL; a global outside the reviewed lists, or an import
//     that cannot be resolved statically, is a LEAD.
//   - the grammar (see Grammar) models the values the stream builds and checks
//     every call's arguments, every persistent id, and the encoding. A
//     conforming checkpoint earns a bounded PASS: it builds only tensors and
//     plain containers, and its storage records match.
//
// Containers are opened and checked as their loaders read them: a torch zip
// (PyTorch's format since 1.6), a legacy torch stream, a legacy tar, a raw
// pickle, and NumPy's .npy and .npz. A stream longer than the scan budget is
// NOT_TESTED, not a pass on what was read.
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
	"_posixsubprocess", "_io", "builtins.__import__", "socketserver", "xmlrpc",
}

// dangerousNames are FAIL in modules that are otherwise benign.
var dangerousNames = map[string]map[string]bool{
	"builtins": {"eval": true, "exec": true, "execfile": true, "compile": true, "open": true,
		"__import__": true, "getattr": true, "setattr": true, "delattr": true, "globals": true,
		"locals": true, "vars": true, "input": true, "breakpoint": true, "apply": true, "help": true},
	"operator":  {"attrgetter": true, "methodcaller": true},
	"functools": {"partial": true, "reduce": true},
	"numpy":     {"fromfile": true},
}

// nestedLoaders deserialize bytes the scan cannot see: a pickle inside the
// pickle, run by a loader that may not check it. torch.storage's
// _load_from_bytes calls torch.load with weights_only off.
var nestedLoaders = map[string]bool{
	"torch.storage._load_from_bytes": true, "torch.load": true, "torch.serialization.load": true,
	"torch.serialization._load": true, "torch.serialization._legacy_load": true, "torch.jit.load": true,
	"torch.jit._serialization.load": true, "numpy.load": true, "numpy.loads": true,
	"numpy.lib.npyio.load": true, "numpy.lib._npyio_impl.load": true, "numpy.lib.format.read_array": true,
	"numpy.lib._format_impl.read_array": true, "joblib.load": true, "joblib.numpy_pickle.load": true,
	"pandas.read_pickle": true, "pandas.io.pickle.read_pickle": true,
}

// verdict classifies one global, as spelled and as CPython renames it.
func verdict(g Global, reviewed map[string]bool) string {
	rmod, rname := pyResolve(g.Module, g.Name)
	for _, mn := range [][2]string{{g.Module, g.Name}, {rmod, rname}} {
		mod, name := mn[0], mn[1]
		for _, d := range dangerousModules {
			if mod == d || strings.HasPrefix(mod, d+".") || mod+"."+name == d {
				return "dangerous"
			}
		}
		if dangerousNames[mod][name] {
			return "dangerous"
		}
		if nestedLoaders[mod+"."+name] {
			return "nested"
		}
	}
	full := rmod + "." + rname
	switch {
	case isModeled(full) || isHarmless(full):
		return "safe"
	case reviewed[full]:
		return "reviewed"
	}
	return "unknown"
}

// Options are reference data the check reads.
type Options struct {
	// Reviewed are classes (module.Name) a review covers: an instance built
	// with a default __new__ and a state dict of plain values conforms as a
	// second tier, named in the notes. The list is reference data, delivered
	// with a signed feed; it is empty by default, and nothing is on it until
	// a review puts it there.
	Reviewed map[string]bool
}

// scan accumulates what every walked stream found.
type scan struct {
	opts       Options
	globals    []Global
	dynamic    []string
	pickles    int
	truncated  []string
	unreadable []string
	where      map[string]string // global -> where it was found

	// What the grammar found: findings by status, gaps, and what a PASS
	// would rest on.
	fails, leads []checks.Finding
	gaps         []string
	proof        proof
}

// proof is what conforming streams and containers showed.
type proof struct {
	pickles   int
	protocols map[int]bool
	tensors   []*tensorInfo
	reviewed  map[string]bool
	layouts   []string
	arrays    []string
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

func (s *scan) finding(status checks.Status, pattern, span, detail string) {
	f := checks.Finding{Pattern: pattern, Span: excerpt(span), Detail: detail}
	if status == checks.Fail {
		s.fails = append(s.fails, f)
	} else {
		s.leads = append(s.leads, f)
	}
}

func (s *scan) gap(reason string) {
	for _, g := range s.gaps {
		if g == reason {
			return
		}
	}
	s.gaps = append(s.gaps, reason)
}

// Inspect checks one artifact's pickles.
func Inspect(path string) checks.Result { return InspectWith(path, Options{}) }

// InspectWith is Inspect with reference data.
func InspectWith(path string, opts Options) checks.Result {
	r := checks.Result{
		Name:     "Pickle opcode scan",
		LooksFor: "Imports in pickle-based model files that reach code execution, and pickles that build more than tensors and plain containers",
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

	s := scan{opts: opts}
	kind := "pickle stream"
	switch {
	case bytes.HasPrefix(head, []byte("PK\x03\x04")):
		kind = "zip archive"
		scanZip(f, fi.Size(), &s)
	case isTar(head):
		kind = "tar archive"
		scanTar(f, &s)
	case strictGrammar && isNPY(head):
		kind = "NumPy array"
		s.npyArray("array", fi.Size(), func() (io.ReadCloser, error) {
			return io.NopCloser(io.NewSectionReader(f, 0, fi.Size())), nil
		})
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
		if strictGrammar {
			s.rawStream(f, fi.Size())
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

// countReader counts what passes through it and keeps the first error that
// is not EOF, such as a zip entry's CRC mismatch.
type countReader struct {
	r   io.Reader
	n   int64
	err error
}

func (c *countReader) Read(p []byte) (int, error) {
	k, err := c.r.Read(p)
	c.n += int64(k)
	if err != nil && err != io.EOF && c.err == nil {
		c.err = err
	}
	return k, err
}

func isTar(head []byte) bool {
	return len(head) >= 262 && string(head[257:262]) == "ustar"
}

// scanZip walks every entry that is a pickle. Entries are recognised by
// content, not name, because a mismatched local and central file name was a
// picklescan bypass; a ".pkl" entry that does not parse is reported, and any
// other entry counts only when it parses to a complete pickle, so raw tensor
// bytes are not misread. The grammar then checks the archive as its loader
// reads it.
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
	if strictGrammar {
		s.zipArchive(zr)
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
			break
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
	if strictGrammar {
		s.tarArchive(f)
	}
}

// judge turns what the scan found into a result.
func judge(r checks.Result, kind string, s *scan) checks.Result {
	var dangerous, nested, unknown []string
	seen := map[string]bool{}
	for _, g := range s.globals {
		k := g.String()
		if seen[k] {
			continue
		}
		seen[k] = true
		switch verdict(g, s.opts.Reviewed) {
		case "dangerous":
			dangerous = append(dangerous, k)
		case "nested":
			nested = append(nested, k)
		case "unknown":
			unknown = append(unknown, k)
		}
	}
	sort.Strings(dangerous)
	sort.Strings(nested)
	sort.Strings(unknown)

	var fails, leads []checks.Finding
	for _, g := range dangerous {
		fails = append(fails, checks.Finding{Pattern: "pickle-dangerous-global", Span: g,
			Detail: "imported in " + s.where[g] + "; reaches code execution, processes, files, or the network when unpickled"})
	}
	for _, g := range nested {
		fails = append(fails, checks.Finding{Pattern: "pickle-nested-loader", Span: g,
			Detail: "imported in " + s.where[g] + "; a nested loader deserializes bytes this scan cannot see"})
	}
	fails = append(fails, s.fails...)
	for _, g := range unknown {
		leads = append(leads, checks.Finding{Pattern: "pickle-unreviewed-global", Span: g,
			Detail: "imported in " + s.where[g] + "; not on the reviewed lists, and a pickle can call any global it imports"})
	}
	for _, d := range s.dynamic {
		leads = append(leads, checks.Finding{Pattern: "pickle-dynamic-global", Span: excerpt(d),
			Detail: "an import that cannot be resolved statically"})
	}
	for _, u := range s.unreadable {
		leads = append(leads, checks.Finding{Pattern: "pickle-unreadable", Span: excerpt(u),
			Detail: "part of the checkpoint could not be read; a loader may still read it"})
	}
	leads = append(leads, s.leads...)

	switch {
	case len(fails) > 0:
		r.Status = checks.Fail
		r.Findings = append(fails, leads...)
		var parts []string
		if len(dangerous) > 0 {
			parts = append(parts, fmt.Sprintf("imports %d dangerous global(s): %s", len(dangerous), strings.Join(dangerous, ", ")))
		}
		if len(nested) > 0 {
			parts = append(parts, fmt.Sprintf("imports %d nested loader(s): %s", len(nested), strings.Join(nested, ", ")))
		}
		if len(s.fails) > 0 {
			parts = append(parts, fmt.Sprintf("%d grammar violation(s) that are positive evidence (%s)", len(s.fails), patternList(s.fails)))
		}
		r.Notes = fmt.Sprintf("%s %s. Positive evidence.", kind, strings.Join(parts, "; "))
		return r
	case len(leads) > 0:
		r.Status = checks.Lead
		r.Findings = leads
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
		if len(s.leads) > 0 {
			parts = append(parts, fmt.Sprintf("%d departure(s) from grammar %s (%s)", len(s.leads), Grammar, patternList(s.leads)))
		}
		r.Notes = kind + ": " + strings.Join(parts, "; ") + ". Needs review."
		return r
	case len(s.truncated) > 0:
		r.Status = checks.NotTested
		r.Notes = fmt.Sprintf("%s scanned only in part (%s); no dangerous import in what was read", kind, strings.Join(s.truncated, ", "))
		return r
	case len(s.gaps) > 0:
		r.Status = checks.NotTested
		r.Notes = fmt.Sprintf("%s: outside grammar %s: %s. No dangerous or unreviewed import was found, but the stream was not shown to build only tensors and plain containers",
			kind, Grammar, strings.Join(s.gaps, "; "))
		return r
	case s.pickles == 0 && len(s.proof.arrays) == 0:
		r.Status = checks.NotTested
		r.Notes = kind + " holds no pickle stream to scan"
		return r
	}
	r.Status = checks.Pass
	if !strictGrammar {
		r.Notes = fmt.Sprintf("%s: %d pickle(s) walked, %d distinct global(s), every one on the reviewed safe list. "+
			"A pickle is still executable code and a safe-list bypass is not excluded; safetensors carries no code.",
			kind, s.pickles, len(seen))
		return r
	}
	r.Notes = kind + ": " + s.proof.String()
	return r
}

// notCovered is what a grammar PASS does not claim.
const notCovered = "Not covered: a bug in a loader, a reader that parses these bytes differently from CPython, " +
	"code carried as data in a string for a later stage, and a tampered Python environment (a patched module)."

func (p proof) String() string {
	var parts []string
	if p.pickles > 0 {
		protos := make([]string, 0, len(p.protocols))
		for v := range p.protocols {
			protos = append(protos, fmt.Sprint(v))
		}
		sort.Strings(protos)
		built := "they build only plain containers, no tensors"
		if len(p.tensors) > 0 {
			built = "they build only tensors and plain containers: " + tensorSummary(p.tensors)
		}
		parts = append(parts, fmt.Sprintf("%d pickle(s) conform to grammar %s (protocol %s); %s",
			p.pickles, Grammar, strings.Join(protos, ", "), built))
		if len(p.reviewed) > 0 {
			names := make([]string, 0, len(p.reviewed))
			for c := range p.reviewed {
				names = append(names, c)
			}
			sort.Strings(names)
			parts = append(parts, "with reviewed class(es) "+strings.Join(names, ", ")+", which a review, not the grammar, covers")
		}
	}
	parts = append(parts, p.layouts...)
	if len(p.arrays) > 0 {
		parts = append(parts, fmt.Sprintf("%d array(s) with no object dtype, so no pickle, each holding exactly shape x itemsize bytes: %s",
			len(p.arrays), strings.Join(firstN(p.arrays, 3), "; ")))
	}
	out := strings.Join(parts, ". ") + "."
	if p.pickles > 0 {
		out += " " + notCovered
	}
	return out
}

func tensorSummary(ts []*tensorInfo) string {
	count := map[string]int{}
	var shapes []string
	for _, t := range ts {
		count[t.dtype]++
		if len(shapes) < 3 {
			shapes = append(shapes, fmt.Sprint(t.shape))
		}
	}
	dtypes := make([]string, 0, len(count))
	for d, n := range count {
		dtypes = append(dtypes, fmt.Sprintf("%s x%d", d, n))
	}
	sort.Strings(dtypes)
	if len(ts) > len(shapes) {
		shapes = append(shapes, fmt.Sprintf("and %d more", len(ts)-len(shapes)))
	}
	return fmt.Sprintf("%d tensor(s) (%s), shapes %s", len(ts), strings.Join(dtypes, ", "), strings.Join(shapes, ", "))
}

func firstN(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(append([]string(nil), s[:n]...), fmt.Sprintf("and %d more", len(s)-n))
}

func patternList(fs []checks.Finding) string {
	var out []string
	seen := map[string]bool{}
	for _, f := range fs {
		if !seen[f.Pattern] {
			seen[f.Pattern] = true
			out = append(out, f.Pattern)
		}
	}
	return strings.Join(out, ", ")
}

func excerpt(s string) string {
	if len(s) > 100 {
		return s[:100] + "..."
	}
	return s
}
