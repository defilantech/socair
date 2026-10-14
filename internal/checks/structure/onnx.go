package structure

import (
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/onnx"
)

// The ONNX rules. docs/onnx.md gives the sources for each.

// onnxDomains are the operator domains ONNX itself defines
// (onnx/common/constants.h, v1.23.2). The reader reads "ai.onnx" as "".
var onnxDomains = map[string]bool{
	"": true, "ai.onnx.ml": true, "ai.onnx.training": true, "ai.onnx.preview": true, "ai.onnx.preview.training": true,
}

// runtimeDomain is onnxruntime's contrib operator domain (kMSDomain in
// include/onnxruntime/core/graph/constants.h). Its kernels are built into
// onnxruntime itself; they are not code the deployment adds.
const runtimeDomain = "com.microsoft"

// memoryTags are onnxruntime's in-process markers for tensor data already
// in memory (tensorprotoutils.h, v1.31.0). As a location they make
// onnxruntime read the address in offset; v1.31.0 refuses one in a model
// file, and v1.20.0 reads it.
var memoryTags = map[string]bool{"*/_ORT_MEM_ADDR_/*": true, "*/_ORT_NATIVE_ENDIAN_MEM_ADDR_/*": true}

var (
	windowsDrive = regexp.MustCompile(`^[A-Za-z]:`)
	decimal      = regexp.MustCompile(`^[0-9]{1,19}$`)
)

// maxFindingsPerPattern bounds the evidence one pattern contributes; the
// notes count the rest.
const maxFindingsPerPattern = 20

// ValidateONNX checks the ONNX model at rel, a slash-separated path inside
// root, the directory the scan holds. External data is resolved inside root,
// relative to the model's own directory, as onnx and onnxruntime resolve it.
func ValidateONNX(root, rel string) checks.Result {
	r := checks.Result{Name: "Format and structure", LooksFor: "Malformed container structure, unexpected tensors"}
	return validateONNX(r, filepath.Join(root, filepath.FromSlash(rel)), &modelDir{root: root, rel: rel})
}

// modelDir is the directory a directory scan holds.
type modelDir struct {
	root string // the snapshot root
	rel  string // the model's slash path inside it
}

// onnxGrade gathers what the rules found in one model.
type onnxGrade struct {
	findings []checks.Finding
	fails    int
	leads    int
	perPat   map[string]int
	dropped  int
	gapCount map[string]*gapGroup
	gapOrder []string
}

type gapGroup struct {
	reason string
	where  []string
	n      int
}

func (g *onnxGrade) fail(pattern, span, detail string) { g.add(pattern, span, detail); g.fails++ }
func (g *onnxGrade) lead(pattern, span, detail string) { g.add(pattern, span, detail); g.leads++ }

func (g *onnxGrade) add(pattern, span, detail string) {
	if g.perPat[pattern] >= maxFindingsPerPattern {
		g.dropped++
		return
	}
	g.perPat[pattern]++
	g.findings = append(g.findings, checks.Finding{Pattern: pattern, Span: span, Detail: detail})
}

// gap records a reason the model could not be fully checked; where names
// what it applies to, grouped so many tensors with one reason make one note.
func (g *onnxGrade) gap(reason, where string) {
	gg, ok := g.gapCount[reason]
	if !ok {
		gg = &gapGroup{reason: reason}
		g.gapCount[reason] = gg
		g.gapOrder = append(g.gapOrder, reason)
	}
	gg.n++
	if where == "" || len(gg.where) >= 3 {
		return
	}
	for _, w := range gg.where {
		if w == where {
			return
		}
	}
	gg.where = append(gg.where, where)
}

func (g *onnxGrade) gapNotes() []string {
	out := make([]string, 0, len(g.gapOrder))
	for _, reason := range g.gapOrder {
		gg := g.gapCount[reason]
		s := reason
		if len(gg.where) > 0 {
			s += " (" + strings.Join(gg.where, "; ")
			if gg.n > len(gg.where) {
				s += fmt.Sprintf("; and %d more", gg.n-len(gg.where))
			}
			s += ")"
		}
		out = append(out, s)
	}
	return out
}

func validateONNX(r checks.Result, p string, dir *modelDir) checks.Result {
	m, err := onnx.Read(p)
	if err != nil {
		var pe *onnx.ParseError
		if errors.As(err, &pe) {
			r.Status = checks.NotTested
			r.Notes = "could not parse the ONNX model, so its structure was not checked: " + err.Error()
			return r
		}
		r.Status = checks.NotTested
		r.Notes = "could not read the ONNX model, so its structure was not checked: " + reasonOf(err)
		return r
	}
	g := &onnxGrade{perPat: map[string]int{}, gapCount: map[string]*gapGroup{}}
	if !m.HasIRVersion {
		g.gap("the model has no ir_version, which onnx.proto requires", "")
	}
	if !m.HasGraph {
		g.gap("the model has no graph", "")
	}
	if len(m.Opsets) == 0 {
		g.gap("the model imports no opset, which onnx.proto requires", "")
	}
	if len(m.Unread) > 0 {
		g.gap("fields this reader does not model, which a loader keeps and does not read: "+strings.Join(m.Unread, "; "), "")
	}
	stats := g.tensors(m, dir)
	g.duplicateInitializers(m)
	g.epContexts(m, dir)
	opNote := g.operators(m)

	r.Findings = g.findings
	summary := fmt.Sprintf("ONNX IR v%d%s, opsets %s: %d node(s) in %d graph(s)%s; %d tensor(s) %s; operators: %s",
		m.IRVersion, producerNote(m), opsetsNote(m.Opsets), m.Nodes, m.Graphs, nestingNote(m),
		len(m.Tensors), stats.note(), opNote)
	gaps := g.gapNotes()
	switch {
	case g.fails > 0 || g.leads > 0:
		r.Status = checks.Lead
		if g.fails > 0 {
			r.Status = checks.Fail
		}
		parts := []string{fmt.Sprintf("%d structure violation(s) and %d ambiguous external data reference(s)", g.fails, g.leads)}
		if g.dropped > 0 {
			parts = append(parts, fmt.Sprintf("%d more finding(s) not listed", g.dropped))
		}
		parts = append(parts, summary)
		if len(gaps) > 0 {
			parts = append(parts, "also not checked: "+strings.Join(gaps, "; "))
		}
		r.Notes = strings.Join(parts, ". ")
	case len(gaps) > 0:
		r.Status = checks.NotTested
		r.Notes = "ONNX model parsed but could not be fully checked: " + strings.Join(gaps, "; ") + ". " + summary
	default:
		r.Status = checks.Pass
		held := "Every tensor's data matches its dims and type"
		if stats.external > 0 {
			held += ", and all external data is inside the model's directory and fits its file"
		}
		r.Notes = summary + ". " + held + ". " + onnxLimits
	}
	return r
}

// onnxLimits says what an ONNX PASS does not cover.
const onnxLimits = "Tensor values are not read. ONNX runs no Python; a runtime runs an operator outside ONNX's and onnxruntime's own " +
	"only from a native library the deployment registers, which is outside the model and this scan"

func reasonOf(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

func producerNote(m *onnx.Model) string {
	p := strings.TrimSpace(m.Producer + " " + m.ProducerVersion)
	if p == "" {
		return ""
	}
	return " from " + strconv.Quote(clip(p, 60))
}

// opsetsNote lists the model's opset imports, each domain cut short, at most
// ten: the notes carry what the model says, bounded.
func opsetsNote(opsets []onnx.Opset) string {
	if len(opsets) == 0 {
		return "none"
	}
	shown := make([]onnx.Opset, 0, 10)
	for i, o := range opsets {
		if i == 10 {
			break
		}
		o.Domain = clip(o.Domain, 60)
		shown = append(shown, o)
	}
	n := onnx.JoinOpsets(shown)
	if len(opsets) > len(shown) {
		n += fmt.Sprintf(" and %d more", len(opsets)-len(shown))
	}
	return n
}

func nestingNote(m *onnx.Model) string {
	if m.MaxNesting == 0 {
		return ""
	}
	return fmt.Sprintf(", subgraphs nested %d deep", m.MaxNesting)
}

// clip cuts s to at most n bytes, at a character boundary.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "..."
}

type tensorStats struct {
	inline, external, externalChecked int
	files                             map[string]bool
	checksums                         int
	// outside are the external data files of a single-file scan, with how
	// many tensors each holds.
	outside map[string]int
}

func (s tensorStats) note() string {
	n := fmt.Sprintf("(%d inline", s.inline)
	if s.external > 0 {
		n += fmt.Sprintf(", %d in external data", s.external)
		if s.externalChecked > 0 {
			files := make([]string, 0, len(s.files))
			for f := range s.files {
				files = append(files, f)
			}
			sort.Strings(files)
			n += fmt.Sprintf(", %d of them found within %s", s.externalChecked, capList(files, 3))
		}
		if s.checksums > 0 {
			n += fmt.Sprintf("; %d external_data checksum(s) not verified", s.checksums)
		}
	}
	return n + ")"
}

func capList(items []string, max int) string {
	if len(items) <= max {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:max], ", ") + fmt.Sprintf(" and %d more", len(items)-max)
}

// elements is a tensor's element count, or false when a dim is negative or
// the product overflows.
func elements(dims []int64) (int64, bool) {
	n := int64(1)
	for _, d := range dims {
		if d < 0 {
			return 0, false
		}
		if d != 0 && n > math.MaxInt64/d {
			return 0, false
		}
		n *= d
	}
	return n, true
}

// rawBytes is the raw_data size of n elements of dt: ceil(n*bits/8).
func rawBytes(n int64, dt onnx.DType) (int64, bool) {
	if dt.Bits == 0 || n > (math.MaxInt64-7)/dt.Bits {
		return 0, false
	}
	return (n*dt.Bits + 7) / 8, true
}

func dimsString(dims []int64) string {
	parts := make([]string, len(dims))
	for i, d := range dims {
		parts[i] = strconv.FormatInt(d, 10)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// tensors checks every tensor's data against its type and shape, and every
// external data reference.
func (g *onnxGrade) tensors(m *onnx.Model, dir *modelDir) tensorStats {
	st := tensorStats{files: map[string]bool{}, outside: map[string]int{}}
	var root *os.Root
	if dir != nil {
		if rt, err := os.OpenRoot(dir.root); err == nil {
			root = rt
			defer rt.Close()
		}
	}
	for i := range m.Tensors {
		t := &m.Tensors[i]
		ext := g.externalEntries(t)
		if t.Location == 1 {
			st.external++
			if ext.checksum {
				st.checksums++
			}
		} else {
			st.inline++
			if len(t.External) > 0 {
				g.gap("external_data entries on a tensor not marked EXTERNAL, which loaders ignore", t.Where)
			}
		}
		if !t.HasDataType || t.DataType == 0 {
			g.gap("a tensor with no data type, which loaders refuse", t.Where)
			continue
		}
		dt, ok := onnx.DTypes[t.DataType]
		if !ok {
			g.gap(fmt.Sprintf("data type %d, which onnx.proto v1.23.2 does not define, so its size was not checked", t.DataType), t.Where)
			continue
		}
		n, ok := elements(t.Dims)
		if !ok {
			g.gap("dims "+dimsString(t.Dims)+" with a negative or overflowing size", t.Where)
			continue
		}
		if t.Segment {
			g.gap("a segment (one part of a tensor), which loaders do not assemble and this check does not model", t.Where)
			continue
		}
		if t.Location == 1 {
			switch file, found := g.externalData(t, dt, n, ext, dir, root); {
			case found:
				st.externalChecked++
				st.files[file] = true
			case file != "":
				st.outside[file]++
			}
			continue
		}
		g.inlineData(t, dt, n)
	}
	if len(st.outside) > 0 {
		files := make([]string, 0, len(st.outside))
		count := 0
		for f, k := range st.outside {
			files = append(files, f)
			count += k
		}
		sort.Strings(files)
		g.gap(fmt.Sprintf("%d tensor(s) keep their data in %s, outside a single-file scan: scan the model's directory to check it", count, capList(files, 3)), "")
	}
	return st
}

// inlineData checks a tensor whose data is in the model file.
func (g *onnxGrade) inlineData(t *onnx.Tensor, dt onnx.DType, n int64) {
	var present []onnx.Field
	if t.HasRaw {
		present = append(present, onnx.FieldRaw)
	}
	for _, f := range onnx.TypedFields {
		if t.Count(f) > 0 {
			present = append(present, f)
		}
	}
	switch {
	case n == 0:
		if len(present) > 0 && !(len(present) == 1 && present[0] == onnx.FieldRaw && t.RawBytes == 0) {
			g.fail("tensor-size", t.Where, fmt.Sprintf("dims %s hold no elements but the tensor carries data in %s; onnx's checker refuses it", dimsString(t.Dims), fieldList(present)))
		}
		return
	case len(present) == 0:
		g.fail("tensor-size", t.Where, fmt.Sprintf("dims %s of %s hold %d element(s) but the tensor carries no data; loaders refuse it", dimsString(t.Dims), dt.Name, n))
		return
	case len(present) > 1:
		g.fail("tensor-data", t.Where, fmt.Sprintf("data in %s: onnxruntime reads %s and ignores the rest, and onnx's checker refuses it", fieldList(present), present[0]))
		return
	}
	f := present[0]
	if f == onnx.FieldRaw {
		if t.DataType == onnx.DataTypeString {
			g.fail("tensor-data", t.Where, "a STRING tensor in raw_data, which holds no strings: loaders read string_data and onnx's checker refuses it")
			return
		}
		want, ok := rawBytes(n, dt)
		if !ok {
			g.gap("dims "+dimsString(t.Dims)+" whose byte size overflows", t.Where)
			return
		}
		if t.RawBytes != want {
			g.fail("tensor-size", t.Where, fmt.Sprintf("raw_data holds %d bytes; dims %s of %s need %d. onnxruntime refuses it, and unaccounted bytes can hide a payload",
				t.RawBytes, dimsString(t.Dims), dt.Name, want))
		}
		return
	}
	if f != dt.Field {
		g.fail("tensor-data", t.Where, fmt.Sprintf("data in %s, which a %s tensor does not use (its values go in %s or raw_data); loaders refuse it", f, dt.Name, dt.Field))
		return
	}
	if dt.PerElement == 0 {
		g.gap("a 4-bit or 2-bit tensor in int32_data, whose entry count onnx.proto (two or four elements an entry) and onnx's checker (eight or sixteen) state differently, so its size was not checked", t.Where)
		return
	}
	want := n * dt.PerElement
	if n > math.MaxInt64/dt.PerElement {
		g.gap("dims "+dimsString(t.Dims)+" whose entry count overflows", t.Where)
		return
	}
	if got := t.Count(f); got != want {
		g.fail("tensor-size", t.Where, fmt.Sprintf("%s holds %d entries; dims %s of %s need %d. onnxruntime refuses it", f, got, dimsString(t.Dims), dt.Name, want))
	}
}

func fieldList(fs []onnx.Field) string {
	parts := make([]string, len(fs))
	for i, f := range fs {
		parts[i] = string(f)
	}
	return strings.Join(parts, " and ")
}

// extInfo is what a tensor's external_data entries say.
type extInfo struct {
	location, offset, length string
	hasLocation, hasOffset   bool
	hasLength, checksum      bool
	clean                    bool   // the location is a clean relative path
	resolved                 string // the file it names, slash path inside the directory
}

// externalEntries reads a tensor's external_data, checking every location
// whatever data_location says: a location that leaves the model's directory
// is evidence of an attempt to read outside it.
func (g *onnxGrade) externalEntries(t *onnx.Tensor) extInfo {
	var e extInfo
	if len(t.External) == 0 {
		return e
	}
	count := map[string]int{}
	for _, en := range t.External {
		count[en.Key]++
		switch en.Key {
		case "location":
			e.location, e.hasLocation = en.Value, true
			g.location(t.Where, en.Value)
		case "offset":
			e.offset, e.hasOffset = en.Value, true
		case "length":
			e.length, e.hasLength = en.Value, true
		case "checksum":
			e.checksum = true
		default:
			g.gap(fmt.Sprintf("external_data key %s, which onnxruntime refuses and onnx ignores", strconv.Quote(clip(en.Key, 40))), t.Where)
		}
	}
	if count["location"] > 1 {
		g.fail("duplicate-key", t.Where+" external_data location",
			"the location key is repeated: onnx's loader takes the last and onnxruntime refuses a second, so loaders read different files")
	}
	if e.hasLocation && count["location"] == 1 {
		if c, _, clean := classifyLocation(e.location); c == locOK {
			e.clean = true
			e.resolved = clean
		}
	}
	return e
}

type locClass int

const (
	locOK locClass = iota
	locEmpty
	locEscape
	locMemory
	locAmbiguous
)

// classifyLocation reads an external data location as onnx and onnxruntime
// would on any system: '/' and '\' both as separators (onnxruntime on
// Windows reads '\' as one), a drive letter as a root.
func classifyLocation(loc string) (locClass, string, string) {
	switch {
	case loc == "":
		return locEmpty, "is empty", ""
	case memoryTags[loc]:
		return locMemory, "", ""
	case strings.HasPrefix(loc, "/") || strings.HasPrefix(loc, `\`):
		return locEscape, "is an absolute path", ""
	case windowsDrive.MatchString(loc):
		return locEscape, "names a Windows drive", ""
	}
	for _, c := range loc {
		if c < 0x20 || c == 0x7f {
			return locAmbiguous, "holds a control character, which ends the path early for some readers and not others", ""
		}
	}
	depth, dotdot := 0, false
	for _, part := range strings.FieldsFunc(loc, func(r rune) bool { return r == '/' || r == '\\' }) {
		switch part {
		case ".":
		case "..":
			dotdot = true
			depth--
			if depth < 0 {
				return locEscape, "climbs out of the model's directory with '..'", ""
			}
		default:
			depth++
		}
	}
	switch {
	case dotdot:
		return locAmbiguous, "holds a '..' component, which the ONNX spec disallows; it stays inside the directory as text, but resolves elsewhere when a link is on its path", ""
	case strings.Contains(loc, `\`):
		return locAmbiguous, "holds a backslash, a separator on Windows and a file-name character elsewhere, so runtimes on different systems read different files", ""
	case strings.Contains(loc, ":"):
		return locAmbiguous, "holds a colon, which on Windows names an alternate data stream of a file", ""
	}
	clean := path.Clean(loc)
	if clean == "." {
		return locAmbiguous, "names the model's directory itself, not a file", ""
	}
	return locOK, "", clean
}

// location grades one location value.
func (g *onnxGrade) location(where, loc string) {
	c, why, _ := classifyLocation(loc)
	q := strconv.Quote(clip(loc, 120))
	switch c {
	case locEmpty:
		g.gap("external data with an empty location, which loaders refuse", where)
	case locEscape:
		g.fail("external-data-escape", where, "location "+q+" "+why+
			": a loader reads tensor data from a file outside the model (onnx before 1.16 and onnxruntime 1.20 follow it; CVE-2022-25882, CVE-2024-27318)")
	case locMemory:
		g.fail("external-data-memory", where, "location "+q+" is onnxruntime's marker for data already in its memory: "+
			"onnxruntime 1.20 reads the tensor from the address in offset. A model file never holds it, and onnxruntime 1.31 refuses it")
	case locAmbiguous:
		g.lead("external-data-path", where, "location "+q+" "+why)
	}
}

// externalData checks a tensor stored in an external file: its declared
// length, and, when the scan holds the model's directory, that the file is
// there and holds the tensor's bytes. It returns the file, as a path inside
// the directory (or as the location, in a single-file scan, with found
// false), and whether the tensor's bytes were found in it.
func (g *onnxGrade) externalData(t *onnx.Tensor, dt onnx.DType, n int64, e extInfo, dir *modelDir, root *os.Root) (string, bool) {
	if t.HasRaw || t.Floats+t.Int32s+t.Strings+t.Int64s+t.Doubles+t.Uint64s > 0 {
		g.fail("tensor-data", t.Where, "stored externally and also carries data in the model file, which onnxruntime does not read and onnx's checker refuses")
	}
	if t.DataType == onnx.DataTypeString {
		g.gap("a STRING tensor stored externally, which onnxruntime refuses", t.Where)
		return "", false
	}
	if !e.hasLocation {
		g.gap("external data with no location, which loaders refuse", t.Where)
		return "", false
	}
	if !e.clean {
		return "", false // graded by location
	}
	want, ok := rawBytes(n, dt)
	if !ok {
		g.gap("dims "+dimsString(t.Dims)+" whose byte size overflows", t.Where)
		return "", false
	}
	var off, length int64
	if e.hasOffset {
		v, ok := parseDecimal(e.offset)
		if !ok {
			g.gap("an external_data offset that is not a plain decimal number, which loaders parse differently", t.Where)
			return "", false
		}
		off = v
	}
	if e.hasLength {
		v, ok := parseDecimal(e.length)
		if !ok {
			g.gap("an external_data length that is not a plain decimal number, which loaders parse differently", t.Where)
			return "", false
		}
		length = v
	}
	switch {
	case e.hasLength && length == 0 && want > 0:
		g.gap("an external_data length of 0 for a tensor of more than 0 bytes: onnxruntime reads the tensor's size and onnx reads nothing", t.Where)
		return "", false
	case e.hasLength && length != want:
		g.fail("tensor-size", t.Where, fmt.Sprintf("external_data length is %d bytes; dims %s of %s need %d. onnxruntime refuses it",
			length, dimsString(t.Dims), dt.Name, want))
		return "", false
	}
	if dir == nil {
		return e.resolved, false
	}
	rel := path.Join(path.Dir(dir.rel), e.resolved)
	if root == nil || strings.HasPrefix(rel, "../") || rel == ".." {
		g.gap("external data file "+rel+" could not be opened in the directory", t.Where)
		return "", false
	}
	fi, err := root.Stat(filepath.FromSlash(rel))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		g.gap("external data file "+rel+" is not in the directory, so the tensors it holds were not checked", t.Where)
		return "", false
	case err != nil:
		g.gap("external data file "+rel+" could not be read ("+reasonOf(err)+")", t.Where)
		return "", false
	case !fi.Mode().IsRegular():
		g.gap("external data "+rel+" is not a regular file", t.Where)
		return "", false
	}
	if off > fi.Size() || want > fi.Size()-off {
		g.gap(fmt.Sprintf("external data runs past the end of %s (%d bytes): truncated, or not the file the model was written with", rel, fi.Size()),
			fmt.Sprintf("%s at [%d, %d)", t.Where, off, off+want))
		return "", false
	}
	return rel, true
}

func parseDecimal(s string) (int64, bool) {
	if !decimal.MatchString(s) {
		return 0, false
	}
	v, err := strconv.ParseInt(s, 10, 64)
	return v, err == nil
}

// duplicateInitializers finds a name given to two initializers of one graph.
// onnxruntime keeps the last and onnx's checker refuses the model, so which
// tensor a loader uses depends on the loader.
func (g *onnxGrade) duplicateInitializers(m *onnx.Model) {
	type key struct {
		graph int
		name  string
	}
	seen := map[key]int{}
	var order []key
	for _, t := range m.Tensors {
		if t.Graph < 0 || t.Name == "" || (t.Kind != onnx.Initializer && t.Kind != onnx.SparseValues) {
			continue
		}
		k := key{t.Graph, t.Name}
		if seen[k] == 0 {
			order = append(order, k)
		}
		seen[k]++
	}
	for _, k := range order {
		if seen[k] > 1 {
			g.fail("duplicate-key", strconv.Quote(clip(k.name, 80)), fmt.Sprintf("%d initializers of one graph share this name: onnxruntime uses the last and onnx's checker refuses the model", seen[k]))
		}
	}
}

// epContexts names each EPContext node: compiled code for an accelerator,
// embedded or in a file, that this scan does not read. A path is graded as
// a location is.
func (g *onnxGrade) epContexts(m *onnx.Model, dir *modelDir) {
	for _, ep := range m.EPContexts {
		where := ep.Where
		switch {
		case ep.EmbedMode == 0 && ep.ContextRead:
			g.location(where+" ep_cache_context", ep.Context)
			g.gap("an EPContext node, whose execution-provider context (compiled code for an accelerator) is in a file this scan does not read", where+": "+strconv.Quote(clip(ep.Context, 80)))
		case ep.EmbedMode == 0:
			g.gap("an EPContext node whose context path was not read", where)
		default:
			g.gap("an EPContext node, which embeds an execution-provider context (compiled code for an accelerator) this scan does not read", fmt.Sprintf("%s: %d bytes", where, ep.ContextBytes))
		}
	}
}

// operators names the operator domains nodes use. ONNX's own domains are
// standard. onnxruntime's contrib operators are named, not judged: their
// kernels are built into onnxruntime. Any other domain, unless it is a
// model-local function, needs a custom-operator library the deployment
// registers: native code outside the model, so a gap.
func (g *onnxGrade) operators(m *onnx.Model) string {
	local := map[onnx.Function]bool{}
	for _, f := range m.Functions {
		local[f] = true
	}
	var runtime []string
	custom := map[string][]string{}
	var customOrder []string
	localCalls := 0
	for _, op := range m.Ops {
		switch {
		case local[onnx.Function{Domain: op.Domain, Name: op.Type, Overload: op.Overload}]:
			localCalls += op.Count
		case onnxDomains[op.Domain]:
		case op.Domain == runtimeDomain:
			runtime = append(runtime, fmt.Sprintf("%s x%d", clip(op.Type, 60), op.Count))
		default:
			if _, ok := custom[op.Domain]; !ok {
				customOrder = append(customOrder, op.Domain)
			}
			custom[op.Domain] = append(custom[op.Domain], clip(op.Type, 60))
		}
	}
	for _, d := range customOrder {
		g.gap(fmt.Sprintf("operators in domain %s, which neither ONNX nor onnxruntime defines: a runtime runs them only from a custom-operator library the deployment registers, native code outside the model that was not inspected",
			strconv.Quote(clip(d, 60))), capList(custom[d], 5))
	}
	note := "ONNX's own"
	if len(runtime) > 0 {
		note += "; " + runtimeDomain + " (onnxruntime's contrib operators, built into onnxruntime; another runtime may lack them): " + capList(runtime, 8)
	}
	if localCalls > 0 {
		note += fmt.Sprintf("; %d call(s) to the model's %d local function(s), whose bodies were checked as nodes", localCalls, len(m.Functions))
	}
	if len(customOrder) > 0 {
		quoted := make([]string, len(customOrder))
		for i, d := range customOrder {
			quoted[i] = strconv.Quote(clip(d, 60))
		}
		note += "; custom domains " + strings.Join(quoted, ", ")
	}
	return note
}
