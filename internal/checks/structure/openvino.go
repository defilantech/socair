package structure

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/openvino"
)

// The OpenVINO IR rules. docs/openvino.md gives the sources for each.

// ValidateOpenVINO checks the OpenVINO IR whose .xml is at rel, a
// slash-separated path inside root, the directory the scan holds. Its
// weights are the .bin OpenVINO reads for it: the same path with the
// extension replaced by .bin.
func ValidateOpenVINO(root, rel string) checks.Result {
	r := checks.Result{Name: "Format and structure", LooksFor: "Malformed container structure, unexpected tensors"}
	return validateOpenVINO(r, filepath.Join(root, filepath.FromSlash(rel)), &modelDir{root: root, rel: rel})
}

// irVersions are the IR versions OpenVINO 2026.4.1's IR frontend reads
// (FrontEnd::supported_impl).
var irVersions = map[int64]bool{10: true, 11: true}

// byteRange is one Const's range in the .bin.
type byteRange struct {
	start, end int64
	where      string
}

func validateOpenVINO(r checks.Result, p string, dir *modelDir) checks.Result {
	m, err := openvino.Read(p)
	if err != nil {
		var pe *openvino.ParseError
		r.Status = checks.NotTested
		if errors.As(err, &pe) {
			r.Notes = "could not parse the OpenVINO IR, so its structure was not checked: " + err.Error()
		} else {
			r.Notes = "could not read the OpenVINO IR, so its structure was not checked: " + reasonOf(err)
		}
		return r
	}
	g := &grade{perPat: map[string]int{}, gapCount: map[string]*gapGroup{}}
	if v, err := strconv.ParseInt(m.Version, 10, 64); !m.VersionOK || err != nil || !irVersions[v] {
		g.gap(fmt.Sprintf("IR version %s, which OpenVINO 2026.4.1 does not read (it reads 10 and 11)", strconv.Quote(clip(m.Version, 20))), "")
	}
	for _, d := range m.Duplicates {
		g.fail("duplicate-key", d, "the IR is read differently by different readers: a repeated attribute is malformed XML, and of a repeated layer id OpenVINO builds one layer and drops the other")
	}
	for _, s := range m.Malformed {
		g.gap("malformed IR: "+s, "")
	}
	for _, s := range m.Unread {
		g.gap("not read: "+s, "")
	}
	if m.UnbuiltCount > 0 {
		g.gap(fmt.Sprintf("%d layer(s) OpenVINO does not build (no output depends on them, a later layer took their id, or they are in a body OpenVINO does not read), so their Consts are not read and their types were not checked",
			m.UnbuiltCount), capList(m.Unbuilt, 3))
	}
	ranges, complete := g.consts(m)
	binNote := g.weights(m, ranges, complete, p, dir)
	opNote := g.irOps(m)

	r.Findings = g.findings
	summary := fmt.Sprintf("OpenVINO IR v%s%s: %d layer(s) in %d graph(s)%s, %d built; operations: %s; %s",
		clip(m.Version, 20), irName(m), m.Layers, m.Graphs, irNesting(m), m.Built, opNote, binNote)
	gaps := g.gapNotes()
	switch {
	case g.fails > 0:
		r.Status = checks.Fail
		parts := []string{fmt.Sprintf("%d structure violation(s)", g.fails)}
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
		r.Notes = "OpenVINO IR parsed but could not be fully checked: " + strings.Join(gaps, "; ") + ". " + summary
	default:
		r.Status = checks.Pass
		held := "The model has no Const, so it reads no weights"
		if len(m.Consts) > 0 {
			held = "Every Const lies inside " + path.Base(openvino.WeightsPath(filepath.ToSlash(p))) +
				" and is exactly the size its element type and shape take, and the Consts' ranges cover the file with no byte outside them and none partly overlapping"
		}
		r.Notes = summary + ". " + held + ". " + openvinoLimits
	}
	return r
}

// openvinoLimits says what an OpenVINO IR PASS does not cover.
const openvinoLimits = "Tensor values are not read. An OpenVINO IR holds no code; a runtime builds an operation outside OpenVINO's opsets " +
	"only from an extension library the deployment registers, which is outside the model and this scan"

func irName(m *openvino.Model) string {
	if m.Name == "" {
		return ""
	}
	return " " + strconv.Quote(clip(m.Name, 60))
}

func irNesting(m *openvino.Model) string {
	if m.MaxNesting == 0 {
		return ""
	}
	return fmt.Sprintf(", bodies nested %d deep", m.MaxNesting)
}

// consts checks each built Const's size against its element type and shape,
// and returns the ranges it declares in the .bin and whether every Const
// declared one.
func (g *grade) consts(m *openvino.Model) ([]byteRange, bool) {
	var ranges []byteRange
	complete := true
	for _, c := range m.Consts {
		if c.Problem != "" {
			g.gap(c.Problem, c.Where)
			complete = false
			continue
		}
		if c.Offset > (1<<63-1)-c.Size {
			g.gap("a Const whose offset and size overflow", c.Where)
			complete = false
			continue
		}
		ranges = append(ranges, byteRange{c.Offset, c.Offset + c.Size, c.Where})
		et := openvino.ElementTypes[c.ElementType]
		n, ok := elements(c.Shape)
		if !ok {
			g.gap("shape "+dimsString(c.Shape)+" whose element count overflows", c.Where)
			continue
		}
		switch et.Packing {
		case openvino.Dynamic:
			g.gap("a Const of element type "+strconv.Quote(c.ElementType)+", which holds no defined data, so its size was not checked", c.Where)
			continue
		case openvino.Strings:
			g.gap("a string Const, whose packed strings were not read, so its size was not checked against its shape", c.Where)
			continue
		}
		want, okWant := openvino.MemorySize(et, n)
		least, okLeast := openvino.MinSize(et, n)
		if !okWant || !okLeast {
			g.gap("shape "+dimsString(c.Shape)+" whose byte size overflows", c.Where)
			continue
		}
		// An empty Constant's buffer is one byte: AlignedBuffer allocates
		// at least one, and the writer writes the buffer's size.
		if c.Size == want || n == 0 && c.Size == 1 {
			continue
		}
		var why string
		switch {
		case c.Size < least:
			why = "OpenVINO refuses it (\"Attribute and shape size are inconsistent\")"
		case c.Size < want:
			why = fmt.Sprintf("OpenVINO's reader accepts it, but %s packs its elements in whole 3-byte groups, and its data is short of the last group", c.ElementType)
		default:
			why = fmt.Sprintf("OpenVINO loads it, and the %d byte(s) past what its type and shape take are read as no value: OpenVINO's writer never writes them, and unaccounted bytes can hide a payload", c.Size-want)
		}
		g.fail("tensor-size", c.Where, fmt.Sprintf("size is %d bytes; shape %s of %s takes %d. %s",
			c.Size, dimsString(c.Shape), c.ElementType, want, why))
	}
	return ranges, complete
}

// weights checks the Consts' ranges against the .bin: in a directory scan,
// that the file is there, that every range lies inside it, and that the
// ranges cover it with no gap and no partial overlap. It returns the
// summary's note on the weights.
func (g *grade) weights(m *openvino.Model, ranges []byteRange, complete bool, p string, dir *modelDir) string {
	n := len(m.Consts)
	if dir == nil {
		bin := path.Base(openvino.WeightsPath(filepath.ToSlash(p)))
		if n == 0 {
			return "no Const"
		}
		g.gap(fmt.Sprintf("%d Const(s) keep their data in %s, outside a single-file scan: scan the model's directory to check it", n, bin), "")
		return fmt.Sprintf("%d Const(s), their data in %s", n, bin)
	}
	binRel := openvino.WeightsPath(dir.rel)
	root, err := os.OpenRoot(dir.root)
	if err != nil {
		g.gap(binRel+" could not be opened in the directory", "")
		return fmt.Sprintf("%d Const(s)", n)
	}
	defer root.Close()
	fi, err := root.Stat(filepath.FromSlash(binRel))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if n == 0 {
			return "no Const and no " + binRel
		}
		g.gap(binRel+" is not in the directory: OpenVINO refuses a model whose Consts have no weights file, and their ranges were not checked", "")
		return fmt.Sprintf("%d Const(s), no %s", n, binRel)
	case err != nil:
		g.gap(binRel+" could not be read ("+reasonOf(err)+")", "")
		return fmt.Sprintf("%d Const(s)", n)
	case !fi.Mode().IsRegular():
		g.gap(binRel+" is not a regular file", "")
		return fmt.Sprintf("%d Const(s)", n)
	}
	size := fi.Size()
	inside := true
	for _, rg := range ranges {
		if rg.start > size || rg.end > size {
			g.gap(fmt.Sprintf("Const data runs past the end of %s (%d bytes): truncated, or not the file the model was written with; OpenVINO refuses it", binRel, size),
				fmt.Sprintf("%s at [%d, %d)", rg.where, rg.start, rg.end))
			inside = false
		}
	}
	distinct := coverage(g, ranges, size, binRel, complete && inside)
	return fmt.Sprintf("%d Const(s) in %d distinct range(s) of %s (%d bytes)", n, distinct, binRel, size)
}

// coverage finds the bytes of the .bin outside every range and the ranges
// that partly overlap, when every Const's range is known and inside the
// file, and returns how many distinct ranges there are. OpenVINO's writer
// (ConstantWriter::write) appends each Const's bytes in turn and gives a
// Const whose bytes and size match an earlier one's the same range, so
// neither occurs in what it writes.
func coverage(g *grade, ranges []byteRange, size int64, binRel string, check bool) int {
	sorted := append([]byteRange(nil), ranges...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].start != sorted[j].start {
			return sorted[i].start < sorted[j].start
		}
		return sorted[i].end < sorted[j].end
	})
	distinct := 0
	var gaps, overlaps []string
	var gapBytes int64
	end := int64(0)
	var last byteRange // the range reaching furthest so far
	for i, rg := range sorted {
		if i > 0 && rg.start == sorted[i-1].start && rg.end == sorted[i-1].end {
			continue // a shared range, as the writer gives identical Consts
		}
		distinct++
		if rg.start == rg.end {
			continue
		}
		if rg.start > end {
			gaps = append(gaps, fmt.Sprintf("[%d, %d)", end, rg.start))
			gapBytes += rg.start - end
		}
		if rg.start < end {
			overlaps = append(overlaps, fmt.Sprintf("%s at [%d, %d) and %s at [%d, %d)", last.where, last.start, last.end, rg.where, rg.start, rg.end))
		}
		if rg.end > end {
			end = rg.end
			last = rg
		}
	}
	if !check {
		return distinct
	}
	if size > end {
		gaps = append(gaps, fmt.Sprintf("[%d, %d)", end, size))
		gapBytes += size - end
	}
	if len(gaps) > 0 {
		g.gap(fmt.Sprintf("%d byte(s) of %s, in %d range(s), are outside every Const: OpenVINO never reads them, its writer leaves none, and they were not inspected",
			gapBytes, binRel, len(gaps)), capList(gaps, 3))
	}
	if len(overlaps) > 0 {
		g.gap("Const ranges that partly overlap, which OpenVINO's writer never writes (it shares a range only between Consts of identical bytes and size)",
			capList(overlaps, 2))
	}
	return distinct
}

// irOps grades the operations built layers name: OpenVINO's own opsets, or
// an extension the deployment registers. It returns the summary's note.
func (g *grade) irOps(m *openvino.Model) string {
	used := map[string]int{}
	var usedOrder []string
	custom := map[string][]string{}
	var customOrder []string
	for _, op := range m.Ops {
		set, ok := openvino.Standard(op.Version, op.Type)
		if ok {
			if used[set] == 0 {
				usedOrder = append(usedOrder, set)
			}
			used[set]++
			continue
		}
		if _, seen := custom[op.Version]; !seen {
			customOrder = append(customOrder, op.Version)
		}
		custom[op.Version] = append(custom[op.Version], clip(op.Type, 60))
	}
	for _, v := range customOrder {
		g.gap(fmt.Sprintf("operations of version %s, which OpenVINO's opsets (opset1 to opset17 in 2026.4.1) do not define: a runtime builds them only from an extension library the deployment registers, native code outside the model that was not inspected",
			strconv.Quote(clip(v, 40))), capList(custom[v], 5))
	}
	sort.Slice(usedOrder, func(i, j int) bool { return opsetNumber(usedOrder[i]) < opsetNumber(usedOrder[j]) })
	parts := make([]string, 0, len(usedOrder))
	for _, s := range usedOrder {
		parts = append(parts, fmt.Sprintf("%s (%d type(s))", s, used[s]))
	}
	note := "none"
	if len(parts) > 0 {
		note = "OpenVINO's own, from " + strings.Join(parts, ", ")
	}
	if len(customOrder) > 0 {
		quoted := make([]string, len(customOrder))
		for i, v := range customOrder {
			quoted[i] = strconv.Quote(clip(v, 40))
		}
		if len(parts) == 0 {
			note = "versions " + strings.Join(quoted, ", ") + " only"
		} else {
			note += "; and versions " + strings.Join(quoted, ", ")
		}
	}
	return note
}

func opsetNumber(s string) int {
	n, _ := strconv.Atoi(strings.TrimPrefix(s, "opset"))
	return n
}
