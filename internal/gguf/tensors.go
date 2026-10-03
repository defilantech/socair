package gguf

import (
	"fmt"
	"io"
	"math/bits"
	"sort"
	"strings"
)

// TensorInfo is one entry of a GGUF tensor table.
type TensorInfo struct {
	Name   string
	Dims   []uint64
	Type   uint32
	Offset uint64 // relative to the start of the data section
}

// ggmlType is a tensor element type's block layout: block elements per block
// of size bytes. From ggml's type traits table (ggml/src/ggml.c).
type ggmlType struct {
	name  string
	block uint64
	size  uint64
}

// ggmlTypes covers the types llama.cpp writes. A type outside it is not
// malformed (new quantizations keep arriving) but its size cannot be checked.
var ggmlTypes = map[uint32]ggmlType{
	0:  {"F32", 1, 4},
	1:  {"F16", 1, 2},
	2:  {"Q4_0", 32, 18},
	3:  {"Q4_1", 32, 20},
	6:  {"Q5_0", 32, 22},
	7:  {"Q5_1", 32, 24},
	8:  {"Q8_0", 32, 34},
	9:  {"Q8_1", 32, 36},
	10: {"Q2_K", 256, 84},
	11: {"Q3_K", 256, 110},
	12: {"Q4_K", 256, 144},
	13: {"Q5_K", 256, 176},
	14: {"Q6_K", 256, 210},
	15: {"Q8_K", 256, 292},
	16: {"IQ2_XXS", 256, 66},
	17: {"IQ2_XS", 256, 74},
	18: {"IQ3_XXS", 256, 98},
	19: {"IQ1_S", 256, 50},
	20: {"IQ4_NL", 32, 18},
	21: {"IQ3_S", 256, 110},
	22: {"IQ2_S", 256, 82},
	23: {"IQ4_XS", 256, 136},
	24: {"I8", 1, 1},
	25: {"I16", 1, 2},
	26: {"I32", 1, 4},
	27: {"I64", 1, 8},
	28: {"F64", 1, 8},
	29: {"IQ1_M", 256, 56},
	30: {"BF16", 1, 2},
	34: {"TQ1_0", 256, 54},
	35: {"TQ2_0", 256, 66},
	39: {"MXFP4", 32, 17},
}

// TypeName is a ggml type's name, or "type N" when it is not in the table.
func TypeName(t uint32) string {
	if g, ok := ggmlTypes[t]; ok {
		return g.name
	}
	return fmt.Sprintf("type %d", t)
}

// Limits on the tensor table, from llama.cpp, so a hostile header cannot
// drive memory: GGML_MAX_DIMS is 4 and GGML_MAX_NAME is 64 bytes with its
// terminator.
const (
	maxTensors    = 1 << 20
	maxDims       = 4
	maxTensorName = 63
)

// readTensorInfos reads the tensor table that follows the metadata.
func readTensorInfos(r io.Reader, m *Manifest) error {
	if m.TensorCount > maxTensors {
		return fmt.Errorf("gguf: tensor count %d is over the %d limit", m.TensorCount, maxTensors)
	}
	// Grow with the entries actually read, not the count the header claims:
	// a few bytes claiming a million tensors must not cost a million slots.
	m.Tensors = make([]TensorInfo, 0, min(m.TensorCount, 1024))
	for i := uint64(0); i < m.TensorCount; i++ {
		name, err := readString(r)
		if err != nil {
			return fmt.Errorf("gguf: reading tensor %d name: %w", i, err)
		}
		nd, err := readU32(r)
		if err != nil {
			return fmt.Errorf("gguf: reading tensor %q dims: %w", name, err)
		}
		if nd > maxDims {
			return fmt.Errorf("gguf: tensor %q has %d dimensions, over ggml's %d", name, nd, maxDims)
		}
		t := TensorInfo{Name: name, Dims: make([]uint64, nd)}
		for d := range t.Dims {
			if t.Dims[d], err = readU64(r); err != nil {
				return fmt.Errorf("gguf: reading tensor %q dims: %w", name, err)
			}
		}
		if t.Type, err = readU32(r); err != nil {
			return fmt.Errorf("gguf: reading tensor %q type: %w", name, err)
		}
		if t.Offset, err = readU64(r); err != nil {
			return fmt.Errorf("gguf: reading tensor %q offset: %w", name, err)
		}
		m.Tensors = append(m.Tensors, t)
	}
	return nil
}

// tensorBytes is a tensor's data size, or why it cannot be computed.
func tensorBytes(t TensorInfo, g ggmlType) (uint64, string) {
	n := uint64(1)
	for _, d := range t.Dims {
		hi, lo := bits.Mul64(n, d)
		if hi != 0 {
			return 0, fmt.Sprintf("tensor %q dims %v overflow the element count", t.Name, t.Dims)
		}
		n = lo
	}
	if len(t.Dims) > 0 && t.Dims[0]%g.block != 0 {
		return 0, fmt.Sprintf("tensor %q first dimension %d is not a multiple of the %s block of %d", t.Name, t.Dims[0], g.name, g.block)
	}
	hi, lo := bits.Mul64(n/g.block, g.size)
	if hi != 0 {
		return 0, fmt.Sprintf("tensor %q dims %v overflow the byte size", t.Name, t.Dims)
	}
	return lo, ""
}

func alignUp(n, a uint64) uint64 {
	if a == 0 {
		return n
	}
	return (n + a - 1) / a * a
}

// Layout is the verdict on a GGUF's tensor table.
type Layout struct {
	// Violations are positive evidence the table does not describe the file:
	// repeated or over-long names, misaligned offsets, overlapping ranges,
	// gaps, or bytes no tensor accounts for.
	Violations []string
	// Unverified names what could not be checked, such as a type outside the
	// known table.
	Unverified []string
	// Truncated is set when tensor data runs past the end of the file, which
	// is a cut-short download as often as anything else.
	Truncated string
}

// ValidateLayout checks the tensor table against the file: each tensor's data
// is sized by its dims and type, aligned, and the tensors tile the data
// section with only alignment padding between them and after the last.
func (m *Manifest) ValidateLayout() Layout {
	var l Layout
	if m.Alignment == 0 || m.Alignment&(m.Alignment-1) != 0 {
		l.Violations = append(l.Violations, fmt.Sprintf("general.alignment %d is not a power of two", m.Alignment))
		return l
	}
	type span struct {
		name       string
		begin, end uint64
	}
	var spans []span
	seen := map[string]bool{}
	for _, t := range m.Tensors {
		if seen[t.Name] {
			l.Violations = append(l.Violations, fmt.Sprintf("tensor name %q is repeated", t.Name))
		}
		seen[t.Name] = true
		if len(t.Name) > maxTensorName {
			l.Violations = append(l.Violations, fmt.Sprintf("tensor name %q is longer than ggml's %d bytes", excerptName(t.Name), maxTensorName))
		}
		if t.Offset%m.Alignment != 0 {
			l.Violations = append(l.Violations, fmt.Sprintf("tensor %q offset %d is not aligned to %d", t.Name, t.Offset, m.Alignment))
		}
		g, ok := ggmlTypes[t.Type]
		if !ok {
			l.Unverified = append(l.Unverified, fmt.Sprintf("tensor %q has ggml type %d, outside the known table, so its size was not checked", t.Name, t.Type))
			continue
		}
		size, problem := tensorBytes(t, g)
		if problem != "" {
			l.Violations = append(l.Violations, problem)
			continue
		}
		spans = append(spans, span{t.Name, t.Offset, t.Offset + size})
	}
	if len(l.Violations) > 0 || len(l.Unverified) > 0 {
		sort.Strings(l.Violations)
		sort.Strings(l.Unverified)
		return l
	}

	dataBytes := uint64(0)
	if m.SizeBytes > m.DataOffset {
		dataBytes = uint64(m.SizeBytes - m.DataOffset)
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].begin < spans[j].begin })
	var at uint64
	last := ""
	for _, sp := range spans {
		switch {
		case sp.begin < at:
			l.Violations = append(l.Violations, fmt.Sprintf("tensor %q [%d,%d) overlaps %q, which runs to %d", sp.name, sp.begin, sp.end, last, at))
		case sp.begin > alignUp(at, m.Alignment):
			l.Violations = append(l.Violations, fmt.Sprintf("gap of %d unaccounted bytes before tensor %q", sp.begin-alignUp(at, m.Alignment), sp.name))
		}
		if sp.end > at {
			at, last = sp.end, sp.name
		}
	}
	switch {
	case at > dataBytes:
		l.Truncated = fmt.Sprintf("tensor data runs to %d bytes but the data section holds %d", at, dataBytes)
	case len(spans) > 0 && dataBytes > alignUp(at, m.Alignment):
		l.Violations = append(l.Violations, fmt.Sprintf("%d bytes after the last tensor are not covered by any tensor", dataBytes-alignUp(at, m.Alignment)))
	case len(spans) == 0 && dataBytes > m.Alignment:
		l.Violations = append(l.Violations, fmt.Sprintf("%d data bytes but no tensors", dataBytes))
	}
	sort.Strings(l.Violations)
	return l
}

// TypeShare is one tensor type's share of the tensor data.
type TypeShare struct {
	Type    string
	Bytes   uint64
	Tensors int
}

// TypeHistogram is the tensor data by ggml type, largest first: the
// quantization the file actually carries, whatever its labels say.
func (m *Manifest) TypeHistogram() []TypeShare {
	by := map[string]*TypeShare{}
	for _, t := range m.Tensors {
		name := TypeName(t.Type)
		s := by[name]
		if s == nil {
			s = &TypeShare{Type: name}
			by[name] = s
		}
		s.Tensors++
		if g, ok := ggmlTypes[t.Type]; ok {
			if n, problem := tensorBytes(t, g); problem == "" {
				s.Bytes += n
			}
		}
	}
	out := make([]TypeShare, 0, len(by))
	for _, s := range by {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Bytes != out[j].Bytes {
			return out[i].Bytes > out[j].Bytes
		}
		return out[i].Type < out[j].Type
	})
	return out
}

// HistogramString renders a histogram as "Q4_K 71%, Q6_K 22%, F32 7%".
func HistogramString(h []TypeShare) string {
	var total uint64
	for _, s := range h {
		total += s.Bytes
	}
	if total == 0 {
		return ""
	}
	parts := make([]string, 0, len(h))
	for _, s := range h {
		pct := float64(s.Bytes) * 100 / float64(total)
		if pct < 0.5 {
			parts = append(parts, s.Type+" <1%")
			continue
		}
		parts = append(parts, fmt.Sprintf("%s %.0f%%", s.Type, pct))
	}
	return strings.Join(parts, ", ")
}

func excerptName(s string) string {
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}
