// Package convert rebuilds a torch.save checkpoint as a safetensors file
// without unpickling it.
//
// The pickle check's grammar (socair-wo/1) models data.pkl as typed values:
// it proves the pickle builds only tensors and plain containers and matches
// every storage to a record of exactly its size. A checkpoint it PASSes is
// read from that model (pickle.ReadStateDict): each tensor's dtype, shape,
// stride, storage offset, and storage record. The converter copies each
// tensor's bytes straight from its record into a safetensors file. No pickle
// is run, and nothing outside the grammar's model is trusted.
//
// What it converts, and what it refuses with a named reason, is versioned as
// Rules:
//
//   - A torch.save zip (PyTorch's format since 1.6) whose root is a dict of
//     names to tensors. A legacy stream or tar, a nested dict, and a value
//     that is not a tensor are refused.
//   - Tensors in the dtypes of the table below, contiguous by c10's rule
//     (c10/core/Contiguity.h: a dimension of size 1 may have any stride), at
//     any storage offset. Non-contiguous views, other dtypes, a tensor without
//     storage, one with torch's conj or neg bit set, and one with Python
//     attributes are refused.
//   - Little-endian storages: a byteorder record of "little", or none, which
//     torch.load reads as little-endian by default. "big" is refused.
//   - Uncompressed storage records whose CRC-32 holds, as torch.save writes
//     them. torch.load does not check the CRC-32 (PyTorch builds miniz with
//     MINIZ_DISABLE_ZIP_READER_CRC32_CHECKS); other readers stop, so a
//     mismatch is refused.
//   - Tensors that share a storage are written as safetensors' own tools
//     write them: views that do not overlap each as its own tensor; exact
//     aliases (the same bytes, dtype, and shape, such as tied weights) once,
//     under the first name in byte order, with each other name recorded in
//     __metadata__ as name: kept name, as safetensors.torch.save_model does.
//     Views that overlap without being exact aliases are refused.
//
// The output follows the safetensors serializer (safetensors/src/tensor.rs,
// prepare): tensors sorted by dtype alignment, largest first, then by name;
// a JSON header with __metadata__ first, padded with spaces to a multiple of
// 8 bytes; and data sections that tile the buffer. __metadata__ holds
// "format": "pt", as transformers and safetensors' convert.py write it. The
// output is byte-stable for a given input.
package convert

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/defilantech/socair/internal/checks/pickle"
)

// Rules names what the converter converts, what it refuses, and the output
// layout. It changes whenever the output for an input, or whether an input
// is converted, could change.
const Rules = "socair-convert/1"

// Refused is an input the converter does not convert, with the reason.
type Refused struct{ Reason string }

func (e *Refused) Error() string { return "not converted: " + e.Reason }

func refuse(format string, a ...any) error {
	return &Refused{Reason: fmt.Sprintf(format, a...)}
}

// IsRefused reports whether err is a refusal, and its reason.
func IsRefused(err error) (string, bool) {
	var r *Refused
	if errors.As(err, &r) {
		return r.Reason, true
	}
	return "", false
}

// stDtype is a safetensors dtype: its name, its element size, and its rank in
// the serializer's Dtype enum, which is declared in increasing alignment.
type stDtype struct {
	name string
	size int64
	rank int
}

// dtypes maps the torch dtypes the stream names (a storage class's dtype, or
// the dtype argument of _rebuild_tensor_v3, aliases included) to safetensors
// dtypes. The pairs are safetensors' own (bindings/python/src/lib.rs,
// parse_dtype_str); the ranks are the Dtype enum's order
// (safetensors/src/tensor.rs).
var dtypes = map[string]stDtype{
	"bool":          {"BOOL", 1, 0},
	"uint8":         {"U8", 1, 4},
	"int8":          {"I8", 1, 5},
	"float8_e5m2":   {"F8_E5M2", 1, 6},
	"float8_e4m3fn": {"F8_E4M3", 1, 7},
	"int16":         {"I16", 2, 11},
	"short":         {"I16", 2, 11},
	"uint16":        {"U16", 2, 12},
	"float16":       {"F16", 2, 13},
	"half":          {"F16", 2, 13},
	"bfloat16":      {"BF16", 2, 14},
	"int32":         {"I32", 4, 15},
	"int":           {"I32", 4, 15},
	"uint32":        {"U32", 4, 16},
	"float32":       {"F32", 4, 17},
	"float":         {"F32", 4, 17},
	"float64":       {"F64", 8, 19},
	"double":        {"F64", 8, 19},
	"int64":         {"I64", 8, 20},
	"long":          {"I64", 8, 20},
	"uint64":        {"U64", 8, 21},
}

// maxHeader is the serializer's MAX_HEADER_SIZE: a reader refuses a longer
// header.
const maxHeader = 100_000_000

// Tensor is one tensor of the output, and where its bytes came from.
type Tensor struct {
	Name string
	// Dtype is the safetensors dtype, SourceDtype the torch dtype.
	Dtype, SourceDtype string
	Shape              []int64
	// Record is the zip record holding its bytes, Offset the byte offset in
	// it, and Size the byte count.
	Record       string
	Offset, Size int64
	// AliasOf names the tensor whose bytes it shares exactly; it is written
	// once, under that name.
	AliasOf string
	// Begin and End locate its bytes in the output's data section (an
	// alias: its kept tensor's).
	Begin, End int64
	// SHA256 is the hash of its bytes, the same in the input record and the
	// output. Write sets it.
	SHA256 string

	storage string
	rank    int
}

// Plan is a checkpoint the converter accepted, and the output it will write.
type Plan struct {
	path  string
	state *pickle.StateDict
	// written are the tensors in output order; aliases name a written one.
	written, aliases []*Tensor
	metadata         map[string]string
	header           []byte
	// Size is the output's size in bytes.
	Size int64
	// Records are the storage records the output reads, sorted.
	Records []string
	// ByteOrder says how the storages' byte order was established.
	ByteOrder string
	// NotCarried names what the output does not carry from the input.
	NotCarried []string
}

// PlanFile reads a checkpoint through the pickle grammar and plans its
// conversion. A checkpoint it does not convert is a *Refused.
func PlanFile(path string) (*Plan, error) {
	sd, err := pickle.ReadStateDict(path)
	if errors.Is(err, pickle.ErrNotStateDict) {
		return nil, refuse("%s", strings.TrimPrefix(err.Error(), pickle.ErrNotStateDict.Error()+": "))
	}
	if err != nil {
		return nil, err
	}
	p := &Plan{path: path, state: sd, metadata: map[string]string{"format": "pt"}}

	switch {
	case !sd.HasByteOrder:
		p.ByteOrder = "little (the checkpoint has no byteorder record; torch.load reads such a checkpoint as little-endian by default)"
	case sd.ByteOrder == "little":
		p.ByteOrder = "little (the byteorder record)"
	case sd.ByteOrder == "big":
		return nil, refuse("the storages are big-endian (the byteorder record says big); safetensors is little-endian and this converter does not swap bytes")
	default:
		return nil, refuse("a byteorder record holding %q, which torch.load rejects", sd.ByteOrder)
	}
	if len(sd.Tensors) == 0 {
		return nil, refuse("the state dict holds no tensors")
	}

	var all []*Tensor
	for _, st := range sd.Tensors {
		t, err := p.tensor(st)
		if err != nil {
			return nil, err
		}
		all = append(all, t)
	}
	shared, err := p.share(all)
	if err != nil {
		return nil, err
	}
	sort.Slice(p.written, func(i, j int) bool {
		a, b := p.written[i], p.written[j]
		if a.rank != b.rank {
			return a.rank > b.rank
		}
		return a.Name < b.Name
	})
	var at int64
	records := map[string]bool{}
	for _, t := range p.written {
		t.Begin, t.End = at, at+t.Size
		at = t.End
		if t.Size > 0 {
			records[t.Record] = true
		}
	}
	for r := range records {
		p.Records = append(p.Records, r)
	}
	sort.Strings(p.Records)
	byName := map[string]*Tensor{}
	for _, t := range p.written {
		byName[t.Name] = t
	}
	for _, a := range p.aliases {
		k := byName[a.AliasOf]
		a.Begin, a.End = k.Begin, k.End
		p.metadata[a.Name] = a.AliasOf
	}

	if p.header, err = p.headerJSON(); err != nil {
		return nil, err
	}
	p.Size = 8 + int64(len(p.header)) + at
	p.notCarried(shared, at)
	return p, nil
}

// tensor checks one state dict entry and places its bytes in its record.
func (p *Plan) tensor(st pickle.StateTensor) (*Tensor, error) {
	name := st.Name
	switch {
	case !utf8.ValidString(name):
		return nil, refuse("a tensor name that is not valid UTF-8 (%q), which a safetensors header cannot hold", name)
	case name == "__metadata__":
		return nil, refuse("a tensor named __metadata__, the safetensors header's metadata key")
	case st.Storage == "":
		return nil, refuse("%q has no storage (a meta tensor), so there are no bytes to write", name)
	case st.Metadata:
		return nil, refuse("%q sets torch's conj or neg bit (a metadata argument), which safetensors cannot record", name)
	case st.Attributes:
		return nil, refuse("%q carries Python attributes, which safetensors cannot record", name)
	case len(st.Shape) != len(st.Stride):
		return nil, refuse("%q has %d sizes and %d strides", name, len(st.Shape), len(st.Stride))
	}
	dt, ok := dtypes[st.Dtype]
	if !ok {
		return nil, refuse("%q is %s, which this converter does not map to a safetensors dtype", name, st.Dtype)
	}
	if dt.size != st.Itemsize {
		return nil, refuse("%q is %s with %d-byte elements, where %s has %d", name, st.Dtype, st.Itemsize, dt.name, dt.size)
	}
	numel, ok := product(st.Shape)
	if !ok {
		return nil, refuse("%q has a shape whose element count overflows", name)
	}
	if !contiguous(st.Shape, st.Stride, numel) {
		return nil, refuse("%q is not contiguous (size %v, stride %v); this converter writes only contiguous views", name, st.Shape, st.Stride)
	}
	s, ok := p.state.Storages[st.Storage]
	if !ok {
		return nil, refuse("%q names storage %s, which the stream does not reference", name, st.Storage)
	}
	have, ok := mul(s.Numel, s.Itemsize)
	if !ok {
		return nil, refuse("storage %s's size overflows", s.Key)
	}
	off, ok1 := mul(st.Offset, dt.size)
	size, ok2 := mul(numel, dt.size)
	if !ok1 || !ok2 || (numel > 0 && (off > have || size > have-off)) {
		return nil, refuse("%q views bytes past the end of storage %s", name, s.Key)
	}
	if numel == 0 {
		off = 0 // an empty tensor reads nothing
	}
	return &Tensor{Name: name, Dtype: dt.name, SourceDtype: st.Dtype, Shape: append([]int64(nil), st.Shape...),
		Record: s.Record, Offset: off, Size: size, storage: st.Storage, rank: dt.rank}, nil
}

// share splits tensors into those written and exact aliases, storage by
// storage, and returns how many written tensors share a storage with
// another.
func (p *Plan) share(all []*Tensor) (int, error) {
	byStorage := map[string][]*Tensor{}
	for _, t := range all {
		if t.Size == 0 {
			p.written = append(p.written, t)
			continue
		}
		byStorage[t.storage] = append(byStorage[t.storage], t)
	}
	keys := make([]string, 0, len(byStorage))
	for k := range byStorage {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	shared := 0
	for _, k := range keys {
		ts := byStorage[k]
		sort.Slice(ts, func(i, j int) bool {
			a, b := ts[i], ts[j]
			if a.Offset != b.Offset {
				return a.Offset < b.Offset
			}
			if a.Size != b.Size {
				return a.Size < b.Size
			}
			return a.Name < b.Name
		})
		var kept *Tensor
		regions := 0
		for _, t := range ts {
			switch {
			case kept != nil && t.Offset == kept.Offset && t.Size == kept.Size:
				if t.Dtype != kept.Dtype || !sameShape(t.Shape, kept.Shape) {
					return 0, refuse("%q and %q view the same bytes of storage %s as %s %v and %s %v; only exact aliases are written once",
						kept.Name, t.Name, k, kept.SourceDtype, kept.Shape, t.SourceDtype, t.Shape)
				}
				if t.Name == "format" {
					return 0, refuse("%q is an alias of %q, and its name would overwrite __metadata__'s format entry", t.Name, kept.Name)
				}
				t.AliasOf = kept.Name
				p.aliases = append(p.aliases, t)
			case kept != nil && t.Offset < kept.Offset+kept.Size:
				return 0, refuse("%q and %q view overlapping bytes of storage %s and are not exact aliases; this converter writes only disjoint views and exact aliases",
					kept.Name, t.Name, k)
			default:
				kept = t
				regions++
				p.written = append(p.written, t)
			}
		}
		if regions > 1 {
			shared += regions
		}
	}
	return shared, nil
}

// headerJSON writes the safetensors header: __metadata__ first, then each
// tensor in output order, padded with spaces to a multiple of 8 bytes.
func (p *Plan) headerJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteString(`{"__metadata__":{`)
	keys := make([]string, 0, len(p.metadata))
	for k := range p.metadata {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.Write(jsonString(k))
		b.WriteByte(':')
		b.Write(jsonString(p.metadata[k]))
	}
	b.WriteByte('}')
	for _, t := range p.written {
		b.WriteByte(',')
		b.Write(jsonString(t.Name))
		fmt.Fprintf(&b, `:{"dtype":%q,"shape":[`, t.Dtype)
		for i, d := range t.Shape {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprint(&b, d)
		}
		fmt.Fprintf(&b, `],"data_offsets":[%d,%d]}`, t.Begin, t.End)
	}
	b.WriteByte('}')
	for b.Len()%8 != 0 {
		b.WriteByte(' ')
	}
	if b.Len() > maxHeader {
		return nil, refuse("a header of %d bytes, over the %d bytes safetensors reads", b.Len(), maxHeader)
	}
	return b.Bytes(), nil
}

// jsonString encodes s as a JSON string, leaving <, >, and & as they are.
func jsonString(s string) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s) // a valid UTF-8 string always encodes
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}

// notCarried names what the output does not carry from the input.
func (p *Plan) notCarried(shared int, data int64) {
	p.NotCarried = append(p.NotCarried,
		"tensor types and flags: a Parameter is written as a tensor, and requires_grad and each storage's device are not recorded; safetensors stores a dtype, a shape, and bytes")
	if attrs := p.state.RootAttributes; len(attrs) > 0 {
		p.NotCarried = append(p.NotCarried, fmt.Sprintf("the state dict's own attributes (%s); a module state dict keeps each module's version in _metadata", strings.Join(attrs, ", ")))
	}
	if n := len(p.aliases); n > 0 {
		p.NotCarried = append(p.NotCarried, fmt.Sprintf("memory sharing: %d exact alias(es) are written once and named in __metadata__ (alias: kept tensor), as safetensors.torch.save_model records them", n))
	}
	if shared > 0 {
		p.NotCarried = append(p.NotCarried, fmt.Sprintf("the view relation between %d tensors that share a storage without overlapping: each is written as its own tensor", shared))
	}
	var total int64
	for _, s := range p.state.Storages {
		if n, ok := mul(s.Numel, s.Itemsize); ok {
			total += n
		}
	}
	if total > data {
		p.NotCarried = append(p.NotCarried, fmt.Sprintf("%d byte(s) of storage that no tensor views: torch.load reads them, and no tensor exposes them", total-data))
	}
}

// contiguous is c10's _compute_contiguous (c10/core/Contiguity.h): an empty
// tensor is contiguous, and otherwise each dimension of size other than 1
// has the stride of the dimensions after it.
func contiguous(size, stride []int64, numel int64) bool {
	if numel == 0 {
		return true
	}
	expected := int64(1)
	for d := len(size) - 1; d >= 0; d-- {
		if size[d] == 1 {
			continue
		}
		if stride[d] != expected {
			return false
		}
		expected *= size[d] // bounded by numel, which did not overflow
	}
	return true
}

func product(shape []int64) (int64, bool) {
	n := int64(1)
	for _, d := range shape {
		if d < 0 {
			return 0, false
		}
		var ok bool
		if n, ok = mul(n, d); !ok {
			return 0, false
		}
	}
	return n, true
}

func mul(a, b int64) (int64, bool) {
	if a < 0 || b < 0 {
		return 0, false
	}
	hi, lo := bits.Mul64(uint64(a), uint64(b))
	if hi != 0 || lo > math.MaxInt64 {
		return 0, false
	}
	return int64(lo), true
}

func sameShape(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
