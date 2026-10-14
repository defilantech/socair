// Package pickletest builds torch.save checkpoints for tests.
//
// A checkpoint is written as torch.save writes one (torch/serialization.py's
// _save, at the pickle protocol 2 it uses by default): a zip of data.pkl, the
// metadata records, and one data/<key> record per storage. data.pkl is
// written as CPython's pickler writes it: the shortest integer opcode,
// BINUNICODE strings, and every memoizable object put into the next memo
// slot. Fixtures are generated, not committed, so they cannot rot silently,
// and they never execute: nothing here unpickles.
package pickletest

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"strconv"
)

// Checkpoint is a state dict and its storages.
type Checkpoint struct {
	// Ordered writes the root as a collections.OrderedDict, as
	// module.state_dict() returns it, with a _metadata attribute naming
	// one module's version.
	Ordered bool
	Tensors []Tensor
	// Storages are keyed by their index: "0", "1", ...
	Storages []Storage
	// ByteOrder is the byteorder record's content: "little" when empty,
	// and "-" leaves the record out.
	ByteOrder string
	// Deflate compresses the storage records, which torch.save never does.
	Deflate bool
	// Root, when set, replaces the root dict: it writes any value with the
	// writer and the checkpoint writes nothing else into data.pkl but PROTO
	// and STOP.
	Root func(*Writer)
}

// Storage is one storage: its dtype and its raw bytes.
type Storage struct {
	Dtype string
	Data  []byte
}

// Tensor is one entry of the state dict: a view of a storage.
type Tensor struct {
	Name    string
	Storage int
	// Dtype is the tensor's dtype; empty means the storage's. A dtype torch
	// writes with _rebuild_tensor_v3 (uint16, float8_e4m3fn, ...) is
	// written over an untyped storage.
	Dtype  string
	Shape  []int
	Stride []int // nil: contiguous
	Offset int   // in elements of Dtype
	// Metadata names keys of the tensor's metadata argument, each true, as
	// torch writes the conj and neg bits.
	Metadata []string
	// Param wraps the tensor in torch._utils._rebuild_parameter.
	Param bool
	// Hook writes one backward hook, which torch.save never writes.
	Hook bool
}

// storageClass is the legacy storage class torch.save names for a dtype
// (torch.storage._dtype_to_storage_type_map). Dtypes not here are written
// with _rebuild_tensor_v3 over an UntypedStorage (torch.storage._new_dtypes).
var storageClass = map[string]string{
	"float64": "DoubleStorage", "float32": "FloatStorage", "float16": "HalfStorage",
	"bfloat16": "BFloat16Storage", "int64": "LongStorage", "int32": "IntStorage",
	"int16": "ShortStorage", "int8": "CharStorage", "uint8": "ByteStorage", "bool": "BoolStorage",
	"complex64": "ComplexFloatStorage", "complex128": "ComplexDoubleStorage", "qint8": "QInt8Storage",
}

// Itemsize is a torch dtype's element size in bytes.
var Itemsize = map[string]int{
	"float64": 8, "float32": 4, "float16": 2, "bfloat16": 2, "int64": 8, "int32": 4, "int16": 2,
	"int8": 1, "uint8": 1, "bool": 1, "complex64": 8, "complex128": 16, "qint8": 1,
	"uint16": 2, "uint32": 4, "uint64": 8, "float8_e4m3fn": 1, "float8_e5m2": 1,
	"float8_e4m3fnuz": 1, "float8_e5m2fnuz": 1, "float8_e8m0fnu": 1, "complex32": 4,
}

// Untyped reports whether torch.save writes dtype over an UntypedStorage.
func Untyped(dtype string) bool {
	_, typed := storageClass[dtype]
	return !typed
}

// Zip writes the checkpoint as torch.save writes it.
func (c Checkpoint) Zip() []byte {
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	add := func(name string, data []byte, method uint16) {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: method})
		if err != nil {
			panic("pickletest: " + err.Error())
		}
		if _, err := w.Write(data); err != nil {
			panic("pickletest: " + err.Error())
		}
	}
	add("archive/data.pkl", c.Pickle(), zip.Store)
	add("archive/.format_version", []byte("1"), zip.Store)
	add("archive/.storage_alignment", []byte("64"), zip.Store)
	switch c.ByteOrder {
	case "":
		add("archive/byteorder", []byte("little"), zip.Store)
	case "-":
	default:
		add("archive/byteorder", []byte(c.ByteOrder), zip.Store)
	}
	method := zip.Store
	if c.Deflate {
		method = zip.Deflate
	}
	for i, s := range c.Storages {
		add("archive/data/"+strconv.Itoa(i), s.Data, method)
	}
	add("archive/version", []byte("3\n"), zip.Store)
	add("archive/.data/serialization_id", []byte("1234567890123456789012345678901234567890"), zip.Store)
	if err := zw.Close(); err != nil {
		panic("pickletest: " + err.Error())
	}
	return b.Bytes()
}

// Pickle writes data.pkl.
func (c Checkpoint) Pickle() []byte {
	p := NewWriter()
	if c.Root != nil {
		c.Root(p)
		return p.Stop()
	}
	if c.Ordered {
		p.Global("collections", "OrderedDict").Raw(")R").Put()
	} else {
		p.Raw("}").Put()
	}
	p.SetItems(len(c.Tensors), func(i int) {
		p.Str(c.Tensors[i].Name)
		c.tensor(p, c.Tensors[i])
	})
	if c.Ordered {
		// The state: {"_metadata": OrderedDict({"": {"version": 1}})}.
		p.Raw("}").Put().Str("_metadata")
		p.Global("collections", "OrderedDict").Raw(")R").Put()
		p.Str("").Raw("}").Put().Str("version").Int(1).Raw("s")
		p.Raw("s")
		p.Raw("s")
		p.Raw("b")
	}
	return p.Stop()
}

func (c Checkpoint) tensor(p *Writer, t Tensor) {
	s := c.Storages[t.Storage]
	dtype := t.Dtype
	if dtype == "" {
		dtype = s.Dtype
	}
	if t.Param {
		p.Global("torch._utils", "_rebuild_parameter")
	}
	untyped := Untyped(s.Dtype)
	fn := "_rebuild_tensor_v2"
	if untyped {
		fn = "_rebuild_tensor_v3"
	}
	p.Global("torch._utils", fn)
	p.Raw("(") // the arguments: six or more
	// The persistent id: ("storage", class, key, location, numel).
	p.Raw("(").Str("storage")
	if untyped {
		// torch.save (2.14.1) spells this class torch.storage.UntypedStorage,
		// its defining module, which grammar socair-wo/1 does not model yet
		// (a real checkpoint with such a tensor is a LEAD). The fixture uses
		// the spelling the grammar models, so it exercises the converter.
		p.Global("torch", "UntypedStorage")
	} else {
		p.Global("torch", storageClass[s.Dtype])
	}
	numel := len(s.Data)
	if !untyped {
		numel /= Itemsize[s.Dtype]
	}
	p.Str(strconv.Itoa(t.Storage)).Str("cpu").Int(int64(numel)).Raw("t").Put().Raw("Q")
	stride := t.Stride
	if stride == nil {
		stride = Contiguous(t.Shape)
	}
	p.Int(int64(t.Offset)).Ints(t.Shape).Ints(stride).Raw("\x89")
	p.Global("collections", "OrderedDict").Raw(")R").Put()
	if t.Hook {
		p.Int(0).Raw("Ns")
	}
	if untyped {
		p.Global("torch", dtype)
	}
	if len(t.Metadata) > 0 {
		p.Raw("}").Put()
		p.SetItems(len(t.Metadata), func(i int) { p.Str(t.Metadata[i]).Raw("\x88") })
	}
	p.Raw("t").Put().Raw("R").Put()
	if t.Param {
		p.Raw("\x88")
		p.Global("collections", "OrderedDict").Raw(")R").Put()
		p.Raw("\x87").Put().Raw("R").Put()
	}
}

// Contiguous is the row-major stride of a shape, in elements.
func Contiguous(shape []int) []int {
	out := make([]int, len(shape))
	n := 1
	for i := len(shape) - 1; i >= 0; i-- {
		out[i] = n
		n *= max(shape[i], 1)
	}
	return out
}

// Writer writes a protocol 2 pickle as CPython's pickler does.
type Writer struct {
	b    bytes.Buffer
	memo int
}

// NewWriter starts a protocol 2 pickle.
func NewWriter() *Writer {
	p := &Writer{}
	p.b.WriteString("\x80\x02")
	return p
}

// Raw writes opcodes as given.
func (p *Writer) Raw(s string) *Writer { p.b.WriteString(s); return p }

// Put memoizes the top of the stack in the next slot.
func (p *Writer) Put() *Writer {
	if p.memo < 256 {
		p.b.WriteByte('q')
		p.b.WriteByte(byte(p.memo))
	} else {
		p.b.WriteByte('r')
		_ = binary.Write(&p.b, binary.LittleEndian, uint32(p.memo))
	}
	p.memo++
	return p
}

// Global writes GLOBAL module name, memoized.
func (p *Writer) Global(mod, name string) *Writer {
	return p.Raw("c" + mod + "\n" + name + "\n").Put()
}

// Str writes a BINUNICODE string, memoized.
func (p *Writer) Str(s string) *Writer {
	p.b.WriteByte('X')
	_ = binary.Write(&p.b, binary.LittleEndian, uint32(len(s)))
	p.b.WriteString(s)
	return p.Put()
}

// Int writes an integer in its shortest form.
func (p *Writer) Int(n int64) *Writer {
	switch {
	case n >= 0 && n <= 0xff:
		p.b.WriteByte('K')
		p.b.WriteByte(byte(n))
	case n >= 0 && n <= 0xffff:
		p.b.WriteByte('M')
		_ = binary.Write(&p.b, binary.LittleEndian, uint16(n))
	case n >= math.MinInt32 && n <= math.MaxInt32:
		p.b.WriteByte('J')
		_ = binary.Write(&p.b, binary.LittleEndian, int32(n))
	default:
		// LONG1: little-endian two's complement, no redundant sign byte.
		var le []byte
		for v := n; ; {
			b := byte(v)
			le = append(le, b)
			v >>= 8 // arithmetic: a negative value runs to -1
			if (v == 0 && b&0x80 == 0) || (v == -1 && b&0x80 != 0) {
				break
			}
		}
		p.b.WriteByte(0x8a)
		p.b.WriteByte(byte(len(le)))
		p.b.Write(le)
	}
	return p
}

// Ints writes a tuple of ints as the pickler does.
func (p *Writer) Ints(ns []int) *Writer {
	if len(ns) == 0 {
		return p.Raw(")")
	}
	if len(ns) > 3 {
		p.Raw("(")
	}
	for _, n := range ns {
		p.Int(int64(n))
	}
	if len(ns) > 3 {
		return p.Raw("t").Put()
	}
	p.b.WriteByte(byte(0x84 + len(ns))) // TUPLE1, TUPLE2, TUPLE3
	return p.Put()
}

// SetItems writes n dict items as CPython's _batch_setitems does: SETITEM
// for one, MARK and SETITEMS for more. item writes the i-th key and value.
func (p *Writer) SetItems(n int, item func(i int)) *Writer {
	if n > 1 {
		p.Raw("(")
	}
	for i := 0; i < n; i++ {
		item(i)
	}
	switch {
	case n == 1:
		p.Raw("s")
	case n > 1:
		p.Raw("u")
	}
	return p
}

// Stop ends the pickle and returns its bytes.
func (p *Writer) Stop() []byte { return append(p.b.Bytes(), '.') }

// Seq is n deterministic bytes, distinct for each seed, for storage data.
func Seq(n int, seed byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7+int(seed)*31+1) ^ byte(i>>8)
	}
	return b
}

// Float32s is the little-endian bytes of float32 values.
func Float32s(vals ...float32) []byte {
	b := make([]byte, 4*len(vals))
	for i, v := range vals {
		binary.LittleEndian.PutUint32(b[4*i:], math.Float32bits(v))
	}
	return b
}

// Bytes is the slice of a storage's data a contiguous tensor views.
func (c Checkpoint) Bytes(t Tensor) []byte {
	s := c.Storages[t.Storage]
	dtype := t.Dtype
	if dtype == "" {
		dtype = s.Dtype
	}
	n := 1
	for _, d := range t.Shape {
		n *= d
	}
	size := Itemsize[dtype]
	if size == 0 {
		panic(fmt.Sprintf("pickletest: no itemsize for %q", dtype))
	}
	return s.Data[t.Offset*size : (t.Offset+n)*size]
}
