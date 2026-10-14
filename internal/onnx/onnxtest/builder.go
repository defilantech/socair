// Package onnxtest builds ONNX models (onnx.proto's ModelProto, protobuf
// wire format) for tests.
//
// Fixtures are generated, not committed, so they cannot rot silently. Fields
// are written in field-number order, as protobuf's own serializers write
// them; Extra fields let a test write what a serializer never would.
package onnxtest

import (
	"encoding/binary"
	"math"
)

// Data types (onnx.proto TensorProto.DataType).
const (
	Float   = 1
	Uint8   = 2
	Int8    = 3
	Int32   = 6
	Int64   = 7
	String  = 8
	Float16 = 10
	Double  = 11
	Uint4   = 21
)

// KV is a StringStringEntryProto.
type KV struct{ Key, Value string }

// Model is a ModelProto.
type Model struct {
	IRVersion       int64 // 0 leaves it out
	Producer        string
	ProducerVersion string
	Domain          string
	Doc             string
	Graph           *Graph
	Opsets          []Opset
	Metadata        []KV
	Functions       []Function
	// Extra is appended after the fields above.
	Extra []byte
}

// Opset is an OperatorSetIdProto.
type Opset struct {
	Domain  string
	Version int64
}

// Graph is a GraphProto.
type Graph struct {
	Name         string
	Nodes        []Node
	Initializers []Tensor
	Sparse       []Sparse
	Doc          string
	Metadata     []KV
	Extra        []byte
}

// Node is a NodeProto.
type Node struct {
	Inputs, Outputs []string
	Name            string
	OpType          string
	Domain          string
	Attrs           []Attr
	Doc             string
	Extra           []byte
}

// Attr is an AttributeProto. Type is the AttributeType; the value fields
// set are written whatever it says.
type Attr struct {
	Name    string
	Type    int64
	I       *int64
	S       []byte
	T       *Tensor
	G       *Graph
	Strings [][]byte
	Tensors []Tensor
	Graphs  []Graph
}

// Tensor is a TensorProto. A nil Raw writes no raw_data; RawSet writes an
// empty one.
type Tensor struct {
	Dims     []int64
	DataType int32
	Floats   []float32
	Int32s   []int32
	Strings  [][]byte
	Int64s   []int64
	Name     string
	Raw      []byte
	RawSet   bool
	Doc      string
	External []KV
	// Location is data_location; 0 leaves it out.
	Location int32
	Extra    []byte
}

// Sparse is a SparseTensorProto.
type Sparse struct {
	Values, Indices Tensor
	Dims            []int64
}

// Function is a FunctionProto.
type Function struct {
	Name, Domain string
	Nodes        []Node
	Opsets       []Opset
}

// Wire types.
const (
	wireVarint = 0
	wireI64    = 1
	wireBytes  = 2
	wireI32    = 5
)

// AppendVarint appends v as a protobuf varint.
func AppendVarint(b []byte, v uint64) []byte { return binary.AppendUvarint(b, v) }

// AppendTag appends a field key.
func AppendTag(b []byte, field int, wire int) []byte {
	return AppendVarint(b, uint64(field)<<3|uint64(wire))
}

// AppendInt appends a varint field.
func AppendInt(b []byte, field int, v int64) []byte {
	return AppendVarint(AppendTag(b, field, wireVarint), uint64(v))
}

// AppendBytes appends a length-delimited field.
func AppendBytes(b []byte, field int, v []byte) []byte {
	b = AppendVarint(AppendTag(b, field, wireBytes), uint64(len(v)))
	return append(b, v...)
}

func appendStr(b []byte, field int, s string) []byte {
	if s == "" {
		return b
	}
	return AppendBytes(b, field, []byte(s))
}

func appendKVs(b []byte, field int, kvs []KV) []byte {
	for _, kv := range kvs {
		var e []byte
		e = AppendBytes(e, 1, []byte(kv.Key))
		e = AppendBytes(e, 2, []byte(kv.Value))
		b = AppendBytes(b, field, e)
	}
	return b
}

// Bytes encodes the model.
func (m Model) Bytes() []byte {
	var b []byte
	if m.IRVersion != 0 {
		b = AppendInt(b, 1, m.IRVersion)
	}
	b = appendStr(b, 2, m.Producer)
	b = appendStr(b, 3, m.ProducerVersion)
	b = appendStr(b, 4, m.Domain)
	b = appendStr(b, 6, m.Doc)
	if m.Graph != nil {
		b = AppendBytes(b, 7, m.Graph.Bytes())
	}
	for _, o := range m.Opsets {
		b = AppendBytes(b, 8, o.bytes())
	}
	b = appendKVs(b, 14, m.Metadata)
	for _, f := range m.Functions {
		b = AppendBytes(b, 25, f.bytes())
	}
	return append(b, m.Extra...)
}

func (o Opset) bytes() []byte {
	var b []byte
	b = appendStr(b, 1, o.Domain)
	return AppendInt(b, 2, o.Version)
}

// Bytes encodes the graph.
func (g Graph) Bytes() []byte {
	var b []byte
	for _, n := range g.Nodes {
		b = AppendBytes(b, 1, n.Bytes())
	}
	b = appendStr(b, 2, g.Name)
	for _, t := range g.Initializers {
		b = AppendBytes(b, 5, t.Bytes())
	}
	b = appendStr(b, 10, g.Doc)
	for _, s := range g.Sparse {
		var sb []byte
		sb = AppendBytes(sb, 1, s.Values.Bytes())
		sb = AppendBytes(sb, 2, s.Indices.Bytes())
		for _, d := range s.Dims {
			sb = AppendInt(sb, 3, d)
		}
		b = AppendBytes(b, 15, sb)
	}
	b = appendKVs(b, 16, g.Metadata)
	return append(b, g.Extra...)
}

// Bytes encodes the node.
func (n Node) Bytes() []byte {
	var b []byte
	for _, s := range n.Inputs {
		b = AppendBytes(b, 1, []byte(s))
	}
	for _, s := range n.Outputs {
		b = AppendBytes(b, 2, []byte(s))
	}
	b = appendStr(b, 3, n.Name)
	b = appendStr(b, 4, n.OpType)
	for _, a := range n.Attrs {
		b = AppendBytes(b, 5, a.Bytes())
	}
	b = appendStr(b, 6, n.Doc)
	b = appendStr(b, 7, n.Domain)
	return append(b, n.Extra...)
}

// Bytes encodes the attribute.
func (a Attr) Bytes() []byte {
	var b []byte
	b = appendStr(b, 1, a.Name)
	if a.I != nil {
		b = AppendInt(b, 3, *a.I)
	}
	if a.S != nil {
		b = AppendBytes(b, 4, a.S)
	}
	if a.T != nil {
		b = AppendBytes(b, 5, a.T.Bytes())
	}
	if a.G != nil {
		b = AppendBytes(b, 6, a.G.Bytes())
	}
	for _, s := range a.Strings {
		b = AppendBytes(b, 9, s)
	}
	for _, t := range a.Tensors {
		b = AppendBytes(b, 10, t.Bytes())
	}
	for _, g := range a.Graphs {
		b = AppendBytes(b, 11, g.Bytes())
	}
	if a.Type != 0 {
		b = AppendInt(b, 20, a.Type)
	}
	return b
}

// Bytes encodes the tensor: dims unpacked, as protobuf writes a repeated
// field onnx.proto does not mark packed, and the typed data fields packed.
func (t Tensor) Bytes() []byte {
	var b []byte
	for _, d := range t.Dims {
		b = AppendInt(b, 1, d)
	}
	if t.DataType != 0 {
		b = AppendInt(b, 2, int64(t.DataType))
	}
	if len(t.Floats) > 0 {
		var p []byte
		for _, f := range t.Floats {
			p = binary.LittleEndian.AppendUint32(p, math.Float32bits(f))
		}
		b = AppendBytes(b, 4, p)
	}
	if len(t.Int32s) > 0 {
		var p []byte
		for _, v := range t.Int32s {
			p = AppendVarint(p, uint64(int64(v)))
		}
		b = AppendBytes(b, 5, p)
	}
	for _, s := range t.Strings {
		b = AppendBytes(b, 6, s)
	}
	if len(t.Int64s) > 0 {
		var p []byte
		for _, v := range t.Int64s {
			p = AppendVarint(p, uint64(v))
		}
		b = AppendBytes(b, 7, p)
	}
	b = appendStr(b, 8, t.Name)
	if t.Raw != nil || t.RawSet {
		b = AppendBytes(b, 9, t.Raw)
	}
	b = appendStr(b, 12, t.Doc)
	b = appendKVs(b, 13, t.External)
	if t.Location != 0 {
		b = AppendInt(b, 14, int64(t.Location))
	}
	return append(b, t.Extra...)
}

func (f Function) bytes() []byte {
	var b []byte
	b = appendStr(b, 1, f.Name)
	for _, n := range f.Nodes {
		b = AppendBytes(b, 7, n.Bytes())
	}
	for _, o := range f.Opsets {
		b = AppendBytes(b, 9, o.bytes())
	}
	b = appendStr(b, 10, f.Domain)
	return b
}

// FloatWeight is a float32 initializer of the given dims, its raw_data
// zero-filled to exactly the size they need.
func FloatWeight(name string, dims ...int64) Tensor {
	n := int64(1)
	for _, d := range dims {
		n *= d
	}
	return Tensor{Name: name, DataType: Float, Dims: dims, Raw: make([]byte, 4*n)}
}

// ExternalWeight is a float32 initializer of the given dims whose data is at
// offset in the file named by location, with the length the dims need.
func ExternalWeight(name, location string, offset int64, dims ...int64) Tensor {
	n := int64(1)
	for _, d := range dims {
		n *= d
	}
	ext := []KV{{"location", location}}
	if offset != 0 {
		ext = append(ext, KV{"offset", itoa(offset)})
	}
	ext = append(ext, KV{"length", itoa(4 * n)})
	return Tensor{Name: name, DataType: Float, Dims: dims, External: ext, Location: 1}
}

func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// Clean is a small, well-formed model: y = x @ w + b, with standard
// operators and two float32 initializers held inline.
func Clean() Model {
	return Model{
		IRVersion:       8,
		Producer:        "pytorch",
		ProducerVersion: "2.5.0",
		Opsets:          []Opset{{"", 17}},
		Graph:           CleanGraph(),
	}
}

// CleanGraph is Clean's graph.
func CleanGraph() *Graph {
	return &Graph{
		Name: "main_graph",
		Nodes: []Node{
			{Inputs: []string{"x", "w"}, Outputs: []string{"h"}, Name: "/MatMul", OpType: "MatMul"},
			{Inputs: []string{"h", "b"}, Outputs: []string{"y"}, Name: "/Add", OpType: "Add"},
		},
		Initializers: []Tensor{FloatWeight("w", 4, 4), FloatWeight("b", 4)},
	}
}
