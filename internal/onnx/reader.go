// Package onnx reads an ONNX model, the ModelProto message of onnx.proto, from
// its protobuf wire format, for the structure and inventory checks.
//
// The schema is onnx.proto at onnx v1.23.2 (commit e1ac8e74b620), IR version
// 14. The reader is written against the wire format with the standard library
// only. It reads every field onnx.proto defines and records the facts the
// checks grade: the operators each node names, every tensor's type, shape,
// and where its data is (never the data itself: raw_data is skipped and typed
// values are counted), external data references, and the free text a model
// carries. It runs no operator and loads no external file.
//
// Where a scanner could read a model differently from protobuf, the reader
// follows protobuf and records what it did not model in Model.Unread:
//
//   - a field onnx.proto does not define, a field number onnx.proto reserves,
//     a known field in a wire type other than its own, and a value outside a
//     closed (proto2) enum are all, to protobuf, unknown fields that a loader
//     keeps and does not read;
//   - a field that may appear once and appears again, which protobuf resolves
//     by keeping the last value or merging the messages.
//
// Malformed bytes (a truncated field, a length past its message, an overlong
// varint, a group) are an error: the model is unparseable.
//
// Bounds: a model larger than protobuf's default total-bytes limit
// (INT_MAX, which onnxruntime parses with), messages nested deeper than
// protobuf's default recursion limit (100), and the counts below are errors,
// not partial results. Free text past its own cap is not kept, and
// Model.TextTruncated says so.
package onnx

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Bounds. MaxFileBytes and MaxDepth are protobuf's own defaults
// (src/google/protobuf/io/coded_stream.h: kDefaultTotalBytesLimit = INT_MAX,
// default_recursion_limit_ = 100), with which onnxruntime parses a model
// (onnxruntime/core/graph/model.cc), so a model past either does not load.
const (
	MaxFileBytes = math.MaxInt32
	MaxDepth     = 100

	maxTensors    = 1 << 18
	maxRank       = 1024
	maxIdent      = 64 << 10 // a name, domain, operator type, or external_data entry
	maxText       = 16 << 20 // one free-text value
	maxTextTotal  = 64 << 20 // all free text kept
	maxTextValues = 1 << 20
	maxOps        = 1 << 16
	maxFunctions  = 1 << 16
	maxOpsets     = 1 << 12
	maxExternal   = 64
	maxEPContexts = 1 << 12
	maxUnread     = 64

	// ArrayScanMin is the shortest element of a repeated string (a STRINGS
	// attribute, a STRING tensor) kept as text: as for GGUF string arrays,
	// shorter elements cannot carry an executable or a long encoded blob.
	ArrayScanMin = 64
)

// Model is what the reader found in a ModelProto.
type Model struct {
	IRVersion       int64
	HasIRVersion    bool
	Producer        string // producer_name
	ProducerVersion string
	Opsets          []Opset // the model's opset_import
	HasGraph        bool

	// Graphs counts every graph read: the main graph, subgraphs in node
	// attributes (If, Loop, Scan bodies), and training graphs. Function
	// bodies are not graphs and are not counted.
	Graphs int
	// MaxNesting is the deepest subgraph nesting, 0 for a model with none.
	MaxNesting int
	// Nodes counts every node, in subgraphs and function bodies too.
	Nodes int
	// Ops are the distinct operators nodes name, with how many name each,
	// sorted by domain, type, and overload. The domain "ai.onnx" is read as
	// "", as onnx and onnxruntime read it.
	Ops []Op
	// Functions are the model-local functions (ModelProto.functions).
	Functions    []Function
	TrainingInfo int

	// Tensors are every TensorProto the model holds: graph initializers,
	// the values and indices of sparse initializers, and tensors in node and
	// function attributes, in file order.
	Tensors []Tensor
	// EPContexts are onnxruntime EPContext nodes (com.microsoft): a
	// precompiled execution-provider context, embedded or in a file.
	EPContexts []EPContext

	// Text is the model's free text, for the inventory: producer name and
	// version, the model's domain, every doc_string, every metadata_props key
	// and value, every string attribute except an EPContext's
	// ep_cache_context, and every element of a STRINGS attribute or a STRING
	// tensor of ArrayScanMin bytes or more. Names (of graphs, nodes, values,
	// tensors, attributes) are identifiers and are not kept.
	Text []string
	// TextBytes is the total size of Text.
	TextBytes int64
	// ShortElements counts the repeated-string elements too short to keep.
	ShortElements int64
	// TextTruncated reports that a cap was reached, so some text was not kept.
	TextTruncated bool

	// Unread names what the reader read past without modelling, with counts
	// (see the package comment). Sorted.
	Unread []string
}

// Opset is one opset_import entry.
type Opset struct {
	Domain  string
	Version int64
}

// Op is one operator nodes name.
type Op struct {
	Domain, Type, Overload string
	Count                  int
}

// Function is a model-local function's identity.
type Function struct {
	Domain, Name, Overload string
}

// Entry is one external_data key and value.
type Entry struct {
	Key, Value string
}

// Kind says where a tensor sits.
type Kind int

const (
	// Initializer is a graph initializer.
	Initializer Kind = iota
	// SparseValues and SparseIndices are a sparse tensor's parts; Graph is
	// set when the sparse tensor is a graph's sparse_initializer.
	SparseValues
	SparseIndices
	// Attribute is a tensor in a node's or a function's attribute.
	Attribute
)

// Tensor is one TensorProto. Counts are of elements as stored: a packed
// field's elements are counted, not read.
type Tensor struct {
	Where string // a label for the report: where in the model it sits
	Name  string
	Kind  Kind
	// Graph is the index of the graph whose initializer it is, in the order
	// graphs were read, or -1.
	Graph int

	DataType    int32
	HasDataType bool
	Dims        []int64
	Segment     bool
	// Location is data_location: 0 (DEFAULT) or 1 (EXTERNAL).
	Location int32

	RawBytes int64
	HasRaw   bool
	Floats   int64
	Int32s   int64
	Strings  int64
	Int64s   int64
	Doubles  int64
	Uint64s  int64

	External []Entry
}

// EPContext is one EPContext node.
type EPContext struct {
	Where string
	// EmbedMode is the embed_mode attribute (1, the default: the context is
	// embedded; 0: ep_cache_context is a path relative to the model).
	EmbedMode int64
	// ContextBytes is ep_cache_context's length, and Context its value when
	// it was read (a path, at most 64 KiB).
	ContextBytes int64
	Context      string
	HasContext   bool
	ContextRead  bool
}

// Read parses the ONNX model at path.
func Read(path string) (*Model, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	return read(f, st.Size())
}

// Sniff reports whether the file at path is an ONNX model by its bytes: its
// top level walks as protobuf fields to the end of the file and holds an
// ir_version (field 1, a varint) and a graph (field 7, a message). Nothing
// below the top level is read. A model whose top level does not walk is not
// recognised; Read says why.
func Sniff(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return false
	}
	return sniff(f, st.Size())
}

// maxSniffFields bounds the top-level walk. A real model's top level holds a
// handful of fields and a few dozen opset and metadata entries.
const maxSniffFields = 1 << 16

func sniff(src io.ReadSeeker, size int64) bool {
	d := newDecoder(src)
	ir, graph := false, false
	for n := 0; d.pos < size; n++ {
		if n >= maxSniffFields {
			return false
		}
		f, wt, err := d.tag(size)
		if err != nil {
			return false
		}
		switch {
		case f == 1 && wt == wireVarint:
			ir = true
		case f == 7 && wt == wireBytes:
			graph = true
		}
		if err := d.skipValue(wt, size); err != nil {
			return false
		}
	}
	return ir && graph
}

func read(src io.ReadSeeker, size int64) (*Model, error) {
	if size > MaxFileBytes {
		return nil, fmt.Errorf("the file is %d bytes, more than protobuf's limit of %d (INT_MAX), with which onnxruntime parses a model", size, int64(MaxFileBytes))
	}
	d := newDecoder(src)
	d.m = &Model{}
	d.ops = map[Op]int{}
	d.unread = map[string]int{}
	if err := d.model(size); err != nil {
		return nil, err
	}
	m := d.m
	for op, n := range d.ops {
		op.Count = n
		m.Ops = append(m.Ops, op)
	}
	sort.Slice(m.Ops, func(i, j int) bool {
		a, b := m.Ops[i], m.Ops[j]
		if a.Domain != b.Domain {
			return a.Domain < b.Domain
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		return a.Overload < b.Overload
	})
	for u, n := range d.unread {
		if n > 1 {
			u += fmt.Sprintf(" (%d times)", n)
		}
		m.Unread = append(m.Unread, u)
	}
	sort.Strings(m.Unread)
	return m, nil
}

// Wire types (protobuf encoding).
const (
	wireVarint = 0
	wireI64    = 1
	wireBytes  = 2
	wireI32    = 5
)

// ParseError is malformed protobuf at a byte offset.
type ParseError struct {
	Off int64
	Msg string
}

func (e *ParseError) Error() string { return fmt.Sprintf("at byte %d: %s", e.Off, e.Msg) }

type decoder struct {
	src io.ReadSeeker
	br  *bufio.Reader
	pos int64

	depth   int // message nesting
	nesting int // subgraph nesting
	scope   string
	m       *Model
	ops     map[Op]int
	unread  map[string]int
}

func newDecoder(src io.ReadSeeker) *decoder {
	return &decoder{src: src, br: bufio.NewReaderSize(src, 1<<20)}
}

func (d *decoder) errf(format string, args ...any) error {
	return &ParseError{Off: d.pos, Msg: fmt.Sprintf(format, args...)}
}

func (d *decoder) readByte() (byte, error) {
	b, err := d.br.ReadByte()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return 0, d.errf("the file ends inside a field")
		}
		return 0, err
	}
	d.pos++
	return b, nil
}

// varint reads a varint that must end before end. Ten bytes is protobuf's
// longest; a tenth byte above 1 would hold bits past 64.
func (d *decoder) varint(end int64) (uint64, error) {
	var v uint64
	for i := 0; i < 10; i++ {
		if d.pos >= end {
			return 0, d.errf("a varint runs past the end of its message")
		}
		b, err := d.readByte()
		if err != nil {
			return 0, err
		}
		if i == 9 && b > 1 {
			return 0, d.errf("a varint overflows 64 bits")
		}
		v |= uint64(b&0x7f) << (7 * i)
		if b < 0x80 {
			return v, nil
		}
	}
	return 0, d.errf("a varint longer than 10 bytes")
}

// skip advances n bytes, seeking past what the buffer does not hold.
func (d *decoder) skip(n int64) error {
	if n <= int64(d.br.Buffered()) {
		_, _ = d.br.Discard(int(n))
		d.pos += n
		return nil
	}
	if _, err := d.src.Seek(d.pos+n, io.SeekStart); err != nil {
		return err
	}
	d.br.Reset(d.src)
	d.pos += n
	return nil
}

func (d *decoder) bytes(n int64) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(d.br, b); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, d.errf("the file ends inside a field")
		}
		return nil, err
	}
	d.pos += n
	return b, nil
}

// tag reads a field's key. Field number 0 and the group wire types (which
// onnx.proto never uses) are malformed.
func (d *decoder) tag(end int64) (int32, int, error) {
	v, err := d.varint(end)
	if err != nil {
		return 0, 0, err
	}
	f, wt := v>>3, int(v&7)
	if f == 0 || f > 1<<29-1 {
		return 0, 0, d.errf("field number %d is outside protobuf's range", f)
	}
	switch wt {
	case wireVarint, wireI64, wireBytes, wireI32:
		return int32(f), wt, nil
	case 3, 4:
		return 0, 0, d.errf("field %d is group-encoded, which onnx.proto never uses", f)
	}
	return 0, 0, d.errf("field %d has wire type %d, which protobuf does not define", f, wt)
}

// length reads a length-delimited field's length, which must fit its message.
func (d *decoder) length(end int64) (int64, error) {
	v, err := d.varint(end)
	if err != nil {
		return 0, err
	}
	if v > uint64(end-d.pos) {
		return 0, d.errf("a field of %d bytes runs past the end of its message", v)
	}
	return int64(v), nil
}

func (d *decoder) skipValue(wt int, end int64) error {
	switch wt {
	case wireVarint:
		_, err := d.varint(end)
		return err
	case wireI64, wireI32:
		n := int64(8)
		if wt == wireI32 {
			n = 4
		}
		if end-d.pos < n {
			return d.errf("a fixed-width field runs past the end of its message")
		}
		return d.skip(n)
	}
	n, err := d.length(end)
	if err != nil {
		return err
	}
	return d.skip(n)
}

// note records something read and not modelled.
func (d *decoder) note(s string) {
	if _, ok := d.unread[s]; !ok && len(d.unread) >= maxUnread {
		s = "further unmodelled fields"
	}
	d.unread[s]++
}

// fields reads a message's fields until end, handing each to fn, which must
// consume its value.
func (d *decoder) fields(end int64, fn func(f int32, wt int) error) error {
	for d.pos < end {
		f, wt, err := d.tag(end)
		if err != nil {
			return err
		}
		if err := fn(f, wt); err != nil {
			return err
		}
	}
	return nil
}

// unknown records and skips a field onnx.proto does not give this message.
func (d *decoder) unknown(msg string, f int32, wt int, end int64, reserved ...int32) error {
	why := "a field onnx.proto does not define"
	for _, r := range reserved {
		if r == f {
			why = "a field number onnx.proto reserves"
		}
	}
	d.note(fmt.Sprintf("%s field %d (%s)", msg, f, why))
	return d.skipValue(wt, end)
}

// wrongWire records and skips a known field in another wire type, which
// protobuf keeps as an unknown field.
func (d *decoder) wrongWire(name string, wt int, end int64) error {
	d.note(fmt.Sprintf("%s in wire type %d, not its own (protobuf keeps it as an unknown field)", name, wt))
	return d.skipValue(wt, end)
}

// seen tracks a message's singular fields; field numbers are below 64.
type seen uint64

func (d *decoder) once(s *seen, name string, f int32) {
	if s == nil || f >= 63 {
		return
	}
	if *s&(1<<uint(f)) != 0 {
		d.note(name + " appears more than once (protobuf keeps the last value or merges the messages)")
	}
	*s |= 1 << uint(f)
}

// oneof records a second member of a oneof, which replaces the first.
func (d *decoder) oneof(s *seen, name string) {
	const bit = 1 << 63
	if *s&bit != 0 {
		d.note(name + " sets more than one member of a oneof (protobuf keeps the last)")
	}
	*s |= bit
}

// --- field readers: each checks the wire type, then consumes the value. ---

func (d *decoder) intField(s *seen, name string, f int32, wt int, end int64, set func(int64)) error {
	if wt != wireVarint {
		return d.wrongWire(name, wt, end)
	}
	d.once(s, name, f)
	v, err := d.varint(end)
	if err != nil {
		return err
	}
	if set != nil {
		set(int64(v))
	}
	return nil
}

// enumField reads a proto2 enum. A value outside it is, to protobuf, an
// unknown field: the field stays unset.
func (d *decoder) enumField(s *seen, name string, f int32, wt int, end int64, max int64, set func(int64)) error {
	if wt != wireVarint {
		return d.wrongWire(name, wt, end)
	}
	v, err := d.varint(end)
	if err != nil {
		return err
	}
	if int64(v) < 0 || int64(v) > max {
		d.note(fmt.Sprintf("%s value %d, outside its enum (protobuf keeps it as an unknown field)", name, int64(v)))
		return nil
	}
	d.once(s, name, f)
	set(int64(v))
	return nil
}

func (d *decoder) fixedField(s *seen, name string, f int32, wt, want int, end int64) error {
	if wt != want {
		return d.wrongWire(name, wt, end)
	}
	d.once(s, name, f)
	return d.skipValue(wt, end)
}

func (d *decoder) identField(s *seen, name string, f int32, wt int, end int64, set func(string)) error {
	if wt != wireBytes {
		return d.wrongWire(name, wt, end)
	}
	d.once(s, name, f)
	n, err := d.length(end)
	if err != nil {
		return err
	}
	if n > maxIdent {
		return d.errf("%s is %d bytes, more than this reader's bound of %d", name, n, maxIdent)
	}
	b, err := d.bytes(n)
	if err != nil {
		return err
	}
	set(string(b))
	return nil
}

// skipString reads past a string or bytes field the checks do not use.
func (d *decoder) skipString(s *seen, name string, f int32, wt int, end int64) error {
	if wt != wireBytes {
		return d.wrongWire(name, wt, end)
	}
	d.once(s, name, f)
	n, err := d.length(end)
	if err != nil {
		return err
	}
	return d.skip(n)
}

// textField reads free text into the model's Text.
func (d *decoder) textField(s *seen, name string, f int32, wt int, end int64, set func(string)) error {
	if wt != wireBytes {
		return d.wrongWire(name, wt, end)
	}
	d.once(s, name, f)
	v, err := d.text(end, 0)
	if err != nil {
		return err
	}
	if set != nil {
		set(v)
	}
	return nil
}

// text reads a length-delimited value as free text and keeps it. A value
// under min bytes (an element of a repeated string) is counted and skipped.
func (d *decoder) text(end int64, min int64) (string, error) {
	n, err := d.length(end)
	if err != nil {
		return "", err
	}
	if n < min {
		d.m.ShortElements++
		return "", d.skip(n)
	}
	v, read, err := d.textValue(n)
	if err != nil {
		return "", err
	}
	d.keep(v, read, n)
	return v, nil
}

// textValue reads n bytes, or skips them when they are past maxText.
func (d *decoder) textValue(n int64) (string, bool, error) {
	if n > maxText {
		return "", false, d.skip(n)
	}
	b, err := d.bytes(n)
	if err != nil {
		return "", false, err
	}
	return string(b), true, nil
}

// keep adds a value of n bytes to the model's text, or, when it was not read
// or a cap is reached, marks the text truncated.
func (d *decoder) keep(v string, read bool, n int64) {
	if n == 0 {
		return
	}
	if !read || d.m.TextBytes+n > maxTextTotal || len(d.m.Text) >= maxTextValues {
		d.m.TextTruncated = true
		return
	}
	d.m.Text = append(d.m.Text, v)
	d.m.TextBytes += n
}

func (d *decoder) msgField(s *seen, name string, f int32, wt int, end int64, fn func(end int64) error) error {
	if wt != wireBytes {
		return d.wrongWire(name, wt, end)
	}
	d.once(s, name, f)
	n, err := d.length(end)
	if err != nil {
		return err
	}
	if d.depth >= MaxDepth {
		return d.errf("messages nest deeper than %d levels, protobuf's default recursion limit", MaxDepth)
	}
	d.depth++
	sub := d.pos + n
	err = fn(sub)
	d.depth--
	if err != nil {
		return err
	}
	if d.pos != sub {
		return d.errf("a message did not end at its length")
	}
	return nil
}

// varints reads one occurrence of a repeated varint field, packed or not,
// handing each value to each (or only counting them when each is nil).
func (d *decoder) varints(name string, wt int, end int64, each func(uint64) error) (int64, error) {
	switch wt {
	case wireVarint:
		v, err := d.varint(end)
		if err != nil {
			return 0, err
		}
		if each != nil {
			if err := each(v); err != nil {
				return 0, err
			}
		}
		return 1, nil
	case wireBytes:
		n, err := d.length(end)
		if err != nil {
			return 0, err
		}
		stop := d.pos + n
		if each != nil {
			var count int64
			for d.pos < stop {
				v, err := d.varint(stop)
				if err != nil {
					return 0, err
				}
				if err := each(v); err != nil {
					return 0, err
				}
				count++
			}
			return count, nil
		}
		return d.countPacked(n)
	}
	return 0, d.wrongWire(name, wt, end)
}

// countPacked counts the varints in n packed bytes without decoding them: a
// varint ends at a byte below 0x80, and none runs past ten bytes or past the
// field.
func (d *decoder) countPacked(n int64) (int64, error) {
	var count int64
	run := 0
	for n > 0 {
		chunk := min(n, int64(d.br.Size()))
		b, err := d.br.Peek(int(chunk))
		if err != nil && len(b) == 0 {
			if errors.Is(err, io.EOF) {
				return 0, d.errf("the file ends inside a field")
			}
			return 0, err
		}
		for _, c := range b {
			if c < 0x80 {
				count++
				run = 0
				continue
			}
			run++
			if run >= 10 {
				return 0, d.errf("a packed varint longer than 10 bytes")
			}
		}
		_, _ = d.br.Discard(len(b))
		d.pos += int64(len(b))
		n -= int64(len(b))
	}
	if run != 0 {
		return 0, d.errf("a packed field ends inside a varint")
	}
	return count, nil
}

// fixeds reads one occurrence of a repeated fixed-width field, packed or not,
// and counts its elements.
func (d *decoder) fixeds(name string, wt, width int, end int64) (int64, error) {
	want := wireI32
	if width == 8 {
		want = wireI64
	}
	switch wt {
	case want:
		return 1, d.skipValue(wt, end)
	case wireBytes:
		n, err := d.length(end)
		if err != nil {
			return 0, err
		}
		if n%int64(width) != 0 {
			return 0, d.errf("a packed %s of %d bytes is not a whole number of %d-byte values", name, n, width)
		}
		return n / int64(width), d.skip(n)
	}
	return 0, d.wrongWire(name, wt, end)
}

// --- messages ---

func (d *decoder) model(end int64) error {
	var s seen
	return d.fields(end, func(f int32, wt int) error {
		m := d.m
		switch f {
		case 1:
			return d.intField(&s, "ModelProto.ir_version", f, wt, end, func(v int64) { m.IRVersion, m.HasIRVersion = v, true })
		case 2:
			return d.textField(&s, "ModelProto.producer_name", f, wt, end, func(v string) { m.Producer = v })
		case 3:
			return d.textField(&s, "ModelProto.producer_version", f, wt, end, func(v string) { m.ProducerVersion = v })
		case 4:
			return d.textField(&s, "ModelProto.domain", f, wt, end, nil)
		case 5:
			return d.intField(&s, "ModelProto.model_version", f, wt, end, nil)
		case 6:
			return d.textField(&s, "ModelProto.doc_string", f, wt, end, nil)
		case 7:
			return d.msgField(&s, "ModelProto.graph", f, wt, end, func(e int64) error {
				m.HasGraph = true
				return d.graph(e)
			})
		case 8:
			return d.msgField(nil, "ModelProto.opset_import", f, wt, end, d.opset)
		case 14:
			return d.msgField(nil, "ModelProto.metadata_props", f, wt, end, d.textEntry)
		case 20:
			return d.msgField(nil, "ModelProto.training_info", f, wt, end, d.trainingInfo)
		case 25:
			return d.msgField(nil, "ModelProto.functions", f, wt, end, d.function)
		case 26:
			return d.msgField(nil, "ModelProto.configuration", f, wt, end, d.deviceConfiguration)
		}
		return d.unknown("ModelProto", f, wt, end)
	})
}

func (d *decoder) opset(end int64) error {
	var s seen
	o := Opset{}
	err := d.fields(end, func(f int32, wt int) error {
		switch f {
		case 1:
			return d.identField(&s, "OperatorSetIdProto.domain", f, wt, end, func(v string) { o.Domain = v })
		case 2:
			return d.intField(&s, "OperatorSetIdProto.version", f, wt, end, func(v int64) { o.Version = v })
		}
		return d.unknown("OperatorSetIdProto", f, wt, end)
	})
	if err != nil {
		return err
	}
	if len(d.m.Opsets) >= maxOpsets {
		return d.errf("more than %d opset imports", maxOpsets)
	}
	d.m.Opsets = append(d.m.Opsets, o)
	return nil
}

// subgraph reads a graph held in a node attribute or a training-info field.
func (d *decoder) subgraph(end int64, scope string) error {
	outer := d.scope
	d.scope = outer + scope + ": "
	d.nesting++
	if d.nesting > d.m.MaxNesting {
		d.m.MaxNesting = d.nesting
	}
	err := d.graph(end)
	d.nesting--
	d.scope = outer
	return err
}

func (d *decoder) graph(end int64) error {
	gi := d.m.Graphs
	d.m.Graphs++
	var s seen
	return d.fields(end, func(f int32, wt int) error {
		switch f {
		case 1:
			return d.msgField(nil, "GraphProto.node", f, wt, end, d.node)
		case 2:
			return d.skipString(&s, "GraphProto.name", f, wt, end)
		case 5:
			return d.msgField(nil, "GraphProto.initializer", f, wt, end, func(e int64) error {
				return d.tensor(e, Initializer, gi, d.scope+"initializer")
			})
		case 15:
			return d.msgField(nil, "GraphProto.sparse_initializer", f, wt, end, func(e int64) error {
				return d.sparseTensor(e, gi, d.scope+"sparse initializer")
			})
		case 10:
			return d.textField(&s, "GraphProto.doc_string", f, wt, end, nil)
		case 11, 12, 13:
			return d.msgField(nil, "GraphProto.input, output, or value_info", f, wt, end, d.valueInfo)
		case 14:
			return d.msgField(nil, "GraphProto.quantization_annotation", f, wt, end, d.tensorAnnotation)
		case 16:
			return d.msgField(nil, "GraphProto.metadata_props", f, wt, end, d.textEntry)
		}
		return d.unknown("GraphProto", f, wt, end, 3, 4, 6, 7, 8, 9)
	})
}

// nodeInfo is what a node's fields say, gathered before it is recorded:
// its domain may follow its attributes.
type nodeInfo struct {
	name, op, domain, overload string
	embedMode                  int64
	ctx                        attrString
}

// attrString is a string attribute's value, held until the node says
// whether it is an EPContext's ep_cache_context.
type attrString struct {
	present bool
	bytes   int64
	value   string
	read    bool
}

func (n *nodeInfo) label() string {
	s := "node"
	if n.name != "" {
		s += " " + quote(n.name)
	}
	if n.op != "" {
		s += " (" + n.op + ")"
	}
	return s
}

func (d *decoder) node(end int64) error {
	n := &nodeInfo{embedMode: 1}
	var s seen
	err := d.fields(end, func(f int32, wt int) error {
		switch f {
		case 1, 2:
			return d.skipString(nil, "NodeProto.input or output", f, wt, end)
		case 3:
			return d.identField(&s, "NodeProto.name", f, wt, end, func(v string) { n.name = v })
		case 4:
			return d.identField(&s, "NodeProto.op_type", f, wt, end, func(v string) { n.op = v })
		case 7:
			return d.identField(&s, "NodeProto.domain", f, wt, end, func(v string) { n.domain = v })
		case 8:
			return d.identField(&s, "NodeProto.overload", f, wt, end, func(v string) { n.overload = v })
		case 5:
			return d.msgField(nil, "NodeProto.attribute", f, wt, end, func(e int64) error { return d.attribute(e, n) })
		case 6:
			return d.textField(&s, "NodeProto.doc_string", f, wt, end, nil)
		case 9:
			return d.msgField(nil, "NodeProto.metadata_props", f, wt, end, d.textEntry)
		case 10:
			return d.msgField(nil, "NodeProto.device_configurations", f, wt, end, d.nodeDeviceConfiguration)
		}
		return d.unknown("NodeProto", f, wt, end)
	})
	if err != nil {
		return err
	}
	d.m.Nodes++
	domain := n.domain
	if domain == "ai.onnx" {
		domain = ""
	}
	op := Op{Domain: domain, Type: n.op, Overload: n.overload}
	if _, ok := d.ops[op]; !ok && len(d.ops) >= maxOps {
		return d.errf("more than %d distinct operators", maxOps)
	}
	d.ops[op]++
	if domain == "com.microsoft" && n.op == "EPContext" {
		if len(d.m.EPContexts) >= maxEPContexts {
			return d.errf("more than %d EPContext nodes", maxEPContexts)
		}
		ep := EPContext{Where: d.scope + n.label(), EmbedMode: n.embedMode, ContextBytes: n.ctx.bytes, HasContext: n.ctx.present}
		// Only a path is kept: an embedded context is compiled code, not read.
		if n.embedMode == 0 && n.ctx.read && n.ctx.bytes <= maxIdent {
			ep.Context, ep.ContextRead = n.ctx.value, true
		}
		d.m.EPContexts = append(d.m.EPContexts, ep)
		return nil
	}
	// On any other node, ep_cache_context is ordinary text.
	if n.ctx.present {
		d.keep(n.ctx.value, n.ctx.read, n.ctx.bytes)
	}
	return nil
}

// attributeTypeMax is AttributeProto.AttributeType's largest value
// (TYPE_PROTOS = 14).
const attributeTypeMax = 14

func (d *decoder) attribute(end int64, n *nodeInfo) error {
	var s seen
	name := ""
	var str attrString
	var i int64
	hasI := false
	label := func() string {
		w := n.label() + " attribute"
		if name != "" {
			w += " " + quote(name)
		}
		return w
	}
	err := d.fields(end, func(f int32, wt int) error {
		switch f {
		case 1:
			return d.identField(&s, "AttributeProto.name", f, wt, end, func(v string) { name = v })
		case 21:
			return d.skipString(&s, "AttributeProto.ref_attr_name", f, wt, end)
		case 13:
			return d.textField(&s, "AttributeProto.doc_string", f, wt, end, nil)
		case 20:
			return d.enumField(&s, "AttributeProto.type", f, wt, end, attributeTypeMax, func(int64) {})
		case 2:
			return d.fixedField(&s, "AttributeProto.f", f, wt, wireI32, end)
		case 3:
			return d.intField(&s, "AttributeProto.i", f, wt, end, func(v int64) { i, hasI = v, true })
		case 4:
			if wt != wireBytes {
				return d.wrongWire("AttributeProto.s", wt, end)
			}
			d.once(&s, "AttributeProto.s", f)
			n, err := d.length(end)
			if err != nil {
				return err
			}
			v, read, err := d.textValue(n)
			str = attrString{present: true, bytes: n, value: v, read: read}
			return err
		case 5:
			return d.msgField(&s, "AttributeProto.t", f, wt, end, func(e int64) error { return d.tensor(e, Attribute, -1, d.scope+label()) })
		case 6:
			return d.msgField(&s, "AttributeProto.g", f, wt, end, func(e int64) error { return d.subgraph(e, label()) })
		case 22:
			return d.msgField(&s, "AttributeProto.sparse_tensor", f, wt, end, func(e int64) error { return d.sparseTensor(e, -1, d.scope+label()) })
		case 14:
			return d.msgField(&s, "AttributeProto.tp", f, wt, end, d.typeProto)
		case 7:
			_, err := d.fixeds("AttributeProto.floats", wt, 4, end)
			return err
		case 8:
			_, err := d.varints("AttributeProto.ints", wt, end, nil)
			return err
		case 9:
			if wt != wireBytes {
				return d.wrongWire("AttributeProto.strings", wt, end)
			}
			_, err := d.text(end, ArrayScanMin)
			return err
		case 10:
			return d.msgField(nil, "AttributeProto.tensors", f, wt, end, func(e int64) error { return d.tensor(e, Attribute, -1, d.scope+label()) })
		case 11:
			return d.msgField(nil, "AttributeProto.graphs", f, wt, end, func(e int64) error { return d.subgraph(e, label()) })
		case 23:
			return d.msgField(nil, "AttributeProto.sparse_tensors", f, wt, end, func(e int64) error { return d.sparseTensor(e, -1, d.scope+label()) })
		case 15:
			return d.msgField(nil, "AttributeProto.type_protos", f, wt, end, d.typeProto)
		}
		return d.unknown("AttributeProto", f, wt, end, 12, 16, 17, 18, 19)
	})
	if err != nil {
		return err
	}
	switch {
	case name == "ep_cache_context" && str.present:
		n.ctx = str
	case name == "embed_mode" && hasI:
		n.embedMode = i
	}
	if str.present && name != "ep_cache_context" {
		d.keep(str.value, str.read, str.bytes)
	}
	return nil
}

// dataLocationMax is TensorProto.DataLocation's largest value (EXTERNAL).
const dataLocationMax = 1

func (d *decoder) tensor(end int64, kind Kind, graph int, where string) error {
	t := Tensor{Kind: kind, Graph: graph}
	var s seen
	err := d.fields(end, func(f int32, wt int) error {
		var n int64
		var err error
		switch f {
		case 1:
			_, err = d.varints("TensorProto.dims", wt, end, func(v uint64) error {
				if len(t.Dims) >= maxRank {
					return d.errf("a tensor with more than %d dims", maxRank)
				}
				t.Dims = append(t.Dims, int64(v))
				return nil
			})
			return err
		case 2:
			return d.intField(&s, "TensorProto.data_type", f, wt, end, func(v int64) { t.DataType, t.HasDataType = int32(v), true })
		case 3:
			return d.msgField(&s, "TensorProto.segment", f, wt, end, func(e int64) error {
				t.Segment = true
				return d.segment(e)
			})
		case 4:
			n, err = d.fixeds("TensorProto.float_data", wt, 4, end)
			t.Floats += n
			return err
		case 5:
			n, err = d.varints("TensorProto.int32_data", wt, end, nil)
			t.Int32s += n
			return err
		case 6:
			if wt != wireBytes {
				return d.wrongWire("TensorProto.string_data", wt, end)
			}
			t.Strings++
			_, err := d.text(end, ArrayScanMin)
			return err
		case 7:
			n, err = d.varints("TensorProto.int64_data", wt, end, nil)
			t.Int64s += n
			return err
		case 8:
			return d.identField(&s, "TensorProto.name", f, wt, end, func(v string) { t.Name = v })
		case 12:
			return d.textField(&s, "TensorProto.doc_string", f, wt, end, nil)
		case 9:
			if wt != wireBytes {
				return d.wrongWire("TensorProto.raw_data", wt, end)
			}
			d.once(&s, "TensorProto.raw_data", f)
			l, err := d.length(end)
			if err != nil {
				return err
			}
			t.RawBytes, t.HasRaw = l, true
			return d.skip(l)
		case 13:
			return d.msgField(nil, "TensorProto.external_data", f, wt, end, func(e int64) error {
				en, err := d.entry(e)
				if err != nil {
					return err
				}
				if len(t.External) >= maxExternal {
					return d.errf("a tensor with more than %d external_data entries", maxExternal)
				}
				t.External = append(t.External, en)
				return nil
			})
		case 14:
			return d.enumField(&s, "TensorProto.data_location", f, wt, end, dataLocationMax, func(v int64) { t.Location = int32(v) })
		case 10:
			n, err = d.fixeds("TensorProto.double_data", wt, 8, end)
			t.Doubles += n
			return err
		case 11:
			n, err = d.varints("TensorProto.uint64_data", wt, end, nil)
			t.Uint64s += n
			return err
		case 16:
			return d.msgField(nil, "TensorProto.metadata_props", f, wt, end, d.textEntry)
		}
		return d.unknown("TensorProto", f, wt, end)
	})
	if err != nil {
		return err
	}
	if len(d.m.Tensors) >= maxTensors {
		return d.errf("more than %d tensors", maxTensors)
	}
	t.Where = where
	if t.Name != "" {
		if kind == Attribute {
			t.Where += " (tensor " + quote(t.Name) + ")"
		} else {
			t.Where += " " + quote(t.Name)
		}
	}
	d.m.Tensors = append(d.m.Tensors, t)
	return nil
}

func (d *decoder) segment(end int64) error {
	var s seen
	return d.fields(end, func(f int32, wt int) error {
		switch f {
		case 1:
			return d.intField(&s, "TensorProto.Segment.begin", f, wt, end, nil)
		case 2:
			return d.intField(&s, "TensorProto.Segment.end", f, wt, end, nil)
		}
		return d.unknown("TensorProto.Segment", f, wt, end)
	})
}

func (d *decoder) sparseTensor(end int64, graph int, where string) error {
	var s seen
	return d.fields(end, func(f int32, wt int) error {
		switch f {
		case 1:
			return d.msgField(&s, "SparseTensorProto.values", f, wt, end, func(e int64) error {
				return d.tensor(e, SparseValues, graph, where+" values")
			})
		case 2:
			return d.msgField(&s, "SparseTensorProto.indices", f, wt, end, func(e int64) error {
				return d.tensor(e, SparseIndices, graph, where+" indices")
			})
		case 3:
			_, err := d.varints("SparseTensorProto.dims", wt, end, nil)
			return err
		}
		return d.unknown("SparseTensorProto", f, wt, end)
	})
}

// entry reads an external_data key and value.
func (d *decoder) entry(end int64) (Entry, error) {
	var s seen
	var e Entry
	err := d.fields(end, func(f int32, wt int) error {
		switch f {
		case 1:
			return d.identField(&s, "StringStringEntryProto.key", f, wt, end, func(v string) { e.Key = v })
		case 2:
			return d.identField(&s, "StringStringEntryProto.value", f, wt, end, func(v string) { e.Value = v })
		}
		return d.unknown("StringStringEntryProto", f, wt, end)
	})
	return e, err
}

// textEntry reads a metadata_props entry: key and value are both free text.
func (d *decoder) textEntry(end int64) error {
	var s seen
	return d.fields(end, func(f int32, wt int) error {
		switch f {
		case 1:
			return d.textField(&s, "StringStringEntryProto.key", f, wt, end, nil)
		case 2:
			return d.textField(&s, "StringStringEntryProto.value", f, wt, end, nil)
		}
		return d.unknown("StringStringEntryProto", f, wt, end)
	})
}

// nameEntry reads a StringStringEntryProto of names (a binding, a
// quantization parameter).
func (d *decoder) nameEntry(end int64) error {
	var s seen
	return d.fields(end, func(f int32, wt int) error {
		switch f {
		case 1:
			return d.skipString(&s, "StringStringEntryProto.key", f, wt, end)
		case 2:
			return d.skipString(&s, "StringStringEntryProto.value", f, wt, end)
		}
		return d.unknown("StringStringEntryProto", f, wt, end)
	})
}

func (d *decoder) valueInfo(end int64) error {
	var s seen
	return d.fields(end, func(f int32, wt int) error {
		switch f {
		case 1:
			return d.skipString(&s, "ValueInfoProto.name", f, wt, end)
		case 2:
			return d.msgField(&s, "ValueInfoProto.type", f, wt, end, d.typeProto)
		case 3:
			return d.textField(&s, "ValueInfoProto.doc_string", f, wt, end, nil)
		case 4:
			return d.msgField(nil, "ValueInfoProto.metadata_props", f, wt, end, d.textEntry)
		}
		return d.unknown("ValueInfoProto", f, wt, end)
	})
}

func (d *decoder) trainingInfo(end int64) error {
	d.m.TrainingInfo++
	var s seen
	return d.fields(end, func(f int32, wt int) error {
		switch f {
		case 1:
			return d.msgField(&s, "TrainingInfoProto.initialization", f, wt, end, func(e int64) error {
				return d.subgraph(e, "training initialization")
			})
		case 2:
			return d.msgField(&s, "TrainingInfoProto.algorithm", f, wt, end, func(e int64) error {
				return d.subgraph(e, "training algorithm")
			})
		case 3, 4:
			return d.msgField(nil, "TrainingInfoProto binding", f, wt, end, d.nameEntry)
		}
		return d.unknown("TrainingInfoProto", f, wt, end)
	})
}

func (d *decoder) function(end int64) error {
	var s seen
	fn := Function{}
	outer := d.scope
	d.scope = outer + "function: "
	n := &nodeInfo{embedMode: 1}
	err := d.fields(end, func(f int32, wt int) error {
		switch f {
		case 1:
			return d.identField(&s, "FunctionProto.name", f, wt, end, func(v string) {
				fn.Name = v
				d.scope = outer + "function " + quote(v) + ": "
			})
		case 4, 5, 6:
			return d.skipString(nil, "FunctionProto.input, output, or attribute", f, wt, end)
		case 11:
			return d.msgField(nil, "FunctionProto.attribute_proto", f, wt, end, func(e int64) error { return d.attribute(e, n) })
		case 7:
			return d.msgField(nil, "FunctionProto.node", f, wt, end, d.node)
		case 8:
			return d.textField(&s, "FunctionProto.doc_string", f, wt, end, nil)
		case 9:
			return d.msgField(nil, "FunctionProto.opset_import", f, wt, end, d.functionOpset)
		case 10:
			return d.identField(&s, "FunctionProto.domain", f, wt, end, func(v string) { fn.Domain = v })
		case 13:
			return d.identField(&s, "FunctionProto.overload", f, wt, end, func(v string) { fn.Overload = v })
		case 12:
			return d.msgField(nil, "FunctionProto.value_info", f, wt, end, d.valueInfo)
		case 14:
			return d.msgField(nil, "FunctionProto.metadata_props", f, wt, end, d.textEntry)
		}
		return d.unknown("FunctionProto", f, wt, end, 2, 3)
	})
	d.scope = outer
	if err != nil {
		return err
	}
	// A default ep_cache_context on a function attribute is text.
	if n.ctx.present {
		d.keep(n.ctx.value, n.ctx.read, n.ctx.bytes)
	}
	if len(d.m.Functions) >= maxFunctions {
		return d.errf("more than %d functions", maxFunctions)
	}
	if fn.Domain == "ai.onnx" {
		fn.Domain = ""
	}
	d.m.Functions = append(d.m.Functions, fn)
	return nil
}

func (d *decoder) functionOpset(end int64) error {
	var s seen
	return d.fields(end, func(f int32, wt int) error {
		switch f {
		case 1:
			return d.skipString(&s, "OperatorSetIdProto.domain", f, wt, end)
		case 2:
			return d.intField(&s, "OperatorSetIdProto.version", f, wt, end, nil)
		}
		return d.unknown("OperatorSetIdProto", f, wt, end)
	})
}

// --- messages read only to check their fields ---

func (d *decoder) typeProto(end int64) error {
	var s seen
	member := func(name string, f int32, wt int, fn func(int64) error) error {
		if wt == wireBytes {
			d.oneof(&s, "TypeProto.value")
		}
		return d.msgField(&s, name, f, wt, end, fn)
	}
	return d.fields(end, func(f int32, wt int) error {
		switch f {
		case 1:
			return member("TypeProto.tensor_type", f, wt, d.typeTensor)
		case 8:
			return member("TypeProto.sparse_tensor_type", f, wt, d.typeTensor)
		case 4:
			return member("TypeProto.sequence_type", f, wt, d.typeElem)
		case 9:
			return member("TypeProto.optional_type", f, wt, d.typeElem)
		case 5:
			return member("TypeProto.map_type", f, wt, d.typeMap)
		case 7:
			return member("TypeProto.opaque_type", f, wt, d.typeOpaque)
		case 6:
			return d.skipString(&s, "TypeProto.denotation", f, wt, end)
		}
		return d.unknown("TypeProto", f, wt, end)
	})
}

func (d *decoder) typeTensor(end int64) error {
	var s seen
	return d.fields(end, func(f int32, wt int) error {
		switch f {
		case 1:
			return d.intField(&s, "TypeProto.Tensor.elem_type", f, wt, end, nil)
		case 2:
			return d.msgField(&s, "TypeProto.Tensor.shape", f, wt, end, d.tensorShape)
		}
		return d.unknown("TypeProto.Tensor", f, wt, end)
	})
}

func (d *decoder) typeElem(end int64) error {
	var s seen
	return d.fields(end, func(f int32, wt int) error {
		if f == 1 {
			return d.msgField(&s, "TypeProto.Sequence or Optional elem_type", f, wt, end, d.typeProto)
		}
		return d.unknown("TypeProto.Sequence or Optional", f, wt, end)
	})
}

func (d *decoder) typeMap(end int64) error {
	var s seen
	return d.fields(end, func(f int32, wt int) error {
		switch f {
		case 1:
			return d.intField(&s, "TypeProto.Map.key_type", f, wt, end, nil)
		case 2:
			return d.msgField(&s, "TypeProto.Map.value_type", f, wt, end, d.typeProto)
		}
		return d.unknown("TypeProto.Map", f, wt, end)
	})
}

func (d *decoder) typeOpaque(end int64) error {
	var s seen
	return d.fields(end, func(f int32, wt int) error {
		switch f {
		case 1, 2:
			return d.skipString(&s, "TypeProto.Opaque.domain or name", f, wt, end)
		}
		return d.unknown("TypeProto.Opaque", f, wt, end, 3)
	})
}

func (d *decoder) tensorShape(end int64) error {
	return d.fields(end, func(f int32, wt int) error {
		if f == 1 {
			return d.msgField(nil, "TensorShapeProto.dim", f, wt, end, d.dimension)
		}
		return d.unknown("TensorShapeProto", f, wt, end)
	})
}

func (d *decoder) dimension(end int64) error {
	var s seen
	return d.fields(end, func(f int32, wt int) error {
		switch f {
		case 1:
			if wt == wireVarint {
				d.oneof(&s, "TensorShapeProto.Dimension.value")
			}
			return d.intField(&s, "TensorShapeProto.Dimension.dim_value", f, wt, end, nil)
		case 2:
			if wt == wireBytes {
				d.oneof(&s, "TensorShapeProto.Dimension.value")
			}
			return d.skipString(&s, "TensorShapeProto.Dimension.dim_param", f, wt, end)
		case 3:
			return d.skipString(&s, "TensorShapeProto.Dimension.denotation", f, wt, end)
		}
		return d.unknown("TensorShapeProto.Dimension", f, wt, end)
	})
}

func (d *decoder) tensorAnnotation(end int64) error {
	var s seen
	return d.fields(end, func(f int32, wt int) error {
		switch f {
		case 1:
			return d.skipString(&s, "TensorAnnotation.tensor_name", f, wt, end)
		case 2:
			return d.msgField(nil, "TensorAnnotation.quant_parameter_tensor_names", f, wt, end, d.nameEntry)
		}
		return d.unknown("TensorAnnotation", f, wt, end)
	})
}

func (d *decoder) deviceConfiguration(end int64) error {
	var s seen
	return d.fields(end, func(f int32, wt int) error {
		switch f {
		case 1:
			return d.skipString(&s, "DeviceConfigurationProto.name", f, wt, end)
		case 2:
			return d.intField(&s, "DeviceConfigurationProto.num_devices", f, wt, end, nil)
		case 3:
			return d.skipString(nil, "DeviceConfigurationProto.device", f, wt, end)
		}
		return d.unknown("DeviceConfigurationProto", f, wt, end)
	})
}

func (d *decoder) nodeDeviceConfiguration(end int64) error {
	var s seen
	return d.fields(end, func(f int32, wt int) error {
		switch f {
		case 1:
			return d.skipString(&s, "NodeDeviceConfigurationProto.configuration_id", f, wt, end)
		case 2:
			return d.msgField(nil, "NodeDeviceConfigurationProto.sharding_spec", f, wt, end, d.shardingSpec)
		case 3:
			return d.intField(&s, "NodeDeviceConfigurationProto.pipeline_stage", f, wt, end, nil)
		}
		return d.unknown("NodeDeviceConfigurationProto", f, wt, end)
	})
}

func (d *decoder) shardingSpec(end int64) error {
	var s seen
	return d.fields(end, func(f int32, wt int) error {
		switch f {
		case 1:
			return d.skipString(&s, "ShardingSpecProto.tensor_name", f, wt, end)
		case 2:
			_, err := d.varints("ShardingSpecProto.device", wt, end, nil)
			return err
		case 3:
			return d.msgField(nil, "ShardingSpecProto.index_to_device_group_map", f, wt, end, d.intIntList)
		case 4:
			return d.msgField(nil, "ShardingSpecProto.sharded_dim", f, wt, end, d.shardedDim)
		}
		return d.unknown("ShardingSpecProto", f, wt, end)
	})
}

func (d *decoder) intIntList(end int64) error {
	var s seen
	return d.fields(end, func(f int32, wt int) error {
		switch f {
		case 1:
			return d.intField(&s, "IntIntListEntryProto.key", f, wt, end, nil)
		case 2:
			_, err := d.varints("IntIntListEntryProto.value", wt, end, nil)
			return err
		}
		return d.unknown("IntIntListEntryProto", f, wt, end)
	})
}

func (d *decoder) shardedDim(end int64) error {
	var s seen
	return d.fields(end, func(f int32, wt int) error {
		switch f {
		case 1:
			return d.intField(&s, "ShardedDimProto.axis", f, wt, end, nil)
		case 2:
			return d.msgField(nil, "ShardedDimProto.simple_sharding", f, wt, end, d.simpleShardedDim)
		}
		return d.unknown("ShardedDimProto", f, wt, end)
	})
}

func (d *decoder) simpleShardedDim(end int64) error {
	var s seen
	return d.fields(end, func(f int32, wt int) error {
		switch f {
		case 1:
			if wt == wireVarint {
				d.oneof(&s, "SimpleShardedDimProto.dim")
			}
			return d.intField(&s, "SimpleShardedDimProto.dim_value", f, wt, end, nil)
		case 2:
			if wt == wireBytes {
				d.oneof(&s, "SimpleShardedDimProto.dim")
			}
			return d.skipString(&s, "SimpleShardedDimProto.dim_param", f, wt, end)
		case 3:
			return d.intField(&s, "SimpleShardedDimProto.num_shards", f, wt, end, nil)
		}
		return d.unknown("SimpleShardedDimProto", f, wt, end)
	})
}

// quote names a value for a label, cut to a readable length.
func quote(s string) string {
	const max = 80
	if len(s) > max {
		s = s[:max] + "..."
	}
	return strconv.Quote(s)
}

// Label names an operator for a note: "com.microsoft::MatMulNBits".
func (o Op) Label() string {
	s := o.Type
	if o.Domain != "" {
		s = o.Domain + "::" + s
	}
	if o.Overload != "" {
		s += " (overload " + o.Overload + ")"
	}
	return s
}

// String names an opset import: "ai.onnx v14".
func (o Opset) String() string {
	d := o.Domain
	if d == "" {
		d = "ai.onnx"
	}
	return d + " v" + strconv.FormatInt(o.Version, 10)
}

// JoinOpsets lists opset imports.
func JoinOpsets(opsets []Opset) string {
	parts := make([]string, 0, len(opsets))
	for _, o := range opsets {
		parts = append(parts, o.String())
	}
	return strings.Join(parts, ", ")
}
