// Package openvino reads an OpenVINO IR model's XML, the .xml of an .xml and
// .bin pair, for the structure and inventory checks.
//
// The reference is OpenVINO 2026.4.1 (commit e213a1472576): its IR frontend
// (src/frontends/ir/src/frontend.cpp and input_model.cpp) and the XML
// deserializer it reads a model with (src/core/xml_util/src/
// xml_deserialize_util.cpp). The reader records what that deserializer would
// build: which layers it builds (those an output depends on), the operation
// type and opset of each, every Const's element type, shape, offset, and
// size, and the model's text. It runs no operation and reads no weights; the
// structure check finds and sizes the .bin.
//
// Where OpenVINO's XML parser, pugixml, reads a document differently from a
// conforming XML parser, the reader follows pugixml and records it:
//
//   - an attribute repeated on one element, which XML forbids and pugixml
//     reads the first of, is in Model.Duplicates, as is a layer id repeated
//     in one graph, of which OpenVINO builds the last;
//   - an element OpenVINO reads once (a layer's <data>, a net's <layers>)
//     repeated, and an element where the IR has none, are in Model.Unread:
//     OpenVINO does not read them.
//
// The XML is read with encoding/xml, which processes no DTD and resolves no
// external entity: an entity reference other than XML's five and character
// references is an error, so is a document that declares an encoding other
// than UTF-8, and a DOCTYPE is recorded, not processed. Malformed XML is an
// error: the model is unparseable.
//
// Bounds: a file larger than MaxFileBytes, elements nested deeper than
// MaxDepth, and the counts below are errors, not partial results. Text past
// its own cap is not kept, and Model.TextTruncated says so.
package openvino

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Bounds. OpenVINO sets none of its own; the largest IR measured
// (OpenVINO/Qwen3.8-27B-int4-ov, 2026-10-14) is a 9.7 MB XML.
const (
	MaxFileBytes = 256 << 20
	MaxDepth     = 256

	maxElements   = 1 << 23
	maxAttrs      = 1 << 12
	maxValue      = 16 << 20 // one attribute value, text, or comment
	maxLayers     = 1 << 20
	maxEdges      = 1 << 22
	maxGraphs     = 1 << 16
	maxTextTotal  = 64 << 20
	maxTextValues = 1 << 20
	maxNotes      = 64
	maxUnbuilt    = 10
)

// Model is what the reader found in an IR.
type Model struct {
	// Root is the root element's name as written; the IR reader takes any
	// spelling of "net".
	Root string
	// Version is the net's version attribute, the IR version, as written,
	// and VersionOK whether it is a plain decimal number. OpenVINO 2026.4.1
	// reads versions 10 and 11.
	Version   string
	VersionOK bool
	Name      string

	// Graphs counts the graphs built: the net and every body OpenVINO reads.
	Graphs int
	// MaxNesting is the deepest body nesting built, 0 for a model with none.
	MaxNesting int
	// Layers counts every <layer>; Built those OpenVINO builds.
	Layers, Built int
	// Ops are the operations of built layers, by version and type as
	// written, with how many layers name each, sorted.
	Ops []Op
	// Consts are the built layers of type "Const", the layers that read the
	// .bin, in the order the graph is read.
	Consts []Const
	// Unbuilt names layers OpenVINO does not build (at most maxUnbuilt), and
	// UnbuiltCount counts them all: no output depends on them, a later layer
	// took their id, or they are in a body OpenVINO does not read.
	Unbuilt      []string
	UnbuiltCount int

	// Duplicates are repeated attributes and layer ids (see the package
	// comment). Malformed are what OpenVINO refuses that the checks do not
	// grade otherwise: a missing mandatory attribute, an edge from a layer
	// that is not there. Unread are constructs OpenVINO does not read, or
	// that this reader does not model. Each is capped and counted.
	Duplicates []string
	Malformed  []string
	Unread     []string

	// Text is the IR's text for the inventory, each distinct value once:
	// every element and attribute name, attribute value, character data,
	// comment, processing instruction, and declaration.
	Text          []string
	TextBytes     int64
	TextTruncated bool
}

// Op is one operation built layers name.
type Op struct {
	Version, Type string
	Count         int
}

// Const is one built Const layer and what its <data> says.
type Const struct {
	Where       string
	ElementType string
	Shape       []int64
	Offset      int64
	Size        int64
	// HasRange is set when offset and size are plain decimal numbers.
	HasRange bool
	// Problem says why the Const's data cannot be checked, or is "".
	Problem string
}

// ParseError is malformed or unexpected XML.
type ParseError struct {
	Line int
	Msg  string
}

func (e *ParseError) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("line %d: %s", e.Line, e.Msg)
	}
	return e.Msg
}

// WeightsPath is the .bin OpenVINO reads for the IR at p (slash-separated):
// p with its extension replaced by .bin (FrontEnd::load_impl,
// std::filesystem::path::replace_extension).
func WeightsPath(p string) string {
	base := path.Base(p)
	if i := strings.LastIndexByte(base, '.'); i > 0 {
		return p[:len(p)-len(base)+i] + ".bin"
	}
	return p + ".bin"
}

// Read parses the IR at path.
func Read(p string) (*Model, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	return read(f, st.Size())
}

// Sniff reports whether the file at path is an OpenVINO IR by its bytes: an
// XML document whose root element is net, in any case, as the IR frontend
// identifies one (get_ir_version in frontend.cpp). Only the prolog and the
// root's start tag are read; Read says why a document does not parse.
func Sniff(p string) bool {
	f, err := os.Open(p)
	if err != nil {
		return false
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return false
	}
	return sniff(f)
}

// sniffBytes bounds the prolog a sniff reads.
const sniffBytes = 1 << 20

func sniff(r io.Reader) bool {
	d := newDecoder(io.LimitReader(r, sniffBytes))
	for first := true; ; first = false {
		tok, err := d.RawToken()
		if err != nil {
			return false
		}
		switch t := tok.(type) {
		case xml.StartElement:
			return t.Name.Space == "" && strings.EqualFold(t.Name.Local, "net")
		case xml.CharData:
			if !blank(t, first) {
				return false
			}
		case xml.EndElement:
			return false
		}
	}
}

func newDecoder(r io.Reader) *xml.Decoder {
	d := xml.NewDecoder(r)
	d.Strict = true
	return d
}

// bom is UTF-8's byte order mark, which pugixml accepts at the start.
var bom = []byte{0xef, 0xbb, 0xbf}

// blank reports whether text outside the root is only white space, and a
// UTF-8 byte order mark when it opens the file.
func blank(b []byte, first bool) bool {
	if first {
		b = bytes.TrimPrefix(b, bom)
	}
	return len(bytes.TrimLeft(b, " \t\r\n")) == 0
}

// The parse keeps a frame per open element.
type kind int

const (
	kNet kind = iota
	kLayers
	kLayer
	kData
	kPorts
	kPort
	kDim
	kEdges
	kEdge
	kBody
	kFree // rt_info and other free-form subtrees: text only
)

type frame struct {
	kind kind
	name xml.Name
	g    *graph
	l    *layer
	seen map[string]bool
}

type graph struct {
	where  string // "" for the net
	layers []*layer
	edges  []edge
}

type layer struct {
	line                      int
	id                        int64
	idOK                      bool
	name, typ, version        string
	hasName, hasType, hasVers bool
	data                      map[string]string // the first <data>'s attributes
	hasData                   bool
	bodies                    map[string]*graph
	bodyOrder                 []string
}

type edge struct {
	from, to int64
	line     int
}

type reader struct {
	d        *xml.Decoder
	m        *Model
	stack    []frame
	elements int
	layers   int
	edges    int
	graphs   int
	net      *graph
	text     map[string]bool
	notes    map[string]map[string]int // kind of note -> message -> count
	order    map[string][]string
}

var plain = regexp.MustCompile(`^[0-9]{1,19}$`)

func read(src io.Reader, size int64) (*Model, error) {
	if size > MaxFileBytes {
		return nil, fmt.Errorf("the file is %d bytes, more than this reader's limit of %d", size, int64(MaxFileBytes))
	}
	r := &reader{
		d:     newDecoder(io.LimitReader(src, MaxFileBytes+1)),
		m:     &Model{},
		text:  map[string]bool{},
		notes: map[string]map[string]int{},
		order: map[string][]string{},
	}
	if err := r.parse(); err != nil {
		return nil, err
	}
	r.build()
	m := r.m
	m.Duplicates = r.list("dup")
	m.Malformed = r.list("malformed")
	m.Unread = r.list("unread")
	return m, nil
}

func (r *reader) errf(format string, args ...any) error {
	line, _ := r.d.InputPos()
	return &ParseError{Line: line, Msg: fmt.Sprintf(format, args...)}
}

func (r *reader) line() int {
	line, _ := r.d.InputPos()
	return line
}

// note records one message of a kind, counted; at most maxNotes distinct.
func (r *reader) note(kind, msg string) {
	m := r.notes[kind]
	if m == nil {
		m = map[string]int{}
		r.notes[kind] = m
	}
	if _, ok := m[msg]; !ok {
		if len(m) >= maxNotes {
			msg = "and more"
			if _, ok := m[msg]; !ok {
				r.order[kind] = append(r.order[kind], msg)
			}
			m[msg]++
			return
		}
		r.order[kind] = append(r.order[kind], msg)
	}
	m[msg]++
}

func (r *reader) list(kind string) []string {
	var out []string
	for _, msg := range r.order[kind] {
		if n := r.notes[kind][msg]; n > 1 && msg != "and more" {
			msg += fmt.Sprintf(" (%d times)", n)
		}
		out = append(out, msg)
	}
	return out
}

// keep adds a text value for the inventory, once.
func (r *reader) keep(s string) {
	if s == "" || r.text[s] {
		return
	}
	if len(r.m.Text) >= maxTextValues || r.m.TextBytes+int64(len(s)) > maxTextTotal {
		r.m.TextTruncated = true
		return
	}
	r.text[s] = true
	r.m.Text = append(r.m.Text, s)
	r.m.TextBytes += int64(len(s))
}

func qname(n xml.Name) string {
	if n.Space != "" {
		return n.Space + ":" + n.Local
	}
	return n.Local
}

func (r *reader) parse() error {
	rootSeen, rootDone := false, false
	for first := true; ; first = false {
		tok, err := r.d.RawToken()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			var se *xml.SyntaxError
			if errors.As(err, &se) {
				return &ParseError{Line: se.Line, Msg: se.Msg}
			}
			return r.errf("%v", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if rootDone {
				return r.errf("a second top-level element <%s>, which a conforming XML parser refuses and OpenVINO does not read", clip(qname(t.Name), 60))
			}
			if err := r.start(t, !rootSeen); err != nil {
				return err
			}
			rootSeen = true
		case xml.EndElement:
			if len(r.stack) == 0 {
				return r.errf("an end tag </%s> with no open element", clip(qname(t.Name), 60))
			}
			top := r.stack[len(r.stack)-1]
			if top.name != t.Name {
				return r.errf("the end tag </%s> does not close <%s>", clip(qname(t.Name), 60), clip(qname(top.name), 60))
			}
			r.stack = r.stack[:len(r.stack)-1]
			if len(r.stack) == 0 {
				rootDone = true
			}
		case xml.CharData:
			if len(r.stack) == 0 {
				if !blank(t, first) {
					return r.errf("text outside the root element")
				}
				continue
			}
			if len(t) > maxValue {
				return r.errf("text of %d bytes, more than this reader's limit of %d", len(t), maxValue)
			}
			if len(bytes.TrimSpace(t)) > 0 {
				r.keep(string(t))
			}
		case xml.Comment:
			if len(t) > maxValue {
				return r.errf("a comment of %d bytes, more than this reader's limit of %d", len(t), maxValue)
			}
			r.keep(string(t))
		case xml.ProcInst:
			if len(t.Inst) > maxValue {
				return r.errf("a processing instruction of %d bytes, more than this reader's limit of %d", len(t.Inst), maxValue)
			}
			if t.Target != "xml" {
				r.keep(t.Target + " " + string(t.Inst))
			}
		case xml.Directive:
			if len(t) > maxValue {
				return r.errf("a declaration of %d bytes, more than this reader's limit of %d", len(t), maxValue)
			}
			r.keep(string(t))
			r.note("unread", "a document type or other declaration (<!...>), which OpenVINO's XML parser skips and this reader does not process")
		}
	}
	if !rootSeen {
		return &ParseError{Msg: "the document has no root element"}
	}
	if len(r.stack) > 0 {
		return r.errf("the file ends inside <%s>", clip(qname(r.stack[len(r.stack)-1].name), 60))
	}
	return nil
}

func (r *reader) start(t xml.StartElement, root bool) error {
	r.elements++
	if r.elements > maxElements {
		return r.errf("more than %d elements", maxElements)
	}
	if len(r.stack) >= MaxDepth {
		return r.errf("elements nested more than %d deep", MaxDepth)
	}
	if len(t.Attr) > maxAttrs {
		return r.errf("an element with %d attributes, more than this reader's limit of %d", len(t.Attr), maxAttrs)
	}
	name := qname(t.Name)
	r.keep(name)
	attrs := map[string]string{}
	for _, a := range t.Attr {
		if len(a.Value) > maxValue {
			return r.errf("an attribute value of %d bytes, more than this reader's limit of %d", len(a.Value), maxValue)
		}
		an := qname(a.Name)
		r.keep(an)
		r.keep(a.Value)
		if _, dup := attrs[an]; dup {
			r.note("dup", fmt.Sprintf("attribute %s repeated on <%s> (line %d): XML forbids it, and pugixml, which OpenVINO reads with, takes the first",
				strconv.Quote(clip(an, 60)), clip(name, 60), r.line()))
			continue
		}
		attrs[an] = a.Value
	}

	if root {
		if t.Name.Space != "" || !strings.EqualFold(t.Name.Local, "net") {
			return r.errf("the root element is <%s>, not <net>: not an OpenVINO IR", clip(name, 60))
		}
		r.m.Root = name
		r.m.Version = attrs["version"]
		r.m.VersionOK = plain.MatchString(r.m.Version)
		r.m.Name = attrs["name"]
		r.graphs++
		r.net = &graph{}
		r.stack = append(r.stack, frame{kind: kNet, name: t.Name, g: r.net})
		return nil
	}

	parent := &r.stack[len(r.stack)-1]
	f := frame{kind: kFree, name: t.Name}
	unread := func(why string) {
		r.note("unread", fmt.Sprintf("<%s> in <%s>, %s", clip(name, 60), clip(qname(parent.name), 60), why))
	}
	// once opens a child OpenVINO reads only the first of (pugixml's
	// xml_node::child).
	once := func(k kind) bool {
		if parent.seen[name] {
			unread("repeated: OpenVINO reads the first and not this one")
			return false
		}
		if parent.seen == nil {
			parent.seen = map[string]bool{}
		}
		parent.seen[name] = true
		f.kind = k
		return true
	}
	const ignored = "which OpenVINO's IR reader does not read"
	switch parent.kind {
	case kNet, kBody:
		switch name {
		case "layers":
			once(kLayers)
			f.g = parent.g
		case "edges":
			once(kEdges)
			f.g = parent.g
		case "rt_info":
			once(kFree)
		case "meta_data", "quantization_parameters":
			if parent.kind == kNet {
				once(kFree)
			} else {
				unread(ignored)
			}
		case "pre-process":
			if parent.kind == kNet {
				unread("whose mean values OpenVINO reads from the .bin and this reader does not model")
			} else {
				unread(ignored)
			}
		default:
			unread(ignored)
		}
	case kLayers:
		if name != "layer" {
			unread(ignored)
			break
		}
		if r.layers++; r.layers > maxLayers {
			return r.errf("more than %d layers", maxLayers)
		}
		l := r.newLayer(attrs)
		parent.g.layers = append(parent.g.layers, l)
		f.kind, f.l = kLayer, l
	case kLayer:
		switch name {
		case "data":
			if once(kData) {
				parent.l.data, parent.l.hasData = attrs, true
			}
		case "input", "output":
			once(kPorts)
		case "rt_info", "port_map", "then_port_map", "else_port_map", "back_edges":
			once(kFree)
		case "body", "then_body", "else_body":
			if once(kBody) {
				if r.graphs++; r.graphs > maxGraphs {
					return r.errf("more than %d graphs", maxGraphs)
				}
				g := &graph{where: fmt.Sprintf("in the %s of %s", name, parent.l.label(""))}
				if parent.l.bodies == nil {
					parent.l.bodies = map[string]*graph{}
				}
				parent.l.bodies[name] = g
				parent.l.bodyOrder = append(parent.l.bodyOrder, name)
				f.g = g
			}
		default:
			unread(ignored)
		}
	case kPorts:
		if name == "port" {
			f.kind = kPort
		} else {
			unread(ignored)
		}
	case kPort:
		switch name {
		case "dim":
			f.kind = kDim
		case "rt_info":
			once(kFree)
		default:
			unread(ignored)
		}
	case kEdges:
		if name != "edge" {
			unread(ignored)
			break
		}
		if r.edges++; r.edges > maxEdges {
			return r.errf("more than %d edges", maxEdges)
		}
		f.kind = kEdge
		r.newEdge(parent.g, attrs)
	case kData, kDim, kEdge:
		unread(ignored)
	case kFree:
		// rt_info and the like hold any elements.
	}
	r.stack = append(r.stack, f)
	return nil
}

func (r *reader) newLayer(attrs map[string]string) *layer {
	l := &layer{line: r.line()}
	l.name, l.hasName = attrs["name"]
	l.typ, l.hasType = attrs["type"]
	l.version, l.hasVers = attrs["version"]
	idText, hasID := attrs["id"]
	switch {
	case !hasID:
		r.note("malformed", fmt.Sprintf("a layer with no id (line %d), which OpenVINO refuses", l.line))
	case !plain.MatchString(idText):
		r.note("malformed", fmt.Sprintf("layer id %s (line %d) is not a plain decimal number, which this reader does not read as OpenVINO does", strconv.Quote(clip(idText, 40)), l.line))
	default:
		if v, err := strconv.ParseInt(idText, 10, 64); err == nil {
			l.id, l.idOK = v, true
		} else {
			r.note("malformed", fmt.Sprintf("layer id %s (line %d) is out of range, which OpenVINO refuses", strconv.Quote(clip(idText, 40)), l.line))
		}
	}
	for _, a := range []struct {
		name string
		has  bool
	}{{"name", l.hasName}, {"type", l.hasType}, {"version", l.hasVers}} {
		if !a.has {
			r.note("malformed", fmt.Sprintf("a layer with no %s attribute (line %d), which OpenVINO refuses", a.name, l.line))
		}
	}
	return l
}

func (r *reader) newEdge(g *graph, attrs map[string]string) {
	e := edge{line: r.line()}
	ok := true
	for _, k := range []string{"from-layer", "from-port", "to-layer", "to-port"} {
		v, has := attrs[k]
		n, err := strconv.ParseInt(v, 10, 64)
		if !has || !plain.MatchString(v) || err != nil {
			r.note("malformed", fmt.Sprintf("an edge (line %d) whose %s is missing or not a plain decimal number, which this reader does not read as OpenVINO does", e.line, k))
			ok = false
			continue
		}
		switch k {
		case "from-layer":
			e.from = n
		case "to-layer":
			e.to = n
		}
	}
	if ok {
		g.edges = append(g.edges, e)
	}
}

func (l *layer) label(where string) string {
	s := "layer " + strconv.FormatInt(l.id, 10)
	if !l.idOK {
		s = fmt.Sprintf("the layer at line %d", l.line)
	}
	if l.hasName {
		s += " " + strconv.Quote(clip(l.name, 80))
	}
	if where != "" {
		s += " " + where
	}
	return s
}

// build works out which layers OpenVINO builds, as XmlDeserializer::
// parse_function does: every Parameter, and every layer a Result or an
// Assign depends on through the edges, found from the outputs back; a later
// layer with an id replaces an earlier one. A built TensorIterator or Loop
// has its body built the same way, and a built If its then_body and
// else_body.
func (r *reader) build() {
	ops := map[Op]int{}
	r.graph(r.net, true, 0, ops)
	for op, n := range ops {
		op.Count = n
		r.m.Ops = append(r.m.Ops, op)
	}
	sort.Slice(r.m.Ops, func(i, j int) bool {
		a, b := r.m.Ops[i], r.m.Ops[j]
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		return a.Type < b.Type
	})
}

func (r *reader) unbuilt(l *layer, where string) {
	r.m.UnbuiltCount++
	if len(r.m.Unbuilt) < maxUnbuilt {
		s := l.label(where)
		if l.hasType {
			s += " (" + clip(l.typ, 60) + ")"
		}
		r.m.Unbuilt = append(r.m.Unbuilt, s)
	}
}

func (r *reader) graph(g *graph, built bool, nesting int, ops map[Op]int) {
	r.m.Layers += len(g.layers)
	if !built {
		for _, l := range g.layers {
			r.unbuilt(l, g.where)
			for _, name := range l.bodyOrder {
				r.graph(l.bodies[name], false, nesting+1, ops)
			}
		}
		return
	}
	r.m.Graphs++
	if nesting > r.m.MaxNesting {
		r.m.MaxNesting = nesting
	}
	byID := map[int64]*layer{}
	for _, l := range g.layers {
		if !l.idOK {
			continue
		}
		if prev, ok := byID[l.id]; ok {
			r.note("dup", fmt.Sprintf("layer id %d%s is given to two layers (lines %d and %d): OpenVINO builds the later one and drops the other",
				l.id, suffix(g.where), prev.line, l.line))
		}
		byID[l.id] = l
	}
	into := map[int64][]int64{}
	for _, e := range g.edges {
		into[e.to] = append(into[e.to], e.from)
	}
	// Roots and Parameters are taken from every layer as read, before a
	// later layer replaces one with the same id, as parse_function does.
	done := map[int64]bool{}
	var stack []int64
	for _, l := range g.layers {
		switch {
		case !l.idOK:
		case l.typ == "Parameter":
			done[l.id] = true
		case l.typ == "Result" || l.typ == "Assign":
			stack = append(stack, l.id)
		}
	}
	for len(stack) > 0 {
		id := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if done[id] {
			continue
		}
		done[id] = true
		if _, ok := byID[id]; !ok {
			r.note("malformed", fmt.Sprintf("an edge from layer %d%s, which the graph does not define: OpenVINO refuses the model", id, suffix(g.where)))
			continue
		}
		for _, from := range into[id] {
			if !done[from] {
				stack = append(stack, from)
			}
		}
	}
	for _, l := range g.layers {
		if !l.idOK || byID[l.id] != l || !done[l.id] {
			r.unbuilt(l, g.where)
			for _, name := range l.bodyOrder {
				r.graph(l.bodies[name], false, nesting+1, ops)
			}
			continue
		}
		r.m.Built++
		ops[Op{Version: l.version, Type: l.typ}]++
		switch {
		case l.typ == "Const":
			r.m.Consts = append(r.m.Consts, r.constOf(l, g.where))
		case isOp(l.version, l.typ, "CONSTANT"):
			r.note("unread", fmt.Sprintf("a Constant layer of type %s, which OpenVINO builds from the XML (a value attribute in <data>), not from the .bin, and this reader does not model",
				strconv.Quote(clip(l.typ, 40))))
		}
		reads := map[string]bool{}
		switch {
		case isOp(l.version, l.typ, "TENSORITERATOR"), isOp(l.version, l.typ, "LOOP"):
			reads["body"] = true
		case isOp(l.version, l.typ, "IF"):
			reads["then_body"], reads["else_body"] = true, true
		}
		for _, name := range l.bodyOrder {
			if !reads[name] {
				r.note("unread", fmt.Sprintf("a <%s> under a layer of type %s, which OpenVINO reads only for TensorIterator, Loop, and If", name, strconv.Quote(clip(l.typ, 40))))
			}
			r.graph(l.bodies[name], reads[name], nesting+1, ops)
		}
	}
}

// constOf reads a built Const layer's <data>, as Constant::visit_attributes
// and XmlDeserializer::set_constant_num_buffer read it.
func (r *reader) constOf(l *layer, where string) Const {
	c := Const{Where: l.label(where)}
	if !l.hasData {
		c.Problem = "a Const with no <data>, which OpenVINO refuses"
		return c
	}
	et, ok := l.data["element_type"]
	c.ElementType = et
	if !ok {
		c.Problem = "a Const with no element_type, which OpenVINO refuses"
		return c
	}
	if _, ok := ElementTypes[et]; !ok {
		c.Problem = fmt.Sprintf("element type %s, which OpenVINO 2026.4.1 does not define for a Const, so it refuses it", strconv.Quote(clip(et, 40)))
		return c
	}
	shape, ok := l.data["shape"]
	if !ok {
		c.Problem = "a Const with no shape, which OpenVINO refuses"
		return c
	}
	dims, ok := parseShape(shape)
	if !ok {
		c.Problem = fmt.Sprintf("shape %s, which is not decimal numbers separated by commas, so this reader does not read it as OpenVINO does", strconv.Quote(clip(shape, 60)))
		return c
	}
	c.Shape = dims
	off, okOff := l.data["offset"]
	size, okSize := l.data["size"]
	if !okOff || !okSize {
		c.Problem = "a Const with no offset or no size, which OpenVINO refuses"
		return c
	}
	o, err1 := strconv.ParseInt(off, 10, 64)
	s, err2 := strconv.ParseInt(size, 10, 64)
	if !plain.MatchString(off) || !plain.MatchString(size) || err1 != nil || err2 != nil {
		c.Problem = fmt.Sprintf("offset %s or size %s is not a plain decimal number, which this reader does not read as OpenVINO does (it also takes a sign, leading spaces, and \"-0\")",
			strconv.Quote(clip(off, 30)), strconv.Quote(clip(size, 30)))
		return c
	}
	c.Offset, c.Size, c.HasRange = o, s, true
	return c
}

// parseShape reads a Const's shape as str_to_container does
// (xml_deserialize_util.hpp): fields split at commas as std::getline splits
// them, so a single trailing comma ends the list and "" is a scalar, each
// field trimmed of white space. A field must then be a plain decimal
// number. OpenVINO reads more (std::from_chars stops at the first
// non-digit, so it reads "4x" as 4); anything past plain digits is refused
// here, never read differently.
func parseShape(s string) ([]int64, bool) {
	if s == "" {
		return nil, true
	}
	fields := strings.Split(s, ",")
	if fields[len(fields)-1] == "" {
		fields = fields[:len(fields)-1]
	}
	dims := make([]int64, 0, len(fields))
	for _, f := range fields {
		f = strings.Trim(f, " \t\n\r")
		v, err := strconv.ParseInt(f, 10, 64)
		if !plain.MatchString(f) || err != nil {
			return nil, false
		}
		dims = append(dims, v)
	}
	return dims, true
}

// suffix is where with a leading space, or "" for the net.
func suffix(where string) string {
	if where == "" {
		return ""
	}
	return " " + where
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
