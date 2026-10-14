package onnx

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/onnx/onnxtest"
)

func parse(t *testing.T, b []byte) *Model {
	t.Helper()
	m, err := read(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return m
}

func parseErr(t *testing.T, b []byte) error {
	t.Helper()
	_, err := read(bytes.NewReader(b), int64(len(b)))
	if err == nil {
		t.Fatal("read accepted malformed bytes")
	}
	return err
}

func i64(v int64) *int64 { return &v }

func TestReadClean(t *testing.T) {
	m := parse(t, onnxtest.Clean().Bytes())
	if !m.HasIRVersion || m.IRVersion != 8 || !m.HasGraph || m.Producer != "pytorch" || m.ProducerVersion != "2.5.0" {
		t.Fatalf("model fields: %+v", m)
	}
	if len(m.Opsets) != 1 || m.Opsets[0] != (Opset{"", 17}) {
		t.Errorf("opsets %v", m.Opsets)
	}
	if m.Nodes != 2 || m.Graphs != 1 || m.MaxNesting != 0 {
		t.Errorf("nodes %d graphs %d nesting %d", m.Nodes, m.Graphs, m.MaxNesting)
	}
	if len(m.Ops) != 2 || m.Ops[0].Type != "Add" || m.Ops[1].Type != "MatMul" {
		t.Errorf("ops %v", m.Ops)
	}
	if len(m.Tensors) != 2 {
		t.Fatalf("tensors %v", m.Tensors)
	}
	w := m.Tensors[0]
	if w.Name != "w" || w.Kind != Initializer || w.Graph != 0 || w.DataType != 1 || !w.HasRaw || w.RawBytes != 64 ||
		len(w.Dims) != 2 || w.Dims[0] != 4 || w.Where != `initializer "w"` {
		t.Errorf("w = %+v", w)
	}
	if len(m.Unread) != 0 || len(m.Text) != 2 {
		t.Errorf("unread %v text %q", m.Unread, m.Text)
	}
}

func TestSniff(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if !Sniff(write("m.onnx", onnxtest.Clean().Bytes())) {
		t.Error("a clean model is not recognised")
	}
	// A model with a field a newer onnx.proto might define is still ONNX.
	newer := onnxtest.Clean()
	newer.Extra = onnxtest.AppendInt(nil, 99, 1)
	if !Sniff(write("newer.onnx", newer.Bytes())) {
		t.Error("an unknown top-level field stopped recognition")
	}
	noGraph := onnxtest.Clean()
	noGraph.Graph = nil
	// A TensorFlow SavedModel begins as a ModelProto would (field 1 varint,
	// field 2 bytes) but has no field 7.
	savedModel := onnxtest.AppendBytes(onnxtest.AppendInt(nil, 1, 1), 2, []byte("meta graph"))
	for name, b := range map[string][]byte{
		"empty":       nil,
		"gguf":        []byte("GGUF\x03\x00\x00\x00"),
		"safetensors": append([]byte{2, 0, 0, 0, 0, 0, 0, 0}, "{}"...),
		"no graph":    noGraph.Bytes(),
		"savedmodel":  savedModel,
		"truncated":   onnxtest.Clean().Bytes()[:20],
		"pickle":      []byte("\x80\x02}q\x00."),
	} {
		if Sniff(write(name, b)) {
			t.Errorf("%s is recognised as ONNX", name)
		}
	}
	if Sniff(filepath.Join(dir, "missing")) || Sniff(dir) {
		t.Error("a missing file or a directory is recognised")
	}
}

// TestUnreadFields pins each way protobuf keeps bytes a loader does not read.
func TestUnreadFields(t *testing.T) {
	cases := map[string]struct {
		model func() onnxtest.Model
		want  string
	}{
		"unknown field": {func() onnxtest.Model {
			m := onnxtest.Clean()
			m.Extra = onnxtest.AppendBytes(nil, 99, []byte("hidden"))
			return m
		}, "ModelProto field 99 (a field onnx.proto does not define)"},
		"reserved field": {func() onnxtest.Model {
			m := onnxtest.Clean()
			m.Graph.Extra = onnxtest.AppendInt(nil, 3, 7)
			return m
		}, "GraphProto field 3 (a field number onnx.proto reserves)"},
		"wrong wire type": {func() onnxtest.Model {
			m := onnxtest.Clean()
			m.Extra = onnxtest.AppendBytes(nil, 1, []byte("eight"))
			return m
		}, "ModelProto.ir_version in wire type 2"},
		"enum value outside its enum": {func() onnxtest.Model {
			m := onnxtest.Clean()
			m.Graph.Initializers[0].Location = 2
			return m
		}, "TensorProto.data_location value 2, outside its enum"},
		"singular field twice": {func() onnxtest.Model {
			m := onnxtest.Clean()
			m.Graph.Initializers[0].Extra = onnxtest.AppendBytes(nil, 9, make([]byte, 64))
			return m
		}, "TensorProto.raw_data appears more than once"},
		"oneof twice": {func() onnxtest.Model {
			m := onnxtest.Clean()
			var tp []byte
			tp = onnxtest.AppendBytes(tp, 1, onnxtest.AppendInt(nil, 1, 1))
			tp = onnxtest.AppendBytes(tp, 4, nil)
			vi := onnxtest.AppendBytes(onnxtest.AppendBytes(nil, 1, []byte("x")), 2, tp)
			m.Graph.Extra = onnxtest.AppendBytes(nil, 11, vi)
			return m
		}, "TypeProto.value sets more than one member of a oneof"},
	}
	for name, c := range cases {
		m := parse(t, c.model().Bytes())
		if len(m.Unread) != 1 || !strings.Contains(m.Unread[0], c.want) {
			t.Errorf("%s: unread %q, want %q", name, m.Unread, c.want)
		}
	}
	if m := parse(t, onnxtest.Clean().Bytes()); len(m.Unread) != 0 {
		t.Errorf("a clean model has unread fields: %v", m.Unread)
	}
}

func TestMalformed(t *testing.T) {
	clean := onnxtest.Clean().Bytes()
	for name, b := range map[string][]byte{
		"truncated":        clean[:len(clean)-3],
		"length overrun":   onnxtest.AppendVarint(onnxtest.AppendTag(nil, 7, 2), 1000),
		"group":            onnxtest.AppendTag(nil, 7, 3),
		"field zero":       {0x00, 0x01},
		"overlong varint":  append([]byte{0x08}, bytes.Repeat([]byte{0xff}, 11)...),
		"varint overflow":  {0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02},
		"bad packed float": onnxtest.Model{IRVersion: 8, Graph: &onnxtest.Graph{Initializers: []onnxtest.Tensor{{Extra: onnxtest.AppendBytes(nil, 4, []byte{1, 2, 3})}}}}.Bytes(),
		"packed ends mid":  onnxtest.Model{IRVersion: 8, Graph: &onnxtest.Graph{Initializers: []onnxtest.Tensor{{Extra: onnxtest.AppendBytes(nil, 5, []byte{0x80})}}}}.Bytes(),
	} {
		err := parseErr(t, b)
		var pe *ParseError
		if !errors.As(err, &pe) {
			t.Errorf("%s: %v is not a ParseError", name, err)
		}
	}
}

// nested is a model whose graph holds an If node whose then_branch holds
// another, depth times.
func nested(depth int) onnxtest.Model {
	g := onnxtest.CleanGraph()
	for i := 0; i < depth; i++ {
		inner := *g
		g = &onnxtest.Graph{Nodes: []onnxtest.Node{{OpType: "If", Name: "if", Attrs: []onnxtest.Attr{{Name: "then_branch", Type: 5, G: &inner}}}}}
	}
	m := onnxtest.Clean()
	m.Graph = g
	return m
}

func TestNestingBound(t *testing.T) {
	m := parse(t, nested(10).Bytes())
	if m.MaxNesting != 10 || m.Graphs != 11 || m.Nodes != 12 || len(m.Tensors) != 2 {
		t.Errorf("nesting %d graphs %d nodes %d tensors %d", m.MaxNesting, m.Graphs, m.Nodes, len(m.Tensors))
	}
	if !strings.HasPrefix(m.Tensors[0].Where, `node "if" (If) attribute "then_branch": `) {
		t.Errorf("a nested tensor is labelled %q", m.Tensors[0].Where)
	}
	// Each level is three messages deep (graph, node, attribute).
	err := parseErr(t, nested(40).Bytes())
	if !strings.Contains(err.Error(), "recursion limit") {
		t.Errorf("deep nesting: %v", err)
	}
}

func TestFileSizeBound(t *testing.T) {
	_, err := read(bytes.NewReader(nil), MaxFileBytes+1)
	if err == nil || !strings.Contains(err.Error(), "INT_MAX") {
		t.Errorf("a file past protobuf's limit: %v", err)
	}
}

func TestText(t *testing.T) {
	long := strings.Repeat("x", ArrayScanMin)
	m := onnxtest.Clean()
	m.Doc = "model doc"
	m.Domain = "com.example"
	m.Metadata = []onnxtest.KV{{Key: "key", Value: "value"}}
	m.Graph.Doc = "graph doc"
	m.Graph.Nodes[0].Doc = "node doc"
	m.Graph.Nodes[0].Attrs = []onnxtest.Attr{
		{Name: "mode", Type: 3, S: []byte("constant")},
		{Name: "labels", Type: 8, Strings: [][]byte{[]byte("short"), []byte(long)}},
	}
	m.Graph.Initializers = append(m.Graph.Initializers, onnxtest.Tensor{Name: "s", DataType: onnxtest.String, Dims: []int64{2},
		Strings: [][]byte{[]byte("tiny"), []byte(long + "!")}, Doc: "tensor doc"})
	got := parse(t, m.Bytes())
	for _, want := range []string{"pytorch", "2.5.0", "com.example", "model doc", "key", "value", "graph doc", "node doc", "constant", long, long + "!", "tensor doc"} {
		found := false
		for _, v := range got.Text {
			found = found || v == want
		}
		if !found {
			t.Errorf("text lacks %q: %q", want, got.Text)
		}
	}
	if got.ShortElements != 2 {
		t.Errorf("short elements %d, want 2 (\"short\", \"tiny\")", got.ShortElements)
	}
	var total int64
	for _, v := range got.Text {
		total += int64(len(v))
	}
	if total != got.TextBytes || got.TextTruncated {
		t.Errorf("text bytes %d, counted %d, truncated %v", total, got.TextBytes, got.TextTruncated)
	}
}

func TestEPContext(t *testing.T) {
	blob := append([]byte("\x7fELF"), make([]byte, 100)...)
	ep := func(op, domain string, embed int64, ctx []byte) onnxtest.Model {
		m := onnxtest.Clean()
		m.Graph.Nodes = append(m.Graph.Nodes, onnxtest.Node{Name: "ctx", OpType: op, Domain: domain, Attrs: []onnxtest.Attr{
			{Name: "embed_mode", Type: 2, I: i64(embed)}, {Name: "ep_cache_context", Type: 3, S: ctx}, {Name: "notes", Type: 3, S: []byte("a note")}}})
		return m
	}
	m := parse(t, ep("EPContext", "com.microsoft", 1, blob).Bytes())
	if len(m.EPContexts) != 1 || m.EPContexts[0].EmbedMode != 1 || m.EPContexts[0].ContextBytes != int64(len(blob)) || m.EPContexts[0].ContextRead {
		t.Fatalf("embedded context: %+v", m.EPContexts)
	}
	for _, v := range m.Text {
		if strings.Contains(v, "ELF") {
			t.Error("an embedded context reached the text")
		}
	}
	if !contains(m.Text, "a note") {
		t.Error("an EPContext's other string attributes are text")
	}
	m = parse(t, ep("EPContext", "com.microsoft", 0, []byte("ctx/model_ctx.bin")).Bytes())
	if e := m.EPContexts[0]; e.EmbedMode != 0 || !e.ContextRead || e.Context != "ctx/model_ctx.bin" {
		t.Errorf("context path: %+v", e)
	}
	// On any other operator the attribute is ordinary text.
	m = parse(t, ep("Relu", "", 1, []byte("ordinary")).Bytes())
	if len(m.EPContexts) != 0 || !contains(m.Text, "ordinary") {
		t.Errorf("ep_cache_context on another operator: contexts %v text %q", m.EPContexts, m.Text)
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func TestOpsAndFunctions(t *testing.T) {
	m := onnxtest.Clean()
	m.Graph.Nodes = append(m.Graph.Nodes,
		onnxtest.Node{OpType: "Relu", Domain: "ai.onnx"},
		onnxtest.Node{OpType: "FastGelu", Domain: "com.microsoft"},
		onnxtest.Node{OpType: "Helper", Domain: "local.fn"})
	m.Functions = []onnxtest.Function{{Name: "Helper", Domain: "local.fn", Nodes: []onnxtest.Node{{OpType: "Custom", Domain: "com.example"}}}}
	got := parse(t, m.Bytes())
	want := []string{"Add", "MatMul", "Relu", "com.example::Custom", "com.microsoft::FastGelu", "local.fn::Helper"}
	if len(got.Ops) != len(want) {
		t.Fatalf("ops %v", got.Ops)
	}
	for i, o := range got.Ops {
		if o.Label() != want[i] {
			t.Errorf("op %d = %s, want %s", i, o.Label(), want[i])
		}
	}
	if len(got.Functions) != 1 || got.Functions[0] != (Function{Domain: "local.fn", Name: "Helper"}) || got.Nodes != 6 {
		t.Errorf("functions %v nodes %d", got.Functions, got.Nodes)
	}
}

func TestTensorCounts(t *testing.T) {
	m := onnxtest.Clean()
	unpacked := onnxtest.AppendTag(nil, 4, 5)
	unpacked = append(unpacked, 0, 0, 0x80, 0x3f)
	m.Graph.Initializers = []onnxtest.Tensor{
		{Name: "i32", DataType: onnxtest.Int32, Dims: []int64{3}, Int32s: []int32{-1, 300, 0}},
		{Name: "f", DataType: onnxtest.Float, Dims: []int64{3}, Floats: []float32{1, 2}, Extra: unpacked},
		{Name: "i64", DataType: onnxtest.Int64, Dims: []int64{2}, Int64s: []int64{1 << 40, -5}},
		{Name: "empty", DataType: onnxtest.Float, Dims: []int64{0}, RawSet: true},
	}
	// dims packed, as a proto3-style writer would.
	m.Graph.Initializers[0].Extra = onnxtest.AppendBytes(nil, 1, []byte{2, 3})
	got := parse(t, m.Bytes())
	ts := got.Tensors
	if ts[0].Int32s != 3 || len(ts[0].Dims) != 3 || ts[0].Dims[1] != 2 || ts[0].Dims[2] != 3 {
		t.Errorf("i32: %+v", ts[0])
	}
	if ts[1].Floats != 3 || ts[2].Int64s != 2 || !ts[3].HasRaw || ts[3].RawBytes != 0 {
		t.Errorf("counts: f %d i64 %d empty %+v", ts[1].Floats, ts[2].Int64s, ts[3])
	}
}

func TestSparseAndAttributeTensors(t *testing.T) {
	m := onnxtest.Clean()
	m.Graph.Sparse = []onnxtest.Sparse{{Values: onnxtest.FloatWeight("sp", 3), Indices: onnxtest.Tensor{DataType: onnxtest.Int64, Dims: []int64{3}, Int64s: []int64{0, 1, 2}}, Dims: []int64{8}}}
	c := onnxtest.FloatWeight("const", 2)
	m.Graph.Nodes = append(m.Graph.Nodes, onnxtest.Node{Name: "c", OpType: "Constant", Outputs: []string{"k"}, Attrs: []onnxtest.Attr{{Name: "value", Type: 4, T: &c}}})
	got := parse(t, m.Bytes())
	var kinds []Kind
	for _, tt := range got.Tensors {
		kinds = append(kinds, tt.Kind)
	}
	// Nodes come first in the graph, so the Constant's tensor is read first.
	if len(got.Tensors) != 5 || got.Tensors[3].Kind != SparseValues || got.Tensors[3].Graph != 0 || got.Tensors[4].Kind != SparseIndices ||
		got.Tensors[0].Kind != Attribute || got.Tensors[0].Graph != -1 || got.Tensors[3].Where != `sparse initializer values "sp"` {
		t.Fatalf("kinds %v", kinds)
	}
	if got.Tensors[0].Where != `node "c" (Constant) attribute "value" (tensor "const")` {
		t.Errorf("attribute tensor labelled %q", got.Tensors[0].Where)
	}
}
