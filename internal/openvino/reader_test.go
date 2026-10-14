package openvino

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/openvino/openvinotest"
)

func parse(t *testing.T, m openvinotest.Model) *Model {
	t.Helper()
	b := m.XML()
	got, err := read(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("read: %v\n%s", err, b)
	}
	return got
}

func parseErr(t *testing.T, xml string) error {
	t.Helper()
	_, err := read(strings.NewReader(xml), int64(len(xml)))
	return err
}

func TestReadClean(t *testing.T) {
	m := parse(t, openvinotest.Clean())
	if m.Version != "11" || !m.VersionOK || m.Name != "Model0" || m.Root != "net" {
		t.Errorf("header %q %v %q %q", m.Version, m.VersionOK, m.Name, m.Root)
	}
	if m.Layers != 4 || m.Built != 4 || m.Graphs != 1 || m.UnbuiltCount != 0 {
		t.Errorf("layers %d built %d graphs %d unbuilt %d", m.Layers, m.Built, m.Graphs, m.UnbuiltCount)
	}
	if len(m.Consts) != 1 {
		t.Fatalf("consts %+v", m.Consts)
	}
	c := m.Consts[0]
	if c.ElementType != "f32" || len(c.Shape) != 1 || c.Shape[0] != 4 || c.Offset != 0 || c.Size != 16 || !c.HasRange || c.Problem != "" {
		t.Errorf("const %+v", c)
	}
	if len(m.Ops) != 4 {
		t.Errorf("ops %+v", m.Ops)
	}
	if len(m.Duplicates)+len(m.Malformed)+len(m.Unread) != 0 {
		t.Errorf("notes on a clean IR: %v %v %v", m.Duplicates, m.Malformed, m.Unread)
	}
	text := strings.Join(m.Text, "\n")
	for _, want := range []string{"pytorch", "is_python_object", "Model0", "auto_broadcast", "numpy"} {
		if !strings.Contains(text, want) {
			t.Errorf("text lacks %q", want)
		}
	}
	var total int64
	for _, s := range m.Text {
		total += int64(len(s))
	}
	if total != m.TextBytes {
		t.Errorf("TextBytes %d, text holds %d", m.TextBytes, total)
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
	upper := openvinotest.Clean()
	upper.Root = "NET"
	cases := map[string]struct {
		b    []byte
		want bool
	}{
		"clean":          {openvinotest.Clean().XML(), true},
		"root NET":       {upper.XML(), true},
		"comment first":  {[]byte("<?xml version=\"1.0\"?>\n<!-- c --><net version=\"11\"></net>"), true},
		"byte order":     {append([]byte{0xef, 0xbb, 0xbf}, "<net/>"...), true},
		"other root":     {[]byte("<model><net/></model>"), false},
		"prefixed root":  {[]byte(`<x:net xmlns:x="u"/>`), false},
		"text first":     {[]byte("hello <net/>"), false},
		"pickle":         {[]byte("\x80\x02}q\x00."), false},
		"empty":          {nil, false},
		"latin1":         {[]byte(`<?xml version="1.0" encoding="ISO-8859-1"?><net/>`), false},
		"net in comment": {[]byte("<!-- <net> --><graph/>"), false},
	}
	for name, c := range cases {
		if got := Sniff(write(name, c.b)); got != c.want {
			t.Errorf("%s: Sniff %v, want %v", name, got, c.want)
		}
	}
	if Sniff(dir) {
		t.Error("a directory sniffed as an IR")
	}
}

func TestWeightsPath(t *testing.T) {
	for in, want := range map[string]string{
		"openvino/openvino_model.xml": "openvino/openvino_model.bin",
		"m.XML":                       "m.bin",
		"a.b/model":                   "a.b/model.bin",
		"model.tar.xml":               "model.tar.bin",
		".xml":                        ".xml.bin",
	} {
		if got := WeightsPath(in); got != want {
			t.Errorf("WeightsPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestBuiltLayers: OpenVINO builds every Parameter and what a Result or an
// Assign depends on; a layer nothing reads, or one whose id a later layer
// took, is not built and its Const not read. Falsification: build every
// layer, or keep the first of a repeated id, and these fail.
func TestBuiltLayers(t *testing.T) {
	m := openvinotest.Clean()
	m.Layers = append(m.Layers, openvinotest.Const(7, "dangle", "f32", "4", 0, 16))
	got := parse(t, m)
	if got.Built != 4 || got.UnbuiltCount != 1 || len(got.Consts) != 1 || !strings.Contains(got.Unbuilt[0], `layer 7 "dangle" (Const)`) {
		t.Errorf("dangling Const: built %d unbuilt %d %v consts %d", got.Built, got.UnbuiltCount, got.Unbuilt, len(got.Consts))
	}

	m = openvinotest.Clean()
	dupe := openvinotest.Const(1, "w2", "f32", "4", 0, 16)
	m.Layers = append(m.Layers, dupe)
	got = parse(t, m)
	if len(got.Duplicates) != 1 || !strings.Contains(got.Duplicates[0], "layer id 1 is given to two layers") {
		t.Errorf("duplicate id: %v", got.Duplicates)
	}
	if len(got.Consts) != 1 || !strings.Contains(got.Consts[0].Where, `"w2"`) || got.UnbuiltCount != 1 {
		t.Errorf("OpenVINO builds the later layer: consts %+v unbuilt %v", got.Consts, got.Unbuilt)
	}

	// No Result: nothing but the Parameter is built.
	m = openvinotest.Clean()
	m.Layers[3].Type = "result"
	got = parse(t, m)
	if got.Built != 1 || len(got.Consts) != 0 {
		t.Errorf("lowercase result is no output for the reader: built %d consts %d", got.Built, len(got.Consts))
	}

	// An edge from a layer the graph lacks, reached from an output.
	m = openvinotest.Clean()
	m.Edges = append(m.Edges, openvinotest.Edge{From: 55, To: 2, ToPort: 0})
	got = parse(t, m)
	if len(got.Malformed) != 1 || !strings.Contains(got.Malformed[0], "edge from layer 55") {
		t.Errorf("edge from nowhere: %v", got.Malformed)
	}
}

// TestBodies: a built Loop's body, and a built If's then_body and
// else_body, are graphs OpenVINO builds; a body under any other layer is
// not read.
func TestBodies(t *testing.T) {
	body := openvinotest.Layers([]openvinotest.Layer{
		{ID: 0, Name: "bx", Type: "Parameter", Version: "opset1", Out: 1, Data: []openvinotest.Attr{{Name: "shape", Value: "4"}, {Name: "element_type", Value: "f32"}}},
		openvinotest.Const(1, "bw", "f32", "4", 0, 16),
		{ID: 2, Name: "badd", Type: "Add", Version: "opset1", In: 2, Out: 1},
		{ID: 3, Name: "bout", Type: "Result", Version: "opset1", In: 1},
	}, []openvinotest.Edge{{From: 0, FromPort: 0, To: 2, ToPort: 0}, {From: 1, FromPort: 0, To: 2, ToPort: 1}, {From: 2, FromPort: 2, To: 3, ToPort: 0}})
	loop := func(typ, version, name string) openvinotest.Model {
		m := openvinotest.Clean()
		m.Layers[2] = openvinotest.Layer{ID: 2, Name: "loop", Type: typ, Version: version, In: 2, Out: 1,
			Raw: "<port_map><input external_port_id=\"0\" internal_layer_id=\"0\"/></port_map><" + name + ">" + body + "</" + name + ">"}
		return m
	}
	got := parse(t, loop("Loop", "opset5", "body"))
	if got.Graphs != 2 || got.MaxNesting != 1 || len(got.Consts) != 2 || got.Layers != 8 || got.Built != 8 {
		t.Errorf("Loop body: graphs %d nesting %d consts %d layers %d built %d unread %v", got.Graphs, got.MaxNesting, len(got.Consts), got.Layers, got.Built, got.Unread)
	}
	if !strings.Contains(got.Consts[1].Where, `in the body of layer 2 "loop"`) {
		t.Errorf("body Const where: %s", got.Consts[1].Where)
	}
	got = parse(t, loop("loop", "opset5", "body"))
	if len(got.Consts) != 2 {
		t.Errorf("a type is looked up ignoring case: %d consts", len(got.Consts))
	}
	got = parse(t, loop("If", "opset8", "then_body"))
	if len(got.Consts) != 2 {
		t.Errorf("If then_body: %d consts", len(got.Consts))
	}
	got = parse(t, loop("Add", "opset1", "body"))
	if len(got.Consts) != 1 || got.UnbuiltCount != 4 || len(got.Unread) != 1 || !strings.Contains(got.Unread[0], "reads only for TensorIterator, Loop, and If") {
		t.Errorf("body under Add: consts %d unbuilt %d unread %v", len(got.Consts), got.UnbuiltCount, got.Unread)
	}
	got = parse(t, loop("Loop", "extension", "body"))
	if len(got.Consts) != 1 || got.UnbuiltCount != 4 {
		t.Errorf("body under an extension op: consts %d unbuilt %d", len(got.Consts), got.UnbuiltCount)
	}
}

// TestDuplicateAttributes: XML forbids a repeated attribute and pugixml
// reads the first. Falsification: drop the duplicate check, or keep the
// last value, and this fails.
func TestDuplicateAttributes(t *testing.T) {
	m := openvinotest.Clean()
	m.Layers[1].Data = []openvinotest.Attr{{Name: "element_type", Value: "f32"}, {Name: "shape", Value: "4"},
		{Name: "offset", Value: "0"}, {Name: "size", Value: "16"}, {Name: "size", Value: "4096"}}
	got := parse(t, m)
	if len(got.Duplicates) != 1 || !strings.Contains(got.Duplicates[0], `attribute "size" repeated on <data>`) {
		t.Errorf("duplicates %v", got.Duplicates)
	}
	if got.Consts[0].Size != 16 {
		t.Errorf("size %d: pugixml reads the first", got.Consts[0].Size)
	}
}

func TestUnread(t *testing.T) {
	cases := map[string]struct {
		edit func(*openvinotest.Model)
		want string
	}{
		"unknown net child": {func(m *openvinotest.Model) { m.Raw = "<zzz/>" }, "<zzz> in <net>"},
		"second layers": {func(m *openvinotest.Model) {
			m.Raw = openvinotest.Layers([]openvinotest.Layer{openvinotest.Const(9, "hidden", "f32", "4", 0, 16)}, nil)
		}, "<layers> in <net>, repeated"},
		"second data": {func(m *openvinotest.Model) {
			m.Layers[1].Raw = `<data element_type="f32" shape="4" offset="0" size="999"/>`
		}, "<data> in <layer>, repeated"},
		"pre-process":   {func(m *openvinotest.Model) { m.Raw = `<pre-process reference-layer-name="x"/>` }, "mean values"},
		"doctype":       {func(m *openvinotest.Model) { m.Prolog = "<!DOCTYPE net>\n" }, "document type"},
		"child of data": {func(m *openvinotest.Model) { m.Layers[2].Data = nil; m.Layers[2].Raw = "<data><x/></data>" }, "<x> in <data>"},
		"constant from xml": {func(m *openvinotest.Model) {
			m.Layers[1] = openvinotest.Layer{ID: 1, Name: "w", Type: "Constant", Version: "opset1", Out: 1,
				Data: []openvinotest.Attr{{Name: "element_type", Value: "f32"}, {Name: "shape", Value: "4"}, {Name: "value", Value: "ABCDEFGHIJKLMNOP"}}}
		}, "builds from the XML"},
	}
	for name, c := range cases {
		m := openvinotest.Clean()
		c.edit(&m)
		got := parse(t, m)
		if !strings.Contains(strings.Join(got.Unread, "\n"), c.want) {
			t.Errorf("%s: unread %v lacks %q", name, got.Unread, c.want)
		}
	}
	// The repeated <data> is not read: the first one's size stands.
	m := openvinotest.Clean()
	m.Layers[1].Raw = `<data element_type="f32" shape="4" offset="0" size="999"/>`
	if got := parse(t, m); got.Consts[0].Size != 16 {
		t.Errorf("a repeated <data> was read: size %d", got.Consts[0].Size)
	}
}

func TestMalformedLayers(t *testing.T) {
	m := openvinotest.Clean()
	m.Layers[2].Attrs = []openvinotest.Attr{{Name: "id", Value: "2"}, {Name: "name", Value: "add"}, {Name: "type", Value: "Add"}}
	got := parse(t, m)
	if len(got.Malformed) != 1 || !strings.Contains(got.Malformed[0], "no version attribute") {
		t.Errorf("missing version: %v", got.Malformed)
	}
	m = openvinotest.Clean()
	m.Layers[2].Attrs = []openvinotest.Attr{{Name: "id", Value: "+2"}, {Name: "name", Value: "add"}, {Name: "type", Value: "Add"}, {Name: "version", Value: "opset1"}}
	got = parse(t, m)
	if !strings.Contains(strings.Join(got.Malformed, "\n"), `layer id "+2"`) {
		t.Errorf("signed id: %v", got.Malformed)
	}
}

// TestConstData: the shape, offset, and size are read as OpenVINO reads
// them where it reads them alike, and anything else is a Problem, never a
// guess.
func TestConstData(t *testing.T) {
	cases := map[string]struct {
		et, shape, off, size string
		dims                 []int64
		problem              string
	}{
		"serializer spacing": {"f32", "30522, 384", "0", "16", []int64{30522, 384}, ""},
		"trailing comma":     {"f32", "4,", "0", "16", []int64{4}, ""},
		"scalar":             {"f32", "", "0", "4", nil, ""},
		"empty field":        {"f32", "4,,4", "0", "16", nil, "shape"},
		"trailing junk":      {"f32", "4x", "0", "16", nil, "shape"},
		"signed dim":         {"f32", "+4", "0", "16", nil, "shape"},
		"signed offset":      {"f32", "4", "+0", "16", nil, "plain decimal"},
		"hex size":           {"f32", "4", "0", "0x10", nil, "plain decimal"},
		"alias type":         {"FP32", "4", "0", "16", nil, "does not define"},
		"unknown type":       {"f33", "4", "0", "16", nil, "does not define"},
	}
	for name, c := range cases {
		m := openvinotest.Clean()
		m.Layers[1].Data = []openvinotest.Attr{{Name: "element_type", Value: c.et}, {Name: "shape", Value: c.shape}, {Name: "offset", Value: c.off}, {Name: "size", Value: c.size}}
		got := parse(t, m).Consts[0]
		if c.problem == "" {
			if got.Problem != "" || len(got.Shape) != len(c.dims) {
				t.Errorf("%s: %+v", name, got)
			}
			for i := range c.dims {
				if got.Shape[i] != c.dims[i] {
					t.Errorf("%s: shape %v", name, got.Shape)
				}
			}
			continue
		}
		if !strings.Contains(got.Problem, c.problem) {
			t.Errorf("%s: problem %q, want %q", name, got.Problem, c.problem)
		}
	}
	m := openvinotest.Clean()
	m.Layers[1].Data = []openvinotest.Attr{{Name: "element_type", Value: "f32"}, {Name: "offset", Value: "0"}, {Name: "size", Value: "16"}}
	if p := parse(t, m).Consts[0].Problem; !strings.Contains(p, "no shape") {
		t.Errorf("missing shape: %q", p)
	}
	m.Layers[1].Data = nil
	if p := parse(t, m).Consts[0].Problem; !strings.Contains(p, "no <data>") {
		t.Errorf("missing data: %q", p)
	}
}

func TestParseErrors(t *testing.T) {
	deep := strings.Repeat("<rt_info>", MaxDepth) + strings.Repeat("</rt_info>", MaxDepth)
	cases := map[string]string{
		"mismatched tag":  "<net><layers></edges></net>",
		"undefined ent":   `<net name="&e;"/>`,
		"latin1":          `<?xml version="1.0" encoding="ISO-8859-1"?><net/>`,
		"second root":     "<net/><net/>",
		"text after root": "<net/>junk",
		"truncated":       "<net><layers>",
		"not net":         "<graph/>",
		"too deep":        "<net>" + deep + "</net>",
		"no root":         "<!-- nothing -->",
		"doctype entity":  `<!DOCTYPE net [<!ENTITY e "x">]><net name="&e;"/>`,
	}
	for name, x := range cases {
		err := parseErr(t, x)
		var pe *ParseError
		if !errors.As(err, &pe) {
			t.Errorf("%s: err %v, want a ParseError", name, err)
		}
	}
	if _, err := read(strings.NewReader("<net/>"), MaxFileBytes+1); err == nil {
		t.Error("a file past MaxFileBytes was read")
	}
}

func TestTextKeepsEverything(t *testing.T) {
	m := openvinotest.Clean()
	m.Prolog = "<!-- prolog comment -->\n"
	m.Raw = "<meta_data><cli_parameters><x value=\"legacy\"/></cli_parameters></meta_data>"
	m.Layers[2].Raw = `<rt_info><attribute name="fused_names" version="0" value="a,b"/></rt_info>`
	m.RTInfo += "<chat_template value=\"{{ messages }}\"/><!-- inner --><notes>free text</notes>"
	got := parse(t, m)
	text := strings.Join(got.Text, "\n")
	for _, want := range []string{"prolog comment", "legacy", "fused_names", "a,b", "{{ messages }}", "inner", "free text", "chat_template"} {
		if !strings.Contains(text, want) {
			t.Errorf("text lacks %q", want)
		}
	}
	if len(got.Unread) != 0 {
		t.Errorf("rt_info and meta_data are read as text: %v", got.Unread)
	}
}

// TestStandard: OpenVINO's opsets, looked up as its IR reader looks a layer
// up. Falsification: a Unicode case mapping, or no opset redirects, and
// these fail.
func TestStandard(t *testing.T) {
	cases := []struct {
		version, typ, set string
		ok                bool
	}{
		{"opset1", "Add", "opset1", true},
		{"opset1", "add", "opset1", true},
		{"opset1", "Const", "opset1", true},
		{"opset1", "ReLU", "opset1", true},
		{"opset8", "Gather", "opset8", true},
		{"opset13", "ScaledDotProductAttention", "opset13", true},
		{"opset17", "Add", "opset17", false},
		{"opset17", "ErfInv", "opset17", true},
		{"opset1", "MVN", "opset2", true},
		{"experimental", "GRUCell", "opset6", true},
		{"extension", "Proposal", "opset6", true},
		{"extension", "BPETokenizer", "extension", false},
		{"opset99", "Add", "opset99", false},
		{"opset1", "Abſ", "opset1", false}, // ſ upper-cases to S in Unicode, not in C
		{"opset1", "const", "opset1", false},
	}
	for _, c := range cases {
		set, ok := Standard(c.version, c.typ)
		if set != c.set || ok != c.ok {
			t.Errorf("Standard(%q, %q) = %q, %v; want %q, %v", c.version, c.typ, set, ok, c.set, c.ok)
		}
	}
	names := Opsets()
	if len(names) != 17 || names[0] != "opset1" || names[16] != "opset17" {
		t.Errorf("opsets %v", names)
	}
	if n := len(opsets["opset16"]); n != 203 {
		t.Errorf("opset16 holds %d operations, want 203 (OpenVINO 2026.4.1)", n)
	}
}

func TestSizes(t *testing.T) {
	cases := []struct {
		et         string
		n          int64
		mem, least int64
		ok         bool
	}{
		{"f32", 4, 16, 16, true},
		{"f16", 3, 6, 6, true},
		{"boolean", 2, 2, 2, true},
		{"u4", 3, 2, 2, true},
		{"nf4", 4, 2, 2, true},
		{"u1", 9, 2, 2, true},
		{"u2", 5, 2, 2, true},
		{"u3", 1, 3, 1, true},
		{"u3", 9, 6, 4, true},
		{"u6", 5, 6, 4, true},
		{"f32", 0, 0, 0, true},
		{"string", 2, 0, 0, false},
		{"dynamic", 2, 0, 0, false},
		{"i64", 1 << 61, 0, 0, false},
	}
	for _, c := range cases {
		et := ElementTypes[c.et]
		mem, ok1 := MemorySize(et, c.n)
		least, ok2 := MinSize(et, c.n)
		if !c.ok {
			if ok1 {
				t.Errorf("%s x%d: MemorySize %d, want none", c.et, c.n, mem)
			}
			continue
		}
		if !ok1 || !ok2 || mem != c.mem || least != c.least {
			t.Errorf("%s x%d: MemorySize %d %v, MinSize %d %v; want %d, %d", c.et, c.n, mem, ok1, least, ok2, c.mem, c.least)
		}
	}
}
