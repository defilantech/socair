// Package openvinotest builds OpenVINO IR models, an .xml and its .bin, for
// tests.
//
// Fixtures are generated, not committed, so they cannot rot silently. The
// XML is laid out as OpenVINO's serializer writes it (xml_serialize_util.cpp):
// layers, then edges, then rt_info, with a Const's shape written "a, b".
// Raw fields let a test write what the serializer never would.
package openvinotest

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
)

// Attr is one attribute, written in order and escaped.
type Attr struct{ Name, Value string }

// Layer is one <layer>.
type Layer struct {
	ID      int
	Name    string
	Type    string
	Version string
	// Data are the <data> attributes; nil writes no <data>.
	Data []Attr
	// In and Out are the port counts, each a one-dim port of 4.
	In, Out int
	// Raw is written inside the layer after its ports: rt_info, a body.
	Raw string
	// Attrs replace the layer's attributes when set, for a test that needs
	// a missing or repeated one.
	Attrs []Attr
}

// Edge is one <edge>.
type Edge struct{ From, FromPort, To, ToPort int }

// Model is an IR.
type Model struct {
	Version string // the net's version; "" leaves it out
	Name    string
	Layers  []Layer
	Edges   []Edge
	// RTInfo is written inside <rt_info>; "" writes none.
	RTInfo string
	// Prolog is written before the root, after the XML declaration; Raw
	// inside <net> after <rt_info>.
	Prolog, Raw string
	// Root replaces the root element's name when set.
	Root string
	// Bin is the .bin: the Consts' data.
	Bin []byte
}

// Floats is n little-endian float32 values 1, 2, 3, ...
func Floats(n int) []byte {
	b := make([]byte, 4*n)
	for i := 0; i < n; i++ {
		binary.LittleEndian.PutUint32(b[4*i:], math.Float32bits(float32(i+1)))
	}
	return b
}

// Const is a Const layer of element type et and shape at [offset, offset+size).
func Const(id int, name, et, shape string, offset, size int64) Layer {
	return Layer{ID: id, Name: name, Type: "Const", Version: "opset1", Out: 1,
		Data: []Attr{{"element_type", et}, {"shape", shape}, {"offset", fmt.Sprint(offset)}, {"size", fmt.Sprint(size)}}}
}

// Clean is x + w -> out: a Parameter, a Const of four f32 (16 bytes, the
// whole .bin), an Add, and a Result, with rt_info as optimum-intel writes
// it.
func Clean() Model {
	return Model{
		Version: "11",
		Name:    "Model0",
		Layers: []Layer{
			{ID: 0, Name: "x", Type: "Parameter", Version: "opset1", Out: 1, Data: []Attr{{"shape", "4"}, {"element_type", "f32"}}},
			Const(1, "w", "f32", "4", 0, 16),
			{ID: 2, Name: "add", Type: "Add", Version: "opset1", In: 2, Out: 1, Data: []Attr{{"auto_broadcast", "numpy"}}},
			{ID: 3, Name: "out", Type: "Result", Version: "opset1", In: 1},
		},
		Edges:  []Edge{{0, 0, 2, 0}, {1, 0, 2, 1}, {2, 2, 3, 0}},
		RTInfo: `<Runtime_version value="2026.4.1-22982-e213a147257-releases/2026/4" /><conversion_parameters><framework value="pytorch" /><is_python_object value="True" /></conversion_parameters>`,
		Bin:    Floats(4),
	}
}

func esc(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}

func attrs(as []Attr) string {
	var b strings.Builder
	for _, a := range as {
		fmt.Fprintf(&b, ` %s="%s"`, a.Name, esc(a.Value))
	}
	return b.String()
}

// Layers writes layers and edges as a <layers> and an <edges> element, for
// a body.
func Layers(ls []Layer, es []Edge) string {
	var b strings.Builder
	b.WriteString("<layers>\n")
	for _, l := range ls {
		as := l.Attrs
		if as == nil {
			as = []Attr{{"id", fmt.Sprint(l.ID)}, {"name", l.Name}, {"type", l.Type}, {"version", l.Version}}
		}
		fmt.Fprintf(&b, "<layer%s>\n", attrs(as))
		if l.Data != nil {
			fmt.Fprintf(&b, "<data%s />\n", attrs(l.Data))
		}
		port := 0
		if l.In > 0 {
			b.WriteString("<input>\n")
			for i := 0; i < l.In; i++ {
				fmt.Fprintf(&b, "<port id=\"%d\" precision=\"FP32\"><dim>4</dim></port>\n", port)
				port++
			}
			b.WriteString("</input>\n")
		}
		if l.Out > 0 {
			b.WriteString("<output>\n")
			for i := 0; i < l.Out; i++ {
				fmt.Fprintf(&b, "<port id=\"%d\" precision=\"FP32\"><dim>4</dim></port>\n", port)
				port++
			}
			b.WriteString("</output>\n")
		}
		b.WriteString(l.Raw)
		b.WriteString("</layer>\n")
	}
	b.WriteString("</layers>\n<edges>\n")
	for _, e := range es {
		fmt.Fprintf(&b, "<edge from-layer=\"%d\" from-port=\"%d\" to-layer=\"%d\" to-port=\"%d\" />\n", e.From, e.FromPort, e.To, e.ToPort)
	}
	b.WriteString("</edges>\n")
	return b.String()
}

// XML is the model's .xml.
func (m Model) XML() []byte {
	var b strings.Builder
	b.WriteString("<?xml version=\"1.0\"?>\n")
	b.WriteString(m.Prolog)
	root := m.Root
	if root == "" {
		root = "net"
	}
	var as []Attr
	if m.Name != "" {
		as = append(as, Attr{"name", m.Name})
	}
	if m.Version != "" {
		as = append(as, Attr{"version", m.Version})
	}
	fmt.Fprintf(&b, "<%s%s>\n", root, attrs(as))
	b.WriteString(Layers(m.Layers, m.Edges))
	if m.RTInfo != "" {
		b.WriteString("<rt_info>" + m.RTInfo + "</rt_info>\n")
	}
	b.WriteString(m.Raw)
	fmt.Fprintf(&b, "</%s>\n", root)
	return []byte(b.String())
}

// Write writes the model as dir/<stem>.xml and dir/<stem>.bin, creating
// dir, and returns the .xml's path. A nil Bin writes no .bin.
func (m Model) Write(dir, stem string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	x := filepath.Join(dir, stem+".xml")
	if err := os.WriteFile(x, m.XML(), 0o644); err != nil {
		return "", err
	}
	if m.Bin != nil {
		if err := os.WriteFile(filepath.Join(dir, stem+".bin"), m.Bin, 0o644); err != nil {
			return "", err
		}
	}
	return x, nil
}
