package openvino

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/defilantech/socair/internal/openvino/openvinotest"
)

// FuzzRead feeds arbitrary bytes to the IR reader and the sniffer. They read
// untrusted artifacts, so neither may panic, a parse must be deterministic,
// and what it reports must hold together: the text it kept adds up to
// TextBytes, it builds no more layers than it read, and every Const it
// reports was built.
func FuzzRead(f *testing.F) {
	f.Add(openvinotest.Clean().XML())
	m := openvinotest.Clean()
	m.Layers = append(m.Layers, openvinotest.Const(1, "dupe", "u4", "3, 1", 4, 2))
	m.Layers[2].Raw = "<body>" + openvinotest.Layers(openvinotest.Clean().Layers, openvinotest.Clean().Edges) + "</body>"
	m.Prolog = "<!-- c -->\n"
	m.Raw = "<zzz a=\"1\" a=\"2\"/><pre-process/>"
	f.Add(m.XML())
	f.Add([]byte(`<net version="10"><layers><layer id="0" name="r" type="Result" version="opset1"/></layers><edges><edge from-layer="1" from-port="0" to-layer="0" to-port="0"/></edges></net>`))
	f.Add([]byte("<NET/>"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = sniff(bytes.NewReader(data))
		a, errA := read(bytes.NewReader(data), int64(len(data)))
		b, errB := read(bytes.NewReader(data), int64(len(data)))
		if (errA == nil) != (errB == nil) {
			t.Fatal("parse is not deterministic")
		}
		if errA != nil {
			return
		}
		if !reflect.DeepEqual(a, b) {
			t.Fatal("two parses of the same bytes differ")
		}
		var total int64
		for _, v := range a.Text {
			total += int64(len(v))
		}
		if total != a.TextBytes {
			t.Fatalf("text holds %d bytes, TextBytes says %d", total, a.TextBytes)
		}
		if a.Built < 0 || a.Built > a.Layers || a.Built+a.UnbuiltCount > a.Layers || len(a.Consts) > a.Built {
			t.Fatalf("layers %d built %d unbuilt %d consts %d", a.Layers, a.Built, a.UnbuiltCount, len(a.Consts))
		}
		if a.MaxNesting > MaxDepth || a.Graphs < 1 {
			t.Fatalf("graphs %d nesting %d", a.Graphs, a.MaxNesting)
		}
		for _, c := range a.Consts {
			if c.Problem == "" && (!c.HasRange || c.Offset < 0 || c.Size < 0) {
				t.Fatalf("const %+v", c)
			}
		}
	})
}
