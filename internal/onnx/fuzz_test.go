package onnx

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/defilantech/socair/internal/onnx/onnxtest"
)

// FuzzRead feeds arbitrary bytes to the model reader and the sniffer. They
// read untrusted artifacts, so neither may panic, a parse must be
// deterministic, and what it reports must hold together: the text it kept
// adds up to TextBytes, and no element count is negative.
func FuzzRead(f *testing.F) {
	f.Add(onnxtest.Clean().Bytes())
	ext := onnxtest.Clean()
	ext.Graph.Initializers = append(ext.Graph.Initializers, onnxtest.ExternalWeight("e", "../../etc/hosts", 4096, 4))
	f.Add(ext.Bytes())
	f.Add(nested(5).Bytes())
	withText := onnxtest.Clean()
	withText.Doc = "doc"
	withText.Metadata = []onnxtest.KV{{Key: "k", Value: "v"}}
	embed := int64(0)
	withText.Graph.Nodes = append(withText.Graph.Nodes, onnxtest.Node{OpType: "EPContext", Domain: "com.microsoft",
		Attrs: []onnxtest.Attr{{Name: "embed_mode", I: &embed}, {Name: "ep_cache_context", S: []byte("ctx.bin")}}})
	withText.Functions = []onnxtest.Function{{Name: "F", Domain: "d", Nodes: []onnxtest.Node{{OpType: "Relu"}}}}
	f.Add(withText.Bytes())
	f.Add([]byte{0x08, 0x08, 0x3a, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = sniff(bytes.NewReader(data), int64(len(data)))
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
		for _, tt := range a.Tensors {
			if tt.RawBytes < 0 || tt.Floats < 0 || tt.Int32s < 0 || tt.Strings < 0 || tt.Int64s < 0 || tt.Doubles < 0 || tt.Uint64s < 0 {
				t.Fatalf("negative count in %+v", tt)
			}
		}
		if a.Nodes < 0 || a.Graphs < 0 || a.MaxNesting > MaxDepth {
			t.Fatalf("nodes %d graphs %d nesting %d", a.Nodes, a.Graphs, a.MaxNesting)
		}
	})
}
