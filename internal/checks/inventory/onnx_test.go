package inventory

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/onnx/onnxtest"
)

var elf = append([]byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0}, make([]byte, 56)...)

func cleanMirror(t *testing.T) string {
	t.Helper()
	mirror := t.TempDir()
	if err := os.WriteFile(filepath.Join(mirror, "config.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	return mirror
}

// TestONNXText: an ONNX model's metadata_props, doc strings, producer, and
// string attributes and tensors go through the same payload patterns as
// GGUF and safetensors metadata. Falsification: drop the ONNX case from
// Inspect, or stop the reader keeping a kind of text, and the FAILs go.
func TestONNXText(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("echo socair; ", 60)))
	cases := map[string]struct {
		edit    func(*onnxtest.Model)
		pattern string
	}{
		"metadata_props script": {func(m *onnxtest.Model) { m.Metadata = []onnxtest.KV{{Key: "note", Value: "#!/bin/sh\necho socair"}} }, "embedded-script"},
		"metadata_props key":    {func(m *onnxtest.Model) { m.Metadata = []onnxtest.KV{{Key: "<script>x</script>", Value: "v"}} }, "embedded-script"},
		"model doc_string":      {func(m *onnxtest.Model) { m.Doc = b64 }, "embedded-base64-blob"},
		"producer_name":         {func(m *onnxtest.Model) { m.Producer = string(elf) }, "embedded-binary"},
		"graph doc_string":      {func(m *onnxtest.Model) { m.Graph.Doc = "powershell -enc AAAA" }, "embedded-script"},
		"node doc_string":       {func(m *onnxtest.Model) { m.Graph.Nodes[0].Doc = b64 }, "embedded-base64-blob"},
		"graph metadata_props":  {func(m *onnxtest.Model) { m.Graph.Metadata = []onnxtest.KV{{Key: "k", Value: b64}} }, "embedded-base64-blob"},
		"string attribute": {func(m *onnxtest.Model) {
			m.Graph.Nodes[0].Attrs = []onnxtest.Attr{{Name: "mode", Type: 3, S: elf}}
		}, "embedded-binary"},
		"strings attribute element": {func(m *onnxtest.Model) {
			m.Graph.Nodes[0].Attrs = []onnxtest.Attr{{Name: "labels", Type: 8, Strings: [][]byte{[]byte("a"), []byte(b64)}}}
		}, "embedded-base64-blob"},
		"STRING tensor element": {func(m *onnxtest.Model) {
			m.Graph.Initializers = append(m.Graph.Initializers, onnxtest.Tensor{Name: "s", DataType: onnxtest.String, Dims: []int64{1}, Strings: [][]byte{elf}})
		}, "embedded-binary"},
		"tensor doc_string": {func(m *onnxtest.Model) { m.Graph.Initializers[0].Doc = "#!/bin/bash\nid" }, "embedded-script"},
		"subgraph node doc_string": {func(m *onnxtest.Model) {
			inner := onnxtest.Graph{Nodes: []onnxtest.Node{{OpType: "Relu", Doc: "#!/bin/sh\nid"}}}
			m.Graph.Nodes = append(m.Graph.Nodes, onnxtest.Node{OpType: "If", Attrs: []onnxtest.Attr{{Name: "then_branch", Type: 5, G: &inner}}})
		}, "embedded-script"},
	}
	for name, c := range cases {
		m := onnxtest.Clean()
		c.edit(&m)
		r := Inspect(writeFixture(t, "model.onnx", m.Bytes()), Options{})
		if r.Status != checks.Fail {
			t.Errorf("%s: status %s, want FAIL: %s", name, r.Status, r.Notes)
			continue
		}
		found := false
		for _, f := range r.Findings {
			found = found || f.Pattern == c.pattern
		}
		if !found {
			t.Errorf("%s: no %s finding: %v", name, c.pattern, r.Findings)
		}
	}
}

func TestONNXCleanText(t *testing.T) {
	m := onnxtest.Clean()
	m.Metadata = []onnxtest.KV{{Key: "onnx.infer", Value: "onnxruntime.quant"}}
	m.Doc = "A sentence embedding model."
	p := writeFixture(t, "model.onnx", m.Bytes())
	r := Inspect(p, Options{})
	if r.Status != checks.NotTested || !strings.Contains(r.Notes, "artifact: ONNX model, 5 text values") || !strings.Contains(r.Notes, "no payload indicator") {
		t.Fatalf("clean without a mirror: %s: %s", r.Status, r.Notes)
	}
	if r := Inspect(p, Options{RepoMirror: cleanMirror(t)}); r.Status != checks.Pass {
		t.Errorf("clean with a mirror: %s: %s", r.Status, r.Notes)
	}
	// A short string element cannot carry a payload and is counted, not kept.
	m = onnxtest.Clean()
	m.Graph.Nodes[0].Attrs = []onnxtest.Attr{{Name: "labels", Type: 8, Strings: [][]byte{[]byte("#!/bin/sh")}}}
	r = Inspect(writeFixture(t, "model.onnx", m.Bytes()), Options{RepoMirror: cleanMirror(t)})
	if r.Status != checks.Pass || !strings.Contains(r.Notes, "1 shorter string elements counted") {
		t.Errorf("short element: %s: %s", r.Status, r.Notes)
	}
}

// TestONNXEmbeddedContextNotScanned: an EPContext's embedded context is
// compiled code. It is not scanned as text (any executable bytes in it
// would be a false FAIL), and it is named, so the row cannot pass.
func TestONNXEmbeddedContextNotScanned(t *testing.T) {
	m := onnxtest.Clean()
	one := int64(1)
	m.Graph.Nodes = append(m.Graph.Nodes, onnxtest.Node{Name: "ctx", OpType: "EPContext", Domain: "com.microsoft",
		Attrs: []onnxtest.Attr{{Name: "embed_mode", Type: 2, I: &one}, {Name: "ep_cache_context", Type: 3, S: elf}}})
	r := Inspect(writeFixture(t, "model.onnx", m.Bytes()), Options{RepoMirror: cleanMirror(t)})
	if r.Status != checks.NotTested || !strings.Contains(r.Notes, "embeds an execution-provider context of 64 bytes") {
		t.Errorf("embedded context: %s: %v %s", r.Status, r.Findings, r.Notes)
	}
}

// TestONNXTextPastTheCapIsNotScanned: a text value the reader does not keep
// leaves the row NOT_TESTED, never PASS. Falsification: ignore TextTruncated
// and this PASSes.
func TestONNXTextPastTheCapIsNotScanned(t *testing.T) {
	m := onnxtest.Clean()
	m.Doc = strings.Repeat("a", 16<<20+1)
	r := Inspect(writeFixture(t, "model.onnx", m.Bytes()), Options{RepoMirror: cleanMirror(t)})
	if r.Status != checks.NotTested || !strings.Contains(r.Notes, "past the reader's caps") {
		t.Errorf("a doc string past the cap: %s: %s", r.Status, r.Notes)
	}
}

func TestONNXUnreadable(t *testing.T) {
	m := onnxtest.Clean()
	b := m.Bytes()
	// A model that sniffs (its top level walks) but whose graph is malformed.
	bad := onnxtest.Model{IRVersion: 8, Graph: &onnxtest.Graph{Extra: onnxtest.AppendBytes(nil, 1, []byte{0x08})}, Opsets: m.Opsets}.Bytes()
	r := Inspect(writeFixture(t, "model.onnx", bad), Options{})
	if r.Status != checks.NotTested || !strings.Contains(r.Notes, "could not read the ONNX model's text") {
		t.Errorf("malformed: %s: %s", r.Status, r.Notes)
	}
	r = Inspect(writeFixture(t, "model.onnx", b[:len(b)/2]), Options{})
	if r.Status != checks.NotTested || !strings.Contains(r.Notes, "not a GGUF, safetensors, or ONNX artifact") {
		t.Errorf("truncated: %s: %s", r.Status, r.Notes)
	}
}
