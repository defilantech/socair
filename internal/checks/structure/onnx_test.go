package structure

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/onnx/onnxtest"
)

// onnxDirModel writes m as onnx/model.onnx inside a new directory, with any
// extra files, and checks it as a directory scan does.
func onnxDirModel(t *testing.T, m onnxtest.Model, files map[string][]byte) checks.Result {
	t.Helper()
	root := t.TempDir()
	files = mergeFiles(files, map[string][]byte{"onnx/model.onnx": m.Bytes()})
	for rel, b := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return ValidateONNX(root, "onnx/model.onnx")
}

func mergeFiles(a, b map[string][]byte) map[string][]byte {
	out := map[string][]byte{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

func single(t *testing.T, m onnxtest.Model) checks.Result {
	t.Helper()
	return Validate(writeFixture(t, "model.onnx", m.Bytes()))
}

func withInit(ts ...onnxtest.Tensor) onnxtest.Model {
	m := onnxtest.Clean()
	m.Graph.Initializers = append(m.Graph.Initializers, ts...)
	return m
}

func hasPattern(r checks.Result, pattern string) bool {
	for _, f := range r.Findings {
		if f.Pattern == pattern {
			return true
		}
	}
	return false
}

func wantStatus(t *testing.T, name string, r checks.Result, status checks.Status, pattern string) {
	t.Helper()
	if r.Status != status {
		t.Errorf("%s: status %s, want %s: %v %s", name, r.Status, status, r.Findings, r.Notes)
		return
	}
	if pattern != "" && !hasPattern(r, pattern) {
		t.Errorf("%s: no %s finding: %v", name, pattern, r.Findings)
	}
	if status != checks.Pass && r.Notes == "" {
		t.Errorf("%s: a non-PASS result needs a reason", name)
	}
}

func TestONNXCleanPasses(t *testing.T) {
	r := single(t, onnxtest.Clean())
	wantStatus(t, "clean", r, checks.Pass, "")
	for _, s := range []string{"ONNX IR v8", `from "pytorch 2.5.0"`, "ai.onnx v17", "2 node(s)", "2 tensor(s) (2 inline)",
		"Every tensor's data matches its dims and type", "runs no Python", "native library"} {
		if !strings.Contains(r.Notes, s) {
			t.Errorf("PASS notes lack %q: %s", s, r.Notes)
		}
	}
	if strings.Contains(r.Notes, "external data is inside") {
		t.Errorf("a model with no external data claims it was checked: %s", r.Notes)
	}
	r = onnxDirModel(t, onnxtest.Clean(), nil)
	wantStatus(t, "clean in a directory", r, checks.Pass, "")
}

// TestONNXInlineSizes: a tensor's inline data must be exactly what its type
// and dims need, in the one field its type uses.
func TestONNXInlineSizes(t *testing.T) {
	big := onnxtest.FloatWeight("big", 4)
	big.Raw = make([]byte, 4096)
	short := onnxtest.FloatWeight("short", 4)
	short.Raw = short.Raw[:8]
	cases := map[string]struct {
		t       onnxtest.Tensor
		status  checks.Status
		pattern string
	}{
		"raw with extra bytes":   {big, checks.Fail, "tensor-size"},
		"raw too short":          {short, checks.Fail, "tensor-size"},
		"typed count mismatch":   {onnxtest.Tensor{Name: "f", DataType: onnxtest.Float, Dims: []int64{4}, Floats: []float32{1, 2, 3}}, checks.Fail, "tensor-size"},
		"typed count matches":    {onnxtest.Tensor{Name: "f", DataType: onnxtest.Float, Dims: []int64{3}, Floats: []float32{1, 2, 3}}, checks.Pass, ""},
		"int8 in int32_data":     {onnxtest.Tensor{Name: "q", DataType: onnxtest.Int8, Dims: []int64{2}, Int32s: []int32{-1, 1}}, checks.Pass, ""},
		"two data fields":        {onnxtest.Tensor{Name: "f", DataType: onnxtest.Float, Dims: []int64{1}, Floats: []float32{1}, Raw: make([]byte, 4)}, checks.Fail, "tensor-data"},
		"field its type omits":   {onnxtest.Tensor{Name: "f", DataType: onnxtest.Float, Dims: []int64{2}, Int64s: []int64{1, 2}}, checks.Fail, "tensor-data"},
		"no data":                {onnxtest.Tensor{Name: "f", DataType: onnxtest.Float, Dims: []int64{2}}, checks.Fail, "tensor-size"},
		"empty tensor with data": {onnxtest.Tensor{Name: "f", DataType: onnxtest.Float, Dims: []int64{0}, Floats: []float32{1}}, checks.Fail, "tensor-size"},
		"empty tensor":           {onnxtest.Tensor{Name: "f", DataType: onnxtest.Float, Dims: []int64{0, 3}, RawSet: true}, checks.Pass, ""},
		"string in raw_data":     {onnxtest.Tensor{Name: "s", DataType: onnxtest.String, Dims: []int64{1}, Raw: []byte("abc")}, checks.Fail, "tensor-data"},
		"strings counted":        {onnxtest.Tensor{Name: "s", DataType: onnxtest.String, Dims: []int64{2}, Strings: [][]byte{[]byte("a"), []byte("b")}}, checks.Pass, ""},
		"4-bit packed raw":       {onnxtest.Tensor{Name: "u4", DataType: onnxtest.Uint4, Dims: []int64{3}, Raw: []byte{0, 0}}, checks.Pass, ""},
		"4-bit in int32_data":    {onnxtest.Tensor{Name: "u4", DataType: onnxtest.Uint4, Dims: []int64{4}, Int32s: []int32{0, 0}}, checks.NotTested, ""},
		"unknown data type":      {onnxtest.Tensor{Name: "x", DataType: 99, Dims: []int64{1}, Raw: []byte{0}}, checks.NotTested, ""},
		"no data type":           {onnxtest.Tensor{Name: "x", Dims: []int64{1}, Raw: []byte{0}}, checks.NotTested, ""},
		"negative dim":           {onnxtest.Tensor{Name: "x", DataType: onnxtest.Float, Dims: []int64{-1}, Raw: []byte{0, 0, 0, 0}}, checks.NotTested, ""},
		"segment": {onnxtest.Tensor{Name: "x", DataType: onnxtest.Float, Dims: []int64{1}, Raw: make([]byte, 4),
			Extra: onnxtest.AppendBytes(nil, 3, onnxtest.AppendInt(nil, 1, 0))}, checks.NotTested, ""},
	}
	for name, c := range cases {
		r := single(t, withInit(c.t))
		wantStatus(t, name, r, c.status, c.pattern)
	}
	for name, c := range map[string]struct {
		t    onnxtest.Tensor
		want string
	}{
		"unknown data type": {cases["unknown data type"].t, "data type 99, which onnx.proto v1.23.2 does not define"},
		"negative dim":      {cases["negative dim"].t, "with a negative or overflowing size"},
		"no data type":      {cases["no data type"].t, "a tensor with no data type"},
	} {
		if r := single(t, withInit(c.t)); !strings.Contains(r.Notes, c.want) {
			t.Errorf("%s: notes lack %q: %s", name, c.want, r.Notes)
		}
	}
}

// TestONNXTensorsEverywhere: tensors in subgraphs, in Constant attributes,
// in sparse initializers, and in function bodies are held to the same rule.
func TestONNXTensorsEverywhere(t *testing.T) {
	bad := onnxtest.FloatWeight("bad", 4)
	bad.Raw = make([]byte, 20)

	sub := onnxtest.Clean()
	inner := onnxtest.Graph{Initializers: []onnxtest.Tensor{bad}}
	sub.Graph.Nodes = append(sub.Graph.Nodes, onnxtest.Node{Name: "if", OpType: "If", Attrs: []onnxtest.Attr{{Name: "then_branch", Type: 5, G: &inner}}})

	constant := onnxtest.Clean()
	constant.Graph.Nodes = append(constant.Graph.Nodes, onnxtest.Node{Name: "c", OpType: "Constant", Attrs: []onnxtest.Attr{{Name: "value", Type: 4, T: &bad}}})

	sparse := onnxtest.Clean()
	sparse.Graph.Sparse = []onnxtest.Sparse{{Values: bad, Indices: onnxtest.Tensor{DataType: onnxtest.Int64, Dims: []int64{4}, Int64s: []int64{0, 1, 2, 3}}, Dims: []int64{8}}}

	fn := onnxtest.Clean()
	fn.Functions = []onnxtest.Function{{Name: "F", Domain: "local", Nodes: []onnxtest.Node{{OpType: "Constant", Attrs: []onnxtest.Attr{{Name: "value", Type: 4, T: &bad}}}}}}

	for name, m := range map[string]onnxtest.Model{"subgraph": sub, "Constant attribute": constant, "sparse initializer": sparse, "function body": fn} {
		r := single(t, m)
		wantStatus(t, name, r, checks.Fail, "tensor-size")
	}
	r := single(t, sub)
	if !strings.Contains(r.Findings[0].Span, `node "if" (If) attribute "then_branch": initializer "bad"`) {
		t.Errorf("a subgraph finding does not say where: %q", r.Findings[0].Span)
	}
}

func TestONNXDuplicateInitializers(t *testing.T) {
	r := single(t, withInit(onnxtest.FloatWeight("w", 4, 4)))
	wantStatus(t, "repeated name", r, checks.Fail, "duplicate-key")
	// The same name in a subgraph is another scope, not a repeat.
	m := onnxtest.Clean()
	inner := onnxtest.Graph{Initializers: []onnxtest.Tensor{onnxtest.FloatWeight("w", 4, 4)}}
	m.Graph.Nodes = append(m.Graph.Nodes, onnxtest.Node{OpType: "If", Attrs: []onnxtest.Attr{{Name: "then_branch", Type: 5, G: &inner}}})
	wantStatus(t, "name in a subgraph", single(t, m), checks.Pass, "")
}

// TestONNXExternalLocations: a location that leaves the model's directory is
// a FAIL in any scan; one systems read differently is a LEAD.
func TestONNXExternalLocations(t *testing.T) {
	cases := map[string]struct {
		loc     string
		status  checks.Status
		pattern string
	}{
		"climbs out":          {"../../etc/hosts", checks.Fail, "external-data-escape"},
		"climbs out late":     {"a/../../hosts", checks.Fail, "external-data-escape"},
		"absolute":            {"/etc/hosts", checks.Fail, "external-data-escape"},
		"windows rooted":      {`\Windows\win.ini`, checks.Fail, "external-data-escape"},
		"windows drive":       {`C:\Windows\win.ini`, checks.Fail, "external-data-escape"},
		"windows dotdot":      {`..\..\etc\hosts`, checks.Fail, "external-data-escape"},
		"memory marker":       {"*/_ORT_MEM_ADDR_/*", checks.Fail, "external-data-memory"},
		"native memory":       {"*/_ORT_NATIVE_ENDIAN_MEM_ADDR_/*", checks.Fail, "external-data-memory"},
		"backslash":           {`sub\w.bin`, checks.Lead, "external-data-path"},
		"colon":               {"w.bin:stream", checks.Lead, "external-data-path"},
		"dotdot inside":       {"sub/../w.bin", checks.Lead, "external-data-path"},
		"control character":   {"w.bin\x00.txt", checks.Lead, "external-data-path"},
		"the directory":       {".", checks.Lead, "external-data-path"},
		"inside, single file": {"w.bin", checks.NotTested, ""},
		"empty":               {"", checks.NotTested, ""},
	}
	for name, c := range cases {
		r := single(t, withInit(onnxtest.ExternalWeight("e", c.loc, 0, 4)))
		wantStatus(t, name, r, c.status, c.pattern)
	}
	r := single(t, withInit(onnxtest.ExternalWeight("e", "w.bin", 0, 4)))
	if !strings.Contains(r.Notes, "1 tensor(s) keep their data in w.bin, outside a single-file scan") {
		t.Errorf("a single-file scan does not say external data was out of scope: %s", r.Notes)
	}
	// The boundary is the model's own directory: onnx/model.onnx may not
	// read the repository root, though the scan holds it.
	r = onnxDirModel(t, withInit(onnxtest.ExternalWeight("e", "../model.safetensors", 0, 4)), map[string][]byte{"model.safetensors": make([]byte, 16)})
	wantStatus(t, "out of the model's directory, inside the scan", r, checks.Fail, "external-data-escape")
	// A location is checked even on a tensor not marked EXTERNAL.
	inert := onnxtest.FloatWeight("i", 4)
	inert.External = []onnxtest.KV{{Key: "location", Value: "../../etc/hosts"}}
	wantStatus(t, "inert location", single(t, withInit(inert)), checks.Fail, "external-data-escape")
}

// TestONNXExternalInDirectory: with the directory in the scan, the file must
// be there and hold every tensor's bytes.
func TestONNXExternalInDirectory(t *testing.T) {
	two := withInit(onnxtest.ExternalWeight("e1", "model.onnx_data", 0, 4), onnxtest.ExternalWeight("e2", "model.onnx_data", 16, 4))
	r := onnxDirModel(t, two, map[string][]byte{"onnx/model.onnx_data": make([]byte, 32)})
	wantStatus(t, "present and fits", r, checks.Pass, "")
	if !strings.Contains(r.Notes, "2 of them found within onnx/model.onnx_data") || !strings.Contains(r.Notes, "external data is inside") {
		t.Errorf("notes do not say the external data was checked: %s", r.Notes)
	}
	r = onnxDirModel(t, two, nil)
	wantStatus(t, "missing", r, checks.NotTested, "")
	if !strings.Contains(r.Notes, "external data file onnx/model.onnx_data is not in the directory") {
		t.Errorf("a missing data file is not named: %s", r.Notes)
	}
	r = onnxDirModel(t, two, map[string][]byte{"onnx/model.onnx_data": make([]byte, 31)})
	wantStatus(t, "past the end", r, checks.NotTested, "")
	if !strings.Contains(r.Notes, "runs past the end of onnx/model.onnx_data (31 bytes)") {
		t.Errorf("past-the-end notes: %s", r.Notes)
	}
	sub := withInit(onnxtest.ExternalWeight("e", "data/w.bin", 0, 4))
	wantStatus(t, "in a subdirectory", onnxDirModel(t, sub, map[string][]byte{"onnx/data/w.bin": make([]byte, 16)}), checks.Pass, "")
	// The data is resolved beside the model, not at the scan's root.
	wantStatus(t, "beside the root, not the model", onnxDirModel(t, sub, map[string][]byte{"data/w.bin": make([]byte, 16)}), checks.NotTested, "")

	wrongLen := onnxtest.ExternalWeight("e", "w.bin", 0, 4)
	wrongLen.External[1].Value = "12"
	wantStatus(t, "length mismatch", onnxDirModel(t, withInit(wrongLen), map[string][]byte{"onnx/w.bin": make([]byte, 16)}), checks.Fail, "tensor-size")

	dup := onnxtest.ExternalWeight("e", "w.bin", 0, 4)
	dup.External = append(dup.External, onnxtest.KV{Key: "location", Value: "w2.bin"})
	wantStatus(t, "repeated location", onnxDirModel(t, withInit(dup), map[string][]byte{"onnx/w.bin": make([]byte, 16), "onnx/w2.bin": make([]byte, 16)}), checks.Fail, "duplicate-key")

	extra := onnxtest.ExternalWeight("e", "w.bin", 0, 4)
	extra.Raw = make([]byte, 16)
	wantStatus(t, "external and inline", onnxDirModel(t, withInit(extra), map[string][]byte{"onnx/w.bin": make([]byte, 16)}), checks.Fail, "tensor-data")

	for name, kv := range map[string]onnxtest.KV{
		"unknown key":      {Key: "basepath", Value: "/tmp"},
		"signed offset":    {Key: "offset", Value: "+16"},
		"offset with a _":  {Key: "offset", Value: "1_6"},
		"zero length":      {Key: "length", Value: "0"},
		"length not a num": {Key: "length", Value: "sixteen"},
		"hex length":       {Key: "length", Value: "0x10"},
	} {
		tt := onnxtest.ExternalWeight("e", "w.bin", 0, 4)
		if kv.Key == "length" {
			tt.External = tt.External[:1]
		}
		tt.External = append(tt.External, kv)
		wantStatus(t, name, onnxDirModel(t, withInit(tt), map[string][]byte{"onnx/w.bin": make([]byte, 64)}), checks.NotTested, "")
	}
	checksum := onnxtest.ExternalWeight("e", "w.bin", 0, 4)
	checksum.External = append(checksum.External, onnxtest.KV{Key: "checksum", Value: "0000"})
	r = onnxDirModel(t, withInit(checksum), map[string][]byte{"onnx/w.bin": make([]byte, 16)})
	wantStatus(t, "checksum", r, checks.Pass, "")
	if !strings.Contains(r.Notes, "checksum(s) not verified") {
		t.Errorf("an unverified checksum is not named: %s", r.Notes)
	}
}

// TestONNXDomains: ONNX's own domains pass; onnxruntime's contrib domain is
// named and passes; any other domain needs native code outside the model.
func TestONNXDomains(t *testing.T) {
	op := func(domain, typ string) onnxtest.Model {
		m := onnxtest.Clean()
		m.Graph.Nodes = append(m.Graph.Nodes, onnxtest.Node{OpType: typ, Domain: domain})
		return m
	}
	wantStatus(t, "ai.onnx", single(t, op("ai.onnx", "Relu")), checks.Pass, "")
	wantStatus(t, "ai.onnx.ml", single(t, op("ai.onnx.ml", "LabelEncoder")), checks.Pass, "")
	r := single(t, op("com.microsoft", "MatMulNBits"))
	wantStatus(t, "com.microsoft", r, checks.Pass, "")
	if !strings.Contains(r.Notes, "com.microsoft (onnxruntime's contrib operators") || !strings.Contains(r.Notes, "MatMulNBits x1") {
		t.Errorf("onnxruntime's operators are not named: %s", r.Notes)
	}
	r = single(t, op("com.example.custom", "Payload"))
	wantStatus(t, "custom domain", r, checks.NotTested, "")
	if !strings.Contains(r.Notes, `domain "com.example.custom"`) || !strings.Contains(r.Notes, "Payload") {
		t.Errorf("a custom domain is not named: %s", r.Notes)
	}
	// A custom domain used only inside a function body is found too.
	fn := onnxtest.Clean()
	fn.Functions = []onnxtest.Function{{Name: "F", Domain: "local", Nodes: []onnxtest.Node{{OpType: "Payload", Domain: "com.example.custom"}}}}
	wantStatus(t, "custom domain in a function", single(t, fn), checks.NotTested, "")
	// A call to a model-local function is defined in the model.
	call := op("local", "F")
	call.Functions = []onnxtest.Function{{Name: "F", Domain: "local", Nodes: []onnxtest.Node{{OpType: "Relu"}}}}
	r = single(t, call)
	wantStatus(t, "local function", r, checks.Pass, "")
	if !strings.Contains(r.Notes, "1 call(s) to the model's 1 local function(s)") {
		t.Errorf("a local function call is not named: %s", r.Notes)
	}
}

func TestONNXEPContext(t *testing.T) {
	ep := func(embed int64, ctx string) onnxtest.Model {
		m := onnxtest.Clean()
		m.Graph.Nodes = append(m.Graph.Nodes, onnxtest.Node{Name: "ctx", OpType: "EPContext", Domain: "com.microsoft",
			Attrs: []onnxtest.Attr{{Name: "embed_mode", Type: 2, I: &embed}, {Name: "ep_cache_context", Type: 3, S: []byte(ctx)}}})
		return m
	}
	wantStatus(t, "embedded", single(t, ep(1, "\x00compiled")), checks.NotTested, "")
	wantStatus(t, "in a file", single(t, ep(0, "model_ctx.bin")), checks.NotTested, "")
	wantStatus(t, "path out", single(t, ep(0, "../../etc/hosts")), checks.Fail, "external-data-escape")
	// An embedded context is compiled bytes, not a path, whatever it holds.
	wantStatus(t, "embedded bytes that look like a path", single(t, ep(1, "../../etc/hosts")), checks.NotTested, "")
}

func TestONNXUnparsedAndIncomplete(t *testing.T) {
	clean := onnxtest.Clean().Bytes()
	r := Validate(writeFixture(t, "truncated.onnx", clean[:len(clean)-5]))
	// Truncated bytes are not recognised as ONNX at all by a single-file scan.
	if r.Status != checks.NotTested {
		t.Errorf("truncated: %s", r.Status)
	}
	r = onnxDirModel(t, onnxtest.Model{IRVersion: 8, Graph: &onnxtest.Graph{Extra: onnxtest.AppendBytes(nil, 1, []byte{0x08})}}, nil)
	wantStatus(t, "malformed node", r, checks.NotTested, "")
	if !strings.Contains(r.Notes, "could not parse the ONNX model") {
		t.Errorf("malformed notes: %s", r.Notes)
	}
	unknown := onnxtest.Clean()
	unknown.Extra = onnxtest.AppendBytes(nil, 99, []byte("payload"))
	r = single(t, unknown)
	wantStatus(t, "unknown field", r, checks.NotTested, "")
	if !strings.Contains(r.Notes, "ModelProto field 99") {
		t.Errorf("unknown field not named: %s", r.Notes)
	}
	noOpset := onnxtest.Clean()
	noOpset.Opsets = nil
	wantStatus(t, "no opset", single(t, noOpset), checks.NotTested, "")
	noIR := onnxtest.Clean()
	noIR.IRVersion = 0
	wantStatus(t, "no ir_version", onnxDirModel(t, noIR, nil), checks.NotTested, "")
}

func TestClassifyLocation(t *testing.T) {
	for loc, want := range map[string]string{"w.bin": "w.bin", "./w.bin": "w.bin", "data//w.bin": "data/w.bin", "a/./b": "a/b"} {
		c, _, clean := classifyLocation(loc)
		if c != locOK || clean != want {
			t.Errorf("%q: class %d clean %q, want %q", loc, c, clean, want)
		}
	}
}
