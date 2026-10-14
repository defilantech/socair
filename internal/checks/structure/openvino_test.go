package structure

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/openvino/openvinotest"
)

// irDir writes m as openvino/openvino_model.xml and .bin inside a new
// directory and checks it as a directory scan does.
func irDir(t *testing.T, m openvinotest.Model) checks.Result {
	t.Helper()
	root := t.TempDir()
	if _, err := m.Write(filepath.Join(root, "openvino"), "openvino_model"); err != nil {
		t.Fatal(err)
	}
	return ValidateOpenVINO(root, "openvino/openvino_model.xml")
}

func withConst(et, shape string, offset, size int64, bin []byte) openvinotest.Model {
	m := openvinotest.Clean()
	m.Layers[1] = openvinotest.Const(1, "w", et, shape, offset, size)
	m.Bin = bin
	return m
}

func TestOpenVINOClean(t *testing.T) {
	r := irDir(t, openvinotest.Clean())
	wantStatus(t, "clean directory", r, checks.Pass, "")
	for _, s := range []string{`OpenVINO IR v11 "Model0"`, "4 layer(s) in 1 graph(s), 4 built", "from opset1 (4 type(s))",
		"1 Const(s) in 1 distinct range(s) of openvino/openvino_model.bin (16 bytes)", "exactly the size its element type and shape take",
		"no byte outside them", "Tensor values are not read", "extension library"} {
		if !strings.Contains(r.Notes, s) {
			t.Errorf("PASS notes lack %q: %s", s, r.Notes)
		}
	}
	// On its own, the .bin is outside the scan: a gap, not a pass.
	r = Validate(writeFixture(t, "openvino_model.xml", openvinotest.Clean().XML()))
	wantStatus(t, "single file", r, checks.NotTested, "")
	if !strings.Contains(r.Notes, "1 Const(s) keep their data in openvino_model.bin, outside a single-file scan") {
		t.Errorf("single-file notes: %s", r.Notes)
	}
}

// TestOpenVINOConstSizes: a Const's size must be exactly what OpenVINO
// allocates for its element type and shape. Falsification: drop the size
// rule and the FAILs go.
func TestOpenVINOConstSizes(t *testing.T) {
	cases := map[string]struct {
		m       openvinotest.Model
		status  checks.Status
		pattern string
		detail  string
	}{
		"larger than its shape":  {withConst("f32", "4", 0, 4096, make([]byte, 4096)), checks.Fail, "tensor-size", "4080 byte(s) past what its type and shape take"},
		"smaller than its shape": {withConst("f32", "4", 0, 12, make([]byte, 12)), checks.Fail, "tensor-size", "OpenVINO refuses it"},
		"u3 short of its groups": {withConst("u3", "1", 0, 1, make([]byte, 1)), checks.Fail, "tensor-size", "3-byte groups"},
		"u3 in whole groups":     {withConst("u3", "1", 0, 3, make([]byte, 3)), checks.Pass, "", ""},
		"u4 packed":              {withConst("u4", "3", 0, 2, make([]byte, 2)), checks.Pass, "", ""},
		"empty, one byte":        {withConst("u8", "0", 0, 1, make([]byte, 1)), checks.Pass, "", ""},
		"empty, no bytes":        {withConst("u8", "0", 0, 0, []byte{}), checks.Pass, "", ""},
		"empty, two bytes":       {withConst("u8", "0", 0, 2, make([]byte, 2)), checks.Fail, "tensor-size", ""},
		"string":                 {withConst("string", "1", 0, 16, make([]byte, 16)), checks.NotTested, "", ""},
		"dynamic":                {withConst("dynamic", "4", 0, 16, make([]byte, 16)), checks.NotTested, "", ""},
		"unknown type":           {withConst("FP32", "4", 0, 16, make([]byte, 16)), checks.NotTested, "", ""},
		"shape overflows":        {withConst("f32", "4294967296, 4294967296", 0, 16, make([]byte, 16)), checks.NotTested, "", ""},
	}
	for name, c := range cases {
		r := irDir(t, c.m)
		wantStatus(t, name, r, c.status, c.pattern)
		if c.detail != "" && (len(r.Findings) == 0 || !strings.Contains(r.Findings[0].Detail, c.detail)) {
			t.Errorf("%s: detail %v lacks %q", name, r.Findings, c.detail)
		}
	}
	// The size rule needs no .bin: a single .xml FAILs on it too.
	r := Validate(writeFixture(t, "m.xml", withConst("f32", "4", 0, 4096, nil).XML()))
	wantStatus(t, "single file size", r, checks.Fail, "tensor-size")
}

// TestOpenVINOWeights: the Consts' ranges against the .bin. Falsification:
// skip the range or coverage checks and the gaps pass.
func TestOpenVINOWeights(t *testing.T) {
	tail := openvinotest.Clean()
	tail.Bin = append(openvinotest.Floats(4), append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, 60)...)...)
	gap := withConst("f32", "4", 8, 16, make([]byte, 24))
	twoShare := openvinotest.Clean()
	twoShare.Layers = append(twoShare.Layers[:2], append([]openvinotest.Layer{openvinotest.Const(4, "w2", "i32", "4", 0, 16)}, twoShare.Layers[2:]...)...)
	twoShare.Layers[3].In = 3
	twoShare.Edges = append(twoShare.Edges, openvinotest.Edge{From: 4, To: 2, ToPort: 2})
	overlap := openvinotest.Clean()
	overlap.Bin = make([]byte, 24)
	overlap.Layers = append(overlap.Layers, openvinotest.Const(4, "w2", "f32", "4", 8, 16))
	overlap.Layers[2].In = 3
	overlap.Edges = append(overlap.Edges, openvinotest.Edge{From: 4, To: 2, ToPort: 2})
	noBin := openvinotest.Clean()
	noBin.Bin = nil
	cases := map[string]struct {
		m    openvinotest.Model
		want checks.Status
		note string
	}{
		"range past the .bin":  {withConst("f32", "4", 8, 16, make([]byte, 16)), checks.NotTested, "runs past the end of openvino/openvino_model.bin (16 bytes)"},
		"offset past the .bin": {withConst("f32", "0", 32, 0, make([]byte, 16)), checks.NotTested, "runs past the end"},
		"bytes after the last": {tail, checks.NotTested, "64 byte(s) of openvino/openvino_model.bin, in 1 range(s), are outside every Const"},
		"bytes before":         {gap, checks.NotTested, "8 byte(s) of openvino/openvino_model.bin, in 1 range(s), are outside every Const: OpenVINO never reads them, its writer leaves none, and they were not inspected ([0, 8))"},
		"a shared range":       {twoShare, checks.Pass, "2 Const(s) in 1 distinct range(s)"},
		"a partial overlap":    {overlap, checks.NotTested, "partly overlap"},
		"no .bin":              {noBin, checks.NotTested, "openvino/openvino_model.bin is not in the directory"},
	}
	for name, c := range cases {
		r := irDir(t, c.m)
		wantStatus(t, name, r, c.want, "")
		if !strings.Contains(r.Notes, c.note) {
			t.Errorf("%s: notes lack %q: %s", name, c.note, r.Notes)
		}
	}
	// A model with no Const needs no .bin; a .bin it has is all unread.
	none := openvinotest.Clean()
	none.Layers = []openvinotest.Layer{none.Layers[0], {ID: 3, Name: "out", Type: "Result", Version: "opset1", In: 1}}
	none.Edges = []openvinotest.Edge{{From: 0, To: 3}}
	none.Bin = nil
	wantStatus(t, "no Const, no .bin", irDir(t, none), checks.Pass, "")
	none.Bin = []byte("payload")
	wantStatus(t, "no Const, a .bin", irDir(t, none), checks.NotTested, "")
}

// TestOpenVINODuplicates: a repeated attribute or layer id is read
// differently by different readers. Falsification: drop either and the
// FAIL goes.
func TestOpenVINODuplicates(t *testing.T) {
	m := openvinotest.Clean()
	m.Layers[1].Data = append(m.Layers[1].Data, openvinotest.Attr{Name: "offset", Value: "4"})
	wantStatus(t, "repeated attribute", irDir(t, m), checks.Fail, "duplicate-key")
	m = openvinotest.Clean()
	m.Layers = append(m.Layers, openvinotest.Const(1, "hidden", "f32", "4", 0, 16))
	wantStatus(t, "repeated layer id", irDir(t, m), checks.Fail, "duplicate-key")
}

// TestOpenVINOOperations: an operation outside OpenVINO's opsets needs an
// extension the deployment registers, a gap. Falsification: treat every
// version as standard and these pass.
func TestOpenVINOOperations(t *testing.T) {
	cases := map[string]struct {
		version, typ string
		want         checks.Status
	}{
		"extension op":            {"extension", "BPETokenizer", checks.NotTested},
		"unknown opset":           {"opset99", "Add", checks.NotTested},
		"op not in its opset":     {"opset17", "Add", checks.NotTested},
		"lowercase standard op":   {"opset1", "add", checks.Pass},
		"later opset's operation": {"opset13", "BitwiseAnd", checks.Pass},
	}
	for name, c := range cases {
		m := openvinotest.Clean()
		m.Layers[2].Version, m.Layers[2].Type = c.version, c.typ
		r := irDir(t, m)
		wantStatus(t, name, r, c.want, "")
		if c.want == checks.NotTested && !strings.Contains(r.Notes, "extension library the deployment registers") {
			t.Errorf("%s: notes: %s", name, r.Notes)
		}
	}
}

func TestOpenVINOGaps(t *testing.T) {
	dangling := openvinotest.Clean()
	dangling.Bin = make([]byte, 32)
	dangling.Layers = append(dangling.Layers, openvinotest.Const(7, "dangle", "f32", "4", 16, 16))
	old := openvinotest.Clean()
	old.Version = "7"
	unknown := openvinotest.Clean()
	unknown.Raw = "<statistics/>"
	cases := map[string]struct {
		m    openvinotest.Model
		note string
	}{
		"a layer nothing reads": {dangling, `1 layer(s) OpenVINO does not build`},
		"IR version 7":          {old, `IR version "7"`},
		"an unknown element":    {unknown, "<statistics> in <net>"},
	}
	for name, c := range cases {
		r := irDir(t, c.m)
		wantStatus(t, name, r, checks.NotTested, "")
		if !strings.Contains(r.Notes, c.note) {
			t.Errorf("%s: notes lack %q: %s", name, c.note, r.Notes)
		}
	}
	// The dangling Const's range is not read, so its bytes are unread too.
	if r := irDir(t, dangling); !strings.Contains(r.Notes, "16 byte(s) of openvino/openvino_model.bin") {
		t.Errorf("a dangling Const counted as reading the .bin: %s", r.Notes)
	}
	r := irDir(t, openvinotest.Model{Version: "11", Bin: []byte{}})
	wantStatus(t, "an empty net", r, checks.Pass, "")
	p := filepath.Join(t.TempDir(), "m.xml")
	if err := os.WriteFile(p, []byte("<net><layers>"), 0o600); err != nil {
		t.Fatal(err)
	}
	r = Validate(p)
	wantStatus(t, "truncated", r, checks.NotTested, "")
	if !strings.Contains(r.Notes, "could not parse the OpenVINO IR") {
		t.Errorf("truncated notes: %s", r.Notes)
	}
}
