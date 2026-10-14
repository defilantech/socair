package engine

import (
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/onnx/onnxtest"
	"github.com/defilantech/socair/internal/report"
)

// An ONNX model scanned on its own is identified by its bytes and read by
// the structure and inventory rows. The Pickle opcode scan does not run on
// it: it is not a pickle, and a NOT_TESTED pickle row would withhold every
// ONNX model for a check that does not apply.
func TestSingleONNXModel(t *testing.T) {
	d, err := Scan(writeFixture(t, "model.onnx", onnxtest.Clean().Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if problems := report.Validate(d); len(problems) != 0 {
		t.Fatal(problems)
	}
	if d.Artifact.Format != "ONNX" {
		t.Errorf("format %q", d.Artifact.Format)
	}
	if s := rowStatus(d, "Format and structure"); s != report.StatusPass {
		t.Errorf("structure %s: %s", s, row(d, "Format and structure").Notes)
	}
	if r := row(d, "File inventory and payloads"); r.Status != report.StatusNotTested || !strings.Contains(r.Notes, "artifact: ONNX model") {
		t.Errorf("inventory %s: %s", r.Status, r.Notes)
	}
	if r := row(d, "Pickle opcode scan"); r.Name != "" {
		t.Errorf("a Pickle opcode scan row on an ONNX model: %s", r.Status)
	}
	if len(d.OutOfScope.UnparsedFormats) != 0 {
		t.Errorf("an ONNX model is named unparsed: %v", d.OutOfScope.UnparsedFormats)
	}
	// Bytes that only end in .onnx are not ONNX.
	d, err = Scan(writeFixture(t, "fake.onnx", []byte("not a model")))
	if err != nil {
		t.Fatal(err)
	}
	if d.Artifact.Format == "ONNX" {
		t.Error("a name made a file ONNX")
	}
}

func onnxRepo(t *testing.T, m onnxtest.Model, extra map[string]string) string {
	t.Helper()
	files := map[string]string{"onnx/model.onnx": string(m.Bytes())}
	for k, v := range extra {
		files[k] = v
	}
	return modelRepo(t, files)
}

func withExternal(location string) onnxtest.Model {
	m := onnxtest.Clean()
	m.Graph.Initializers = append(m.Graph.Initializers, onnxtest.ExternalWeight("e", location, 0, 4))
	return m
}

// A sentence-transformers repository ships its model as safetensors and as
// ONNX in onnx/. Before #264 the ONNX files were NOT_TESTED ("not a
// container this scanner parses"), so a clean repository stayed withheld.
func TestDirectoryONNXIsChecked(t *testing.T) {
	ms := onnxtest.Clean()
	ms.Graph.Nodes = append(ms.Graph.Nodes, onnxtest.Node{OpType: "SkipLayerNormalization", Domain: "com.microsoft"})
	dir := onnxRepo(t, withExternal("model.onnx_data"), map[string]string{
		"onnx/model.onnx_data": string(make([]byte, 16)),
		"onnx/model_O2.onnx":   string(ms.Bytes()),
	})
	d, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if problems := report.Validate(d); len(problems) != 0 {
		t.Fatal(problems)
	}
	r := row(d, "Format and structure")
	if r.Status != report.StatusPass || !strings.Contains(r.Notes, "3 of 3 file(s) PASS") {
		t.Errorf("structure %s: %s", r.Status, r.Notes)
	}
	for _, u := range d.OutOfScope.UnparsedFormats {
		if strings.Contains(u, ".onnx") {
			t.Errorf("an ONNX file is named unparsed: %s", u)
		}
	}
	if r := row(d, "File inventory and payloads"); r.Status != report.StatusPass {
		t.Errorf("inventory %s: %s", r.Status, r.Notes)
	}
}

// In a directory, each ONNX model's text is scanned, not only the listing.
func TestDirectoryONNXTextIsScanned(t *testing.T) {
	m := onnxtest.Clean()
	m.Metadata = []onnxtest.KV{{Key: "note", Value: "#!/bin/sh\necho socair"}}
	d, err := Scan(onnxRepo(t, m, nil))
	if err != nil {
		t.Fatal(err)
	}
	if r := row(d, "File inventory and payloads"); r.Status != report.StatusFail || !strings.Contains(r.Evidence, "embedded-script: onnx/model.onnx") {
		t.Errorf("inventory %s: %s %s", r.Status, r.Evidence, r.Notes)
	}
}

func TestDirectoryONNXEscapeWithholds(t *testing.T) {
	d, err := Scan(onnxRepo(t, withExternal("../../etc/hosts"), nil))
	if err != nil {
		t.Fatal(err)
	}
	r := row(d, "Format and structure")
	if r.Status != report.StatusFail || !strings.Contains(r.Evidence, "external-data-escape: onnx/model.onnx: initializer \"e\"") {
		t.Errorf("structure %s: %s %s", r.Status, r.Evidence, r.Notes)
	}
	if d.PromotionAuthorization.Authorized {
		t.Errorf("an escaping location was authorized: %s", d.PromotionAuthorization.State)
	}
	// A data file the pull left out is a gap, not evidence.
	d, err = Scan(onnxRepo(t, withExternal("model.onnx_data"), nil))
	if err != nil {
		t.Fatal(err)
	}
	if r := row(d, "Format and structure"); r.Status != report.StatusNotTested || !strings.Contains(r.Notes, "onnx/model.onnx_data is not in the directory") {
		t.Errorf("missing data file: %s: %s", r.Status, r.Notes)
	}
}
