package engine

import (
	"fmt"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/openvino/openvinotest"
	"github.com/defilantech/socair/internal/report"
)

// An OpenVINO IR's .xml scanned on its own is identified by its bytes and
// read by the structure and inventory rows; its .bin is not in the scan.
// The Pickle opcode scan does not run on it.
func TestSingleOpenVINOIR(t *testing.T) {
	d, err := Scan(writeFixture(t, "openvino_model.xml", openvinotest.Clean().XML()))
	if err != nil {
		t.Fatal(err)
	}
	if problems := report.Validate(d); len(problems) != 0 {
		t.Fatal(problems)
	}
	if d.Artifact.Format != "OpenVINO IR" {
		t.Errorf("format %q", d.Artifact.Format)
	}
	if r := row(d, "Format and structure"); r.Status != report.StatusNotTested || !strings.Contains(r.Notes, "outside a single-file scan") {
		t.Errorf("structure %s: %s", r.Status, r.Notes)
	}
	if r := row(d, "File inventory and payloads"); r.Status != report.StatusNotTested || !strings.Contains(r.Notes, "artifact: OpenVINO IR XML") {
		t.Errorf("inventory %s: %s", r.Status, r.Notes)
	}
	if r := row(d, "Pickle opcode scan"); r.Name != "" {
		t.Errorf("a Pickle opcode scan row on an OpenVINO IR: %s", r.Status)
	}
	if len(d.OutOfScope.UnparsedFormats) != 0 {
		t.Errorf("an IR is named unparsed: %v", d.OutOfScope.UnparsedFormats)
	}
	// XML whose root is not <net> is not an IR.
	d, err = Scan(writeFixture(t, "pom.xml", []byte("<project/>")))
	if err != nil {
		t.Fatal(err)
	}
	if d.Artifact.Format == "OpenVINO IR" {
		t.Error("a name made a file an IR")
	}
	// A .bin on its own keeps today's handling: the pickle row says why.
	d, err = Scan(writeFixture(t, "openvino_model.bin", openvinotest.Floats(4)))
	if err != nil {
		t.Fatal(err)
	}
	if r := row(d, "Pickle opcode scan"); r.Status != report.StatusNotTested {
		t.Errorf("a lone .bin: pickle row %s: %s", r.Status, r.Notes)
	}
}

func irRepo(t *testing.T, m openvinotest.Model, extra map[string]string) string {
	t.Helper()
	files := map[string]string{"openvino/openvino_model.xml": string(m.XML())}
	if m.Bin != nil {
		files["openvino/openvino_model.bin"] = string(m.Bin)
	}
	for k, v := range extra {
		files[k] = v
	}
	return modelRepo(t, files)
}

// A sentence-transformers repository ships its model as OpenVINO IR in
// openvino/. Before #268 its .bin reached the Pickle opcode scan by its
// extension and was NOT_TESTED there, and the .xml was not read.
func TestDirectoryOpenVINOIsChecked(t *testing.T) {
	d, err := Scan(irRepo(t, openvinotest.Clean(), nil))
	if err != nil {
		t.Fatal(err)
	}
	if problems := report.Validate(d); len(problems) != 0 {
		t.Fatal(problems)
	}
	r := row(d, "Format and structure")
	if r.Status != report.StatusPass || !strings.Contains(r.Notes, "2 of 2 file(s) PASS (model.safetensors, openvino/openvino_model.xml)") {
		t.Errorf("structure %s: %s", r.Status, r.Notes)
	}
	if r := row(d, "Pickle opcode scan"); r.Name != "" {
		t.Errorf("the IR's .bin reached the pickle row: %s: %s", r.Status, r.Notes)
	}
	inv := row(d, "File inventory and payloads")
	if inv.Status != report.StatusPass || !strings.Contains(inv.Notes, "read through its .xml") {
		t.Errorf("inventory %s: %s", inv.Status, inv.Notes)
	}
}

// The .bin is spared the pickle row's extension rule only when an IR beside
// it names it and its bytes hold nothing the pickle check reads: a pickle
// there still reaches the row by its name, and a .bin with no IR, or
// pytorch_model.bin, is handled as before.
func TestDirectoryOpenVINOBinStillScanned(t *testing.T) {
	gadget := "\x80\x02cposix\nsystem\nX\x15\x00\x00\x00echo socair-benchmark\x85R."
	m := openvinotest.Clean()
	m.Bin = []byte(gadget)
	m.Layers[1] = openvinotest.Const(1, "w", "u8", fmt.Sprint(len(gadget)), 0, int64(len(gadget)))
	d, err := Scan(irRepo(t, m, nil))
	if err != nil {
		t.Fatal(err)
	}
	if r := row(d, "Pickle opcode scan"); r.Status != report.StatusFail || !strings.Contains(r.Evidence, "openvino/openvino_model.bin") {
		t.Errorf("a pickle as the IR's .bin: %s: %s %s", r.Status, r.Evidence, r.Notes)
	}
	d, err = Scan(modelRepo(t, map[string]string{"openvino/other.bin": string(openvinotest.Floats(4)), "pytorch_model.bin": string(openvinotest.Floats(4))}))
	if err != nil {
		t.Fatal(err)
	}
	r := row(d, "Pickle opcode scan")
	if r.Status != report.StatusNotTested || !strings.Contains(r.Notes, "openvino/other.bin") || !strings.Contains(r.Notes, "pytorch_model.bin") {
		t.Errorf("a .bin with no IR: %s: %s", r.Status, r.Notes)
	}
}

// A protocol 0 pickle has no header for pickle.Sniff to find, so naming one
// pytorch_model.bin and writing an IR beside it whose u8 Const covers it
// must not keep it from the pickle row: a loader that reads the .bin by its
// name as a torch checkpoint runs it. Falsification: keep every IR's .bin
// from the pickle row, or decide by pickle.Sniff alone, and this passes
// unscanned.
func TestDirectoryOpenVINOBinPolyglot(t *testing.T) {
	gadget := "cposix\nsystem\n(Vecho socair-benchmark\ntR."
	m := openvinotest.Clean()
	m.Layers[1] = openvinotest.Const(1, "w", "u8", fmt.Sprint(len(gadget)), 0, int64(len(gadget)))
	d, err := Scan(modelRepo(t, map[string]string{"pytorch_model.xml": string(m.XML()), "pytorch_model.bin": gadget}))
	if err != nil {
		t.Fatal(err)
	}
	if r := row(d, "Format and structure"); r.Status != report.StatusPass {
		t.Fatalf("the fixture is not a well-formed IR, so it tests nothing: %s: %s", r.Status, r.Notes)
	}
	if r := row(d, "Pickle opcode scan"); r.Status != report.StatusFail || !strings.Contains(r.Evidence, "pytorch_model.bin") {
		t.Errorf("a protocol 0 pickle under an IR's weights name: %s: %s %s", r.Status, r.Evidence, r.Notes)
	}
	if d.PromotionAuthorization.Authorized {
		t.Errorf("a pickle gadget beside an IR was authorized: %s", d.PromotionAuthorization.State)
	}
}

func TestDirectoryOpenVINOFindings(t *testing.T) {
	m := openvinotest.Clean()
	m.RTInfo += `<note value="#!/bin/sh&#10;echo socair"/>`
	d, err := Scan(irRepo(t, m, nil))
	if err != nil {
		t.Fatal(err)
	}
	if r := row(d, "File inventory and payloads"); r.Status != report.StatusFail || !strings.Contains(r.Evidence, "embedded-script: openvino/openvino_model.xml") {
		t.Errorf("inventory %s: %s %s", r.Status, r.Evidence, r.Notes)
	}
	m = openvinotest.Clean()
	m.Layers[1] = openvinotest.Const(1, "w", "f32", "4", 0, 4096)
	m.Bin = make([]byte, 4096)
	d, err = Scan(irRepo(t, m, nil))
	if err != nil {
		t.Fatal(err)
	}
	r := row(d, "Format and structure")
	if r.Status != report.StatusFail || !strings.Contains(r.Evidence, "tensor-size: openvino/openvino_model.xml") {
		t.Errorf("structure %s: %s %s", r.Status, r.Evidence, r.Notes)
	}
	if d.PromotionAuthorization.Authorized {
		t.Errorf("a mis-sized Const was authorized: %s", d.PromotionAuthorization.State)
	}
	// A .bin the pull left out is a gap, not evidence.
	m = openvinotest.Clean()
	m.Bin = nil
	d, err = Scan(irRepo(t, m, nil))
	if err != nil {
		t.Fatal(err)
	}
	if r := row(d, "Format and structure"); r.Status != report.StatusNotTested || !strings.Contains(r.Notes, "openvino/openvino_model.bin is not in the directory") {
		t.Errorf("missing .bin: %s: %s", r.Status, r.Notes)
	}
}
