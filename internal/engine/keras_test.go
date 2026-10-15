package engine

import (
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/hdf5/hdf5test"
	"github.com/defilantech/socair/internal/keras/kerastest"
	"github.com/defilantech/socair/internal/report"
)

// A Keras model scanned on its own is identified by its bytes (an HDF5
// signature, or a zip holding config.json and the weights) and read by the
// structure and inventory rows. The Pickle opcode scan does not run on it:
// it is not a pickle. Before #269 a weights-only tf_model.h5 was NOT_TESTED
// ("not a GGUF, safetensors, or ONNX artifact").
func TestSingleKerasModels(t *testing.T) {
	cases := []struct {
		name, file, format, inventory string
		b                             []byte
	}{
		{"weights only", "tf_model.h5", "Keras (HDF5)", "artifact: Keras HDF5", kerastest.WeightsOnly().Bytes()},
		{"a full model", "model.h5", "Keras (HDF5)", "artifact: Keras HDF5", kerastest.FullModel(kerastest.Functional2(kerastest.Dense2("dense"))).Bytes()},
		{"an archive", "model.keras", "Keras", "artifact: .keras archive",
			kerastest.Archive(kerastest.Functional3(kerastest.Dense3("dense")), kerastest.Keras3Weights().Bytes())},
		{"HDF5 that is not Keras", "data.hdf5", "HDF5", "artifact: Keras HDF5", (&hdf5test.File{Root: &hdf5test.Group{
			Datasets: map[string]*hdf5test.Dataset{"x": hdf5test.Weights(3)}}}).Bytes()},
	}
	for _, c := range cases {
		d, err := Scan(writeFixture(t, c.file, c.b))
		if err != nil {
			t.Fatal(err)
		}
		if problems := report.Validate(d); len(problems) != 0 {
			t.Fatalf("%s: %v", c.name, problems)
		}
		if d.Artifact.Format != c.format {
			t.Errorf("%s: format %q", c.name, d.Artifact.Format)
		}
		if r := row(d, "Format and structure"); r.Status != report.StatusPass {
			t.Errorf("%s: structure %s: %s", c.name, r.Status, r.Notes)
		}
		if r := row(d, "File inventory and payloads"); r.Status != report.StatusNotTested || !strings.Contains(r.Notes, c.inventory) {
			t.Errorf("%s: inventory %s: %s", c.name, r.Status, r.Notes)
		}
		if r := row(d, "Pickle opcode scan"); r.Name != "" {
			t.Errorf("%s: a Pickle opcode scan row on a Keras model: %s", c.name, r.Status)
		}
		if len(d.OutOfScope.UnparsedFormats) != 0 {
			t.Errorf("%s: named unparsed: %v", c.name, d.OutOfScope.UnparsedFormats)
		}
	}
	// Bytes that only end in .h5 are not Keras.
	d, err := Scan(writeFixture(t, "fake.h5", []byte("not a model")))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(d.Artifact.Format, "HDF5") || strings.Contains(d.Artifact.Format, "Keras") {
		t.Errorf("a name made a file Keras: %q", d.Artifact.Format)
	}
	// A user block's bytes come before the HDF5 data, and a pickle loader
	// reads them first, so the pickle row runs on them.
	f := kerastest.WeightsOnly()
	f.UserBlock = 512
	if d, err = Scan(writeFixture(t, "tf_model.h5", f.Bytes())); err != nil {
		t.Fatal(err)
	}
	if r := row(d, "Pickle opcode scan"); r.Name == "" {
		t.Error("no Pickle opcode scan row on an HDF5 file with a user block")
	}
}

// A Lambda's bytecode in a single file is a FAIL that withholds it.
func TestSingleKerasLambdaWithholds(t *testing.T) {
	d, err := Scan(writeFixture(t, "model.h5", kerastest.FullModel(kerastest.Functional2(kerastest.Lambda2("lam", kerastest.Bytecode))).Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	r := row(d, "Format and structure")
	if r.Status != report.StatusFail || !strings.Contains(r.Evidence, "keras-lambda") || d.PromotionAuthorization.Authorized {
		t.Errorf("structure %s: %s %s; %s", r.Status, r.Evidence, r.Notes, d.PromotionAuthorization.State)
	}
}

// In a model directory, a tf_model.h5 beside the safetensors is read, not
// named unparsed; a .keras archive is read entry by entry, so the
// inventory counts it as read; and a KerasHub preset's config.json, a Keras
// serialized object, is checked by the config rules.
func TestDirectoryKeras(t *testing.T) {
	d, err := Scan(modelRepo(t, map[string]string{
		"tf_model.h5": string(kerastest.WeightsOnly().Bytes()),
		"model.keras": string(kerastest.Archive(kerastest.Functional3(kerastest.Dense3("dense")), kerastest.Keras3Weights().Bytes())),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if problems := report.Validate(d); len(problems) != 0 {
		t.Fatal(problems)
	}
	if r := row(d, "Format and structure"); r.Status != report.StatusPass || !strings.Contains(r.Notes, "3 of 3 file(s) PASS") {
		t.Errorf("structure %s: %s", r.Status, r.Notes)
	}
	if r := row(d, "File inventory and payloads"); r.Status != report.StatusPass {
		t.Errorf("inventory %s: %s", r.Status, r.Notes)
	}
	for _, u := range d.OutOfScope.UnparsedFormats {
		if strings.Contains(u, ".h5") || strings.Contains(u, ".keras") {
			t.Errorf("a Keras file is named unparsed: %s", u)
		}
	}

	// A KerasHub preset: its backbone's config.json names a class with a
	// code path outside Keras; it is graded, not passed over.
	preset := modelRepo(t, map[string]string{
		"config.json":      kerastest.Layer3("tornet.models.keras.layers", "CoordConv2D", "c"),
		"model.weights.h5": string(kerastest.Keras3Weights().Bytes()),
	})
	if d, err = Scan(preset); err != nil {
		t.Fatal(err)
	}
	if r := row(d, "Format and structure"); r.Status != report.StatusNotTested || !strings.Contains(r.Notes, "tornet.models.keras.layers.CoordConv2D") {
		t.Errorf("preset structure %s: %s", r.Status, r.Notes)
	}
	// A junk .h5 is a weight file this scanner does not parse.
	if d, err = Scan(modelRepo(t, map[string]string{"tf_model.h5": "not a model"})); err != nil {
		t.Fatal(err)
	}
	if r := row(d, "Format and structure"); r.Status != report.StatusNotTested || !strings.Contains(r.Notes, ".h5 is not a container this scanner parses") {
		t.Errorf("junk .h5 %s: %s", r.Status, r.Notes)
	}
}
