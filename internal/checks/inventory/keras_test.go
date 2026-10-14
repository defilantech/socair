package inventory

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/hdf5/hdf5test"
	"github.com/defilantech/socair/internal/keras/kerastest"
)

// TestKerasText: a Keras model's text goes through the same payload
// patterns as GGUF, safetensors, and ONNX metadata: an archive's
// config.json and metadata.json (keys and string values), its assets and
// any member Keras does not read, its comments, the weights file's string
// attributes, and an HDF5 file's attributes, model config, object comments,
// and user block. Falsification: drop the Keras case from Inspect, or stop
// the reader keeping a kind of text, and the FAILs go.
func TestKerasText(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("echo socair; ", 60)))
	config := kerastest.Functional3(kerastest.Dense3("dense"))
	weights := kerastest.Keras3Weights().Bytes()
	withAttr := func(a hdf5test.Attr) []byte {
		f := kerastest.WeightsOnly()
		f.Root.Attrs = append(f.Root.Attrs, a)
		return f.Bytes()
	}
	commented := kerastest.WeightsOnly()
	commented.Root.Groups["bert"].Extra = []hdf5test.Message{{Type: 0x0D, Data: []byte("#!/bin/sh\nid\x00")}}
	userBlock := kerastest.WeightsOnly()
	userBlock.UserBlock, userBlock.UserBlockBytes = 512, elf
	cases := map[string]struct {
		name    string
		b       []byte
		pattern string
	}{
		"metadata.json value": {"model.keras", kerastest.Zip(
			kerastest.Member{Name: "metadata.json", Data: []byte(`{"keras_version": "3.15.1", "note": "#!/bin/sh\necho socair-benchmark"}`)},
			kerastest.Member{Name: "config.json", Data: []byte(config)},
			kerastest.Member{Name: "model.weights.h5", Data: weights}), "embedded-script"},
		"metadata.json key": {"model.keras", kerastest.Zip(
			kerastest.Member{Name: "metadata.json", Data: []byte(`{"<script>x</script>": "v"}`)},
			kerastest.Member{Name: "config.json", Data: []byte(config)},
			kerastest.Member{Name: "model.weights.h5", Data: weights}), "embedded-script"},
		"config.json value": {"model.keras", kerastest.Archive(kerastest.Functional3(kerastest.Layer3("keras.layers", "Dense", b64)), weights), "embedded-base64-blob"},
		"an asset":          {"model.keras", kerastest.Archive(config, weights, kerastest.Member{Name: "assets/vocab.txt", Data: elf}), "embedded-binary"},
		"a member Keras does not read": {"model.keras", kerastest.Archive(config, weights,
			kerastest.Member{Name: "run.sh", Data: []byte("#!/bin/sh\necho socair-benchmark\n")}), "embedded-script"},
		"a scalar attribute":   {"tf_model.h5", withAttr(hdf5test.Attr{Name: "note", Strings: []string{b64}}), "embedded-base64-blob"},
		"a fixed-length array": {"tf_model.h5", withAttr(hdf5test.Attr{Name: "names", Fixed: true, Array: true, Strings: []string{"a", "#!/bin/sh\n" + strings.Repeat("echo socair-benchmark; ", 4)}}), "embedded-script"},
		"the model config": {"model.h5", kerastest.FullModel(kerastest.Functional2(
			`{"class_name": "Dense", "config": {"name": "#!/bin/sh\necho socair-benchmark"}}`)).Bytes(), "embedded-script"},
		"an object comment": {"tf_model.h5", commented.Bytes(), "embedded-script"},
		"a user block":      {"tf_model.h5", userBlock.Bytes(), "embedded-binary"},
	}
	for name, c := range cases {
		r := Inspect(writeFixture(t, c.name, c.b), Options{})
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

// TestKerasCleanText: a clean archive and a clean weights-only file pass
// with a repository listing, and say what they read; a short string-array
// element (a weight name) is counted, not scanned.
func TestKerasCleanText(t *testing.T) {
	archive := writeFixture(t, "model.keras", kerastest.Archive(kerastest.Functional3(kerastest.Dense3("dense")), kerastest.Keras3Weights().Bytes()))
	if r := Inspect(archive, Options{RepoMirror: cleanMirror(t)}); r.Status != checks.Pass || !strings.Contains(r.Notes, "artifact: .keras archive") {
		t.Errorf("clean archive: %s: %s", r.Status, r.Notes)
	}
	f := kerastest.WeightsOnly()
	f.Root.Attrs = append(f.Root.Attrs, hdf5test.Attr{Name: "names", Array: true, Strings: []string{"#!/bin/sh"}})
	r := Inspect(writeFixture(t, "tf_model.h5", f.Bytes()), Options{RepoMirror: cleanMirror(t)})
	if r.Status != checks.Pass || !strings.Contains(r.Notes, "artifact: Keras HDF5") || !strings.Contains(r.Notes, "4 string-array elements under 64 bytes counted") ||
		strings.Contains(r.Notes, "model config") {
		t.Errorf("clean weights: %s: %s", r.Status, r.Notes)
	}
}

// TestKerasWeightsUnread: an archive whose weights file was not read (here,
// compressed) has text the inventory did not see, so it cannot pass.
func TestKerasWeightsUnread(t *testing.T) {
	b := kerastest.Zip(kerastest.Member{Name: "config.json", Data: []byte(kerastest.Functional3(kerastest.Dense3("dense")))},
		kerastest.Member{Name: "model.weights.h5", Data: kerastest.Keras3Weights().Bytes(), Deflate: true})
	r := Inspect(writeFixture(t, "model.keras", b), Options{RepoMirror: cleanMirror(t)})
	if r.Status != checks.NotTested || !strings.Contains(r.Notes, "weights file's attributes were not read") {
		t.Errorf("compressed weights: %s: %s", r.Status, r.Notes)
	}
}
