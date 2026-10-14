package ociattest_test

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/ociattest"
	"github.com/defilantech/socair/internal/report"
)

// modelFiles is the model directory the mapping tests attest.
var modelFiles = map[string][]byte{
	"config.json":           []byte(`{"model_type":"llama"}`),
	"model.safetensors":     []byte("weights"),
	"tokenizer/vocab.json":  []byte(`{"a":0}`),
	"tokenizer_config.json": []byte(`{}`),
}

func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// dirIdentity is a model directory attestation's identity for files.
func dirIdentity(files map[string][]byte) report.ArtifactIdentity {
	a := report.ArtifactIdentity{FileName: "tiny-model", SHA256: strings.Repeat("0", 64)}
	for p, b := range files {
		a.Files = append(a.Files, report.ArtifactFile{Path: p, SHA256: sha(b), SizeBytes: int64(len(b))})
	}
	return a
}

func fileIdentity(name string, b []byte) report.ArtifactIdentity {
	return report.ArtifactIdentity{FileName: name, SHA256: sha(b), SizeBytes: int64(len(b))}
}

// mapImage maps layers held in memory.
func mapImage(t testing.TB, layers []imgLayer, a report.ArtifactIdentity, o ociattest.MapOptions) (*ociattest.Match, error) {
	t.Helper()
	blobs := memBlobs{}
	m := imageManifest(layers, "", blobs.put)
	return ociattest.MapTarLayers(ctx, m, a, blobs.open, o)
}

// modelcar is the image KServe's documentation builds: FROM busybox, RUN
// mkdir /models, COPY data/ /models/.
func modelcar(t testing.TB, extra ...imgLayer) []imgLayer {
	return append([]imgLayer{busyboxBase(t), runLayer(t), copyLayer(t, modelFiles)}, extra...)
}

func TestMapAModelCarImage(t *testing.T) {
	m, err := mapImage(t, modelcar(t), dirIdentity(modelFiles), ociattest.MapOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if m.Kind != ociattest.MatchModelRoot || m.ModelRoot != "models" || m.Rules != ociattest.LayerRules || len(m.Layers) != 3 {
		t.Fatalf("match %+v", m)
	}
	var roles []string
	for _, l := range m.Layers {
		roles = append(roles, l.Role)
	}
	if !slices.Equal(roles, []string{ociattest.RoleBase, ociattest.RoleBase, ociattest.RoleModel}) {
		t.Errorf("roles %v", roles)
	}
	want := []string{"config.json", "model.safetensors", "tokenizer/vocab.json", "tokenizer_config.json"}
	if !slices.Equal(m.Layers[2].Files, want) || m.Layers[0].Files != nil {
		t.Errorf("files %v / %v", m.Layers[2].Files, m.Layers[0].Files)
	}
	if m.Layers[0].Entries != 15 || m.Layers[1].Entries != 3 || m.Layers[2].Entries != 6 {
		t.Errorf("entries %d %d %d", m.Layers[0].Entries, m.Layers[1].Entries, m.Layers[2].Entries)
	}
}

// TestMapLayerKinds: uncompressed OCI layers and Docker's gzip layers are
// read; a model root elsewhere is mapped when named; a single file is mapped
// when it is the model root's one file.
func TestMapLayerKinds(t *testing.T) {
	copyTar := copyLayer(t, modelFiles)
	plain := imgLayer{tarOf(t, []ent{dir("models/"), dir("models/tokenizer/"), reg("models/config.json", `{"model_type":"llama"}`),
		reg("models/model.safetensors", "weights"), reg("models/tokenizer/vocab.json", `{"a":0}`), reg("models/tokenizer_config.json", `{}`)}), ociLayerTar, nil}
	docker := imgLayer{copyTar.blob, dockerLayerGzip, nil}
	for name, layers := range map[string][]imgLayer{
		"uncompressed": {busyboxBase(t), plain},
		"docker":       {busyboxBase(t), docker},
		"model only":   {copyTar},
	} {
		if _, err := mapImage(t, layers, dirIdentity(modelFiles), ociattest.MapOptions{}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	opt := gzLayer(t, dir("opt/"), dir("opt/ml/"), dir("opt/ml/model/"), reg("opt/ml/model/w.gguf", "gguf"))
	m, err := mapImage(t, []imgLayer{busyboxBase(t), opt}, fileIdentity("tiny.gguf", []byte("gguf")), ociattest.MapOptions{ModelRoot: "/opt/ml/model/"})
	if err != nil || m.ModelRoot != "opt/ml/model" || !slices.Equal(m.Layers[1].Files, []string{"w.gguf"}) {
		t.Errorf("a single file under /opt/ml/model: %+v, %v", m, err)
	}
}

// TestMapRefusals: each image differs from the ModelCar image in one way that
// could make the tree a consumer unpacks under /models differ from what was
// scanned, or that Socair does not read; each is refused, naming why. The
// ModelCar image itself maps (TestMapAModelCarImage), so each case is the
// falsification test of the check it names: without the check, it maps.
func TestMapRefusals(t *testing.T) {
	cfg := string(modelFiles["config.json"])
	files := dirIdentity(modelFiles)
	multi := func() imgLayer {
		raw := tarOf(t, []ent{dir("models/"), dir("models/tokenizer/"), reg("models/config.json", cfg), reg("models/model.safetensors", "weights"),
			reg("models/tokenizer/vocab.json", `{"a":0}`), reg("models/tokenizer_config.json", `{}`)})
		// models/, models/tokenizer/, and config.json (a header and a data
		// block): the first member ends at an entry boundary, where Python's
		// tarfile, reading the layer as a stream, would stop without error.
		cut := 4 * 512
		return imgLayer{append(gz(raw[:cut]), gz(raw[cut:])...), ociLayerGzip, nil}
	}
	afterArchive := imgLayer{append(copyLayer(t, modelFiles).blob, gz(tarOf(t, []ent{reg("models/evil", "x")}))...), ociLayerGzip, nil}
	bomb := imgLayer{gz(tarOf(t, []ent{reg("var/zeros", string(make([]byte, 4<<20)))})), ociLayerGzip, nil}
	cases := []struct {
		name   string
		layers []imgLayer
		a      report.ArtifactIdentity
		o      ociattest.MapOptions
		want   string
	}{
		// What the model root holds.
		{"a file the attestation does not list", modelcar(t, gzLayer(t, reg("models/extra.json", "{}"))), files, ociattest.MapOptions{}, "not a file the attestation lists"},
		{"an attested file missing", []imgLayer{busyboxBase(t), copyLayer(t, map[string][]byte{"config.json": modelFiles["config.json"]})}, files, ociattest.MapOptions{}, "no file for attested models/model.safetensors"},
		{"other bytes", []imgLayer{copyLayer(t, map[string][]byte{"config.json": []byte(`{"model_type":"lla.a"}`), "model.safetensors": []byte("weights"), "tokenizer/vocab.json": []byte(`{"a":0}`), "tokenizer_config.json": []byte(`{}`)})}, files, ociattest.MapOptions{}, "but the attested file is sha256:"},
		{"another size", []imgLayer{copyLayer(t, map[string][]byte{"config.json": []byte(`{}`), "model.safetensors": []byte("weights"), "tokenizer/vocab.json": []byte(`{"a":0}`), "tokenizer_config.json": []byte(`{}`)})}, files, ociattest.MapOptions{}, "2 bytes, but the attested file is"},
		{"an empty directory", modelcar(t, gzLayer(t, dir("models/empty/"))), files, ociattest.MapOptions{}, "holds no attested file"},
		{"a file where the model root is", []imgLayer{gzLayer(t, reg("models", "x")), copyLayer(t, modelFiles)}, files, ociattest.MapOptions{}, "where the model root's directory is"},
		{"a file above the model root", []imgLayer{gzLayer(t, reg("opt", "x")), gzLayer(t, dir("opt/models/"), reg("opt/models/w", "w"))}, fileIdentity("w", []byte("w")), ociattest.MapOptions{ModelRoot: "opt/models"}, "a directory the model root is in"},
		{"a second file for a single-file attestation", []imgLayer{gzLayer(t, reg("models/a.gguf", "gguf"), reg("models/LICENSE", "MIT"))}, fileIdentity("a.gguf", []byte("gguf")), ociattest.MapOptions{}, "a second file in the model root"},
		{"a single file's directory", []imgLayer{gzLayer(t, dir("models/sub/"), reg("models/sub/a.gguf", "gguf"))}, fileIdentity("a.gguf", []byte("gguf")), ociattest.MapOptions{}, "holds no attested file"},
		{"a single file in a subdirectory", []imgLayer{gzLayer(t, reg("models/sub/a.gguf", "gguf"))}, fileIdentity("a.gguf", []byte("gguf")), ociattest.MapOptions{}, "is in a subdirectory of the model root"},
		{"a file that names the image's root", []imgLayer{busyboxBase(t), {renamed(tarOf(t, []ent{reg("X", "x")}), "X", "."), ociLayerTar, nil}, copyLayer(t, modelFiles)}, files, ociattest.MapOptions{}, "names the image's root directory"},
		{"no file for a single-file attestation", []imgLayer{busyboxBase(t), runLayer(t)}, fileIdentity("a.gguf", []byte("gguf")), ociattest.MapOptions{}, "has no file in its model root"},

		// Overlay order and whiteouts.
		{"a duplicate in one layer", []imgLayer{copyLayer(t, modelFiles, reg("models/config.json", cfg))}, files, ociattest.MapOptions{}, "appears twice, in layer 0 and layer 0"},
		{"a later layer replaces a model file", modelcar(t, gzLayer(t, dir("models/"), reg("models/config.json", `{"evil":1}`))), files, ociattest.MapOptions{}, "appears twice, in layer 2 and layer 3"},
		{"a later layer repeats a model file", modelcar(t, gzLayer(t, reg("models/config.json", cfg))), files, ociattest.MapOptions{}, "appears twice"},
		{"a whiteout of a model file", modelcar(t, gzLayer(t, reg("models/.wh.config.json", ""))), files, ociattest.MapOptions{}, "a whiteout of models/config.json"},
		{"a whiteout of the model root", []imgLayer{busyboxBase(t), gzLayer(t, reg(".wh.models", "")), copyLayer(t, modelFiles)}, files, ociattest.MapOptions{}, "a whiteout of models"},
		{"an opaque whiteout in the model root", modelcar(t, gzLayer(t, dir("models/"), reg("models/.wh..wh..opq", ""))), files, ociattest.MapOptions{}, "an opaque whiteout on models/"},
		{"an opaque whiteout on the image's root", []imgLayer{busyboxBase(t), gzLayer(t, reg(".wh..wh..opq", "")), copyLayer(t, modelFiles)}, files, ociattest.MapOptions{}, "an opaque whiteout on ./"},
		{"a whiteout that is not empty", []imgLayer{busyboxBase(t), gzLayer(t, reg("etc/.wh.passwd", "x")), copyLayer(t, modelFiles)}, files, ociattest.MapOptions{}, "not an empty regular file"},
		{"an AUFS metadata name", []imgLayer{busyboxBase(t), gzLayer(t, dir(".wh..wh.plnk/")), copyLayer(t, modelFiles)}, files, ociattest.MapOptions{}, "not an empty regular file"},
		{"an AUFS hard link directory entry", []imgLayer{busyboxBase(t), gzLayer(t, reg(".wh..wh.plnk", "")), copyLayer(t, modelFiles)}, files, ociattest.MapOptions{}, "AUFS metadata name"},
		{"a path through a whiteout name", []imgLayer{busyboxBase(t), gzLayer(t, reg(".wh.x/y", "y")), copyLayer(t, modelFiles)}, files, ociattest.MapOptions{}, "a whiteout name"},

		// Links.
		{"a symbolic link in the model root", modelcar(t, gzLayer(t, sym("models/alias.json", "config.json"))), files, ociattest.MapOptions{}, "a symbolic link at models/alias.json"},
		{"the model root as a symbolic link", []imgLayer{busyboxBase(t), gzLayer(t, dir("data/"), sym("models", "/data"))}, files, ociattest.MapOptions{}, "a symbolic link at models"},
		{"a link outside that leads into the model root", []imgLayer{busyboxBase(t), gzLayer(t, sym("data", "/models")), copyLayer(t, modelFiles)}, files, ociattest.MapOptions{}, "a symbolic link data -> /models"},
		{"a relative link into the model root", []imgLayer{busyboxBase(t), gzLayer(t, dir("a/"), sym("a/l", "../models/config.json")), copyLayer(t, modelFiles)}, files, ociattest.MapOptions{}, "a symbolic link a/l -> ../models/config.json"},
		{"a link to the image's root", []imgLayer{busyboxBase(t), gzLayer(t, sym("rootfs", "/")), copyLayer(t, modelFiles)}, files, ociattest.MapOptions{}, "a symbolic link rootfs -> /"},
		{"a link that reaches the model root only physically", []imgLayer{busyboxBase(t), gzLayer(t, dir("p/"), dir("x/"), sym("x/y", "/p"), sym("x/l", "y/../models")), copyLayer(t, modelFiles)}, files, ociattest.MapOptions{}, "a symbolic link x/l -> y/../models"},
		{"a link that a later layer turns toward the model root", []imgLayer{busyboxBase(t), gzLayer(t, dir("w/"), dir("w/c/"), sym("w/a", "c/../models"), dir("z/")), gzLayer(t, sym("w/c", "/z")), copyLayer(t, modelFiles)}, files, ociattest.MapOptions{}, "symbolic link w/a -> c/../models leads to the model root"},
		{"an entry placed in the model root through a link", []imgLayer{busyboxBase(t), gzLayer(t, dir("w/"), dir("w/c/"), sym("w/a", "c/../models"), dir("z/")), gzLayer(t, sym("w/c", "/z")), gzLayer(t, reg("w/a/evil", "x")), gzLayer(t, dir("w/c/"))}, files, ociattest.MapOptions{}, "w/a/evil is placed at models/evil through a symbolic link"},
		{"a link loop on an entry's path", []imgLayer{busyboxBase(t), gzLayer(t, sym("a", "b"), sym("b", "a"), reg("a/x", "x")), copyLayer(t, modelFiles)}, files, ociattest.MapOptions{}, "more than 40 symbolic links"},
		{"a hard link in the model root", modelcar(t, gzLayer(t, hard("models/copy.json", "models/config.json"))), files, ociattest.MapOptions{}, "a hard link at models/copy.json"},
		{"a hard link outside to a model file", modelcar(t, gzLayer(t, dir("tmp/"), hard("tmp/w", "models/model.safetensors"))), files, ociattest.MapOptions{}, "a hard link tmp/w to models/model.safetensors"},
		{"a hard link to a symbolic link", []imgLayer{busyboxBase(t), gzLayer(t, hard("lib32", "lib64")), copyLayer(t, modelFiles)}, files, ociattest.MapOptions{}, "a symbolic link: it would make lib32"},
		{"a hard link with an absolute target", []imgLayer{busyboxBase(t), gzLayer(t, hard("bin/cat", "/bin/busybox")), copyLayer(t, modelFiles)}, files, ociattest.MapOptions{}, "absolute path"},

		// Names.
		{"an absolute name", []imgLayer{busyboxBase(t), gzLayer(t, reg("/models/config.json", cfg))}, files, ociattest.MapOptions{}, "absolute path"},
		{"a model file named with ./", []imgLayer{busyboxBase(t), gzLayer(t, dir("./models/"), reg("./models/config.json", cfg))}, files, ociattest.MapOptions{}, "leading ./"},
		{"a name that climbs with ..", []imgLayer{busyboxBase(t), gzLayer(t, reg("tmp/../models/config.json", cfg))}, files, ociattest.MapOptions{}, "climbs out"},
		{"a name with a double slash", []imgLayer{busyboxBase(t), gzLayer(t, reg("models//config.json", cfg))}, files, ociattest.MapOptions{}, "not a clean path"},
		{"a file name with a trailing slash", []imgLayer{busyboxBase(t), {gz(renamed(tarOf(t, []ent{reg("models/config.jsonX", cfg)}), "models/config.jsonX", "models/config.json/")), ociLayerGzip, nil}}, files, ociattest.MapOptions{}, "ends in /"},
		{"a model root that is not clean", modelcar(t), files, ociattest.MapOptions{ModelRoot: "models/../etc"}, "not a clean directory path"},

		// Layers and their bytes.
		{"a layer with files in and outside the model root", []imgLayer{busyboxBase(t), copyLayer(t, modelFiles, reg("etc/hosts", "x"))}, files, ociattest.MapOptions{}, "holds files in the model root models/ and 1 entries outside it"},
		{"two gzip members split at an entry", []imgLayer{busyboxBase(t), multi()}, files, ociattest.MapOptions{}, "without tar's end-of-archive marker"},
		{"a second gzip member after the archive", []imgLayer{busyboxBase(t), afterArchive}, files, ociattest.MapOptions{}, "more than one gzip member"},
		{"gzip bytes under an uncompressed type", []imgLayer{busyboxBase(t), {copyLayer(t, modelFiles).blob, ociLayerTar, nil}}, files, ociattest.MapOptions{}, "start with a gzip header"},
		{"plain bytes under a gzip type", []imgLayer{busyboxBase(t), {tarOf(t, []ent{reg("models/config.json", cfg)}), ociLayerGzip, nil}}, files, ociattest.MapOptions{}, "are not a gzip stream"},
		{"a zstd layer", []imgLayer{busyboxBase(t), {[]byte{0x28, 0xb5, 0x2f, 0xfd}, "application/vnd.oci.image.layer.v1.tar+zstd", nil}}, files, ociattest.MapOptions{}, "zstd"},
		{"a Docker uncompressed layer", []imgLayer{busyboxBase(t), {tarOf(t, []ent{dir("x/")}), "application/vnd.docker.image.rootfs.diff.tar", nil}}, files, ociattest.MapOptions{}, "KServe's oci+fetch skips"},
		{"a raw model layer among image layers", []imgLayer{busyboxBase(t), {[]byte("weights"), "application/vnd.cncf.model.weight.v1.raw", nil}}, files, ociattest.MapOptions{}, "raw model layer, in an image of tar layers"},
		{"a layer with URLs", []imgLayer{{busyboxBase(t).blob, ociLayerGzip, []string{"https://elsewhere.example/blob"}}, copyLayer(t, modelFiles)}, files, ociattest.MapOptions{}, "names URLs"},
		{"a device file in the model root", modelcar(t, gzLayer(t, ent{name: "models/null", kind: tar.TypeChar})), files, ociattest.MapOptions{}, "a character device at models/null"},
		{"an overlay whiteout device on a model file", modelcar(t, gzLayer(t, ent{name: "models/config.json", kind: tar.TypeChar})), files, ociattest.MapOptions{}, "a character device at models/config.json"},
		{"a FIFO above the model root", []imgLayer{gzLayer(t, ent{name: "opt", kind: tar.TypeFifo}), gzLayer(t, dir("opt/models/"), reg("opt/models/w", "w"))}, fileIdentity("w", []byte("w")), ociattest.MapOptions{ModelRoot: "opt/models"}, "a FIFO at opt"},
		{"an overlay attribute", []imgLayer{busyboxBase(t), gzLayer(t, ent{name: "models/", kind: tar.TypeDir, pax: map[string]string{"SCHILY.xattr.trusted.overlay.opaque": "y"}}), copyLayer(t, modelFiles)}, files, ociattest.MapOptions{}, "overlayfs attribute"},
		{"bytes after the archive", []imgLayer{busyboxBase(t), {append(tarOf(t, []ent{dir("x/")}), 1), ociLayerTar, nil}, copyLayer(t, modelFiles)}, files, ociattest.MapOptions{}, "data follows the end-of-archive marker"},
		{"a corrupt gzip stream", []imgLayer{busyboxBase(t), {func() []byte { b := copyLayer(t, modelFiles).blob; b[len(b)-8] ^= 0xff; return b }(), ociLayerGzip, nil}}, files, ociattest.MapOptions{}, "does not decompress"},

		// Bounds.
		{"a decompression bomb", []imgLayer{bomb, copyLayer(t, modelFiles)}, files, ociattest.MapOptions{MaxRatio: 8, MinBudget: 1 << 20}, "past the 8:1 bound"},
		{"too many entries", modelcar(t), files, ociattest.MapOptions{MaxEntries: 10}, "more than 10 entries"},
		{"too many layers", modelcar(t), files, ociattest.MapOptions{MaxLayers: 2}, "over the 2 Socair maps"},
		{"no layers", nil, files, ociattest.MapOptions{}, "no layers"},
	}
	for _, c := range cases {
		_, err := mapImage(t, c.layers, c.a, c.o)
		if !errors.Is(err, ociattest.ErrNotBound) {
			t.Errorf("%s: %v, want ErrNotBound", c.name, err)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %q does not say %q", c.name, err, c.want)
		}
	}
}
