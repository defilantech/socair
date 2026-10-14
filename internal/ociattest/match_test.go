package ociattest_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/ociattest"
	"github.com/defilantech/socair/internal/registry"
	"github.com/defilantech/socair/internal/report"
)

func hexOf(b string) string { return strings.TrimPrefix(registry.Digest([]byte(b)), "sha256:") }

func desc(body, mediaType string, ann map[string]string) registry.Descriptor {
	return registry.Descriptor{MediaType: mediaType, Digest: registry.Digest([]byte(body)), Size: int64(len(body)), Annotations: ann}
}

func path(p string) map[string]string { return map[string]string{ociattest.AnnotationFilepath: p} }

func TestMatchLayers(t *testing.T) {
	file := report.ArtifactIdentity{FileName: "m.gguf", SHA256: hexOf("weights"), SizeBytes: 7}
	dir := report.ArtifactIdentity{FileName: "tiny", Files: []report.ArtifactFile{
		{Path: "config.json", SHA256: hexOf("{}"), SizeBytes: 2},
		{Path: "sub/model.safetensors", SHA256: hexOf("weights"), SizeBytes: 7},
	}}
	gguf := "application/vnd.docker.ai.gguf.v3"
	raw := "application/vnd.cncf.model.weight.v1.raw"
	cfg := "application/vnd.cncf.model.weight.config.v1.raw"
	manifest := func(layers ...registry.Descriptor) registry.Manifest { return registry.Manifest{Layers: layers} }
	om := registry.MediaTypeImageManifest

	ok := []struct {
		name string
		mt   string
		m    registry.Manifest
		a    report.ArtifactIdentity
		kind string
	}{
		{"one raw GGUF layer", om, manifest(desc("weights", gguf, nil)), file, ociattest.MatchFile},
		{"a Docker manifest", registry.MediaTypeDockerManifest, manifest(desc("weights", gguf, nil)), file, ociattest.MatchFile},
		{"a renamed single file", om, manifest(desc("weights", raw, path("other.gguf"))), file, ociattest.MatchFile},
		{"a KitOps raw layer", om, manifest(desc("weights", "application/vnd.kitops.modelkit.model.v1.raw", nil)), file, ociattest.MatchFile},
		{"a directory", om, manifest(desc("{}", cfg, path("./config.json")), desc("weights", raw, map[string]string{
			ociattest.AnnotationFilepathLegacy: "sub/model.safetensors", ociattest.AnnotationTitle: "sub/model.safetensors"})), dir, ociattest.MatchDirectory},
	}
	for _, c := range ok {
		m, err := ociattest.MatchLayers(c.mt, c.m, c.a)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if m.Kind != c.kind || len(m.Layers) != len(c.m.Layers) {
			t.Errorf("%s: %+v", c.name, m)
		}
	}

	bad := []struct {
		name string
		mt   string
		m    registry.Manifest
		a    report.ArtifactIdentity
		want string
	}{
		{"an index", registry.MediaTypeImageIndex, manifest(), file, "image index"},
		{"no layers", om, manifest(), file, "no layers"},
		{"another file's bytes", om, manifest(desc("other", gguf, nil)), file, "attested file m.gguf is"},
		{"a wrong size", om, manifest(registry.Descriptor{MediaType: gguf, Digest: registry.Digest([]byte("weights")), Size: 8}), file, "8 bytes"},
		{"a tar layer", om, manifest(desc("weights", "application/vnd.cncf.model.weight.v1.tar", nil)), file, "tar archive"},
		{"an image layer", om, manifest(desc("weights", "application/vnd.oci.image.layer.v1.tar+gzip", nil)), file, "compressed"},
		{"a docker image layer", om, manifest(desc("weights", "application/vnd.docker.image.rootfs.diff.tar.gzip", nil)), file, "tar archive"},
		{"a compressed raw layer", om, manifest(desc("weights", "application/vnd.kitops.modelkit.model.v1.raw+zstd", nil)), file, "compressed"},
		{"an unknown type", om, manifest(desc("weights", "application/octet-stream", nil)), file, "not one Socair knows"},
		{"an ORAS default type", om, manifest(desc("weights", "application/vnd.oci.image.layer.v1.tar", nil)), file, "tar archive"},
		{"a sha512 layer", om, manifest(registry.Descriptor{MediaType: gguf, Digest: "sha512:" + strings.Repeat("a", 128), Size: 7}), file, "SHA-256"},
		{"an extra layer beside one file", om, manifest(desc("weights", gguf, nil), desc("MIT", "application/vnd.docker.ai.license", path("LICENSE"))), file, "layer 1 (LICENSE)"},
		{"a directory layer with no path", om, manifest(desc("{}", cfg, path("config.json")), desc("weights", raw, nil)), dir, "names no file path"},
		{"a directory missing a file", om, manifest(desc("{}", cfg, path("config.json"))), dir, "no layer for attested file(s) sub/model.safetensors"},
		{"a directory with an extra file", om, manifest(desc("{}", cfg, path("config.json")), desc("weights", raw, path("sub/model.safetensors")), desc("x", cfg, path("extra.json"))), dir, "extra.json, which the attestation does not list"},
		{"bytes at the wrong path", om, manifest(desc("weights", cfg, path("config.json")), desc("{}", raw, path("sub/model.safetensors"))), dir, "holds config.json as"},
		{"two layers at one path", om, manifest(desc("{}", cfg, path("config.json")), desc("{}", cfg, path("config.json"))), dir, "two layers name config.json"},
		{"a path that leaves the directory", om, manifest(desc("{}", cfg, path("../config.json"))), dir, "leaves the model directory"},
		{"an absolute path", om, manifest(desc("{}", cfg, path("/config.json"))), dir, "not a relative file path"},
		{"annotations that disagree", om, manifest(desc("{}", cfg, map[string]string{ociattest.AnnotationFilepath: "config.json", ociattest.AnnotationTitle: "other.json"})), dir, "two paths"},
	}
	for _, c := range bad {
		_, err := ociattest.MatchLayers(c.mt, c.m, c.a)
		if !errors.Is(err, ociattest.ErrNotBound) {
			t.Errorf("%s: %v, want ErrNotBound", c.name, err)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %q does not say %q", c.name, err, c.want)
		}
	}
}

func TestRawLayerTypesHaveNoArchiveOrCompression(t *testing.T) {
	for _, mt := range ociattest.RawLayerTypes() {
		if strings.Contains(mt, "+") || strings.Contains(mt, ".tar") {
			t.Errorf("%s is listed as raw", mt)
		}
	}
}
