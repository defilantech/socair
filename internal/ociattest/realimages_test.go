package ociattest_test

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/ociattest"
	"github.com/defilantech/socair/internal/registry"
)

// TestRealBaseImages is a real-corpus gate, opt-in:
// SOCAIR_OCI_BASE_CORPUS names OCI image layouts (directories holding
// index.json and blobs/, as `crane pull --format oci` writes), separated by
// the OS list separator. Each image in each layout is used as a base: a
// layer holding a small model under /models is put on top, as COPY data/
// /models/ would, and the image must map. A refusal is a rule a real base
// image trips; record the result in docs/oci.md.
func TestRealBaseImages(t *testing.T) {
	corpus := os.Getenv("SOCAIR_OCI_BASE_CORPUS")
	if corpus == "" {
		t.Skip("set SOCAIR_OCI_BASE_CORPUS to OCI image layouts to map real base images")
	}
	for _, layout := range filepath.SplitList(corpus) {
		for _, m := range layoutManifests(t, layout) {
			blobs := memBlobs{}
			open := func(_ context.Context, l registry.Descriptor) (io.ReadCloser, error) {
				if b, ok := blobs[l.Digest]; ok {
					return io.NopCloser(strings.NewReader(string(b))), nil
				}
				return os.Open(filepath.Join(layout, "blobs", "sha256", registry.Hex(l.Digest)))
			}
			model := copyLayer(t, modelFiles)
			m.Layers = append(m.Layers, registry.Descriptor{MediaType: model.mediaType, Digest: blobs.put(model.blob), Size: int64(len(model.blob))})
			name := filepath.Base(layout)
			got, err := ociattest.MapTarLayers(context.Background(), m, dirIdentity(modelFiles), open, ociattest.MapOptions{})
			if err != nil {
				t.Errorf("%s: %v", name, err)
				continue
			}
			entries := 0
			for _, l := range got.Layers {
				entries += l.Entries
			}
			t.Logf("%s: maps; %d layers, %d entries", name, len(got.Layers), entries)
		}
	}
}

// layoutManifests returns the image manifests of an OCI layout, following
// nested indexes and skipping attestation manifests.
func layoutManifests(t *testing.T, layout string) []registry.Manifest {
	t.Helper()
	read := func(p string, v any) {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, v); err != nil {
			t.Fatal(err)
		}
	}
	var out []registry.Manifest
	var walk func(idx registry.Index)
	walk = func(idx registry.Index) {
		for _, d := range idx.Manifests {
			p := filepath.Join(layout, "blobs", "sha256", registry.Hex(d.Digest))
			switch d.MediaType {
			case registry.MediaTypeImageIndex, registry.MediaTypeDockerList:
				var sub registry.Index
				read(p, &sub)
				walk(sub)
			case registry.MediaTypeImageManifest, registry.MediaTypeDockerManifest:
				if d.Annotations["vnd.docker.reference.type"] == "attestation-manifest" {
					continue
				}
				var m registry.Manifest
				read(p, &m)
				out = append(out, m)
			}
		}
	}
	var idx registry.Index
	read(filepath.Join(layout, "index.json"), &idx)
	walk(idx)
	return out
}
