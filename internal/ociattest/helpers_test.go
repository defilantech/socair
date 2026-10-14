package ociattest_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/engine"
	"github.com/defilantech/socair/internal/gguf/gguftest"
	"github.com/defilantech/socair/internal/ociattest"
	"github.com/defilantech/socair/internal/registry"
	"github.com/defilantech/socair/internal/registry/registrytest"
	"github.com/defilantech/socair/internal/report"
	"github.com/defilantech/socair/internal/safetensors/safetensorstest"
)

const (
	modelpackManifest = "application/vnd.cncf.model.manifest.v1+json"
	modelpackConfig   = "application/vnd.cncf.model.config.v1+json"
	weightRaw         = "application/vnd.cncf.model.weight.v1.raw"
	configRaw         = "application/vnd.cncf.model.weight.config.v1.raw"
)

// hermetic clears the scan inputs a developer's environment could set.
func hermetic(t *testing.T) {
	t.Helper()
	for _, k := range []string{"SOCAIR_EGRESS", "SOCAIR_REPO_MIRROR", "SOCAIR_DENYLIST", "SOCAIR_PROVENANCE", "SOCAIR_ACCEPTED_BY",
		"SOCAIR_FEED", "SOCAIR_LICENSE_POLICY", "SOCAIR_TIER2_HELPER", "SOCAIR_PUBLISHER_KEYS", "SOCAIR_OMS_SIGNATURE"} {
		t.Setenv(k, "")
	}
}

type keys struct {
	key  *attest.PrivateKey
	ring attest.Keyring
	pub  string
}

func newKey(t *testing.T, issuer string) keys {
	t.Helper()
	prefix := filepath.Join(t.TempDir(), "k")
	if _, err := attest.GenerateNamedKey(prefix, issuer); err != nil {
		t.Fatal(err)
	}
	k, err := attest.LoadPrivateKey(prefix + ".key")
	if err != nil {
		t.Fatal(err)
	}
	ring, err := attest.LoadKeyring(prefix + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	return keys{k, ring, prefix + ".pub"}
}

// fileFixture writes a small GGUF and scans it.
func fileFixture(t *testing.T) ([]byte, report.Document) {
	t.Helper()
	b := gguftest.BuildGGUF(gguftest.Clean())
	p := filepath.Join(t.TempDir(), "tiny.gguf")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	d, err := engine.Scan(p)
	if err != nil {
		t.Fatal(err)
	}
	return b, *d
}

// dirFixture writes a small model directory and scans it.
func dirFixture(t *testing.T) (map[string][]byte, report.Document) {
	t.Helper()
	files := map[string][]byte{
		"config.json":           []byte(`{"model_type":"llama"}`),
		"model.safetensors":     safetensorstest.Clean(),
		"tokenizer_config.json": []byte(`{"chat_template":"{% for m in messages %}{{ m['content'] }}{% endfor %}"}`),
	}
	dir := filepath.Join(t.TempDir(), "tiny-model")
	for rel, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	d, err := engine.Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	return files, *d
}

func sign(t *testing.T, d report.Document, k keys) []byte {
	t.Helper()
	env, err := attest.Sign(d, k.key)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

type layer struct {
	data      []byte
	mediaType string
	path      string
}

// pushArtifact pushes an artifact built from layers and returns its
// reference, tagged, and its manifest digest.
func pushArtifact(t *testing.T, srv *registrytest.Registry, repoName, tag string, layers []layer, annotations map[string]string) (registry.Reference, string) {
	t.Helper()
	ref, err := registry.ParseReference(srv.Host + "/" + repoName + ":" + tag)
	if err != nil {
		t.Fatal(err)
	}
	var descs []registry.Descriptor
	for _, l := range layers {
		d := registry.Descriptor{MediaType: l.mediaType, Digest: srv.PutBlob(l.data), Size: int64(len(l.data))}
		if l.path != "" {
			d.Annotations = map[string]string{ociattest.AnnotationFilepath: l.path}
		}
		descs = append(descs, d)
	}
	cfg := []byte(`{"descriptor":{"name":"tiny"}}`)
	m := registry.Manifest{SchemaVersion: 2, MediaType: registry.MediaTypeImageManifest, ArtifactType: modelpackManifest,
		Config: registry.Descriptor{MediaType: modelpackConfig, Digest: srv.PutBlob(cfg), Size: int64(len(cfg))}, Layers: descs, Annotations: annotations}
	b, _ := json.Marshal(m)
	return ref, srv.PutManifest(repoName, tag, registry.MediaTypeImageManifest, b)
}

// dirLayers is one raw layer per file of a model directory, at its path.
func dirLayers(files map[string][]byte) []layer {
	var out []layer
	for p, b := range files {
		mt := configRaw
		if filepath.Ext(p) == ".safetensors" {
			mt = weightRaw
		}
		out = append(out, layer{b, mt, p})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out
}

func attachOpts(k keys) ociattest.AttachOptions {
	return ociattest.AttachOptions{Key: k.key, Trusted: k.ring, ToolVersion: "socair test",
		Now: func() time.Time { return time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC) }}
}

func client() *registry.Client { return registry.New(registry.Options{}) }

var ctx = context.Background()
