package ociattest_test

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/defilantech/socair/internal/ociattest"
	"github.com/defilantech/socair/internal/registry"
)

// TestRealRegistry pushes a small ModelPack artifact to a real registry,
// attaches its attestation, and verifies it, through the registry's own
// referrers support or its absence. Opt-in, and only for a scratch
// registry: it pushes to it.
//
//	SOCAIR_TEST_REGISTRY=127.0.0.1:5000 go test ./internal/ociattest -run RealRegistry -v
//
// Credentials, when the registry needs them, come from the Docker config.
func TestRealRegistry(t *testing.T) {
	host := os.Getenv("SOCAIR_TEST_REGISTRY")
	if host == "" {
		t.Skip("set SOCAIR_TEST_REGISTRY to a scratch registry's host:port to run")
	}
	hermetic(t)
	creds, err := registry.LoadDockerConfig(registry.DockerConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	c := registry.New(registry.Options{Credentials: creds})
	tag := fmt.Sprintf("t%d", time.Now().UnixNano())
	ref, err := registry.ParseReference(host + "/socair-test/tiny:" + tag)
	if err != nil {
		t.Fatal(err)
	}
	repo := c.Repo(ref)
	gguf, d := fileFixture(t)
	k := newKey(t, "Socair test")

	layer, err := repo.PushBlob(ctx, gguf)
	if err != nil {
		t.Fatal(err)
	}
	layer.MediaType, layer.Annotations = weightRaw, map[string]string{ociattest.AnnotationFilepath: "tiny.gguf"}
	cfgBytes := []byte(`{"descriptor":{"name":"tiny"}}`)
	cfg, err := repo.PushBlob(ctx, cfgBytes)
	if err != nil {
		t.Fatal(err)
	}
	cfg.MediaType = modelpackConfig
	m, _ := json.Marshal(registry.Manifest{SchemaVersion: 2, MediaType: registry.MediaTypeImageManifest, ArtifactType: modelpackManifest,
		Config: cfg, Layers: []registry.Descriptor{layer}})
	if _, err := repo.PushManifest(ctx, tag, registry.MediaTypeImageManifest, m); err != nil {
		t.Fatal(err)
	}

	a, err := ociattest.Attach(ctx, c, ref, sign(t, d, k), attachOpts(k))
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	t.Logf("attached %s: referrer %s via %s, bundle %s via %s", a.Ref, a.Referrer.Digest, a.Via, a.Bundle.Digest, a.BundleVia)
	res, err := ociattest.Verify(ctx, c, ref, ociattest.VerifyOptions{Trusted: k.ring})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if v := res.Verified(); len(v) != 1 || v[0].Bundle == nil || v[0].Binding.Subject != a.Artifact.Digest {
		t.Fatalf("verified %+v", v)
	}
	t.Logf("verified via %s", res.Via)

	// With SOCAIR_TEST_COSIGN set too, cosign must verify the binding there.
	if cosign := os.Getenv("SOCAIR_TEST_COSIGN"); cosign != "" {
		if _, err := runCosign(t, cosign, k.pub, host+"/"+ref.Repository+"@"+a.Artifact.Digest, os.Environ()); err != nil {
			t.Fatalf("cosign verify-attestation on %s: %v", host, err)
		}
	}
}
