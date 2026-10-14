package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/gguf/gguftest"
	"github.com/defilantech/socair/internal/registry"
	"github.com/defilantech/socair/internal/registry/registrytest"
)

// TestAttachThenVerifyAnOCIArtifact runs the two commands end to end against
// an in-process registry: attach binds the attestation to the artifact,
// verify <oci-ref> finds and checks it, and verify of a file still reads
// the file.
func TestAttachThenVerifyAnOCIArtifact(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SOCAIR_EGRESS", "")
	t.Setenv("DOCKER_CONFIG", dir) // no credentials
	att, op := withheldAttestation(t, dir)
	srv := registrytest.New(t, registrytest.Options{NoReferrersAPI: true})
	gguf := gguftest.BuildGGUF(gguftest.Clean())
	layer := registry.Descriptor{MediaType: "application/vnd.cncf.model.weight.v1.raw", Digest: srv.PutBlob(gguf), Size: int64(len(gguf)),
		Annotations: map[string]string{"org.cncf.model.filepath": "clean-Q5_K_M.gguf"}}
	cfg := []byte(`{}`)
	m, _ := json.Marshal(registry.Manifest{SchemaVersion: 2, MediaType: registry.MediaTypeImageManifest, ArtifactType: "application/vnd.cncf.model.manifest.v1+json",
		Config: registry.Descriptor{MediaType: "application/vnd.cncf.model.config.v1+json", Digest: srv.PutBlob(cfg), Size: 2}, Layers: []registry.Descriptor{layer}})
	md := srv.PutManifest("models/clean", "q5", registry.MediaTypeImageManifest, m)
	ref := srv.Host + "/models/clean:q5"

	out, err := stdout(t, func() error {
		return attachCmd([]string{ref, "--attestation", att, "--key", op + ".key", "--trusted", op + ".pub"})
	})
	if err != nil {
		t.Fatalf("attach: %v\n%s", err, out)
	}
	for _, want := range []string{"attached to " + srv.Host + "/models/clean:q5@" + md, "promotion withheld", "is the attested file", "referrers tag sha256-", "Sigstore bundle referrer"} {
		if !strings.Contains(out, want) {
			t.Errorf("attach output lacks %q:\n%s", want, out)
		}
	}

	out, err = stdout(t, func() error { return verifyCmd([]string{ref, "--trusted", op + ".pub"}) })
	if err != nil {
		t.Fatalf("verify <oci-ref>: %v\n%s", err, out)
	}
	for _, want := range []string{"1 of 1 Socair attestation(s) verified", "for this manifest digest", "is the attested file", "promotion withheld", "Sigstore bundle copy"} {
		if !strings.Contains(out, want) {
			t.Errorf("verify output lacks %q:\n%s", want, out)
		}
	}

	// Another key's trust list: nothing verifies, and the command fails.
	other := filepath.Join(dir, "other")
	if _, err := stdout(t, func() error { return keyCmd([]string{"gen", "--out", other}) }); err != nil {
		t.Fatal(err)
	}
	out, err = stdout(t, func() error { return verifyCmd([]string{ref, "--trusted", other + ".pub"}) })
	if err == nil || !strings.Contains(out, "0 of 1") {
		t.Errorf("verify under another key = %v\n%s", err, out)
	}

	// An attestation file is still read as a file.
	if out, err := stdout(t, func() error { return verifyCmd([]string{att, "--trusted", op + ".pub"}) }); err != nil || !strings.Contains(out, "verified: issued by") {
		t.Errorf("verify of a file = %v\n%s", err, out)
	}
}

func TestIsOCIRef(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "r.dsse.json")
	os.WriteFile(f, []byte("{}"), 0o600)
	for arg, want := range map[string]bool{
		f:                      false,
		"r.dsse.json":          false,
		"ghcr.io/org/model:v1": true,
		"localhost:5000/m@sha256:" + strings.Repeat("a", 64): true,
		"ghcr.io/org/model": false,
	} {
		if got := isOCIRef(arg); got != want {
			t.Errorf("isOCIRef(%q) = %v, want %v", arg, got, want)
		}
	}
}

// TestAttachThenVerifyAModelCarImage: an image whose tar layers hold the
// attested file under /models (a base layer, and the model's own layer) is
// attached and verified, and both commands say what the binding does not
// cover.
func TestAttachThenVerifyAModelCarImage(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SOCAIR_EGRESS", "")
	t.Setenv("DOCKER_CONFIG", dir)
	att, op := withheldAttestation(t, dir)
	srv := registrytest.New(t, registrytest.Options{})
	layer := func(ents ...[3]string) registry.Descriptor {
		var raw bytes.Buffer
		tw := tar.NewWriter(&raw)
		for _, e := range ents {
			h := &tar.Header{Name: e[0], Typeflag: e[1][0], Mode: 0o755, Size: int64(len(e[2]))}
			tw.WriteHeader(h)
			tw.Write([]byte(e[2]))
		}
		tw.Close()
		var z bytes.Buffer
		zw := gzip.NewWriter(&z)
		zw.Write(raw.Bytes())
		zw.Close()
		return registry.Descriptor{MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Digest: srv.PutBlob(z.Bytes()), Size: int64(z.Len())}
	}
	gguf := string(gguftest.BuildGGUF(gguftest.Clean()))
	base := layer([3]string{"bin/", "5", ""}, [3]string{"bin/sh", "0", "sh"})
	model := layer([3]string{"models/", "5", ""}, [3]string{"models/clean-Q5_K_M.gguf", "0", gguf})
	cfg := []byte(`{"architecture":"amd64","os":"linux"}`)
	m, _ := json.Marshal(registry.Manifest{SchemaVersion: 2, MediaType: registry.MediaTypeImageManifest,
		Config: registry.Descriptor{MediaType: "application/vnd.oci.image.config.v1+json", Digest: srv.PutBlob(cfg), Size: int64(len(cfg))},
		Layers: []registry.Descriptor{base, model}})
	srv.PutManifest("models/modelcar", "v1", registry.MediaTypeImageManifest, m)
	ref := srv.Host + "/models/modelcar:v1"

	out, err := stdout(t, func() error {
		return attachCmd([]string{ref, "--attestation", att, "--key", op + ".key", "--trusted", op + ".pub", "--model-root", "/models"})
	})
	if err != nil {
		t.Fatalf("attach: %v\n%s", err, out)
	}
	for _, want := range []string{"/models holds exactly the attested file(s), 1, from 1 of its 2 layers", "not covered: 1 base layer(s) (2 entries) outside /models", "KServe ModelCar"} {
		if !strings.Contains(out, want) {
			t.Errorf("attach output lacks %q:\n%s", want, out)
		}
	}
	out, err = stdout(t, func() error { return verifyCmd([]string{ref, "--trusted", op + ".pub"}) })
	if err != nil {
		t.Fatalf("verify: %v\n%s", err, out)
	}
	for _, want := range []string{"1 of 1 Socair attestation(s) verified", "/models holds exactly the attested file(s)", "not covered: 1 base layer(s)"} {
		if !strings.Contains(out, want) {
			t.Errorf("verify output lacks %q:\n%s", want, out)
		}
	}
}
