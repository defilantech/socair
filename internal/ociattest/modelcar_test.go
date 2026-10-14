package ociattest_test

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defilantech/socair/internal/ociattest"
	"github.com/defilantech/socair/internal/registry"
	"github.com/defilantech/socair/internal/registry/registrytest"
)

// modelcarFixture scans a model directory, pushes it as a KServe ModelCar
// image (FROM a busybox-like base, RUN mkdir /models, COPY data/ /models/),
// and attaches the attestation.
type modelcarFixture struct {
	fixture
	files map[string][]byte
}

func attachedModelcar(t *testing.T, o registrytest.Options) modelcarFixture {
	t.Helper()
	hermetic(t)
	srv := registrytest.New(t, o)
	files, d := dirFixture(t)
	k := newKey(t, "")
	env := sign(t, d, k)
	ref, md := pushImage(t, srv, "models/modelcar", "v1", []imgLayer{busyboxBase(t), runLayer(t), copyLayer(t, files)}, "")
	a, err := ociattest.Attach(ctx, client(), ref, env, attachOpts(k))
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	return modelcarFixture{fixture{srv: srv, ref: ref, md: md, k: k, doc: d, env: env, att: a}, files}
}

func TestAttachAndVerifyAModelCarImage(t *testing.T) {
	modes(t, func(t *testing.T, o registrytest.Options) {
		f := attachedModelcar(t, o)
		b := f.att.Binding.Artifact
		if b.Match != ociattest.MatchModelRoot || b.ModelRoot != "models" || b.LayerRules != ociattest.LayerRules || b.Digest != f.md {
			t.Fatalf("binding artifact %+v", b)
		}
		var roles []string
		for _, l := range b.Layers {
			roles = append(roles, l.Role)
		}
		if !slices.Equal(roles, []string{"base", "base", "model"}) || len(b.Layers[2].Files) != len(f.files) {
			t.Errorf("layers %+v", b.Layers)
		}
		res, err := ociattest.Verify(ctx, client(), f.ref, ociattest.VerifyOptions{Trusted: f.k.ring})
		if err != nil {
			t.Fatalf("Verify: %v (%+v)", err, res)
		}
		got := res.Verified()[0]
		if got.Match.Kind != ociattest.MatchModelRoot || got.Match.ModelRoot != "models" || got.Bundle == nil {
			t.Errorf("verified %+v", got)
		}
	})
}

// TestAttachRefusesATamperedModelCar: an image whose model root holds other
// bytes than the attested files is refused, and nothing is pushed.
func TestAttachRefusesATamperedModelCar(t *testing.T) {
	hermetic(t)
	srv := registrytest.New(t, registrytest.Options{})
	files, d := dirFixture(t)
	k := newKey(t, "")
	tampered := map[string][]byte{}
	for p, b := range files {
		tampered[p] = b
	}
	tampered["config.json"] = []byte(`{"model_type":"other"}`)
	ref, md := pushImage(t, srv, "models/modelcar", "bad", []imgLayer{busyboxBase(t), copyLayer(t, tampered)}, "")
	before := len(srv.Requests())
	_, err := ociattest.Attach(ctx, client(), ref, sign(t, d, k), attachOpts(k))
	if !errors.Is(err, ociattest.ErrNotBound) || !strings.Contains(err.Error(), "models/config.json is sha256:") {
		t.Fatalf("Attach = %v", err)
	}
	for _, r := range srv.Requests()[before:] {
		if r.Method != "GET" && r.Method != "HEAD" {
			t.Errorf("a refused attach sent %s %s", r.Method, r.Path)
		}
	}
	if list, _, _ := client().Repo(ref).Referrers(ctx, md, ""); len(list) != 0 {
		t.Errorf("a refused attach left referrers: %+v", list)
	}
}

// TestAttachRefusesALayerServedWithOtherBytes: the registry serves a layer
// whose bytes do not hash to its digest, of the same length and a valid
// archive that would map. The read that reaches the end of the blob fails,
// so nothing read from it is trusted. Falsification: drop the digest check
// from registry.OpenBlob and this attaches.
func TestAttachRefusesALayerServedWithOtherBytes(t *testing.T) {
	hermetic(t)
	srv := registrytest.New(t, registrytest.Options{})
	files, d := dirFixture(t)
	k := newKey(t, "")
	base := imgLayer{tarOf(t, []ent{dir("etc/"), reg("etc/motd", "hello")}), ociLayerTar, nil}
	ref, _ := pushImage(t, srv, "models/modelcar", "v1", []imgLayer{base, copyLayer(t, files)}, "")
	swapped := []byte(strings.Replace(string(base.blob), "hello", "HELLO", 1))
	srv.ServeAs(registry.Digest(base.blob), swapped)
	_, err := ociattest.Attach(ctx, client(), ref, sign(t, d, k), attachOpts(k))
	if err == nil || !strings.Contains(err.Error(), "the registry served bytes that hash to") {
		t.Fatalf("Attach = %v", err)
	}
}

// TestAttachWithAModelRootOnRawLayers: a model root names where an image's
// files are; for raw model layers it means nothing, and is refused rather
// than ignored.
func TestAttachWithAModelRootOnRawLayers(t *testing.T) {
	hermetic(t)
	srv := registrytest.New(t, registrytest.Options{})
	gguf, d := fileFixture(t)
	k := newKey(t, "")
	ref, _ := pushArtifact(t, srv, "models/tiny", "q4", []layer{{gguf, "application/vnd.docker.ai.gguf.v3", ""}}, nil)
	o := attachOpts(k)
	o.Map.ModelRoot = "models"
	if _, err := ociattest.Attach(ctx, client(), ref, sign(t, d, k), o); err == nil || !strings.Contains(err.Error(), "raw model layers") {
		t.Fatalf("Attach = %v", err)
	}
}

// rebind re-signs the fixture's binding after change and pushes it, with the
// original attestation, as another referrer; it returns that referrer's
// manifest digest.
func (f fixture) rebind(t *testing.T, change func(*ociattest.Binding)) string {
	t.Helper()
	b := f.att.Binding
	b.Artifact.Layers = slices.Clone(b.Artifact.Layers)
	change(&b)
	benv, err := ociattest.SignBinding(b, f.k.key)
	if err != nil {
		t.Fatal(err)
	}
	m := f.referrer(t)
	for i, l := range m.Layers {
		if ociattest.PredicateTypeOf(f.blob(t, l.Digest)) == ociattest.BindingPredicateType {
			m.Layers[i].Digest, m.Layers[i].Size = f.srv.PutBlob(benv), int64(len(benv))
		}
	}
	mb, _ := json.Marshal(m)
	return f.srv.PutManifest(f.ref.Repository, "", registry.MediaTypeImageManifest, mb)
}

// verifyReferrerFails verifies the fixture's artifact and checks that the
// referrer d fails for want, while the original still verifies.
func (f fixture) verifyReferrerFails(t *testing.T, d, want string) {
	t.Helper()
	res, err := ociattest.Verify(ctx, client(), f.ref, ociattest.VerifyOptions{Trusted: f.k.ring})
	if err != nil {
		t.Fatal(err)
	}
	for _, found := range res.Found {
		if found.Referrer.Digest == d {
			if found.Err == nil || !strings.Contains(found.Err.Error(), want) {
				t.Fatalf("referrer %s = %v, want %q", d, found.Err, want)
			}
			return
		}
	}
	t.Fatalf("referrer %s was not listed", d)
}

// TestVerifyRefusesAModelRootBindingThatMisstatesItsLayers: verify maps the
// image again, and a binding whose statement of what it covers differs from
// that mapping does not verify. Falsification: drop sameMatch from
// checkReferrer and these verify.
func TestVerifyRefusesAModelRootBindingThatMisstatesItsLayers(t *testing.T) {
	f := attachedModelcar(t, registrytest.Options{})
	for name, c := range map[string]struct {
		change func(*ociattest.Binding)
		want   string
	}{
		"a base layer called a model layer": {func(b *ociattest.Binding) { b.Artifact.Layers[0].Role = ociattest.RoleModel }, "the binding states layer 0"},
		"a file left out":                   {func(b *ociattest.Binding) { b.Artifact.Layers[2].Files = b.Artifact.Layers[2].Files[1:] }, "the binding states layer 2"},
		"a raw match": {func(b *ociattest.Binding) {
			b.Artifact.Match, b.Artifact.ModelRoot, b.Artifact.LayerRules = ociattest.MatchDirectory, "", ""
		}, "the binding states match"},
		"other rules":              {func(b *ociattest.Binding) { b.Artifact.LayerRules = "socair.tar-map/v0" }, "made under layer rules"},
		"a layer left out":         {func(b *ociattest.Binding) { b.Artifact.Layers = b.Artifact.Layers[1:] }, "the binding lists 2 layers"},
		"another root":             {func(b *ociattest.Binding) { b.Artifact.ModelRoot = "opt" }, "no file for attested"},
		"a root that is not clean": {func(b *ociattest.Binding) { b.Artifact.ModelRoot = "models/../etc" }, "not a clean directory path"},
	} {
		t.Run(name, func(t *testing.T) { f.verifyReferrerFails(t, f.rebind(t, c.change), c.want) })
	}
}

// TestVerifyMapsAnImageOncePerAttestation: two referrers of one attestation
// cost one read of each layer.
func TestVerifyMapsAnImageOncePerAttestation(t *testing.T) {
	f := attachedModelcar(t, registrytest.Options{})
	o := attachOpts(f.k)
	o.Now = func() time.Time { return time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC) } // a second, distinct binding
	if _, err := ociattest.Attach(ctx, client(), f.ref, f.env, o); err != nil {
		t.Fatal(err)
	}
	before := len(f.srv.Requests())
	res, err := ociattest.Verify(ctx, client(), f.ref, ociattest.VerifyOptions{Trusted: f.k.ring})
	if err != nil || len(res.Verified()) != 2 {
		t.Fatalf("Verify: %v, %d verified", err, len(res.Verified()))
	}
	gets := map[string]int{}
	for _, r := range f.srv.Requests()[before:] {
		gets[r.Path]++
	}
	for _, l := range f.att.Binding.Artifact.Layers {
		if n := gets["/v2/models/modelcar/blobs/"+l.Digest]; n != 1 {
			t.Errorf("layer %s read %d times", l.Digest, n)
		}
	}
}
