package ociattest_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/ociattest"
	"github.com/defilantech/socair/internal/registry"
	"github.com/defilantech/socair/internal/registry/registrytest"
	"github.com/defilantech/socair/internal/report"
)

func modes(t *testing.T, f func(t *testing.T, o registrytest.Options)) {
	for _, noAPI := range []bool{false, true} {
		name := "referrers API"
		if noAPI {
			name = "referrers tag schema"
		}
		t.Run(name, func(t *testing.T) { f(t, registrytest.Options{NoReferrersAPI: noAPI}) })
	}
}

func TestAttachAndVerifyAFile(t *testing.T) {
	modes(t, func(t *testing.T, o registrytest.Options) {
		hermetic(t)
		srv := registrytest.New(t, o)
		gguf, d := fileFixture(t)
		k := newKey(t, "Acme ML Platform")
		env := sign(t, d, k)
		ref, md := pushArtifact(t, srv, "models/tiny", "q4", []layer{{gguf, "application/vnd.docker.ai.gguf.v3", "tiny.gguf"}}, nil)

		a, err := ociattest.Attach(ctx, client(), ref, env, attachOpts(k))
		if err != nil {
			t.Fatalf("Attach: %v", err)
		}
		if a.Artifact.Digest != md || a.Binding.Artifact.Digest != md {
			t.Errorf("attached to %s, binding for %s; want %s", a.Artifact.Digest, a.Binding.Artifact.Digest, md)
		}
		if a.Binding.Attestation.PromotionState != d.PromotionAuthorization.State || a.Binding.Artifact.Match != ociattest.MatchFile {
			t.Errorf("binding = %+v", a.Binding)
		}
		if !strings.Contains(a.Via, "referrers") || !strings.Contains(a.BundleVia, "referrers") {
			t.Errorf("via %q / %q", a.Via, a.BundleVia)
		}

		res, err := ociattest.Verify(ctx, client(), ref, ociattest.VerifyOptions{Trusted: k.ring})
		if err != nil {
			t.Fatalf("Verify: %v (%+v)", err, res)
		}
		v := res.Verified()
		if len(v) != 1 {
			t.Fatalf("%d verified, want 1", len(v))
		}
		f := v[0]
		if f.Binding.Subject != md || f.Attestation.SHA256 != d.Artifact.SHA256 || f.Match.Kind != ociattest.MatchFile {
			t.Errorf("found %+v", f)
		}
		if f.Issuer != "Acme ML Platform" {
			t.Errorf("issuer %q", f.Issuer)
		}
		if f.Bundle == nil || f.Bundle.Digest != a.Bundle.Digest {
			t.Errorf("the Sigstore bundle copy was not found: %+v", f.Bundle)
		}
		if res.Via != a.Via {
			t.Errorf("listed via %q, pushed via %q", res.Via, a.Via)
		}
	})
}

func TestAttachAndVerifyAModelDirectory(t *testing.T) {
	modes(t, func(t *testing.T, o registrytest.Options) {
		hermetic(t)
		srv := registrytest.New(t, o)
		files, d := dirFixture(t)
		k := newKey(t, "")
		ref, md := pushArtifact(t, srv, "models/dir", "v1", dirLayers(files), nil)
		if _, err := ociattest.Attach(ctx, client(), ref, sign(t, d, k), attachOpts(k)); err != nil {
			t.Fatalf("Attach: %v", err)
		}
		pinned, _ := registry.ParseReference(srv.Host + "/models/dir@" + md)
		res, err := ociattest.Verify(ctx, client(), pinned, ociattest.VerifyOptions{Trusted: k.ring})
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		f := res.Verified()[0]
		if f.Match.Kind != ociattest.MatchDirectory || len(f.Match.Layers) != len(files) {
			t.Errorf("match %+v", f.Match)
		}
	})
}

// TestAttachRefusesLayersThatDoNotCarryTheBytes: an artifact whose layer is
// another file is refused, and nothing is pushed.
func TestAttachRefusesLayersThatDoNotCarryTheBytes(t *testing.T) {
	hermetic(t)
	srv := registrytest.New(t, registrytest.Options{})
	gguf, d := fileFixture(t)
	k := newKey(t, "")
	other := append([]byte(nil), gguf...)
	other[len(other)-1] ^= 1
	ref, md := pushArtifact(t, srv, "models/tiny", "q4", []layer{{other, "application/vnd.docker.ai.gguf.v3", ""}}, nil)
	before := len(srv.Requests())
	_, err := ociattest.Attach(ctx, client(), ref, sign(t, d, k), attachOpts(k))
	if !errors.Is(err, ociattest.ErrNotBound) {
		t.Fatalf("Attach = %v, want ErrNotBound", err)
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

func TestAttachRefusesAnAttestationThatDoesNotVerify(t *testing.T) {
	hermetic(t)
	srv := registrytest.New(t, registrytest.Options{})
	gguf, d := fileFixture(t)
	k, stranger := newKey(t, ""), newKey(t, "")
	ref, _ := pushArtifact(t, srv, "models/tiny", "q4", []layer{{gguf, "application/vnd.docker.ai.gguf.v3", ""}}, nil)
	o := attachOpts(k)
	o.Trusted = stranger.ring
	if _, err := ociattest.Attach(ctx, client(), ref, sign(t, d, k), o); !errors.Is(err, attest.ErrVerify) {
		t.Fatalf("Attach with an untrusted signer = %v, want ErrVerify", err)
	}
}

// attached pushes a file artifact, attaches its attestation, and returns
// the pieces a tampering test needs.
type fixture struct {
	srv  *registrytest.Registry
	ref  registry.Reference
	md   string
	k    keys
	doc  report.Document
	env  []byte
	gguf []byte
	att  *ociattest.Attached
}

func attached(t *testing.T, o registrytest.Options) fixture {
	t.Helper()
	hermetic(t)
	srv := registrytest.New(t, o)
	gguf, d := fileFixture(t)
	k := newKey(t, "")
	env := sign(t, d, k)
	ref, md := pushArtifact(t, srv, "models/tiny", "q4", []layer{{gguf, "application/vnd.docker.ai.gguf.v3", ""}}, nil)
	a, err := ociattest.Attach(ctx, client(), ref, env, attachOpts(k))
	if err != nil {
		t.Fatal(err)
	}
	return fixture{srv, ref, md, k, d, env, gguf, a}
}

func (f fixture) referrer(t *testing.T) registry.Manifest {
	t.Helper()
	b, ok := f.srv.ManifestBytes(f.ref.Repository, f.att.Referrer.Digest)
	if !ok {
		t.Fatal("referrer not stored")
	}
	var m registry.Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func (f fixture) blob(t *testing.T, d string) []byte {
	t.Helper()
	b, err := client().Repo(f.ref).Blob(ctx, d, registry.MaxBlob)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// pushReferrer pushes m as a referrer of subject through the client, so the
// registry lists it for that subject.
func pushReferrer(t *testing.T, ref registry.Reference, m registry.Manifest) registry.Descriptor {
	t.Helper()
	d, _, err := client().Repo(ref).PushReferrer(ctx, m)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func verifyFails(t *testing.T, ref registry.Reference, ring attest.Keyring, want string) {
	t.Helper()
	res, err := ociattest.Verify(ctx, client(), ref, ociattest.VerifyOptions{Trusted: ring})
	if !errors.Is(err, ociattest.ErrNoAttestation) {
		t.Fatalf("Verify = %v, want ErrNoAttestation", err)
	}
	for _, f := range res.Found {
		if f.Err != nil && strings.Contains(f.Err.Error(), want) {
			return
		}
	}
	var got []string
	for _, f := range res.Found {
		got = append(got, f.Err.Error())
	}
	t.Fatalf("no referrer failed for %q; reasons: %v", want, got)
}

// secondArtifact pushes an artifact that carries the same bytes as the
// fixture under another manifest digest (another annotation), so the
// attestation's bytes match it and only the binding tells them apart.
func (f fixture) secondArtifact(t *testing.T) (registry.Reference, string) {
	t.Helper()
	return pushArtifact(t, f.srv, "models/tiny", "other", []layer{{f.gguf, "application/vnd.docker.ai.gguf.v3", ""}},
		map[string]string{"org.opencontainers.image.description": "same bytes, another manifest"})
}

// TestVerifyRefusesABindingForAnotherArtifact is the issue's falsification:
// a referrer whose signed subject digest is another artifact's must not
// verify, even when that artifact carries the same bytes and the referrer
// is listed for this one. Falsification: drop the binding subject check in
// checkReferrer and this verifies.
func TestVerifyRefusesABindingForAnotherArtifact(t *testing.T) {
	modes(t, func(t *testing.T, o registrytest.Options) {
		f := attached(t, o)
		ref2, md2 := f.secondArtifact(t)
		m := f.referrer(t)
		art, err := client().Repo(ref2).Manifest(ctx, md2)
		if err != nil {
			t.Fatal(err)
		}
		m.Subject = &registry.Descriptor{MediaType: art.Descriptor.MediaType, Digest: md2, Size: art.Descriptor.Size}
		m.Annotations = map[string]string{"copied": "from " + f.md}
		pushReferrer(t, ref2, m)
		verifyFails(t, ref2, f.k.ring, "the binding is for artifact "+f.md)
	})
}

// TestVerifyRefusesAReferrerWhoseSubjectDiffers: a referrer listed for this
// artifact whose own subject field names another must not verify, even when
// the binding inside is this artifact's. Falsification: drop the referrer
// subject check in checkReferrer and this verifies.
func TestVerifyRefusesAReferrerWhoseSubjectDiffers(t *testing.T) {
	f := attached(t, registrytest.Options{NoReferrersAPI: true})
	ref2, md2 := f.secondArtifact(t)
	// A binding signed for the second artifact, carried in a referrer whose
	// subject is the first, listed under the second's referrers tag.
	a2, err := ociattest.Attach(ctx, client(), ref2, f.env, attachOpts(f.k))
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := f.srv.ManifestBytes(ref2.Repository, a2.Referrer.Digest)
	var m registry.Manifest
	json.Unmarshal(b2, &m)
	first, _ := f.srv.ManifestBytes(f.ref.Repository, f.md)
	m.Subject = &registry.Descriptor{MediaType: registry.MediaTypeImageManifest, Digest: f.md, Size: int64(len(first))}
	mb, _ := json.Marshal(m)
	moved := f.srv.PutManifest(ref2.Repository, "", registry.MediaTypeImageManifest, mb)
	idx := registry.Index{SchemaVersion: 2, MediaType: registry.MediaTypeImageIndex, Manifests: []registry.Descriptor{
		{MediaType: registry.MediaTypeImageManifest, ArtifactType: ociattest.ArtifactType, Digest: moved, Size: int64(len(mb))}}}
	ib, _ := json.Marshal(idx)
	f.srv.PutManifest(ref2.Repository, registry.ReferrersTag(md2), registry.MediaTypeImageIndex, ib)
	verifyFails(t, ref2, f.k.ring, "the referrer's subject is "+f.md)
}

func TestVerifyRefusesATamperedEnvelope(t *testing.T) {
	for _, which := range []string{ociattest.BindingPredicateType, attest.PredicateType} {
		t.Run(which, func(t *testing.T) {
			f := attached(t, registrytest.Options{})
			m := f.referrer(t)
			for i, l := range m.Layers {
				raw := f.blob(t, l.Digest)
				if ociattest.PredicateTypeOf(raw) != which {
					continue
				}
				var e attest.Envelope
				json.Unmarshal(raw, &e)
				payload, _ := base64.StdEncoding.DecodeString(e.Payload)
				payload = []byte(strings.Replace(string(payload), `"withheld"`, `"authorized"`, 1))
				e.Payload = base64.StdEncoding.EncodeToString(payload)
				tampered, _ := json.Marshal(e)
				m.Layers[i].Digest, m.Layers[i].Size = f.srv.PutBlob(tampered), int64(len(tampered))
			}
			// Only the tampered referrer is listed.
			mb, _ := json.Marshal(m)
			d := f.srv.PutManifest(f.ref.Repository, "", registry.MediaTypeImageManifest, mb)
			res, _ := ociattest.Verify(ctx, client(), f.ref, ociattest.VerifyOptions{Trusted: f.k.ring})
			for _, found := range res.Found {
				if found.Referrer.Digest == d {
					if found.Err == nil || !strings.Contains(found.Err.Error(), "verif") {
						t.Fatalf("a tampered %s verified: %v", which, found.Err)
					}
					return
				}
			}
			t.Fatal("the tampered referrer was not listed")
		})
	}
}

// TestVerifyRefusesASwappedAttestation: the binding names its attestation
// by the hash of the envelope's bytes. The same signed envelope, re-encoded,
// still verifies on its own, but it is not the one the binding was signed
// for. Falsification: drop the attestation hash check in checkReferrer.
func TestVerifyRefusesASwappedAttestation(t *testing.T) {
	f := attached(t, registrytest.Options{})
	m := f.referrer(t)
	for i, l := range m.Layers {
		raw := f.blob(t, l.Digest)
		if ociattest.PredicateTypeOf(raw) != attest.PredicateType {
			continue
		}
		var e attest.Envelope
		json.Unmarshal(raw, &e)
		compact, _ := json.Marshal(e)
		if _, err := attest.Verify(compact, f.k.ring); err != nil {
			t.Fatalf("the re-encoded envelope should still verify on its own: %v", err)
		}
		m.Layers[i].Digest, m.Layers[i].Size = f.srv.PutBlob(compact), int64(len(compact))
	}
	mb, _ := json.Marshal(m)
	d := f.srv.PutManifest(f.ref.Repository, "", registry.MediaTypeImageManifest, mb)
	res, _ := ociattest.Verify(ctx, client(), f.ref, ociattest.VerifyOptions{Trusted: f.k.ring})
	for _, found := range res.Found {
		if found.Referrer.Digest == d {
			if found.Err == nil || !strings.Contains(found.Err.Error(), "the binding names attestation") {
				t.Fatalf("a swapped attestation = %v", found.Err)
			}
			return
		}
	}
	t.Fatal("the swapped referrer was not listed")
}

func TestVerifyRefusesAnUntrustedKey(t *testing.T) {
	f := attached(t, registrytest.Options{})
	verifyFails(t, f.ref, newKey(t, "").ring, "not trusted")
}

// TestVerifyMatchesTheLayersItself: a binding signed for an artifact whose
// layers do not carry the attested bytes does not verify, though attach
// would never sign one. Falsification: drop MatchLayers from checkReferrer
// and this verifies.
func TestVerifyMatchesTheLayersItself(t *testing.T) {
	f := attached(t, registrytest.Options{})
	other := append([]byte(nil), f.gguf...)
	other[0] ^= 1
	ref2, md2 := pushArtifact(t, f.srv, "models/tiny", "wrong", []layer{{other, "application/vnd.docker.ai.gguf.v3", ""}}, nil)
	b := f.att.Binding
	b.Artifact.Digest = md2
	benv, err := ociattest.SignBinding(b, f.k.key)
	if err != nil {
		t.Fatal(err)
	}
	m := f.referrer(t)
	art, _ := client().Repo(ref2).Manifest(ctx, md2)
	m.Subject = &art.Descriptor
	m.Subject.Annotations = nil
	for i, l := range m.Layers {
		if ociattest.PredicateTypeOf(f.blob(t, l.Digest)) == ociattest.BindingPredicateType {
			m.Layers[i].Digest, m.Layers[i].Size = f.srv.PutBlob(benv), int64(len(benv))
		}
	}
	pushReferrer(t, ref2, m)
	verifyFails(t, ref2, f.k.ring, ociattest.ErrNotBound.Error())
}

// TestVerifyRefusesABindingThatMisstatesTheAttestation: the binding carries
// the promotion state for an admission policy; one that says authorized over
// a withheld attestation must not verify. Falsification: drop agrees.
func TestVerifyRefusesABindingThatMisstatesTheAttestation(t *testing.T) {
	f := attached(t, registrytest.Options{})
	if f.doc.PromotionAuthorization.State != report.StateWithheld {
		t.Fatalf("fixture is %s, want withheld", f.doc.PromotionAuthorization.State)
	}
	b := f.att.Binding
	b.Attestation.PromotionState = report.StateAuthorized
	benv, _ := ociattest.SignBinding(b, f.k.key)
	m := f.referrer(t)
	for i, l := range m.Layers {
		if ociattest.PredicateTypeOf(f.blob(t, l.Digest)) == ociattest.BindingPredicateType {
			m.Layers[i].Digest, m.Layers[i].Size = f.srv.PutBlob(benv), int64(len(benv))
		}
	}
	mb, _ := json.Marshal(m)
	f.srv.PutManifest(f.ref.Repository, "", registry.MediaTypeImageManifest, mb)
	res, err := ociattest.Verify(ctx, client(), f.ref, ociattest.VerifyOptions{Trusted: f.k.ring})
	if err != nil {
		t.Fatal(err) // the original still verifies
	}
	for _, found := range res.Found {
		if found.Referrer.Digest == registry.Digest(mb) {
			if found.Err == nil || !strings.Contains(found.Err.Error(), "promotion_state") {
				t.Fatalf("a binding that misstates the state = %v", found.Err)
			}
			return
		}
	}
	t.Fatal("the misstating referrer was not listed")
}

func TestAttachAConditionalAttestation(t *testing.T) {
	hermetic(t)
	srv := registrytest.New(t, registrytest.Options{})
	gguf, d := fileFixture(t)
	k, acceptor := newKey(t, ""), newKey(t, "")
	v, err := attest.Verify(sign(t, d, k), k.ring)
	if err != nil {
		t.Fatal(err)
	}
	acc, err := attest.Accept(v, acceptor.key, "Jane Doe, CISO", time.Now().Add(24*time.Hour), "reviewed", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cd, err := attest.Conditional(v, acc, acceptor.ring, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	env := sign(t, cd, k)
	ref, _ := pushArtifact(t, srv, "models/tiny", "q4", []layer{{gguf, "application/vnd.docker.ai.gguf.v3", ""}}, nil)
	o := attachOpts(k)
	o.Now = nil
	if _, err := ociattest.Attach(ctx, client(), ref, env, o); err == nil || !strings.Contains(err.Error(), "--acceptors") {
		t.Fatalf("a conditional attach without acceptor keys = %v", err)
	}
	o.Acceptors = k.ring // the wrong keys
	if _, err := ociattest.Attach(ctx, client(), ref, env, o); !errors.Is(err, attest.ErrVerify) {
		t.Fatalf("a conditional attach whose acceptance does not verify = %v", err)
	}
	o.Acceptors = acceptor.ring
	a, err := ociattest.Attach(ctx, client(), ref, env, o)
	if err != nil {
		t.Fatal(err)
	}
	if a.Binding.Attestation.PromotionState != report.StateAuthorizedWithConditions || a.Binding.Attestation.AcceptedBy != "Jane Doe, CISO" {
		t.Errorf("binding %+v", a.Binding.Attestation)
	}
	res, err := ociattest.Verify(ctx, client(), ref, ociattest.VerifyOptions{Trusted: k.ring, Acceptors: acceptor.ring})
	if err != nil || res.Verified()[0].Acceptance == nil {
		t.Fatalf("Verify with acceptor keys = %v", err)
	}
}

func TestAttachRefusesAnUnsignedAcceptance(t *testing.T) {
	hermetic(t)
	srv := registrytest.New(t, registrytest.Options{})
	gguf, d := fileFixture(t)
	var gaps []string
	for _, c := range d.Checks {
		if c.Status == report.StatusNotTested {
			gaps = append(gaps, c.Name)
		}
	}
	d.PromotionAuthorization = report.PromotionAuthorization{State: report.StateAuthorizedWithConditions, Authorized: true,
		Level: "Tier 1 only", AcceptedBy: "chris", AcceptedSurfaces: gaps,
		AcceptanceExpires: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
	k := newKey(t, "")
	env, err := attest.Sign(d, k.key)
	if err != nil {
		t.Fatalf("a conditional fixture named at scan time: %v", err)
	}
	ref, _ := pushArtifact(t, srv, "models/tiny", "q4", []layer{{gguf, "application/vnd.docker.ai.gguf.v3", ""}}, nil)
	o := attachOpts(k)
	o.Acceptors = k.ring
	if _, err := ociattest.Attach(ctx, client(), ref, env, o); err == nil || !strings.Contains(err.Error(), "unsigned acceptance") {
		t.Fatalf("Attach of an unsigned acceptance = %v", err)
	}
}

func TestEgressDeniedRefusesAttach(t *testing.T) {
	hermetic(t)
	srv := registrytest.New(t, registrytest.Options{})
	gguf, d := fileFixture(t)
	k := newKey(t, "")
	ref, _ := pushArtifact(t, srv, "models/tiny", "q4", []layer{{gguf, "application/vnd.docker.ai.gguf.v3", ""}}, nil)
	t.Setenv("SOCAIR_EGRESS", "deny")
	if _, err := ociattest.Attach(ctx, client(), ref, sign(t, d, k), attachOpts(k)); !errors.Is(err, registry.ErrEgressDenied) {
		t.Fatalf("Attach under SOCAIR_EGRESS=deny = %v", err)
	}
	if n := len(srv.Requests()); n != 0 {
		t.Errorf("%d request(s) reached the registry", n)
	}
}

func TestSigstoreBundleCarriesTheBindingSignature(t *testing.T) {
	f := attached(t, registrytest.Options{})
	b, ok := f.srv.ManifestBytes(f.ref.Repository, f.att.Bundle.Digest)
	if !ok {
		t.Fatal("bundle referrer not stored")
	}
	var m registry.Manifest
	json.Unmarshal(b, &m)
	if m.ArtifactType != ociattest.BundleMediaType || len(m.Layers) != 1 || m.Layers[0].MediaType != ociattest.BundleMediaType ||
		m.Subject == nil || m.Subject.Digest != f.md || m.Annotations[ociattest.AnnotationBundlePredicateType] != ociattest.BindingPredicateType ||
		m.Annotations[ociattest.AnnotationBundleContent] != "dsse-envelope" || m.Config.MediaType != registry.MediaTypeEmpty {
		t.Fatalf("bundle referrer %s", b)
	}
	raw := f.blob(t, m.Layers[0].Digest)
	var bundle map[string]any
	json.Unmarshal(raw, &bundle)
	env := bundle["dsseEnvelope"].(map[string]any)
	sig := env["signatures"].([]any)[0].(map[string]any)
	if _, has := sig["keyid"]; has {
		t.Errorf("the bundle's DSSE signature keeps a key id: %v", sig)
	}
	if vm := bundle["verificationMaterial"].(map[string]any); vm["publicKey"] == nil || len(vm) != 1 {
		t.Errorf("verification material %v, want a public key and nothing else", vm)
	}
	payload, _ := base64.StdEncoding.DecodeString(env["payload"].(string))
	var st struct {
		Subject []struct {
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
		PredicateType string `json:"predicateType"`
	}
	json.Unmarshal(payload, &st)
	if st.PredicateType != ociattest.BindingPredicateType || len(st.Subject) != 1 || "sha256:"+st.Subject[0].Digest["sha256"] != f.md {
		t.Errorf("the bundle's statement is %+v, want the binding about %s", st, f.md)
	}
}
