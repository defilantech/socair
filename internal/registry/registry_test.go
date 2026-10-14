package registry_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/registry"
	"github.com/defilantech/socair/internal/registry/registrytest"
)

func TestParseReference(t *testing.T) {
	t.Setenv("SOCAIR_EGRESS", "")
	dig := "sha256:" + strings.Repeat("a", 64)
	ok := map[string]registry.Reference{
		"ghcr.io/org/model:v1":                       {Registry: "ghcr.io", Repository: "org/model", Tag: "v1"},
		"localhost:5000/m@" + dig:                    {Registry: "localhost:5000", Repository: "m", Digest: dig},
		"registry.example:443/a/b/c:1.0@" + dig:      {Registry: "registry.example:443", Repository: "a/b/c", Tag: "1.0", Digest: dig},
		"docker.io/ai/smollm2:latest":                {Registry: "docker.io", Repository: "ai/smollm2", Tag: "latest"},
		"docker.io/busybox:1":                        {Registry: "docker.io", Repository: "library/busybox", Tag: "1"},
		"127.0.0.1:5000/x_y/z-w:t":                   {Registry: "127.0.0.1:5000", Repository: "x_y/z-w", Tag: "t"},
		"localhost/m:t":                              {Registry: "localhost", Repository: "m", Tag: "t"},
		"[::1]:5000/m:t":                             {Registry: "[::1]:5000", Repository: "m", Tag: "t"},
		"registry.example/models/llama.cpp__q4:v1.0": {Registry: "registry.example", Repository: "models/llama.cpp__q4", Tag: "v1.0"},
	}
	for s, want := range ok {
		got, err := registry.ParseReference(s)
		if err != nil {
			t.Errorf("%s: %v", s, err)
			continue
		}
		if got != want {
			t.Errorf("%s = %+v, want %+v", s, got, want)
		}
	}
	for _, s := range []string{
		"",
		"model:v1",                     // no registry
		"org/model:v1",                 // first component is not a host
		"ghcr.io/org/model",            // no tag or digest: no implicit latest
		"ghcr.io/Org/model:v1",         // uppercase repository
		"ghcr.io/org/model@sha256:abc", // short digest
		"ghcr.io/org/model@sha512:" + strings.Repeat("a", 128),
		"./reports/r.dsse.json",
		"r.dsse.json",
		"reports.d/r.dsse.json", // a file path: no tag or digest
		"ghcr.io/org/model:bad tag",
		"ghcr.io//model:v1",
	} {
		if _, err := registry.ParseReference(s); err == nil {
			t.Errorf("%q parsed as a reference", s)
		}
	}
}

func TestReferrersTag(t *testing.T) {
	d := "sha256:" + strings.Repeat("ab", 32)
	if got := registry.ReferrersTag(d); got != "sha256-"+strings.Repeat("ab", 32) {
		t.Errorf("ReferrersTag = %s", got)
	}
}

func ref(t *testing.T, r *registrytest.Registry, repo, tag string) registry.Reference {
	t.Helper()
	x, err := registry.ParseReference(r.Host + "/" + repo + ":" + tag)
	if err != nil {
		t.Fatal(err)
	}
	return x
}

// pushModel pushes a one-layer artifact and returns its manifest digest.
func pushModel(t *testing.T, repo *registry.Repo, tag string, layer []byte) string {
	t.Helper()
	ctx := context.Background()
	d, err := repo.PushBlob(ctx, layer)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := repo.PushBlob(ctx, registry.EmptyJSON)
	if err != nil {
		t.Fatal(err)
	}
	cfg.MediaType = registry.MediaTypeEmpty
	d.MediaType = "application/vnd.cncf.model.weight.v1.raw"
	m := registry.Manifest{SchemaVersion: 2, MediaType: registry.MediaTypeImageManifest, ArtifactType: "application/vnd.cncf.model.manifest.v1+json",
		Config: cfg, Layers: []registry.Descriptor{d}}
	b, _ := json.Marshal(m)
	if _, err := repo.PushManifest(ctx, tag, registry.MediaTypeImageManifest, b); err != nil {
		t.Fatal(err)
	}
	return registry.Digest(b)
}

func TestPushFetchAndReferrers(t *testing.T) {
	for _, noAPI := range []bool{false, true} {
		t.Run(map[bool]string{false: "referrers API", true: "tag schema fallback"}[noAPI], func(t *testing.T) {
			t.Setenv("SOCAIR_EGRESS", "")
			srv := registrytest.New(t, registrytest.Options{NoReferrersAPI: noAPI})
			c := registry.New(registry.Options{})
			repo := c.Repo(ref(t, srv, "org/model", "v1"))
			ctx := context.Background()
			md := pushModel(t, repo, "v1", []byte("weights"))

			f, err := repo.Manifest(ctx, "v1")
			if err != nil {
				t.Fatal(err)
			}
			if f.Descriptor.Digest != md || f.Descriptor.MediaType != registry.MediaTypeImageManifest {
				t.Fatalf("resolved %+v, want %s", f.Descriptor, md)
			}
			if b, err := repo.Blob(ctx, registry.Digest([]byte("weights")), 100); err != nil || string(b) != "weights" {
				t.Fatalf("Blob = %q, %v", b, err)
			}

			subject := f.Descriptor
			payload, err := repo.PushBlob(ctx, []byte(`{"a":1}`))
			if err != nil {
				t.Fatal(err)
			}
			payload.MediaType = "application/vnd.dsse.envelope.v1+json"
			cfg := registry.EmptyDescriptor()
			referrer := registry.Manifest{ArtifactType: "application/vnd.example+json", Config: cfg, Layers: []registry.Descriptor{payload}, Subject: &subject,
				Annotations: map[string]string{"org.opencontainers.image.created": "2026-10-12T00:00:00Z"}}
			if _, err := repo.PushBlob(ctx, registry.EmptyJSON); err != nil {
				t.Fatal(err)
			}
			desc, via, err := repo.PushReferrer(ctx, referrer)
			if err != nil {
				t.Fatal(err)
			}
			wantVia := "referrers API"
			if noAPI {
				wantVia = "referrers tag " + registry.ReferrersTag(md)
			}
			if via != wantVia {
				t.Errorf("pushed via %q, want %q", via, wantVia)
			}
			// A second push of the same referrer adds no duplicate.
			if _, _, err := repo.PushReferrer(ctx, referrer); err != nil {
				t.Fatal(err)
			}
			list, via, err := repo.Referrers(ctx, md, "application/vnd.example+json")
			if err != nil {
				t.Fatal(err)
			}
			if via != wantVia {
				t.Errorf("listed via %q, want %q", via, wantVia)
			}
			if len(list) != 1 || list[0].Digest != desc.Digest || list[0].ArtifactType != "application/vnd.example+json" {
				t.Fatalf("referrers = %+v, want the one pushed (%s)", list, desc.Digest)
			}
			if list[0].Annotations["org.opencontainers.image.created"] == "" {
				t.Error("the referrer's annotations should be in its descriptor")
			}
			if other, _, err := repo.Referrers(ctx, md, "application/vnd.other+json"); err != nil || len(other) != 0 {
				t.Errorf("a filter for another type returned %+v, %v", other, err)
			}
			// No referrers at all is an empty list, not an error.
			none, _, err := repo.Referrers(ctx, "sha256:"+strings.Repeat("0", 64), "")
			if err != nil || len(none) != 0 {
				t.Errorf("no referrers = %+v, %v", none, err)
			}
		})
	}
}

// TestManifestDigestIsComputed: a registry that serves other bytes for a
// digest, or a Docker-Content-Digest header its bytes do not hash to, is
// caught.
func TestManifestDigestIsComputed(t *testing.T) {
	t.Setenv("SOCAIR_EGRESS", "")
	body := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","layers":[]}`)
	header := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if header != "" {
			w.Header().Set("Docker-Content-Digest", header)
		}
		w.Write(body)
	}))
	defer srv.Close()
	x, err := registry.ParseReference(strings.TrimPrefix(srv.URL, "http://") + "/m:v1")
	if err != nil {
		t.Fatal(err)
	}
	repo := registry.New(registry.Options{}).Repo(x)
	other := "sha256:" + strings.Repeat("1", 64)
	if _, err := repo.Manifest(context.Background(), other); err == nil || !strings.Contains(err.Error(), "served manifest") {
		t.Errorf("bytes for another digest = %v, want a refusal", err)
	}
	header = other
	if _, err := repo.Manifest(context.Background(), "v1"); err == nil || !strings.Contains(err.Error(), "hash to") {
		t.Errorf("a Docker-Content-Digest the bytes do not match = %v, want a refusal", err)
	}
	header = ""
	f, err := repo.Manifest(context.Background(), "v1")
	if err != nil || f.Descriptor.Digest != registry.Digest(body) || f.Descriptor.MediaType != registry.MediaTypeImageManifest {
		t.Errorf("Manifest = %+v, %v", f, err)
	}
}

func TestBearerAuthAndCredentialScope(t *testing.T) {
	t.Setenv("SOCAIR_EGRESS", "")
	srv := registrytest.New(t, registrytest.Options{Auth: registrytest.Bearer, User: "alice", Password: "s3cret", RedirectBlobs: true})
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json")
	os.WriteFile(cfg, []byte(`{"auths":{"`+srv.Host+`":{"auth":"`+b64("alice:s3cret")+`"}}}`), 0o600)
	creds, err := registry.LoadDockerConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c := registry.New(registry.Options{Credentials: creds})
	repo := c.Repo(ref(t, srv, "org/model", "v1"))
	pushModel(t, repo, "v1", []byte("weights"))
	b, err := repo.Blob(context.Background(), registry.Digest([]byte("weights")), 100)
	if err != nil || string(b) != "weights" {
		t.Fatalf("Blob through a redirect = %q, %v", b, err)
	}
	if got := srv.CDNAuthorization(); len(got) != 0 {
		t.Errorf("the blob redirect target on another host received credentials: %v", got)
	}
	sawBasic := false
	for _, r := range srv.Requests() {
		if strings.HasPrefix(r.Authorization, "Basic ") {
			if r.Path != "/token" {
				t.Errorf("the password went to %s %s, not only the token realm", r.Method, r.Path)
			}
			sawBasic = true
		}
	}
	if !sawBasic {
		t.Error("the credential was never sent to the token realm")
	}

	// Without a credential, a push is refused and the error says why.
	anon := registry.New(registry.Options{Credentials: &registry.DockerConfig{}})
	_, err = anon.Repo(ref(t, srv, "org/model", "v1")).PushBlob(context.Background(), []byte("x"))
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("an anonymous push = %v, want a 401 refusal", err)
	}
}

func TestBasicAuth(t *testing.T) {
	t.Setenv("SOCAIR_EGRESS", "")
	srv := registrytest.New(t, registrytest.Options{Auth: registrytest.Basic, User: "bob", Password: "pw"})
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json")
	os.WriteFile(cfg, []byte(`{"auths":{"http://`+srv.Host+`/v2/":{"username":"bob","password":"pw"}}}`), 0o600)
	creds, err := registry.LoadDockerConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	repo := registry.New(registry.Options{Credentials: creds}).Repo(ref(t, srv, "m", "v1"))
	pushModel(t, repo, "v1", []byte("w"))
	if _, err := repo.Manifest(context.Background(), "v1"); err != nil {
		t.Fatal(err)
	}
}

func TestEgressDenied(t *testing.T) {
	srv := registrytest.New(t, registrytest.Options{})
	t.Setenv("SOCAIR_EGRESS", "deny")
	repo := registry.New(registry.Options{}).Repo(ref(t, srv, "m", "v1"))
	_, err := repo.Manifest(context.Background(), "v1")
	if !errors.Is(err, registry.ErrEgressDenied) {
		t.Fatalf("Manifest under SOCAIR_EGRESS=deny = %v", err)
	}
	if n := len(srv.Requests()); n != 0 {
		t.Errorf("%d request(s) reached the registry under SOCAIR_EGRESS=deny", n)
	}
}

func TestDockerConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json")
	os.WriteFile(cfg, []byte(`{
	  "auths": {
	    "https://index.docker.io/v1/": {"auth": "`+b64("hub:pw")+`"},
	    "ghcr.io": {"auth": "`+b64("gh:tok:with:colons")+`"},
	    "quay.io": {"identitytoken": "x"}
	  },
	  "credsStore": "osxkeychain"
	}`), 0o600)
	c, err := registry.LoadDockerConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := c.Lookup("docker.io"); !ok || got.Username != "hub" || got.Password != "pw" {
		t.Errorf("docker.io = %+v %v", got, ok)
	}
	if got, ok := c.Lookup("ghcr.io"); !ok || got.Password != "tok:with:colons" {
		t.Errorf("ghcr.io = %+v %v (a password keeps its colons)", got, ok)
	}
	if _, ok := c.Lookup("quay.io"); ok {
		t.Error("an identity token is not a username and password")
	}
	if !strings.Contains(c.Why("quay.io"), "identity token") || !strings.Contains(c.Why("example.com"), "credential helper") {
		t.Errorf("Why does not explain: %q / %q", c.Why("quay.io"), c.Why("example.com"))
	}
	missing, err := registry.LoadDockerConfig(filepath.Join(dir, "absent.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := missing.Lookup("ghcr.io"); ok {
		t.Error("a missing config holds no credentials")
	}
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
