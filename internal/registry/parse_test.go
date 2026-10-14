package registry

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseChallenge(t *testing.T) {
	c, ok := parseChallenge(`Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:samalba/my-app:pull,push"`)
	if !ok || c.scheme != "bearer" || c.params["realm"] != "https://auth.docker.io/token" ||
		c.params["service"] != "registry.docker.io" || c.params["scope"] != "repository:samalba/my-app:pull,push" {
		t.Errorf("bearer = %+v %v", c, ok)
	}
	c, ok = parseChallenge(`Basic realm="Registry \"x\""`)
	if !ok || c.scheme != "basic" || c.params["realm"] != `Registry "x"` {
		t.Errorf("basic = %+v %v", c, ok)
	}
	for _, h := range []string{"", "Negotiate abc", "Digest realm=x"} {
		if _, ok := parseChallenge(h); ok {
			t.Errorf("%q accepted", h)
		}
	}
}

func FuzzParseChallenge(f *testing.F) {
	f.Add(`Bearer realm="https://r/token",service="s",scope="repository:a:pull"`)
	f.Add(`Basic realm="x`)
	f.Add(`Bearer realm=,=,"`)
	f.Fuzz(func(t *testing.T, h string) { parseChallenge(h) })
}

func FuzzParseReference(f *testing.F) {
	f.Add("ghcr.io/org/model:v1")
	f.Add("localhost:5000/m@sha256:" + strings.Repeat("a", 64))
	f.Add("[::1]:5000/m:t")
	f.Fuzz(func(t *testing.T, s string) {
		r, err := ParseReference(s)
		if err != nil {
			return
		}
		if r.Registry == "" || r.Repository == "" || (r.Tag == "" && r.Digest == "") {
			t.Fatalf("%q parsed to an incomplete reference %+v", s, r)
		}
		if _, err := ParseReference(r.String()); err != nil {
			t.Fatalf("%q round-trips to %q, which does not parse: %v", s, r.String(), err)
		}
	})
}

func TestNextLink(t *testing.T) {
	for h, want := range map[string]string{
		`</v2/m/referrers/sha256:a?n=1&last=b>; rel="next"`:            "/v2/m/referrers/sha256:a?n=1&last=b",
		`<https://other/x>; rel="prev", </v2/m/referrers/x>; rel=next`: "/v2/m/referrers/x",
		``:                            "",
		`</x>; rel="last"`:            "",
		`no angle; rel="next"`:        "",
		`</y>;   rel = "next"`:        "/y",
		`</z>; title="a"; rel="next"`: "/z",
	} {
		if got := nextLink(h); got != want {
			t.Errorf("nextLink(%q) = %q, want %q", h, got, want)
		}
	}
}

// TestReferrersFollowsPagesOnTheRegistryOnly: a Link to the next page is
// followed on the registry's host, and refused when it leaves it.
func TestReferrersFollowsPagesOnTheRegistryOnly(t *testing.T) {
	t.Setenv("SOCAIR_EGRESS", "")
	d := "sha256:" + strings.Repeat("a", 64)
	page := func(digest string) []byte {
		b, _ := json.Marshal(Index{SchemaVersion: 2, MediaType: MediaTypeImageIndex,
			Manifests: []Descriptor{{MediaType: MediaTypeImageManifest, ArtifactType: "t", Digest: digest, Size: 1}}})
		return b
	}
	leave := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "2" {
			w.Write(page("sha256:" + strings.Repeat("2", 64)))
			return
		}
		next := "</v2/m/referrers/" + d + "?page=2>; rel=\"next\""
		if leave {
			next = "<http://elsewhere.example/v2/m/referrers/" + d + "?page=2>; rel=\"next\""
		}
		w.Header().Set("Link", next)
		w.Write(page("sha256:" + strings.Repeat("1", 64)))
	}))
	defer srv.Close()
	ref, err := ParseReference(strings.TrimPrefix(srv.URL, "http://") + "/m:v1")
	if err != nil {
		t.Fatal(err)
	}
	repo := New(Options{}).Repo(ref)
	list, via, err := repo.Referrers(context.Background(), d, "t")
	if err != nil || len(list) != 2 || via != "referrers API" {
		t.Fatalf("two pages = %+v, %q, %v", list, via, err)
	}
	leave = true
	if _, _, err := repo.Referrers(context.Background(), d, "t"); err == nil || !strings.Contains(err.Error(), "leaves the registry") {
		t.Fatalf("a next page on another host = %v", err)
	}
}
