package registry_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defilantech/socair/internal/registry"
	"github.com/defilantech/socair/internal/registry/registrytest"
)

func TestOpenBlobStreamsAndChecks(t *testing.T) {
	t.Setenv("SOCAIR_EGRESS", "")
	srv := registrytest.New(t, registrytest.Options{RedirectBlobs: true})
	blob := bytes.Repeat([]byte("layer bytes "), 10000)
	d := srv.PutBlob(blob)
	repo := registry.New(registry.Options{}).Repo(ref(t, srv, "m", "v1"))
	ctx := context.Background()

	rc, err := repo.OpenBlob(ctx, d, int64(len(blob)))
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(rc)
	rc.Close()
	if err != nil || !bytes.Equal(got, blob) {
		t.Fatalf("read %d bytes, %v", len(got), err)
	}

	// A registry that says the blob's length refuses another size at once,
	// before a byte is read.
	direct := registrytest.New(t, registrytest.Options{})
	dd := direct.PutBlob(blob)
	if _, err := registry.New(registry.Options{}).Repo(ref(t, direct, "m", "v1")).OpenBlob(ctx, dd, int64(len(blob))-1); err == nil ||
		!strings.Contains(err.Error(), "the registry sends") {
		t.Errorf("a blob whose length is not the manifest's = %v", err)
	}

	// The manifest's size, not the registry's, is the size: refused when
	// the response says its length, else at the end.
	rc, err = repo.OpenBlob(ctx, d, int64(len(blob))+1)
	if err == nil {
		_, err = io.ReadAll(rc)
		rc.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "the manifest gives") {
		t.Errorf("a blob of another size = %v", err)
	}

	// Other bytes of the same length: the read that reaches the end fails.
	other := bytes.ToUpper(blob)
	srv.ServeAs(d, other)
	rc, _ = repo.OpenBlob(ctx, d, int64(len(blob)))
	if _, err := io.ReadAll(rc); err == nil || !strings.Contains(err.Error(), "the registry served bytes that hash to") {
		t.Errorf("other bytes = %v", err)
	}
	if auth := srv.CDNAuthorization(); len(auth) != 0 {
		t.Errorf("the redirect target was sent %v", auth)
	}
}

// blobServer serves one blob path with a handler, for what registrytest does
// not do: a body with no length, a body that stalls.
func blobServer(t *testing.T, h http.HandlerFunc) registry.Reference {
	t.Helper()
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	r, err := registry.ParseReference(strings.TrimPrefix(s.URL, "http://") + "/m:v1")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestOpenBlobBoundsTheBody(t *testing.T) {
	t.Setenv("SOCAIR_EGRESS", "")
	blob := []byte("0123456789")
	d := registry.Digest(blob)
	ctx := context.Background()
	chunked := func(body []byte, stall time.Duration) http.HandlerFunc {
		return func(w http.ResponseWriter, q *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write(body[:len(body)/2])
			w.(http.Flusher).Flush()
			time.Sleep(stall)
			w.Write(body[len(body)/2:])
		}
	}
	for name, c := range map[string]struct {
		h     http.HandlerFunc
		stall time.Duration
		want  string
	}{
		"more bytes than the manifest gives": {chunked(append(blob, '!'), 0), 0, "more than the 10 bytes"},
		"fewer bytes":                        {chunked(blob[:9], 0), 0, "sent 9 bytes, the manifest gives 10"},
		"a body that stalls":                 {chunked(blob, time.Second), 100 * time.Millisecond, "no data for 100ms after 5 of 10 bytes"},
	} {
		t.Run(name, func(t *testing.T) {
			repo := registry.New(registry.Options{Stall: c.stall}).Repo(blobServer(t, c.h))
			rc, err := repo.OpenBlob(ctx, d, int64(len(blob)))
			if err != nil {
				t.Fatal(err)
			}
			defer rc.Close()
			if _, err := io.ReadAll(rc); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("= %v, want %q", err, c.want)
			}
		})
	}
}

func TestOpenBlobUnderEgressDeny(t *testing.T) {
	srv := registrytest.New(t, registrytest.Options{})
	d := srv.PutBlob([]byte("x"))
	t.Setenv("SOCAIR_EGRESS", "deny")
	_, err := registry.New(registry.Options{}).Repo(ref(t, srv, "m", "v1")).OpenBlob(context.Background(), d, 1)
	if !errors.Is(err, registry.ErrEgressDenied) {
		t.Fatalf("OpenBlob under SOCAIR_EGRESS=deny = %v", err)
	}
}
