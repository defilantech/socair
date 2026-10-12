// Package registrytest is an in-process OCI registry for tests: the subset of
// the distribution spec v1.1 the registry client uses (blob HEAD, GET, and
// POST-then-PUT upload; manifest GET, HEAD, and PUT by tag or digest; the
// referrers API, which can be switched off to exercise the referrers tag
// schema), with optional Basic or bearer-token authentication and a blob
// redirect to a second host.
package registrytest

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// Auth selects how the registry authenticates.
type Auth int

const (
	// NoAuth serves anyone.
	NoAuth Auth = iota
	// Basic asks for HTTP Basic with User and Password.
	Basic
	// Bearer answers with a Bearer challenge naming the registry's own
	// /token realm, which grants a token for User and Password (or an
	// anonymous pull-only token when AnonymousPull is set).
	Bearer
)

// Options configure a registry.
type Options struct {
	// NoReferrersAPI makes /referrers/ answer 404, as a registry without the
	// referrers API does, and manifest PUTs set no OCI-Subject.
	NoReferrersAPI bool
	Auth           Auth
	User, Password string
	// AnonymousPull lets a bearer token request without credentials read.
	AnonymousPull bool
	// RedirectBlobs serves blob GETs by redirecting to a second server on the
	// same host name at another port, which records any Authorization header
	// it is sent. net/http alone would forward the registry's token there.
	RedirectBlobs bool
}

// Request is one request the registry saw.
type Request struct {
	Method, Path, Authorization string
}

// Registry is a running test registry.
type Registry struct {
	*httptest.Server
	// Host is the registry's host:port, for a reference.
	Host string
	opt  Options

	mu        sync.Mutex
	blobs     map[string][]byte
	manifests map[string]stored // "<repo>@<digest>" -> manifest
	tags      map[string]string // "<repo>:<tag>" -> digest
	uploads   map[string]bool
	log       []Request
	cdnAuth   []string
	tokens    map[string]string // token -> scope granted
}

type stored struct {
	mediaType string
	data      []byte
}

// New starts a registry, closed when the test ends.
func New(t testing.TB, o Options) *Registry {
	t.Helper()
	r := &Registry{opt: o, blobs: map[string][]byte{}, manifests: map[string]stored{}, tags: map[string]string{},
		uploads: map[string]bool{}, tokens: map[string]string{}}
	var cdn *httptest.Server
	if o.RedirectBlobs {
		cdn = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
			r.mu.Lock()
			if a := q.Header.Get("Authorization"); a != "" {
				r.cdnAuth = append(r.cdnAuth, a)
			}
			b, ok := r.blobs[strings.TrimPrefix(q.URL.Path, "/cdn/")]
			r.mu.Unlock()
			if !ok {
				http.NotFound(w, q)
				return
			}
			w.Write(b)
		}))
		t.Cleanup(cdn.Close)
	}
	r.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) { r.serve(w, q, cdn) }))
	t.Cleanup(r.Server.Close)
	r.Host = strings.TrimPrefix(r.Server.URL, "http://")
	return r
}

// Requests returns every request seen so far.
func (r *Registry) Requests() []Request {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Request(nil), r.log...)
}

// CDNAuthorization returns every Authorization header the blob redirect
// target was sent. It should stay empty.
func (r *Registry) CDNAuthorization() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.cdnAuth...)
}

func digest(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// PutBlob stores a blob directly, without the upload protocol.
func (r *Registry) PutBlob(b []byte) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	d := digest(b)
	r.blobs[d] = append([]byte(nil), b...)
	return d
}

// PutManifest stores a manifest directly under its digest and, when tag is
// set, the tag. It returns the digest.
func (r *Registry) PutManifest(repo, tag, mediaType string, b []byte) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	d := digest(b)
	r.manifests[repo+"@"+d] = stored{mediaType, append([]byte(nil), b...)}
	if tag != "" {
		r.tags[repo+":"+tag] = d
	}
	return d
}

// SetTag points a tag at a digest the registry holds.
func (r *Registry) SetTag(repo, tag, d string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tags[repo+":"+tag] = d
}

// ManifestBytes returns a stored manifest.
func (r *Registry) ManifestBytes(repo, d string) ([]byte, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	m, ok := r.manifests[repo+"@"+d]
	return m.data, ok
}

// Tag returns the digest a tag names.
func (r *Registry) Tag(repo, tag string) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.tags[repo+":"+tag]
	return d, ok
}

// split finds the repository name and the rest of a /v2/ path: the name
// may hold slashes, so the operation keyword is found from the right.
func split(p string) (repo, op, rest string, ok bool) {
	p = strings.TrimPrefix(p, "/v2/")
	for _, kw := range []string{"/blobs/uploads/", "/blobs/", "/manifests/", "/referrers/"} {
		if i := strings.LastIndex(p, kw); i > 0 {
			return p[:i], strings.Trim(kw, "/"), p[i+len(kw):], true
		}
	}
	return "", "", "", false
}

func (r *Registry) serve(w http.ResponseWriter, q *http.Request, cdn *httptest.Server) {
	r.mu.Lock()
	r.log = append(r.log, Request{Method: q.Method, Path: q.URL.Path, Authorization: q.Header.Get("Authorization")})
	r.mu.Unlock()
	if q.URL.Path == "/token" {
		r.token(w, q)
		return
	}
	if q.URL.Path == "/v2/" {
		w.WriteHeader(http.StatusOK)
		return
	}
	repo, op, rest, ok := split(q.URL.Path)
	if !ok {
		http.NotFound(w, q)
		return
	}
	push := q.Method == http.MethodPut || q.Method == http.MethodPost || q.Method == http.MethodPatch
	if !r.authorized(w, q, repo, push) {
		return
	}
	switch {
	case op == "blobs/uploads":
		r.upload(w, q, repo, rest)
	case op == "blobs":
		r.blob(w, q, rest, cdn)
	case op == "manifests":
		r.manifest(w, q, repo, rest)
	case op == "referrers" && q.Method == http.MethodGet:
		r.referrers(w, q, repo, rest)
	default:
		http.Error(w, "unsupported", http.StatusMethodNotAllowed)
	}
}

func (r *Registry) authorized(w http.ResponseWriter, q *http.Request, repo string, push bool) bool {
	action := "pull"
	if push {
		action = "pull,push"
	}
	switch r.opt.Auth {
	case NoAuth:
		return true
	case Basic:
		if u, p, ok := q.BasicAuth(); ok && u == r.opt.User && p == r.opt.Password {
			return true
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="registrytest"`)
	case Bearer:
		tok, ok := strings.CutPrefix(q.Header.Get("Authorization"), "Bearer ")
		r.mu.Lock()
		granted := r.tokens[tok]
		r.mu.Unlock()
		if ok && (granted == "repository:"+repo+":pull,push" || (!push && strings.HasPrefix(granted, "repository:"+repo+":pull"))) {
			return true
		}
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s/token",service="registrytest",scope="repository:%s:%s"`, r.Server.URL, repo, action))
	}
	writeErr(w, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
	return false
}

func (r *Registry) token(w http.ResponseWriter, q *http.Request) {
	scope := q.URL.Query().Get("scope")
	u, p, hasCred := q.BasicAuth()
	switch {
	case hasCred && u == r.opt.User && p == r.opt.Password:
	case !hasCred && r.opt.AnonymousPull && strings.HasSuffix(scope, ":pull"):
	default:
		writeErr(w, http.StatusUnauthorized, "UNAUTHORIZED", "bad credentials")
		return
	}
	buf := make([]byte, 16)
	rand.Read(buf)
	tok := hex.EncodeToString(buf)
	r.mu.Lock()
	r.tokens[tok] = scope
	r.mu.Unlock()
	json.NewEncoder(w).Encode(map[string]string{"token": tok})
}

func (r *Registry) upload(w http.ResponseWriter, q *http.Request, repo, id string) {
	switch q.Method {
	case http.MethodPost:
		buf := make([]byte, 8)
		rand.Read(buf)
		id := hex.EncodeToString(buf)
		r.mu.Lock()
		r.uploads[id] = true
		r.mu.Unlock()
		// A relative Location, which the spec allows.
		w.Header().Set("Location", "/v2/"+repo+"/blobs/uploads/"+id+"?state=opaque")
		w.WriteHeader(http.StatusAccepted)
	case http.MethodPut:
		r.mu.Lock()
		open := r.uploads[id]
		r.mu.Unlock()
		if !open || q.URL.Query().Get("state") != "opaque" {
			writeErr(w, http.StatusNotFound, "BLOB_UPLOAD_UNKNOWN", "no such upload")
			return
		}
		b, _ := io.ReadAll(q.Body)
		if d := q.URL.Query().Get("digest"); d != digest(b) {
			writeErr(w, http.StatusBadRequest, "DIGEST_INVALID", "digest mismatch")
			return
		}
		r.PutBlob(b)
		w.Header().Set("Location", "/v2/"+repo+"/blobs/"+digest(b))
		w.WriteHeader(http.StatusCreated)
	default:
		http.Error(w, "unsupported", http.StatusMethodNotAllowed)
	}
}

func (r *Registry) blob(w http.ResponseWriter, q *http.Request, d string, cdn *httptest.Server) {
	r.mu.Lock()
	b, ok := r.blobs[d]
	r.mu.Unlock()
	if !ok {
		writeErr(w, http.StatusNotFound, "BLOB_UNKNOWN", "blob unknown")
		return
	}
	if q.Method == http.MethodGet && cdn != nil {
		http.Redirect(w, q, cdn.URL+"/cdn/"+d+"?sig=secret", http.StatusTemporaryRedirect)
		return
	}
	w.Header().Set("Docker-Content-Digest", d)
	w.Header().Set("Content-Length", fmt.Sprint(len(b)))
	if q.Method == http.MethodGet {
		w.Write(b)
	}
}

func (r *Registry) manifest(w http.ResponseWriter, q *http.Request, repo, ref string) {
	switch q.Method {
	case http.MethodGet, http.MethodHead:
		r.mu.Lock()
		d := ref
		if !strings.HasPrefix(ref, "sha256:") {
			d = r.tags[repo+":"+ref]
		}
		m, ok := r.manifests[repo+"@"+d]
		r.mu.Unlock()
		if !ok {
			writeErr(w, http.StatusNotFound, "MANIFEST_UNKNOWN", "manifest unknown")
			return
		}
		w.Header().Set("Content-Type", m.mediaType)
		w.Header().Set("Docker-Content-Digest", d)
		w.Header().Set("ETag", `"`+d+`"`)
		if q.Method == http.MethodGet {
			w.Write(m.data)
		}
	case http.MethodPut:
		b, _ := io.ReadAll(q.Body)
		d := digest(b)
		if strings.HasPrefix(ref, "sha256:") && ref != d {
			writeErr(w, http.StatusBadRequest, "DIGEST_INVALID", "digest mismatch")
			return
		}
		tag := ""
		if !strings.HasPrefix(ref, "sha256:") {
			tag = ref
			if m := q.Header.Get("If-Match"); m != "" {
				r.mu.Lock()
				cur := r.tags[repo+":"+tag]
				r.mu.Unlock()
				if m != `"`+cur+`"` {
					writeErr(w, http.StatusPreconditionFailed, "PRECONDITION", "changed")
					return
				}
			}
		}
		var probe struct {
			Subject *struct {
				Digest string `json:"digest"`
			} `json:"subject"`
		}
		json.Unmarshal(b, &probe)
		r.PutManifest(repo, tag, q.Header.Get("Content-Type"), b)
		if probe.Subject != nil && !r.opt.NoReferrersAPI {
			w.Header().Set("OCI-Subject", probe.Subject.Digest)
		}
		w.Header().Set("Docker-Content-Digest", d)
		w.Header().Set("Location", "/v2/"+repo+"/manifests/"+d)
		w.WriteHeader(http.StatusCreated)
	default:
		http.Error(w, "unsupported", http.StatusMethodNotAllowed)
	}
}

func (r *Registry) referrers(w http.ResponseWriter, q *http.Request, repo, d string) {
	if r.opt.NoReferrersAPI {
		writeErr(w, http.StatusNotFound, "NOT_FOUND", "no referrers API")
		return
	}
	want := q.URL.Query().Get("artifactType")
	type desc struct {
		MediaType    string            `json:"mediaType"`
		ArtifactType string            `json:"artifactType,omitempty"`
		Digest       string            `json:"digest"`
		Size         int               `json:"size"`
		Annotations  map[string]string `json:"annotations,omitempty"`
	}
	list := []desc{}
	r.mu.Lock()
	for key, m := range r.manifests {
		if !strings.HasPrefix(key, repo+"@") {
			continue
		}
		var man struct {
			MediaType    string `json:"mediaType"`
			ArtifactType string `json:"artifactType"`
			Config       struct {
				MediaType string `json:"mediaType"`
			} `json:"config"`
			Subject *struct {
				Digest string `json:"digest"`
			} `json:"subject"`
			Annotations map[string]string `json:"annotations"`
		}
		if json.Unmarshal(m.data, &man) != nil || man.Subject == nil || man.Subject.Digest != d {
			continue
		}
		at := man.ArtifactType
		if at == "" {
			at = man.Config.MediaType
		}
		if want != "" && at != want {
			continue
		}
		list = append(list, desc{MediaType: m.mediaType, ArtifactType: at, Digest: digest(m.data), Size: len(m.data), Annotations: man.Annotations})
	}
	r.mu.Unlock()
	if want != "" {
		w.Header().Set("OCI-Filters-Applied", "artifactType")
	}
	w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
	json.NewEncoder(w).Encode(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": list})
}

func writeErr(w http.ResponseWriter, code int, ecode, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]any{"errors": []map[string]string{{"code": ecode, "message": msg}}})
}

// BasicCred is the Authorization value for a user and password, for tests
// that check what was sent.
func BasicCred(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}
