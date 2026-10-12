package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Repo is one repository on a registry: what every operation acts on.
type Repo struct {
	c    *Client
	ref  Reference
	base string // scheme://api-host
}

// Repo returns the repository ref names.
func (c *Client) Repo(ref Reference) *Repo {
	return &Repo{c: c, ref: ref, base: baseURL(ref.apiHost())}
}

func (r *Repo) request(method, path string, push bool) request {
	scope := "repository:" + r.ref.Repository + ":pull"
	if push {
		scope += ",push"
	}
	return request{
		method:  method,
		url:     r.base + "/v2/" + r.ref.Repository + path,
		header:  http.Header{},
		scope:   scope,
		host:    r.ref.apiHost(),
		regName: r.ref.Registry,
	}
}

// manifestAccept is every manifest type this client reads.
var manifestAccept = strings.Join([]string{MediaTypeImageManifest, MediaTypeImageIndex, MediaTypeDockerManifest, MediaTypeDockerList}, ", ")

// Fetched is a manifest as the registry served it, its digest computed from
// the bytes.
type Fetched struct {
	Descriptor Descriptor
	Bytes      []byte
	etag       string
}

// Manifest fetches the manifest a tag or digest names. The digest is
// computed from the bytes received, never taken from a header: a digest
// reference must match it, and a Docker-Content-Digest header that
// disagrees with it is an error.
func (r *Repo) Manifest(ctx context.Context, reference string) (*Fetched, error) {
	return r.manifest(ctx, reference, false)
}

func (r *Repo) manifest(ctx context.Context, reference string, push bool) (*Fetched, error) {
	rq := r.request(http.MethodGet, "/manifests/"+reference, push)
	rq.header.Set("Accept", manifestAccept)
	resp, err := r.c.do(ctx, rq)
	if err != nil {
		return nil, fmt.Errorf("fetch manifest %s: %w", reference, redact(err))
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		return nil, r.c.statusError(rq, resp)
	}
	b, err := readLimited(resp.Body, MaxManifest)
	if err != nil {
		return nil, fmt.Errorf("manifest %s: %w", reference, err)
	}
	dig := Digest(b)
	if strings.Contains(reference, ":") && reference != dig {
		return nil, fmt.Errorf("the registry served manifest %s for %s", dig, reference)
	}
	if h := resp.Header.Get("Docker-Content-Digest"); strings.HasPrefix(h, "sha256:") && h != dig {
		return nil, fmt.Errorf("the registry says manifest %s is %s, but its bytes hash to %s", reference, h, dig)
	}
	mt := mediaTypeOf(resp.Header.Get("Content-Type"), b)
	return &Fetched{Descriptor: Descriptor{MediaType: mt, Digest: dig, Size: int64(len(b))}, Bytes: b, etag: resp.Header.Get("ETag")}, nil
}

// mediaTypeOf takes a manifest's media type from its own mediaType field,
// which is what its digest covers, and the Content-Type header only when
// the field is absent.
func mediaTypeOf(contentType string, b []byte) string {
	var probe struct {
		MediaType string `json:"mediaType"`
	}
	if json.Unmarshal(b, &probe) == nil && probe.MediaType != "" {
		return probe.MediaType
	}
	ct, _, _ := strings.Cut(contentType, ";")
	return strings.TrimSpace(ct)
}

// Blob fetches a blob of at most max bytes and checks it against its digest.
// A redirect to a storage service is followed without credentials.
func (r *Repo) Blob(ctx context.Context, digest string, max int64) ([]byte, error) {
	if err := ValidDigest(digest); err != nil {
		return nil, err
	}
	rq := r.request(http.MethodGet, "/blobs/"+digest, false)
	resp, err := r.c.do(ctx, rq)
	if err != nil {
		return nil, fmt.Errorf("fetch blob %s: %w", digest, redact(err))
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		return nil, r.c.statusError(rq, resp)
	}
	b, err := readLimited(resp.Body, max)
	if err != nil {
		return nil, fmt.Errorf("blob %s: %w", digest, err)
	}
	if got := Digest(b); got != digest {
		return nil, fmt.Errorf("blob %s: the registry served bytes that hash to %s", digest, got)
	}
	return b, nil
}

// PushBlob uploads data unless the registry already holds it (a HEAD), with
// a POST that opens an upload and a PUT that completes it.
func (r *Repo) PushBlob(ctx context.Context, data []byte) (Descriptor, error) {
	dig := Digest(data)
	desc := Descriptor{Digest: dig, Size: int64(len(data))}
	head := r.request(http.MethodHead, "/blobs/"+dig, true)
	resp, err := r.c.do(ctx, head)
	if err != nil {
		return desc, fmt.Errorf("check blob %s: %w", dig, redact(err))
	}
	drain(resp)
	if resp.StatusCode == http.StatusOK {
		return desc, nil
	}
	post := r.request(http.MethodPost, "/blobs/uploads/", true)
	resp, err = r.c.do(ctx, post)
	if err != nil {
		return desc, fmt.Errorf("open upload: %w", redact(err))
	}
	if resp.StatusCode != http.StatusAccepted {
		defer drain(resp)
		return desc, r.c.statusError(post, resp)
	}
	loc, err := resp.Request.URL.Parse(resp.Header.Get("Location"))
	drain(resp)
	if err != nil || resp.Header.Get("Location") == "" {
		return desc, errors.New("the registry opened an upload with no usable Location")
	}
	q := loc.Query()
	q.Set("digest", dig)
	loc.RawQuery = q.Encode()
	put := r.request(http.MethodPut, "", true)
	put.url = loc.String()
	put.body = data
	put.header.Set("Content-Type", "application/octet-stream")
	resp, err = r.c.do(ctx, put)
	if err != nil {
		return desc, fmt.Errorf("upload blob %s: %w", dig, redact(err))
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusCreated {
		return desc, r.c.statusError(put, resp)
	}
	return desc, nil
}

// PushManifest puts a manifest under a tag or its digest and returns the
// OCI-Subject header, which a registry with the referrers API sets when the
// manifest has a subject.
func (r *Repo) PushManifest(ctx context.Context, reference, mediaType string, data []byte) (string, error) {
	put := r.request(http.MethodPut, "/manifests/"+reference, true)
	put.body = data
	put.header.Set("Content-Type", mediaType)
	resp, err := r.c.do(ctx, put)
	if err != nil {
		return "", fmt.Errorf("push manifest %s: %w", reference, redact(err))
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusCreated {
		return "", r.c.statusError(put, resp)
	}
	if h := resp.Header.Get("Docker-Content-Digest"); strings.HasPrefix(h, "sha256:") && h != Digest(data) {
		return "", fmt.Errorf("the registry stored manifest %s as %s", Digest(data), h)
	}
	return resp.Header.Get("OCI-Subject"), nil
}

// Referrers lists the manifests whose subject is digest, of artifactType
// when it is set. It asks the referrers API first; a 404 means the registry
// lacks it, and the referrers tag schema's index is read instead (a 404 there
// is no referrers). Via says which answered. The list is filtered here too,
// as a registry may not apply the filter.
func (r *Repo) Referrers(ctx context.Context, digest, artifactType string) (list []Descriptor, via string, err error) {
	if err := ValidDigest(digest); err != nil {
		return nil, "", err
	}
	rq := r.request(http.MethodGet, "/referrers/"+digest, false)
	if artifactType != "" {
		rq.url += "?artifactType=" + url.QueryEscape(artifactType)
	}
	rq.header.Set("Accept", MediaTypeImageIndex)
	var all []Descriptor
	for page := 0; ; page++ {
		if page >= 100 {
			return nil, "", errors.New("referrers: more than 100 pages")
		}
		resp, err := r.c.do(ctx, rq)
		if err != nil {
			return nil, "", fmt.Errorf("list referrers: %w", redact(err))
		}
		if resp.StatusCode == http.StatusNotFound && page == 0 {
			drain(resp)
			return r.referrersByTag(ctx, digest, artifactType)
		}
		if resp.StatusCode != http.StatusOK {
			defer drain(resp)
			return nil, "", r.c.statusError(rq, resp)
		}
		b, err := readLimited(resp.Body, MaxManifest)
		link := resp.Header.Get("Link")
		reqURL := resp.Request.URL
		drain(resp)
		if err != nil {
			return nil, "", fmt.Errorf("referrers: %w", err)
		}
		var idx Index
		if err := json.Unmarshal(b, &idx); err != nil {
			return nil, "", fmt.Errorf("referrers: the response is not an image index: %w", err)
		}
		all = append(all, idx.Manifests...)
		next := nextLink(link)
		if next == "" {
			break
		}
		nu, err := reqURL.Parse(next)
		if err != nil || !strings.EqualFold(nu.Host, reqURL.Host) {
			return nil, "", fmt.Errorf("referrers: the next page link %q leaves the registry", next)
		}
		rq.url = nu.String()
	}
	return filter(all, artifactType), "referrers API", nil
}

func (r *Repo) referrersByTag(ctx context.Context, digest, artifactType string) ([]Descriptor, string, error) {
	tag := ReferrersTag(digest)
	via := "referrers tag " + tag
	f, err := r.Manifest(ctx, tag)
	if IsNotFound(err) {
		return nil, via, nil
	}
	if err != nil {
		return nil, via, err
	}
	idx, err := asIndex(f, tag)
	if err != nil {
		return nil, via, err
	}
	return filter(idx.Manifests, artifactType), via, nil
}

func asIndex(f *Fetched, tag string) (Index, error) {
	var idx Index
	if f.Descriptor.MediaType != MediaTypeImageIndex {
		return idx, fmt.Errorf("tag %s holds a %q, not the referrers image index", tag, f.Descriptor.MediaType)
	}
	if err := json.Unmarshal(f.Bytes, &idx); err != nil {
		return idx, fmt.Errorf("tag %s: %w", tag, err)
	}
	return idx, nil
}

func filter(list []Descriptor, artifactType string) []Descriptor {
	if artifactType == "" {
		return list
	}
	var out []Descriptor
	for _, d := range list {
		if d.ArtifactType == artifactType {
			out = append(out, d)
		}
	}
	return out
}

// nextLink returns the target of a Link header's rel="next" entry.
func nextLink(h string) string {
	for _, part := range strings.Split(h, ",") {
		target, params, ok := strings.Cut(part, ";")
		if !ok {
			continue
		}
		if !strings.Contains(strings.ReplaceAll(params, " ", ""), `rel="next"`) && !strings.Contains(params, "rel=next") {
			continue
		}
		target = strings.TrimSpace(target)
		if strings.HasPrefix(target, "<") && strings.HasSuffix(target, ">") {
			return target[1 : len(target)-1]
		}
	}
	return ""
}

// PushReferrer pushes m, which must have a subject, by its digest. A
// registry with the referrers API says so with OCI-Subject. Without it, the
// descriptor is added to the index under the referrers tag schema's tag,
// which is read, appended to, and pushed back; a conditional push (If-Match
// on the index's ETag) is retried when another client changed it first.
// Via says which path was taken.
func (r *Repo) PushReferrer(ctx context.Context, m Manifest) (Descriptor, string, error) {
	if m.Subject == nil {
		return Descriptor{}, "", errors.New("a referrer needs a subject")
	}
	m.SchemaVersion, m.MediaType = 2, MediaTypeImageManifest
	data, err := json.Marshal(m)
	if err != nil {
		return Descriptor{}, "", err
	}
	if len(data) > MaxManifest {
		return Descriptor{}, "", fmt.Errorf("the referrer manifest is %d bytes, over the %d a registry must accept", len(data), MaxManifest)
	}
	desc := Descriptor{MediaType: MediaTypeImageManifest, Digest: Digest(data), Size: int64(len(data)), ArtifactType: m.ArtifactType, Annotations: m.Annotations}
	if desc.ArtifactType == "" {
		desc.ArtifactType = m.Config.MediaType
	}
	subj, err := r.PushManifest(ctx, desc.Digest, MediaTypeImageManifest, data)
	if err != nil {
		return desc, "", err
	}
	if subj != "" {
		return desc, "referrers API", nil
	}
	tag := ReferrersTag(m.Subject.Digest)
	for try := 0; try < 3; try++ {
		idx := Index{SchemaVersion: 2, MediaType: MediaTypeImageIndex, Manifests: []Descriptor{}}
		etag := ""
		f, err := r.manifest(ctx, tag, true)
		switch {
		case IsNotFound(err):
		case err != nil:
			return desc, "", err
		default:
			if idx, err = asIndex(f, tag); err != nil {
				return desc, "", err
			}
			etag = f.etag
		}
		for _, d := range idx.Manifests {
			if d.Digest == desc.Digest {
				return desc, "referrers tag " + tag, nil
			}
		}
		idx.Manifests = append(idx.Manifests, desc)
		b, err := json.Marshal(idx)
		if err != nil {
			return desc, "", err
		}
		put := r.request(http.MethodPut, "/manifests/"+tag, true)
		put.body = b
		put.header.Set("Content-Type", MediaTypeImageIndex)
		if etag != "" {
			put.header.Set("If-Match", etag)
		}
		resp, err := r.c.do(ctx, put)
		if err != nil {
			return desc, "", fmt.Errorf("push referrers index %s: %w", tag, redact(err))
		}
		code := resp.StatusCode
		if code == http.StatusCreated {
			drain(resp)
			return desc, "referrers tag " + tag, nil
		}
		if code != http.StatusPreconditionFailed {
			defer drain(resp)
			return desc, "", r.c.statusError(put, resp)
		}
		drain(resp)
	}
	return desc, "", fmt.Errorf("the referrers index %s kept changing under this push; try again", tag)
}
