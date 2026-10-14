package registry

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// Reference names a manifest in a registry: registry/repository, with a tag,
// a digest, or both (the digest wins).
type Reference struct {
	// Registry is the host[:port] as written, such as ghcr.io or
	// localhost:5000. docker.io names Docker Hub.
	Registry   string
	Repository string
	Tag        string
	Digest     string
}

var (
	pathComponent = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$`)
	tagPattern    = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	hostLabel     = regexp.MustCompile(`^(?:[A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9-]*[A-Za-z0-9])$`)
)

// ParseReference reads registry/repository:tag, registry/repository@digest,
// or both. The registry must be named (a host with a dot or a port, or
// localhost), and a tag or a digest must be given: an attestation is about
// one artifact, so there is no implicit "latest" and no implicit registry.
func ParseReference(s string) (Reference, error) {
	var r Reference
	orig := s
	if strings.ContainsAny(s, " \t\r\n") || s == "" {
		return r, fmt.Errorf("%q is not an OCI reference", orig)
	}
	if name, dig, ok := strings.Cut(s, "@"); ok {
		if err := ValidDigest(dig); err != nil {
			return r, fmt.Errorf("%q: %w", orig, err)
		}
		r.Digest, s = dig, name
	}
	slash := strings.IndexByte(s, '/')
	if slash < 0 {
		return r, fmt.Errorf("%q names no registry: write it as <registry>/<repository>:<tag> or @sha256:<digest>", orig)
	}
	host, rest := s[:slash], s[slash+1:]
	if !isRegistryHost(host) {
		return r, fmt.Errorf("%q names no registry (%q is not a host with a dot or a port, or localhost)", orig, host)
	}
	r.Registry = host
	// A tag follows the last colon after the last slash.
	if i := strings.LastIndexByte(rest, ':'); i > strings.LastIndexByte(rest, '/') {
		r.Tag, rest = rest[i+1:], rest[:i]
		if !tagPattern.MatchString(r.Tag) {
			return r, fmt.Errorf("%q: tag %q is not a valid tag", orig, r.Tag)
		}
	}
	if rest == "" {
		return r, fmt.Errorf("%q names no repository", orig)
	}
	for _, c := range strings.Split(rest, "/") {
		if !pathComponent.MatchString(c) {
			return r, fmt.Errorf("%q: repository component %q is not valid (lowercase letters, digits, and separators)", orig, c)
		}
	}
	if len(host)+1+len(rest) > 255 {
		return r, fmt.Errorf("%q: the name is longer than 255 characters", orig)
	}
	if isDockerHub(host) && !strings.Contains(rest, "/") {
		rest = "library/" + rest
	}
	r.Repository = rest
	if r.Tag == "" && r.Digest == "" {
		return r, fmt.Errorf("%q has no tag or digest: name the artifact exactly, as :<tag> or @sha256:<digest>", orig)
	}
	return r, nil
}

// LooksLikeReference reports whether s parses as a reference, for a caller
// that takes either a file path or a reference.
func LooksLikeReference(s string) bool {
	_, err := ParseReference(s)
	return err == nil
}

func isRegistryHost(h string) bool {
	if h == "localhost" || strings.HasPrefix(h, "localhost:") {
		return validPort(strings.TrimPrefix(strings.TrimPrefix(h, "localhost"), ":"), h != "localhost")
	}
	if strings.HasPrefix(h, "[") {
		end := strings.IndexByte(h, ']')
		if end < 0 || net.ParseIP(h[1:end]) == nil {
			return false
		}
		rest := h[end+1:]
		return rest == "" || (strings.HasPrefix(rest, ":") && validPort(rest[1:], true))
	}
	name, port, hasPort := strings.Cut(h, ":")
	if hasPort && !validPort(port, true) {
		return false
	}
	if !strings.Contains(name, ".") && !hasPort {
		return false
	}
	for _, l := range strings.Split(name, ".") {
		if !hostLabel.MatchString(l) {
			return false
		}
	}
	return true
}

func validPort(p string, required bool) bool {
	if p == "" {
		return !required
	}
	if len(p) > 5 {
		return false
	}
	for _, c := range p {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func isDockerHub(host string) bool {
	return host == "docker.io" || host == "index.docker.io" || host == "registry-1.docker.io"
}

// apiHost is the host the registry API is served from: Docker Hub's
// docker.io is registry-1.docker.io.
func (r Reference) apiHost() string {
	if isDockerHub(r.Registry) {
		return "registry-1.docker.io"
	}
	return r.Registry
}

// Ref is what a manifest request names: the digest when there is one, else
// the tag.
func (r Reference) Ref() string {
	if r.Digest != "" {
		return r.Digest
	}
	return r.Tag
}

// Name is registry/repository.
func (r Reference) Name() string { return r.Registry + "/" + r.Repository }

// String is the reference as registry/repository[:tag][@digest].
func (r Reference) String() string {
	s := r.Name()
	if r.Tag != "" {
		s += ":" + r.Tag
	}
	if r.Digest != "" {
		s += "@" + r.Digest
	}
	return s
}

// WithDigest is r pinned to a digest, its tag kept for display.
func (r Reference) WithDigest(d string) Reference {
	r.Digest = d
	return r
}
