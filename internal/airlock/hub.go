package airlock

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/defilantech/socair/internal/report"
)

// Hub serves the clean store's admitted models over a read-only subset of the
// Hugging Face Hub HTTP API: the requests huggingface_hub makes to download a
// model when HF_ENDPOINT points at it (docs/hub-endpoint.md).
//
//	GET  /api/models/{org}/{name}[/revision/{rev}]     model info: commit and files
//	GET  /api/models/{org}/{name}/tree/{rev}[/{path}]  file listing (?recursive=true)
//	HEAD /{org}/{name}/resolve/{rev}/{path}            a file's metadata
//	GET  /{org}/{name}/resolve/{rev}/{path}            a file's bytes (Range too)
//	GET  /api/socair/attestations/{sha256}             the entry's signed attestation
//	GET  /api/health
//
// It serves an entry only while the store admits it (AdmittedEntry, checked
// on every request), and of that entry only the files its attestation lists,
// opened beneath the entry's own directory. It never writes: not the store,
// not the activity log. A model is addressed by the repo id its attestation
// records (org/name) and always by its hash (sha256/<hash>).
type Hub struct {
	store *Store
	opts  HubOptions
	now   func() time.Time

	mu    sync.Mutex
	index []hubIndexEntry
	built time.Time

	vmu      sync.Mutex
	verified map[hubFileKey]hubFileState
}

// HubOptions configures a Hub.
type HubOptions struct {
	// AuthorizedOnly serves authorized entries only, never one promoted with
	// conditions.
	AuthorizedOnly bool
	// AllowAnyHost serves requests whatever their Host header. Off, only a
	// loopback Host is served, so a web page cannot read the endpoint through
	// DNS rebinding. ServeHub sets it for a non-loopback bind.
	AllowAnyHost bool
	// Refresh is how long the repo-id index is reused before it is rebuilt.
	// Admission itself is re-derived on every request; the index only finds
	// the candidates for a repo id, so a newly promoted model is served within
	// Refresh. Zero means DefaultHubRefresh.
	Refresh time.Duration
	// Log receives one line per request and why a model was not served.
	// Nil discards them.
	Log io.Writer
}

// DefaultHubAddr is where the hub endpoint binds unless told otherwise.
const DefaultHubAddr = "127.0.0.1:8081"

// DefaultHubRefresh is how long the repo-id index is reused.
const DefaultHubRefresh = 5 * time.Second

// NewHub returns a hub endpoint over the store s.
func NewHub(s *Store, o HubOptions) *Hub {
	if o.Refresh <= 0 {
		o.Refresh = DefaultHubRefresh
	}
	if o.Log == nil {
		o.Log = io.Discard
	}
	return &Hub{store: s, opts: o, now: func() time.Time { return now() }, verified: map[hubFileKey]hubFileState{}}
}

// CheckHubAddr reports whether the hub endpoint may bind addr. It has no
// authentication, so an address that is not loopback needs allowPublic.
func CheckHubAddr(addr string, allowPublic bool) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("hub address %q: %v", addr, err)
	}
	if loopbackName(host) || allowPublic {
		return nil
	}
	return fmt.Errorf("refusing to bind %s: the hub endpoint has no authentication. Bind loopback, or pass --allow-public and let a network policy decide who reaches it", addr)
}

// ServeHub runs the hub endpoint on addr. It refuses an address that is not
// loopback unless allowPublic is set, and logs which models it serves.
func ServeHub(addr string, s *Store, o HubOptions, allowPublic bool) error {
	if err := CheckHubAddr(addr, allowPublic); err != nil {
		return err
	}
	host, _, _ := net.SplitHostPort(addr)
	if !loopbackName(host) {
		o.AllowAnyHost = true
	}
	h := NewHub(s, o)
	h.Announce()
	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		IdleTimeout:       120 * time.Second,
		// No WriteTimeout: a multi-GB file that keeps moving must finish.
	}
	return srv.ListenAndServe()
}

// Announce logs every clean entry: how each admitted one is addressed, and
// why each other one is not served.
func (h *Hub) Announce() {
	ok, not, err := h.store.AdmittedEntries(h.now())
	if err != nil {
		fmt.Fprintf(h.opts.Log, "hub: %v\n", err)
		return
	}
	fmt.Fprintf(h.opts.Log, "hub: %d admitted model(s) in %s\n", len(ok), h.store.cleanRoot())
	for _, a := range ok {
		names := HashNamespace + "/" + a.ID
		if r := a.RepoID(); r != "" {
			names = r + " and " + names
		}
		state := strings.ReplaceAll(a.State, "_", " ")
		if !a.Expires.IsZero() {
			state += " until " + a.Expires.UTC().Format(time.RFC3339)
		}
		if h.opts.AuthorizedOnly && a.State != report.StateAuthorized {
			fmt.Fprintf(h.opts.Log, "hub:   not served: %s (%s; --authorized-only)\n", names, state)
			continue
		}
		fmt.Fprintf(h.opts.Log, "hub:   %s at revision %s, %d file(s), %s\n", names, a.Revision(), len(a.Files), state)
	}
	for _, n := range not {
		fmt.Fprintf(h.opts.Log, "hub:   not served: %v\n", n)
	}
}

func (h *Hub) logf(format string, args ...any) {
	fmt.Fprintf(h.opts.Log, "hub: "+format+"\n", args...)
}

// hubIndexEntry maps an admitted entry to the repo id its attestation
// records. The index finds candidates only; admission is re-derived per
// request.
type hubIndexEntry struct {
	id, repo string
}

// candidates are the ids of the entries the index last saw admitted under
// repo, rebuilding the index when it is older than Refresh.
func (h *Hub) candidates(repo string, at time.Time) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.index == nil || at.Sub(h.built) >= h.opts.Refresh || at.Before(h.built) {
		ok, _, err := h.store.AdmittedEntries(at)
		if err != nil {
			h.logf("index: %v", err)
		} else {
			idx := make([]hubIndexEntry, 0, len(ok))
			for _, a := range ok {
				if r := a.RepoID(); r != "" {
					idx = append(idx, hubIndexEntry{id: a.ID, repo: r})
				}
			}
			h.index, h.built = idx, at
		}
	}
	var ids []string
	for _, e := range h.index {
		if e.repo == repo {
			ids = append(ids, e.id)
		}
	}
	return ids
}

// hubGroup is what a repo id at a revision names: one admitted entry, or
// several at the same revision (single files pulled from one repo at one
// commit), whose files together are the listing.
type hubGroup struct {
	repo     string
	revision string
	entries  []*Admitted
	files    map[string]hubFile
	paths    []string
}

type hubFile struct {
	entry *Admitted
	AdmittedFile
}

// hubError is an answer in the Hub's own shape: huggingface_hub reads the
// X-Error-Code header to tell a missing repo, revision, or file apart.
type hubError struct {
	status int
	code   string
	msg    string
	commit string
}

func repoNotFound() *hubError {
	return &hubError{status: http.StatusNotFound, code: "RepoNotFound", msg: "Repository not found"}
}

// group resolves a repo id and a revision to the admitted entries they name,
// re-deriving each candidate's admission at the moment at. An entry that is
// not admitted is answered exactly as a repo that does not exist; the reason
// goes to the log only.
func (h *Hub) group(org, name, rev string, at time.Time) (*hubGroup, *hubError) {
	repo := org + "/" + name
	var ids []string
	if org == HashNamespace {
		if hexSHA256.MatchString(name) {
			ids = []string{name}
		}
	} else {
		ids = h.candidates(repo, at)
	}
	var entries []*Admitted
	for _, id := range ids {
		a, err := h.store.AdmittedEntry(id, at)
		switch {
		case err != nil:
			if !errors.Is(err, ErrNoModel) {
				h.logf("not served: %s: %v", repo, err)
			}
			continue
		case org != HashNamespace && a.RepoID() != repo:
			continue
		case h.opts.AuthorizedOnly && a.State != report.StateAuthorized:
			h.logf("not served: %s: clean entry %s is %s, and --authorized-only is set", repo, shortSHA(a.ID), a.State)
			continue
		}
		entries = append(entries, a)
	}
	if len(entries) == 0 {
		return nil, repoNotFound()
	}

	var chosen []*Admitted
	switch {
	case rev == "" || rev == "main":
		chosen = entries
		revs := map[string]bool{}
		var list []string
		for _, a := range entries {
			if r := a.Revision(); !revs[r] {
				revs[r] = true
				list = append(list, r)
			}
		}
		if len(list) > 1 {
			sort.Strings(list)
			return nil, &hubError{status: http.StatusConflict,
				msg: fmt.Sprintf("%s has %d admitted revisions (%s); request one of them as the revision", repo, len(list), strings.Join(list, ", "))}
		}
	case commitID.MatchString(rev):
		for _, a := range entries {
			if a.Revision() == rev {
				chosen = append(chosen, a)
			}
		}
	case hexSHA256.MatchString(rev):
		for _, a := range entries {
			if a.ID == rev {
				chosen = append(chosen, a)
			}
		}
	}
	if len(chosen) == 0 {
		return nil, &hubError{status: http.StatusNotFound, code: "RevisionNotFound", msg: "Revision not found"}
	}

	g := &hubGroup{repo: repo, revision: chosen[0].Revision(), entries: chosen, files: map[string]hubFile{}}
	if hexSHA256.MatchString(rev) {
		// Named by its hash, the entry reports its hash as the commit, so
		// every request a client makes next is pinned to this entry alone.
		g.revision = rev
	}
	for _, a := range chosen {
		for _, f := range a.Files {
			if prev, ok := g.files[f.Path]; ok {
				if prev.SHA256 != f.SHA256 {
					return nil, &hubError{status: http.StatusConflict,
						msg: fmt.Sprintf("%s at %s: admitted entries %s and %s hold different bytes at %s; request one by its hash", repo, g.revision, shortSHA(prev.entry.ID), shortSHA(a.ID), f.Path)}
				}
				continue
			}
			g.files[f.Path] = hubFile{entry: a, AdmittedFile: f}
			g.paths = append(g.paths, f.Path)
		}
	}
	sort.Strings(g.paths)
	return g, nil
}

// ServeHTTP answers one request. Only GET and HEAD are served.
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rec := &hubRecorder{ResponseWriter: w, status: http.StatusOK}
	defer func() {
		h.logf("%s %q %d %d", r.Method, r.URL.EscapedPath(), rec.status, rec.n)
	}()
	rec.Header().Set("X-Content-Type-Options", "nosniff")
	if !h.opts.AllowAnyHost && !loopbackHost(r.Host) {
		writeHubError(rec, &hubError{status: http.StatusForbidden, msg: "host " + r.Host + " is not a loopback address"})
		return
	}
	raw := r.URL.EscapedPath()
	if !strings.HasPrefix(raw, "/") {
		writeHubError(rec, &hubError{status: http.StatusBadRequest, msg: "bad request path"})
		return
	}
	segs := strings.Split(raw[1:], "/")
	switch {
	case len(segs) >= 1 && segs[0] == "api":
		h.api(rec, r, segs[1:])
	case len(segs) >= 4 && segs[2] == "resolve":
		if !h.allow(rec, r, http.MethodGet, http.MethodHead) {
			return
		}
		h.resolve(rec, r, segs[0], segs[1], segs[3], segs[4:])
	default:
		writeHubError(rec, &hubError{status: http.StatusNotFound, msg: "no such route"})
	}
}

func (h *Hub) allow(w http.ResponseWriter, r *http.Request, methods ...string) bool {
	for _, m := range methods {
		if r.Method == m {
			return true
		}
	}
	w.Header().Set("Allow", strings.Join(methods, ", "))
	writeHubError(w, &hubError{status: http.StatusMethodNotAllowed, msg: r.Method + " is not allowed here; the hub endpoint is read-only"})
	return false
}

func (h *Hub) api(w http.ResponseWriter, r *http.Request, segs []string) {
	switch {
	case len(segs) == 1 && segs[0] == "health":
		if h.allow(w, r, http.MethodGet, http.MethodHead) {
			h.health(w)
		}
		return
	case len(segs) == 3 && segs[0] == "socair" && segs[1] == "attestations":
		if h.allow(w, r, http.MethodGet, http.MethodHead) {
			h.attestation(w, segs[2])
		}
		return
	case len(segs) < 3 || segs[0] != "models":
		writeHubError(w, &hubError{status: http.StatusNotFound, msg: "no such route"})
		return
	}
	org, name, rest := segs[1], segs[2], segs[3:]
	switch {
	case len(rest) == 0:
		if h.allow(w, r, http.MethodGet, http.MethodHead) {
			h.modelInfo(w, org, name, "main")
		}
	case len(rest) == 2 && rest[0] == "revision":
		if h.allow(w, r, http.MethodGet, http.MethodHead) {
			h.modelInfo(w, org, name, rest[1])
		}
	case len(rest) >= 2 && rest[0] == "tree":
		if h.allow(w, r, http.MethodGet, http.MethodHead) {
			h.tree(w, r, org, name, rest[1], rest[2:])
		}
	default:
		writeHubError(w, &hubError{status: http.StatusNotFound, msg: "no such route"})
	}
}

// requestGroup decodes the repo id and revision segments of a request and
// resolves them. A repo id that is not org/name, in the shape a hub repo id
// takes, names nothing.
func (h *Hub) requestGroup(rawOrg, rawName, rawRev string) (*hubGroup, *hubError) {
	org, err1 := nameSegment(rawOrg)
	name, err2 := nameSegment(rawName)
	if err1 != nil || err2 != nil || !hubRepoID.MatchString(org+"/"+name) || hasDotDot(org+"/"+name) {
		return nil, repoNotFound()
	}
	rev, err := url.PathUnescape(rawRev)
	if err != nil || strings.IndexFunc(rev, unicode.IsControl) >= 0 {
		return nil, &hubError{status: http.StatusNotFound, code: "RevisionNotFound", msg: "Revision not found"}
	}
	return h.group(org, name, rev, h.now())
}

// nameSegment decodes one path segment that must be a plain name: not empty,
// not "." or "..", and no separator, NUL, or control character once decoded.
func nameSegment(raw string) (string, error) {
	s, err := url.PathUnescape(raw)
	switch {
	case err != nil:
		return "", err
	case s == "" || s == "." || s == "..", strings.ContainsAny(s, `/\`), strings.IndexFunc(s, unicode.IsControl) >= 0:
		return "", fmt.Errorf("%q is not a plain name", s)
	}
	return s, nil
}

// repoPathFrom decodes the trailing segments of a request into a path in the
// model. Each segment is decoded on its own, so an encoded separator or dot
// is seen for what it is, and the joined path must be a relative path that
// stays inside the model (the rules a pulled listing obeys). The result is
// only ever looked up among the attested paths; it is never joined to disk.
func repoPathFrom(raw []string) (string, error) {
	parts := make([]string, len(raw))
	for i, seg := range raw {
		s, err := url.PathUnescape(seg)
		if err != nil {
			return "", err
		}
		parts[i] = s
	}
	p := strings.Join(parts, "/")
	if err := safeRepoPath(p); err != nil {
		return "", err
	}
	return p, nil
}

func (h *Hub) modelInfo(w http.ResponseWriter, rawOrg, rawName, rawRev string) {
	g, herr := h.requestGroup(rawOrg, rawName, rawRev)
	if herr != nil {
		writeHubError(w, herr)
		return
	}
	org, _, _ := strings.Cut(g.repo, "/")
	info := hubModelInfo{ID: g.repo, ModelID: g.repo, Author: org, SHA: g.revision, Tags: []string{}, Siblings: []hubSibling{}}
	for _, p := range g.paths {
		f := g.files[p]
		ptr := lfsPointer(f.SHA256, f.Size)
		size := f.Size
		info.Siblings = append(info.Siblings, hubSibling{RFilename: p, Size: &size, BlobID: gitBlobID(ptr),
			LFS: &hubSiblingLFS{Size: f.Size, SHA256: f.SHA256, PointerSize: len(ptr)}})
		info.UsedStorage += f.Size
	}
	for _, a := range g.entries {
		e := hubSocairEntry{Subject: a.ID, PromotionState: a.State, Issuer: a.Issuer, Files: len(a.Files),
			Attestation: "/api/socair/attestations/" + a.ID}
		if !a.Expires.IsZero() {
			e.AcceptanceExpires = a.Expires.UTC().Format(time.RFC3339)
		}
		info.Socair.Entries = append(info.Socair.Entries, e)
	}
	writeHubJSON(w, http.StatusOK, info)
}

func (h *Hub) tree(w http.ResponseWriter, r *http.Request, rawOrg, rawName, rawRev string, rawPath []string) {
	g, herr := h.requestGroup(rawOrg, rawName, rawRev)
	if herr != nil {
		writeHubError(w, herr)
		return
	}
	dir := ""
	if len(rawPath) > 0 && !(len(rawPath) == 1 && rawPath[0] == "") {
		p, err := repoPathFrom(rawPath)
		if err != nil {
			writeHubError(w, &hubError{status: http.StatusNotFound, code: "EntryNotFound", msg: "Entry not found", commit: g.revision})
			return
		}
		dir = p
	}
	recursive := false
	switch strings.ToLower(r.URL.Query().Get("recursive")) {
	case "true", "1":
		recursive = true
	}
	out, found := g.list(dir, recursive)
	if !found {
		writeHubError(w, &hubError{status: http.StatusNotFound, code: "EntryNotFound", msg: "Entry not found", commit: g.revision})
		return
	}
	writeHubJSON(w, http.StatusOK, out)
}

// list is the tree listing under dir ("" for the root): its files and
// directories, every level of them when recursive. found is false when dir
// is not a directory of the group.
func (g *hubGroup) list(dir string, recursive bool) ([]hubTreeEntry, bool) {
	prefix := ""
	if dir != "" {
		prefix = dir + "/"
	}
	found := dir == ""
	dirs := map[string]bool{}
	out := []hubTreeEntry{}
	for _, p := range g.paths {
		if !strings.HasPrefix(p, prefix) {
			continue
		}
		found = true
		rest := p[len(prefix):]
		parts := strings.Split(rest, "/")
		if len(parts) > 1 {
			if !recursive {
				dirs[prefix+parts[0]] = true
				continue
			}
			for j := 1; j < len(parts); j++ {
				dirs[prefix+strings.Join(parts[:j], "/")] = true
			}
		}
		out = append(out, fileEntry(g.files[p]))
	}
	for d := range dirs {
		out = append(out, g.dirEntry(d))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, found
}

// dirEntry is a directory as the tree API lists one. Its oid is not a git
// tree id (there is no git tree here): it is the SHA-1 of the paths and
// SHA-256 hashes of the files under it, so it changes when they do.
func (g *hubGroup) dirEntry(dir string) hubTreeEntry {
	h := sha1.New()
	for _, p := range g.paths {
		if strings.HasPrefix(p, dir+"/") {
			fmt.Fprintf(h, "%s\x00%s\n", p, g.files[p].SHA256)
		}
	}
	return hubTreeEntry{Type: "directory", OID: hex.EncodeToString(h.Sum(nil)), Path: dir}
}

// fileEntry is a file as the tree API lists a Git LFS file: lfs.oid is its
// SHA-256 and oid is the git blob id of its LFS pointer, as the Hub lists an
// LFS file. Every file is presented this way, small ones too, so a client
// that checks a download against the listing checks its SHA-256.
func fileEntry(f hubFile) hubTreeEntry {
	ptr := lfsPointer(f.SHA256, f.Size)
	return hubTreeEntry{Type: "file", OID: gitBlobID(ptr), Size: f.Size, Path: f.Path,
		LFS: &hubTreeLFS{OID: f.SHA256, Size: f.Size, PointerSize: len(ptr)}}
}

// lfsPointer is the Git LFS pointer file for content with this SHA-256 and
// size (git-lfs docs/spec.md).
func lfsPointer(sha string, size int64) string {
	return "version https://git-lfs.github.com/spec/v1\noid sha256:" + sha + "\nsize " + strconv.FormatInt(size, 10) + "\n"
}

// gitBlobID is the git object id of a blob with this content.
func gitBlobID(content string) string {
	h := sha1.New()
	fmt.Fprintf(h, "blob %d\x00%s", len(content), content)
	return hex.EncodeToString(h.Sum(nil))
}

func (h *Hub) resolve(w http.ResponseWriter, r *http.Request, rawOrg, rawName, rawRev string, rawPath []string) {
	g, herr := h.requestGroup(rawOrg, rawName, rawRev)
	if herr != nil {
		writeHubError(w, herr)
		return
	}
	notFound := &hubError{status: http.StatusNotFound, code: "EntryNotFound", msg: "Entry not found", commit: g.revision}
	p, err := repoPathFrom(rawPath)
	if err != nil {
		writeHubError(w, notFound)
		return
	}
	f, ok := g.files[p]
	if !ok {
		writeHubError(w, notFound)
		return
	}
	file, err := h.store.OpenAdmitted(f.entry, f.Path)
	if err != nil {
		h.logf("cannot serve %s from clean entry %s: %v", f.Path, f.entry.ID, err)
		writeHubError(w, &hubError{status: http.StatusInternalServerError, msg: "the clean store's copy of this file cannot be served", commit: g.revision})
		return
	}
	defer file.Close()
	fi, err := file.Stat()
	if err != nil || fi.Size() != f.Size {
		h.logf("%s in clean entry %s is not the attested %d bytes", f.Path, f.entry.ID, f.Size)
		writeHubError(w, &hubError{status: http.StatusInternalServerError, msg: "the clean store's copy of this file does not match its attestation", commit: g.revision})
		return
	}
	key := hubFileKey{id: f.entry.ID, path: f.Path}
	good, known := h.checked(key, fi)
	if f.Size == 0 {
		// An empty file has no last byte to withhold: check it first.
		good, known = hashMatches(file, 0, f.SHA256), true
	}
	if known && !good {
		writeHubError(w, &hubError{status: http.StatusInternalServerError, msg: "the clean store's copy of this file does not match its attestation", commit: g.revision})
		return
	}

	hdr := w.Header()
	etag := `"` + f.SHA256 + `"`
	hdr.Set("X-Repo-Commit", g.revision)
	hdr.Set("ETag", etag)
	hdr.Set("X-Linked-Etag", etag)
	hdr.Set("X-Linked-Size", strconv.FormatInt(f.Size, 10))
	hdr.Set("Accept-Ranges", "bytes")
	hdr.Set("Content-Type", "application/octet-stream")
	hdr.Set("X-Socair-Subject", f.entry.ID)
	hdr.Set("X-Socair-Promotion-State", f.entry.State)

	switch {
	case r.Method == http.MethodHead:
		hdr.Set("Content-Length", strconv.FormatInt(f.Size, 10))
		w.WriteHeader(http.StatusOK)
	case r.Header.Get("Range") != "":
		// A part of a file cannot be checked on its own, so a range is served
		// only from a file a whole pass has checked, unchanged since.
		if !known {
			good = hashMatches(file, f.Size, f.SHA256)
			h.record(key, fi, good)
			if !good {
				h.logf("%s in clean entry %s does not hash to its attestation; not served", f.Path, f.entry.ID)
				hdr.Del("ETag")
				writeHubError(w, &hubError{status: http.StatusInternalServerError, msg: "the clean store's copy of this file does not match its attestation", commit: g.revision})
				return
			}
		}
		http.ServeContent(w, r, "", time.Time{}, io.NewSectionReader(file, 0, f.Size))
	default:
		hdr.Set("Content-Length", strconv.FormatInt(f.Size, 10))
		w.WriteHeader(http.StatusOK)
		ok, err := streamVerified(w, file, f.Size, f.SHA256)
		if err == nil {
			h.record(key, fi, ok)
		}
		if !ok || err != nil {
			if err == nil {
				h.logf("%s in clean entry %s does not hash to its attestation; the download was cut short of its last byte", f.Path, f.entry.ID)
			}
			// The client has fewer bytes than Content-Length: the transfer
			// fails, never completes.
			panic(http.ErrAbortHandler)
		}
	}
}

// streamVerified writes size bytes of f to w while hashing them, and writes
// the last byte only if the whole file hashes to want. A file that does not
// match never reaches a client complete.
func streamVerified(w io.Writer, f *os.File, size int64, want string) (bool, error) {
	h := sha256.New()
	if size == 0 {
		return hex.EncodeToString(h.Sum(nil)) == want, nil
	}
	buf := make([]byte, 1<<20)
	if _, err := io.CopyBuffer(io.MultiWriter(h, w), io.NewSectionReader(f, 0, size-1), buf); err != nil {
		return false, err
	}
	last := make([]byte, 1)
	if _, err := f.ReadAt(last, size-1); err != nil {
		return false, err
	}
	h.Write(last)
	if hex.EncodeToString(h.Sum(nil)) != want {
		return false, nil
	}
	_, err := w.Write(last)
	return true, err
}

// hashMatches reports whether the first size bytes of f hash to want.
func hashMatches(f *os.File, size int64, want string) bool {
	h := sha256.New()
	if _, err := io.CopyBuffer(h, io.NewSectionReader(f, 0, size), make([]byte, 1<<20)); err != nil {
		return false
	}
	return hex.EncodeToString(h.Sum(nil)) == want
}

// A file's check result holds while the file is the same file with the same
// size and modification time. A change to any of them is checked again.
type hubFileKey struct{ id, path string }

type hubFileState struct {
	fi fs.FileInfo
	ok bool
}

func (h *Hub) checked(k hubFileKey, fi fs.FileInfo) (good, known bool) {
	h.vmu.Lock()
	defer h.vmu.Unlock()
	st, found := h.verified[k]
	if !found || !os.SameFile(st.fi, fi) || st.fi.Size() != fi.Size() || !st.fi.ModTime().Equal(fi.ModTime()) {
		return false, false
	}
	return st.ok, true
}

func (h *Hub) record(k hubFileKey, fi fs.FileInfo, ok bool) {
	h.vmu.Lock()
	defer h.vmu.Unlock()
	h.verified[k] = hubFileState{fi: fi, ok: ok}
}

// attestation serves the DSSE envelope of an admitted entry, byte for byte,
// for a consumer to verify offline with `socair verify`.
func (h *Hub) attestation(w http.ResponseWriter, raw string) {
	id, err := url.PathUnescape(raw)
	if err != nil || !hexSHA256.MatchString(id) {
		writeHubError(w, &hubError{status: http.StatusNotFound, msg: "no admitted entry with that hash"})
		return
	}
	at := h.now()
	a, err := h.store.AdmittedEntry(id, at)
	if err == nil && h.opts.AuthorizedOnly && a.State != report.StateAuthorized {
		err = ErrNoModel
	}
	if err != nil {
		writeHubError(w, &hubError{status: http.StatusNotFound, msg: "no admitted entry with that hash"})
		return
	}
	b, err := h.readEnvelope(id)
	if err == nil {
		// The bytes served are the bytes that assess, not merely the file
		// that assessed a moment ago.
		var as *Assessment
		if as, err = h.store.Assess(b, at); err == nil && as.SHA256 != id {
			err = errors.New("the attestation is for another entry")
		}
	}
	if err != nil {
		h.logf("cannot serve the attestation of clean entry %s: %v", id, err)
		writeHubError(w, &hubError{status: http.StatusNotFound, msg: "no admitted entry with that hash"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="`+id+`.dsse.json"`)
	w.WriteHeader(http.StatusOK)
	w.Write(b)
}

func (h *Hub) readEnvelope(id string) ([]byte, error) {
	root, err := os.OpenRoot(h.store.CleanPath(id))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	fi, err := noSymlinks(root, attestationEnvelope)
	if err != nil {
		return nil, err
	}
	f, err := openBeneath(root, attestationEnvelope, fi)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxAPIResponse))
}

func (h *Hub) health(w http.ResponseWriter) {
	if fi, err := os.Stat(h.store.cleanRoot()); err != nil || !fi.IsDir() {
		writeHubJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable", "error": "the clean store cannot be read"})
		return
	}
	if _, _, err := h.store.TrustedIssuers(); err != nil {
		writeHubJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable", "error": "the store trusts no signing key, so it admits nothing"})
		return
	}
	writeHubJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// The Hub's JSON shapes, as huggingface_hub reads them (hf_api.py: ModelInfo,
// RepoSibling, RepoFile, RepoFolder).
type hubModelInfo struct {
	ID          string       `json:"id"`
	ModelID     string       `json:"modelId"`
	Author      string       `json:"author"`
	SHA         string       `json:"sha"`
	Private     bool         `json:"private"`
	Gated       bool         `json:"gated"`
	Disabled    bool         `json:"disabled"`
	Tags        []string     `json:"tags"`
	Siblings    []hubSibling `json:"siblings"`
	UsedStorage int64        `json:"usedStorage"`
	Socair      hubSocair    `json:"socair"`
}

type hubSibling struct {
	RFilename string         `json:"rfilename"`
	Size      *int64         `json:"size,omitempty"`
	BlobID    string         `json:"blobId,omitempty"`
	LFS       *hubSiblingLFS `json:"lfs,omitempty"`
}

type hubSiblingLFS struct {
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
	PointerSize int    `json:"pointerSize"`
}

// hubSocair is Socair's addition to the model info: the admitted entries the
// listing comes from, each with its attestation.
type hubSocair struct {
	Entries []hubSocairEntry `json:"entries"`
}

type hubSocairEntry struct {
	Subject           string `json:"subject"`
	PromotionState    string `json:"promotion_state"`
	AcceptanceExpires string `json:"acceptance_expires,omitempty"`
	Issuer            string `json:"issuer,omitempty"`
	Files             int    `json:"files"`
	Attestation       string `json:"attestation"`
}

type hubTreeEntry struct {
	Type string      `json:"type"`
	OID  string      `json:"oid"`
	Size int64       `json:"size"`
	Path string      `json:"path"`
	LFS  *hubTreeLFS `json:"lfs,omitempty"`
}

type hubTreeLFS struct {
	OID         string `json:"oid"`
	Size        int64  `json:"size"`
	PointerSize int    `json:"pointerSize"`
}

func writeHubJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeHubError(w http.ResponseWriter, e *hubError) {
	if e.code != "" {
		w.Header().Set("X-Error-Code", e.code)
	}
	w.Header().Set("X-Error-Message", e.msg)
	if e.commit != "" {
		w.Header().Set("X-Repo-Commit", e.commit)
	}
	writeHubJSON(w, e.status, map[string]string{"error": e.msg})
}

// hubRecorder notes the status and byte count for the request log.
type hubRecorder struct {
	http.ResponseWriter
	status int
	n      int64
}

func (r *hubRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *hubRecorder) Write(b []byte) (int, error) {
	n, err := r.ResponseWriter.Write(b)
	r.n += int64(n)
	return n, err
}

// loopbackHost reports whether a Host header names the loopback interface.
func loopbackHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	return loopbackName(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]"))
}

func loopbackName(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
