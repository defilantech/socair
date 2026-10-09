package airlock

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/defilantech/socair/internal/checks/provenance"
	"github.com/defilantech/socair/internal/diskfree"
	"github.com/defilantech/socair/internal/modeldir"
)

// maxAPIResponse bounds one hub API response read into memory.
const maxAPIResponse = 64 << 20

var commitID = regexp.MustCompile(`^[0-9a-f]{40}$`)

// treeEntry is one entry of the hub's tree listing at a commit.
type treeEntry struct {
	Type string `json:"type"`
	Path string `json:"path"`
	Size int64  `json:"size"`
	// OID is the git blob id: sha1("blob <size>\0" + content).
	OID string `json:"oid"`
	// LFS carries the SHA-256 of a large file's content.
	LFS *struct {
		OID  string `json:"oid"`
		Size int64  `json:"size"`
	} `json:"lfs"`
}

// PullRepo fetches every file of a hub repo at one commit into staging, as a
// model directory: incoming/<digest>/<name>/, where digest is the manifest
// digest a directory scan computes (see internal/modeldir) and name is the
// repo's name. A provenance manifest bound to that digest, naming the commit,
// is written at incoming/<digest>/provenance.json.
//
// The pull is pinned: revision must be a full commit id, or wantDigest must
// name the expected manifest digest. A branch alone could deliver different
// bytes tomorrow, and nothing would say so. The revision is resolved to its
// commit, the tree is listed at that commit, and every file is fetched at
// that commit and verified against the hub's own hash for it: the SHA-256 of
// a large (LFS) file, the git blob id of a small one. Any file that does not
// verify, and any path that would leave the directory, refuses the pull.
// Every request goes through the egress policy.
func PullRepo(ctx context.Context, s *Store, repo, revision, wantDigest string, pol EgressPolicy) (Event, string, error) {
	refuse := func(err error) (Event, string, error) {
		e := Event{Action: ActionPull, Outcome: OutcomeRefused, Repo: repo, SHA256: normalizeSHA(wantDigest), Detail: err.Error()}
		if s != nil {
			_ = s.Record(e)
		}
		return e, "", fmt.Errorf("airlock pull %s: %w", repo, err)
	}
	fail := func(detail string) (Event, string, error) { return refuse(errors.New(detail)) }
	if err := validRepo(repo); err != nil {
		return fail(err.Error())
	}
	if strings.TrimSpace(revision) == "" {
		revision = "main"
	}
	if err := validRevision(revision); err != nil {
		return fail(err.Error())
	}
	if wantDigest != "" {
		if err := ValidSHA256(wantDigest); err != nil {
			return fail(err.Error())
		}
	} else if !commitID.MatchString(revision) {
		return fail(fmt.Sprintf("revision %q can move; pin the pull with a full commit id (--revision <40-hex>) or the expected manifest digest (--sha256)", revision))
	}
	pol = pol.withDefaults()
	endpoint := strings.TrimRight(pol.Endpoint, "/")
	if host, ok := pol.allows(endpoint); !ok {
		return fail(fmt.Sprintf("egress to %q is denied by policy (unset SOCAIR_EGRESS=deny and add the host to SOCAIR_EGRESS_ALLOW)", host))
	}
	name := path.Base(repo)
	if err := validFileName(name); err != nil {
		return fail(err.Error())
	}
	// The repo's files are staged under incoming/<digest>/<name>/, so only
	// name itself sits beside the entry's evidence files.
	if err := notEvidenceName(name); err != nil {
		return fail(err.Error())
	}
	client := pol.client()

	// Resolve the revision to the commit every later request is pinned to.
	var rev struct {
		SHA string `json:"sha"`
	}
	if err := getJSON(ctx, client, pol, endpoint+"/api/models/"+repo+"/revision/"+url.PathEscape(revision), &rev); err != nil {
		return fail("resolve revision: " + err.Error())
	}
	commit := strings.ToLower(rev.SHA)
	if !commitID.MatchString(commit) {
		return fail(fmt.Sprintf("the hub resolved %q to %q, not a commit id", revision, rev.SHA))
	}
	if commitID.MatchString(revision) && commit != revision {
		return fail(fmt.Sprintf("the hub resolved commit %s to a different commit %s", revision, commit))
	}

	entries, skipped, err := listTree(ctx, client, pol, endpoint+"/api/models/"+repo+"/tree/"+commit+"?recursive=true")
	if err != nil {
		return fail("list files: " + err.Error())
	}
	if len(entries) == 0 {
		return fail("the repo has no files at commit " + commit)
	}

	tmp, err := s.tmpRoot()
	if err != nil {
		return fail(err.Error())
	}
	// The listing names every size, so a repo that cannot fit is refused
	// before the first byte, not hundreds of gigabytes in.
	var need int64
	for _, e := range entries {
		need += e.Size
	}
	if err := diskfree.Need(tmp, need); err != nil {
		return refuse(err)
	}
	work, err := os.MkdirTemp(tmp, "pull-")
	if err != nil {
		return fail(err.Error())
	}
	defer removeTree(work)
	tree := filepath.Join(work, name)

	files := make([]modeldir.File, 0, len(entries))
	var total int64
	for _, e := range entries {
		src := endpoint + "/" + repo + "/resolve/" + commit + "/" + escapePath(e.Path)
		sum, err := fetchVerified(ctx, client, pol, src, filepath.Join(tree, filepath.FromSlash(e.Path)), e)
		if err != nil {
			return fail(e.Path + ": " + err.Error())
		}
		files = append(files, modeldir.File{Path: e.Path, SHA256: sum, Size: e.Size})
		total += e.Size
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })

	// The staged tree must be exactly the listed files: a file system that
	// folds case or normalizes names could merge two of them.
	if err := sameTree(tree, files); err != nil {
		return fail(err.Error())
	}
	digest := modeldir.Digest(files)
	if wantDigest != "" && digest != normalizeSHA(wantDigest) {
		return fail(fmt.Sprintf("the files at commit %s have manifest digest %s, not the requested %s", commit, digest, normalizeSHA(wantDigest)))
	}

	stage := s.StagingPath(digest)
	if err := os.MkdirAll(stage, 0o755); err != nil {
		return fail(err.Error())
	}
	if err := replaceDir(tree, filepath.Join(stage, name), tmp); err != nil {
		return fail("stage: " + err.Error())
	}
	manifest := provenance.Manifest{
		ArtifactSHA256: digest,
		RepoURL:        endpoint + "/" + repo,
		CommitOrTag:    revision,
		CommitSHA:      commit,
		Source:         "airlock pull",
	}
	b, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fail(err.Error())
	}
	if err := writeBytes(stage, filepath.Join(stage, "provenance.json"), b); err != nil {
		return fail("write provenance manifest: " + err.Error())
	}

	detail := fmt.Sprintf("model directory, revision %s at commit %s, %d files, %d bytes, each verified against the hub's hash", revision, commit, len(files), total)
	if len(skipped) > 0 {
		detail += "; not fetched: " + strings.Join(skipped, ", ")
	}
	e := Event{Action: ActionPull, Outcome: OutcomeOK, Repo: repo, SHA256: digest, Detail: detail}
	if s != nil {
		if err := s.Record(e); err != nil {
			return e, filepath.Join(stage, name), err
		}
	}
	return e, filepath.Join(stage, name), nil
}

// getJSON fetches one bounded JSON response, through the egress policy.
func getJSON(ctx context.Context, client *http.Client, pol EgressPolicy, u string, v any) error {
	_, err := getJSONPage(ctx, client, pol, u, v)
	return err
}

// getJSONPage is getJSON returning the next-page URL from a Link header.
func getJSONPage(ctx context.Context, client *http.Client, pol EgressPolicy, u string, v any) (string, error) {
	if host, ok := pol.allows(u); !ok {
		return "", fmt.Errorf("egress to %q is denied by policy", host)
	}
	cctx, cancel := context.WithTimeout(ctx, 4*pol.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed within the %s budget: %w", pol.Timeout, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("the hub returned HTTP %d for %s", resp.StatusCode, u)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIResponse+1))
	if err != nil {
		return "", err
	}
	if len(b) > maxAPIResponse {
		return "", fmt.Errorf("response over %d bytes", maxAPIResponse)
	}
	if err := json.Unmarshal(b, v); err != nil {
		return "", fmt.Errorf("unreadable response: %w", err)
	}
	return nextLink(resp.Header.Get("Link"), u), nil
}

var linkNext = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// nextLink resolves a Link header's rel="next" URL against the request URL.
func nextLink(header, base string) string {
	m := linkNext.FindStringSubmatch(header)
	if m == nil {
		return ""
	}
	b, err := url.Parse(base)
	if err != nil {
		return ""
	}
	n, err := b.Parse(m[1])
	if err != nil {
		return ""
	}
	return n.String()
}

// listTree lists every file at a commit, following pagination, and validates
// every path. It returns the files sorted by path and the paths left out
// because a scan leaves them out too.
func listTree(ctx context.Context, client *http.Client, pol EgressPolicy, u string) ([]treeEntry, []string, error) {
	var files []treeEntry
	var skipped []string
	seen := map[string]bool{}
	folded := map[string]string{}
	for page := 0; u != ""; page++ {
		if page > modeldir.MaxFiles {
			return nil, nil, fmt.Errorf("more than %d pages", modeldir.MaxFiles)
		}
		var batch []treeEntry
		next, err := getJSONPage(ctx, client, pol, u, &batch)
		if err != nil {
			return nil, nil, err
		}
		for _, e := range batch {
			if e.Type != "file" {
				continue
			}
			if err := safeRepoPath(e.Path); err != nil {
				return nil, nil, err
			}
			if why, skip := skippedPath(e.Path); skip {
				skipped = append(skipped, e.Path+" ("+why+")")
				continue
			}
			if seen[e.Path] {
				return nil, nil, fmt.Errorf("the listing names %q twice", e.Path)
			}
			seen[e.Path] = true
			// Two names one file system may treat as the same file.
			if prev, ok := folded[strings.ToLower(e.Path)]; ok {
				return nil, nil, fmt.Errorf("%q and %q differ only in case", prev, e.Path)
			}
			folded[strings.ToLower(e.Path)] = e.Path
			if e.Size < 0 || (e.LFS == nil && !gitOID.MatchString(e.OID)) || (e.LFS != nil && !hexSHA256.MatchString(e.LFS.OID)) {
				return nil, nil, fmt.Errorf("%q has no hash the hub vouches for", e.Path)
			}
			files = append(files, e)
			if len(files) > modeldir.MaxFiles {
				return nil, nil, fmt.Errorf("more than %d files; not a model directory this scanner reads", modeldir.MaxFiles)
			}
		}
		u = next
	}
	// A file and a directory with the same path cannot both be staged.
	for p := range seen {
		// Bounded by the parent, not by reaching ".": path.Dir("/") is "/",
		// so a walk that only stops at "." would never end on an absolute
		// path, should one ever get past safeRepoPath.
		for dir, parent := path.Dir(p), p; dir != parent && dir != "." && dir != "/"; parent, dir = dir, path.Dir(dir) {
			if seen[dir] {
				return nil, nil, fmt.Errorf("%q is both a file and a directory", dir)
			}
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, skipped, nil
}

var gitOID = regexp.MustCompile(`^[0-9a-f]{40}$`)

// safeRepoPath accepts a relative, "/"-separated path that stays inside the
// directory and can be named in a manifest.
func safeRepoPath(p string) error {
	bad := p == "" || !utf8.ValidString(p) || strings.ContainsAny(p, "\\\x00\n\r") || path.IsAbs(p) || path.Clean(p) != p
	if !bad {
		for _, seg := range strings.Split(p, "/") {
			if seg == "" || seg == "." || seg == ".." {
				bad = true
			}
		}
	}
	if bad {
		return fmt.Errorf("the listing names an unsafe path %q", p)
	}
	return nil
}

// skippedPath reports whether a scan would leave this path out.
func skippedPath(p string) (string, bool) {
	segs := strings.Split(p, "/")
	for _, seg := range segs[:len(segs)-1] {
		if why, ok := modeldir.Skipped(seg); ok {
			return why, true
		}
	}
	return "", false
}

// escapePath escapes each segment of a repo path for a resolve URL.
func escapePath(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}

// fetchVerified downloads one file to dst, hashing while writing, and keeps
// it only if its size and hash are the ones the hub listed. It returns the
// SHA-256 of the content.
func fetchVerified(ctx context.Context, client *http.Client, pol EgressPolicy, src, dst string, e treeEntry) (string, error) {
	if host, ok := pol.allows(src); !ok {
		return "", fmt.Errorf("egress to %q is denied by policy", host)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return "", err
	}
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, src, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch failed within the %s stall budget: %w", pol.Timeout, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("the hub returned HTTP %d", resp.StatusCode)
	}
	body := newStallReader(io.LimitReader(resp.Body, e.Size+1), pol.Timeout, cancel)
	defer body.stop()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	sum256 := sha256.New()
	var blob hash.Hash
	writers := []io.Writer{out, sum256}
	if e.LFS == nil {
		blob = sha1.New()
		io.WriteString(blob, "blob "+strconv.FormatInt(e.Size, 10)+"\x00")
		writers = append(writers, blob)
	}
	n, err := io.Copy(io.MultiWriter(writers...), body)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		if body.stalled() {
			return "", fmt.Errorf("download stalled for longer than the %s stall budget", pol.Timeout)
		}
		return "", err
	}
	if n != e.Size {
		return "", fmt.Errorf("the hub listed %d bytes but served %d", e.Size, n)
	}
	got := hex.EncodeToString(sum256.Sum(nil))
	if e.LFS != nil {
		if got != strings.ToLower(e.LFS.OID) {
			return "", fmt.Errorf("content hashes to %s, but the hub lists sha256 %s", got, e.LFS.OID)
		}
	} else if b := hex.EncodeToString(blob.Sum(nil)); b != strings.ToLower(e.OID) {
		return "", fmt.Errorf("content has git blob id %s, but the hub lists %s", b, e.OID)
	}
	return got, nil
}

// sameTree checks that the tree on disk holds exactly the listed files.
func sameTree(root string, files []modeldir.File) error {
	want := map[string]int64{}
	for _, f := range files {
		want[f.Path] = f.Size
	}
	found := 0
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		size, ok := want[rel]
		info, ierr := d.Info()
		if !ok || ierr != nil || info.Size() != size {
			return fmt.Errorf("the staged tree does not match the listing at %q (a file system that folds names?)", rel)
		}
		found++
		return nil
	})
	if err != nil {
		return err
	}
	if found != len(files) {
		return fmt.Errorf("staged %d of %d listed files (a file system that folds names?)", found, len(files))
	}
	return nil
}
