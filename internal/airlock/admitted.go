package airlock

import (
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/defilantech/socair/internal/report"
)

// What the clean store admits right now, for a reader that hands models out
// (the hub endpoint, hub.go). "In clean" does not mean admitted: a clean
// entry is admitted only while its stage, derived by the gate's own checks,
// is approved. Its attestation verifies against the trust policy, its state
// crosses, a conditional acceptance has not expired, and no recheck has
// flagged it. Every file of an admitted entry is one its verified attestation
// lists, opened beneath the entry's own directory.

// HashNamespace is the hub namespace that addresses every admitted entry by
// its hash: sha256/<64-hex>.
const HashNamespace = "sha256"

// Admitted is a clean entry the store admits at a moment (AdmittedEntry).
type Admitted struct {
	// ID is the entry's hash: the artifact's SHA-256, or a model directory's
	// manifest digest. It is the attestation subject.
	ID string
	// Name is the artifact's file or directory name in clean/<id>/.
	Name string
	// Directory is true for a model directory.
	Directory bool
	// Document is the verified attestation's report.
	Document *report.Document
	// State is the attestation's promotion state, and Expires a conditional
	// acceptance's expiry (zero for an authorized entry).
	State   string
	Expires time.Time
	// Issuer is who signed the attestation, as the store names the key.
	Issuer string
	// Files are the files the attestation binds, sorted by path: a model
	// directory's files, or the single file under its name.
	Files []AdmittedFile
}

// AdmittedFile is one file of an admitted entry, as its attestation lists it.
type AdmittedFile struct {
	// Path is the file's "/"-separated path in the model: its path in a
	// model directory, or a single file's name.
	Path   string
	SHA256 string
	Size   int64
}

// NotAdmittedError says why a clean entry is not admitted now.
type NotAdmittedError struct {
	ID     string
	Stage  Stage
	Reason string
}

func (e *NotAdmittedError) Error() string {
	if e.Reason == "" {
		return fmt.Sprintf("clean entry %s is %s", shortSHA(e.ID), e.Stage)
	}
	return fmt.Sprintf("clean entry %s is %s: %s", shortSHA(e.ID), e.Stage, e.Reason)
}

// AdmittedEntry returns the clean entry id if the store admits it at the
// moment at, re-derived from its files through the gate's checks. An id that
// names no clean entry is ErrNoModel; an entry that is not admitted is a
// *NotAdmittedError naming its stage and why. A clean entry that is a
// symlink is not an entry.
func (s *Store) AdmittedEntry(id string, at time.Time) (*Admitted, error) {
	if !hexSHA256.MatchString(id) {
		return nil, ErrNoModel
	}
	if fi, err := os.Lstat(s.CleanPath(id)); err != nil || !fi.IsDir() {
		return nil, ErrNoModel
	}
	m, d := s.derive(cleanDir, id, at)
	if m.Stage != StageApproved || d == nil {
		return nil, &NotAdmittedError{ID: id, Stage: m.Stage, Reason: m.StageReason}
	}
	refuse := func(why string) (*Admitted, error) {
		return nil, &NotAdmittedError{ID: id, Stage: StageDoesNotVerify, Reason: why}
	}
	if m.ArtifactPath == "" {
		return refuse("the clean entry does not hold exactly one artifact beside its attestation")
	}
	a := &Admitted{ID: id, Name: filepath.Base(m.ArtifactPath), Document: d, State: m.PromotionState, Issuer: m.Issuer}
	if m.AcceptanceExpires != "" {
		exp, err := time.Parse(time.RFC3339, m.AcceptanceExpires)
		if err != nil {
			return refuse(fmt.Sprintf("acceptance expiry %q cannot be enforced", m.AcceptanceExpires))
		}
		a.Expires = exp
	}
	art, err := os.Lstat(m.ArtifactPath)
	if err != nil {
		return refuse(err.Error())
	}
	if len(d.Artifact.Files) > 0 {
		if !art.IsDir() {
			return refuse("the attestation is for a model directory, but " + a.Name + " is not a directory")
		}
		a.Directory = true
		seen := map[string]bool{}
		for _, f := range d.Artifact.Files {
			if err := safeRepoPath(f.Path); err != nil || seen[f.Path] || !hexSHA256.MatchString(f.SHA256) || f.SizeBytes < 0 {
				return refuse(fmt.Sprintf("the attestation lists a file it cannot serve: %q", f.Path))
			}
			seen[f.Path] = true
			a.Files = append(a.Files, AdmittedFile{Path: f.Path, SHA256: f.SHA256, Size: f.SizeBytes})
		}
	} else {
		if !art.Mode().IsRegular() {
			return refuse(a.Name + " is not a regular file")
		}
		a.Files = []AdmittedFile{{Path: a.Name, SHA256: id, Size: d.Artifact.SizeBytes}}
	}
	sort.Slice(a.Files, func(i, j int) bool { return a.Files[i].Path < a.Files[j].Path })
	return a, nil
}

// AdmittedEntries lists the clean entries the store admits at the moment
// at, in id order, and why each other clean entry is not admitted. Names in
// clean/ that are not 64-hex directories are skipped, as Models skips them.
func (s *Store) AdmittedEntries(at time.Time) ([]*Admitted, []*NotAdmittedError, error) {
	entries, err := os.ReadDir(s.cleanRoot())
	if err != nil {
		return nil, nil, fmt.Errorf("read %s: %w", cleanDir, err)
	}
	var ok []*Admitted
	var not []*NotAdmittedError
	for _, e := range entries {
		if !e.IsDir() || !hexSHA256.MatchString(e.Name()) {
			continue
		}
		a, err := s.AdmittedEntry(e.Name(), at)
		var na *NotAdmittedError
		switch {
		case err == nil:
			ok = append(ok, a)
		case errors.As(err, &na):
			not = append(not, na)
		}
	}
	return ok, not, nil
}

var hubRepoID = regexp.MustCompile(`^` + repoPart + `/` + repoPart + `$`)

// RepoID is the hub repo id (org/name) the attestation records the artifact
// came from, from its repo_url, or "" when it records none. It is a label the
// signer vouched for, not a check: the bytes are bound by the hash. A repo id
// in the hash namespace is not one, so it cannot shadow an entry's hash.
func (a *Admitted) RepoID() string {
	u, err := url.Parse(strings.TrimSpace(a.Document.Artifact.RepoURL))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return ""
	}
	p := strings.TrimSuffix(strings.TrimPrefix(u.Path, "/"), "/")
	if !hubRepoID.MatchString(p) || hasDotDot(p) || strings.HasPrefix(p, HashNamespace+"/") {
		return ""
	}
	return p
}

// Revision is the entry's 40-hex revision id: the commit the attestation
// records the bytes came from, or, for an entry that records none, the first
// 40 hex digits of its hash. The second is not a git commit; it is shaped
// like one because hub clients pin and cache by a 40-hex commit.
func (a *Admitted) Revision() string {
	if c := strings.ToLower(strings.TrimSpace(a.Document.Artifact.CommitSHA)); commitID.MatchString(c) {
		return c
	}
	return a.ID[:40]
}

// File returns the attested file at path, if the attestation lists one.
func (a *Admitted) File(path string) (AdmittedFile, bool) {
	i := sort.Search(len(a.Files), func(i int) bool { return a.Files[i].Path >= path })
	if i < len(a.Files) && a.Files[i].Path == path {
		return a.Files[i], true
	}
	return AdmittedFile{}, false
}

// ErrNotServable marks a file of an admitted entry that cannot be opened as
// the attested file: not listed, missing, a symlink, or not a regular file.
var ErrNotServable = errors.New("not a servable file of the entry")

// OpenAdmitted opens one of an admitted entry's files for reading. path must
// be a path the attestation lists; it is never joined to the disk as given.
// The file is opened beneath clean/<id>/ through os.Root, so no name
// resolves outside the entry, and a symlink anywhere on the way, or anything
// but a regular file, is refused even inside it: promote writes regular files
// only, so a symlink in clean/ is not what was attested.
func (s *Store) OpenAdmitted(a *Admitted, path string) (*os.File, error) {
	if !hexSHA256.MatchString(a.ID) {
		return nil, ErrNoModel
	}
	if _, ok := a.File(path); !ok {
		return nil, fmt.Errorf("%w: %q is not a file its attestation lists", ErrNotServable, path)
	}
	rel := a.Name
	if a.Directory {
		rel = a.Name + "/" + path
	}
	if err := safeRepoPath(rel); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotServable, err)
	}
	root, err := os.OpenRoot(s.CleanPath(a.ID))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	last, err := noSymlinks(root, rel)
	if err != nil {
		return nil, err
	}
	return openBeneath(root, rel, last)
}

// noSymlinks walks rel beneath root without following links, and returns
// the final element, which must be a regular file. Every element before it
// must be a directory.
func noSymlinks(root *os.Root, rel string) (fs.FileInfo, error) {
	segs := strings.Split(rel, "/")
	var fi fs.FileInfo
	for i := range segs {
		p := filepath.Join(segs[:i+1]...)
		var err error
		if fi, err = root.Lstat(p); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrNotServable, err)
		}
		switch {
		case fi.Mode()&fs.ModeSymlink != 0:
			return nil, fmt.Errorf("%w: %s is a symlink", ErrNotServable, filepath.ToSlash(p))
		case i < len(segs)-1 && !fi.IsDir():
			return nil, fmt.Errorf("%w: %s is not a directory", ErrNotServable, filepath.ToSlash(p))
		case i == len(segs)-1 && !fi.Mode().IsRegular():
			return nil, fmt.Errorf("%w: %s is not a regular file", ErrNotServable, filepath.ToSlash(p))
		}
	}
	return fi, nil
}

// openBeneath opens rel through root, which refuses any name that resolves
// outside it, and checks the open file is the regular file want: a swap
// between the walk and the open is refused, not served.
func openBeneath(root *os.Root, rel string, want fs.FileInfo) (*os.File, error) {
	f, err := root.Open(filepath.FromSlash(rel))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotServable, err)
	}
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || (want != nil && !os.SameFile(fi, want)) {
		f.Close()
		return nil, fmt.Errorf("%w: %s changed while it was opened", ErrNotServable, rel)
	}
	return f, nil
}
