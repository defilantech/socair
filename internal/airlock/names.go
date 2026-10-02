package airlock

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// Every name that reaches a filesystem path or a hub URL comes from a caller:
// a CLI flag or an API body. Each is checked for shape at the boundary, and a
// resolved path is checked to stay under its root, so no input walks out of
// the store or the cache.

var (
	hexSHA256   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	repoPart    = `[A-Za-z0-9][A-Za-z0-9._-]*`
	repoID      = regexp.MustCompile(`^(` + repoPart + `/)?` + repoPart + `$`)
	revisionRef = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)
)

// ValidSHA256 reports whether sha, once normalized, is a 64-hex digest.
func ValidSHA256(sha string) error {
	if !hexSHA256.MatchString(normalizeSHA(sha)) {
		return errors.New("an expected 64-hex artifact hash is required")
	}
	return nil
}

// validRepo accepts a hub repo id: "name" or "org/name".
func validRepo(repo string) error {
	if !repoID.MatchString(repo) || hasDotDot(repo) {
		return fmt.Errorf("repo %q is not a hub repo id (org/name)", repo)
	}
	return nil
}

// validRevision accepts a branch, tag, commit, or ref such as refs/pr/1.
func validRevision(rev string) error {
	if !revisionRef.MatchString(rev) || strings.HasPrefix(rev, "/") || hasDotDot(rev) {
		return fmt.Errorf("revision %q is not a branch, tag, or commit", rev)
	}
	return nil
}

// validFileName accepts one path element: no separators, not "." or "..".
func validFileName(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) || strings.ContainsRune(name, 0) {
		return fmt.Errorf("artifact file %q must be a plain file name", name)
	}
	return nil
}

func hasDotDot(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." || seg == "." {
			return true
		}
	}
	return false
}

// within reports whether p resolves under root.
func within(root, p string) bool {
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return false
	}
	return rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// StagingFile is the pull destination for one artifact file under its hash. It
// refuses a hash that is not 64 hex and a file name that is not a plain name,
// so the destination cannot leave the staging root.
func (s *Store) StagingFile(sha, file string) (string, error) {
	if err := ValidSHA256(sha); err != nil {
		return "", err
	}
	if err := validFileName(file); err != nil {
		return "", err
	}
	p := filepath.Join(s.StagingPath(sha), file)
	if !within(s.stagingRoot(), p) {
		return "", fmt.Errorf("staging path %q escapes the store", p)
	}
	return p, nil
}
