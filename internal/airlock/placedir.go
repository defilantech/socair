package airlock

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/defilantech/socair/internal/modeldir"
	"github.com/defilantech/socair/internal/report"
)

// tmpDir holds in-progress copies inside the store, on the same volume as
// incoming/ and clean/, so a finished copy lands with a rename.
const tmpDir = ".tmp"

func (s *Store) tmpRoot() (string, error) {
	p := filepath.Join(s.Root, tmpDir)
	return p, os.MkdirAll(p, 0o700)
}

// dirMismatchError is a model directory whose bytes are not the attested
// ones, naming each file that differs.
type dirMismatchError struct {
	got, want string
	diff      []string
}

func (e *dirMismatchError) Error() string {
	why := "the file list matches but the digest does not"
	if len(e.diff) > 0 {
		why = strings.Join(e.diff, "; ")
	}
	return fmt.Sprintf("model directory hashes to %s but the attestation is for %s: %s", e.got, e.want, why)
}

// placeVerifiedDir copies the model directory src into clean/<sha>/<name>/,
// hashing every file while copying, under the same rules a scan uses (see
// modeldir), and renames the copy into place only if its manifest digest is
// wantSHA. As with a single file, the stored bytes are the verified bytes,
// whatever happens to src during the copy. A repeat promotion replaces the
// stored tree, so one that was altered or deleted is restored.
func (s *Store) placeVerifiedDir(src, clean, name, wantSHA string, attested []report.ArtifactFile) error {
	tmp, err := s.tmpRoot()
	if err != nil {
		return err
	}
	if promoteOpened != nil {
		promoteOpened()
	}
	copyRoot, files, _, cleanup, err := modeldir.Snapshot(src, tmp)
	if err != nil {
		return err
	}
	defer cleanup() // a no-op once the copy is renamed into place

	if got := modeldir.Digest(files); got != normalizeSHA(wantSHA) {
		want := make([]modeldir.File, 0, len(attested))
		for _, f := range attested {
			want = append(want, modeldir.File{Path: f.Path, SHA256: f.SHA256, Size: f.SizeBytes})
		}
		return &dirMismatchError{got: got, want: normalizeSHA(wantSHA), diff: modeldir.Diff(want, files)}
	}
	if err := os.MkdirAll(clean, 0o755); err != nil {
		return err
	}
	return replaceDir(copyRoot, filepath.Join(clean, name), tmp)
}

// replaceDir renames src over dst. An existing dst is first moved aside into
// tmp and removed after, so dst is never a mix of old and new files.
func replaceDir(src, dst, tmp string) error {
	if _, err := os.Lstat(dst); err == nil {
		old, err := os.MkdirTemp(tmp, "replaced-")
		if err != nil {
			return err
		}
		aside := filepath.Join(old, "tree")
		if err := os.Rename(dst, aside); err != nil {
			os.Remove(old)
			return err
		}
		defer removeTree(old)
	}
	return os.Rename(src, dst)
}

// removeTree deletes a tree whose files and directories may be read-only.
func removeTree(p string) {
	_ = filepath.Walk(p, func(path string, info os.FileInfo, err error) error {
		if err == nil && info.IsDir() {
			_ = os.Chmod(path, 0o700)
		}
		return nil
	})
	_ = os.RemoveAll(p)
}
