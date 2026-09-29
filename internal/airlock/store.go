// Package airlock is the controlled junction between untrusted egress and the
// on-prem clean store. A pull lands in staging; only a promotion moves bytes
// across into the clean store, and only a validating attestation that
// authorizes the artifact's own hash is a ticket to cross.
package airlock

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Store is a content-addressed clean store with a staging area.
//
// The store is keyed by artifact hash: the hash is the ticket, so promotion is
// idempotent and the store holds one identity per artifact. "In the clean
// store" does not mean "clean": a conditional promotion crosses too, so any
// listing or query of the store must carry the attestation state, never
// assume a clean entry.
type Store struct {
	Root string
}

// ErrNotInitialized is returned when a store directory was not created by Init.
var ErrNotInitialized = errors.New("airlock store not initialized")

const (
	stagingDir = "incoming"
	cleanDir   = "clean"
	logName    = "log.jsonl"
)

// Init creates the store layout and returns it. It is idempotent.
func Init(root string) (*Store, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("store root is empty")
	}
	s := &Store{Root: root}
	for _, d := range []string{s.stagingRoot(), s.cleanRoot()} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, fmt.Errorf("create store dir: %w", err)
		}
	}
	return s, nil
}

// Open returns an existing store, or ErrNotInitialized if its layout is absent.
func Open(root string) (*Store, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("store root is empty")
	}
	s := &Store{Root: root}
	for _, d := range []string{s.stagingRoot(), s.cleanRoot()} {
		fi, err := os.Stat(d)
		if err != nil || !fi.IsDir() {
			return nil, fmt.Errorf("%w: %s", ErrNotInitialized, root)
		}
	}
	return s, nil
}

func (s *Store) stagingRoot() string { return filepath.Join(s.Root, stagingDir) }
func (s *Store) cleanRoot() string   { return filepath.Join(s.Root, cleanDir) }

// LogPath is the append-only activity log.
func (s *Store) LogPath() string { return filepath.Join(s.Root, logName) }

// StagingPath is the pull destination for an artifact hash.
func (s *Store) StagingPath(sha string) string {
	return filepath.Join(s.stagingRoot(), normalizeSHA(sha))
}

// CleanPath is the clean-store directory for an artifact hash.
func (s *Store) CleanPath(sha string) string {
	return filepath.Join(s.cleanRoot(), normalizeSHA(sha))
}

// Place copies src into dstDir and returns the destination file path. It writes
// to a temp file in the destination directory and renames it into place, so a
// crash mid-copy never leaves a half-promoted artifact.
func (s *Store) Place(src, dstDir string) (string, error) {
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return "", fmt.Errorf("create destination: %w", err)
	}
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()

	dst := filepath.Join(dstDir, filepath.Base(src))
	if err := writeTemp(dstDir, dst, in); err != nil {
		return "", err
	}
	return dst, nil
}

// WriteFile writes b to path through a temp file and a rename.
func (s *Store) WriteFile(path string, b []byte) error {
	return writeBytes(filepath.Dir(path), path, b)
}

// writeBytes writes b to dst through a temp file in dir and a rename.
func writeBytes(dir, dst string, b []byte) error {
	return writeTemp(dir, dst, bytes.NewReader(b))
}

// writeTemp copies r to a temp file in dir and renames it over dst.
func writeTemp(dir, dst string, r io.Reader) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create destination: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".socair-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // a no-op once the rename lands

	if _, err := io.Copy(tmp, r); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, dst)
}

// normalizeSHA lowercases a hash for use as a store key.
func normalizeSHA(sha string) string { return strings.ToLower(strings.TrimSpace(sha)) }
