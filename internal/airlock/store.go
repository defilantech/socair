// Package airlock is the controlled junction between untrusted egress and the
// on-prem clean store. A pull lands in staging; only a promotion moves bytes
// across into the clean store, and only a validating attestation that
// authorizes the artifact's own hash is a ticket to cross.
package airlock

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/defilantech/socair/internal/attest"
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
	trustDir   = "trusted-keys"
	// acceptorDir holds the keys that may sign acceptances of untested
	// surfaces, kept apart from trustDir: the operator who signs a report
	// does not accept its gaps.
	acceptorDir = "acceptor-keys"
	logName     = "log.jsonl"
)

// Init creates the store layout and returns it. It is idempotent.
func Init(root string) (*Store, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("store root is empty")
	}
	s := &Store{Root: root}
	for _, d := range []string{s.stagingRoot(), s.cleanRoot(), s.TrustPath(), s.AcceptorPath()} {
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

// TrustPath is the store's trust policy: the public keys whose signatures
// admit an artifact to the clean store.
func (s *Store) TrustPath() string { return filepath.Join(s.Root, trustDir) }

// TrustedKeys loads the store's trust policy. No trusted key is an error that
// says how to add one, because a store that trusts nobody refuses everything.
func (s *Store) TrustedKeys() (attest.Keyring, error) {
	ring, _, err := s.TrustedIssuers()
	return ring, err
}

// TrustedIssuers is TrustedKeys with the issuer name the store gives each
// key: who the store says holds it.
func (s *Store) TrustedIssuers() (attest.Keyring, attest.Names, error) {
	ring, names, err := attest.LoadNamedKeyring(s.TrustPath())
	if err != nil {
		return nil, nil, fmt.Errorf("no trusted signing key in %s; add one with `socair airlock trust add <key.pub>`: %v", s.TrustPath(), err)
	}
	return ring, names, nil
}

// AcceptorPath holds the public keys whose signed acceptances of untested
// surfaces the airlock honours.
func (s *Store) AcceptorPath() string { return filepath.Join(s.Root, acceptorDir) }

// AcceptorKeys loads the acceptor keys. None is an error that says how to add
// one: without them, no conditional attestation crosses.
func (s *Store) AcceptorKeys() (attest.Keyring, error) {
	ring, err := attest.LoadKeyring(s.AcceptorPath())
	if err != nil {
		return nil, fmt.Errorf("no acceptor key in %s; add one with `socair airlock trust add --acceptor <key.pub>`: %v", s.AcceptorPath(), err)
	}
	return ring, nil
}

// TrustAcceptor adds a public key to the acceptor keys. A key that signs
// attestations is refused: one key may not both report and accept the gaps.
func (s *Store) TrustAcceptor(pubPath string) (string, error) {
	id, _, err := attest.LoadPublicKey(pubPath)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(filepath.Join(s.TrustPath(), id+".pub")); err == nil {
		return "", fmt.Errorf("key %s already signs attestations here; an acceptor key must be a different key", attest.ShortID(id))
	}
	b, err := os.ReadFile(pubPath)
	if err != nil {
		return "", err
	}
	if err := writeBytes(s.AcceptorPath(), filepath.Join(s.AcceptorPath(), id+".pub"), b); err != nil {
		return "", err
	}
	return id, s.Record(Event{Action: ActionTrust, Outcome: OutcomeOK, Detail: "trusted acceptor key " + id})
}

// Trust adds a public key to the store's trust policy, stored under its key
// id so the same key is never listed twice. An acceptor key is refused.
func (s *Store) Trust(pubPath string) (string, error) { return s.TrustAs(pubPath, "") }

// TrustAs is Trust with the issuer name the store gives the key, replacing
// whatever name the key file declares. Empty keeps the file's name. An
// attestation signed with the key must then claim this issuer.
func (s *Store) TrustAs(pubPath, issuer string) (string, error) {
	id, _, err := attest.LoadPublicKey(pubPath)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(filepath.Join(s.AcceptorPath(), id+".pub")); err == nil {
		return "", fmt.Errorf("key %s is an acceptor key here; a signing key must be a different key", attest.ShortID(id))
	}
	b, err := os.ReadFile(pubPath)
	if err != nil {
		return "", err
	}
	if issuer != "" {
		if b, err = attest.WithIssuer(b, issuer); err != nil {
			return "", err
		}
	}
	if err := writeBytes(s.TrustPath(), filepath.Join(s.TrustPath(), id+".pub"), b); err != nil {
		return "", err
	}
	_, _, name, err := attest.LoadNamedPublicKey(filepath.Join(s.TrustPath(), id+".pub"))
	if err != nil {
		return "", err
	}
	detail := "trusted signing key " + id
	if name != "" {
		detail += " as issuer " + name
	}
	return id, s.Record(Event{Action: ActionTrust, Outcome: OutcomeOK, Detail: detail})
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

// promoteOpened is a test hook, called once the promotion has opened the
// artifact and before it reads a byte.
var promoteOpened func()

type hashMismatchError struct{ got, want string }

func (e *hashMismatchError) Error() string {
	return fmt.Sprintf("artifact hashes to %s, want %s", e.got, e.want)
}

// placeVerified copies src into dstDir, hashing the bytes as they are copied,
// and renames the copy into place only if they hash to wantSHA. The stored
// bytes are the verified bytes, whatever happens to src during the copy.
func (s *Store) placeVerified(src, dstDir, wantSHA string) (string, error) {
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return "", fmt.Errorf("create destination: %w", err)
	}
	in, err := os.Open(src)
	if err != nil {
		return "", fmt.Errorf("open artifact %q: %w", src, err)
	}
	defer in.Close()
	if promoteOpened != nil {
		promoteOpened()
	}

	tmp, err := os.CreateTemp(dstDir, ".socair-*")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // a no-op once the rename lands

	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), in); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != normalizeSHA(wantSHA) {
		return "", &hashMismatchError{got: got, want: normalizeSHA(wantSHA)}
	}
	dst := filepath.Join(dstDir, filepath.Base(src))
	if err := os.Rename(tmpName, dst); err != nil {
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
