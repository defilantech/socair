package attest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// PrivateKey is an Ed25519 signing key and its key id.
type PrivateKey struct {
	ID  string
	key ed25519.PrivateKey
}

// Keyring maps key id to a trusted public key.
type Keyring map[string]ed25519.PublicKey

// KeyID is the hex SHA-256 of the key's PKIX DER encoding: stable, and
// derivable from the public key file alone.
func KeyID(pub ed25519.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// GenerateKey writes a new key pair: <prefix>.key (PKCS#8 PEM, mode 0600) and
// <prefix>.pub (PKIX PEM). It refuses to overwrite either file.
func GenerateKey(prefix string) (id string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	id, err = KeyID(pub)
	if err != nil {
		return "", err
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	if err := writeNew(prefix+".key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0o600); err != nil {
		return "", err
	}
	if err := writeNew(prefix+".pub", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o644); err != nil {
		_ = os.Remove(prefix + ".key")
		return "", err
	}
	return id, nil
}

func writeNew(path string, b []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// LoadPrivateKey reads a PKCS#8 PEM Ed25519 private key. It refuses a key
// file that other users can read.
func LoadPrivateKey(path string) (*PrivateKey, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("private key %s is readable by other users (mode %v); chmod 600 it", path, fi.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("%s is not a PEM private key", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s is not an Ed25519 key", path)
	}
	id, err := KeyID(priv.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	return &PrivateKey{ID: id, key: priv}, nil
}

// LoadPublicKey reads a PKIX PEM Ed25519 public key and returns its id.
func LoadPublicKey(path string) (string, ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "PUBLIC KEY" {
		return "", nil, fmt.Errorf("%s is not a PEM public key", path)
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return "", nil, fmt.Errorf("%s: %w", path, err)
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return "", nil, fmt.Errorf("%s is not an Ed25519 key", path)
	}
	id, err := KeyID(pub)
	return id, pub, err
}

// LoadKeyring reads trusted public keys from a .pub file or every *.pub file
// in a directory. An empty keyring is an error: verifying against no keys
// would refuse everything, and that is never what the caller meant.
func LoadKeyring(path string) (Keyring, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	files := []string{path}
	if fi.IsDir() {
		files, _ = filepath.Glob(filepath.Join(path, "*.pub"))
		sort.Strings(files)
	}
	ring := Keyring{}
	for _, f := range files {
		id, pub, err := LoadPublicKey(f)
		if err != nil {
			return nil, err
		}
		ring[id] = pub
	}
	if len(ring) == 0 {
		return nil, errors.New("no trusted keys in " + path)
	}
	return ring, nil
}

// ShortID is a key id cut for display.
func ShortID(id string) string {
	if len(id) > 16 {
		return id[:16]
	}
	return strings.TrimSpace(id)
}
