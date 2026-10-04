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

// PrivateKey is an Ed25519 signing key, its key id, and the issuer name its
// file declares (empty when it declares none).
type PrivateKey struct {
	ID     string
	Issuer string
	key    ed25519.PrivateKey
}

// IssuerPrefix starts the line that names a key's issuer in its PEM files.
// The line sits outside the PEM block, where PEM parsers (Go's, OpenSSL's)
// ignore it, so the key files stay standard.
const IssuerPrefix = "Socair-Issuer:"

// Names maps key id to the issuer name the trust list gives that key.
type Names map[string]string

// issuerOf reads the issuer name a PEM file declares before its block.
func issuerOf(b []byte) string {
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "-----BEGIN") {
			break
		}
		if v, ok := strings.CutPrefix(line, IssuerPrefix); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// ValidIssuer checks an issuer name: one line of printable text.
func ValidIssuer(name string) error {
	if len(name) > 200 || strings.ContainsAny(name, "\r\n") || strings.TrimSpace(name) != name {
		return fmt.Errorf("issuer name %q must be one line of at most 200 characters, without surrounding spaces", name)
	}
	return nil
}

// WithIssuer returns PEM bytes naming issuer: any existing issuer line is
// replaced, and an empty name removes it.
func WithIssuer(pemBytes []byte, issuer string) ([]byte, error) {
	if err := ValidIssuer(issuer); err != nil {
		return nil, err
	}
	var kept []string
	for _, line := range strings.SplitAfter(string(pemBytes), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), IssuerPrefix) {
			kept = append(kept, line)
		}
	}
	out := strings.Join(kept, "")
	if issuer != "" {
		out = IssuerPrefix + " " + issuer + "\n" + out
	}
	return []byte(out), nil
}

// Sign signs msg with the key: the signer Socair's other signed statements
// (feeds) take, without exposing the key itself.
func (k *PrivateKey) Sign(msg []byte) []byte { return ed25519.Sign(k.key, msg) }

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
func GenerateKey(prefix string) (id string, err error) { return GenerateNamedKey(prefix, "") }

// GenerateNamedKey is GenerateKey with an issuer name in both files: the name
// a report signed with the key states as its issuer.
func GenerateNamedKey(prefix, issuer string) (id string, err error) {
	if err := ValidIssuer(issuer); err != nil {
		return "", err
	}
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
	privPEM, _ := WithIssuer(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), issuer)
	pubPEM, _ := WithIssuer(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), issuer)
	if err := writeNew(prefix+".key", privPEM, 0o600); err != nil {
		return "", err
	}
	if err := writeNew(prefix+".pub", pubPEM, 0o644); err != nil {
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
	return &PrivateKey{ID: id, Issuer: issuerOf(b), key: priv}, nil
}

// LoadPublicKey reads a PKIX PEM Ed25519 public key and returns its id.
func LoadPublicKey(path string) (string, ed25519.PublicKey, error) {
	id, pub, _, err := LoadNamedPublicKey(path)
	return id, pub, err
}

// LoadNamedPublicKey is LoadPublicKey with the issuer name the file gives
// the key, empty when it gives none.
func LoadNamedPublicKey(path string) (string, ed25519.PublicKey, string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", nil, "", err
	}
	id, pub, err := parsePublicKey(path, b)
	return id, pub, issuerOf(b), err
}

func parsePublicKey(path string, b []byte) (string, ed25519.PublicKey, error) {
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
	ring, _, err := LoadNamedKeyring(path)
	return ring, err
}

// LoadNamedKeyring is LoadKeyring with the issuer name each trusted key file
// gives its key: the verifier's statement of whose key it is.
func LoadNamedKeyring(path string) (Keyring, Names, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, nil, err
	}
	files := []string{path}
	if fi.IsDir() {
		files, _ = filepath.Glob(filepath.Join(path, "*.pub"))
		sort.Strings(files)
	}
	ring, names := Keyring{}, Names{}
	for _, f := range files {
		id, pub, name, err := LoadNamedPublicKey(f)
		if err != nil {
			return nil, nil, err
		}
		ring[id] = pub
		if name != "" {
			names[id] = name
		}
	}
	if len(ring) == 0 {
		return nil, nil, errors.New("no trusted keys in " + path)
	}
	return ring, names, nil
}

// ShortID is a key id cut for display.
func ShortID(id string) string {
	if len(id) > 16 {
		return id[:16]
	}
	return strings.TrimSpace(id)
}
