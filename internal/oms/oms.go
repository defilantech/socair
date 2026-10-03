// Package oms verifies OpenSSF Model Signing (OMS) signatures, offline.
//
// An OMS signature (model_signing v1.0, sigstore/model-transparency) is a
// Sigstore bundle over a DSSE envelope whose payload is an in-toto Statement
// with predicate type https://model_signing/signature/v1.0. The predicate
// lists every file of the model with its SHA-256; the one subject is the
// SHA-256 of those digests' raw bytes, concatenated in name order.
//
// This package verifies bundles signed with an elliptic-curve key or a
// certificate chained to a PKI root, against keys and roots the operator
// supplies, using only the standard library. There is no default trust: a
// signature from a key nobody configured proves nothing, so it is reported
// unverified, never verified and never invalid. Keyless Sigstore bundles
// (Fulcio certificates and a transparency log) are recognized and reported
// unverified, as keyless verification is not built.
//
// A verified signature proves the files are the ones the key holder signed.
// It is a statement of origin and integrity, never of safety.
package oms

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Format constants from model_signing v1.x.
const (
	BundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"
	PayloadType     = "application/vnd.in-toto+json"
	StatementType   = "https://in-toto.io/Statement/v1"
	PredicateType   = "https://model_signing/signature/v1.0"
	// predicateLegacy is the pre-1.0 format, signed over a different
	// encoding; it is recognized and reported unverified.
	predicateLegacy = "https://model_signing/Digests/v0.1"
)

// MaxBundle bounds a signature file read into memory.
const MaxBundle = 64 << 20

// States of a signature check.
const (
	Verified   = "verified"
	Invalid    = "invalid"
	Unverified = "unverified"
)

// Trust is the operator's trust policy for publisher signatures.
type Trust struct {
	// Keys are trusted publisher public keys, by the hint OMS records in a
	// key-signed bundle: the SHA-256 of the key's PEM (SubjectPublicKeyInfo)
	// text. The SHA-256 of the DER encoding is also accepted.
	Keys map[string]*ecdsa.PublicKey
	// Roots are trusted certificate authorities; nil when none were given.
	Roots *x509.CertPool
}

// Empty reports whether the policy trusts nothing.
func (t Trust) Empty() bool { return len(t.Keys) == 0 && t.Roots == nil }

// LoadTrust reads trusted keys and roots. Each path is a PEM file or a
// directory of PEM files; empty means none.
func LoadTrust(keysPath, rootsPath string) (Trust, error) {
	t := Trust{Keys: map[string]*ecdsa.PublicKey{}}
	if keysPath != "" {
		blocks, err := pemBlocks(keysPath)
		if err != nil {
			return t, fmt.Errorf("publisher keys: %w", err)
		}
		for _, b := range blocks {
			if b.Type != "PUBLIC KEY" {
				continue
			}
			k, err := x509.ParsePKIXPublicKey(b.Bytes)
			if err != nil {
				return t, fmt.Errorf("publisher keys: %w", err)
			}
			ek, ok := k.(*ecdsa.PublicKey)
			if !ok || hashFor(ek) == 0 {
				return t, errors.New("publisher keys: OMS keys are ECDSA on P-256, P-384, or P-521")
			}
			t.Keys[KeyHint(b.Bytes)] = ek
			der := sha256.Sum256(b.Bytes)
			t.Keys[hex.EncodeToString(der[:])] = ek
		}
		if len(t.Keys) == 0 {
			return t, fmt.Errorf("publisher keys: no PUBLIC KEY block in %s", keysPath)
		}
	}
	if rootsPath != "" {
		blocks, err := pemBlocks(rootsPath)
		if err != nil {
			return t, fmt.Errorf("publisher roots: %w", err)
		}
		pool := x509.NewCertPool()
		n := 0
		for _, b := range blocks {
			if b.Type != "CERTIFICATE" {
				continue
			}
			c, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				return t, fmt.Errorf("publisher roots: %w", err)
			}
			pool.AddCert(c)
			n++
		}
		if n == 0 {
			return t, fmt.Errorf("publisher roots: no CERTIFICATE block in %s", rootsPath)
		}
		t.Roots = pool
	}
	return t, nil
}

// KeyHint is the identifier model_signing records for a public key: the
// SHA-256 of its PEM-encoded SubjectPublicKeyInfo, given its DER bytes.
func KeyHint(der []byte) string {
	sum := sha256.Sum256(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	return hex.EncodeToString(sum[:])
}

func pemBlocks(p string) ([]*pem.Block, error) {
	var files []string
	fi, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if fi.IsDir() {
		entries, err := os.ReadDir(p)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if !e.IsDir() {
				files = append(files, filepath.Join(p, e.Name()))
			}
		}
		sort.Strings(files)
	} else {
		files = []string{p}
	}
	var out []*pem.Block
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		for {
			var blk *pem.Block
			blk, b = pem.Decode(b)
			if blk == nil {
				break
			}
			out = append(out, blk)
		}
	}
	return out, nil
}

// Resource is one signed file, or one shard of a file.
type Resource struct {
	Name      string `json:"name"`
	Algorithm string `json:"algorithm"`
	Digest    string `json:"digest"`
}

// Manifest is the signed content of an OMS signature.
type Manifest struct {
	ModelName   string
	RootDigest  string
	Method      string // "files" or "shards"
	HashType    string
	ShardSize   int64
	IgnorePaths []string
	Resources   []Resource
}

// Outcome is the result of checking one signature.
type Outcome struct {
	State string
	// Method is how it was signed: "key", "certificate", "keyless", or "".
	Method string
	// Signer names a verified or claimed signer: a key fingerprint, or a
	// certificate's subject.
	Signer string
	// Detail says why, for an invalid or unverified signature.
	Detail   string
	Manifest *Manifest
	// Recognized is false when the file is not a Sigstore DSSE bundle at
	// all (a minisign or GPG .sig), so it is not an OMS signature to report.
	Recognized bool
}

type bundle struct {
	MediaType            string `json:"mediaType"`
	VerificationMaterial struct {
		PublicKey *struct {
			Hint string `json:"hint"`
		} `json:"publicKey"`
		X509CertificateChain *struct {
			Certificates []struct {
				RawBytes string `json:"rawBytes"`
			} `json:"certificates"`
		} `json:"x509CertificateChain"`
		Certificate *struct {
			RawBytes string `json:"rawBytes"`
		} `json:"certificate"`
		TlogEntries []json.RawMessage `json:"tlogEntries"`
	} `json:"verificationMaterial"`
	DSSEEnvelope *struct {
		Payload     string `json:"payload"`
		PayloadType string `json:"payloadType"`
		Signatures  []struct {
			Sig   string `json:"sig"`
			KeyID string `json:"keyid"`
		} `json:"signatures"`
	} `json:"dsseEnvelope"`
}

type statement struct {
	Type          string `json:"_type"`
	PredicateType string `json:"predicateType"`
	Subject       []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	Predicate struct {
		Serialization map[string]any `json:"serialization"`
		Resources     []Resource     `json:"resources"`
	} `json:"predicate"`
}

// Verify checks a signature against the trust policy and returns the signed
// manifest when the signer is trusted. It does not look at the model's files;
// CheckFiles does.
func Verify(raw []byte, trust Trust) Outcome {
	o := verify(raw, trust)
	var probe struct {
		DSSEEnvelope json.RawMessage `json:"dsseEnvelope"`
	}
	if json.Unmarshal(raw, &probe) == nil && len(probe.DSSEEnvelope) > 0 {
		o.Recognized = true
	}
	return o
}

func verify(raw []byte, trust Trust) Outcome {
	unverified := func(method, signer, why string) Outcome {
		return Outcome{State: Unverified, Method: method, Signer: signer, Detail: why}
	}
	var b bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return unverified("", "", "the signature file is not a Sigstore bundle: "+err.Error())
	}
	if b.DSSEEnvelope == nil {
		return unverified("", "", "the bundle carries no DSSE envelope, so it is not an OMS signature")
	}
	env := b.DSSEEnvelope
	if b.MediaType != BundleMediaType {
		return unverified("", "", fmt.Sprintf("bundle media type %q is not the OMS v1 bundle format", b.MediaType))
	}
	if env.PayloadType != PayloadType || len(env.Signatures) != 1 {
		return unverified("", "", "the envelope is not a single-signature in-toto payload")
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return unverified("", "", "the payload is not base64")
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
	if err != nil {
		return unverified("", "", "the signature is not base64")
	}
	var st statement
	if err := json.Unmarshal(payload, &st); err != nil {
		return unverified("", "", "the payload is not an in-toto statement")
	}
	if st.PredicateType == predicateLegacy {
		return unverified("", "", "a pre-1.0 model_signing signature (Digests/v0.1), signed over an encoding this verifier does not reproduce")
	}
	if st.Type != StatementType || st.PredicateType != PredicateType {
		return unverified("", "", fmt.Sprintf("predicate type %q is not OMS v1.0", st.PredicateType))
	}

	// Who claims to have signed it, and do we trust them?
	vm := b.VerificationMaterial
	var key *ecdsa.PublicKey
	method, signer := "", ""
	switch {
	case vm.PublicKey != nil:
		method = "key"
		hint := strings.ToLower(vm.PublicKey.Hint)
		signer = "key sha256:" + hint
		k, ok := trust.Keys[hint]
		if !ok {
			// The hint is unsigned; try every trusted key before deciding
			// the signer is unknown.
			for id, tk := range trust.Keys {
				if verifySig(tk, payload, sig) {
					k, ok, signer = tk, true, "key sha256:"+id
					break
				}
			}
		}
		if !ok {
			return unverified(method, signer, "signed by a key that is not in the publisher trust policy (SOCAIR_PUBLISHER_KEYS)")
		}
		key = k
	case vm.X509CertificateChain != nil || vm.Certificate != nil:
		certs, err := chainOf(vm.X509CertificateChain, vm.Certificate)
		if err != nil {
			return unverified("certificate", "", err.Error())
		}
		leaf := certs[0]
		signer = "certificate " + subjectOf(leaf)
		method = "certificate"
		if len(vm.TlogEntries) > 0 || isFulcio(leaf) {
			return unverified("keyless", signer, "a keyless Sigstore signature (Fulcio certificate, transparency log); keyless verification is not built")
		}
		if trust.Roots == nil {
			return unverified(method, signer, "signed with a certificate, and no publisher roots are configured (SOCAIR_PUBLISHER_ROOTS)")
		}
		inter := x509.NewCertPool()
		for _, c := range certs[1:] {
			inter.AddCert(c)
		}
		// As the reference verifier does, the chain is evaluated at the
		// leaf's issue time: a short-lived signing certificate signs once.
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: trust.Roots, Intermediates: inter, CurrentTime: leaf.NotBefore,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
			return unverified(method, signer, "the certificate does not chain to a configured publisher root: "+err.Error())
		}
		if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 && !hasCodeSigning(leaf) {
			return Outcome{State: Invalid, Method: method, Signer: signer, Detail: "the signing certificate is not issued for signing (no digitalSignature key usage or codeSigning extended key usage)"}
		}
		ek, ok := leaf.PublicKey.(*ecdsa.PublicKey)
		if !ok || hashFor(ek) == 0 {
			return Outcome{State: Invalid, Method: method, Signer: signer, Detail: "the signing certificate's key is not ECDSA on P-256, P-384, or P-521"}
		}
		key = ek
	default:
		return unverified("", "", "the bundle names no key or certificate")
	}

	// A trusted signer from here on: a failure is evidence, not a gap.
	invalid := func(why string) Outcome {
		return Outcome{State: Invalid, Method: method, Signer: signer, Detail: why}
	}
	if !verifySig(key, payload, sig) {
		return invalid("the signature does not verify against the trusted " + method)
	}
	m, err := manifestOf(st)
	if err != nil {
		return invalid(err.Error())
	}
	return Outcome{State: Verified, Method: method, Signer: signer, Manifest: m}
}

// verifySig checks an ECDSA signature over the DSSE pre-authentication
// encoding, hashed as OMS signs: SHA-256, -384, or -512 by curve.
func verifySig(k *ecdsa.PublicKey, payload, sig []byte) bool {
	h := hashFor(k)
	if h == 0 {
		return false
	}
	var hh hash.Hash
	switch h {
	case crypto.SHA256:
		hh = sha256.New()
	case crypto.SHA384:
		hh = sha512.New384()
	default:
		hh = sha512.New()
	}
	hh.Write(pae(payload))
	return ecdsa.VerifyASN1(k, hh.Sum(nil), sig)
}

func hashFor(k *ecdsa.PublicKey) crypto.Hash {
	switch k.Curve {
	case elliptic.P256():
		return crypto.SHA256
	case elliptic.P384():
		return crypto.SHA384
	case elliptic.P521():
		return crypto.SHA512
	}
	return 0
}

// pae is DSSE's pre-authentication encoding.
func pae(payload []byte) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "DSSEv1 %d %s %d ", len(PayloadType), PayloadType, len(payload))
	b.Write(payload)
	return b.Bytes()
}

func chainOf(chain *struct {
	Certificates []struct {
		RawBytes string `json:"rawBytes"`
	} `json:"certificates"`
}, single *struct {
	RawBytes string `json:"rawBytes"`
}) ([]*x509.Certificate, error) {
	var raws []string
	if chain != nil {
		for _, c := range chain.Certificates {
			raws = append(raws, c.RawBytes)
		}
	} else {
		raws = []string{single.RawBytes}
	}
	if len(raws) == 0 || len(raws) > 10 {
		return nil, errors.New("the certificate chain is empty or implausibly long")
	}
	out := make([]*x509.Certificate, 0, len(raws))
	for _, r := range raws {
		der, err := base64.StdEncoding.DecodeString(r)
		if err != nil {
			return nil, errors.New("a certificate is not base64")
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("a certificate does not parse: %w", err)
		}
		out = append(out, c)
	}
	return out, nil
}

func subjectOf(c *x509.Certificate) string {
	s := c.Subject.String()
	if len(c.EmailAddresses) > 0 {
		s += " <" + strings.Join(c.EmailAddresses, ", ") + ">"
	}
	for _, u := range c.URIs {
		s += " " + u.String()
	}
	if s == "" {
		s = "(empty subject)"
	}
	return s + ", issued by " + c.Issuer.String()
}

// isFulcio recognizes a Sigstore Fulcio certificate by its OIDC issuer
// extension (1.3.6.1.4.1.57264.1.1 or .1.8).
func isFulcio(c *x509.Certificate) bool {
	for _, e := range c.Extensions {
		id := e.Id.String()
		if id == "1.3.6.1.4.1.57264.1.1" || id == "1.3.6.1.4.1.57264.1.8" {
			return true
		}
	}
	return false
}

func hasCodeSigning(c *x509.Certificate) bool {
	for _, u := range c.ExtKeyUsage {
		if u == x509.ExtKeyUsageCodeSigning {
			return true
		}
	}
	return false
}

// manifestOf reads the signed manifest and checks it is self-consistent: the
// subject digest is the SHA-256 of the resource digests, in order.
func manifestOf(st statement) (*Manifest, error) {
	if len(st.Subject) != 1 {
		return nil, fmt.Errorf("the statement has %d subjects, want 1", len(st.Subject))
	}
	m := &Manifest{ModelName: st.Subject[0].Name, RootDigest: strings.ToLower(st.Subject[0].Digest["sha256"]), Resources: st.Predicate.Resources}
	ser := st.Predicate.Serialization
	m.Method, _ = ser["method"].(string)
	m.HashType, _ = ser["hash_type"].(string)
	if ss, ok := ser["shard_size"].(float64); ok {
		m.ShardSize = int64(ss)
	}
	if ip, ok := ser["ignore_paths"].([]any); ok {
		for _, p := range ip {
			if s, ok := p.(string); ok {
				m.IgnorePaths = append(m.IgnorePaths, s)
			}
		}
	}
	h := sha256.New()
	for _, r := range m.Resources {
		d, err := hex.DecodeString(r.Digest)
		if err != nil {
			return nil, fmt.Errorf("resource %q has a digest that is not hex", r.Name)
		}
		h.Write(d)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != m.RootDigest {
		return nil, fmt.Errorf("the signed manifest is inconsistent: its resources hash to %s, but the subject says %s", got, m.RootDigest)
	}
	return m, nil
}

// shardName parses a "path:start:end" shard resource name.
func shardName(name string) (string, int64, int64, bool) {
	i := strings.LastIndex(name, ":")
	if i < 0 {
		return "", 0, 0, false
	}
	j := strings.LastIndex(name[:i], ":")
	if j < 0 {
		return "", 0, 0, false
	}
	start, err1 := strconv.ParseInt(name[j+1:i], 10, 64)
	end, err2 := strconv.ParseInt(name[i+1:], 10, 64)
	if err1 != nil || err2 != nil || start < 0 || end < start {
		return "", 0, 0, false
	}
	return name[:j], start, end, true
}
