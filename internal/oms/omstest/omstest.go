// Package omstest makes OpenSSF Model Signing (OMS) signatures, for tests and
// for the conformance harness (tools/oms-conformance). Socair verifies OMS
// signatures; it does not sign models, and nothing else uses this package.
//
// Keys and certificates are generated in code, so no private key is ever
// committed, and a fixture is a model directory and a signature whose bytes
// the test controls.
package omstest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/defilantech/socair/internal/oms"
)

// PKI is a three-level certificate chain, the shape NVIDIA's NGC model
// signatures carry: a self-signed root, an intermediate CA, and a leaf whose
// key signs.
type PKI struct {
	Root, Intermediate, Leaf *x509.Certificate
	LeafKey                  *ecdsa.PrivateKey
}

// NewPKI makes a P-384 chain whose leaf is valid from notBefore to notAfter
// and carries only the digitalSignature key usage, with no extended key
// usage, as NVIDIA's NGC signing certificate does. The CAs are valid for ten
// years either side of the leaf.
func NewPKI(org string, notBefore, notAfter time.Time) (*PKI, error) {
	caFrom, caTo := notBefore.AddDate(-10, 0, 0), notAfter.AddDate(10, 0, 0)
	rootKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	rootTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{Organization: []string{org}, CommonName: org + " Model Signing Root CA"},
		NotBefore: caFrom, NotAfter: caTo, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	root, err := create(rootTpl, rootTpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	icaKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	icaTpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{Organization: []string{org}, CommonName: org + " Model Signing ICA 001"},
		NotBefore: caFrom, NotAfter: caTo, IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	ica, err := create(icaTpl, root, &icaKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	leafTpl := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{Organization: []string{org}, CommonName: org + " Model Signing Issuer 001"},
		NotBefore: notBefore, NotAfter: notAfter, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature}
	leaf, err := create(leafTpl, ica, &leafKey.PublicKey, icaKey)
	if err != nil {
		return nil, err
	}
	return &PKI{Root: root, Intermediate: ica, Leaf: leaf, LeafKey: leafKey}, nil
}

func create(tpl, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) (*x509.Certificate, error) {
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, pub, signer)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// Chain is the certificate chain in bundle order, leaf first, root last, as
// NGC bundles carry it.
func (p *PKI) Chain() [][]byte { return [][]byte{p.Leaf.Raw, p.Intermediate.Raw, p.Root.Raw} }

// RootPEM is the root certificate as an operator would trust it.
func (p *PKI) RootPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.Root.Raw})
}

// Options say how to sign.
type Options struct {
	// Key signs. With no Chain it is the key method, named by its hint.
	Key *ecdsa.PrivateKey
	// Chain, DER and leaf first, makes it the certificate method.
	Chain [][]byte
	// Ignore are paths relative to the model directory left out of the
	// signature and recorded in ignore_paths, beside the OMS default
	// exclusions, which a directory always leaves out.
	Ignore []string
	// NGC shapes the bundle as NVIDIA's NGC signatures are shaped (read from
	// nvidia/tao/dashcamnet:pruned_onnx_v1.0.5 in October 2026): no
	// ignore_paths, allow_symlinks as the string "false", the subject named
	// for the first file, a null keyid, and no tlogEntries.
	NGC bool
}

// Sign signs the model at p, a directory or one file, with the files
// serialization and SHA-256, and returns the bundle bytes. Every file under a
// directory is signed except the ignored paths and the OMS default
// exclusions at its top. A caller writing the signature into the directory
// ignores it, or signs first.
func Sign(p string, o Options) ([]byte, error) {
	if o.Key == nil {
		return nil, errors.New("omstest: no signing key")
	}
	res, ignored, err := resources(p, o.Ignore)
	if err != nil {
		return nil, err
	}
	if len(res) == 0 {
		return nil, errors.New("omstest: nothing to sign")
	}
	h := sha256.New()
	for _, r := range res {
		d, _ := hex.DecodeString(r.Digest)
		h.Write(d)
	}
	ser := map[string]any{"method": "files", "hash_type": "sha256", "allow_symlinks": false}
	name := filepath.Base(filepath.Clean(p))
	if o.NGC {
		ser["allow_symlinks"] = "false"
		name = res[0].Name
	} else if len(ignored) > 0 {
		ser["ignore_paths"] = ignored
	}
	rs := make([]any, len(res))
	for i, r := range res {
		rs[i] = map[string]any{"name": r.Name, "digest": r.Digest, "algorithm": r.Algorithm}
	}
	payload, err := json.Marshal(map[string]any{
		"_type":         oms.StatementType,
		"subject":       []any{map[string]any{"name": name, "digest": map[string]any{"sha256": hex.EncodeToString(h.Sum(nil))}}},
		"predicateType": oms.PredicateType,
		"predicate":     map[string]any{"serialization": ser, "resources": rs},
	})
	if err != nil {
		return nil, err
	}
	sig, err := SignPayload(o.Key, payload)
	if err != nil {
		return nil, err
	}
	var vm map[string]any
	if len(o.Chain) > 0 {
		certs := make([]any, len(o.Chain))
		for i, der := range o.Chain {
			certs[i] = map[string]any{"rawBytes": base64.StdEncoding.EncodeToString(der)}
		}
		vm = map[string]any{"x509CertificateChain": map[string]any{"certificates": certs}}
	} else {
		der, err := x509.MarshalPKIXPublicKey(&o.Key.PublicKey)
		if err != nil {
			return nil, err
		}
		vm = map[string]any{"publicKey": map[string]any{"hint": oms.KeyHint(der)}}
	}
	var keyid any = ""
	if o.NGC {
		keyid = nil
	} else {
		vm["tlogEntries"] = []any{}
	}
	return json.Marshal(map[string]any{
		"mediaType":            oms.BundleMediaType,
		"verificationMaterial": vm,
		"dsseEnvelope": map[string]any{
			"payload":     base64.StdEncoding.EncodeToString(payload),
			"payloadType": oms.PayloadType,
			"signatures":  []any{map[string]any{"sig": base64.StdEncoding.EncodeToString(sig), "keyid": keyid}},
		},
	})
}

// SignPayload signs a DSSE payload as OMS does: ECDSA over the
// pre-authentication encoding, hashed with SHA-256, -384, or -512 by curve.
func SignPayload(k *ecdsa.PrivateKey, payload []byte) ([]byte, error) {
	pae := fmt.Appendf(nil, "DSSEv1 %d %s %d ", len(oms.PayloadType), oms.PayloadType, len(payload))
	pae = append(pae, payload...)
	var sum []byte
	switch k.Curve {
	case elliptic.P256():
		s := sha256.Sum256(pae)
		sum = s[:]
	case elliptic.P384():
		s := sha512.Sum384(pae)
		sum = s[:]
	case elliptic.P521():
		s := sha512.Sum512(pae)
		sum = s[:]
	default:
		return nil, errors.New("omstest: OMS keys are P-256, P-384, or P-521")
	}
	return ecdsa.SignASN1(rand.Reader, k, sum)
}

// resources hashes the model at p. A single file is named by its base name.
func resources(p string, ignore []string) ([]oms.Resource, []string, error) {
	fi, err := os.Stat(p)
	if err != nil {
		return nil, nil, err
	}
	if !fi.IsDir() {
		d, err := digest(p)
		if err != nil {
			return nil, nil, err
		}
		return []oms.Resource{{Name: filepath.Base(p), Algorithm: "sha256", Digest: d}}, nil, nil
	}
	skip := func(rel string) bool {
		for _, ip := range append(append([]string{}, oms.DefaultExclusions...), ignore...) {
			ip = strings.TrimSuffix(path.Clean(ip), "/")
			if rel == ip || strings.HasPrefix(rel, ip+"/") {
				return true
			}
		}
		return false
	}
	var res []oms.Resource
	err = filepath.WalkDir(p, func(fp string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(p, fp)
		if err != nil || rel == "." {
			return err
		}
		rel = filepath.ToSlash(rel)
		if skip(rel) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("omstest: %s is not a regular file", rel)
		}
		sum, err := digest(fp)
		if err != nil {
			return err
		}
		res = append(res, oms.Resource{Name: rel, Algorithm: "sha256", Digest: sum})
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	sort.Slice(res, func(i, j int) bool { return res[i].Name < res[j].Name })
	ignored := append([]string{}, ignore...)
	sort.Strings(ignored)
	return res, ignored, nil
}

func digest(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ParsePrivateKey reads an EC private key in PEM, SEC 1 or PKCS #8.
func ParsePrivateKey(b []byte) (*ecdsa.PrivateKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("omstest: no PEM block")
	}
	if k, err := x509.ParseECPrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("omstest: not an EC private key")
	}
	return ek, nil
}
