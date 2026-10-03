package oms

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defilantech/socair/internal/modeldir"
)

const interop = "testdata/interop"

func trustFrom(t *testing.T, keys, roots string) Trust {
	t.Helper()
	if keys != "" {
		keys = filepath.Join(interop, "keys", keys)
	}
	if roots != "" {
		roots = filepath.Join(interop, "keys", roots)
	}
	tr, err := LoadTrust(keys, roots)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func readSig(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(interop, p))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// snapshot copies an interop directory, so a test can alter it.
func snapshot(t *testing.T, dir string) (string, []modeldir.File) {
	t.Helper()
	root, files, _, cleanup, err := modeldir.Snapshot(filepath.Join(interop, dir), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanup)
	return root, files
}

// TestReferenceSignaturesVerify: every signature produced by the reference
// implementation verifies, and binds the files it was made over.
func TestReferenceSignaturesVerify(t *testing.T) {
	for _, c := range []struct{ dir, keys, roots, method string }{
		{"key256", "p256.pub", "", "key"},
		{"key384", "p384.pub", "", "key"},
		{"cert", "", "ca.crt", "certificate"},
		{"shards", "p256.pub", "", "key"},
	} {
		o := Verify(readSig(t, c.dir+"/model.sig"), trustFrom(t, c.keys, c.roots))
		if o.State != Verified || o.Method != c.method {
			t.Errorf("%s: %s %s (%s)", c.dir, o.State, o.Method, o.Detail)
			continue
		}
		root, files := snapshot(t, c.dir)
		diffs, _, err := CheckFiles(o.Manifest, root, files, "model.sig")
		if err != nil || len(diffs) != 0 {
			t.Errorf("%s: files do not match the reference signature: %v %v", c.dir, diffs, err)
		}
	}
	o := Verify(readSig(t, "single/model.bin.sig"), trustFrom(t, "p256.pub", ""))
	b, _ := os.ReadFile(filepath.Join(interop, "single", "model.bin"))
	sum := sha256.Sum256(b)
	if diffs, err := CheckFile(o.Manifest, hex.EncodeToString(sum[:])); o.State != Verified || err != nil || len(diffs) != 0 {
		t.Errorf("single file: %s %v %v (%s)", o.State, diffs, err, o.Detail)
	}
	if !strings.Contains(Verify(readSig(t, "cert/model.sig"), trustFrom(t, "", "ca.crt")).Signer, "model-release-signer") {
		t.Error("a certificate signer must be named by its subject")
	}
}

// Every change to a signed directory is named. Falsification: skip a branch
// of CheckFiles and its case passes.
func TestChangedFilesAreDifferences(t *testing.T) {
	cases := map[string]struct {
		dir    string
		change func(root string) error
		want   string
	}{
		"changed byte": {"key256", func(r string) error { return rewrite(r, "config.json", `{"model_type":"evil!"}`) }, "changed: config.json"},
		"added file":   {"key256", func(r string) error { return os.WriteFile(filepath.Join(r, "evil.py"), []byte("x"), 0o600) }, "not signed: evil.py"},
		"removed file": {"key256", func(r string) error { return os.Remove(filepath.Join(r, "sub", "notes.txt")) }, "missing: sub/notes.txt"},
		"shard byte":   {"shards", func(r string) error { return flipByte(r, "model.safetensors", 1500) }, "changed: model.safetensors bytes 1024-2048"},
		"shard length": {"shards", func(r string) error { return appendBytes(r, "model.safetensors") }, "changed: model.safetensors (signed for 3000 bytes"},
	}
	for name, c := range cases {
		dir := filepath.Join(t.TempDir(), c.dir)
		copyTree(t, filepath.Join(interop, c.dir), dir)
		if err := c.change(dir); err != nil {
			t.Fatal(err)
		}
		root, files, _, cleanup, err := modeldir.Snapshot(dir, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		o := Verify(readSig(t, c.dir+"/model.sig"), trustFrom(t, "p256.pub", ""))
		diffs, _, err := CheckFiles(o.Manifest, root, files, "model.sig")
		cleanup()
		if err != nil || !containsPrefix(diffs, c.want) {
			t.Errorf("%s: diffs %v (%v), want %q", name, diffs, err, c.want)
		}
	}
	o := Verify(readSig(t, "single/model.bin.sig"), trustFrom(t, "p256.pub", ""))
	if diffs, _ := CheckFile(o.Manifest, strings.Repeat("0", 64)); len(diffs) == 0 {
		t.Error("a single file with other bytes must differ")
	}
}

// Trust decides verified versus unverified; only a trusted signer can make
// a signature invalid.
func TestTrustPolicy(t *testing.T) {
	sig := readSig(t, "key256/model.sig")
	if o := Verify(sig, Trust{}); o.State != Unverified || !strings.Contains(o.Detail, "SOCAIR_PUBLISHER_KEYS") {
		t.Errorf("no trust: %s (%s)", o.State, o.Detail)
	}
	if o := Verify(sig, trustFrom(t, "p384.pub", "")); o.State != Unverified {
		t.Errorf("another key: %s, want unverified", o.State)
	}
	cert := readSig(t, "cert/model.sig")
	if o := Verify(cert, Trust{}); o.State != Unverified || !strings.Contains(o.Detail, "SOCAIR_PUBLISHER_ROOTS") {
		t.Errorf("certificate, no roots: %s (%s)", o.State, o.Detail)
	}
	otherRoot := writePEM(t, "CERTIFICATE", selfSigned(t).Raw)
	tr, err := LoadTrust("", otherRoot)
	if err != nil {
		t.Fatal(err)
	}
	if o := Verify(cert, tr); o.State != Unverified {
		t.Errorf("certificate, another root: %s, want unverified", o.State)
	}
}

// A signature that claims a trusted key but does not verify, or a payload
// altered after signing, is invalid. Falsification: skip verifySig and both
// verify.
func TestTamperedSignatureIsInvalid(t *testing.T) {
	tr := trustFrom(t, "p256.pub", "")
	var b map[string]any
	if err := json.Unmarshal(readSig(t, "key256/model.sig"), &b); err != nil {
		t.Fatal(err)
	}
	env := b["dsseEnvelope"].(map[string]any)
	payload, _ := base64.StdEncoding.DecodeString(env["payload"].(string))

	altered := strings.Replace(string(payload), `"name":"config.json"`, `"name":"config.jsom"`, 1)
	if altered == string(payload) {
		altered = strings.Replace(string(payload), `config.json`, `config.jsom`, 1)
	}
	env["payload"] = base64.StdEncoding.EncodeToString([]byte(altered))
	raw, _ := json.Marshal(b)
	if o := Verify(raw, tr); o.State != Invalid {
		t.Errorf("altered payload: %s (%s), want invalid", o.State, o.Detail)
	}

	env["payload"] = base64.StdEncoding.EncodeToString(payload)
	env["signatures"].([]any)[0].(map[string]any)["sig"] = base64.StdEncoding.EncodeToString([]byte("not a signature"))
	raw, _ = json.Marshal(b)
	if o := Verify(raw, tr); o.State != Invalid {
		t.Errorf("garbage signature claiming a trusted key: %s, want invalid", o.State)
	}
}

// A self-consistent signature from a trusted key whose subject does not
// match its resources is invalid: the reference verifier rejects it too.
func TestInconsistentManifestIsInvalid(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	st := statementFor([]Resource{{Name: "a", Algorithm: "sha256", Digest: strings.Repeat("ab", 32)}}, strings.Repeat("00", 32), "files")
	tr := trustKey(t, key)
	if o := Verify(keyBundle(t, key, st), tr); o.State != Invalid || !strings.Contains(o.Detail, "inconsistent") {
		t.Fatalf("%s (%s)", o.State, o.Detail)
	}
}

func TestUnsupportedAndLegacyAreUnverified(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tr := trustKey(t, key)
	res := []Resource{{Name: "a", Algorithm: "blake2b", Digest: strings.Repeat("ab", 32)}}
	st := statementFor(res, rootOf(res), "files")
	st["predicate"].(map[string]any)["serialization"].(map[string]any)["hash_type"] = "blake2b"
	o := Verify(keyBundle(t, key, st), tr)
	if o.State != Verified {
		t.Fatalf("a well-signed BLAKE2 manifest verifies as a signature: %s (%s)", o.State, o.Detail)
	}
	if _, _, err := CheckFiles(o.Manifest, t.TempDir(), nil, "model.sig"); err == nil {
		t.Error("a BLAKE2 manifest cannot be checked against files and must say so")
	}
	legacy := statementFor(res, rootOf(res), "files")
	legacy["predicateType"] = predicateLegacy
	if o := Verify(keyBundle(t, key, legacy), tr); o.State != Unverified || !strings.Contains(o.Detail, "pre-1.0") {
		t.Errorf("legacy: %s (%s)", o.State, o.Detail)
	}
}

// A keyless Sigstore bundle is recognized and left unverified, never
// verified on a certificate nobody configured.
func TestKeylessIsUnverified(t *testing.T) {
	var b map[string]any
	if err := json.Unmarshal(readSig(t, "cert/model.sig"), &b); err != nil {
		t.Fatal(err)
	}
	b["verificationMaterial"].(map[string]any)["tlogEntries"] = []any{map[string]any{"logIndex": "1"}}
	raw, _ := json.Marshal(b)
	if o := Verify(raw, trustFrom(t, "", "ca.crt")); o.State != Unverified || o.Method != "keyless" {
		t.Fatalf("%s %s (%s)", o.State, o.Method, o.Detail)
	}
}

func TestCertificateWithoutSigningUsageIsInvalid(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "root"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "tls-only"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leaf, caCert, &leafKey.PublicKey, caKey)

	res := []Resource{{Name: "a", Algorithm: "sha256", Digest: strings.Repeat("ab", 32)}}
	payload, _ := json.Marshal(statementFor(res, rootOf(res), "files"))
	b := map[string]any{
		"mediaType": BundleMediaType,
		"verificationMaterial": map[string]any{"x509CertificateChain": map[string]any{"certificates": []any{
			map[string]any{"rawBytes": base64.StdEncoding.EncodeToString(leafDER)},
			map[string]any{"rawBytes": base64.StdEncoding.EncodeToString(caDER)},
		}}},
		"dsseEnvelope": map[string]any{"payload": base64.StdEncoding.EncodeToString(payload), "payloadType": PayloadType,
			"signatures": []any{map[string]any{"sig": base64.StdEncoding.EncodeToString(sign(t, leafKey, payload))}}},
	}
	raw, _ := json.Marshal(b)
	tr, err := LoadTrust("", writePEM(t, "CERTIFICATE", caDER))
	if err != nil {
		t.Fatal(err)
	}
	if o := Verify(raw, tr); o.State != Invalid || !strings.Contains(o.Detail, "not issued for signing") {
		t.Fatalf("%s (%s)", o.State, o.Detail)
	}
}

// --- helpers ---

func statementFor(res []Resource, root, method string) map[string]any {
	rs := make([]any, len(res))
	for i, r := range res {
		rs[i] = map[string]any{"name": r.Name, "algorithm": r.Algorithm, "digest": r.Digest}
	}
	return map[string]any{
		"_type": StatementType, "predicateType": PredicateType,
		"subject":   []any{map[string]any{"name": "m", "digest": map[string]any{"sha256": root}}},
		"predicate": map[string]any{"serialization": map[string]any{"method": method, "hash_type": "sha256", "allow_symlinks": false}, "resources": rs},
	}
}

func rootOf(res []Resource) string {
	h := sha256.New()
	for _, r := range res {
		d, _ := hex.DecodeString(r.Digest)
		h.Write(d)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func sign(t *testing.T, k *ecdsa.PrivateKey, payload []byte) []byte {
	t.Helper()
	sum := sha256.Sum256(pae(payload))
	s, err := ecdsa.SignASN1(rand.Reader, k, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func keyBundle(t *testing.T, k *ecdsa.PrivateKey, st map[string]any) []byte {
	t.Helper()
	payload, _ := json.Marshal(st)
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	b, _ := json.Marshal(map[string]any{
		"mediaType":            BundleMediaType,
		"verificationMaterial": map[string]any{"publicKey": map[string]any{"hint": KeyHint(der)}},
		"dsseEnvelope": map[string]any{"payload": base64.StdEncoding.EncodeToString(payload), "payloadType": PayloadType,
			"signatures": []any{map[string]any{"sig": base64.StdEncoding.EncodeToString(sign(t, k, payload))}}},
	})
	return b
}

func trustKey(t *testing.T, k *ecdsa.PrivateKey) Trust {
	t.Helper()
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	tr, err := LoadTrust(writePEM(t, "PUBLIC KEY", der), "")
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func writePEM(t *testing.T, typ string, der []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "x.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func selfSigned(t *testing.T) *x509.Certificate {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "other"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	c, _ := x509.ParseCertificate(der)
	return c
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if info.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func rewrite(root, rel, body string) error {
	return os.WriteFile(filepath.Join(root, rel), []byte(body), 0o644)
}

func flipByte(root, rel string, at int) error {
	p := filepath.Join(root, rel)
	b, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	b[at] ^= 0xff
	return os.WriteFile(p, b, 0o644)
}

func appendBytes(root, rel string) error {
	f, err := os.OpenFile(filepath.Join(root, rel), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write([]byte("tail"))
	return err
}

func containsPrefix(list []string, p string) bool {
	for _, s := range list {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
