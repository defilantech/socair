package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The harness signs and verifies a directory through the suite's protocol,
// and a changed file, an extra file, or another key is a failure, not a
// pass. Falsification: return nil from verifyModel and the bad cases pass.
func TestSignThenVerify(t *testing.T) {
	dir := t.TempDir()
	model := filepath.Join(dir, "model")
	for name, body := range map[string]string{"signme-1": "one", "signme-2": "two", "ignore-me": "x"} {
		write(t, filepath.Join(model, name), body)
	}
	key, pub := keyPair(t, dir, "a")
	_, otherPub := keyPair(t, dir, "b")
	bundle := filepath.Join(dir, "bundle.sig")
	if err := signModel([]string{"--method", "key", "--model-path", model, "--output-bundle", bundle,
		"--private-key", key, "--ignore-paths", filepath.Join(model, "ignore-me")}); err != nil {
		t.Fatal(err)
	}
	verify := func(pub string, extra ...string) error {
		return verifyModel(append([]string{"--method", "key", "--model-path", model, "--bundle", bundle, "--public-key", pub}, extra...))
	}
	if err := verify(pub); err != nil {
		t.Fatalf("a good signature: %v", err)
	}
	if err := verify(otherPub); err == nil {
		t.Error("another key must not verify")
	}
	if err := verifyModel([]string{"--method", "certificate", "--model-path", model, "--bundle", bundle, "--cert-chain", pub}); err == nil {
		t.Error("a key bundle verified as a certificate must fail")
	}
	write(t, filepath.Join(model, "extra"), "e")
	if err := verify(pub); err == nil {
		t.Error("an unsigned file must fail")
	}
	if err := verify(pub, "--ignore-unsigned-files"); err != nil {
		t.Errorf("an unsigned file, tolerated: %v", err)
	}
	write(t, filepath.Join(model, "signme-1"), "changed")
	if err := verify(pub, "--ignore-unsigned-files"); err == nil {
		t.Error("a changed file must fail even with unsigned files tolerated")
	}
	var u usageError
	if err := verifyModel([]string{"--method", "sigstore", "--model-path", model, "--bundle", bundle}); !errors.As(err, &u) {
		t.Errorf("sigstore: %v, want a usage error", err)
	}
}

func keyPair(t *testing.T, dir, name string) (string, string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	priv, pub := filepath.Join(dir, name+".key"), filepath.Join(dir, name+".pub")
	write(t, priv, string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})))
	write(t, pub, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})))
	return priv, pub
}

func write(t *testing.T, p, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
