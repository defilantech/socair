package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/attest"
)

// TestSignAndVerifyABOM runs the harness: sign --bom writes the signed BOM of
// an attestation, verify --bom checks it against the operator's key and the
// artifact and writes the BOM it carries, and each verifier refuses the
// other's envelope.
func TestSignAndVerifyABOM(t *testing.T) {
	dir := t.TempDir()
	env, op := withheldAttestation(t, dir)
	art := filepath.Join(dir, "clean-Q5_K_M.gguf")
	bom := filepath.Join(dir, "bom.json")

	out, err := stdout(t, func() error {
		return signCmd([]string{"--key", op + ".key", "--bom", "--attestation", env, "--cyclonedx", bom})
	})
	if err != nil {
		t.Fatalf("sign --bom: %v", err)
	}
	signed := filepath.Join(dir, "r.cdx.dsse.json")
	if !strings.Contains(out, signed) || !strings.Contains(out, "not a promotion ticket") {
		t.Errorf("sign --bom printed:\n%s", out)
	}

	verified := filepath.Join(dir, "verified.json")
	out, err = stdout(t, func() error {
		return verifyCmd([]string{"--bom", signed, "--trusted", op + ".pub", "--artifact", art, "--cyclonedx", verified})
	})
	if err != nil {
		t.Fatalf("verify --bom: %v", err)
	}
	if !strings.Contains(out, "verified CycloneDX BOM") || !strings.Contains(out, "authorizes no promotion") {
		t.Errorf("verify --bom printed:\n%s", out)
	}
	a, _ := os.ReadFile(bom)
	b, _ := os.ReadFile(verified)
	if len(a) == 0 || !bytes.Equal(a, b) {
		t.Error("the verified BOM must be the BOM that was signed")
	}

	if err := os.WriteFile(art, []byte("other bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := stdout(t, func() error {
		return verifyCmd([]string{signed, "--bom", "--trusted", op + ".pub", "--artifact", art})
	}); err == nil {
		t.Error("a signed BOM verified against other bytes")
	}
	if _, err := stdout(t, func() error { return verifyCmd([]string{signed, "--trusted", op + ".pub"}) }); err == nil ||
		!strings.Contains(err.Error(), "verify --bom") {
		t.Errorf("verifying a signed BOM as an attestation must fail and say what it is, got %v", err)
	}
	if _, err := stdout(t, func() error { return verifyCmd([]string{"--bom", env, "--trusted", op + ".pub"}) }); err == nil {
		t.Error("an attestation verified as a signed BOM")
	}

	other := filepath.Join(dir, "other")
	if _, err := attest.GenerateKey(other); err != nil {
		t.Fatal(err)
	}
	if _, err := stdout(t, func() error {
		return signCmd([]string{"--key", other + ".key", "--bom", "--attestation", env, "--out", filepath.Join(dir, "x.dsse.json")})
	}); err == nil {
		t.Error("a key signed the BOM of an attestation it did not sign")
	}
	if _, err := stdout(t, func() error { return signCmd([]string{"--key", op + ".key", "--bom", env}) }); err == nil {
		t.Error("--bom with a value must be refused with the usage")
	}
}
