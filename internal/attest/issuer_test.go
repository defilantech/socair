package attest

import (
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/report"
)

func namedKey(t *testing.T, issuer string) (*PrivateKey, string) {
	t.Helper()
	prefix := filepath.Join(t.TempDir(), "k")
	if _, err := GenerateNamedKey(prefix, issuer); err != nil {
		t.Fatal(err)
	}
	k, err := LoadPrivateKey(prefix + ".key")
	if err != nil {
		t.Fatal(err)
	}
	return k, prefix + ".pub"
}

// The name sits outside the PEM block: the files stay standard PEM, and
// the name reads back from both.
func TestNamedKeyFiles(t *testing.T) {
	k, pub := namedKey(t, "Acme ML Platform")
	if k.Issuer != "Acme ML Platform" {
		t.Fatalf("private key issuer %q", k.Issuer)
	}
	b, _ := os.ReadFile(pub)
	if blk, _ := pem.Decode(b); blk == nil || blk.Type != "PUBLIC KEY" {
		t.Fatal("a named public key must still be a standard PEM block")
	}
	id, _, name, err := LoadNamedPublicKey(pub)
	if err != nil || name != "Acme ML Platform" || id != k.ID {
		t.Fatalf("%s %q %v", id, name, err)
	}
	if _, err := GenerateNamedKey(filepath.Join(t.TempDir(), "x"), "two\nlines"); err == nil {
		t.Error("a multi-line issuer name must be refused")
	}
	renamed, err := WithIssuer(b, "Other")
	if err != nil || strings.Count(string(renamed), IssuerPrefix) != 1 || issuerOf(renamed) != "Other" {
		t.Fatalf("WithIssuer replaces, never duplicates: %q", renamed)
	}
	if bare, _ := WithIssuer(b, ""); issuerOf(bare) != "" {
		t.Error("an empty name removes the line")
	}
}

func TestSignNamesTheIssuer(t *testing.T) {
	for _, c := range []struct{ name, want string }{
		{"Acme ML Platform", "Acme ML Platform"},
		{"", "unnamed issuer (key "},
	} {
		k, pub := namedKey(t, c.name)
		env, err := Sign(golden(t), k)
		if err != nil {
			t.Fatal(err)
		}
		ring, names, err := LoadNamedKeyring(pub)
		if err != nil {
			t.Fatal(err)
		}
		v, err := Verify(env, ring)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(v.Document.Issuer.SignedBy, c.want) || v.Document.Issuer.Authority != v.Document.Issuer.SignedBy {
			t.Errorf("issuer %+v, want %q", v.Document.Issuer, c.want)
		}
		_, confirmed, err := v.Issuer(names)
		if err != nil || confirmed != (c.name != "") {
			t.Errorf("%q: confirmed %v, err %v", c.name, confirmed, err)
		}
	}
	if golden(t).Issuer.Authority == "Defilan Technologies" {
		t.Error("an unsigned report must not name Defilan as its issuer")
	}
	if report.Unissued == "" {
		t.Error("an unsigned report needs an issuer statement")
	}
}

// Anyone can name their key "Defilan Technologies". To a verifier who has not
// named the key, that is a claim; to one who has named it otherwise, it is
// refused. Falsification: drop the comparison in Verified.Issuer and the
// impersonation is confirmed.
func TestIssuerImpersonationIsRefused(t *testing.T) {
	k, pub := namedKey(t, "Defilan Technologies")
	env, err := Sign(golden(t), k)
	if err != nil {
		t.Fatal(err)
	}
	ring, err := LoadKeyring(pub)
	if err != nil {
		t.Fatal(err)
	}
	v, err := Verify(env, ring)
	if err != nil {
		t.Fatal(err)
	}
	if name, confirmed, err := v.Issuer(Names{}); err != nil || confirmed || name != "Defilan Technologies" {
		t.Fatalf("an unnamed key's claim is unconfirmed: %q %v %v", name, confirmed, err)
	}
	if _, _, err := v.Issuer(Names{k.ID: "Acme ML Platform"}); !errors.Is(err, ErrIssuer) {
		t.Fatalf("a claim contradicting the trust list must be refused, got %v", err)
	}
}
