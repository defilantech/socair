package acceptance

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/defilantech/socair/internal/dsse"
	"strings"
	"testing"
	"time"
)

var sha = strings.Repeat("ab", 32)

func key(t *testing.T) (ed25519.PrivateKey, string, map[string]ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := KeyID(pub)
	if err != nil {
		t.Fatal(err)
	}
	return priv, id, map[string]ed25519.PublicKey{id: pub}
}

func predicate() Predicate {
	return Predicate{
		ReviewedDocumentHash: strings.Repeat("cd", 32), ReviewedDocumentID: "SOCAIR-x",
		AcceptedSurfaces: []string{"b", "a"}, AcceptedBy: "Jane Doe, CISO",
		AcceptedAt: "2026-10-03T12:00:00Z", Expires: "2026-12-01T00:00:00Z",
	}
}

func signed(t *testing.T) ([]byte, map[string]ed25519.PublicKey) {
	t.Helper()
	priv, id, ring := key(t)
	raw, err := Sign(predicate(), "model.gguf", sha, priv, id)
	if err != nil {
		t.Fatal(err)
	}
	return raw, ring
}

func TestSignVerifyRoundTrip(t *testing.T) {
	raw, ring := signed(t)
	a, err := Verify(raw, ring)
	if err != nil {
		t.Fatal(err)
	}
	if a.ArtifactSHA256 != sha || a.AcceptedBy != "Jane Doe, CISO" || strings.Join(a.AcceptedSurfaces, ",") != "a,b" {
		t.Fatalf("%+v", a)
	}
	if err := a.Current(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Error(err)
	}
	if err := a.Current(time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Error("an acceptance at its expiry is not current")
	}
}

// A trusted key's acceptance, altered after signing, does not verify.
// Falsification: skip ed25519.Verify and these pass.
func TestTamperedAcceptanceFails(t *testing.T) {
	for name, mutate := range map[string]func(*dsse.Envelope){
		"signature byte": func(e *dsse.Envelope) {
			sig, _ := base64.StdEncoding.DecodeString(e.Signatures[0].Sig)
			sig[0] ^= 1
			e.Signatures[0].Sig = base64.StdEncoding.EncodeToString(sig)
		},
		"expiry extended": func(e *dsse.Envelope) {
			p, _ := base64.StdEncoding.DecodeString(e.Payload)
			e.Payload = base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(p), "2026-12-01", "2027-12-01", 1)))
		},
		"surface added": func(e *dsse.Envelope) {
			p, _ := base64.StdEncoding.DecodeString(e.Payload)
			e.Payload = base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(p), `["a","b"]`, `["a","b","c"]`, 1)))
		},
	} {
		raw, ring := signed(t)
		var e dsse.Envelope
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatal(err)
		}
		mutate(&e)
		out, _ := json.Marshal(e)
		if _, err := Verify(out, ring); err == nil {
			t.Errorf("%s: a tampered acceptance must not verify", name)
		}
	}
}

func TestUntrustedKeyFails(t *testing.T) {
	raw, _ := signed(t)
	_, _, other := key(t)
	if _, err := Verify(raw, other); err == nil || !strings.Contains(err.Error(), "not a trusted acceptor key") {
		t.Fatalf("got %v", err)
	}
}

func TestMalformedAcceptancesAreRefused(t *testing.T) {
	priv, id, _ := key(t)
	for name, edit := range map[string]func(*Predicate){
		"no acceptor":         func(p *Predicate) { p.AcceptedBy = " " },
		"no surfaces":         func(p *Predicate) { p.AcceptedSurfaces = nil },
		"no reviewed hash":    func(p *Predicate) { p.ReviewedDocumentHash = "" },
		"free-text expiry":    func(p *Predicate) { p.Expires = "next quarter" },
		"expires before made": func(p *Predicate) { p.Expires = "2026-10-01T00:00:00Z" },
	} {
		p := predicate()
		edit(&p)
		if _, err := Sign(p, "m", sha, priv, id); err == nil {
			t.Errorf("%s: Sign must refuse", name)
		}
	}
	if _, err := Sign(predicate(), "m", "", priv, id); err == nil {
		t.Error("an acceptance must name the artifact")
	}
	if _, err := Parse([]byte(`{"payloadType":"x","payload":"","signatures":[]}`)); err == nil {
		t.Error("a malformed envelope must not parse")
	}
}
