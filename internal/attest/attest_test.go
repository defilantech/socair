package attest

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/report"
)

func golden(t *testing.T) report.Document {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var d report.Document
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

func newKey(t *testing.T) (*PrivateKey, Keyring, string) {
	t.Helper()
	prefix := filepath.Join(t.TempDir(), "operator")
	id, err := GenerateKey(prefix)
	if err != nil {
		t.Fatal(err)
	}
	k, err := LoadPrivateKey(prefix + ".key")
	if err != nil {
		t.Fatal(err)
	}
	if k.ID != id {
		t.Fatalf("loaded key id %s, generated %s", k.ID, id)
	}
	ring, err := LoadKeyring(prefix + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	return k, ring, prefix
}

// resign re-signs a hand-edited envelope payload with k, so a test can show
// that a check other than the signature catches the edit.
func resign(t *testing.T, env []byte, k *PrivateKey, edit func(*Statement)) []byte {
	t.Helper()
	var e Envelope
	if err := json.Unmarshal(env, &e); err != nil {
		t.Fatal(err)
	}
	payload, _ := base64.StdEncoding.DecodeString(e.Payload)
	var st Statement
	if err := json.Unmarshal(payload, &st); err != nil {
		t.Fatal(err)
	}
	edit(&st)
	payload, _ = json.Marshal(st)
	e.Payload = base64.StdEncoding.EncodeToString(payload)
	e.Signatures = []Signature{{KeyID: k.ID, Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(k.key, pae(e.PayloadType, payload)))}}
	out, _ := json.Marshal(e)
	return out
}

func mustFail(t *testing.T, env []byte, ring Keyring, want string) {
	t.Helper()
	_, err := Verify(env, ring)
	if !errors.Is(err, ErrVerify) {
		t.Fatalf("Verify = %v, want ErrVerify", err)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q does not name %q", err, want)
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	k, ring, _ := newKey(t)
	d := golden(t)
	env, err := Sign(d, k)
	if err != nil {
		t.Fatal(err)
	}
	v, err := Verify(env, ring)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if v.KeyID != k.ID || v.SHA256 != d.Artifact.SHA256 {
		t.Fatalf("verified %+v", v)
	}
	ver := v.Document.Verification
	if ver.SigningMethod != SigningMethod || ver.SignerKeyID != k.ID || len(ver.DocumentHash) != 64 {
		t.Fatalf("verification section not filled: %+v", ver)
	}
	if v.Document.Header.SignerKeyID != k.ID || v.Document.Header.DocumentHash != ver.DocumentHash {
		t.Fatalf("header not filled: %+v", v.Document.Header)
	}
}

// One altered byte anywhere in the payload breaks the signature.
// Falsification: skip ed25519.Verify and this passes.
func TestAlteredPayloadFails(t *testing.T) {
	k, ring, _ := newKey(t)
	env, _ := Sign(golden(t), k)
	var e Envelope
	_ = json.Unmarshal(env, &e)
	p, _ := base64.StdEncoding.DecodeString(e.Payload)
	i := strings.Index(string(p), `"PASS"`) + 2
	p[i] ^= 0x01 // PASS -> PBSS, one bit
	e.Payload = base64.StdEncoding.EncodeToString(p)
	out, _ := json.Marshal(e)
	mustFail(t, out, ring, "no valid signature")
}

func TestUntrustedKeyFails(t *testing.T) {
	k, _, _ := newKey(t)
	_, other, _ := newKey(t)
	env, _ := Sign(golden(t), k)
	mustFail(t, env, other, "no valid signature by a trusted key")
}

func TestUnsignedEnvelopeFails(t *testing.T) {
	k, ring, _ := newKey(t)
	env, _ := Sign(golden(t), k)
	var e Envelope
	_ = json.Unmarshal(env, &e)
	e.Signatures = nil
	out, _ := json.Marshal(e)
	mustFail(t, out, ring, "unsigned")
}

func TestPayloadTypeIsBound(t *testing.T) {
	k, ring, _ := newKey(t)
	env, _ := Sign(golden(t), k)
	var e Envelope
	_ = json.Unmarshal(env, &e)
	e.PayloadType = "application/json"
	out, _ := json.Marshal(e)
	mustFail(t, out, ring, "payload type")
}

// A trusted signer still cannot attest a document to another artifact's hash.
func TestSubjectMustBeTheArtifact(t *testing.T) {
	k, ring, _ := newKey(t)
	env, _ := Sign(golden(t), k)
	out := resign(t, env, k, func(st *Statement) {
		st.Subject[0].Digest["sha256"] = strings.Repeat("0", 64)
	})
	mustFail(t, out, ring, "subject digest")
}

func TestPredicateTypeIsChecked(t *testing.T) {
	k, ring, _ := newKey(t)
	env, _ := Sign(golden(t), k)
	out := resign(t, env, k, func(st *Statement) { st.PredicateType = "https://example.com/other" })
	mustFail(t, out, ring, "predicate type")
}

// The recorded document hash must match the document, so the hash printed in
// the rendered report identifies what was signed.
func TestDocumentHashIsChecked(t *testing.T) {
	k, ring, _ := newKey(t)
	env, _ := Sign(golden(t), k)
	out := resign(t, env, k, func(st *Statement) { st.Predicate.Scope.ToolVersions = "edited after hashing" })
	mustFail(t, out, ring, "document hash")
}

// Even a trusted signer cannot attest a promotion state the checks do not
// support: the document is validated after the signature.
func TestSignedForgedStateFails(t *testing.T) {
	k, ring, _ := newKey(t)
	env, _ := Sign(golden(t), k)
	out := resign(t, env, k, func(st *Statement) {
		st.Predicate.PromotionAuthorization = report.PromotionAuthorization{State: report.StateAuthorized, Authorized: true, Level: "Tier 1 only"}
		h, _ := DocumentHash(st.Predicate)
		st.Predicate.Verification.DocumentHash, st.Predicate.Header.DocumentHash = h, h
	})
	mustFail(t, out, ring, "NOT_TESTED")
}

func TestSignRefusesInvalidOrHeaderOnly(t *testing.T) {
	k, _, _ := newKey(t)
	d := golden(t)
	d.PromotionAuthorization.State = report.StateAuthorized
	d.PromotionAuthorization.Authorized = true
	d.PromotionAuthorization.AcceptedSurfaces = nil
	if _, err := Sign(d, k); err == nil {
		t.Fatal("signing a document whose state its checks do not support must fail")
	}
	d = golden(t)
	d.Artifact.SHA256 = ""
	d.Verification.ArtifactSHA256 = ""
	if _, err := Sign(d, k); err == nil {
		t.Fatal("signing a header-only document must fail")
	}
}

func TestKeyFileHygiene(t *testing.T) {
	_, _, prefix := newKey(t)
	if _, err := GenerateKey(prefix); err == nil {
		t.Fatal("GenerateKey must not overwrite an existing key")
	}
	if err := os.Chmod(prefix+".key", 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivateKey(prefix + ".key"); err == nil || !strings.Contains(err.Error(), "readable by other users") {
		t.Fatalf("a world-readable private key must be refused, got %v", err)
	}
	if _, err := LoadKeyring(t.TempDir()); err == nil {
		t.Fatal("an empty keyring must be an error")
	}
}
