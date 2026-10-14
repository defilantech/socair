package cyclonedx

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/dsse"
	"github.com/defilantech/socair/internal/report"
)

// operator makes an operator key with an issuer name, and its trust list.
func operator(t *testing.T, issuer string) (*attest.PrivateKey, attest.Keyring, attest.Names) {
	t.Helper()
	prefix := filepath.Join(t.TempDir(), "operator")
	if _, err := attest.GenerateNamedKey(prefix, issuer); err != nil {
		t.Fatal(err)
	}
	k, err := attest.LoadPrivateKey(prefix + ".key")
	if err != nil {
		t.Fatal(err)
	}
	ring, names, err := attest.LoadNamedKeyring(prefix + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	return k, ring, names
}

// signedBOM signs the golden report with k, then signs its BOM.
func signedBOM(t *testing.T, k *attest.PrivateKey) (attestation, bom, envelope []byte) {
	t.Helper()
	att, err := attest.Sign(*golden(t), k)
	if err != nil {
		t.Fatal(err)
	}
	bom, env, err := Sign(att, k)
	if err != nil {
		t.Fatal(err)
	}
	return att, bom, env
}

// editPayload rewrites the statement inside an envelope and keeps the old
// signature, as an attacker without the key would.
func editPayload(t *testing.T, env []byte, edit func([]byte) []byte) []byte {
	t.Helper()
	var e dsse.Envelope
	if err := json.Unmarshal(env, &e); err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		t.Fatal(err)
	}
	e.Payload = base64.StdEncoding.EncodeToString(edit(payload))
	out, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestSignedBOMVerifies: the BOM of a signed attestation, signed with the same
// key, verifies offline against that key, carries the BOM Render writes for
// the signed document, binds the attested artifact's digest, and names the
// issuer as its author, confirmed by the trust list.
func TestSignedBOMVerifies(t *testing.T) {
	k, ring, names := operator(t, "Acme Model Intake")
	att, bom, env := signedBOM(t, k)

	v, err := Verify(env, ring)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	signed, err := attest.Verify(att, ring)
	if err != nil {
		t.Fatal(err)
	}
	want := render(t, &signed.Document)
	if !bytes.Equal(v.BOM, want) || !bytes.Equal(bom, want) {
		t.Error("the verified BOM must be the BOM of the signed document, byte for byte")
	}
	if v.SHA256 != golden(t).Artifact.SHA256 || v.Name != golden(t).Artifact.FileName || v.KeyID != k.ID {
		t.Errorf("verified = %+v, want the attested artifact and the signing key", v)
	}
	if err := validate(t, schema(t), v.BOM); err != nil {
		t.Errorf("the signed BOM does not validate: %v", err)
	}
	name, confirmed, err := v.Issuer(names)
	if err != nil || !confirmed || name != "Acme Model Intake" {
		t.Errorf("Issuer = %q, %v, %v; want the confirmed issuer", name, confirmed, err)
	}
	// The BOM of a signed report references its attestation.
	if !bytes.Contains(v.BOM, []byte("urn:socair:attestation:"+signed.Document.Verification.DocumentHash)) {
		t.Error("a signed report's BOM must reference its attestation")
	}

	var st Statement
	payload, _, _, err := dsse.Open(env)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(payload, &st); err != nil {
		t.Fatal(err)
	}
	if st.Type != attest.StatementType || st.PredicateType != "https://cyclonedx.org/bom" || len(st.Subject) != 1 ||
		st.Subject[0].Digest["sha256"] != v.SHA256 {
		t.Errorf("statement = %s %s %v, want an in-toto v1 CycloneDX statement about the artifact", st.Type, st.PredicateType, st.Subject)
	}
}

// TestChangedBOMFailsVerification: any change to the signed BOM, or to the
// subject it is bound to, breaks the signature. Falsification: skip the
// signature check in Verify and these verify.
func TestChangedBOMFailsVerification(t *testing.T) {
	k, ring, _ := operator(t, "Acme Model Intake")
	_, _, env := signedBOM(t, k)

	for name, edit := range map[string]func([]byte) []byte{
		"a check status": func(p []byte) []byte {
			return bytes.Replace(p, []byte(`"value":"NOT_TESTED"`), []byte(`"value":"PASS"`), 1)
		},
		"the license": func(p []byte) []byte {
			return bytes.Replace(p, []byte(`"name":"Gemma Terms of Use"`), []byte(`"name":"Apache License 2.0"`), 1)
		},
		"the subject": func(p []byte) []byte {
			return bytes.Replace(p, []byte(`"sha256":"13d4`), []byte(`"sha256":"03d4`), 1)
		},
	} {
		changed := editPayload(t, env, edit)
		if bytes.Equal(changed, env) {
			t.Fatalf("%s: the edit changed nothing", name)
		}
		if _, err := Verify(changed, ring); !errors.Is(err, ErrVerify) {
			t.Errorf("%s: a changed BOM verified (err %v)", name, err)
		}
	}
}

// TestBOMMustBindItsSubject: a statement signed by a trusted key whose subject
// is not the BOM's described component is refused, so a BOM cannot be
// attached to other bytes.
func TestBOMMustBindItsSubject(t *testing.T) {
	k, ring, _ := operator(t, "")
	_, _, env := signedBOM(t, k)
	payload, _, _, err := dsse.Open(env)
	if err != nil {
		t.Fatal(err)
	}
	var st Statement
	if err := json.Unmarshal(payload, &st); err != nil {
		t.Fatal(err)
	}
	st.Subject[0].Digest["sha256"] = strings.Repeat("0", 64)
	resigned, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := dsse.Sign(resigned, k.ID, k.Sign)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(forged, ring); !errors.Is(err, ErrVerify) || !strings.Contains(err.Error(), "subject digest") {
		t.Fatalf("a BOM bound to another subject verified (err %v)", err)
	}
}

// TestBOMIsNotAnAttestation keeps the two apart: the attestation verifier,
// which the airlock gate runs, refuses a signed BOM, and the BOM verifier
// refuses an attestation.
func TestBOMIsNotAnAttestation(t *testing.T) {
	k, ring, _ := operator(t, "")
	att, _, env := signedBOM(t, k)
	if _, err := attest.Verify(env, ring); !errors.Is(err, attest.ErrVerify) || !strings.Contains(err.Error(), "predicate type") {
		t.Fatalf("attest.Verify accepted a signed BOM (err %v)", err)
	}
	if !IsSignedBOM(env) || IsSignedBOM(att) {
		t.Error("IsSignedBOM must tell a signed BOM from an attestation")
	}
	if _, err := Verify(att, ring); !errors.Is(err, ErrVerify) || !strings.Contains(err.Error(), "predicate type") {
		t.Fatalf("an attestation verified as a BOM (err %v)", err)
	}
}

// TestBOMIsSignedOnlyByItsReportsIssuer: Sign refuses an attestation another
// key signed, so a BOM's author is always its signer; Verify refuses an
// untrusted key; and a trust list that names the key differently refuses the
// BOM's stated author.
func TestBOMIsSignedOnlyByItsReportsIssuer(t *testing.T) {
	op, ring, _ := operator(t, "Acme Model Intake")
	other, otherRing, _ := operator(t, "Someone Else")
	att, err := attest.Sign(*golden(t), op)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Sign(att, other); err == nil {
		t.Fatal("a key signed the BOM of a report it did not issue")
	}
	if _, _, err := Sign([]byte(`{"payloadType":"application/vnd.in-toto+json","payload":"","signatures":[]}`), op); err == nil {
		t.Fatal("an unsigned envelope produced a signed BOM")
	}
	_, _, env := signedBOM(t, op)
	if _, err := Verify(env, otherRing); !errors.Is(err, ErrVerify) {
		t.Fatalf("a BOM signed by an untrusted key verified (err %v)", err)
	}
	v, err := Verify(env, ring)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := v.Issuer(attest.Names{op.ID: "Mallory"}); !errors.Is(err, ErrAuthor) {
		t.Fatalf("a BOM whose author the trust list contradicts was accepted (err %v)", err)
	}
	if name, confirmed, err := v.Issuer(nil); err != nil || confirmed || name != "Acme Model Intake" {
		t.Errorf("unnamed key: %q %v %v, want the stated author, unconfirmed", name, confirmed, err)
	}
	if v.Author == report.Unissued {
		t.Error("a signed BOM's author is its issuer, not Unissued")
	}
}
