package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

// The vectors are keyless OMS signatures from the reference implementation's
// own test suite (sigstore/model-transparency scripts/tests), signed through
// IBM's Sigstore OIDC issuer and logged in the public-good Rekor.
const (
	trustedRoot = "testdata/trusted-root-public-good.json"
	signerSAN   = "stefanb@us.ibm.com"
	signerIss   = "https://sigstore.verify.ibm.com/oauth2"
)

var vectors = []string{"v1.0.0-sigstore.sig", "v1.0.1-sigstore.sig", "v1.1.0-sigstore.sig"}

func request(t *testing.T, sig string, ids ...Identity) Request {
	t.Helper()
	b, err := os.ReadFile("testdata/" + sig)
	if err != nil {
		t.Fatal(err)
	}
	return Request{Bundle: base64.StdEncoding.EncodeToString(b), TrustedRoot: trustedRoot, Identities: ids}
}

var policy = Identity{Issuer: signerIss, SAN: signerSAN}

func TestReferenceKeylessSignaturesVerify(t *testing.T) {
	for _, v := range vectors {
		got, err := Verify(request(t, v, policy))
		if err != nil || got.State != stateVerified || !strings.Contains(got.Signer, signerSAN) {
			t.Errorf("%s: %+v %v", v, got, err)
		}
	}
	got, err := Verify(request(t, vectors[2], Identity{IssuerRegexp: `^https://sigstore\.verify\.ibm\.com/`, SANRegexp: `@us\.ibm\.com$`}))
	if err != nil || got.State != stateVerified {
		t.Errorf("regexp policy: %+v %v", got, err)
	}
}

// Anyone can sign keylessly: a signer outside the policy proves nothing, and
// is unverified, never invalid. Falsification: drop the identity pre-check
// and this reports invalid.
func TestOtherIdentityIsUnverified(t *testing.T) {
	for _, id := range []Identity{
		{Issuer: signerIss, SAN: "someone-else@us.ibm.com"},
		{Issuer: "https://accounts.google.com", SAN: signerSAN},
	} {
		got, err := Verify(request(t, vectors[2], id))
		if err != nil || got.State != stateUnverified || !strings.Contains(got.Signer, signerSAN) {
			t.Errorf("%+v: %+v %v", id, got, err)
		}
	}
}

// A bundle from the trusted identity whose payload, signature, or log entry
// was altered is invalid. Falsification: skip the full verification and these
// verify.
func TestTamperedKeylessBundleIsInvalid(t *testing.T) {
	mutations := map[string]func(map[string]any){
		"payload": func(b map[string]any) {
			env := b["dsseEnvelope"].(map[string]any)
			p, _ := base64.StdEncoding.DecodeString(env["payload"].(string))
			env["payload"] = base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(p), "signme-1", "signme-X", 1)))
		},
		"signature": func(b map[string]any) {
			s := b["dsseEnvelope"].(map[string]any)["signatures"].([]any)[0].(map[string]any)
			raw, _ := base64.StdEncoding.DecodeString(s["sig"].(string))
			raw[len(raw)-1] ^= 1
			s["sig"] = base64.StdEncoding.EncodeToString(raw)
		},
		"log index": func(b map[string]any) {
			e := b["verificationMaterial"].(map[string]any)["tlogEntries"].([]any)[0].(map[string]any)
			e["logIndex"] = "1"
		},
		"integrated time": func(b map[string]any) {
			e := b["verificationMaterial"].(map[string]any)["tlogEntries"].([]any)[0].(map[string]any)
			e["integratedTime"] = "1700000000"
		},
	}
	for name, mutate := range mutations {
		raw, _ := os.ReadFile("testdata/" + vectors[2])
		var b map[string]any
		if err := json.Unmarshal(raw, &b); err != nil {
			t.Fatal(err)
		}
		mutate(b)
		out, _ := json.Marshal(b)
		got, err := Verify(Request{Bundle: base64.StdEncoding.EncodeToString(out), TrustedRoot: trustedRoot, Identities: []Identity{policy}})
		if err != nil || got.State != stateInvalid {
			t.Errorf("%s: %+v %v, want invalid", name, got, err)
		}
	}
}

func TestBadRequestsAreConfigErrors(t *testing.T) {
	for name, req := range map[string]Request{
		"no identities":   request(t, vectors[2]),
		"no trusted root": {Bundle: "e30=", Identities: []Identity{policy}},
		"missing root":    {Bundle: "e30=", TrustedRoot: "testdata/none.json", Identities: []Identity{policy}},
	} {
		if _, err := Verify(req); !errors.Is(err, errConfig) {
			t.Errorf("%s: %v, want a configuration error", name, err)
		}
	}
	if _, err := handle([]byte(`{"bundle":"","unknown":1}`)); !errors.Is(err, errConfig) {
		t.Error("an unknown request field must be refused")
	}
}

func TestProtocolRoundTrip(t *testing.T) {
	in, _ := json.Marshal(request(t, vectors[2], policy))
	out, err := handle(in)
	if err != nil {
		t.Fatal(err)
	}
	var v Verdict
	if err := json.Unmarshal(out, &v); err != nil || v.State != stateVerified {
		t.Fatalf("%s %v", out, err)
	}
}
