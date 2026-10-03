// Command socair-sigstore verifies keyless Sigstore signatures for Socair.
//
// It is a separate module, built and shipped apart from socair, so the
// scanner's default build keeps its small dependency set; the scanner invokes
// it only when SOCAIR_SIGSTORE_VERIFIER names it. It answers one question:
// does this bundle carry a valid keyless signature, from an identity in the
// policy, under this trust root? Reading the signed payload, and binding it to
// any files, is the scanner's job, on the same bytes it sent here.
//
// Protocol: one JSON request on stdin, one JSON verdict on stdout.
//
//	request:  {"bundle": "<base64 bundle bytes>", "trusted_root": "<path>",
//	           "identities": [{"issuer": "...", "san": "..."}]}
//	          (issuer_regexp and san_regexp may replace issuer and san)
//	verdict:  {"state": "verified" | "invalid" | "unverified",
//	           "signer": "<san> (<issuer>)", "detail": "..."}
//
// A signer outside the identity policy is unverified: anyone can sign
// keylessly, so such a signature proves nothing about the publisher. A
// signer inside the policy whose certificate, transparency-log entry, or
// signature does not hold is invalid.
package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// Identity is one signer the operator accepts.
type Identity struct {
	Issuer       string `json:"issuer,omitempty"`
	IssuerRegexp string `json:"issuer_regexp,omitempty"`
	SAN          string `json:"san,omitempty"`
	SANRegexp    string `json:"san_regexp,omitempty"`
}

// Request is what the scanner sends.
type Request struct {
	Bundle      string     `json:"bundle"`
	TrustedRoot string     `json:"trusted_root"`
	Identities  []Identity `json:"identities"`
}

// Verdict is what the scanner reads back.
type Verdict struct {
	State  string `json:"state"`
	Signer string `json:"signer,omitempty"`
	Detail string `json:"detail,omitempty"`
}

const (
	stateVerified   = "verified"
	stateInvalid    = "invalid"
	stateUnverified = "unverified"
)

// errConfig is a request the verifier cannot act on; the scanner reports it
// as a configuration error, not a verdict on the artifact.
var errConfig = errors.New("socair-sigstore: bad request")

// Verify answers one request.
func Verify(req Request) (Verdict, error) {
	if req.TrustedRoot == "" || len(req.Identities) == 0 {
		return Verdict{}, fmt.Errorf("%w: a trusted root and at least one identity are required", errConfig)
	}
	tr, err := root.NewTrustedRootFromPath(req.TrustedRoot)
	if err != nil {
		return Verdict{}, fmt.Errorf("%w: trusted root: %v", errConfig, err)
	}
	var ids verify.CertificateIdentities
	for _, id := range req.Identities {
		ci, err := verify.NewShortCertificateIdentity(id.Issuer, id.IssuerRegexp, id.SAN, id.SANRegexp)
		if err != nil {
			return Verdict{}, fmt.Errorf("%w: identity %+v: %v", errConfig, id, err)
		}
		ids = append(ids, ci)
	}

	raw, err := base64.StdEncoding.DecodeString(req.Bundle)
	if err != nil {
		return Verdict{}, fmt.Errorf("%w: bundle is not base64", errConfig)
	}
	var b bundle.Bundle
	if err := b.UnmarshalJSON(raw); err != nil {
		return Verdict{State: stateUnverified, Detail: "not a Sigstore bundle this verifier reads: " + err.Error()}, nil
	}
	vc, err := b.VerificationContent()
	if err != nil {
		return Verdict{State: stateUnverified, Detail: "the bundle has no verification material: " + err.Error()}, nil
	}
	leaf := vc.Certificate()
	if leaf == nil {
		return Verdict{State: stateUnverified, Detail: "the bundle is not keyless (no signing certificate)"}, nil
	}
	sum, err := certificate.SummarizeCertificate(leaf)
	if err != nil {
		return Verdict{State: stateUnverified, Detail: "the signing certificate carries no readable identity: " + err.Error()}, nil
	}
	signer := sum.SubjectAlternativeName + " (" + sum.Extensions.Issuer + ")"

	// Who signed decides whether a failure is evidence. Outside the policy,
	// the signature proves nothing either way.
	if _, err := ids.Verify(sum); err != nil {
		return Verdict{State: stateUnverified, Signer: signer, Detail: "signed by an identity that is not in the policy (SOCAIR_SIGSTORE_IDENTITIES)"}, nil
	}

	// Inside the policy: the certificate must chain to the trust root with
	// its certificate-transparency proof, the signature must be in the
	// transparency log, and it must have been made while the certificate was
	// valid, as attested by the log's integrated time or a timestamp
	// authority. The artifact itself is not passed: the payload names the
	// model's files, and the scanner binds them itself.
	v, err := verify.NewVerifier(tr,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1))
	if err != nil {
		return Verdict{}, fmt.Errorf("%w: verifier: %v", errConfig, err)
	}
	if _, err := v.Verify(&b, verify.NewPolicy(verify.WithoutArtifactUnsafe(), verify.WithCertificateIdentity(mustFirst(req.Identities, sum)))); err != nil {
		return Verdict{State: stateInvalid, Signer: signer, Detail: err.Error()}, nil
	}
	return Verdict{State: stateVerified, Signer: signer}, nil
}

// mustFirst returns the policy identity the signer matched, which the
// full verification is then held to.
func mustFirst(ids []Identity, sum certificate.Summary) verify.CertificateIdentity {
	for _, id := range ids {
		ci, err := verify.NewShortCertificateIdentity(id.Issuer, id.IssuerRegexp, id.SAN, id.SANRegexp)
		if err != nil {
			continue
		}
		if ci.Verify(sum) == nil {
			return ci
		}
	}
	return verify.CertificateIdentity{}
}

// handle decodes a request and encodes a verdict.
func handle(in []byte) ([]byte, error) {
	var req Request
	dec := json.NewDecoder(bytesReader(in))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return nil, fmt.Errorf("%w: %v", errConfig, err)
	}
	v, err := Verify(req)
	if err != nil {
		return nil, err
	}
	return json.Marshal(v)
}
