package attest

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/defilantech/socair/internal/acceptance"
	"github.com/defilantech/socair/internal/report"
)

// gaps are a report's NOT_TESTED rows; ok is false when any row FAILs or
// LEADs, which no acceptance can clear.
func gaps(d report.Document) (names []string, ok bool) {
	for _, c := range d.Checks {
		switch c.Status {
		case report.StatusFail, report.StatusLead:
			return nil, false
		case report.StatusNotTested:
			names = append(names, c.Name)
		}
	}
	return names, true
}

// Accept signs the acceptor's acceptance of a reviewed report: a verified
// attestation that is withheld only for untested surfaces. It accepts exactly
// those surfaces, until expires, which may not outlast the report's re-scan
// date. The acceptor's key must not be the key that signed the report: the
// operator does not accept their own gaps.
func Accept(reviewed *Verified, k *PrivateKey, by string, expires time.Time, rationale string, now time.Time) ([]byte, error) {
	d := reviewed.Document
	if d.PromotionAuthorization.State != report.StateWithheld {
		return nil, fmt.Errorf("the report is %s; only a withheld report is accepted", d.PromotionAuthorization.State)
	}
	surfaces, ok := gaps(d)
	if !ok {
		return nil, errors.New("the report has a FAIL or LEAD, which only escalated review clears, never an acceptance")
	}
	if len(surfaces) == 0 {
		return nil, errors.New("the report has no NOT_TESTED rows to accept")
	}
	if k.ID == reviewed.KeyID {
		return nil, errors.New("the acceptor key is the key that signed the report; the operator does not accept their own gaps")
	}
	if strings.TrimSpace(by) == "" {
		return nil, errors.New("name the acceptor (--by)")
	}
	if !expires.After(now) {
		return nil, errors.New("the expiry is not in the future")
	}
	if due := d.Header.RescanDue; due != "" {
		if t, err := time.Parse(time.RFC3339, due); err == nil && expires.After(t) {
			return nil, fmt.Errorf("the acceptance would outlast the report's re-scan date %s", due)
		}
	}
	return acceptance.Sign(acceptance.Predicate{
		ReviewedDocumentHash: d.Verification.DocumentHash,
		ReviewedDocumentID:   d.Header.DocumentID,
		AcceptedSurfaces:     surfaces,
		AcceptedBy:           strings.TrimSpace(by),
		AcceptedAt:           now.UTC().Format(time.RFC3339),
		Expires:              expires.UTC().Format(time.RFC3339),
		Rationale:            strings.TrimSpace(rationale),
	}, d.Artifact.FileName, d.Artifact.SHA256, k.key, k.ID)
}

// Conditional re-issues a reviewed, withheld report as
// authorized_with_conditions, carrying the acceptor's signed acceptance. The
// acceptance must verify against the acceptor keys, be current, be for this
// artifact and this exact reviewed report, and accept exactly its NOT_TESTED
// rows. The result is unsigned; Sign it with the operator's key.
func Conditional(reviewed *Verified, rawAcceptance []byte, acceptors Keyring, now time.Time) (report.Document, error) {
	d := reviewed.Document
	if d.PromotionAuthorization.State != report.StateWithheld {
		return report.Document{}, fmt.Errorf("the report is %s; only a withheld report is re-issued with an acceptance", d.PromotionAuthorization.State)
	}
	a, err := acceptance.Verify(rawAcceptance, acceptors)
	if err != nil {
		return report.Document{}, err
	}
	if a.KeyID == reviewed.KeyID {
		return report.Document{}, errors.New("the acceptance is signed by the key that signed the report; the operator does not accept their own gaps")
	}
	if err := a.Current(now); err != nil {
		return report.Document{}, err
	}
	surfaces, ok := gaps(d)
	switch {
	case !ok:
		return report.Document{}, errors.New("the report has a FAIL or LEAD; an acceptance never clears one")
	case a.ArtifactSHA256 != d.Artifact.SHA256:
		return report.Document{}, fmt.Errorf("the acceptance is for artifact %s, not %s", a.ArtifactSHA256, d.Artifact.SHA256)
	case a.ReviewedDocumentHash != d.Verification.DocumentHash:
		return report.Document{}, errors.New("the acceptance was signed over another report than this one")
	case !acceptance.SameSurfaces(a.AcceptedSurfaces, surfaces):
		return report.Document{}, fmt.Errorf("the acceptance accepts %v, but the report's NOT_TESTED rows are %v", a.AcceptedSurfaces, surfaces)
	}

	pa := &d.PromotionAuthorization
	pa.State = report.StateAuthorizedWithConditions
	pa.Authorized = true
	pa.AcceptedSurfaces = surfaces
	pa.AcceptedBy = a.AcceptedBy
	pa.AcceptedAt = a.AcceptedAt
	pa.AcceptanceExpires = a.Expires
	pa.Acceptance = base64.StdEncoding.EncodeToString(rawAcceptance)
	pa.ReviewedDocumentHash = a.ReviewedDocumentHash
	pa.Conditions = "Authorized with conditions: " + strings.Join(surfaces, ", ") +
		" are NOT_TESTED and were accepted by " + a.AcceptedBy + " (signed acceptance, acceptor key " + ShortID(a.KeyID) + ") until " + a.Expires + "."
	// The re-issued report is a new document, signed afresh.
	d.Verification.DocumentHash, d.Header.DocumentHash = "", ""
	d.Verification.SignerKeyID, d.Header.SignerKeyID = "", ""
	return d, nil
}

// VerifyAcceptance checks the signed acceptance a verified, conditional report
// carries, against the acceptor keys, at now. A report accepted without a
// signature returns an error naming that.
func VerifyAcceptance(v *Verified, acceptors Keyring, now time.Time) (*acceptance.Acceptance, error) {
	pa := v.Document.PromotionAuthorization
	if pa.State != report.StateAuthorizedWithConditions {
		return nil, nil
	}
	if !pa.Signed() {
		return nil, fmt.Errorf("the acceptance by %s is unsigned (named at scan time); have the acceptor sign one with socair accept", pa.AcceptedBy)
	}
	raw, err := base64.StdEncoding.DecodeString(pa.Acceptance)
	if err != nil {
		return nil, errors.New("the embedded acceptance is not base64")
	}
	a, err := acceptance.Verify(raw, acceptors)
	if err != nil {
		return nil, err
	}
	if a.KeyID == v.KeyID {
		return nil, errors.New("the acceptance is signed by the key that signed the attestation; the operator does not accept their own gaps")
	}
	if err := a.Current(now); err != nil {
		return nil, err
	}
	return a, nil
}
