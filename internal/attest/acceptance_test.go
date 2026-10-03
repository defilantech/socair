package attest

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/defilantech/socair-verify"

	"github.com/defilantech/socair/internal/acceptance"
	"github.com/defilantech/socair/internal/report"
)

// reviewed signs the golden report (withheld for two NOT_TESTED rows) with an
// operator key and returns it verified, as an acceptor would receive it.
func reviewed(t *testing.T) (*Verified, *PrivateKey, Keyring) {
	t.Helper()
	op, ring, _ := newKey(t)
	env, err := Sign(golden(t), op)
	if err != nil {
		t.Fatal(err)
	}
	v, err := Verify(env, ring)
	if err != nil {
		t.Fatal(err)
	}
	return v, op, ring
}

var (
	at      = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	expires = time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
)

func TestReviewAcceptReissue(t *testing.T) {
	v, op, opRing := reviewed(t)
	acc, accRing, _ := newKey(t)
	raw, err := Accept(v, acc, "Jane Doe, CISO", expires, "change 4411", at)
	if err != nil {
		t.Fatal(err)
	}
	d, err := Conditional(v, raw, accRing, at)
	if err != nil {
		t.Fatal(err)
	}
	pa := d.PromotionAuthorization
	if pa.State != report.StateAuthorizedWithConditions || !pa.Signed() || pa.AcceptedBy != "Jane Doe, CISO" ||
		pa.ReviewedDocumentHash != v.Document.Verification.DocumentHash || pa.AcceptanceExpires != "2026-12-01T00:00:00Z" {
		t.Fatalf("re-issued: %+v", pa)
	}
	// The re-issue signs and verifies, and its acceptance verifies.
	env, err := Sign(d, op)
	if err != nil {
		t.Fatalf("sign re-issued: %v", err)
	}
	fv, err := Verify(env, opRing)
	if err != nil {
		t.Fatal(err)
	}
	if a, err := VerifyAcceptance(fv, accRing, at); err != nil || a.AcceptedBy != "Jane Doe, CISO" {
		t.Fatalf("acceptance: %v %v", a, err)
	}
	if _, err := VerifyAcceptance(fv, accRing, expires); err == nil {
		t.Error("an acceptance at its expiry must not verify")
	}
	if _, err := VerifyAcceptance(fv, opRing, at); err == nil {
		t.Error("an acceptance must verify only against acceptor keys")
	}
}

// Accept refuses what an acceptance must never cover. Falsification: drop a
// guard and its case signs.
func TestAcceptRefuses(t *testing.T) {
	v, op, _ := reviewed(t)
	acc, _, _ := newKey(t)
	cases := map[string]func() error{
		"own key": func() error { _, err := Accept(v, op, "op", expires, "", at); return err },
		"no name": func() error { _, err := Accept(v, acc, " ", expires, "", at); return err },
		"past":    func() error { _, err := Accept(v, acc, "x", at.Add(-time.Hour), "", at); return err },
		"outlasts the re-scan": func() error {
			_, err := Accept(v, acc, "x", time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC), "", at)
			return err
		},
		"a FAIL": func() error {
			f := *v
			f.Document.Checks = append([]report.CheckResult{}, v.Document.Checks...)
			f.Document.Checks[0].Status = report.StatusFail
			_, err := Accept(&f, acc, "x", expires, "", at)
			return err
		},
		"a LEAD": func() error {
			f := *v
			f.Document.Checks = append([]report.CheckResult{}, v.Document.Checks...)
			f.Document.Checks[0].Status = report.StatusLead
			_, err := Accept(&f, acc, "x", expires, "", at)
			return err
		},
		"not withheld": func() error {
			f := *v
			f.Document.PromotionAuthorization.State = report.StateAuthorized
			_, err := Accept(&f, acc, "x", expires, "", at)
			return err
		},
	}
	for name, run := range cases {
		if err := run(); err == nil {
			t.Errorf("%s: Accept must refuse", name)
		}
	}
}

// Conditional refuses an acceptance that is not for exactly this reviewed
// report. Falsification: drop a comparison and its case re-issues.
func TestConditionalRefusesAMismatchedAcceptance(t *testing.T) {
	v, _, _ := reviewed(t)
	acc, accRing, _ := newKey(t)
	sign := func(edit func(*acceptance.Predicate), sha string) []byte {
		p := acceptance.Predicate{
			ReviewedDocumentHash: v.Document.Verification.DocumentHash,
			AcceptedSurfaces:     []string{"File inventory and payloads", "Hash, provenance, lineage"},
			AcceptedBy:           "Jane", AcceptedAt: at.Format(time.RFC3339), Expires: expires.Format(time.RFC3339),
		}
		edit(&p)
		raw, err := acceptance.Sign(p, "x", sha, acc.key, acc.ID)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	sha := v.Document.Artifact.SHA256
	other := strings.Repeat("ab", 32)
	cases := map[string][]byte{
		"another artifact":        sign(func(*acceptance.Predicate) {}, other),
		"another reviewed report": sign(func(p *acceptance.Predicate) { p.ReviewedDocumentHash = other }, sha),
		"one surface short":       sign(func(p *acceptance.Predicate) { p.AcceptedSurfaces = p.AcceptedSurfaces[:1] }, sha),
		"a surface too many":      sign(func(p *acceptance.Predicate) { p.AcceptedSurfaces = append(p.AcceptedSurfaces, "Quant match") }, sha),
		"expired": sign(func(p *acceptance.Predicate) {
			p.Expires = at.Add(-time.Minute).Format(time.RFC3339)
			p.AcceptedAt = at.Add(-time.Hour).Format(time.RFC3339)
		}, sha),
	}
	for name, raw := range cases {
		if _, err := Conditional(v, raw, accRing, at); err == nil {
			t.Errorf("%s: Conditional must refuse", name)
		}
	}
	good := sign(func(*acceptance.Predicate) {}, sha)
	if _, err := Conditional(v, good, Keyring{}, at); err == nil {
		t.Error("an acceptance from no trusted acceptor must be refused")
	}
	if _, err := Conditional(v, good, accRing, at); err != nil {
		t.Errorf("the matching acceptance re-issues: %v", err)
	}
}

// A re-issued report whose fields disagree with its own embedded acceptance
// does not validate, so it cannot be signed. Falsification: drop
// validateAcceptance and these sign.
func TestReissueMustMatchItsAcceptance(t *testing.T) {
	v, op, _ := reviewed(t)
	acc, accRing, _ := newKey(t)
	raw, err := Accept(v, acc, "Jane Doe, CISO", expires, "", at)
	if err != nil {
		t.Fatal(err)
	}
	base, err := Conditional(v, raw, accRing, at)
	if err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*report.PromotionAuthorization){
		"acceptor renamed": func(pa *report.PromotionAuthorization) { pa.AcceptedBy = "Someone Else" },
		"expiry extended":  func(pa *report.PromotionAuthorization) { pa.AcceptanceExpires = "2027-03-01T00:00:00Z" },
		"reviewed hash":    func(pa *report.PromotionAuthorization) { pa.ReviewedDocumentHash = strings.Repeat("cd", 32) },
		"acceptance garbage": func(pa *report.PromotionAuthorization) {
			pa.Acceptance = base64.StdEncoding.EncodeToString([]byte("{}"))
		},
	} {
		d := base
		edit(&d.PromotionAuthorization)
		if _, err := Sign(d, op); err == nil {
			t.Errorf("%s: a report disagreeing with its acceptance must not sign", name)
		}
	}
}

// The re-issued attestation is admitted by the published socair-verify
// v0.1.0, unchanged: the code LLMKube's admission gate runs. It admits it
// under allowConditions and refuses it without, as for any conditional
// attestation.
func TestReissueIsAdmittedBySocairVerifyV010(t *testing.T) {
	v, op, opRing := reviewed(t)
	acc, accRing, _ := newKey(t)
	raw, err := Accept(v, acc, "Jane Doe, CISO", expires, "", at)
	if err != nil {
		t.Fatal(err)
	}
	d, err := Conditional(v, raw, accRing, at)
	if err != nil {
		t.Fatal(err)
	}
	env, err := Sign(d, op)
	if err != nil {
		t.Fatal(err)
	}
	ring := verify.Keyring(opRing)
	if _, err := (verify.Policy{Keys: ring, AllowConditions: true}).Admit(env, d.Artifact.SHA256); err != nil {
		t.Fatalf("LLMKube's gate with allowConditions must admit the re-issue: %v", err)
	}
	if _, err := (verify.Policy{Keys: ring}).Admit(env, d.Artifact.SHA256); err == nil {
		t.Fatal("without allowConditions the gate must refuse a conditional attestation")
	}
}
