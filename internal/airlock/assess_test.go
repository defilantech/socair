package airlock

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/defilantech/socair/internal/report"
)

func TestAssessAuthorizedAdmits(t *testing.T) {
	s := trustedStore(t)
	_, d := authorizedArtifact(t)
	a, err := s.Assess(envelopeFor(t, d), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if a.State != report.StateAuthorized || a.Admits() != nil || a.SHA256 != d.Artifact.SHA256 {
		t.Fatalf("state %s admits %v sha %s", a.State, a.Admits(), a.SHA256)
	}
}

// A withheld attestation is valid evidence: Assess returns it, and only
// Admits refuses it. The console needs this to show needs-acceptance.
func TestAssessWithheldVerifiesButDoesNotAdmit(t *testing.T) {
	s := trustedStore(t)
	_, d := authorizedArtifact(t)
	withholdForGap(d)
	a, err := s.Assess(envelopeFor(t, d), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if a.State != report.StateWithheld || a.Admits() == nil {
		t.Fatalf("state %s admits %v", a.State, a.Admits())
	}
}

// TestAdmitsNamesWhatTheWithholdingNeeds: a report withheld only on
// NOT_TESTED rows was refused with "a FAIL or LEAD is clearable only by
// escalated review", which named neither its gaps nor the way through. The
// refusal now follows the reason: gaps need a signed acceptance, and a FAIL
// or LEAD needs a person's review outside Socair. Falsification: return one
// message for every withheld report and one of the cases fails.
func TestAdmitsNamesWhatTheWithholdingNeeds(t *testing.T) {
	s := trustedStore(t)
	_, d := authorizedArtifact(t)
	gap := *d
	gap.Checks = append([]report.CheckResult(nil), d.Checks...)
	withholdForGap(&gap)
	a, err := s.Assess(envelopeFor(t, &gap), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	msg := a.Admits().Error()
	for _, want := range []string{"withholds promotion", gap.Checks[0].Name, "NOT_TESTED", "socair accept", "socair sign --acceptance"} {
		if !strings.Contains(msg, want) {
			t.Errorf("a gap refusal must say %q, got %q", want, msg)
		}
	}
	if strings.Contains(msg, "FAIL") || strings.Contains(msg, "escalat") {
		t.Errorf("a report withheld only on gaps has no FAIL or LEAD to review, got %q", msg)
	}

	fail := *d
	fail.Checks = append([]report.CheckResult(nil), d.Checks...)
	fail.Checks[0].Status = report.StatusFail
	fail.BoundedStatement = report.BoundedStatementFor(fail.Checks)
	fail.Findings.Fails = []string{fail.Checks[0].Name}
	fail.PromotionAuthorization = report.PromotionAuthorization{State: report.StateWithheld, Level: "Tier 1 only"}
	if a, err = s.Assess(envelopeFor(t, &fail), time.Now()); err != nil {
		t.Fatal(err)
	}
	msg = a.Admits().Error()
	for _, want := range []string{"withholds promotion", "FAIL on " + fail.Checks[0].Name, "no acceptance clears", "a person's review outside Socair"} {
		if !strings.Contains(msg, want) {
			t.Errorf("a FAIL refusal must say %q, got %q", want, msg)
		}
	}
	if strings.Contains(msg, "socair accept") || strings.Contains(msg, "escalat") {
		t.Errorf("a FAIL refusal must not point at an acceptance or an escalation, got %q", msg)
	}
}

// Falsification: drop the expiry check in Assess and this returns no error.
func TestAssessExpiredAcceptance(t *testing.T) {
	s := trustedStore(t)
	_, d := authorizedArtifact(t)
	withholdForGap(d)
	ticket := acceptedTicket(t, s, d, time.Hour)
	env, err := os.ReadFile(ticket)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Assess(env, time.Now()); err != nil {
		t.Fatalf("current acceptance: %v", err)
	}
	a, err := s.Assess(env, time.Now().Add(2*time.Hour))
	if !errors.Is(err, ErrAcceptanceExpired) || a == nil || a.Expires.IsZero() {
		t.Fatalf("err %v assessment %+v", err, a)
	}
}

func TestAssessRefusesAnUntrustedKey(t *testing.T) {
	s, err := Init(t.TempDir()) // trusts no key
	if err != nil {
		t.Fatal(err)
	}
	_, d := authorizedArtifact(t)
	if _, err := s.Assess(envelopeFor(t, d), time.Now()); err == nil {
		t.Fatal("an envelope from an untrusted key must not assess")
	}
}
