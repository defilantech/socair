package airlock

import (
	"errors"
	"os"
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
