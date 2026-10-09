package airlock

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defilantech/socair/internal/acceptance"
	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/report"
)

// withholdForGap makes d the report an acceptor reviews: its first row is
// NOT_TESTED and promotion is withheld.
func withholdForGap(d *report.Document) {
	d.Checks[0].Status = report.StatusNotTested
	d.Findings.NotTested = []string{d.Checks[0].Name}
	d.PromotionAuthorization = report.PromotionAuthorization{
		State:      report.StateWithheld,
		Level:      "Tier 1 only",
		Conditions: "Withheld: " + d.Checks[0].Name + " is NOT_TESTED.",
	}
}

// newAcceptor generates an acceptor key and returns it with its .pub path.
func newAcceptor(t *testing.T) (*attest.PrivateKey, string) {
	t.Helper()
	prefix := filepath.Join(t.TempDir(), "acceptor")
	if _, err := attest.GenerateKey(prefix); err != nil {
		t.Fatal(err)
	}
	k, err := attest.LoadPrivateKey(prefix + ".key")
	if err != nil {
		t.Fatal(err)
	}
	return k, prefix + ".pub"
}

// acceptedTicket runs review, accept, re-issue: the withheld d is signed by
// the operator's test key, an acceptor key (trusted by s) signs an acceptance
// of it, and the re-issued conditional report is signed by the test key. It
// returns the re-issued attestation's path.
func acceptedTicket(t *testing.T, s *Store, d *report.Document, expiresIn time.Duration) string {
	t.Helper()
	v, err := attest.Verify(envelopeFor(t, d), attest.Keyring{testKeyID(t): testKey.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatalf("reviewed report: %v", err)
	}
	k, pub := newAcceptor(t)
	acc, err := attest.Accept(v, k, "Jane Doe, CISO", time.Now().Add(expiresIn), "reviewed in change 4411", time.Now())
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if _, err := s.TrustAcceptor(pub); err != nil {
		t.Fatal(err)
	}
	ring, err := attest.LoadKeyring(pub)
	if err != nil {
		t.Fatal(err)
	}
	final, err := attest.Conditional(v, acc, ring, time.Now())
	if err != nil {
		t.Fatalf("re-issue: %v", err)
	}
	return writeReport(t, &final)
}

// An acceptance typed at scan time (SOCAIR_ACCEPTED_BY) is not signed by
// the acceptor, so it does not cross. Falsification: drop the signed check in
// Promote and this crosses.
func TestPromoteRefusesUnsignedAcceptance(t *testing.T) {
	artifact, d := authorizedArtifact(t)
	d.Checks[0].Status = report.StatusNotTested
	d.Findings.NotTested = []string{d.Checks[0].Name}
	d.PromotionAuthorization = report.PromotionAuthorization{
		State: report.StateAuthorizedWithConditions, Authorized: true, Level: "Tier 1 only",
		AcceptedBy: "chris", AcceptedSurfaces: []string{d.Checks[0].Name},
		AcceptanceExpires: time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
	}
	s := trustedStore(t)
	_, acceptorPub := newAcceptor(t)
	if _, err := s.TrustAcceptor(acceptorPub); err != nil {
		t.Fatal(err)
	}
	_, err := Promote(s, artifact, writeReport(t, d))
	if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "unsigned") {
		t.Fatalf("an unsigned acceptance must be refused by name, got %v", err)
	}
}

func TestPromoteRefusesAnUntrustedAcceptor(t *testing.T) {
	artifact, d := authorizedArtifact(t)
	withholdForGap(d)
	other := trustedStore(t)
	ticket := acceptedTicket(t, other, d, 24*time.Hour) // trusted by another store only

	s := trustedStore(t)
	if _, err := Promote(s, artifact, ticket); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "acceptor key") {
		t.Fatalf("no acceptor keys: %v", err)
	}
	_, unrelated := newAcceptor(t)
	if _, err := s.TrustAcceptor(unrelated); err != nil {
		t.Fatal(err)
	}
	if _, err := Promote(s, artifact, ticket); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "not a trusted acceptor key") {
		t.Fatalf("another acceptor's key: %v", err)
	}
}

// The operator does not accept their own gaps: an acceptance signed by the
// key that signed the attestation is refused, even if that key were listed
// as an acceptor. Falsification: drop the same-key check and it crosses.
func TestPromoteRefusesSelfAcceptance(t *testing.T) {
	artifact, d := authorizedArtifact(t)
	withholdForGap(d)
	v, err := attest.Verify(envelopeFor(t, d), attest.Keyring{testKeyID(t): testKey.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := acceptance.Sign(acceptance.Predicate{
		ReviewedDocumentHash: v.Document.Verification.DocumentHash, AcceptedSurfaces: []string{d.Checks[0].Name},
		AcceptedBy: "the operator", AcceptedAt: time.Now().UTC().Format(time.RFC3339),
		Expires: time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
	}, d.Artifact.FileName, d.Artifact.SHA256, testKey, testKeyID(t))
	if err != nil {
		t.Fatal(err)
	}
	ring := attest.Keyring{testKeyID(t): testKey.Public().(ed25519.PublicKey)}
	if _, err := attest.Conditional(v, raw, ring, time.Now()); err == nil {
		t.Fatal("re-issue with the operator's own acceptance must be refused")
	}

	// Forge the re-issue by hand, and list the operator key as an acceptor
	// behind the store's back: promote still refuses.
	final := v.Document
	pa := &final.PromotionAuthorization
	a, _ := acceptance.Parse(raw)
	pa.State, pa.Authorized = report.StateAuthorizedWithConditions, true
	pa.AcceptedSurfaces = a.AcceptedSurfaces
	pa.AcceptedBy, pa.AcceptedAt, pa.AcceptanceExpires = a.AcceptedBy, a.AcceptedAt, a.Expires
	pa.Acceptance, pa.ReviewedDocumentHash = base64.StdEncoding.EncodeToString(raw), a.ReviewedDocumentHash
	final.Verification.DocumentHash, final.Header.DocumentHash = "", ""
	s := trustedStore(t)
	pub, _ := os.ReadFile(filepath.Join(s.TrustPath(), "test.pub"))
	if err := os.WriteFile(filepath.Join(s.AcceptorPath(), testKeyID(t)+".pub"), pub, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = Promote(s, artifact, writeReport(t, &final))
	if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "own gaps") {
		t.Fatalf("self-acceptance must be refused, got %v", err)
	}
}

func TestTrustListsAreDisjoint(t *testing.T) {
	s := trustedStore(t)
	_, pub := newAcceptor(t)
	if _, err := s.TrustAcceptor(pub); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Trust(pub); err == nil {
		t.Error("an acceptor key must not also become a signing key")
	}
	_, signer := newAcceptor(t)
	if _, err := s.Trust(signer); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TrustAcceptor(signer); err == nil {
		t.Error("a signing key must not also become an acceptor key")
	}
}

// The store names the keys it trusts; promote refuses an attestation whose
// claimed issuer contradicts that name, and logs a confirmed issuer.
func TestPromoteChecksTheIssuer(t *testing.T) {
	artifact, d := authorizedArtifact(t)
	prefix := filepath.Join(t.TempDir(), "imposter")
	if _, err := attest.GenerateNamedKey(prefix, "Defilan Technologies"); err != nil {
		t.Fatal(err)
	}
	k, err := attest.LoadPrivateKey(prefix + ".key")
	if err != nil {
		t.Fatal(err)
	}
	env, err := attest.Sign(*d, k)
	if err != nil {
		t.Fatal(err)
	}
	ticket := filepath.Join(t.TempDir(), "a.dsse.json")
	if err := os.WriteFile(ticket, env, 0o600); err != nil {
		t.Fatal(err)
	}

	s, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.TrustAs(prefix+".pub", "Acme ML Platform"); err != nil {
		t.Fatal(err)
	}
	if _, err := Promote(s, artifact, ticket); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "Acme ML Platform") {
		t.Fatalf("an issuer claim contradicting the store must be refused, got %v", err)
	}

	s2, _ := Init(t.TempDir())
	if _, err := s2.TrustAs(prefix+".pub", ""); err != nil {
		t.Fatal(err)
	}
	e, err := Promote(s2, artifact, ticket)
	if err != nil || !strings.Contains(e.Detail, "issued by Defilan Technologies") {
		t.Fatalf("the store took the key's own name, so it is confirmed: %v %q", err, e.Detail)
	}
}
