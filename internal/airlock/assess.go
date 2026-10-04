package airlock

import (
	"errors"
	"fmt"
	"time"

	"github.com/defilantech/socair/internal/acceptance"
	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/report"
)

// ErrAcceptanceExpired marks a conditional attestation whose acceptance has
// lapsed. Assess returns the Assessment with it, so a caller can still show
// what was accepted and when it expired.
var ErrAcceptanceExpired = errors.New("acceptance expired")

// Assessment is an attestation that passed the gate's checks: a signature by
// a trusted key, the issuer the store names for it, and for a conditional
// attestation a current acceptance by a trusted acceptor key.
type Assessment struct {
	Verified        *attest.Verified
	SHA256          string
	State           string
	Issuer          string
	IssuerConfirmed bool
	// Acceptance and Expires are set for authorized_with_conditions only.
	Acceptance *acceptance.Acceptance
	Expires    time.Time
}

// Assess runs the promotion gate's checks on an envelope at a moment, without
// placing anything. Promote and the console both use it, so what the console
// shows as approved is exactly what the gate admits. A withheld or escalated
// attestation assesses; Admits says it does not cross.
func (s *Store) Assess(envelope []byte, at time.Time) (*Assessment, error) {
	ring, names, err := s.TrustedIssuers()
	if err != nil {
		return nil, err
	}
	v, err := attest.Verify(envelope, ring)
	if err != nil {
		return nil, err
	}
	issuer, confirmed, err := v.Issuer(names)
	if err != nil {
		return nil, err
	}
	pa := v.Document.PromotionAuthorization
	a := &Assessment{Verified: v, SHA256: normalizeSHA(v.SHA256), State: pa.State, Issuer: issuer, IssuerConfirmed: confirmed}
	if a.State != report.StateAuthorizedWithConditions {
		return a, nil
	}
	// An acceptance covers its gaps only until it expires. Verify has already
	// required an RFC 3339 expiry; a lapsed one needs a fresh scan and a
	// fresh acceptance.
	exp, err := time.Parse(time.RFC3339, pa.AcceptanceExpires)
	if err != nil {
		return nil, fmt.Errorf("acceptance expiry %q cannot be enforced", pa.AcceptanceExpires)
	}
	a.Expires = exp
	if !at.Before(exp) {
		return a, fmt.Errorf("%w: the acceptance by %s of %d untested surface(s) expired at %s; re-scan and re-accept",
			ErrAcceptanceExpired, pa.AcceptedBy, len(pa.AcceptedSurfaces), exp.UTC().Format(time.RFC3339))
	}
	// The acceptance must be the acceptor's own signature, from a key in
	// acceptor-keys, never the operator's.
	acceptors, err := s.AcceptorKeys()
	if err != nil {
		return nil, err
	}
	acc, err := attest.VerifyAcceptance(v, acceptors, at)
	if err != nil {
		return nil, fmt.Errorf("the conditional attestation's acceptance does not hold: %w", err)
	}
	a.Acceptance = acc
	return a, nil
}

// Admits returns why the attestation does not cross into the clean store, or
// nil when it does.
func (a *Assessment) Admits() error {
	switch a.State {
	case report.StateAuthorized, report.StateAuthorizedWithConditions:
		return nil
	}
	return fmt.Errorf("attestation state %q withholds promotion; a FAIL or LEAD is clearable only by escalated review", a.State)
}
