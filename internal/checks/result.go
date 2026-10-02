// Package checks holds the shared result types for Socair checks.
//
// A check returns PASS, FAIL, LEAD, or NOT_TESTED. FAIL is reserved for
// positive evidence. LEAD is a suspicious signal that is not conclusive: it is
// not a FAIL, but it is not a gap either, so only escalated review clears it.
// Anything ambiguous or unparseable is NOT_TESTED with a named reason, never a
// silent pass and never a guess dressed as a failure.
package checks

// Status is a per-check result.
type Status string

const (
	Pass      Status = "PASS"
	Fail      Status = "FAIL"
	NotTested Status = "NOT_TESTED"
	Lead      Status = "LEAD"
)

// Finding is one piece of positive evidence inside a check.
type Finding struct {
	Pattern string `json:"pattern"`
	Span    string `json:"span,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// Result is the outcome of one check.
type Result struct {
	Name     string    `json:"name"`
	LooksFor string    `json:"looks_for"`
	Status   Status    `json:"status"`
	Findings []Finding `json:"findings,omitempty"`
	Notes    string    `json:"notes,omitempty"`
}
