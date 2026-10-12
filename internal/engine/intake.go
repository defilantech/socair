package engine

import (
	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/checks/intake"
	"github.com/defilantech/socair/internal/checks/provenance"
	"github.com/defilantech/socair/internal/report"
)

// intakeRow checks the artifact against the organization's intake policy
// (SOCAIR_INTAKE_POLICY) and names the policy in the report's scope. Without
// a policy it adds nothing: no row, no scope entry, and no file is read for
// it. facts is called only when a policy is set.
func (r *references) intakeRow(d *report.Document, facts func() intake.Facts) (checks.Result, bool) {
	if r.intake == nil {
		return checks.Result{}, false
	}
	d.Scope.IntakePolicy = &report.PolicyRef{Name: r.intake.Name, SHA256: r.intake.SHA256}
	return r.intake.Check(facts()), true
}

// intakeFacts are what the scan established that the intake policy is
// checked against: the model files' formats, the provenance manifest only
// when it is bound to this artifact's hash, and the publisher signature's
// verification. checked is false for a header-only scan, which verifies no
// signature.
func intakeFacts(files []intake.File, provOpts provenance.Options, sig *provenance.Signature, checked bool) intake.Facts {
	f := intake.Facts{Files: files, SignatureChecked: checked, Signature: sig}
	m, unbound := provenance.Bind(provOpts)
	if unbound == "" {
		f.Manifest = m
	} else {
		f.Unbound = unbound
	}
	return f
}
