package engine

import (
	"github.com/defilantech/socair/internal/checks/chattemplate"
	"github.com/defilantech/socair/internal/report"
)

// A check whose input neither the artifact nor the operator supplied does not
// run, rather than grading NOT_TESTED. The report names it under
// out_of_scope.not_run with the reason, so a reader sees what was not done,
// and it withholds nothing, as the License policy row does without a policy.

// knownBadNotRun is the Known-bad hash match check with no list supplied.
// There is no standing public list of malicious model files to default to,
// and a match against nothing says nothing: an organization supplies its own,
// as a local list or in a feed it signs.
var knownBadNotRun = report.NotRunCheck{
	Name:     "Known-bad hash match",
	LooksFor: "Match against the known-bad artifact denylist",
	Reason:   "no known-bad list was supplied (SOCAIR_DENYLIST, or a signed feed that carries one), so the artifact's hash was not matched against one",
}

// noChatTemplate is the Chat template check for an artifact that carries no
// template, where it would be: there was none to read. A template a serving
// stack supplies at run time is outside the artifact.
func noChatTemplate(where string) report.NotRunCheck {
	return report.NotRunCheck{
		Name:     chattemplate.Name,
		LooksFor: chattemplate.LooksFor,
		Reason:   "the artifact carries no chat template (" + where + "), so there was none to read; a template a serving stack supplies is outside the artifact",
	}
}
