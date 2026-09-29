// Package render turns a report document into the fileable HTML attestation.
//
// The document is the contract; this package is one consumer of it, alongside
// the CLI and the future SvelteKit wizard. Output is byte-stable for a fixed
// input, so a report can be diffed.
package render

import (
	_ "embed"
	"html/template"
	"io"

	"github.com/defilantech/socair/internal/report"
)

//go:embed template.html
var templateHTML string

var tmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"statusClass":    statusClass,
	"isNotTested":    isNotTested,
	"promotionClass": promotionClass,
	"promotionLabel": promotionLabel,
}).Parse(templateHTML))

// Counts tallies check results for the cover block.
type Counts struct {
	Pass      int
	Fail      int
	NotTested int
}

// View is what the template renders.
type View struct {
	Document *report.Document
	Counts   Counts
	Sample   bool
}

// Render writes the HTML attestation for d to w.
func Render(w io.Writer, d *report.Document) error {
	return RenderWith(w, d, Options{})
}

// Options controls optional rendering behavior.
type Options struct {
	// Sample marks the document as fabricated sample data. It is set for the
	// sales demo and must never be set for a real issuance.
	Sample bool
}

// RenderWith writes the HTML attestation with explicit options.
func RenderWith(w io.Writer, d *report.Document, opts Options) error {
	return tmpl.Execute(w, View{Document: d, Counts: countChecks(d), Sample: opts.Sample})
}

func countChecks(d *report.Document) Counts {
	var c Counts
	for _, ch := range d.Checks {
		switch ch.Status {
		case report.StatusPass:
			c.Pass++
		case report.StatusFail:
			c.Fail++
		default:
			c.NotTested++
		}
	}
	return c
}

// statusClass maps a check status to its CSS pill class. NOT_TESTED maps to a
// neutral class, never the pass class.
func statusClass(s report.Status) string {
	switch s {
	case report.StatusPass:
		return "pass"
	case report.StatusFail:
		return "fail"
	default:
		return "not-tested"
	}
}

func isNotTested(s report.Status) bool {
	return s == report.StatusNotTested
}

// promotionClass maps a promotion state to its badge class. The condition
// state is deliberately not the clean class, so an authorized-with-conditions
// report never reads as a clean pass.
func promotionClass(state string) string {
	switch state {
	case report.StateAuthorized:
		return "authorized"
	case report.StateAuthorizedWithConditions:
		return "conditions"
	case report.StateEscalated:
		return "escalated"
	default:
		return "withheld"
	}
}

func promotionLabel(state string) string {
	switch state {
	case report.StateAuthorized:
		return "authorized"
	case report.StateAuthorizedWithConditions:
		return "authorized with conditions"
	case report.StateEscalated:
		return "escalated"
	default:
		return "withheld"
	}
}
