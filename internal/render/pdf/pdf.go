// Package pdf draws the attestation as a PDF from the report data model.
//
// Pure Go, no external binary, so it works on an air-gapped appliance. Output
// is deterministic: the creation date comes from the document, not the clock.
// Core fonts are Latin-1; non-Latin text is a named follow-up, not a silent
// mangling.
package pdf

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/go-pdf/fpdf"

	"github.com/defilantech/socair/internal/report"
)

// Page geometry, A4 portrait in millimetres.
const (
	pageWidth = 210.0
	margin    = 15.0
	contentW  = pageWidth - 2*margin
	lineH     = 4.8
)

var colW = []float64{48, 44, 30, 58} // Check, Looks for, Result, Evidence

type rgb struct{ r, g, b int }

var (
	ink         = rgb{28, 28, 30}
	muted       = rgb{107, 107, 112}
	line        = rgb{226, 226, 230}
	passBG      = rgb{230, 244, 234}
	passInk     = rgb{30, 107, 58}
	failBG      = rgb{253, 236, 234}
	failInk     = rgb{163, 35, 27}
	untested    = rgb{241, 241, 243}
	untestedInk = rgb{85, 85, 92}
	leadBG      = rgb{253, 243, 225}
	leadInk     = rgb{138, 75, 0}
)

// UnsignedMark is printed on a report that no key has signed.
const UnsignedMark = "UNSIGNED - not an attestation until signed"

// RenderPDF writes the PDF attestation for d to w.
func RenderPDF(w io.Writer, d *report.Document) error {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(margin, margin, margin)
	pdf.SetAutoPageBreak(true, margin+6)
	pdf.SetCreator("Socair", false)
	pdf.SetTitle("Model Assurance Attestation "+d.Header.DocumentID, false)

	// Sort the internal resource catalogs. Without this the library emits font
	// and image objects in Go map order, so the same document produces different
	// bytes run to run even though the content is identical.
	pdf.SetCatalogSort(true)

	// Deterministic metadata: derive the date from the document, not the clock.
	issued := parsedOrEpoch(d.Header.IssuedUTC)
	pdf.SetCreationDate(issued)
	pdf.SetModificationDate(issued)

	pdf.AddPage()

	title(pdf, "Model Assurance Attestation")
	sub(pdf, "Issued "+d.Header.IssuedUTC+"  ·  Template "+d.Header.TemplateVersion)
	if d.Verification.SignerKeyID == "" {
		// A report no key has signed is a draft, and says so on its face.
		pdf.SetFont("Helvetica", "B", 9)
		pdf.SetTextColor(failInk.r, failInk.g, failInk.b)
		pdf.CellFormat(contentW, 6, UnsignedMark, "", 1, "L", false, 0, "")
	}
	pdf.Ln(2)

	cover(pdf, d)
	pdf.Ln(4)

	heading(pdf, "Checks performed")
	checksTable(pdf, d)
	pdf.Ln(4)

	if al := d.AssuranceLevel; al.Definition != "" {
		heading(pdf, "Assurance level: "+al.Awarded)
		for _, row := range [][2]string{
			{"What it is", al.Definition},
			{"What it means", al.DoesMean},
			{"What it does not mean", al.DoesNotMean},
			{"Tier 2", al.Tier2Note},
		} {
			if row[1] == "" {
				continue
			}
			pdf.SetFont("Helvetica", "B", 9)
			pdf.SetTextColor(ink.r, ink.g, ink.b)
			pdf.MultiCell(contentW, lineH, row[0], "", "L", false)
			pdf.SetFont("Helvetica", "", 9)
			pdf.SetTextColor(muted.r, muted.g, muted.b)
			pdf.MultiCell(contentW, lineH, row[1], "", "L", false)
		}
		pdf.Ln(4)
	}

	heading(pdf, "Bounded statement")
	pdf.SetFont("Helvetica", "I", 10)
	pdf.SetTextColor(ink.r, ink.g, ink.b)
	pdf.MultiCell(contentW, lineH, d.BoundedStatement, "", "L", false)
	pdf.Ln(4)

	heading(pdf, "Out of scope")
	pdf.SetFont("Helvetica", "B", 10)
	pdf.SetTextColor(ink.r, ink.g, ink.b)
	pdf.MultiCell(contentW, lineH, d.OutOfScope.DoesNotCertify, "", "L", false)
	pdf.SetFont("Helvetica", "", 9)
	pdf.SetTextColor(muted.r, muted.g, muted.b)
	for _, item := range d.OutOfScope.Ceiling {
		pdf.MultiCell(contentW, lineH, "• "+item, "", "L", false)
	}
	if len(d.OutOfScope.NotRun) > 0 {
		pdf.Ln(2)
		pdf.MultiCell(contentW, lineH, "Checks not run at this level:", "", "L", false)
		for _, c := range d.OutOfScope.NotRun {
			pdf.MultiCell(contentW, lineH, "• "+c.Name+" ("+c.LooksFor+"): not run. "+c.Reason, "", "L", false)
		}
	}
	if len(d.OutOfScope.UnparsedFormats) > 0 {
		pdf.Ln(2)
		pdf.MultiCell(contentW, lineH, "Not parsed by this scan:", "", "L", false)
		for _, f := range d.OutOfScope.UnparsedFormats {
			pdf.MultiCell(contentW, lineH, "• "+f, "", "L", false)
		}
	}
	if len(d.OutOfScope.UntestedNodeClasses) > 0 {
		pdf.Ln(2)
		pdf.MultiCell(contentW, lineH, "Node classes not tested:", "", "L", false)
		for _, n := range d.OutOfScope.UntestedNodeClasses {
			pdf.MultiCell(contentW, lineH, "• "+n, "", "L", false)
		}
	}
	pdf.Ln(4)

	heading(pdf, "Promotion authorization")
	pdf.SetFont("Helvetica", "", 10)
	pdf.SetTextColor(ink.r, ink.g, ink.b)
	auth := "withheld"
	if d.PromotionAuthorization.Authorized {
		auth = "authorized"
	}
	pdf.MultiCell(contentW, lineH, "Clean-store promotion: "+auth+"  ·  "+d.PromotionAuthorization.Level, "", "L", false)
	if d.PromotionAuthorization.Conditions != "" {
		pdf.SetTextColor(muted.r, muted.g, muted.b)
		pdf.MultiCell(contentW, lineH, d.PromotionAuthorization.Conditions, "", "L", false)
	}
	pdf.Ln(4)

	heading(pdf, "Verification")
	pdf.SetFont("Helvetica", "", 9)
	pdf.SetTextColor(muted.r, muted.g, muted.b)
	pdf.MultiCell(contentW, lineH, "Signing: "+d.Verification.SigningMethod, "", "L", false)
	if d.Verification.SignerKeyID != "" {
		pdf.MultiCell(contentW, lineH, "Signer key: "+d.Verification.SignerKeyID, "", "L", false)
		pdf.MultiCell(contentW, lineH, "Document hash: "+d.Verification.DocumentHash, "", "L", false)
		pdf.MultiCell(contentW, lineH, "A printed report is a claim, not the proof. Check the attestation: socair verify <attestation.dsse.json> --trusted <key.pub> --artifact <file or directory>", "", "L", false)
	}
	pdf.MultiCell(contentW, lineH, "Artifact SHA256: "+d.Verification.ArtifactSHA256, "", "L", false)
	pdf.Ln(2)

	if len(d.Artifact.Files) > 0 {
		heading(pdf, "Files")
		pdf.SetFont("Helvetica", "", 8)
		pdf.SetTextColor(muted.r, muted.g, muted.b)
		pdf.MultiCell(contentW, lineH, "The artifact SHA256 is the digest of this manifest: every file's hash, size, and path (socair.modeldir/v1).", "", "L", false)
		for _, f := range d.Artifact.Files {
			pdf.MultiCell(contentW, lineH, fmt.Sprintf("%s  ·  %s  ·  %d bytes  ·  %s", f.Path, f.Role, f.SizeBytes, f.SHA256), "", "L", false)
		}
		pdf.Ln(2)
	}

	pdf.SetFont("Helvetica", "", 8)
	pdf.SetTextColor(muted.r, muted.g, muted.b)
	footer := d.Issuer.Authority
	if d.Issuer.Excludes != "" {
		footer += "  ·  " + d.Issuer.Excludes
	}
	pdf.MultiCell(contentW, lineH, footer, "", "L", false)

	return pdf.Output(w)
}

func parsedOrEpoch(s string) time.Time {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	return time.Unix(0, 0).UTC()
}

func title(pdf *fpdf.Fpdf, s string) {
	pdf.SetFont("Helvetica", "B", 18)
	pdf.SetTextColor(ink.r, ink.g, ink.b)
	pdf.MultiCell(contentW, 9, s, "", "L", false)
}

func sub(pdf *fpdf.Fpdf, s string) {
	pdf.SetFont("Helvetica", "", 9)
	pdf.SetTextColor(muted.r, muted.g, muted.b)
	pdf.MultiCell(contentW, lineH, s, "", "L", false)
}

func heading(pdf *fpdf.Fpdf, s string) {
	pdf.SetFont("Helvetica", "B", 10)
	pdf.SetTextColor(muted.r, muted.g, muted.b)
	pdf.MultiCell(contentW, lineH+1, strings.ToUpper(s), "", "L", false)
	pdf.SetDrawColor(line.r, line.g, line.b)
	y := pdf.GetY()
	pdf.Line(margin, y, margin+contentW, y)
	pdf.Ln(2)
}

func cover(pdf *fpdf.Fpdf, d *report.Document) {
	pdf.SetFont("Helvetica", "B", 14)
	pdf.SetTextColor(ink.r, ink.g, ink.b)
	pdf.MultiCell(contentW, 7, d.Artifact.Name, "", "L", false)

	pdf.SetFont("Helvetica", "", 8)
	pdf.SetTextColor(muted.r, muted.g, muted.b)
	pdf.MultiCell(contentW, 4, d.Artifact.SHA256, "", "L", false)

	facts := d.Artifact.Format
	if d.Artifact.QuantDeclared != "" {
		facts += "  ·  declared " + d.Artifact.QuantDeclared
	}
	if d.Artifact.QuantObserved != "" {
		facts += "  ·  observed " + d.Artifact.QuantObserved
	}
	if d.Artifact.Split != "" {
		facts += "  ·  " + d.Artifact.Split
	}
	facts += "  ·  document " + d.Header.DocumentID + "  ·  issuer " + d.Issuer.Authority
	pdf.MultiCell(contentW, 4, facts, "", "L", false)
	pdf.Ln(2)

	pdf.SetFont("Helvetica", "B", 11)
	pdf.SetTextColor(ink.r, ink.g, ink.b)
	pdf.CellFormat(contentW, 7, d.Header.AssuranceLevelAwarded, "", 1, "L", false, 0, "")

	// Promotion state, colored by state. The condition state is amber, never the
	// clean pass ink.
	state := d.PromotionAuthorization.State
	label := "withheld"
	stateRGB := untestedInk
	switch state {
	case report.StateAuthorized:
		label, stateRGB = "authorized", passInk
	case report.StateAuthorizedWithConditions:
		label, stateRGB = "authorized with conditions", rgb{122, 90, 0}
	case report.StateEscalated:
		label, stateRGB = "escalated", rgb{122, 90, 0}
	}
	pdf.SetFont("Helvetica", "B", 10)
	pdf.SetTextColor(stateRGB.r, stateRGB.g, stateRGB.b)
	pdf.CellFormat(contentW, 6, "Promotion: "+label, "", 1, "L", false, 0, "")
	if accepted := d.PromotionAuthorization.Accepted(); len(accepted) > 0 {
		pdf.SetFont("Helvetica", "", 8)
		pdf.SetTextColor(122, 90, 0)
		line := "Accepted, not tested: " + strings.Join(accepted, ", ")
		if d.PromotionAuthorization.AcceptedBy != "" {
			line += ". Accepted by " + d.PromotionAuthorization.AcceptedBy + " on " + d.PromotionAuthorization.AcceptedAt
			if d.PromotionAuthorization.Signed() {
				line += " (signed acceptance, until " + d.PromotionAuthorization.AcceptanceExpires + ")."
			} else {
				line += " (unsigned: named at scan time, not signed by the acceptor)."
			}
		}
		pdf.MultiCell(contentW, 4, line, "", "L", false)
	}

	var p, f, l, n int
	for _, c := range d.Checks {
		switch c.Status {
		case report.StatusPass:
			p++
		case report.StatusFail:
			f++
		case report.StatusLead:
			l++
		default:
			n++
		}
	}
	pdf.SetFont("Helvetica", "", 10)
	pdf.SetTextColor(muted.r, muted.g, muted.b)
	pdf.CellFormat(contentW, 6, countsLine(p, f, l, n), "", 1, "L", false, 0, "")
}

func countsLine(pass, fail, lead, notTested int) string {
	part := func(n int, label string) string {
		return itoa(n) + " " + label
	}
	return part(pass, "pass") + "   " + part(fail, "fail") + "   " + part(lead, "lead") + "   " + part(notTested, "not tested")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func checksTable(pdf *fpdf.Fpdf, d *report.Document) {
	// Header row.
	pdf.SetFont("Helvetica", "B", 8)
	pdf.SetTextColor(muted.r, muted.g, muted.b)
	pdf.SetFillColor(255, 255, 255)
	drawRow(pdf, []string{"Check", "Looks for", "Result", "Evidence"}, func(i int) rgb { return muted }, false)

	pdf.SetDrawColor(line.r, line.g, line.b)
	pdf.SetFont("Helvetica", "", 8)
	pdf.SetTextColor(ink.r, ink.g, ink.b)

	for _, c := range d.Checks {
		evidence := c.Evidence
		if evidence == "" {
			evidence = c.Notes
		}
		looks := c.LooksFor
		if c.PassMeans != "" {
			looks += "\nPASS means: " + c.PassMeans
		}
		if len(c.MapsTo) > 0 {
			ids := make([]string, 0, len(c.MapsTo))
			for _, m := range c.MapsTo {
				ids = append(ids, m.ID)
			}
			looks += "\nAddresses " + strings.Join(ids, ", ")
		}
		status := string(c.Status)
		if c.Severity != "" {
			status += "\n" + c.Severity
		}
		cells := []string{c.Name, looks, status, evidence}
		bg, txt := statusColors(c.Status)
		drawRow(pdf, cells, func(i int) rgb {
			if i == 2 {
				return txt
			}
			return ink
		}, true, resultFill{bg, txt})
	}
	pdf.Ln(2)
}

type resultFill struct {
	background rgb
	text       rgb
}

func statusColors(s report.Status) (rgb, rgb) {
	switch s {
	case report.StatusPass:
		return passBG, passInk
	case report.StatusFail:
		return failBG, failInk
	case report.StatusLead:
		return leadBG, leadInk
	default:
		return untested, untestedInk
	}
}

// drawRow lays a table row, filling only the result cell when the row is a
// data row. Row height is the tallest wrapped column.
func drawRow(pdf *fpdf.Fpdf, cells []string, colorFor func(int) rgb, data bool, fills ...resultFill) {
	h := rowHeight(pdf, cells)
	if pdf.GetY()+h > 297-margin-10 {
		pdf.AddPage()
	}
	x0, y0 := pdf.GetX(), pdf.GetY()
	x := x0
	for i, cell := range cells {
		w := colW[i]
		pdf.SetXY(x, y0)
		if data && i == 2 && len(fills) == 1 {
			pdf.SetFillColor(fills[0].background.r, fills[0].background.g, fills[0].background.b)
			pdf.SetTextColor(fills[0].text.r, fills[0].text.g, fills[0].text.b)
			pdf.CellFormat(w-1, h, cell, "", 0, "L", true, 0, "")
		} else {
			pdf.SetTextColor(colorFor(i).r, colorFor(i).g, colorFor(i).b)
			pdf.MultiCell(w-1, lineH, cell, "", "L", false)
		}
		x += w
	}
	pdf.SetXY(x0, y0+h+1)
	pdf.SetDrawColor(line.r, line.g, line.b)
	pdf.Line(x0, y0+h+1, x0+contentW, y0+h+1)
}

func rowHeight(pdf *fpdf.Fpdf, cells []string) float64 {
	max := 1
	for i, c := range cells {
		lines := len(pdf.SplitLines([]byte(c), colW[i]-1))
		if lines > max {
			max = lines
		}
	}
	return float64(max)*lineH + 1.5
}
