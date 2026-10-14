package pdf

import (
	"fmt"
	"strings"

	"github.com/go-pdf/fpdf"
)

// page is the PDF being drawn. The core fonts read each byte of a string as a
// Windows-1252 code (the PDF's WinAnsiEncoding), so a Go string, which is
// UTF-8, must be encoded before it is drawn or measured: drawn as it is, the
// middle dot "·" prints as "Â·" and the bullet "•" as "â€¢". Every method that
// takes text is wrapped here, so no call site can pass UTF-8 through.
type page struct{ *fpdf.Fpdf }

func (p page) MultiCell(w, h float64, s, border, align string, fill bool) {
	p.Fpdf.MultiCell(w, h, winAnsi(s), border, align, fill)
}

func (p page) CellFormat(w, h float64, s, border string, ln int, align string, fill bool, link int, linkStr string) {
	p.Fpdf.CellFormat(w, h, winAnsi(s), border, ln, align, fill, link, linkStr)
}

func (p page) SplitLines(txt []byte, w float64) [][]byte {
	return p.Fpdf.SplitLines([]byte(winAnsi(string(txt))), w)
}

// cp1252 holds the Windows-1252 codes from 0x80 to 0x9F, where it differs
// from Latin-1 (https://www.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/WINDOWS/CP1252.TXT).
// From 0xA0 to 0xFF the code is the code point.
var cp1252 = map[rune]byte{
	'€': 0x80, '‚': 0x82, 'ƒ': 0x83, '„': 0x84, '…': 0x85, '†': 0x86, '‡': 0x87,
	'ˆ': 0x88, '‰': 0x89, 'Š': 0x8A, '‹': 0x8B, 'Œ': 0x8C, 'Ž': 0x8E,
	'‘': 0x91, '’': 0x92, '“': 0x93, '”': 0x94, '•': 0x95, '–': 0x96, '—': 0x97,
	'˜': 0x98, '™': 0x99, 'š': 0x9A, '›': 0x9B, 'œ': 0x9C, 'ž': 0x9E, 'Ÿ': 0x9F,
}

// winAnsi encodes s for the core fonts. A character Windows-1252 has no code
// for (CJK text in a chat template's notes, say) is written as its code
// point, <U+4E2D>, so it is named on the page, never dropped or replaced by a
// look-alike.
func winAnsi(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r < 0x80:
			b.WriteByte(byte(r))
		case r >= 0xA0 && r <= 0xFF:
			b.WriteByte(byte(r))
		default:
			if c, ok := cp1252[r]; ok {
				b.WriteByte(c)
			} else {
				fmt.Fprintf(&b, "<U+%04X>", r)
			}
		}
	}
	return b.String()
}
