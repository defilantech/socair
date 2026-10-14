package pdf

import (
	"bytes"
	"compress/zlib"
	"io"
	"regexp"
	"testing"
)

func TestWinAnsi(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"plain ASCII (a) \\ b", "plain ASCII (a) \\ b"},
		{"a · b", "a \xb7 b"},
		{"• item", "\x95 item"},
		{"x — y – z", "x \x97 y \x96 z"},
		{"“quoted” ‘and’ …", "\x93quoted\x94 \x91and\x92 \x85"},
		{"café ×2 €", "caf\xe9 \xd72 \x80"},
		{"中文", "<U+4E2D><U+6587>"},
		{"emoji 🙂", "emoji <U+1F642>"},
	} {
		if got := winAnsi(c.in); got != c.want {
			t.Errorf("winAnsi(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

var pdfStream = regexp.MustCompile(`(?s)stream\r?\n(.*?)\r?\nendstream`)

// contentStreams inflates every compressed stream in a rendered PDF.
func contentStreams(t *testing.T, out []byte) []byte {
	t.Helper()
	var all []byte
	for _, m := range pdfStream.FindAllSubmatch(out, -1) {
		r, err := zlib.NewReader(bytes.NewReader(m[1]))
		if err != nil {
			continue
		}
		b, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("inflate a stream: %v", err)
		}
		all = append(all, b...)
	}
	if len(all) == 0 {
		t.Fatal("no content stream found in the PDF")
	}
	return all
}

// TestPDFDrawsWinAnsi: the renderer passed its own UTF-8 punctuation to the
// core fonts, so every PDF printed "Â·" between the cover's facts and "â€¢"
// before each out-of-scope item. Falsification: draw through *fpdf.Fpdf
// instead of page, and the UTF-8 bytes are back in the content.
func TestPDFDrawsWinAnsi(t *testing.T) {
	content := contentStreams(t, render(t, loadGolden(t)))
	for _, utf8Seq := range []string{"\xc2\xb7", "\xe2\x80\xa2"} {
		if bytes.Contains(content, []byte(utf8Seq)) {
			t.Errorf("the PDF draws the UTF-8 bytes %q, which the core fonts print as mojibake", utf8Seq)
		}
	}
	for _, code := range []string{"\xb7", "\x95"} {
		if !bytes.Contains(content, []byte(code)) {
			t.Errorf("the PDF does not draw the Windows-1252 code %q (the middle dot and the bullet)", code)
		}
	}
}
