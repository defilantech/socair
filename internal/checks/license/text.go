package license

import (
	"bufio"
	"embed"
	"fmt"
	"hash/fnv"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// shingleWords is the width of a body fingerprint's shingles: every run of
// this many consecutive words. One changed word changes up to this many.
const shingleWords = 5

// words returns the words of a license text that identify it: letters and
// digits, lowercased, so formatting, punctuation, and line wrapping do not
// change them. A copyright notice names a holder and a year, not the
// license, so it is dropped (see notice); so are list markers ("1.", "(a)"),
// which copies number differently, and URL schemes.
func words(text string) []string {
	var out []string
	lines := strings.Split(text, "\n")
	drop := notice(lines)
	for i, line := range lines {
		if drop[i] {
			continue
		}
		line = listMarker.ReplaceAllString(line, "")
		for _, w := range strings.FieldsFunc(strings.ToLower(line), notWordRune) {
			if w == "http" || w == "https" || w == "www" {
				continue
			}
			out = append(out, w)
		}
	}
	return out
}

// notWordRune splits words. "+" is kept, because "RAIL++-M" and "RAIL-M"
// are different licenses.
func notWordRune(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '+' }

// listMarker is a numbered or bulleted item's marker at the start of a line.
var listMarker = regexp.MustCompile(`^[\s#*>]*(?:\(?[0-9a-zA-Z]{1,3}[.)]|[-*•])\s+`)

// maxNotice is the most lines a copyright notice block holds: a holder line,
// the statement, "All rights reserved".
const maxNotice = 3

// notice marks the lines of copyright notices: every copyright statement,
// and the whole paragraph around one when the paragraph is that short (a
// holder's name above it, "All rights reserved." below). A longer paragraph
// is license text, and only its statement line is dropped.
func notice(lines []string) []bool {
	drop := make([]bool, len(lines))
	for start := 0; start < len(lines); {
		end := start
		for end < len(lines) && strings.TrimSpace(lines[end]) != "" {
			end++
		}
		statement := false
		for i := start; i < end; i++ {
			if copyrightLine(lines[i]) {
				drop[i], statement = true, true
			}
		}
		if statement && end-start <= maxNotice {
			for i := start; i < end; i++ {
				drop[i] = true
			}
		}
		start = end + 1
	}
	return drop
}

// copyrightLine reports whether a line is a copyright statement: "Copyright"
// followed by a year, "(c)", "©", or a placeholder, or a line that starts with
// "(c)" or "©". "copyright notice that is included", a wrapped line of a
// license's own text, is not one.
func copyrightLine(line string) bool {
	t := strings.ToLower(strings.TrimLeft(strings.TrimSpace(line), "#*>-_ \t"))
	if strings.HasPrefix(t, "(c)") || strings.HasPrefix(t, "©") || strings.HasPrefix(t, "spdx-license-identifier") {
		return true
	}
	rest, ok := strings.CutPrefix(t, "copyright")
	if !ok {
		return false
	}
	rest = strings.TrimLeft(rest, " \t:")
	if rest == "" {
		return true
	}
	r, _ := utf8.DecodeRuneInString(rest)
	return r == '(' || r == '©' || r == '[' || unicode.IsDigit(r)
}

// phrase normalizes a catalogue phrase the way words normalizes a text.
func phrase(s string) string { return strings.Join(words(s), " ") }

// hasPhrase reports whether the joined words contain the phrase as whole
// words.
func hasPhrase(joined, p string) bool { return strings.Contains(" "+joined+" ", " "+p+" ") }

func shingleHash(ws []string) uint64 {
	h := fnv.New64a()
	for i, w := range ws {
		if i > 0 {
			h.Write([]byte{' '})
		}
		h.Write([]byte(w))
	}
	return h.Sum64()
}

// Kinds of shingle in a body fingerprint.
const (
	// Required text a copy must carry, word for word.
	Required byte = 'r'
	// Omittable text, such as an appendix, a copy may leave out whole but
	// not change.
	Omittable byte = 'o'
	// Placeholder text, such as a holder's name, a copy fills in with a few
	// words of its own.
	Placeholder byte = 'p'
)

// Shingle is one shingle of a canonical text, in order.
type Shingle struct {
	Hash uint64
	Kind byte
}

// Fingerprint returns the shingles of a canonical license text, in order,
// for a body fingerprint (see fpgen). Text inside [[ and ]] is omittable and
// text inside {{ and }} is a placeholder. A shingle touching a placeholder is
// a placeholder shingle, one touching omittable text is omittable, and every
// other shingle is required.
func Fingerprint(canonical string) ([]Shingle, error) {
	var ws []string
	var kind []byte
	in := Required
	var seg strings.Builder
	flush := func() {
		for _, w := range words(seg.String()) {
			ws = append(ws, w)
			kind = append(kind, in)
		}
		seg.Reset()
	}
	for i := 0; i < len(canonical); i++ {
		m := ""
		if i+1 < len(canonical) {
			m = canonical[i : i+2]
		}
		next, ok := map[string]byte{"[[": Omittable, "{{": Placeholder, "]]": Required, "}}": Required}[m]
		if !ok {
			seg.WriteByte(canonical[i])
			continue
		}
		closes := map[byte]string{Omittable: "]]", Placeholder: "}}"}[in]
		if (in == Required) != (next != Required) || (in != Required && m != closes) {
			return nil, fmt.Errorf("unbalanced %q at byte %d", m, i)
		}
		flush()
		in = next
		i++
	}
	flush()
	if in != Required {
		return nil, fmt.Errorf("unclosed marker")
	}
	if len(ws) < shingleWords {
		return nil, fmt.Errorf("text has %d words, fewer than one shingle", len(ws))
	}
	var out []Shingle
	for i := 0; i+shingleWords <= len(ws); i++ {
		k := Required
		for _, w := range kind[i : i+shingleWords] {
			if w == Placeholder || (w == Omittable && k == Required) {
				k = w
			}
		}
		out = append(out, Shingle{Hash: shingleHash(ws[i : i+shingleWords]), Kind: k})
	}
	return out, nil
}

// body is a license identified by its whole text: its shingles in order,
// each required, omittable, or a placeholder. It holds hashes, not the text.
type body struct {
	seq      []Shingle
	at       map[uint64][]int
	required int
}

//go:embed bodies/*.txt
var bodyFiles embed.FS

// loadBody reads an embedded fingerprint: one shingle per line in text
// order, "<kind> <hex>" with kind r (required), o (omittable), or p
// (placeholder); "#" starts a comment.
func loadBody(name string) (body, error) {
	f, err := bodyFiles.Open("bodies/" + name + ".txt")
	if err != nil {
		return body{}, err
	}
	defer f.Close()
	var seq []Shingle
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		kind, hex, ok := strings.Cut(line, " ")
		v, err := strconv.ParseUint(hex, 16, 64)
		if !ok || err != nil || len(kind) != 1 || !strings.Contains("rop", kind) {
			return body{}, fmt.Errorf("bodies/%s.txt line %d: want \"<r|o|p> <hex>\"", name, n)
		}
		seq = append(seq, Shingle{Hash: v, Kind: kind[0]})
	}
	if err := sc.Err(); err != nil {
		return body{}, err
	}
	b := newBody(seq)
	if b.required == 0 {
		return body{}, fmt.Errorf("bodies/%s.txt has no required shingle", name)
	}
	return b, nil
}

func newBody(seq []Shingle) body {
	b := body{seq: seq, at: map[uint64][]int{}}
	for i, s := range seq {
		b.at[s.Hash] = append(b.at[s.Hash], i)
		if s.Kind == Required {
			b.required++
		}
	}
	return b
}

// maxPreamble bounds the words a copy may carry before the license text,
// which must also be only a title for it (see titleWords): "MIT License",
// "The MIT License (MIT)", "BSD 3-Clause License".
const maxPreamble = 8

// bodyFit is how a text compares with a body, read in order.
type bodyFit struct {
	// preamble is the words before the license text begins.
	preamble []string
	// matched counts the required shingles found in order.
	matched int
	// changed says how the text departs from the license outside its
	// optional parts: "added", "removed", or "" when it does not.
	changed string
}

// maxFill bounds the shingles a filled-in placeholder adds: a holder's name
// of up to twelve words ("The Board of Trustees of the Leland Stanford
// Junior University" is ten).
const maxFill = shingleWords - 1 + 12

// fit walks the text's shingles against the body in order. The text may
// open with a short preamble, leave out omittable parts, and fill a
// placeholder with a few words; any other word added, removed, or changed
// departs from the license.
func (b body) fit(ws []string) bodyFit {
	var f bodyFit
	last, run, started := -1, 0, false
	for i := 0; i+shingleWords <= len(ws); i++ {
		p := b.next(shingleHash(ws[i:i+shingleWords]), last)
		if p < 0 {
			if started {
				run++
			} else {
				f.preamble = ws[:i+1]
			}
			continue
		}
		gap := b.seq[last+1 : p]
		switch {
		case has(gap, Required):
			f.depart("removed")
		case run > 0 && (!has(gap, Placeholder) || run > maxFill):
			f.depart("added")
		}
		if b.seq[p].Kind == Required {
			f.matched++
		}
		last, run, started = p, 0, true
	}
	if run > 0 {
		f.depart("added")
	}
	if has(b.seq[last+1:], Required) {
		f.depart("removed")
	}
	return f
}

func has(seq []Shingle, kind byte) bool {
	for _, s := range seq {
		if s.Kind == kind {
			return true
		}
	}
	return false
}

func (f *bodyFit) depart(how string) {
	if f.changed == "" {
		f.changed = how
	}
}

// next returns the first position after last holding hash h, or -1.
func (b body) next(h uint64, last int) int {
	for _, p := range b.at[h] {
		if p > last {
			return p
		}
	}
	return -1
}

func (f bodyFit) matches() bool { return f.changed == "" && f.matched > 0 }

// near reports whether the text carries nearly all of this license, for
// naming what an unrecognized text is built on.
func (f bodyFit) near(b body) bool { return f.matched*10 >= b.required*9 }
