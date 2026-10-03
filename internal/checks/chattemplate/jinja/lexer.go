package jinja

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

type tokKind int

const (
	tName tokKind = iota
	tNum
	tStr
	tOp
)

type token struct {
	kind tokKind
	v    string
	pos  int
}

type segKind int

const (
	segText segKind = iota
	segOutput
	segStmt
)

// segment is a run of text or one tag with its tokens.
type segment struct {
	kind segKind
	text string
	toks []token
	pos  int
}

// Error is a parse failure with the line it happened on.
type Error struct {
	Line int
	Msg  string
}

func (e *Error) Error() string { return fmt.Sprintf("line %d: %s", e.Line, e.Msg) }

func errAt(src string, pos int, format string, args ...any) *Error {
	if pos > len(src) {
		pos = len(src)
	}
	return &Error{Line: 1 + strings.Count(src[:pos], "\n"), Msg: fmt.Sprintf(format, args...)}
}

// lex splits a template into text runs and tags. Comments are dropped, and a
// raw block becomes text.
func lex(src string) ([]segment, error) {
	var out []segment
	i := 0
	for i < len(src) {
		open := nextOpen(src, i)
		if open < 0 {
			out = append(out, segment{kind: segText, text: src[i:], pos: i})
			break
		}
		if open > i {
			out = append(out, segment{kind: segText, text: src[i:open], pos: i})
		}
		kind := src[open+1]
		j := open + 2
		if j < len(src) && (src[j] == '-' || src[j] == '+') {
			j++
		}
		switch kind {
		case '#':
			end := strings.Index(src[j:], "#}")
			if end < 0 {
				return nil, errAt(src, open, "unclosed comment")
			}
			i = j + end + 2
		case '{', '%':
			closer := "}}"
			sk := segOutput
			if kind == '%' {
				closer, sk = "%}", segStmt
			}
			toks, next, err := lexTag(src, j, closer)
			if err != nil {
				return nil, err
			}
			seg := segment{kind: sk, toks: toks, pos: open}
			i = next
			if sk == segStmt && len(toks) == 1 && toks[0].kind == tName && toks[0].v == "raw" {
				body, after, err := rawBody(src, i)
				if err != nil {
					return nil, err
				}
				out = append(out, segment{kind: segText, text: body, pos: i})
				i = after
				continue
			}
			out = append(out, seg)
		}
	}
	return out, nil
}

// nextOpen finds the next tag opener at or after i.
func nextOpen(src string, i int) int {
	for {
		k := strings.IndexByte(src[i:], '{')
		if k < 0 {
			return -1
		}
		p := i + k
		if p+1 < len(src) && (src[p+1] == '{' || src[p+1] == '%' || src[p+1] == '#') {
			return p
		}
		i = p + 1
	}
}

// rawBody returns the text up to {% endraw %} and the offset after it.
func rawBody(src string, i int) (string, int, error) {
	for k := i; k < len(src); {
		open := strings.Index(src[k:], "{%")
		if open < 0 {
			break
		}
		p := k + open
		j := p + 2
		if j < len(src) && (src[j] == '-' || src[j] == '+') {
			j++
		}
		toks, next, err := lexTag(src, j, "%}")
		if err == nil && len(toks) == 1 && toks[0].v == "endraw" {
			return src[i:p], next, nil
		}
		k = p + 2
	}
	return "", 0, errAt(src, i, "raw block without endraw")
}

var ops3 = []string{"**", "//", "==", "!=", "<=", ">="}

// lexTag tokenizes one tag body starting at i until its closer, which only
// counts outside brackets so a dict literal's "}}" does not end the tag.
func lexTag(src string, i int, closer string) ([]token, int, error) {
	var toks []token
	depth := 0
	for {
		for i < len(src) && strings.ContainsRune(" \t\r\n", rune(src[i])) {
			i++
		}
		if i >= len(src) {
			return nil, 0, errAt(src, i, "unclosed tag, want %q", closer)
		}
		if depth == 0 {
			if strings.HasPrefix(src[i:], closer) {
				return toks, i + len(closer), nil
			}
			if (src[i] == '-' || src[i] == '+') && strings.HasPrefix(src[i+1:], closer) {
				return toks, i + 1 + len(closer), nil
			}
		}
		c := src[i]
		switch {
		case c == '\'' || c == '"':
			s, next, err := lexString(src, i)
			if err != nil {
				return nil, 0, err
			}
			toks = append(toks, token{tStr, s, i})
			i = next
		case isDigit(c):
			j := i
			for j < len(src) && (isDigit(src[j]) || src[j] == '_' || src[j] == '.' ||
				src[j] == 'e' || src[j] == 'E') {
				if src[j] == '.' && (j+1 >= len(src) || !isDigit(src[j+1])) {
					break
				}
				j++
			}
			toks = append(toks, token{tNum, src[i:j], i})
			i = j
		case isNameStart(c):
			j := i + 1
			for j < len(src) && isNameChar(src[j]) {
				j++
			}
			toks = append(toks, token{tName, src[i:j], i})
			i = j
		default:
			op := ""
			for _, o := range ops3 {
				if strings.HasPrefix(src[i:], o) {
					op = o
					break
				}
			}
			if op == "" {
				if !strings.ContainsRune("+-*/%~<>=()[]{},.:|", rune(c)) {
					r, _ := utf8.DecodeRuneInString(src[i:])
					return nil, 0, errAt(src, i, "unexpected character %q in tag", r)
				}
				op = string(c)
			}
			switch op {
			case "(", "[", "{":
				depth++
			case ")", "]", "}":
				depth--
			}
			toks = append(toks, token{tOp, op, i})
			i += len(op)
		}
	}
}

func isDigit(c byte) bool     { return c >= '0' && c <= '9' }
func isNameStart(c byte) bool { return c == '_' || (c|0x20 >= 'a' && c|0x20 <= 'z') }
func isNameChar(c byte) bool  { return isNameStart(c) || isDigit(c) }

// lexString reads a quoted string at i and decodes Python escapes, so a name
// spelled '\x5f\x5fclass\x5f\x5f' is analysed as __class__.
func lexString(src string, i int) (string, int, error) {
	q := src[i]
	var b strings.Builder
	j := i + 1
	for j < len(src) {
		c := src[j]
		if c == q {
			return b.String(), j + 1, nil
		}
		if c != '\\' {
			b.WriteByte(c)
			j++
			continue
		}
		if j+1 >= len(src) {
			break
		}
		e := src[j+1]
		j += 2
		switch e {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case 'a':
			b.WriteByte('\a')
		case 'b':
			b.WriteByte('\b')
		case 'f':
			b.WriteByte('\f')
		case 'v':
			b.WriteByte('\v')
		case '0', '1', '2', '3', '4', '5', '6', '7':
			k := j - 1
			end := k
			for end < len(src) && end < k+3 && src[end] >= '0' && src[end] <= '7' {
				end++
			}
			v, _ := strconv.ParseUint(src[k:end], 8, 32)
			b.WriteRune(rune(v))
			j = end
		case 'x', 'u', 'U':
			n := map[byte]int{'x': 2, 'u': 4, 'U': 8}[e]
			if j+n > len(src) {
				return "", 0, errAt(src, j, "truncated \\%c escape", e)
			}
			v, err := strconv.ParseUint(src[j:j+n], 16, 32)
			if err != nil {
				return "", 0, errAt(src, j, "bad \\%c escape", e)
			}
			b.WriteRune(rune(v))
			j += n
		case '\n':
			// line continuation
		case '\\', '\'', '"':
			b.WriteByte(e)
		default:
			// Python keeps an unknown escape as written.
			b.WriteByte('\\')
			b.WriteByte(e)
		}
	}
	return "", 0, errAt(src, i, "unterminated string")
}
