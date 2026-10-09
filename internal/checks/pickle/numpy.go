package pickle

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/bits"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// A NumPy .npy file is a header, a Python dict literal naming the dtype and
// shape, then the data: raw bytes, or for a dtype that holds Python objects,
// a pickle (numpy.load with allow_pickle). An .npz is a zip of them.

var npyMagic = []byte("\x93NUMPY")

// maxNPYHeader is numpy's own limit (numpy.lib.format._MAX_HEADER_SIZE): a
// larger header is refused unless the file is trusted.
const maxNPYHeader = 10000

type npyHeader struct {
	descr     string // the descr as written, for notes
	itemsize  int64
	object    bool
	shape     []int64
	count     int64 // elements
	dataStart int64
}

func isNPY(head []byte) bool { return bytes.HasPrefix(head, npyMagic) }

// errNPYUnread is a header this check does not read, or numpy refuses.
var errNPYUnread = errors.New("npy header")

func npyErr(format string, a ...any) error {
	return fmt.Errorf("%w: %s", errNPYUnread, fmt.Sprintf(format, a...))
}

// readNPYHeader parses an .npy header from r, positioned at the magic.
func readNPYHeader(r io.Reader) (npyHeader, error) {
	var h npyHeader
	pre := make([]byte, 8)
	if _, err := io.ReadFull(r, pre); err != nil || !bytes.HasPrefix(pre, npyMagic) {
		return h, npyErr("no .npy magic")
	}
	major, minor := pre[6], pre[7]
	var hlen int64
	switch {
	case major == 1 && minor == 0:
		b := make([]byte, 2)
		if _, err := io.ReadFull(r, b); err != nil {
			return h, npyErr("truncated header length")
		}
		hlen, h.dataStart = int64(binary.LittleEndian.Uint16(b)), 10
	case (major == 2 || major == 3) && minor == 0:
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return h, npyErr("truncated header length")
		}
		hlen, h.dataStart = int64(binary.LittleEndian.Uint32(b)), 12
	default:
		return h, npyErr("format version %d.%d, which numpy does not read", major, minor)
	}
	if hlen > maxNPYHeader {
		return h, npyErr("a header of %d bytes, over numpy's %d-byte limit", hlen, maxNPYHeader)
	}
	raw := make([]byte, hlen)
	if _, err := io.ReadFull(r, raw); err != nil {
		return h, npyErr("truncated header")
	}
	h.dataStart += hlen
	text := string(raw)
	if major < 3 {
		// latin1: every byte is the code point of the same value.
		var sb strings.Builder
		for _, c := range raw {
			sb.WriteRune(rune(c))
		}
		text = sb.String()
	} else if !utf8.Valid(raw) {
		return h, npyErr("a version 3 header that is not UTF-8")
	}
	p := &litParser{s: text, py2Long: major < 3}
	d, err := p.value(0)
	if err == nil {
		p.space()
		if p.i != len(p.s) {
			err = npyErr("text after the header dict")
		}
	}
	if err != nil {
		return h, err
	}
	if d.kind != 'd' || len(d.keys) != 3 {
		return h, npyErr("a header that is not a dict of descr, fortran_order, and shape")
	}
	fields := map[string]pyLit{}
	for i, k := range d.keys {
		fields[k] = d.items[i]
	}
	descr, okD := fields["descr"]
	fortran, okF := fields["fortran_order"]
	shape, okS := fields["shape"]
	if !okD || !okF || !okS || fortran.kind != 'b' || shape.kind != 't' {
		return h, npyErr("a header that is not a dict of descr, fortran_order, and shape")
	}
	for _, s := range shape.items {
		if s.kind != 'i' || s.i < 0 {
			return h, npyErr("a shape that is not a tuple of non-negative ints")
		}
		h.shape = append(h.shape, s.i)
	}
	count, ok := elements(h.shape)
	if !ok {
		return h, npyErr("a shape whose element count overflows")
	}
	h.count = count
	h.itemsize, h.object, err = descrSize(descr, 0)
	if err != nil {
		return h, err
	}
	h.descr = descr.text()
	return h, nil
}

// descrRe is a dtype as dtype.str writes it: a byte order, a kind, a size,
// and for datetimes a unit.
var descrRe = regexp.MustCompile(`^[<>|=]([biufcOSUVMm])([0-9]*)(\[[A-Za-z0-9]+\])?$`)

// descrSize is the item size of an .npy descr, and whether it holds Python
// objects: a dtype string, a list of fields, or a (dtype, shape) subarray.
func descrSize(d pyLit, depth int) (int64, bool, error) {
	if depth > 16 {
		return 0, false, npyErr("a descr nested too deeply")
	}
	switch d.kind {
	case 's':
		m := descrRe.FindStringSubmatch(d.s)
		if m == nil {
			return 0, false, npyErr("descr %q, which this check does not read", excerpt(d.s))
		}
		n, _ := strconv.ParseInt(m[2], 10, 64)
		kind, sized := m[1], m[2] != ""
		switch {
		case kind == "O" && (!sized || n == 8) && m[3] == "":
			return 8, true, nil
		case kind == "U" && sized && m[3] == "":
			return n * 4, false, nil
		case (kind == "S" || kind == "V") && sized && m[3] == "":
			return n, false, nil
		case (kind == "M" || kind == "m") && n == 8:
			return 8, false, nil
		case m[3] != "":
		case kind == "b" && n == 1, (kind == "i" || kind == "u") && (n == 1 || n == 2 || n == 4 || n == 8),
			kind == "f" && (n == 2 || n == 4 || n == 8 || n == 16), kind == "c" && (n == 8 || n == 16 || n == 32):
			return n, false, nil
		}
		return 0, false, npyErr("descr %q, which this check does not read", excerpt(d.s))
	case 't': // (descr, shape): a subarray
		if len(d.items) != 2 || d.items[1].kind != 't' {
			return 0, false, npyErr("a subarray descr that is not (dtype, shape)")
		}
		size, obj, err := descrSize(d.items[0], depth+1)
		if err != nil {
			return 0, false, err
		}
		n, ok := litCount(d.items[1])
		if !ok {
			return 0, false, npyErr("a subarray shape that is not non-negative ints")
		}
		return mulSize(size, n, obj)
	case 'l': // [(name, descr[, shape]), ...]: a structured dtype
		var total int64
		object := false
		for _, f := range d.items {
			if f.kind != 't' || len(f.items) < 2 || len(f.items) > 3 || (f.items[0].kind != 's' && f.items[0].kind != 't') {
				return 0, false, npyErr("a field descr that is not (name, dtype[, shape])")
			}
			size, obj, err := descrSize(f.items[1], depth+1)
			if err != nil {
				return 0, false, err
			}
			if len(f.items) == 3 {
				n, ok := litCount(f.items[2])
				if !ok {
					return 0, false, npyErr("a field shape that is not non-negative ints")
				}
				if size, _, err = mulSize(size, n, obj); err != nil {
					return 0, false, err
				}
			}
			sum, carry := bits.Add64(uint64(total), uint64(size), 0)
			if carry != 0 || sum > math.MaxInt64 {
				return 0, false, npyErr("a dtype whose size overflows")
			}
			total, object = int64(sum), object || obj
		}
		return total, object, nil
	}
	return 0, false, npyErr("a descr that is not a dtype string, field list, or subarray")
}

func litCount(t pyLit) (int64, bool) {
	if t.kind == 'i' && t.i >= 0 {
		return t.i, true
	}
	if t.kind != 't' {
		return 0, false
	}
	var shape []int64
	for _, s := range t.items {
		if s.kind != 'i' || s.i < 0 {
			return 0, false
		}
		shape = append(shape, s.i)
	}
	return elements(shape)
}

func mulSize(size, n int64, obj bool) (int64, bool, error) {
	hi, lo := bits.Mul64(uint64(size), uint64(n))
	if hi != 0 || lo > math.MaxInt64 {
		return 0, false, npyErr("a dtype whose size overflows")
	}
	return int64(lo), obj, nil
}

// pyLit is a Python literal from an .npy header: 's' str, 'i' int, 'b' bool,
// 'n' None, 't' tuple, 'l' list, 'd' dict with string keys.
type pyLit struct {
	kind  byte
	s     string
	i     int64
	b     bool
	items []pyLit
	keys  []string
}

func (l pyLit) text() string {
	switch l.kind {
	case 's':
		return strconv.Quote(l.s)
	case 'i':
		return strconv.FormatInt(l.i, 10)
	case 'b':
		if l.b {
			return "True"
		}
		return "False"
	case 'n':
		return "None"
	}
	parts := make([]string, len(l.items))
	for i, it := range l.items {
		parts[i] = it.text()
	}
	if l.kind == 'l' {
		return "[" + strings.Join(parts, ", ") + "]"
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

// litParser reads the literal subset numpy writes into a header, which
// numpy itself reads with ast.literal_eval. Anything outside it is an error,
// never a guess.
type litParser struct {
	s       string
	i       int
	py2Long bool // numpy strips Python 2's "L" suffix from version 1 and 2 headers
}

func (p *litParser) space() {
	for p.i < len(p.s) && strings.ContainsRune(" \t\r\n", rune(p.s[p.i])) {
		p.i++
	}
}

func (p *litParser) peek() byte {
	p.space()
	if p.i >= len(p.s) {
		return 0
	}
	return p.s[p.i]
}

func (p *litParser) value(depth int) (pyLit, error) {
	if depth > 32 {
		return pyLit{}, npyErr("a header nested too deeply")
	}
	switch c := p.peek(); {
	case c == '{':
		p.i++
		d := pyLit{kind: 'd'}
		for p.peek() != '}' {
			k, err := p.value(depth + 1)
			if err != nil {
				return d, err
			}
			if k.kind != 's' || p.peek() != ':' {
				return d, npyErr("a dict entry that is not a string key and a value")
			}
			p.i++
			v, err := p.value(depth + 1)
			if err != nil {
				return d, err
			}
			for _, seen := range d.keys {
				if seen == k.s {
					return d, npyErr("key %q repeated in the header", k.s)
				}
			}
			d.keys, d.items = append(d.keys, k.s), append(d.items, v)
			if p.peek() == ',' {
				p.i++
			} else if p.peek() != '}' {
				return d, npyErr("a dict without a closing brace")
			}
		}
		p.i++
		return d, nil
	case c == '(' || c == '[':
		p.i++
		closer, kind := byte(')'), byte('t')
		if c == '[' {
			closer, kind = ']', 'l'
		}
		t := pyLit{kind: kind}
		comma := false
		for p.peek() != closer {
			v, err := p.value(depth + 1)
			if err != nil {
				return t, err
			}
			t.items = append(t.items, v)
			if p.peek() == ',' {
				p.i++
				comma = true
			} else if p.peek() != closer {
				return t, npyErr("a sequence without its closing bracket")
			}
		}
		p.i++
		if kind == 't' && len(t.items) == 1 && !comma {
			return t.items[0], nil // (x) is x, not a tuple
		}
		return t, nil
	case c == '\'' || c == '"':
		return p.str(c)
	case c == '-' || (c >= '0' && c <= '9'):
		start := p.i
		p.i++
		for p.i < len(p.s) && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
			p.i++
		}
		n, err := strconv.ParseInt(p.s[start:p.i], 10, 64)
		if err != nil {
			return pyLit{}, npyErr("an int %q this check does not read", excerpt(p.s[start:p.i]))
		}
		if p.py2Long && p.i < len(p.s) && p.s[p.i] == 'L' {
			p.i++
		}
		return pyLit{kind: 'i', i: n}, nil
	}
	for _, w := range []struct {
		word string
		lit  pyLit
	}{{"True", pyLit{kind: 'b', b: true}}, {"False", pyLit{kind: 'b'}}, {"None", pyLit{kind: 'n'}}} {
		if strings.HasPrefix(p.s[p.i:], w.word) {
			p.i += len(w.word)
			return w.lit, nil
		}
	}
	return pyLit{}, npyErr("a header value this check does not read at byte %d", p.i)
}

func (p *litParser) str(quote byte) (pyLit, error) {
	p.i++
	var sb strings.Builder
	for p.i < len(p.s) {
		c := p.s[p.i]
		switch {
		case c == quote:
			p.i++
			return pyLit{kind: 's', s: sb.String()}, nil
		case c == '\\':
			if p.i+1 >= len(p.s) || !strings.ContainsRune(`\'"`, rune(p.s[p.i+1])) {
				return pyLit{}, npyErr("a string escape this check does not read")
			}
			sb.WriteByte(p.s[p.i+1])
			p.i += 2
		case c == '\n':
			return pyLit{}, npyErr("an unterminated string")
		default:
			sb.WriteByte(c)
			p.i++
		}
	}
	return pyLit{}, npyErr("an unterminated string")
}
