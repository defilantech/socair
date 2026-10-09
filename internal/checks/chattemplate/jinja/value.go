package jinja

import (
	"fmt"
	"math"
	"math/bits"
	"sort"
	"strconv"
	"strings"
)

// Value is a template value. The evaluator uses these Go types: nil (None),
// undefined, bool, int, float64, str, *list (a list or tuple), *dict,
// *namespace, *macro, *loopInfo, builtin, and method. There is no Python
// object model behind them: an attribute is a key, a listed method, or
// undefined, so a template reaches nothing the evaluator does not define.
type Value any

// part is a run of a string's bytes and whether they came from the render's
// inputs.
type part struct {
	s  string
	in bool
}

// str is a string that remembers which of its bytes came from the inputs
// (the conversation, the tools, the special tokens) and which from the
// template. Operations keep that provenance byte for byte where they can.
// safe marks markupsafe's Markup (the |safe filter): adding a plain string
// to it with + escapes that string, as Python does.
type str struct {
	parts []part
	safe  bool
}

func lit(s string) str {
	if s == "" {
		return str{}
	}
	return str{parts: []part{{s: s}}}
}

func inputStr(s string) str {
	if s == "" {
		return str{}
	}
	return str{parts: []part{{s: s, in: true}}}
}

func (s str) String() string {
	if len(s.parts) == 1 {
		return s.parts[0].s
	}
	var b strings.Builder
	for _, p := range s.parts {
		b.WriteString(p.s)
	}
	return b.String()
}

func (s str) len() int {
	n := 0
	for _, p := range s.parts {
		n += len(p.s)
	}
	return n
}

// allInput reports whether every byte came from the inputs.
func (s str) allInput() bool {
	for _, p := range s.parts {
		if !p.in {
			return false
		}
	}
	return len(s.parts) > 0
}

// cat joins strings, merging adjacent parts of the same provenance.
func cat(ss ...str) str {
	var b builder
	for _, s := range ss {
		b.str(s)
	}
	return b.done()
}

func (s *str) push(p part) {
	if p.s == "" {
		return
	}
	if n := len(s.parts); n > 0 && s.parts[n-1].in == p.in {
		s.parts[n-1].s += p.s
		return
	}
	s.parts = append(s.parts, p)
}

// sub is the substring of bytes [lo, hi), with its provenance.
func (s str) sub(lo, hi int) str {
	var out str
	at := 0
	for _, p := range s.parts {
		end := at + len(p.s)
		if end > lo && at < hi {
			a, b := max(lo, at)-at, min(hi, end)-at
			out.push(part{s: p.s[a:b], in: p.in})
		}
		at = end
	}
	return out
}

// cutter takes substrings of one str at increasing offsets in a single pass
// over its parts, where repeated sub calls would be quadratic.
type cutter struct {
	s      str
	pi, at int // the first part that can hold the next offset, and where it starts
}

func (c *cutter) sub(lo, hi int) str {
	for c.pi < len(c.s.parts) && c.at+len(c.s.parts[c.pi].s) <= lo {
		c.at += len(c.s.parts[c.pi].s)
		c.pi++
	}
	var out str
	at := c.at
	for i := c.pi; i < len(c.s.parts) && at < hi; i++ {
		p := c.s.parts[i]
		end := at + len(p.s)
		if end > lo {
			a, b := max(lo, at)-at, min(hi, end)-at
			out.push(part{s: p.s[a:b], in: p.in})
		}
		at = end
	}
	return out
}

// mapText applies a case mapping. When it keeps the byte length (ASCII
// text), provenance is kept byte for byte; otherwise each part is mapped on
// its own.
func (s str) mapText(f func(string) string) str {
	flat := s.String()
	r := f(flat)
	var out str
	if len(r) == len(flat) {
		at := 0
		for _, p := range s.parts {
			out.push(part{s: r[at : at+len(p.s)], in: p.in})
			at += len(p.s)
		}
		return out
	}
	for _, p := range s.parts {
		out.push(part{s: f(p.s), in: p.in})
	}
	return out
}

// runeOffsets returns the byte offset of each rune of s, then len(s).
func runeOffsets(s string) []int {
	offs := make([]int, 0, len(s)+1)
	for i := range s {
		offs = append(offs, i)
	}
	return append(offs, len(s))
}

// undefined is Jinja's Undefined: it prints as "", is false, and iterates as
// empty, and any attribute or item of it is an error. why says what was
// missing.
type undefined struct{ why string }

// list is a list or a tuple. in marks a list that came from the inputs, so
// its brackets and separators count as input when it is printed. gen marks
// the lazy result of a filter such as map or select, which in Jinja is a
// generator: always true, iterable, and with no length, index, or JSON form.
type list struct {
	items []Value
	tuple bool
	in    bool
	gen   bool
}

// errGenerator is what Python raises for a generator used as a sequence.
func errGenerator(what string) error {
	return failf("a generator (the result of map, select, or reverse) has no %s; Jinja needs |list first", what)
}

// generator wraps items as a filter's lazy result.
func generator(items []Value) *list { return &list{items: items, gen: true} }

// dict is an ordered dict.
type dict struct {
	keys []Value
	vals []Value
	in   bool
}

func (d *dict) find(k Value) int {
	for i, x := range d.keys {
		if equal(x, k) {
			return i
		}
	}
	return -1
}

func (d *dict) get(k Value) (Value, bool) {
	if i := d.find(k); i >= 0 {
		return d.vals[i], true
	}
	return nil, false
}

func (d *dict) set(k, v Value) {
	if i := d.find(k); i >= 0 {
		d.vals[i] = v
		return
	}
	d.keys = append(d.keys, k)
	d.vals = append(d.vals, v)
}

// namespace is Jinja's namespace(), the one object a template may assign
// attributes on.
type namespace struct{ attrs dict }

// Map is an ordered mapping for a render's variables: Keys[i] maps to
// Vals[i].
type Map struct {
	Keys []string
	Vals []any
}

// M builds a Map from alternating string keys and values.
func M(kv ...any) Map {
	var m Map
	for i := 0; i+1 < len(kv); i += 2 {
		m.Keys = append(m.Keys, kv[i].(string))
		m.Vals = append(m.Vals, kv[i+1])
	}
	return m
}

// input converts a render variable to a value marked as input: a string,
// bool, int, float64, nil, []any, or Map.
func input(v any) (Value, error) {
	switch v := v.(type) {
	case nil:
		return nil, nil
	case string:
		return inputStr(v), nil
	case bool, int, float64:
		return v, nil
	case []any:
		l := &list{in: true}
		for _, x := range v {
			iv, err := input(x)
			if err != nil {
				return nil, err
			}
			l.items = append(l.items, iv)
		}
		return l, nil
	case Map:
		d := &dict{in: true}
		for i, k := range v.Keys {
			iv, err := input(v.Vals[i])
			if err != nil {
				return nil, err
			}
			d.set(inputStr(k), iv)
		}
		return d, nil
	}
	return nil, fmt.Errorf("jinja: unsupported variable type %T", v)
}

func truthy(v Value) bool {
	switch v := v.(type) {
	case nil, undefined:
		return false
	case bool:
		return v
	case int:
		return v != 0
	case float64:
		return v != 0
	case str:
		return v.len() > 0
	case *list:
		return v.gen || len(v.items) > 0
	case *dict:
		return len(v.keys) > 0
	}
	return true
}

// equal is Python's ==.
func equal(a, b Value) bool {
	if x, ok := number(a); ok {
		y, ok := number(b)
		return ok && x == y
	}
	switch a := a.(type) {
	case nil:
		return b == nil
	case undefined:
		_, ok := b.(undefined)
		return ok
	case str:
		y, ok := b.(str)
		return ok && a.String() == y.String()
	case *list:
		y, ok := b.(*list)
		if ok && (a.gen || y.gen) {
			return a == y
		}
		if !ok || a.tuple != y.tuple || len(a.items) != len(y.items) {
			return false
		}
		for i := range a.items {
			if !equal(a.items[i], y.items[i]) {
				return false
			}
		}
		return true
	case *dict:
		y, ok := b.(*dict)
		if !ok || len(a.keys) != len(y.keys) {
			return false
		}
		for i, k := range a.keys {
			v, ok := y.get(k)
			if !ok || !equal(a.vals[i], v) {
				return false
			}
		}
		return true
	case *namespace, *loopInfo, *macro:
		return a == b
	}
	return false
}

// number reads a numeric value; Python's bool is an int.
func number(v Value) (float64, bool) {
	switch v := v.(type) {
	case bool:
		if v {
			return 1, true
		}
		return 0, true
	case int:
		return float64(v), true
	case float64:
		return v, true
	}
	return 0, false
}

// compare is Python's ordering, for <, <=, >, >=, and sorting.
func compare(a, b Value) (int, error) {
	if x, ok := number(a); ok {
		if y, ok := number(b); ok {
			switch {
			case x < y:
				return -1, nil
			case x > y:
				return 1, nil
			}
			return 0, nil
		}
	}
	if x, ok := a.(str); ok {
		if y, ok := b.(str); ok {
			return strings.Compare(x.String(), y.String()), nil
		}
	}
	if x, ok := a.(*list); ok {
		if y, ok := b.(*list); ok {
			for i := 0; i < len(x.items) && i < len(y.items); i++ {
				if equal(x.items[i], y.items[i]) {
					continue
				}
				return compare(x.items[i], y.items[i])
			}
			return len(x.items) - len(y.items), nil
		}
	}
	return 0, failf("ordering is not defined between %s and %s", typeName(a), typeName(b))
}

func typeName(v Value) string {
	switch v := v.(type) {
	case nil:
		return "None"
	case undefined:
		return "Undefined"
	case bool:
		return "bool"
	case int:
		return "int"
	case float64:
		return "float"
	case str:
		return "str"
	case *list:
		if v.tuple {
			return "tuple"
		}
		return "list"
	case *dict:
		return "dict"
	case *namespace:
		return "Namespace"
	case *loopInfo:
		return "LoopContext"
	}
	return "function"
}

// pyFloat formats a float as Python's repr does.
func pyFloat(f float64) string {
	switch {
	case math.IsNaN(f):
		return "nan"
	case math.IsInf(f, 1):
		return "inf"
	case math.IsInf(f, -1):
		return "-inf"
	}
	if a := math.Abs(f); a != 0 && (a < 1e-4 || a >= 1e16) {
		return strconv.FormatFloat(f, 'e', -1, 64)
	}
	s := strconv.FormatFloat(f, 'f', -1, 64)
	if !strings.Contains(s, ".") {
		s += ".0"
	}
	return s
}

// toStr is Python's str() of a value, with provenance: the template's text
// stays the template's, input stays input, and a container printed whole
// takes its own provenance for its brackets and separators.
func (r *renderer) toStr(v Value) (str, error) {
	switch v := v.(type) {
	case str:
		return v, nil
	case undefined:
		return str{}, nil
	case nil:
		return lit("None"), nil
	case bool:
		if v {
			return lit("True"), nil
		}
		return lit("False"), nil
	case int:
		return lit(strconv.Itoa(v)), nil
	case float64:
		return lit(pyFloat(v)), nil
	case *list, *dict:
		var w builder
		if err := r.repr(&w, v, false); err != nil {
			return str{}, err
		}
		return w.done(), r.charge(w.n)
	case *namespace:
		var w builder
		w.lit("<Namespace ", false)
		if err := r.repr(&w, &v.attrs, false); err != nil {
			return str{}, err
		}
		w.lit(">", false)
		return w.done(), nil
	}
	return str{}, &UnsupportedError{What: "printing a " + typeName(v)}
}

// builder builds a str in time linear in its length, merging runs of the
// same provenance as it goes.
type builder struct {
	parts []part
	cur   strings.Builder
	in    bool
	n     int
}

func (b *builder) lit(s string, in bool) {
	if s == "" {
		return
	}
	if b.cur.Len() > 0 && in != b.in {
		b.flush()
	}
	b.in = in
	b.cur.WriteString(s)
	b.n += len(s)
}

func (b *builder) str(s str) {
	for _, p := range s.parts {
		b.lit(p.s, p.in)
	}
}

func (b *builder) flush() {
	if b.cur.Len() > 0 {
		b.parts = append(b.parts, part{s: b.cur.String(), in: b.in})
		b.cur.Reset()
	}
}

func (b *builder) done() str {
	b.flush()
	return str{parts: b.parts}
}

// repr writes Python's repr of v. in is the provenance of the enclosing
// container, which numbers and punctuation take.
func (r *renderer) repr(w *builder, v Value, in bool) error {
	leave, err := r.enter()
	defer leave()
	if err != nil {
		return err
	}
	if err := r.fits(w.n); err != nil {
		return err
	}
	switch v := v.(type) {
	case str:
		reprStr(w, v)
	case *list:
		if v.gen {
			// Python prints a generator as its memory address.
			return errGenerator("printable form")
		}
		open, closer := "[", "]"
		if v.tuple {
			open, closer = "(", ")"
		}
		w.lit(open, v.in)
		for i, x := range v.items {
			if i > 0 {
				w.lit(", ", v.in)
			}
			if err := r.repr(w, x, v.in); err != nil {
				return err
			}
		}
		if v.tuple && len(v.items) == 1 {
			w.lit(",", v.in)
		}
		w.lit(closer, v.in)
	case *dict:
		w.lit("{", v.in)
		for i, k := range v.keys {
			if i > 0 {
				w.lit(", ", v.in)
			}
			if err := r.repr(w, k, v.in); err != nil {
				return err
			}
			w.lit(": ", v.in)
			if err := r.repr(w, v.vals[i], v.in); err != nil {
				return err
			}
		}
		w.lit("}", v.in)
	case undefined:
		return failf("%s", v.why)
	default:
		s, err := r.toStr(v)
		if err != nil {
			return err
		}
		w.lit(s.String(), in)
	}
	return nil
}

// reprStr quotes a string as Python's repr does, keeping each part's
// provenance for its characters and the string's own for the quotes.
func reprStr(w *builder, s str) {
	flat := s.String()
	q := "'"
	if strings.Contains(flat, "'") && !strings.Contains(flat, `"`) {
		q = `"`
	}
	in := s.allInput()
	w.lit(q, in)
	for _, p := range s.parts {
		var b strings.Builder
		for _, c := range p.s {
			switch {
			case c == '\\':
				b.WriteString(`\\`)
			case string(c) == q:
				b.WriteString(`\` + q)
			case c == '\n':
				b.WriteString(`\n`)
			case c == '\r':
				b.WriteString(`\r`)
			case c == '\t':
				b.WriteString(`\t`)
			case c < 0x20 || c == 0x7f:
				fmt.Fprintf(&b, `\x%02x`, c)
			default:
				b.WriteRune(c)
			}
		}
		w.lit(b.String(), p.in)
	}
	w.lit(q, in)
}

// sortValues sorts in place, stably and Python style, by key(v), and charges
// for the comparisons.
func (r *renderer) sortValues(vs []Value, key func(Value) Value, reverse bool) error {
	if err := r.charge(64 * len(vs) * bits.Len(uint(len(vs)))); err != nil {
		return err
	}
	var err error
	sort.SliceStable(vs, func(i, j int) bool {
		c, e := compare(key(vs[i]), key(vs[j]))
		if e != nil && err == nil {
			err = e
		}
		if reverse {
			return c > 0
		}
		return c < 0
	})
	return err
}
