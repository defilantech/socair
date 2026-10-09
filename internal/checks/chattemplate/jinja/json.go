package jinja

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// jsonOpts are json.dumps's options, as transformers' tojson passes them.
type jsonOpts struct {
	ensureASCII     bool
	pretty          bool
	indent          string
	itemSep, keySep string
	sortKeys        bool
}

// filterToJSON is transformers' tojson, which replaces Jinja's: json.dumps
// with ensure_ascii off, no HTML escaping, and keys in their own order, so
// tojson(x, ensure_ascii=False, indent=None, separators=None,
// sort_keys=False).
func filterToJSON(r *renderer, x Value, args []Value, kw map[string]Value) (Value, error) {
	o := jsonOpts{ensureASCII: truthy(arg(args, kw, 0, "ensure_ascii", false)), itemSep: ", ", keySep: ": "}
	switch ind := arg(args, kw, 1, "indent", nil).(type) {
	case nil:
	case int:
		if err := r.fits(ind); err != nil {
			return nil, err
		}
		o.pretty, o.indent, o.itemSep = true, strings.Repeat(" ", max(ind, 0)), ","
	case str:
		o.pretty, o.indent, o.itemSep = true, ind.String(), ","
	default:
		return nil, failf("tojson indent must be an int or a string, not %s", typeName(ind))
	}
	if sep := arg(args, kw, 2, "separators", nil); sep != nil {
		l, ok := sep.(*list)
		if !ok || len(l.items) != 2 {
			return nil, failf("tojson separators must be a pair of strings")
		}
		a, ok1 := l.items[0].(str)
		b, ok2 := l.items[1].(str)
		if !ok1 || !ok2 {
			return nil, failf("tojson separators must be a pair of strings")
		}
		o.itemSep, o.keySep = a.String(), b.String()
	}
	o.sortKeys = truthy(arg(args, kw, 3, "sort_keys", false))
	var w builder
	if err := r.json(&w, x, false, o, 0); err != nil {
		return nil, err
	}
	return w.done(), r.charge(w.n)
}

// json writes v as json.dumps does. in is the enclosing container's
// provenance, which punctuation, numbers, and literals take.
func (r *renderer) json(w *builder, v Value, in bool, o jsonOpts, level int) error {
	leave, err := r.enter()
	defer leave()
	if err != nil {
		return err
	}
	if err := r.fits(w.n + len(o.indent)*level); err != nil {
		return err
	}
	newline := func(lv int) {
		if o.pretty {
			w.lit("\n"+strings.Repeat(o.indent, lv), in)
		}
	}
	switch v := v.(type) {
	case nil:
		w.lit("null", in)
	case bool:
		w.lit(strconv.FormatBool(v), in)
	case int:
		w.lit(strconv.Itoa(v), in)
	case float64:
		w.lit(jsonFloat(v), in)
	case str:
		jsonString(w, v, o.ensureASCII)
	case *list:
		if v.gen {
			return errGenerator("JSON form")
		}
		in = v.in
		if len(v.items) == 0 {
			w.lit("[]", in)
			return nil
		}
		w.lit("[", in)
		for i, x := range v.items {
			if i > 0 {
				w.lit(o.itemSep, in)
			}
			newline(level + 1)
			if err := r.json(w, x, in, o, level+1); err != nil {
				return err
			}
		}
		newline(level)
		w.lit("]", in)
	case *dict:
		in = v.in
		if len(v.keys) == 0 {
			w.lit("{}", in)
			return nil
		}
		keys := make([]str, len(v.keys))
		order := make([]int, len(v.keys))
		for i, k := range v.keys {
			ks, err := jsonKey(k)
			if err != nil {
				return err
			}
			keys[i], order[i] = ks, i
		}
		if o.sortKeys {
			sort.SliceStable(order, func(a, b int) bool { return keys[order[a]].String() < keys[order[b]].String() })
		}
		w.lit("{", in)
		for n, i := range order {
			if n > 0 {
				w.lit(o.itemSep, in)
			}
			newline(level + 1)
			jsonString(w, keys[i], o.ensureASCII)
			w.lit(o.keySep, in)
			if err := r.json(w, v.vals[i], in, o, level+1); err != nil {
				return err
			}
		}
		newline(level)
		w.lit("}", in)
	default:
		return failf("Object of type %s is not JSON serializable", typeName(v))
	}
	return nil
}

// jsonKey converts a dict key as json.dumps does.
func jsonKey(k Value) (str, error) {
	switch k := k.(type) {
	case str:
		return k, nil
	case nil:
		return lit("null"), nil
	case bool:
		return lit(strconv.FormatBool(k)), nil
	case int:
		return lit(strconv.Itoa(k)), nil
	case float64:
		return lit(jsonFloat(k)), nil
	}
	return str{}, failf("keys must be str, int, float, bool or None, not %s", typeName(k))
}

func jsonFloat(f float64) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	}
	return pyFloat(f)
}

// jsonString writes a JSON string. The quotes take the string's provenance
// when it is all input; each part's characters keep their own.
func jsonString(w *builder, s str, ascii bool) {
	in := s.allInput()
	w.lit(`"`, in)
	for _, p := range s.parts {
		var b strings.Builder
		for _, c := range p.s {
			switch {
			case c == '"':
				b.WriteString(`\"`)
			case c == '\\':
				b.WriteString(`\\`)
			case c == '\n':
				b.WriteString(`\n`)
			case c == '\r':
				b.WriteString(`\r`)
			case c == '\t':
				b.WriteString(`\t`)
			case c == '\b':
				b.WriteString(`\b`)
			case c == '\f':
				b.WriteString(`\f`)
			case c < 0x20:
				fmt.Fprintf(&b, `\u%04x`, c)
			case ascii && c > 0x7e:
				if c > 0xffff {
					hi, lo := utf16.EncodeRune(c)
					fmt.Fprintf(&b, `\u%04x\u%04x`, hi, lo)
				} else {
					fmt.Fprintf(&b, `\u%04x`, c)
				}
			default:
				b.WriteRune(c)
			}
		}
		w.lit(b.String(), p.in)
	}
	w.lit(`"`, in)
}
