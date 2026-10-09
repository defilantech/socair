package jinja

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// builtin is a global function.
type builtin func(r *renderer, args []Value, kw map[string]Value) (Value, error)

// method is a method bound to its receiver: a str, dict, list, or loop.
type method struct {
	recv Value
	name string
}

type (
	filterFunc func(r *renderer, x Value, args []Value, kw map[string]Value) (Value, error)
	testFunc   func(r *renderer, x Value, args []Value) (bool, error)
	strFunc    func(r *renderer, s str, args []Value, kw map[string]Value) (Value, error)
)

// The tables are filled in init: some of their functions apply other
// filters, which would otherwise make an initialization cycle.
var (
	globals    map[string]Value
	filters    map[string]filterFunc
	tests      map[string]testFunc
	strMethods map[string]strFunc
)

// dictMethods and listMethods name the methods a dict or list has. The
// mutating ones are refused when called: Hugging Face renders in an
// immutable sandbox, where they raise.
var (
	dictMethods = map[string]bool{"items": true, "keys": true, "values": true, "get": true,
		"update": true, "pop": true, "popitem": true, "setdefault": true, "clear": true}
	listMethods = map[string]bool{"index": true, "count": true, "append": true, "extend": true,
		"insert": true, "pop": true, "remove": true, "clear": true, "sort": true, "reverse": true}
)

func init() {
	globals = map[string]Value{
		"range":           builtin(globalRange),
		"namespace":       builtin(globalNamespace),
		"dict":            builtin(globalDict),
		"raise_exception": builtin(globalRaise),
		"strftime_now": builtin(func(*renderer, []Value, map[string]Value) (Value, error) {
			return lit(DatePlaceholder), nil
		}),
		"lipsum":    builtin(unsupported("lipsum()")),
		"cycler":    builtin(unsupported("cycler()")),
		"joiner":    builtin(unsupported("joiner()")),
		"zip":       builtin(unsupported("zip()")),
		"enumerate": builtin(unsupported("enumerate()")),
	}
	strMethods = map[string]strFunc{
		"strip":      strStrip(true, true),
		"lstrip":     strStrip(true, false),
		"rstrip":     strStrip(false, true),
		"split":      strSplit,
		"rsplit":     strRsplit,
		"splitlines": strSplitlines,
		"startswith": strAffix(strings.HasPrefix),
		"endswith":   strAffix(strings.HasSuffix),
		"upper":      strMap(strings.ToUpper),
		"lower":      strMap(strings.ToLower),
		"title":      strMap(pyTitle),
		"capitalize": strMap(capitalize),
		"replace":    strReplace,
		"find":       strFind(false),
		"rfind":      strFind(true),
		"index":      strIndex,
		"count": func(r *renderer, s str, args []Value, kw map[string]Value) (Value, error) {
			sub, err := strArg(args, 0)
			if err != nil {
				return nil, err
			}
			if sub == "" {
				return utf8.RuneCountInString(s.String()) + 1, nil
			}
			return strings.Count(s.String(), sub), nil
		},
		"join":      strJoin,
		"format":    strFormat,
		"isdigit":   strIs(unicode.IsDigit),
		"isdecimal": strIs(unicode.IsDigit),
		"isnumeric": strIs(unicode.IsNumber),
		"isalpha":   strIs(unicode.IsLetter),
		"isalnum":   strIs(func(c rune) bool { return unicode.IsLetter(c) || unicode.IsNumber(c) }),
		"isspace":   strIs(pySpace),
		"isupper":   strCase(unicode.IsUpper, unicode.IsLower),
		"islower":   strCase(unicode.IsLower, unicode.IsUpper),
	}
	filters = map[string]filterFunc{
		"abs":         filterAbs,
		"attr":        filterAttr,
		"capitalize":  filterText(capitalize),
		"count":       filterLength,
		"d":           filterDefault,
		"default":     filterDefault,
		"dictsort":    filterDictsort,
		"e":           filterEscape,
		"escape":      filterEscape,
		"first":       filterFirst,
		"float":       filterFloat,
		"forceescape": filterEscape,
		"format":      filterFormat,
		"indent":      filterIndent,
		"int":         filterInt,
		"items":       filterItems,
		"join":        filterJoin,
		"last":        filterLast,
		"length":      filterLength,
		"list":        filterList,
		"lower":       filterText(strings.ToLower),
		"map":         filterMap,
		"max":         filterMinMax(1),
		"min":         filterMinMax(-1),
		"reject":      filterSelect(false, false),
		"rejectattr":  filterSelect(false, true),
		"replace":     filterReplace,
		"reverse":     filterReverse,
		"round":       filterRound,
		"safe":        filterSafe,
		"select":      filterSelect(true, false),
		"selectattr":  filterSelect(true, true),
		"sort":        filterSort,
		"string":      func(r *renderer, x Value, _ []Value, _ map[string]Value) (Value, error) { return r.toStr(x) },
		"sum":         filterSum,
		"title":       filterText(jinjaTitle),
		"tojson":      filterToJSON,
		"trim":        filterTrim,
		"unique":      filterUnique,
		"upper":       filterText(strings.ToUpper),
		"wordcount":   filterWordcount,
	}
	tests = map[string]testFunc{
		"defined":     func(_ *renderer, x Value, _ []Value) (bool, error) { _, u := x.(undefined); return !u, nil },
		"undefined":   func(_ *renderer, x Value, _ []Value) (bool, error) { _, u := x.(undefined); return u, nil },
		"none":        func(_ *renderer, x Value, _ []Value) (bool, error) { return x == nil, nil },
		"string":      func(_ *renderer, x Value, _ []Value) (bool, error) { _, ok := x.(str); return ok, nil },
		"mapping":     func(_ *renderer, x Value, _ []Value) (bool, error) { _, ok := x.(*dict); return ok, nil },
		"boolean":     func(_ *renderer, x Value, _ []Value) (bool, error) { _, ok := x.(bool); return ok, nil },
		"true":        func(_ *renderer, x Value, _ []Value) (bool, error) { return x == true, nil },
		"false":       func(_ *renderer, x Value, _ []Value) (bool, error) { return x == false, nil },
		"integer":     func(_ *renderer, x Value, _ []Value) (bool, error) { _, ok := x.(int); return ok, nil },
		"float":       func(_ *renderer, x Value, _ []Value) (bool, error) { _, ok := x.(float64); return ok, nil },
		"number":      func(_ *renderer, x Value, _ []Value) (bool, error) { _, ok := number(x); return ok, nil },
		"iterable":    testIterable,
		"sequence":    testSequence,
		"callable":    testCallable,
		"sameas":      testSameas,
		"escaped":     func(*renderer, Value, []Value) (bool, error) { return false, nil },
		"eq":          testEqual(true),
		"equalto":     testEqual(true),
		"==":          testEqual(true),
		"ne":          testEqual(false),
		"!=":          testEqual(false),
		"lt":          testOrder(func(c int) bool { return c < 0 }),
		"lessthan":    testOrder(func(c int) bool { return c < 0 }),
		"<":           testOrder(func(c int) bool { return c < 0 }),
		"le":          testOrder(func(c int) bool { return c <= 0 }),
		"<=":          testOrder(func(c int) bool { return c <= 0 }),
		"gt":          testOrder(func(c int) bool { return c > 0 }),
		"greaterthan": testOrder(func(c int) bool { return c > 0 }),
		">":           testOrder(func(c int) bool { return c > 0 }),
		"ge":          testOrder(func(c int) bool { return c >= 0 }),
		">=":          testOrder(func(c int) bool { return c >= 0 }),
		"in":          testIn,
		"odd":         testParity(1),
		"even":        testParity(0),
		"divisibleby": testDivisible,
		"lower":       testCase(unicode.IsLower, unicode.IsUpper),
		"upper":       testCase(unicode.IsUpper, unicode.IsLower),
	}
}

func unsupported(what string) func(*renderer, []Value, map[string]Value) (Value, error) {
	return func(*renderer, []Value, map[string]Value) (Value, error) {
		return nil, &UnsupportedError{What: what}
	}
}

// arg is the i-th positional argument, or the named keyword, or def.
func arg(args []Value, kw map[string]Value, i int, name string, def Value) Value {
	if i < len(args) {
		return args[i]
	}
	if v, ok := kw[name]; ok {
		return v
	}
	return def
}

func strArg(args []Value, i int) (string, error) {
	if i >= len(args) {
		return "", failf("missing a string argument")
	}
	s, ok := args[i].(str)
	if !ok {
		return "", failf("expected a string, got %s", typeName(args[i]))
	}
	return s.String(), nil
}

func intArg(v Value, name string) (int, error) {
	switch v := v.(type) {
	case int:
		return v, nil
	case bool:
		if v {
			return 1, nil
		}
		return 0, nil
	}
	return 0, failf("%s must be an integer, not %s", name, typeName(v))
}

// --- globals -----------------------------------------------------------------

func globalRange(r *renderer, args []Value, _ map[string]Value) (Value, error) {
	var bounds []int
	for _, a := range args {
		n, err := intArg(a, "range argument")
		if err != nil {
			return nil, err
		}
		bounds = append(bounds, n)
	}
	lo, hi, step := 0, 0, 1
	switch len(bounds) {
	case 1:
		hi = bounds[0]
	case 2:
		lo, hi = bounds[0], bounds[1]
	case 3:
		lo, hi, step = bounds[0], bounds[1], bounds[2]
	default:
		return nil, failf("range takes one to three arguments")
	}
	if step == 0 {
		return nil, failf("range step cannot be zero")
	}
	n := 0
	if step > 0 && hi > lo {
		n = (hi - lo + step - 1) / step
	} else if step < 0 && hi < lo {
		n = (lo - hi - step - 1) / -step
	}
	if err := r.items(n); err != nil {
		return nil, err
	}
	out := &list{}
	for i := 0; i < n; i++ {
		out.items = append(out.items, lo+i*step)
	}
	return out, nil
}

func globalNamespace(_ *renderer, args []Value, kw map[string]Value) (Value, error) {
	ns := &namespace{}
	for _, a := range args {
		d, ok := a.(*dict)
		if !ok {
			return nil, failf("namespace() takes a dict or keywords")
		}
		for i, k := range d.keys {
			ns.attrs.set(k, d.vals[i])
		}
	}
	for _, k := range sortedKeys(kw) {
		ns.attrs.set(lit(k), kw[k])
	}
	return ns, nil
}

func globalDict(_ *renderer, args []Value, kw map[string]Value) (Value, error) {
	d := &dict{}
	for _, a := range args {
		src, ok := a.(*dict)
		if !ok {
			return nil, &UnsupportedError{What: "dict() of a " + typeName(a)}
		}
		for i, k := range src.keys {
			d.set(k, src.vals[i])
		}
	}
	for _, k := range sortedKeys(kw) {
		d.set(lit(k), kw[k])
	}
	return d, nil
}

func globalRaise(r *renderer, args []Value, _ map[string]Value) (Value, error) {
	msg := ""
	if len(args) > 0 {
		s, err := r.toStr(args[0])
		if err != nil {
			return nil, err
		}
		msg = s.String()
	}
	return nil, &RaiseError{Message: msg}
}

// sortedKeys orders keyword arguments. Python keeps call order, which the
// parser does not record; sorted is at least the same on every run.
func sortedKeys(kw map[string]Value) []string {
	keys := make([]string, 0, len(kw))
	for k := range kw {
		keys = append(keys, k)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}

// --- methods -----------------------------------------------------------------

func (r *renderer) callMethod(m method, args []Value, kw map[string]Value) (Value, error) {
	switch recv := m.recv.(type) {
	case str:
		return strMethods[m.name](r, recv, args, kw)
	case *dict:
		switch m.name {
		case "items":
			out := &list{in: recv.in}
			for i, k := range recv.keys {
				out.items = append(out.items, &list{items: []Value{k, recv.vals[i]}, tuple: true, in: recv.in})
			}
			return out, nil
		case "keys":
			return &list{items: append([]Value(nil), recv.keys...), in: recv.in}, nil
		case "values":
			return &list{items: append([]Value(nil), recv.vals...), in: recv.in}, nil
		case "get":
			if len(args) == 0 {
				return nil, failf("get() takes a key")
			}
			if v, ok := recv.get(args[0]); ok {
				return v, nil
			}
			return arg(args, kw, 1, "default", nil), nil
		}
		return nil, failf("transformers' immutable sandbox refuses dict.%s()", m.name)
	case *list:
		switch m.name {
		case "index":
			for i, x := range recv.items {
				if len(args) > 0 && equal(x, args[0]) {
					return i, nil
				}
			}
			return nil, failf("value is not in the list")
		case "count":
			n := 0
			for _, x := range recv.items {
				if len(args) > 0 && equal(x, args[0]) {
					n++
				}
			}
			return n, nil
		}
		return nil, failf("transformers' immutable sandbox refuses list.%s()", m.name)
	case *loopInfo:
		if len(args) == 0 {
			return nil, failf("loop.cycle() takes at least one argument")
		}
		return args[recv.index0%len(args)], nil
	}
	return nil, failf("%s has no method %s", typeName(m.recv), m.name)
}

// pySpace is Python's str.isspace for one character.
func pySpace(c rune) bool { return unicode.IsSpace(c) || (c >= 0x1c && c <= 0x1f) }

func strStrip(left, right bool) strFunc {
	return func(_ *renderer, s str, args []Value, _ map[string]Value) (Value, error) {
		cut := pySpace
		if len(args) > 0 && args[0] != nil {
			chars, err := strArg(args, 0)
			if err != nil {
				return nil, err
			}
			cut = func(c rune) bool { return strings.ContainsRune(chars, c) }
		}
		return stripStr(s, cut, left, right), nil
	}
}

func stripStr(s str, cut func(rune) bool, left, right bool) str {
	flat := s.String()
	lo, hi := 0, len(flat)
	if left {
		lo = len(flat) - len(strings.TrimLeftFunc(flat, cut))
	}
	if right {
		hi = len(strings.TrimRightFunc(flat, cut))
	}
	if lo > hi {
		return str{}
	}
	return s.sub(lo, hi)
}

// splitStr is Python's str.split: on sep, or on runs of whitespace when sep
// is "" and whitespace is set; at most max splits when max >= 0.
func splitStr(s str, sep string, whitespace bool, max int) []str {
	flat, cs := s.String(), &cutter{s: s}
	var out []str
	if whitespace {
		i := 0
		for i < len(flat) {
			c, n := utf8.DecodeRuneInString(flat[i:])
			if pySpace(c) {
				i += n
				continue
			}
			if max >= 0 && len(out) == max {
				end := len(strings.TrimRightFunc(flat, pySpace))
				return append(out, cs.sub(i, end))
			}
			j := i
			for j < len(flat) {
				c, n := utf8.DecodeRuneInString(flat[j:])
				if pySpace(c) {
					break
				}
				j += n
			}
			out = append(out, cs.sub(i, j))
			i = j
		}
		return out
	}
	start := 0
	for max < 0 || len(out) < max {
		k := strings.Index(flat[start:], sep)
		if k < 0 {
			break
		}
		out = append(out, cs.sub(start, start+k))
		start += k + len(sep)
	}
	return append(out, cs.sub(start, len(flat)))
}

func splitArgs(args []Value, kw map[string]Value) (string, bool, int, error) {
	sepV := arg(args, kw, 0, "sep", nil)
	max := -1
	if m := arg(args, kw, 1, "maxsplit", -1); m != nil {
		n, err := intArg(m, "maxsplit")
		if err != nil {
			return "", false, 0, err
		}
		max = n
	}
	if sepV == nil {
		return "", true, max, nil
	}
	sep, ok := sepV.(str)
	if !ok || sep.len() == 0 {
		return "", false, 0, failf("empty or non-string separator")
	}
	return sep.String(), false, max, nil
}

func strList(items []str, in bool) *list {
	out := &list{in: in}
	for _, x := range items {
		out.items = append(out.items, x)
	}
	return out
}

func strSplit(_ *renderer, s str, args []Value, kw map[string]Value) (Value, error) {
	sep, ws, max, err := splitArgs(args, kw)
	if err != nil {
		return nil, err
	}
	return strList(splitStr(s, sep, ws, max), s.allInput()), nil
}

func strRsplit(_ *renderer, s str, args []Value, kw map[string]Value) (Value, error) {
	sep, ws, max, err := splitArgs(args, kw)
	if err != nil {
		return nil, err
	}
	if ws || max < 0 {
		return strList(splitStr(s, sep, ws, -1), s.allInput()), nil
	}
	flat := s.String()
	var cuts []int // separator offsets, right to left
	end := len(flat)
	for len(cuts) < max {
		k := strings.LastIndex(flat[:end], sep)
		if k < 0 {
			break
		}
		cuts = append(cuts, k)
		end = k
	}
	cs := &cutter{s: s}
	var out []str
	start := 0
	for i := len(cuts) - 1; i >= 0; i-- {
		out = append(out, cs.sub(start, cuts[i]))
		start = cuts[i] + len(sep)
	}
	out = append(out, cs.sub(start, len(flat)))
	return strList(out, s.allInput()), nil
}

func strSplitlines(_ *renderer, s str, args []Value, kw map[string]Value) (Value, error) {
	keep := truthy(arg(args, kw, 0, "keepends", false))
	return strList(splitLines(s, keep), s.allInput()), nil
}

// splitLines is Python's str.splitlines.
func splitLines(s str, keep bool) []str {
	flat, cs := s.String(), &cutter{s: s}
	var out []str
	start := 0
	for i := 0; i < len(flat); {
		c, n := utf8.DecodeRuneInString(flat[i:])
		switch c {
		case '\n', '\r', '\v', '\f', 0x1c, 0x1d, 0x1e, 0x85, 0x2028, 0x2029:
			end := i + n
			if c == '\r' && end < len(flat) && flat[end] == '\n' {
				end++
			}
			if keep {
				out = append(out, cs.sub(start, end))
			} else {
				out = append(out, cs.sub(start, i))
			}
			start, i = end, end
			continue
		}
		i += n
	}
	if start < len(flat) {
		out = append(out, cs.sub(start, len(flat)))
	}
	return out
}

func strAffix(has func(string, string) bool) strFunc {
	return func(_ *renderer, s str, args []Value, _ map[string]Value) (Value, error) {
		if len(args) != 1 {
			return nil, &UnsupportedError{What: "startswith or endswith with start and end positions"}
		}
		flat := s.String()
		switch a := args[0].(type) {
		case str:
			return has(flat, a.String()), nil
		case *list:
			for _, x := range a.items {
				p, ok := x.(str)
				if !ok {
					return nil, failf("a prefix must be a string")
				}
				if has(flat, p.String()) {
					return true, nil
				}
			}
			return false, nil
		}
		return nil, failf("a prefix must be a string or a tuple of strings")
	}
}

func strMap(f func(string) string) strFunc {
	return func(_ *renderer, s str, _ []Value, _ map[string]Value) (Value, error) {
		return s.mapText(f), nil
	}
}

func strReplace(r *renderer, s str, args []Value, kw map[string]Value) (Value, error) {
	if len(args) < 2 {
		return nil, failf("replace() takes two strings")
	}
	old, ok1 := args[0].(str)
	repl, ok2 := args[1].(str)
	if !ok1 || !ok2 {
		return nil, failf("replace() takes two strings")
	}
	count := -1
	if c := arg(args, kw, 2, "count", nil); c != nil {
		n, err := intArg(c, "count")
		if err != nil {
			return nil, err
		}
		count = n
	}
	return r.replace(s, old.String(), repl, count)
}

// replace is Python's str.replace, with the replacement's own provenance.
func (r *renderer) replace(s str, old string, repl str, count int) (Value, error) {
	flat := s.String()
	n := strings.Count(flat, old)
	if old == "" {
		n = utf8.RuneCountInString(flat) + 1
	}
	if count >= 0 && count < n {
		n = count
	}
	if err := r.sized(len(flat) + n*(repl.len()-len(old))); err != nil {
		return nil, err
	}
	var out builder
	cs := &cutter{s: s}
	at := 0
	for done := 0; done < n; done++ {
		if old == "" {
			out.str(repl)
			if at < len(flat) {
				_, w := utf8.DecodeRuneInString(flat[at:])
				out.str(cs.sub(at, at+w))
				at += w
			}
			continue
		}
		k := strings.Index(flat[at:], old)
		out.str(cs.sub(at, at+k))
		out.str(repl)
		at += k + len(old)
	}
	out.str(cs.sub(at, len(flat)))
	return out.done(), nil
}

func strFind(last bool) strFunc {
	return func(_ *renderer, s str, args []Value, _ map[string]Value) (Value, error) {
		if len(args) != 1 {
			return nil, &UnsupportedError{What: "find() with start and end positions"}
		}
		sub, err := strArg(args, 0)
		if err != nil {
			return nil, err
		}
		flat := s.String()
		k := strings.Index(flat, sub)
		if last {
			k = strings.LastIndex(flat, sub)
		}
		if k < 0 {
			return -1, nil
		}
		return utf8.RuneCountInString(flat[:k]), nil
	}
}

func strIndex(r *renderer, s str, args []Value, kw map[string]Value) (Value, error) {
	v, err := strFind(false)(r, s, args, kw)
	if err == nil && v == -1 {
		return nil, failf("substring not found")
	}
	return v, err
}

func strJoin(r *renderer, s str, args []Value, _ map[string]Value) (Value, error) {
	if len(args) != 1 {
		return nil, failf("join() takes one iterable")
	}
	items, err := r.iterate(args[0])
	if err != nil {
		return nil, err
	}
	var out builder
	for i, x := range items {
		t, ok := x.(str)
		if !ok {
			return nil, failf("sequence item %d: expected str, got %s", i, typeName(x))
		}
		if err := r.fits(out.n + s.len() + t.len()); err != nil {
			return nil, err
		}
		if i > 0 {
			out.str(s)
		}
		out.str(t)
	}
	return out.done(), r.charge(out.n)
}

// strFormat is Python's str.format with {}, {0}, and {name} fields and no
// format specs.
func strFormat(r *renderer, s str, args []Value, kw map[string]Value) (Value, error) {
	flat, cs := s.String(), &cutter{s: s}
	var w builder
	auto := 0
	for i := 0; i < len(flat); {
		switch {
		case strings.HasPrefix(flat[i:], "{{"):
			w.str(cs.sub(i, i+1))
			i += 2
		case strings.HasPrefix(flat[i:], "}}"):
			w.str(cs.sub(i, i+1))
			i += 2
		case flat[i] == '{':
			end := strings.IndexByte(flat[i:], '}')
			if end < 0 {
				return nil, failf("single '{' in a format string")
			}
			field := flat[i+1 : i+end]
			var v Value
			switch {
			case field == "":
				if auto >= len(args) {
					return nil, failf("format() is missing an argument")
				}
				v = args[auto]
				auto++
			case strings.Trim(field, "0123456789") == "":
				n, _ := strconv.Atoi(field)
				if n >= len(args) {
					return nil, failf("format() is missing argument %d", n)
				}
				v = args[n]
			case isIdent(field):
				x, ok := kw[field]
				if !ok {
					return nil, failf("format() is missing %s", field)
				}
				v = x
			default:
				return nil, &UnsupportedError{What: "the format field {" + field + "}"}
			}
			t, err := r.toStr(v)
			if err != nil {
				return nil, err
			}
			w.str(t)
			i += end + 1
		default:
			n := strings.IndexAny(flat[i+1:], "{}") + 1
			if n == 0 {
				n = len(flat) - i
			}
			w.str(cs.sub(i, i+n))
			i += n
		}
		if err := r.fits(w.n); err != nil {
			return nil, err
		}
	}
	return w.done(), r.charge(w.n)
}

func isIdent(s string) bool {
	for i, c := range s {
		if !(c == '_' || unicode.IsLetter(c) || (i > 0 && unicode.IsDigit(c))) {
			return false
		}
	}
	return s != ""
}

func strIs(f func(rune) bool) strFunc {
	return func(_ *renderer, s str, _ []Value, _ map[string]Value) (Value, error) {
		flat := s.String()
		if flat == "" {
			return false, nil
		}
		for _, c := range flat {
			if !f(c) {
				return false, nil
			}
		}
		return true, nil
	}
}

// strCase is isupper or islower: at least one cased character, none of the
// other case.
func strCase(is, other func(rune) bool) strFunc {
	return func(_ *renderer, s str, _ []Value, _ map[string]Value) (Value, error) {
		return hasCase(s.String(), is, other), nil
	}
}

func hasCase(s string, is, other func(rune) bool) bool {
	seen := false
	for _, c := range s {
		if other(c) {
			return false
		}
		seen = seen || is(c)
	}
	return seen
}

// pyTitle is Python's str.title.
func pyTitle(s string) string {
	var b strings.Builder
	prev := false
	for _, c := range s {
		if prev {
			b.WriteRune(unicode.ToLower(c))
		} else {
			b.WriteRune(unicode.ToUpper(c))
		}
		prev = unicode.IsLetter(c)
	}
	return b.String()
}

// jinjaTitle is Jinja's title filter, which starts a word after a space,
// dash, or opening bracket.
func jinjaTitle(s string) string {
	var b strings.Builder
	start := true
	for _, c := range s {
		switch {
		case pySpace(c) || strings.ContainsRune("-({[<", c):
			b.WriteRune(c)
			start = true
		case start:
			b.WriteRune(unicode.ToUpper(c))
			start = false
		default:
			b.WriteRune(unicode.ToLower(c))
		}
	}
	return b.String()
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	c, n := utf8.DecodeRuneInString(s)
	return string(unicode.ToUpper(c)) + strings.ToLower(s[n:])
}

// printf is Python's % formatting with %s, %r, %d, %i, %f, %c, and %%.
func (r *renderer) printf(f str, operand Value) (Value, error) {
	args := []Value{operand}
	if t, ok := operand.(*list); ok && t.tuple {
		args = t.items
	}
	flat, fc := f.String(), &cutter{s: f}
	var w builder
	ai := 0
	next := func() (Value, error) {
		if ai >= len(args) {
			return nil, failf("not enough arguments for the format string")
		}
		ai++
		return args[ai-1], nil
	}
	for i := 0; i < len(flat); i++ {
		if flat[i] != '%' {
			start := i
			for i+1 < len(flat) && flat[i+1] != '%' {
				i++
			}
			w.str(fc.sub(start, i+1))
			continue
		}
		if i+1 >= len(flat) {
			return nil, failf("incomplete format")
		}
		i++
		if flat[i] == '%' {
			w.lit("%", false)
			continue
		}
		v, err := next()
		if err != nil {
			return nil, err
		}
		switch flat[i] {
		case 's':
			t, err := r.toStr(v)
			if err != nil {
				return nil, err
			}
			w.str(t)
		case 'r':
			if err := r.repr(&w, v, false); err != nil {
				return nil, err
			}
		case 'd', 'i':
			x, ok := number(v)
			if !ok {
				return nil, failf("%%d format: a number is required, not %s", typeName(v))
			}
			w.lit(strconv.Itoa(int(x)), false)
		case 'f':
			x, ok := number(v)
			if !ok {
				return nil, failf("%%f format: a number is required, not %s", typeName(v))
			}
			w.lit(strconv.FormatFloat(x, 'f', 6, 64), false)
		case 'c':
			if s, ok := v.(str); ok {
				w.str(s)
				break
			}
			n, err := intArg(v, "%c")
			if err != nil {
				return nil, err
			}
			w.lit(string(rune(n)), false)
		default:
			return nil, &UnsupportedError{What: fmt.Sprintf("the format conversion %%%c", flat[i])}
		}
		if err := r.fits(w.n); err != nil {
			return nil, err
		}
	}
	if ai < len(args) && len(args) > 1 {
		return nil, failf("not all arguments converted during string formatting")
	}
	return w.done(), r.charge(w.n)
}

// --- filters -----------------------------------------------------------------

func (r *renderer) filter(name string, x Value, args []Value, kw map[string]Value) (Value, error) {
	f, ok := filters[name]
	if !ok {
		return nil, &UnsupportedError{What: "the filter " + name}
	}
	if err := r.tick(); err != nil {
		return nil, err
	}
	return f(r, x, args, kw)
}

func (r *renderer) test(name string, x Value, args []Value) (bool, error) {
	f, ok := tests[name]
	if !ok {
		return false, &UnsupportedError{What: "the test " + name}
	}
	return f(r, x, args)
}

func filterText(f func(string) string) filterFunc {
	return func(r *renderer, x Value, _ []Value, _ map[string]Value) (Value, error) {
		s, err := r.toStr(x)
		if err != nil {
			return nil, err
		}
		return s.mapText(f), nil
	}
}

func filterTrim(r *renderer, x Value, args []Value, kw map[string]Value) (Value, error) {
	s, err := r.toStr(x)
	if err != nil {
		return nil, err
	}
	if c := arg(args, kw, 0, "chars", nil); c != nil {
		return strStrip(true, true)(r, s, []Value{c}, nil)
	}
	return stripStr(s, pySpace, true, true), nil
}

func filterLength(_ *renderer, x Value, _ []Value, _ map[string]Value) (Value, error) {
	switch x := x.(type) {
	case str:
		return utf8.RuneCountInString(x.String()), nil
	case *list:
		if x.gen {
			return nil, errGenerator("length")
		}
		return len(x.items), nil
	case *dict:
		return len(x.keys), nil
	case *namespace:
		return len(x.attrs.keys), nil
	case undefined:
		return 0, nil
	}
	return nil, failf("object of type %s has no len()", typeName(x))
}

func filterDefault(_ *renderer, x Value, args []Value, kw map[string]Value) (Value, error) {
	def := arg(args, kw, 0, "default_value", lit(""))
	_, isUndef := x.(undefined)
	if isUndef || (truthy(arg(args, kw, 1, "boolean", false)) && !truthy(x)) {
		return def, nil
	}
	return x, nil
}

func filterAttr(r *renderer, x Value, args []Value, _ map[string]Value) (Value, error) {
	name, err := strArg(args, 0)
	if err != nil {
		return nil, err
	}
	return r.getattr(x, name)
}

func filterAbs(_ *renderer, x Value, _ []Value, _ map[string]Value) (Value, error) {
	switch x := x.(type) {
	case int:
		if x < 0 {
			return -x, nil
		}
		return x, nil
	case float64:
		return math.Abs(x), nil
	}
	return nil, failf("bad operand type for abs(): %s", typeName(x))
}

func filterEscape(r *renderer, x Value, _ []Value, _ map[string]Value) (Value, error) {
	s, err := r.toStr(x)
	if err != nil {
		return nil, err
	}
	if s.safe {
		return s, nil
	}
	out := escapeStr(s)
	return out, r.sized(out.len())
}

// filterSafe marks a string as Markup.
func filterSafe(r *renderer, x Value, _ []Value, _ map[string]Value) (Value, error) {
	s, err := r.toStr(x)
	if err != nil {
		return nil, err
	}
	s.safe = true
	return s, nil
}

// escapeStr is markupsafe's escape, keeping provenance; the result is
// Markup.
func escapeStr(s str) str {
	var out str
	for _, p := range s.parts {
		var b strings.Builder
		for _, c := range p.s {
			switch c {
			case '&':
				b.WriteString("&amp;")
			case '<':
				b.WriteString("&lt;")
			case '>':
				b.WriteString("&gt;")
			case '"':
				b.WriteString("&#34;")
			case '\'':
				b.WriteString("&#39;")
			default:
				b.WriteRune(c)
			}
		}
		out.push(part{s: b.String(), in: p.in})
	}
	out.safe = true
	return out
}

func filterFormat(r *renderer, x Value, args []Value, kw map[string]Value) (Value, error) {
	s, err := r.toStr(x)
	if err != nil {
		return nil, err
	}
	if len(kw) > 0 {
		return nil, &UnsupportedError{What: "the format filter with keywords"}
	}
	return r.printf(s, &list{items: args, tuple: true})
}

func filterIndent(r *renderer, x Value, args []Value, kw map[string]Value) (Value, error) {
	s, err := r.toStr(x)
	if err != nil {
		return nil, err
	}
	var ind str
	switch w := arg(args, kw, 0, "width", 4).(type) {
	case str:
		ind = w
	default:
		n, err := intArg(w, "width")
		if err != nil {
			return nil, err
		}
		if err := r.fits(n); err != nil {
			return nil, err
		}
		ind = lit(strings.Repeat(" ", max(n, 0)))
	}
	first := truthy(arg(args, kw, 1, "first", false))
	blank := truthy(arg(args, kw, 2, "blank", false))
	lines := splitLines(cat(s, lit("\n")), false)
	var out builder
	if first {
		out.str(ind)
	}
	for i, l := range lines {
		if i > 0 {
			out.lit("\n", false)
			if blank || l.len() > 0 {
				out.str(ind)
			}
		}
		out.str(l)
		if err := r.fits(out.n); err != nil {
			return nil, err
		}
	}
	return out.done(), r.charge(out.n)
}

func filterInt(r *renderer, x Value, args []Value, kw map[string]Value) (Value, error) {
	def := arg(args, kw, 0, "default", 0)
	switch x := x.(type) {
	case int:
		return x, nil
	case bool:
		return intArg(x, "value")
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return def, nil
		}
		return intResult(math.Trunc(x))
	case str:
		t := strings.TrimSpace(x.String())
		if n, err := strconv.Atoi(strings.ReplaceAll(t, "_", "")); err == nil {
			return n, nil
		}
		if f, err := strconv.ParseFloat(t, 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
			return intResult(math.Trunc(f))
		}
	}
	return def, nil
}

func filterFloat(_ *renderer, x Value, args []Value, kw map[string]Value) (Value, error) {
	def := arg(args, kw, 0, "default", 0.0)
	if f, ok := number(x); ok {
		return f, nil
	}
	if s, ok := x.(str); ok {
		if f, err := strconv.ParseFloat(strings.TrimSpace(s.String()), 64); err == nil {
			return f, nil
		}
	}
	return def, nil
}

func filterRound(_ *renderer, x Value, args []Value, kw map[string]Value) (Value, error) {
	f, ok := number(x)
	if !ok {
		return nil, failf("round needs a number, not %s", typeName(x))
	}
	p, err := intArg(arg(args, kw, 0, "precision", 0), "precision")
	if err != nil {
		return nil, err
	}
	scale := math.Pow(10, float64(p))
	how := "common"
	if m, ok := arg(args, kw, 1, "method", lit("common")).(str); ok {
		how = m.String()
	}
	switch how {
	case "common":
		return math.RoundToEven(f*scale) / scale, nil
	case "ceil":
		return math.Ceil(f*scale) / scale, nil
	case "floor":
		return math.Floor(f*scale) / scale, nil
	}
	return nil, failf("round method must be common, ceil, or floor")
}

func filterItems(_ *renderer, x Value, _ []Value, _ map[string]Value) (Value, error) {
	switch x := x.(type) {
	case undefined:
		return generator(nil), nil
	case *dict:
		out := &list{in: x.in, gen: true}
		for i, k := range x.keys {
			out.items = append(out.items, &list{items: []Value{k, x.vals[i]}, tuple: true, in: x.in})
		}
		return out, nil
	}
	return nil, failf("items() needs a mapping, not %s", typeName(x))
}

func filterDictsort(r *renderer, x Value, args []Value, kw map[string]Value) (Value, error) {
	d, ok := x.(*dict)
	if !ok {
		return nil, failf("dictsort needs a mapping, not %s", typeName(x))
	}
	cs := truthy(arg(args, kw, 0, "case_sensitive", false))
	byValue := false
	if b, ok := arg(args, kw, 1, "by", lit("key")).(str); ok {
		byValue = b.String() == "value"
	}
	reverse := truthy(arg(args, kw, 2, "reverse", false))
	pairs := make([]Value, len(d.keys))
	for i, k := range d.keys {
		pairs[i] = &list{items: []Value{k, d.vals[i]}, tuple: true, in: d.in}
	}
	err := r.sortValues(pairs, func(v Value) Value {
		p := v.(*list).items
		if byValue {
			return caseKey(p[1], cs)
		}
		return caseKey(p[0], cs)
	}, reverse)
	return &list{items: pairs, in: d.in}, err
}

func caseKey(v Value, caseSensitive bool) Value {
	if s, ok := v.(str); ok && !caseSensitive {
		return lit(strings.ToLower(s.String()))
	}
	return v
}

func filterFirst(r *renderer, x Value, _ []Value, _ map[string]Value) (Value, error) {
	items, err := r.iterate(x)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return undefined{why: "first of an empty sequence"}, nil
	}
	return items[0], nil
}

func filterLast(r *renderer, x Value, _ []Value, _ map[string]Value) (Value, error) {
	if l, ok := x.(*list); ok && l.gen {
		return nil, errGenerator("last item")
	}
	items, err := r.iterate(x)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return undefined{why: "last of an empty sequence"}, nil
	}
	return items[len(items)-1], nil
}

func filterList(r *renderer, x Value, _ []Value, _ map[string]Value) (Value, error) {
	items, err := r.iterate(x)
	if err != nil {
		return nil, err
	}
	in := false
	if l, ok := x.(*list); ok {
		in = l.in
	}
	return &list{items: items, in: in}, nil
}

func filterReverse(r *renderer, x Value, _ []Value, _ map[string]Value) (Value, error) {
	items, err := r.iterate(x)
	if err != nil {
		return nil, err
	}
	for i, j := 0, len(items)-1; i < j; i, j = i+1, j-1 {
		items[i], items[j] = items[j], items[i]
	}
	if _, ok := x.(str); ok {
		var out builder
		for _, c := range items {
			out.str(c.(str))
		}
		return out.done(), nil
	}
	return generator(items), nil
}

func filterReplace(r *renderer, x Value, args []Value, kw map[string]Value) (Value, error) {
	s, err := r.toStr(x)
	if err != nil {
		return nil, err
	}
	return strReplace(r, s, args, kw)
}

func filterJoin(r *renderer, x Value, args []Value, kw map[string]Value) (Value, error) {
	items, err := r.iterate(x)
	if err != nil {
		return nil, err
	}
	sep, err := r.toStr(arg(args, kw, 0, "d", lit("")))
	if err != nil {
		return nil, err
	}
	attr := arg(args, kw, 1, "attribute", nil)
	var out builder
	for i, it := range items {
		if attr != nil {
			if it, err = r.attrPath(it, attr); err != nil {
				return nil, err
			}
		}
		t, err := r.toStr(it)
		if err != nil {
			return nil, err
		}
		if err := r.fits(out.n + sep.len() + t.len()); err != nil {
			return nil, err
		}
		if i > 0 {
			out.str(sep)
		}
		out.str(t)
	}
	return out.done(), r.charge(out.n)
}

// attrPath is Jinja's attribute lookup for map, sort, and friends: a dotted
// path whose numeric parts index.
func (r *renderer) attrPath(x, path Value) (Value, error) {
	if n, ok := path.(int); ok {
		return r.getitem(x, n)
	}
	p, ok := path.(str)
	if !ok {
		return nil, failf("attribute must be a string")
	}
	for _, k := range strings.Split(p.String(), ".") {
		var key Value = lit(k)
		if n, err := strconv.Atoi(k); err == nil {
			key = n
		}
		v, err := r.getitem(x, key)
		if err != nil {
			return nil, err
		}
		x = v
	}
	return x, nil
}

// lazyItems is what map and select iterate: like Jinja's, they read a
// false value (None, an empty list) as nothing, not as an error.
func (r *renderer) lazyItems(x Value) ([]Value, error) {
	if !truthy(x) {
		return nil, nil
	}
	return r.iterate(x)
}

func filterMap(r *renderer, x Value, args []Value, kw map[string]Value) (Value, error) {
	items, err := r.lazyItems(x)
	if err != nil {
		return nil, err
	}
	out := generator(nil)
	for _, it := range items {
		if err := r.tick(); err != nil {
			return nil, err
		}
		var v Value
		if a, ok := kw["attribute"]; ok {
			if v, err = r.attrPath(it, a); err != nil {
				return nil, err
			}
			if _, u := v.(undefined); u {
				if d, ok := kw["default"]; ok {
					v = d
				}
			}
		} else {
			name, err := strArg(args, 0)
			if err != nil {
				return nil, err
			}
			if v, err = r.filter(name, it, args[1:], kw); err != nil {
				return nil, err
			}
		}
		out.items = append(out.items, v)
	}
	return out, nil
}

// filterSelect is select, reject, selectattr, and rejectattr.
func filterSelect(keep, byAttr bool) filterFunc {
	return func(r *renderer, x Value, args []Value, _ map[string]Value) (Value, error) {
		items, err := r.lazyItems(x)
		if err != nil {
			return nil, err
		}
		var attr Value
		if byAttr {
			if len(args) == 0 {
				return nil, failf("selectattr needs an attribute")
			}
			attr, args = args[0], args[1:]
		}
		in := false
		if l, ok := x.(*list); ok {
			in = l.in
		}
		out := &list{in: in, gen: true}
		for _, it := range items {
			if err := r.tick(); err != nil {
				return nil, err
			}
			v := it
			if byAttr {
				if v, err = r.attrPath(it, attr); err != nil {
					return nil, err
				}
			}
			var ok bool
			if len(args) == 0 {
				ok = truthy(v)
			} else {
				name, err := strArg(args, 0)
				if err != nil {
					return nil, err
				}
				if ok, err = r.test(name, v, args[1:]); err != nil {
					return nil, err
				}
			}
			if ok == keep {
				out.items = append(out.items, it)
			}
		}
		return out, nil
	}
}

func filterSort(r *renderer, x Value, args []Value, kw map[string]Value) (Value, error) {
	items, err := r.iterate(x)
	if err != nil {
		return nil, err
	}
	reverse := truthy(arg(args, kw, 0, "reverse", false))
	cs := truthy(arg(args, kw, 1, "case_sensitive", false))
	attr := arg(args, kw, 2, "attribute", nil)
	var lookupErr error
	err = r.sortValues(items, func(v Value) Value {
		if attr != nil {
			a, err := r.attrPath(v, attr)
			if err != nil && lookupErr == nil {
				lookupErr = err
			}
			v = a
		}
		return caseKey(v, cs)
	}, reverse)
	if lookupErr != nil {
		return nil, lookupErr
	}
	return &list{items: items}, err
}

func filterUnique(r *renderer, x Value, args []Value, kw map[string]Value) (Value, error) {
	items, err := r.iterate(x)
	if err != nil {
		return nil, err
	}
	cs := truthy(arg(args, kw, 0, "case_sensitive", false))
	attr := arg(args, kw, 1, "attribute", nil)
	var seen []Value
	out := generator(nil)
	for _, it := range items {
		k := it
		if attr != nil {
			if k, err = r.attrPath(it, attr); err != nil {
				return nil, err
			}
		}
		k = caseKey(k, cs)
		if err := r.charge(64 * len(seen)); err != nil {
			return nil, err
		}
		dup := false
		for _, s := range seen {
			if equal(s, k) {
				dup = true
				break
			}
		}
		if !dup {
			seen = append(seen, k)
			out.items = append(out.items, it)
		}
	}
	return out, nil
}

func filterMinMax(sign int) filterFunc {
	return func(r *renderer, x Value, args []Value, kw map[string]Value) (Value, error) {
		items, err := r.iterate(x)
		if err != nil {
			return nil, err
		}
		if len(items) == 0 {
			return undefined{why: "min or max of an empty sequence"}, nil
		}
		cs := truthy(arg(args, kw, 0, "case_sensitive", false))
		attr := arg(args, kw, 1, "attribute", nil)
		key := func(v Value) (Value, error) {
			if attr != nil {
				a, err := r.attrPath(v, attr)
				if err != nil {
					return nil, err
				}
				v = a
			}
			return caseKey(v, cs), nil
		}
		best := items[0]
		bk, err := key(best)
		if err != nil {
			return nil, err
		}
		for _, it := range items[1:] {
			k, err := key(it)
			if err != nil {
				return nil, err
			}
			c, err := compare(k, bk)
			if err != nil {
				return nil, err
			}
			if c*sign > 0 {
				best, bk = it, k
			}
		}
		return best, nil
	}
}

func filterSum(r *renderer, x Value, args []Value, kw map[string]Value) (Value, error) {
	items, err := r.iterate(x)
	if err != nil {
		return nil, err
	}
	attr := arg(args, kw, 0, "attribute", nil)
	total := arg(args, kw, 1, "start", 0)
	for _, it := range items {
		if attr != nil {
			if it, err = r.attrPath(it, attr); err != nil {
				return nil, err
			}
		}
		if total, err = r.arith("+", total, it); err != nil {
			return nil, err
		}
	}
	return total, nil
}

func filterWordcount(r *renderer, x Value, _ []Value, _ map[string]Value) (Value, error) {
	s, err := r.toStr(x)
	if err != nil {
		return nil, err
	}
	return len(strings.FieldsFunc(s.String(), func(c rune) bool {
		return !(unicode.IsLetter(c) || unicode.IsDigit(c) || c == '_')
	})), nil
}

// --- tests -------------------------------------------------------------------

func testIterable(_ *renderer, x Value, _ []Value) (bool, error) {
	switch x.(type) {
	case str, *list, *dict, undefined:
		return true, nil
	}
	return false, nil
}

func testSequence(_ *renderer, x Value, _ []Value) (bool, error) {
	switch x := x.(type) {
	case str, *dict:
		return true, nil
	case *list:
		return !x.gen, nil
	}
	return false, nil
}

func testCallable(_ *renderer, x Value, _ []Value) (bool, error) {
	switch x.(type) {
	case *macro, builtin, method:
		return true, nil
	}
	return false, nil
}

func testSameas(_ *renderer, x Value, args []Value) (bool, error) {
	if len(args) != 1 {
		return false, failf("sameas takes one argument")
	}
	switch x.(type) {
	case nil, bool, undefined:
		return equal(x, args[0]) && typeName(x) == typeName(args[0]), nil
	case *list, *dict, *namespace:
		return x == args[0], nil
	}
	return false, nil
}

func testEqual(want bool) testFunc {
	return func(r *renderer, x Value, args []Value) (bool, error) {
		if len(args) != 1 {
			return false, failf("a comparison test takes one argument")
		}
		if err := r.charge(weight(x) + weight(args[0])); err != nil {
			return false, err
		}
		return equal(x, args[0]) == want, nil
	}
}

func testOrder(ok func(int) bool) testFunc {
	return func(_ *renderer, x Value, args []Value) (bool, error) {
		if len(args) != 1 {
			return false, failf("a comparison test takes one argument")
		}
		c, err := compare(x, args[0])
		return err == nil && ok(c), err
	}
}

func testIn(r *renderer, x Value, args []Value) (bool, error) {
	if len(args) != 1 {
		return false, failf("in takes one argument")
	}
	if err := r.charge(weight(args[0]) + weight(x)); err != nil {
		return false, err
	}
	return contains(args[0], x)
}

func testParity(rem int) testFunc {
	return func(_ *renderer, x Value, _ []Value) (bool, error) {
		n, err := intArg(x, "value")
		if err != nil {
			return false, err
		}
		return ((n%2)+2)%2 == rem, nil
	}
}

func testDivisible(_ *renderer, x Value, args []Value) (bool, error) {
	if len(args) != 1 {
		return false, failf("divisibleby takes one argument")
	}
	n, err := intArg(x, "value")
	if err != nil {
		return false, err
	}
	d, err := intArg(args[0], "divisor")
	if err != nil || d == 0 {
		return false, failf("divisibleby needs a non-zero integer")
	}
	return n%d == 0, nil
}

func testCase(is, other func(rune) bool) testFunc {
	return func(_ *renderer, x Value, _ []Value) (bool, error) {
		s, ok := x.(str)
		return ok && hasCase(s.String(), is, other), nil
	}
}
