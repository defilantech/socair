package jinja

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Limits bound one render, so a hostile template cannot hang the check or
// exhaust its memory. A render that passes one stops with a *LimitError.
type Limits struct {
	Steps      int // statements and expressions evaluated
	Output     int // bytes emitted in all, and the size of any one string
	Iterations int // loop iterations, across all loops
	Depth      int // nested macro calls
	Items      int // elements of a list built at once
}

// DefaultLimits are far above what a real template needs to render a short
// conversation: the largest real templates take a few tens of thousands of
// steps and emit a few kilobytes.
var DefaultLimits = Limits{Steps: 2_000_000, Output: 1 << 20, Iterations: 100_000, Depth: 64, Items: 100_000}

// DatePlaceholder is what strftime_now returns, so a render that states
// today's date is the same on every run.
const DatePlaceholder = "[current date]"

// Piece is a run of rendered text and where it came from: Input text came
// from the render's variables (the conversation, the tools, the special
// tokens); the rest is text the template added.
type Piece struct {
	Text  string
	Input bool
}

// UnsupportedError is a template that reached a construct the evaluator
// does not model. It is never rendered some other way.
type UnsupportedError struct{ What string }

func (e *UnsupportedError) Error() string {
	return "uses " + e.What + ", which the evaluator does not model"
}

// LimitError is a render that passed one of its Limits.
type LimitError struct{ Limit string }

func (e *LimitError) Error() string { return "exceeded the render bound: " + e.Limit }

// RaiseError is a template that called raise_exception: it refuses the
// conversation it was given.
type RaiseError struct{ Message string }

func (e *RaiseError) Error() string { return "raised: " + e.Message }

// FailError is a template that fails as Jinja would: an undefined value
// used, an operation on the wrong types.
type FailError struct{ Msg string }

func (e *FailError) Error() string { return e.Msg }

func failf(format string, args ...any) error { return &FailError{Msg: fmt.Sprintf(format, args...)} }

// Render evaluates a parsed template with the given variables, under
// Hugging Face transformers' Jinja settings: an immutable sandbox (lists and
// dicts cannot be changed), trim_blocks and lstrip_blocks, loop controls,
// the {% generation %} tag, and the globals raise_exception and
// strftime_now (which returns DatePlaceholder). Every variable is input: a
// string, bool, int, float64, nil, []any, or Map.
func Render(nodes []Node, vars map[string]any, lim Limits) ([]Piece, error) {
	r := &renderer{lim: lim, root: &scope{vars: map[string]Value{}}}
	for k, v := range vars {
		iv, err := input(v)
		if err != nil {
			return nil, err
		}
		r.root.vars[k] = iv
	}
	var out builder
	r.out = &out
	err := r.nodes(nodes, r.root)
	if errors.Is(err, errBreak) || errors.Is(err, errContinue) {
		err = failf("break or continue outside a loop")
	}
	if err != nil {
		return nil, err
	}
	s := out.done()
	pieces := make([]Piece, 0, len(s.parts))
	for _, p := range s.parts {
		pieces = append(pieces, Piece{Text: p.s, Input: p.in})
	}
	return pieces, nil
}

var (
	errBreak    = errors.New("break")
	errContinue = errors.New("continue")
)

type scope struct {
	vars   map[string]Value
	parent *scope
}

func (s *scope) child() *scope { return &scope{vars: map[string]Value{}, parent: s} }

func (s *scope) lookup(name string) (Value, bool) {
	for c := s; c != nil; c = c.parent {
		if v, ok := c.vars[name]; ok {
			return v, true
		}
	}
	return nil, false
}

type renderer struct {
	lim                         Limits
	steps, iters, depth, output int
	nest                        int
	root                        *scope
	out                         *builder
}

func (r *renderer) tick() error { return r.charge(64) }

// maxNest bounds how deep a value is printed: a namespace can hold a list
// that holds it.
const maxNest = 100

// enter counts one level of printing a nested value; call the returned func
// on the way out.
func (r *renderer) enter() (func(), error) {
	r.nest++
	leave := func() { r.nest-- }
	if r.nest > maxNest {
		return leave, &LimitError{Limit: fmt.Sprintf("a value nested more than %d deep", maxNest)}
	}
	return leave, r.tick()
}

// charge counts building n bytes as work, a step per 64 bytes, so a
// template that copies long strings over and over runs out of steps rather
// than time.
func (r *renderer) charge(n int) error {
	r.steps += max(n/64, 1)
	if r.steps > r.lim.Steps {
		return &LimitError{Limit: fmt.Sprintf("more than %d evaluation steps", r.lim.Steps)}
	}
	return nil
}

// fits refuses a string over the output bound before it is built.
func (r *renderer) fits(n int) error {
	if n > r.lim.Output {
		return &LimitError{Limit: fmt.Sprintf("a string over %d bytes", r.lim.Output)}
	}
	return nil
}

// sized is fits, and charges for building the string.
func (r *renderer) sized(n int) error {
	if err := r.fits(n); err != nil {
		return err
	}
	return r.charge(n)
}

func (r *renderer) items(n int) error {
	if n > r.lim.Items {
		return &LimitError{Limit: fmt.Sprintf("a list over %d elements", r.lim.Items)}
	}
	return nil
}

func (r *renderer) emit(s str) error {
	n := s.len()
	r.output += n
	if r.output > r.lim.Output {
		return &LimitError{Limit: fmt.Sprintf("more than %d bytes of output", r.lim.Output)}
	}
	r.out.str(s)
	return r.charge(n)
}

// capture renders nodes into a string of their own.
func (r *renderer) capture(nodes []Node, sc *scope) (str, error) {
	saved := r.out
	var buf builder
	r.out = &buf
	err := r.nodes(nodes, sc)
	r.out = saved
	return buf.done(), err
}

func (r *renderer) nodes(nodes []Node, sc *scope) error {
	for _, n := range nodes {
		if err := r.node(n, sc); err != nil {
			return err
		}
	}
	return nil
}

func (r *renderer) node(n Node, sc *scope) error {
	if err := r.tick(); err != nil {
		return err
	}
	switch n := n.(type) {
	case Text:
		return r.emit(lit(n.Out))
	case Output:
		v, err := r.eval(n.X, sc)
		if err != nil {
			return err
		}
		s, err := r.toStr(v)
		if err != nil {
			return err
		}
		return r.emit(s)
	case If:
		for _, b := range n.Branches {
			c, err := r.eval(b.Cond, sc)
			if err != nil {
				return err
			}
			if truthy(c) {
				return r.nodes(b.Body, sc)
			}
		}
		return r.nodes(n.Else, sc)
	case For:
		return r.forLoop(n, sc)
	case Set:
		return r.set(n, sc)
	case Macro:
		sc.vars[n.Name] = &macro{def: n, scope: sc}
		return nil
	case FilterBlock:
		body, err := r.capture(n.Body, sc)
		if err != nil {
			return err
		}
		v, err := r.applyChain(n.Filter, body, sc)
		if err != nil {
			return err
		}
		s, err := r.toStr(v)
		if err != nil {
			return err
		}
		return r.emit(s)
	case Generation:
		return r.nodes(n.Body, sc)
	case Do:
		_, err := r.eval(n.X, sc)
		return err
	case Break:
		return errBreak
	case Continue:
		return errContinue
	case CallBlock:
		return &UnsupportedError{What: "a {% call %} block"}
	}
	return &UnsupportedError{What: fmt.Sprintf("the statement %T", n)}
}

// applyChain applies a filter chain written against the placeholder name ""
// ({% filter %} and {% set x | f %}) to v.
func (r *renderer) applyChain(chain Expr, v Value, sc *scope) (Value, error) {
	tmp := sc.child()
	tmp.vars[""] = v
	return r.eval(chain, tmp)
}

func (r *renderer) set(n Set, sc *scope) error {
	var v Value
	if n.X == nil {
		body, err := r.capture(n.Body, sc)
		if err != nil {
			return err
		}
		v = body
		if n.Filter != nil {
			if v, err = r.applyChain(n.Filter, body, sc); err != nil {
				return err
			}
		}
	} else {
		var err error
		if v, err = r.eval(n.X, sc); err != nil {
			return err
		}
	}
	if len(n.Targets) == 1 {
		return r.assign(n.Targets[0], v, sc)
	}
	vals, err := r.unpack(v, len(n.Targets))
	if err != nil {
		return err
	}
	for i, t := range n.Targets {
		if err := r.assign(t, vals[i], sc); err != nil {
			return err
		}
	}
	return nil
}

func (r *renderer) assign(target Expr, v Value, sc *scope) error {
	switch t := target.(type) {
	case Name:
		sc.vars[t.N] = v
		return nil
	case Attr:
		obj, err := r.eval(t.X, sc)
		if err != nil {
			return err
		}
		ns, ok := obj.(*namespace)
		if !ok {
			return failf("cannot assign attribute on a %s", typeName(obj))
		}
		ns.attrs.set(lit(t.Name), v)
		return nil
	}
	return &UnsupportedError{What: "an assignment to an expression"}
}

// unpack spreads a value over n targets, as Python's a, b = x does.
func (r *renderer) unpack(v Value, n int) ([]Value, error) {
	vals, err := r.iterate(v)
	if err != nil {
		return nil, err
	}
	if len(vals) != n {
		return nil, failf("cannot unpack %d values into %d names", len(vals), n)
	}
	return vals, nil
}

func (r *renderer) forLoop(n For, sc *scope) error {
	seq, err := r.eval(n.Iter, sc)
	if err != nil {
		return err
	}
	all, err := r.iterate(seq)
	if err != nil {
		return err
	}
	bind := func(s *scope, item Value) error {
		if len(n.Targets) == 1 {
			s.vars[n.Targets[0]] = item
			return nil
		}
		vals, err := r.unpack(item, len(n.Targets))
		if err != nil {
			return err
		}
		for i, t := range n.Targets {
			s.vars[t] = vals[i]
		}
		return nil
	}
	items := all
	if n.Filter != nil {
		items = nil
		for _, item := range all {
			s := sc.child()
			if err := bind(s, item); err != nil {
				return err
			}
			c, err := r.eval(n.Filter, s)
			if err != nil {
				return err
			}
			if truthy(c) {
				items = append(items, item)
			}
		}
	}
	if len(items) == 0 {
		return r.nodes(n.Else, sc)
	}
	loop := &loopInfo{items: items}
	for i, item := range items {
		r.iters++
		if r.iters > r.lim.Iterations {
			return &LimitError{Limit: fmt.Sprintf("more than %d loop iterations", r.lim.Iterations)}
		}
		if err := r.tick(); err != nil {
			return err
		}
		// Each iteration has its own scope, as in Jinja: a set inside the
		// body does not carry to the next iteration or out of the loop.
		s := sc.child()
		if err := bind(s, item); err != nil {
			return err
		}
		loop.index0 = i
		s.vars["loop"] = loop
		err := r.nodes(n.Body, s)
		if errors.Is(err, errBreak) {
			break
		}
		if err != nil && !errors.Is(err, errContinue) {
			return err
		}
	}
	return nil
}

// iterate lists what a for loop over v visits.
func (r *renderer) iterate(v Value) ([]Value, error) {
	var out []Value
	switch v := v.(type) {
	case *list:
		out = append(out, v.items...)
	case *dict:
		out = append(out, v.keys...)
	case str:
		if err := r.items(v.len()); err != nil {
			return nil, err
		}
		out = chars(v)
	case undefined:
	default:
		return nil, failf("%s is not iterable", typeName(v))
	}
	return out, r.charge(8 * len(out))
}

// chars splits a string into one-character strings, with provenance.
func chars(s str) []Value {
	var out []Value
	for _, p := range s.parts {
		for i := 0; i < len(p.s); {
			_, n := utf8.DecodeRuneInString(p.s[i:])
			out = append(out, str{parts: []part{{s: p.s[i : i+n], in: p.in}}})
			i += n
		}
	}
	return out
}

// loopInfo is the loop variable.
type loopInfo struct {
	items  []Value
	index0 int
}

func (l *loopInfo) attr(name string) (Value, bool) {
	n := len(l.items)
	switch name {
	case "index":
		return l.index0 + 1, true
	case "index0":
		return l.index0, true
	case "revindex":
		return n - l.index0, true
	case "revindex0":
		return n - l.index0 - 1, true
	case "first":
		return l.index0 == 0, true
	case "last":
		return l.index0 == n-1, true
	case "length":
		return n, true
	case "depth":
		return 1, true
	case "depth0":
		return 0, true
	case "previtem":
		if l.index0 > 0 {
			return l.items[l.index0-1], true
		}
		return undefined{why: "there is no previous item"}, true
	case "nextitem":
		if l.index0+1 < n {
			return l.items[l.index0+1], true
		}
		return undefined{why: "there is no next item"}, true
	case "cycle":
		return method{recv: l, name: name}, true
	}
	return nil, false
}

// macro is a defined macro and the scope it was defined in.
type macro struct {
	def   Macro
	scope *scope
}

func (r *renderer) callMacro(m *macro, args []Value, kw map[string]Value) (Value, error) {
	r.depth++
	defer func() { r.depth-- }()
	if r.depth > r.lim.Depth {
		return nil, &LimitError{Limit: fmt.Sprintf("macro calls nested more than %d deep", r.lim.Depth)}
	}
	d := m.def
	if len(args) > len(d.Params) {
		return nil, failf("macro %s takes at most %d arguments", d.Name, len(d.Params))
	}
	s := m.scope.child()
	for k := range kw {
		found := false
		for _, p := range d.Params {
			found = found || p == k
		}
		if !found {
			return nil, failf("macro %s has no parameter %s", d.Name, k)
		}
	}
	for i, p := range d.Params {
		switch v, ok := kw[p]; {
		case i < len(args):
			s.vars[p] = args[i]
		case ok:
			s.vars[p] = v
		case d.Defaults[i] != nil:
			dv, err := r.eval(d.Defaults[i], s)
			if err != nil {
				return nil, err
			}
			s.vars[p] = dv
		default:
			s.vars[p] = undefined{why: fmt.Sprintf("parameter %s of macro %s was not given", p, d.Name)}
		}
	}
	body, err := r.capture(d.Body, s)
	if errors.Is(err, errBreak) || errors.Is(err, errContinue) {
		err = failf("break or continue outside a loop")
	}
	return body, err
}

func (r *renderer) eval(e Expr, sc *scope) (Value, error) {
	if err := r.tick(); err != nil {
		return nil, err
	}
	switch e := e.(type) {
	case Str:
		return lit(e.V), nil
	case Num:
		return parseNum(e.V)
	case Const:
		switch e.V {
		case "true":
			return true, nil
		case "false":
			return false, nil
		}
		return nil, nil
	case Name:
		if v, ok := sc.lookup(e.N); ok {
			return v, nil
		}
		if g, ok := globals[e.N]; ok {
			return g, nil
		}
		return undefined{why: fmt.Sprintf("%q is undefined", e.N)}, nil
	case Attr:
		x, err := r.eval(e.X, sc)
		if err != nil {
			return nil, err
		}
		return r.getattr(x, e.Name)
	case Index:
		x, err := r.eval(e.X, sc)
		if err != nil {
			return nil, err
		}
		k, err := r.eval(e.I, sc)
		if err != nil {
			return nil, err
		}
		return r.getitem(x, k)
	case Slice:
		return r.slice(e, sc)
	case Call:
		return r.call(e, sc)
	case Filter:
		x, err := r.eval(e.X, sc)
		if err != nil {
			return nil, err
		}
		args, kw, err := r.args(e.Args, e.Kw, sc)
		if err != nil {
			return nil, err
		}
		return r.filter(e.Name, x, args, kw)
	case Test:
		x, err := r.eval(e.X, sc)
		if err != nil {
			return nil, err
		}
		args, _, err := r.args(e.Args, nil, sc)
		if err != nil {
			return nil, err
		}
		ok, err := r.test(e.Name, x, args)
		return ok != e.Not, err
	case Bin:
		return r.binary(e, sc)
	case Unary:
		x, err := r.eval(e.X, sc)
		if err != nil {
			return nil, err
		}
		switch e.Op {
		case "not":
			return !truthy(x), nil
		case "-":
			switch x := x.(type) {
			case int:
				return -x, nil
			case float64:
				return -x, nil
			case bool:
				if x {
					return -1, nil
				}
				return 0, nil
			}
			return nil, failf("bad operand for unary -: %s", typeName(x))
		}
		if _, ok := number(x); !ok {
			return nil, failf("bad operand for unary +: %s", typeName(x))
		}
		return x, nil
	case Cond:
		c, err := r.eval(e.If, sc)
		if err != nil {
			return nil, err
		}
		if truthy(c) {
			return r.eval(e.Then, sc)
		}
		if e.Else == nil {
			return undefined{why: "the conditional expression has no else"}, nil
		}
		return r.eval(e.Else, sc)
	case List:
		return r.listOf(e.Items, false, sc)
	case Tuple:
		return r.listOf(e.Items, true, sc)
	case Dict:
		d := &dict{}
		for i := range e.Keys {
			k, err := r.eval(e.Keys[i], sc)
			if err != nil {
				return nil, err
			}
			v, err := r.eval(e.Vals[i], sc)
			if err != nil {
				return nil, err
			}
			d.set(k, v)
		}
		return d, nil
	}
	return nil, &UnsupportedError{What: fmt.Sprintf("the expression %T", e)}
}

func (r *renderer) listOf(xs []Expr, tuple bool, sc *scope) (Value, error) {
	l := &list{tuple: tuple}
	for _, x := range xs {
		v, err := r.eval(x, sc)
		if err != nil {
			return nil, err
		}
		l.items = append(l.items, v)
	}
	return l, nil
}

func parseNum(s string) (Value, error) {
	s = strings.ReplaceAll(s, "_", "")
	if !strings.ContainsAny(s, ".eE") {
		n, err := strconv.Atoi(s)
		if err != nil {
			return nil, failf("integer literal %s is out of range", s)
		}
		return n, nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return nil, failf("bad number %s", s)
	}
	return f, nil
}

func (r *renderer) args(xs []Expr, kws []Kw, sc *scope) ([]Value, map[string]Value, error) {
	var args []Value
	for _, x := range xs {
		v, err := r.eval(x, sc)
		if err != nil {
			return nil, nil, err
		}
		args = append(args, v)
	}
	var kw map[string]Value
	for _, k := range kws {
		v, err := r.eval(k.X, sc)
		if err != nil {
			return nil, nil, err
		}
		if kw == nil {
			kw = map[string]Value{}
		}
		kw[k.Name] = v
	}
	return args, kw, nil
}

func isDunder(n string) bool {
	return len(n) > 4 && strings.HasPrefix(n, "__") && strings.HasSuffix(n, "__")
}

// getattr is Jinja's x.name: a listed method, a dict key, a namespace or
// loop attribute, or undefined. A dunder is refused: the evaluator has no
// object model, and the analysis has already failed any template that
// reaches for one.
func (r *renderer) getattr(x Value, name string) (Value, error) {
	if isDunder(name) {
		return nil, &UnsupportedError{What: "the attribute " + name}
	}
	switch x := x.(type) {
	case undefined:
		return nil, failf("%s", x.why)
	case *dict:
		if dictMethods[name] {
			return method{recv: x, name: name}, nil
		}
		if v, ok := x.get(lit(name)); ok {
			return v, nil
		}
	case str:
		if _, ok := strMethods[name]; ok {
			return method{recv: x, name: name}, nil
		}
	case *list:
		if listMethods[name] {
			return method{recv: x, name: name}, nil
		}
	case *namespace:
		if v, ok := x.attrs.get(lit(name)); ok {
			return v, nil
		}
	case *loopInfo:
		if v, ok := x.attr(name); ok {
			return v, nil
		}
	}
	return undefined{why: fmt.Sprintf("%s has no attribute %q", typeName(x), name)}, nil
}

// getitem is Jinja's x[k].
func (r *renderer) getitem(x, k Value) (Value, error) {
	if s, ok := k.(str); ok && isDunder(s.String()) {
		return nil, &UnsupportedError{What: "the key " + s.String()}
	}
	switch x := x.(type) {
	case undefined:
		return nil, failf("%s", x.why)
	case *dict:
		if v, ok := x.get(k); ok {
			return v, nil
		}
	case *namespace:
		if v, ok := x.attrs.get(k); ok {
			return v, nil
		}
	case *list:
		if x.gen {
			return undefined{why: "a generator cannot be indexed"}, nil
		}
		if i, ok := index(k, len(x.items)); ok {
			return x.items[i], nil
		}
	case str:
		offs := runeOffsets(x.String())
		if i, ok := index(k, len(offs)-1); ok {
			return x.sub(offs[i], offs[i+1]), nil
		}
	case *loopInfo:
		if s, ok := k.(str); ok {
			if v, ok := x.attr(s.String()); ok {
				return v, nil
			}
		}
	}
	if s, ok := k.(str); ok {
		return r.getattr(x, s.String())
	}
	return undefined{why: fmt.Sprintf("%s has no item %v", typeName(x), k)}, nil
}

// index resolves a Python index, negative counting from the end.
func index(k Value, n int) (int, bool) {
	i, ok := k.(int)
	if !ok {
		if b, isBool := k.(bool); isBool {
			i, ok = 0, true
			if b {
				i = 1
			}
		}
	}
	if !ok {
		return 0, false
	}
	if i < 0 {
		i += n
	}
	return i, i >= 0 && i < n
}

func (r *renderer) slice(e Slice, sc *scope) (Value, error) {
	x, err := r.eval(e.X, sc)
	if err != nil {
		return nil, err
	}
	bound := func(b Expr) (*int, error) {
		if b == nil {
			return nil, nil
		}
		v, err := r.eval(b, sc)
		if err != nil {
			return nil, err
		}
		if v == nil {
			return nil, nil
		}
		i, ok := v.(int)
		if !ok {
			return nil, failf("slice indices must be integers, not %s", typeName(v))
		}
		return &i, nil
	}
	lo, err := bound(e.Lo)
	if err != nil {
		return nil, err
	}
	hi, err := bound(e.Hi)
	if err != nil {
		return nil, err
	}
	step, err := bound(e.Step)
	if err != nil {
		return nil, err
	}
	switch x := x.(type) {
	case *list:
		if x.gen {
			return undefined{why: "a generator cannot be sliced"}, nil
		}
		idx, err := sliceIndices(len(x.items), lo, hi, step)
		if err != nil {
			return nil, err
		}
		out := &list{tuple: x.tuple, in: x.in}
		for _, i := range idx {
			out.items = append(out.items, x.items[i])
		}
		return out, nil
	case str:
		offs := runeOffsets(x.String())
		idx, err := sliceIndices(len(offs)-1, lo, hi, step)
		if err != nil {
			return nil, err
		}
		var out str
		for _, i := range idx {
			for _, p := range x.sub(offs[i], offs[i+1]).parts {
				out.push(p)
			}
		}
		return out, nil
	case undefined:
		return nil, failf("%s", x.why)
	}
	return nil, failf("%s cannot be sliced", typeName(x))
}

// sliceIndices lists the indices a Python slice of a length-n sequence
// visits.
func sliceIndices(n int, lo, hi, step *int) ([]int, error) {
	st := 1
	if step != nil {
		st = *step
	}
	if st == 0 {
		return nil, failf("slice step cannot be zero")
	}
	clamp := func(p *int, def, low, high int) int {
		if p == nil {
			return def
		}
		v := *p
		if v < 0 {
			v += n
			if v < low {
				v = low
			}
		} else if v > high {
			v = high
		}
		return v
	}
	var out []int
	if st > 0 {
		a, b := clamp(lo, 0, 0, n), clamp(hi, n, 0, n)
		for i := a; i < b; i += st {
			out = append(out, i)
		}
		return out, nil
	}
	a, b := clamp(lo, n-1, -1, n-1), clamp(hi, -1, -1, n-1)
	for i := a; i > b; i += st {
		out = append(out, i)
	}
	return out, nil
}

func (r *renderer) call(e Call, sc *scope) (Value, error) {
	args, kw, err := r.args(e.Args, e.Kw, sc)
	if err != nil {
		return nil, err
	}
	f, err := r.eval(e.F, sc)
	if err != nil {
		return nil, err
	}
	switch f := f.(type) {
	case *macro:
		return r.callMacro(f, args, kw)
	case builtin:
		return f(r, args, kw)
	case method:
		return r.callMethod(f, args, kw)
	case undefined:
		return nil, failf("%s", f.why)
	}
	return nil, failf("%s is not callable", typeName(f))
}

func (r *renderer) binary(e Bin, sc *scope) (Value, error) {
	l, err := r.eval(e.L, sc)
	if err != nil {
		return nil, err
	}
	switch e.Op {
	case "and":
		if !truthy(l) {
			return l, nil
		}
		return r.eval(e.R, sc)
	case "or":
		if truthy(l) {
			return l, nil
		}
		return r.eval(e.R, sc)
	}
	rv, err := r.eval(e.R, sc)
	if err != nil {
		return nil, err
	}
	switch e.Op {
	case "~":
		a, err := r.toStr(l)
		if err != nil {
			return nil, err
		}
		b, err := r.toStr(rv)
		if err != nil {
			return nil, err
		}
		if err := r.sized(a.len() + b.len()); err != nil {
			return nil, err
		}
		return cat(a, b), nil
	}
	// Comparing and searching walk the operands: charge for their size, so
	// a loop of them over large values runs out of steps, not time.
	if err := r.charge(weight(l) + weight(rv)); err != nil {
		return nil, err
	}
	switch e.Op {
	case "==":
		return equal(l, rv), nil
	case "!=":
		return !equal(l, rv), nil
	case "<", "<=", ">", ">=":
		c, err := compare(l, rv)
		if err != nil {
			return nil, err
		}
		switch e.Op {
		case "<":
			return c < 0, nil
		case "<=":
			return c <= 0, nil
		case ">":
			return c > 0, nil
		}
		return c >= 0, nil
	case "in", "not in":
		ok, err := contains(rv, l)
		if err != nil {
			return nil, err
		}
		return ok == (e.Op == "in"), nil
	}
	return r.arith(e.Op, l, rv)
}

// weight is the work comparing or searching a value takes, in the bytes
// charge counts: a string's length, and a fixed cost per element of a
// container.
func weight(v Value) int {
	switch v := v.(type) {
	case str:
		return v.len()
	case *list:
		return 64 * len(v.items)
	case *dict:
		return 64 * len(v.keys)
	case *namespace:
		return 64 * len(v.attrs.keys)
	}
	return 0
}

// contains is Python's item in container.
func contains(container, item Value) (bool, error) {
	switch c := container.(type) {
	case str:
		s, ok := item.(str)
		if !ok {
			return false, failf("'in <string>' requires a string, not %s", typeName(item))
		}
		return strings.Contains(c.String(), s.String()), nil
	case *list:
		for _, x := range c.items {
			if equal(x, item) {
				return true, nil
			}
		}
		return false, nil
	case *dict:
		return c.find(item) >= 0, nil
	case *namespace:
		return c.attrs.find(item) >= 0, nil
	case undefined:
		return false, nil
	}
	return false, failf("%s is not a container", typeName(container))
}

func (r *renderer) arith(op string, l, rv Value) (Value, error) {
	if s, ok := l.(str); ok {
		switch op {
		case "+":
			t, ok := rv.(str)
			if !ok {
				return nil, failf("can only concatenate str (not %s) to str", typeName(rv))
			}
			// Markup + str escapes the plain operand, either side.
			switch {
			case s.safe && !t.safe:
				t = escapeStr(t)
			case t.safe && !s.safe:
				s = escapeStr(s)
			}
			if err := r.sized(s.len() + t.len()); err != nil {
				return nil, err
			}
			out := cat(s, t)
			out.safe = s.safe
			return out, nil
		case "*":
			return r.repeatStr(s, rv)
		case "%":
			return r.printf(s, rv)
		}
	}
	if s, ok := rv.(str); ok && op == "*" {
		return r.repeatStr(s, l)
	}
	if a, ok := l.(*list); ok {
		if b, ok := rv.(*list); a.gen || (ok && b.gen) {
			return nil, errGenerator("operator " + op)
		}
		switch op {
		case "+":
			b, ok := rv.(*list)
			if !ok || a.tuple != b.tuple {
				return nil, failf("can only concatenate %s to %s", typeName(a), typeName(a))
			}
			if err := r.items(len(a.items) + len(b.items)); err != nil {
				return nil, err
			}
			if err := r.charge(8 * (len(a.items) + len(b.items))); err != nil {
				return nil, err
			}
			return &list{items: append(append([]Value(nil), a.items...), b.items...), tuple: a.tuple}, nil
		case "*":
			n, ok := rv.(int)
			if !ok {
				return nil, failf("can't multiply a list by %s", typeName(rv))
			}
			if n > 0 && len(a.items) > 0 && n > r.lim.Items/len(a.items) {
				return nil, r.items(r.lim.Items + 1)
			}
			if err := r.charge(len(a.items) * max(n, 0) * 8); err != nil {
				return nil, err
			}
			out := &list{tuple: a.tuple}
			for i := 0; i < n; i++ {
				out.items = append(out.items, a.items...)
			}
			return out, nil
		}
	}
	x, xok := number(l)
	y, yok := number(rv)
	if !xok || !yok {
		return nil, failf("unsupported operand types for %s: %s and %s", op, typeName(l), typeName(rv))
	}
	_, lf := l.(float64)
	_, rf := rv.(float64)
	ints := !lf && !rf
	switch op {
	case "+", "-", "*":
		var v float64
		switch op {
		case "+":
			v = x + y
		case "-":
			v = x - y
		default:
			v = x * y
		}
		if ints {
			return intResult(v)
		}
		return v, nil
	case "/":
		if y == 0 {
			return nil, failf("division by zero")
		}
		return x / y, nil
	case "//", "%":
		if y == 0 {
			return nil, failf("integer division or modulo by zero")
		}
		q := math.Floor(x / y)
		if op == "%" {
			q = x - q*y
		}
		if ints {
			return intResult(q)
		}
		return q, nil
	case "**":
		v := math.Pow(x, y)
		if ints && y >= 0 {
			return intResult(v)
		}
		return v, nil
	}
	return nil, &UnsupportedError{What: "the operator " + op}
}

func intResult(v float64) (Value, error) {
	if math.Abs(v) > 1<<53 {
		return nil, &LimitError{Limit: "an integer beyond 2^53"}
	}
	return int(v), nil
}

func (r *renderer) repeatStr(s str, n Value) (Value, error) {
	k, ok := n.(int)
	if !ok {
		return nil, failf("can't multiply a string by %s", typeName(n))
	}
	if k <= 0 || s.len() == 0 {
		return str{}, nil
	}
	if k > r.lim.Output/s.len() {
		return nil, r.fits(r.lim.Output + 1)
	}
	if err := r.sized(s.len() * k); err != nil {
		return nil, err
	}
	var out builder
	for i := 0; i < k; i++ {
		out.str(s)
	}
	return out.done(), nil
}
