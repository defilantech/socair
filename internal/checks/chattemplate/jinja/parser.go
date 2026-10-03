package jinja

import "strings"

// Parse turns a template into a syntax tree.
func Parse(src string) ([]Node, error) {
	segs, err := lex(src)
	if err != nil {
		return nil, err
	}
	p := &parser{src: src, segs: segs}
	body, stop, err := p.body()
	if err != nil {
		return nil, err
	}
	if stop != "" {
		return nil, errAt(src, p.segs[p.i-1].pos, "unexpected {%% %s %%}", stop)
	}
	return body, nil
}

type parser struct {
	src   string
	segs  []segment
	i     int
	last  segment // the stop tag body() returned on
	depth int
}

// maxDepth bounds statement and expression nesting. Real templates nest a few
// levels; a hostile one must not drive unbounded recursion.
const maxDepth = 200

// maxChain bounds a run of same-precedence operators, such as a ~ b ~ c. The
// tree of a long chain is as deep as the chain, so it is bounded like nesting.
const maxChain = 1000

// body parses nodes until a statement whose keyword is in stops, and returns
// that keyword ("" at end of input). The stop tag is consumed; its tokens are
// left in p.last for the caller.
func (p *parser) body(stops ...string) ([]Node, string, error) {
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > maxDepth {
		return nil, "", errAt(p.src, p.segs[p.i-1].pos, "statements nested deeper than %d", maxDepth)
	}
	var out []Node
	for p.i < len(p.segs) {
		s := p.segs[p.i]
		p.i++
		switch s.kind {
		case segText:
			out = append(out, Text{S: s.text})
		case segOutput:
			e := p.exprs(s)
			x, err := e.tuple(true)
			if err != nil {
				return nil, "", err
			}
			if err := e.end(); err != nil {
				return nil, "", err
			}
			out = append(out, Output{X: x})
		case segStmt:
			if len(s.toks) == 0 || s.toks[0].kind != tName {
				return nil, "", errAt(p.src, s.pos, "empty or malformed statement")
			}
			kw := s.toks[0].v
			for _, st := range stops {
				if kw == st {
					p.last = s
					return out, kw, nil
				}
			}
			n, err := p.stmt(kw, s)
			if err != nil {
				return nil, "", err
			}
			if n != nil {
				out = append(out, n)
			}
		}
	}
	if len(stops) > 0 {
		return nil, "", errAt(p.src, len(p.src), "missing {%% %s %%}", stops[len(stops)-1])
	}
	return out, "", nil
}

func (p *parser) exprs(s segment) *exprParser {
	return &exprParser{src: p.src, toks: s.toks, pos: s.pos}
}

func (p *parser) stmt(kw string, s segment) (Node, error) {
	e := p.exprs(s)
	e.i = 1
	switch kw {
	case "if":
		return p.ifStmt(e)
	case "for":
		return p.forStmt(e)
	case "set":
		return p.setStmt(e)
	case "macro":
		return p.macroStmt(e)
	case "call":
		return p.callStmt(e)
	case "filter":
		f, err := e.filterChain(Name{N: ""})
		if err != nil {
			return nil, err
		}
		if err := e.end(); err != nil {
			return nil, err
		}
		b, _, err := p.body("endfilter")
		return FilterBlock{Filter: f, Body: b}, err
	case "generation":
		if err := e.end(); err != nil {
			return nil, err
		}
		b, _, err := p.body("endgeneration")
		return Generation{Body: b}, err
	case "break":
		return Break{}, e.end()
	case "continue":
		return Continue{}, e.end()
	case "do":
		x, err := e.tuple(true)
		if err != nil {
			return nil, err
		}
		return Do{X: x}, e.end()
	}
	return nil, errAt(p.src, s.pos, "unsupported statement %q", kw)
}

func (p *parser) ifStmt(e *exprParser) (Node, error) {
	var n If
	for {
		cond, err := e.expr()
		if err != nil {
			return nil, err
		}
		if err := e.end(); err != nil {
			return nil, err
		}
		b, stop, err := p.body("elif", "else", "endif")
		if err != nil {
			return nil, err
		}
		n.Branches = append(n.Branches, Branch{Cond: cond, Body: b})
		switch stop {
		case "elif":
			e = p.exprs(p.last)
			e.i = 1
			continue
		case "else":
			if err := p.endOf(p.last); err != nil {
				return nil, err
			}
			b, _, err := p.body("endif")
			if err != nil {
				return nil, err
			}
			n.Else = b
		}
		return n, nil
	}
}

func (p *parser) forStmt(e *exprParser) (Node, error) {
	var n For
	paren := e.accept(tOp, "(")
	for {
		t, ok := e.next()
		if !ok || t.kind != tName {
			return nil, e.fail("for wants a loop variable")
		}
		n.Targets = append(n.Targets, t.v)
		if !e.accept(tOp, ",") {
			break
		}
	}
	if paren && !e.accept(tOp, ")") {
		return nil, e.fail("for wants )")
	}
	if !e.accept(tName, "in") {
		return nil, e.fail("for wants in")
	}
	iter, err := e.tuple(false)
	if err != nil {
		return nil, err
	}
	n.Iter = iter
	if e.accept(tName, "if") {
		if n.Filter, err = e.expr(); err != nil {
			return nil, err
		}
	}
	e.accept(tName, "recursive")
	if err := e.end(); err != nil {
		return nil, err
	}
	b, stop, err := p.body("else", "endfor")
	if err != nil {
		return nil, err
	}
	n.Body = b
	if stop == "else" {
		if err := p.endOf(p.last); err != nil {
			return nil, err
		}
		if n.Else, _, err = p.body("endfor"); err != nil {
			return nil, err
		}
	}
	return n, nil
}

func (p *parser) setStmt(e *exprParser) (Node, error) {
	var n Set
	for {
		t, err := e.unary(false)
		if err != nil {
			return nil, err
		}
		n.Targets = append(n.Targets, t)
		if !e.accept(tOp, ",") {
			break
		}
	}
	if e.accept(tOp, "=") {
		x, err := e.tuple(true)
		if err != nil {
			return nil, err
		}
		n.X = x
		return n, e.end()
	}
	if e.accept(tOp, "|") {
		e.i--
		if _, err := e.filterChain(Name{N: ""}); err != nil {
			return nil, err
		}
	}
	if err := e.end(); err != nil {
		return nil, err
	}
	b, _, err := p.body("endset")
	n.Body = b
	return n, err
}

func (p *parser) macroStmt(e *exprParser) (Node, error) {
	t, ok := e.next()
	if !ok || t.kind != tName {
		return nil, e.fail("macro wants a name")
	}
	n := Macro{Name: t.v}
	params, defaults, err := e.params()
	if err != nil {
		return nil, err
	}
	n.Params, n.Defaults = params, defaults
	if err := e.end(); err != nil {
		return nil, err
	}
	n.Body, _, err = p.body("endmacro")
	return n, err
}

func (p *parser) callStmt(e *exprParser) (Node, error) {
	if e.peekIs(tOp, "(") {
		if _, _, err := e.params(); err != nil {
			return nil, err
		}
	}
	c, err := e.expr()
	if err != nil {
		return nil, err
	}
	if err := e.end(); err != nil {
		return nil, err
	}
	b, _, err := p.body("endcall")
	return CallBlock{Call: c, Body: b}, err
}

// endOf checks a bare stop tag such as {% else %} carries nothing else.
func (p *parser) endOf(s segment) error {
	if len(s.toks) != 1 {
		return errAt(p.src, s.pos, "unexpected tokens after %q", s.toks[0].v)
	}
	return nil
}

// exprParser parses the tokens of one tag.
type exprParser struct {
	src   string
	toks  []token
	i     int
	pos   int
	depth int
}

// enter bounds expression recursion; call the returned func on the way out.
func (e *exprParser) enter() (func(), error) {
	e.depth++
	if e.depth > maxDepth {
		return func() {}, e.fail("expression nested too deeply")
	}
	return func() { e.depth-- }, nil
}

func (e *exprParser) fail(msg string) error {
	at := e.pos
	if e.i < len(e.toks) {
		at = e.toks[e.i].pos
	}
	return errAt(e.src, at, "%s", msg)
}

func (e *exprParser) peek() (token, bool) {
	if e.i < len(e.toks) {
		return e.toks[e.i], true
	}
	return token{}, false
}

func (e *exprParser) next() (token, bool) {
	t, ok := e.peek()
	if ok {
		e.i++
	}
	return t, ok
}

func (e *exprParser) peekIs(k tokKind, v string) bool {
	t, ok := e.peek()
	return ok && t.kind == k && t.v == v
}

func (e *exprParser) accept(k tokKind, v string) bool {
	if e.peekIs(k, v) {
		e.i++
		return true
	}
	return false
}

func (e *exprParser) end() error {
	if e.i < len(e.toks) {
		return e.fail("unexpected " + e.toks[e.i].v)
	}
	return nil
}

// tuple parses an expression, or a bare tuple when commas follow.
func (e *exprParser) tuple(withCond bool) (Expr, error) {
	first, err := e.exprMaybeCond(withCond)
	if err != nil {
		return nil, err
	}
	if !e.peekIs(tOp, ",") {
		return first, nil
	}
	items := []Expr{first}
	for e.accept(tOp, ",") {
		if e.atTupleEnd() {
			break
		}
		x, err := e.exprMaybeCond(withCond)
		if err != nil {
			return nil, err
		}
		items = append(items, x)
	}
	return Tuple{Items: items}, nil
}

func (e *exprParser) atTupleEnd() bool {
	t, ok := e.peek()
	return !ok || (t.kind == tName && (t.v == "if" || t.v == "recursive"))
}

func (e *exprParser) exprMaybeCond(withCond bool) (Expr, error) {
	if withCond {
		return e.expr()
	}
	return e.or()
}

func (e *exprParser) expr() (Expr, error) {
	leave, err := e.enter()
	defer leave()
	if err != nil {
		return nil, err
	}
	x, err := e.or()
	if err != nil {
		return nil, err
	}
	for e.accept(tName, "if") {
		c, err := e.or()
		if err != nil {
			return nil, err
		}
		var els Expr
		if e.accept(tName, "else") {
			if els, err = e.or(); err != nil {
				return nil, err
			}
		}
		x = Cond{Then: x, If: c, Else: els}
	}
	return x, nil
}

func (e *exprParser) or() (Expr, error) {
	return e.binary(e.and, "or")
}

func (e *exprParser) and() (Expr, error) {
	return e.binary(e.not, "and")
}

func (e *exprParser) binary(sub func() (Expr, error), names ...string) (Expr, error) {
	l, err := sub()
	if err != nil {
		return nil, err
	}
	for n := 0; ; n++ {
		if n > maxChain {
			return nil, e.fail("expression chains too many operators")
		}
		t, ok := e.peek()
		if !ok {
			return l, nil
		}
		matched := ""
		for _, n := range names {
			if t.v == n && (t.kind == tName || t.kind == tOp) {
				matched = n
			}
		}
		if matched == "" {
			return l, nil
		}
		e.i++
		r, err := sub()
		if err != nil {
			return nil, err
		}
		l = Bin{Op: matched, L: l, R: r}
	}
}

func (e *exprParser) not() (Expr, error) {
	leave, err := e.enter()
	defer leave()
	if err != nil {
		return nil, err
	}
	if e.accept(tName, "not") {
		x, err := e.not()
		if err != nil {
			return nil, err
		}
		return Unary{Op: "not", X: x}, nil
	}
	return e.compare()
}

func (e *exprParser) compare() (Expr, error) {
	l, err := e.math1()
	if err != nil {
		return nil, err
	}
	for {
		t, ok := e.peek()
		if !ok {
			return l, nil
		}
		op := ""
		switch {
		case t.kind == tOp && (t.v == "==" || t.v == "!=" || t.v == "<" || t.v == ">" || t.v == "<=" || t.v == ">="):
			op = t.v
			e.i++
		case t.kind == tName && t.v == "in":
			op = "in"
			e.i++
		case t.kind == tName && t.v == "not" && e.i+1 < len(e.toks) && e.toks[e.i+1].v == "in":
			op = "not in"
			e.i += 2
		default:
			return l, nil
		}
		r, err := e.math1()
		if err != nil {
			return nil, err
		}
		l = Bin{Op: op, L: l, R: r}
	}
}

func (e *exprParser) math1() (Expr, error)  { return e.binary(e.concat, "+", "-") }
func (e *exprParser) concat() (Expr, error) { return e.binary(e.math2, "~") }
func (e *exprParser) math2() (Expr, error)  { return e.binary(e.pow, "*", "/", "//", "%") }
func (e *exprParser) pow() (Expr, error) {
	return e.binary(func() (Expr, error) { return e.unary(true) }, "**")
}

func (e *exprParser) unary(withFilter bool) (Expr, error) {
	leave, err := e.enter()
	defer leave()
	if err != nil {
		return nil, err
	}
	if t, ok := e.peek(); ok && t.kind == tOp && (t.v == "-" || t.v == "+") {
		e.i++
		x, err := e.unary(withFilter)
		if err != nil {
			return nil, err
		}
		return Unary{Op: t.v, X: x}, nil
	}
	x, err := e.primary()
	if err != nil {
		return nil, err
	}
	if x, err = e.postfix(x); err != nil {
		return nil, err
	}
	if withFilter {
		return e.filterChain(x)
	}
	return x, nil
}

func (e *exprParser) primary() (Expr, error) {
	t, ok := e.next()
	if !ok {
		return nil, e.fail("expression expected")
	}
	switch t.kind {
	case tStr:
		var b strings.Builder
		b.WriteString(t.v)
		for {
			n, ok := e.peek()
			if !ok || n.kind != tStr {
				break
			}
			b.WriteString(n.v) // adjacent literals concatenate
			e.i++
		}
		return Str{V: b.String()}, nil
	case tNum:
		return Num{V: t.v}, nil
	case tName:
		switch t.v {
		case "true", "True", "false", "False", "none", "None":
			return Const{V: strings.ToLower(t.v)}, nil
		}
		return Name{N: t.v}, nil
	}
	switch t.v {
	case "(":
		if e.accept(tOp, ")") {
			return Tuple{}, nil
		}
		x, err := e.tuple(true)
		if err != nil {
			return nil, err
		}
		if !e.accept(tOp, ")") {
			return nil, e.fail("want )")
		}
		return x, nil
	case "[":
		var items []Expr
		for !e.accept(tOp, "]") {
			x, err := e.expr()
			if err != nil {
				return nil, err
			}
			items = append(items, x)
			if !e.accept(tOp, ",") {
				if !e.accept(tOp, "]") {
					return nil, e.fail("want ]")
				}
				break
			}
		}
		return List{Items: items}, nil
	case "{":
		var d Dict
		for !e.accept(tOp, "}") {
			k, err := e.expr()
			if err != nil {
				return nil, err
			}
			if !e.accept(tOp, ":") {
				return nil, e.fail("want : in dict")
			}
			v, err := e.expr()
			if err != nil {
				return nil, err
			}
			d.Keys, d.Vals = append(d.Keys, k), append(d.Vals, v)
			if !e.accept(tOp, ",") {
				if !e.accept(tOp, "}") {
					return nil, e.fail("want }")
				}
				break
			}
		}
		return d, nil
	}
	return nil, e.fail("unexpected " + t.v)
}

func (e *exprParser) postfix(x Expr) (Expr, error) {
	for {
		switch {
		case e.accept(tOp, "."):
			t, ok := e.next()
			if !ok || (t.kind != tName && t.kind != tNum) {
				return nil, e.fail("want attribute name")
			}
			x = Attr{X: x, Name: t.v}
		case e.accept(tOp, "["):
			s, err := e.subscript(x)
			if err != nil {
				return nil, err
			}
			x = s
		case e.peekIs(tOp, "("):
			c, err := e.call(x)
			if err != nil {
				return nil, err
			}
			x = c
		default:
			return x, nil
		}
	}
}

func (e *exprParser) subscript(x Expr) (Expr, error) {
	var parts [3]Expr
	n := 0
	slice := false
	for {
		if e.accept(tOp, "]") {
			break
		}
		if e.accept(tOp, ":") {
			slice = true
			n++
			if n > 2 {
				return nil, e.fail("too many : in slice")
			}
			continue
		}
		v, err := e.expr()
		if err != nil {
			return nil, err
		}
		parts[n] = v
		if e.peekIs(tOp, ",") {
			return nil, e.fail("tuple subscripts are not supported")
		}
	}
	if !slice {
		if parts[0] == nil {
			return nil, e.fail("empty subscript")
		}
		return Index{X: x, I: parts[0]}, nil
	}
	return Slice{X: x, Lo: parts[0], Hi: parts[1], Step: parts[2]}, nil
}

func (e *exprParser) call(f Expr) (Expr, error) {
	args, kw, err := e.args()
	if err != nil {
		return nil, err
	}
	return Call{F: f, Args: args, Kw: kw}, nil
}

// args parses a parenthesized argument list.
func (e *exprParser) args() ([]Expr, []Kw, error) {
	if !e.accept(tOp, "(") {
		return nil, nil, e.fail("want (")
	}
	var args []Expr
	var kw []Kw
	for !e.accept(tOp, ")") {
		if t, ok := e.peek(); ok && t.kind == tName && e.i+1 < len(e.toks) && e.toks[e.i+1].v == "=" && e.toks[e.i+1].kind == tOp {
			e.i += 2
			x, err := e.expr()
			if err != nil {
				return nil, nil, err
			}
			kw = append(kw, Kw{Name: t.v, X: x})
		} else {
			x, err := e.expr()
			if err != nil {
				return nil, nil, err
			}
			args = append(args, x)
		}
		if !e.accept(tOp, ",") {
			if !e.accept(tOp, ")") {
				return nil, nil, e.fail("want )")
			}
			break
		}
	}
	return args, kw, nil
}

// params parses a macro or call-block parameter list.
func (e *exprParser) params() ([]string, []Expr, error) {
	if !e.accept(tOp, "(") {
		return nil, nil, e.fail("want (")
	}
	var names []string
	var defs []Expr
	for !e.accept(tOp, ")") {
		t, ok := e.next()
		if !ok || t.kind != tName {
			return nil, nil, e.fail("want parameter name")
		}
		names = append(names, t.v)
		var d Expr
		if e.accept(tOp, "=") {
			x, err := e.expr()
			if err != nil {
				return nil, nil, err
			}
			d = x
		}
		defs = append(defs, d)
		if !e.accept(tOp, ",") {
			if !e.accept(tOp, ")") {
				return nil, nil, e.fail("want )")
			}
			break
		}
	}
	return names, defs, nil
}

var testStops = map[string]bool{"and": true, "or": true, "else": true, "if": true, "in": true,
	"not": true, "is": true, "recursive": true}

func (e *exprParser) filterChain(x Expr) (Expr, error) {
	for {
		switch {
		case e.accept(tOp, "|"):
			t, ok := e.next()
			if !ok || t.kind != tName {
				return nil, e.fail("want filter name")
			}
			f := Filter{X: x, Name: t.v}
			if e.peekIs(tOp, "(") {
				args, kw, err := e.args()
				if err != nil {
					return nil, err
				}
				f.Args, f.Kw = args, kw
			}
			x = f
		case e.accept(tName, "is"):
			tst := Test{X: x, Not: e.accept(tName, "not")}
			t, ok := e.next()
			if !ok || t.kind != tName {
				return nil, e.fail("want test name")
			}
			tst.Name = t.v
			if e.peekIs(tOp, "(") {
				args, _, err := e.args()
				if err != nil {
					return nil, err
				}
				tst.Args = args
			} else if n, ok := e.peek(); ok && (n.kind == tStr || n.kind == tNum ||
				(n.kind == tName && !testStops[n.v])) {
				a, err := e.primary()
				if err != nil {
					return nil, err
				}
				if a, err = e.postfix(a); err != nil {
					return nil, err
				}
				tst.Args = []Expr{a}
			}
			x = tst
		case e.peekIs(tOp, "("):
			c, err := e.call(x)
			if err != nil {
				return nil, err
			}
			x = c
		default:
			return x, nil
		}
	}
}
