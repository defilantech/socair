package chattemplate

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/defilantech/socair/internal/checks/chattemplate/jinja"
)

// signal is one structural observation about a parsed template.
type signal struct {
	pattern string
	span    string
	detail  string
	fail    bool // positive evidence; otherwise a lead
}

// analysis is what the syntax-tree walk found.
type analysis struct {
	signals []signal
	// outsideText is natural-language text the template emits outside the
	// message loop, such as a default system prompt. It is not a finding on
	// its own (Qwen and Granite ship one), but a reviewer should see it.
	outsideText []string
	// guards are the constants a content condition tests ("html" in
	// "if 'html' in message.content"), in the order found: the renderer puts
	// them in a probe message to see what the condition makes the template
	// add.
	guards []string
	// exhausted is set when the work budget ran out before the walk finished.
	exhausted bool
}

// scope tracks what each template variable is bound to. It is flat: a
// binding made inside a loop stays, which over-approximates and so errs
// toward seeing content where Jinja's scoping would not.
type scope struct {
	msgs    map[string]bool   // the messages collection, or a slice of it
	msg     map[string]bool   // one message
	content map[string]bool   // values derived from message content
	consts  map[string]string // names bound to a constant string
}

type ctx struct {
	inLoop      bool // inside a loop over messages
	contentCond bool // inside a branch whose condition tests what message content says
}

func analyse(nodes []jinja.Node) analysis {
	a := &analyser{sc: scope{
		msgs:    map[string]bool{"messages": true},
		msg:     map[string]bool{},
		content: map[string]bool{},
		consts:  map[string]string{},
	}, seen: map[string]bool{}, scanned: map[string]bool{}}
	a.walk(nodes, ctx{})
	a.out.exhausted = a.exhausted()
	return a.out
}

type analyser struct {
	sc      scope
	out     analysis
	seen    map[string]bool
	scanned map[string]bool // text already run through scanText
	steps   int
}

// maxSteps is the analysis work budget. Real templates use a few thousand
// steps; a template built to make analysis super-linear runs out, and is
// reported as unanalysable rather than analysed in part.
const maxSteps = 2_000_000

// tick counts one unit of work and reports whether the budget remains.
func (a *analyser) tick() bool {
	a.steps++
	return a.steps <= maxSteps
}

func (a *analyser) exhausted() bool { return a.steps > maxSteps }

func (a *analyser) add(s signal) {
	k := s.pattern + "\x00" + s.span
	if a.seen[k] {
		return
	}
	a.seen[k] = true
	a.out.signals = append(a.out.signals, s)
}

func (a *analyser) walk(nodes []jinja.Node, c ctx) {
	if !a.tick() {
		return
	}
	// run is the constant text emitted back to back, scanned as one string so
	// a phrase split across adjacent pieces ({{ 'Ign' }}ore previous...) is
	// still read whole.
	var run strings.Builder
	flush := func() {
		if run.Len() > 0 {
			a.emitted(run.String(), c)
			run.Reset()
		}
	}
	defer flush()
	for _, n := range nodes {
		switch n := n.(type) {
		case jinja.Text:
			a.emitted(n.S, c)
			run.WriteString(n.S)
			continue
		case jinja.Output:
			a.scanExpr(n.X)
			if isRaise(n.X) {
				continue // error text for the caller, never sent to the model
			}
			if v, ok := a.fold(n.X); ok {
				a.emitted(v, c)
				run.WriteString(v)
				continue
			}
			flush()
			for _, piece := range a.literalPieces(n.X) {
				a.emitted(piece, c)
			}
			continue
		}
		flush()
		switch n := n.(type) {
		case jinja.If:
			for _, b := range n.Branches {
				a.scanExpr(b.Cond)
				bc := c
				if a.testsContentValue(b.Cond) {
					bc.contentCond = true
				}
				a.walk(b.Body, bc)
			}
			a.walk(n.Else, c)
		case jinja.For:
			a.scanExpr(n.Iter)
			if n.Filter != nil {
				a.scanExpr(n.Filter)
			}
			bc := c
			switch {
			case a.readsContent(n.Iter):
				for _, t := range n.Targets {
					a.sc.content[t] = true
				}
			case a.isMessage(n.Iter) || a.readsMsgs(n.Iter):
				for _, t := range n.Targets {
					a.sc.msg[t] = true
				}
				bc.inLoop = true
			}
			a.walk(n.Body, bc)
			a.walk(n.Else, c)
		case jinja.Set:
			a.set(n, c)
		case jinja.Macro:
			for _, d := range n.Defaults {
				if d != nil {
					a.scanExpr(d)
				}
			}
			// A macro's text is attributed to its call sites, which this walk
			// does not resolve, so it is scanned but not counted as default
			// text outside the loop.
			a.walk(n.Body, ctx{inLoop: true})
		case jinja.CallBlock:
			a.scanExpr(n.Call)
			a.walk(n.Body, c)
		case jinja.FilterBlock:
			a.scanExpr(n.Filter)
			a.walk(n.Body, c)
		case jinja.Generation:
			a.walk(n.Body, c)
		case jinja.Do:
			a.scanExpr(n.X)
		}
	}
}

func (a *analyser) set(n jinja.Set, c ctx) {
	if n.X == nil {
		if n.Filter != nil {
			a.scanExpr(n.Filter)
		}
		a.walk(n.Body, ctx{inLoop: true}) // captured, not emitted here
		return
	}
	a.scanExpr(n.X)
	for _, piece := range a.literalPieces(n.X) {
		a.scanText(piece)
	}
	if len(n.Targets) != 1 {
		return
	}
	key := nameKey(n.Targets[0])
	if key == "" {
		return
	}
	if v, ok := a.fold(n.X); ok {
		a.sc.consts[key] = v
	}
	switch {
	case a.readsContent(n.X):
		a.sc.content[key] = true
	case a.isMessage(n.X):
		a.sc.msg[key] = true
	case a.readsMsgs(n.X):
		a.sc.msgs[key] = true
	}
}

// isRaise reports a call to raise_exception, the template's error path.
func isRaise(e jinja.Expr) bool {
	c, ok := e.(jinja.Call)
	if !ok {
		return false
	}
	n, ok := c.F.(jinja.Name)
	return ok && n.N == "raise_exception"
}

// nameKey is a binding's name: "x", or "ns.x" for a namespace attribute.
func nameKey(e jinja.Expr) string {
	switch e := e.(type) {
	case jinja.Name:
		return e.N
	case jinja.Attr:
		if n, ok := e.X.(jinja.Name); ok {
			return n.N + "." + e.Name
		}
	}
	return ""
}

func (a *analyser) bound(m map[string]bool, e jinja.Expr) bool {
	k := nameKey(e)
	return k != "" && m[k]
}

// readsMsgs reports whether e refers to the messages collection.
func (a *analyser) readsMsgs(e jinja.Expr) bool {
	found := false
	visit(e, func(x jinja.Expr) {
		if a.bound(a.sc.msgs, x) {
			found = true
		}
	})
	return found
}

// isMessage reports whether e is one message: a message variable, or the
// messages collection indexed by position.
func (a *analyser) isMessage(e jinja.Expr) bool {
	if a.bound(a.sc.msg, e) {
		return true
	}
	if ix, ok := e.(jinja.Index); ok {
		if _, isStr := ix.I.(jinja.Str); !isStr && a.bound(a.sc.msgs, ix.X) {
			return true
		}
	}
	return false
}

var contentKeys = map[string]bool{"content": true, "reasoning_content": true, "thinking": true}

// readsContent reports whether e reads message content anywhere inside it.
func (a *analyser) readsContent(e jinja.Expr) bool {
	found := false
	visit(e, func(x jinja.Expr) {
		switch x := x.(type) {
		case jinja.Name, jinja.Attr:
			if a.bound(a.sc.content, x) {
				found = true
			}
		}
		switch x := x.(type) {
		case jinja.Attr:
			if contentKeys[x.Name] && a.isMessage(x.X) {
				found = true
			}
		case jinja.Index:
			if k, ok := a.fold(x.I); ok && contentKeys[k] && a.isMessage(x.X) {
				found = true
			}
		}
	})
	return found
}

// testsContentValue reports whether a condition tests what message content
// says: membership of a constant, equality with a non-empty constant, or a
// startswith-style method with constant arguments. That is the trigger shape
// of a content-conditional injection ("if 'html' in message.content"). A
// type or existence test ("content is string", "if system_message") is how
// every real template handles content, and does not count.
func (a *analyser) testsContentValue(e jinja.Expr) bool {
	found := false
	visit(e, func(x jinja.Expr) {
		switch x := x.(type) {
		case jinja.Bin:
			switch x.Op {
			case "in", "not in":
				if a.readsContent(x.R) && a.isConst(x.L) {
					found = true
					a.guard(x.L)
				} else if a.readsContent(x.L) && a.isConst(x.R) {
					found = true
					a.guard(x.R)
				}
			case "==", "!=":
				if a.readsContent(x.L) && a.isNonEmptyConst(x.R) {
					found = true
					a.guard(x.R)
				} else if a.readsContent(x.R) && a.isNonEmptyConst(x.L) {
					found = true
					a.guard(x.L)
				}
			}
		case jinja.Call:
			if at, ok := x.F.(jinja.Attr); ok && contentProbes[at.Name] && a.readsContent(at.X) {
				for _, arg := range x.Args {
					if a.isConst(arg) {
						found = true
						a.guard(arg)
					}
				}
			}
		}
	})
	return found
}

// maxGuards bounds the trigger probes a template gets.
const maxGuards = 8

// guard records the constant (or each constant of a list) a content
// condition tests.
func (a *analyser) guard(e jinja.Expr) {
	if l, ok := e.(jinja.List); ok {
		for _, x := range l.Items {
			a.guard(x)
		}
		return
	}
	v, ok := a.fold(e)
	if !ok || v == "" || len(v) > 256 || len(a.out.guards) >= maxGuards {
		return
	}
	for _, g := range a.out.guards {
		if g == v {
			return
		}
	}
	a.out.guards = append(a.out.guards, v)
}

var contentProbes = map[string]bool{"startswith": true, "endswith": true, "find": true, "rfind": true,
	"index": true, "count": true, "__contains__": true}

func (a *analyser) isConst(e jinja.Expr) bool {
	if l, ok := e.(jinja.List); ok {
		for _, x := range l.Items {
			if !a.isConst(x) {
				return false
			}
		}
		return len(l.Items) > 0
	}
	_, ok := a.fold(e)
	return ok
}

func (a *analyser) isNonEmptyConst(e jinja.Expr) bool {
	v, ok := a.fold(e)
	return ok && v != ""
}

// visit calls f on e and every subexpression.
func visit(e jinja.Expr, f func(jinja.Expr)) {
	if e == nil {
		return
	}
	f(e)
	visitChildren(e, f)
}

func visitChildren(e jinja.Expr, f func(jinja.Expr)) {
	switch e := e.(type) {
	case jinja.Attr:
		visit(e.X, f)
	case jinja.Index:
		visit(e.X, f)
		visit(e.I, f)
	case jinja.Slice:
		visit(e.X, f)
		visit(e.Lo, f)
		visit(e.Hi, f)
		visit(e.Step, f)
	case jinja.Call:
		visit(e.F, f)
		for _, x := range e.Args {
			visit(x, f)
		}
		for _, k := range e.Kw {
			visit(k.X, f)
		}
	case jinja.Filter:
		visit(e.X, f)
		for _, x := range e.Args {
			visit(x, f)
		}
		for _, k := range e.Kw {
			visit(k.X, f)
		}
	case jinja.Test:
		visit(e.X, f)
		for _, x := range e.Args {
			visit(x, f)
		}
	case jinja.Bin:
		visit(e.L, f)
		visit(e.R, f)
	case jinja.Unary:
		visit(e.X, f)
	case jinja.Cond:
		visit(e.Then, f)
		visit(e.If, f)
		visit(e.Else, f)
	case jinja.List:
		for _, x := range e.Items {
			visit(x, f)
		}
	case jinja.Tuple:
		for _, x := range e.Items {
			visit(x, f)
		}
	case jinja.Dict:
		for i := range e.Keys {
			visit(e.Keys[i], f)
			visit(e.Vals[i], f)
		}
	}
}

// literalPieces returns the constant text an expression contributes: the whole
// value when it folds, otherwise each maximal constant subexpression. A
// payload hidden in one operand of a non-constant concatenation is still seen.
func (a *analyser) literalPieces(e jinja.Expr) []string {
	if v, ok := a.fold(e); ok {
		return []string{v}
	}
	var out []string
	switch e := e.(type) {
	case jinja.Bin:
		out = append(out, a.literalPieces(e.L)...)
		out = append(out, a.literalPieces(e.R)...)
	case jinja.Cond:
		out = append(out, a.literalPieces(e.Then)...)
		if e.Else != nil {
			out = append(out, a.literalPieces(e.Else)...)
		}
	case jinja.Filter:
		out = append(out, a.literalPieces(e.X)...)
		for _, x := range e.Args {
			out = append(out, a.literalPieces(x)...)
		}
	case jinja.Call:
		if isRaise(e) {
			return nil
		}
		for _, x := range e.Args {
			out = append(out, a.literalPieces(x)...)
		}
	case jinja.List:
		for _, x := range e.Items {
			out = append(out, a.literalPieces(x)...)
		}
	}
	return out
}

// scanExpr looks for code-execution reach (a dunder name however it is built),
// obfuscated constants, and lead language in every constant inside e.
func (a *analyser) scanExpr(e jinja.Expr) {
	visit(e, func(x jinja.Expr) {
		if !a.tick() {
			return
		}
		switch x := x.(type) {
		case jinja.Name:
			a.moduleUse(x.N)
		case jinja.Call:
			a.callUse(x)
		case jinja.Attr:
			a.nameUse(x.Name)
		case jinja.Index:
			if k, ok := a.fold(x.I); ok {
				a.nameUse(k)
			}
		case jinja.Filter:
			if x.Name == "attr" && len(x.Args) > 0 {
				if k, ok := a.fold(x.Args[0]); ok && processAttrs[k] {
					a.processUse(k, "template reaches the process-execution function "+k+" by name")
				}
			}
			switch x.Name {
			case "attr", "map", "selectattr", "rejectattr", "groupby", "sum", "sort", "unique", "min", "max":
				for _, arg := range x.Args {
					if k, ok := a.fold(arg); ok {
						a.nameUse(k)
					}
				}
				for _, kw := range x.Kw {
					if k, ok := a.fold(kw.X); ok {
						a.nameUse(k)
					}
				}
			case "reverse":
				if v, ok := a.fold(x.X); ok && hasLetters(v) {
					a.add(signal{pattern: "obfuscated-literal", span: excerptS(v), detail: "a constant string is reversed before use"})
				}
			}
		case jinja.Slice:
			if st, ok := x.Step.(jinja.Unary); ok && st.Op == "-" {
				if v, ok := a.fold(x.X); ok && hasLetters(v) {
					a.add(signal{pattern: "obfuscated-literal", span: excerptS(v), detail: "a constant string is reversed by slicing"})
				}
			}
		case jinja.Bin:
			if x.Op == "~" || x.Op == "+" {
				l, lok := a.fold(x.L)
				r, rok := a.fold(x.R)
				if lok && rok && splitsWord(l, r) {
					a.add(signal{pattern: "split-word-literal", span: excerptS(l + r),
						detail: "a word is split across concatenated string literals"})
				}
			}
		case jinja.Str:
			a.scanText(x.V)
		}
		if _, isStr := x.(jinja.Str); !isStr {
			if v, ok := a.fold(x); ok {
				a.scanText(v)
			}
		}
	})
}

// nameUse FAILs a dunder attribute or key, however it was spelled: a dunder is
// the first step of every Jinja sandbox escape.
func (a *analyser) nameUse(n string) {
	if len(n) > 4 && strings.HasPrefix(n, "__") && strings.HasSuffix(n, "__") {
		a.add(signal{pattern: "python-object-escape", span: n, fail: true,
			detail: "template reaches a Python dunder attribute"})
	}
}

// Process execution is judged from the parsed template, never from its text:
// a template that names os.system in prose a model will read is not code. In
// an expression, these names are the reach a sandbox escape needs.
var (
	// processModules are Python modules that run commands or import others.
	processModules = map[string]bool{"os": true, "subprocess": true, "sys": true,
		"builtins": true, "importlib": true, "posix": true, "nt": true, "pty": true}
	// processCalls are builtins that execute code when called by name.
	processCalls = map[string]bool{"eval": true, "exec": true, "compile": true, "__import__": true}
	// processAttrs are functions that start a process or import a module,
	// reached as an attribute.
	processAttrs = map[string]bool{"system": true, "popen": true, "spawnl": true, "spawnv": true,
		"execv": true, "execve": true, "check_output": true, "check_call": true, "getoutput": true,
		"getstatusoutput": true, "import_module": true}
)

func (a *analyser) processUse(span, detail string) {
	a.add(signal{pattern: "process-execution", span: span, fail: true, detail: detail})
}

// moduleUse FAILs a reference to a command-running module in an expression.
func (a *analyser) moduleUse(n string) {
	if processModules[n] {
		a.processUse(n, "template references the Python module "+n)
	}
}

// callUse FAILs a call to a code-executing builtin or a process function.
func (a *analyser) callUse(c jinja.Call) {
	switch f := c.F.(type) {
	case jinja.Name:
		if processCalls[f.N] {
			a.processUse(f.N+"(...)", "template calls the code-executing builtin "+f.N)
		}
	case jinja.Attr:
		if processAttrs[f.Name] {
			a.processUse("."+f.Name+"(...)", "template calls the process-execution function "+f.Name)
		}
	}
}

// emitted records constant text the template outputs.
func (a *analyser) emitted(s string, c ctx) {
	a.scanText(s)
	clean := normalize(s)
	if c.contentCond {
		if m := systemTurn.FindString(clean); m != "" {
			a.add(signal{pattern: "content-conditional-injection", span: excerptS(m),
				detail: "a branch that tests message content emits a system turn"})
		} else if m := prose.FindString(clean); m != "" {
			a.add(signal{pattern: "content-conditional-injection", span: excerptS(m),
				detail: "a branch that tests message content emits its own instruction text"})
		}
	}
	if !c.inLoop {
		if m := prose.FindString(clean); m != "" {
			a.out.outsideText = append(a.out.outsideText, excerptS(strings.TrimSpace(m)))
		}
	}
}

var (
	systemTurn = regexp.MustCompile(`(?i)(<\|im_start\|>|<\|start_header_id\|>|<start_of_turn>|<\|start\|>)\s*system\b|<\|system\|>|\[SYSTEM_PROMPT\]|<<SYS>>`)
	prose      = regexp.MustCompile(`[A-Za-z]{2,}[,;]?(\s+[A-Za-z]{2,}[,;.]?){3,}`)
	url        = regexp.MustCompile(`(?i)\b(https?|ftp)://[^\s'"<>]+`)
	markup     = regexp.MustCompile(`(?i)<\s*(script|iframe|object|embed)\b|javascript:|\bon(error|load)\s*=`)
	blob       = regexp.MustCompile(`[A-Za-z0-9+/]{160,}={0,2}`)
)

// scanText runs the language leads over constant text, after normalizing it,
// and flags characters that hide text from a reviewer.
func (a *analyser) scanText(s string) {
	if s == "" || a.scanned[s] {
		return
	}
	a.scanned[s] = true
	if r, ok := hiddenRune(s); ok {
		a.add(signal{pattern: "invisible-character", span: fmt.Sprintf("U+%04X", r),
			detail: "zero-width or bidirectional control character hides text from review"})
	}
	if w := mixedScriptWord(s); w != "" {
		a.add(signal{pattern: "mixed-script-word", span: w,
			detail: "a word mixes Latin with lookalike letters from another script"})
	}
	clean := normalize(s)
	for _, p := range leads {
		if loc := p.re.FindStringIndex(clean); loc != nil {
			a.add(signal{pattern: p.name, span: excerpt(clean, loc[0], loc[1]), detail: p.detail})
		}
	}
	if m := url.FindString(clean); m != "" {
		a.add(signal{pattern: "external-url", span: excerptS(m), detail: "template text carries an external URL"})
	}
	if m := markup.FindString(clean); m != "" {
		a.add(signal{pattern: "markup-injection", span: excerptS(m), detail: "template text carries active HTML or script"})
	}
	if m := blob.FindString(clean); m != "" {
		a.add(signal{pattern: "encoded-blob", span: excerptS(m), detail: "template text carries a long encoded blob"})
	}
}

// concatOperands flattens a chain of ~ and + into its operands, in order,
// without recursion.
func concatOperands(e jinja.Bin) []jinja.Expr {
	var out []jinja.Expr
	stack := []jinja.Expr{e}
	for len(stack) > 0 {
		x := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if b, ok := x.(jinja.Bin); ok && (b.Op == "~" || b.Op == "+") {
			stack = append(stack, b.R, b.L)
			continue
		}
		out = append(out, x)
	}
	return out
}

// fold evaluates e to a constant string when it is built only from constants.
func (a *analyser) fold(e jinja.Expr) (string, bool) {
	return a.foldDepth(e, 0)
}

// maxFold caps a folded constant. Folding through set chains or replace can
// grow a string exponentially; past the cap the value is treated as not
// constant, and the text it would carry has already been scanned in pieces.
const maxFold = 1 << 16

func (a *analyser) foldDepth(e jinja.Expr, d int) (string, bool) {
	v, ok := a.foldOnce(e, d)
	if !ok || len(v) > maxFold {
		return "", false
	}
	return v, true
}

func (a *analyser) foldOnce(e jinja.Expr, d int) (string, bool) {
	if d > 64 || !a.tick() {
		return "", false
	}
	f := func(x jinja.Expr) (string, bool) { return a.foldDepth(x, d+1) }
	switch e := e.(type) {
	case jinja.Str:
		return e.V, true
	case jinja.Num:
		return e.V, true
	case jinja.Name:
		v, ok := a.sc.consts[e.N]
		return v, ok
	case jinja.Attr:
		k := nameKey(e)
		v, ok := a.sc.consts[k]
		return v, ok
	case jinja.Bin:
		if e.Op != "~" && e.Op != "+" {
			return "", false
		}
		// A chain a ~ b ~ c is a tree as deep as it is long, so it is folded
		// as a flat list of operands: the depth limit must not stop a long
		// chain of short pieces from being read.
		var b strings.Builder
		for _, x := range concatOperands(e) {
			v, ok := f(x)
			if !ok || b.Len()+len(v) > maxFold {
				return "", false
			}
			if isNumber(v) && e.Op == "+" {
				return "", false
			}
			b.WriteString(v)
		}
		return b.String(), true
	case jinja.Filter:
		return a.foldFilter(e, f)
	case jinja.Slice:
		v, ok := f(e.X)
		if !ok {
			return "", false
		}
		return slice(v, e, f)
	case jinja.Call:
		at, ok := e.F.(jinja.Attr)
		if !ok {
			return "", false
		}
		recv, ok := f(at.X)
		if !ok {
			return "", false
		}
		args := make([]string, len(e.Args))
		for i, x := range e.Args {
			if args[i], ok = f(x); !ok {
				return "", false
			}
		}
		return strMethod(recv, at.Name, args)
	}
	return "", false
}

func (a *analyser) foldFilter(e jinja.Filter, f func(jinja.Expr) (string, bool)) (string, bool) {
	if e.Name == "join" {
		l, ok := e.X.(jinja.List)
		if !ok {
			return "", false
		}
		sep := ""
		if len(e.Args) > 0 {
			var sok bool
			if sep, sok = f(e.Args[0]); !sok {
				return "", false
			}
		}
		parts := make([]string, len(l.Items))
		for i, x := range l.Items {
			var pok bool
			if parts[i], pok = f(x); !pok {
				return "", false
			}
		}
		return strings.Join(parts, sep), true
	}
	v, ok := f(e.X)
	if !ok {
		return "", false
	}
	args := make([]string, len(e.Args))
	for i, x := range e.Args {
		if args[i], ok = f(x); !ok {
			return "", false
		}
	}
	switch e.Name {
	case "reverse":
		return reverse(v), true
	case "upper":
		return strings.ToUpper(v), true
	case "lower":
		return strings.ToLower(v), true
	case "trim":
		return strings.TrimSpace(v), true
	case "string", "safe", "e", "escape":
		return v, true
	case "title":
		return title(v), true
	case "capitalize":
		if v == "" {
			return v, true
		}
		r, n := utf8.DecodeRuneInString(v)
		return string(unicode.ToUpper(r)) + strings.ToLower(v[n:]), true
	case "replace":
		if len(args) >= 2 && replacedLen(v, args[0], args[1]) <= maxFold {
			return strings.ReplaceAll(v, args[0], args[1]), true
		}
	case "format":
		return printf(v, args)
	}
	return "", false
}

// replacedLen is the length strings.ReplaceAll would produce, computed before
// building it so a replace bomb never allocates.
func replacedLen(s, old, repl string) int {
	if old == "" {
		return len(s) + (len(s)+1)*len(repl)
	}
	n := strings.Count(s, old)
	return len(s) + n*(len(repl)-len(old))
}

func strMethod(recv, name string, args []string) (string, bool) {
	switch name {
	case "upper":
		return strings.ToUpper(recv), true
	case "lower":
		return strings.ToLower(recv), true
	case "strip":
		if len(args) == 1 {
			return strings.Trim(recv, args[0]), true
		}
		return strings.TrimSpace(recv), true
	case "replace":
		if len(args) >= 2 && replacedLen(recv, args[0], args[1]) <= maxFold {
			return strings.ReplaceAll(recv, args[0], args[1]), true
		}
	case "format":
		out := recv
		for _, a := range args {
			out = strings.Replace(out, "{}", a, 1)
		}
		return out, true
	}
	return "", false
}

// printf implements the %s, %d, %c, and %% of Jinja's format filter.
func printf(f string, args []string) (string, bool) {
	var b strings.Builder
	ai := 0
	for i := 0; i < len(f); i++ {
		if f[i] != '%' || i+1 >= len(f) {
			b.WriteByte(f[i])
			continue
		}
		i++
		switch f[i] {
		case '%':
			b.WriteByte('%')
			continue
		case 's', 'd':
		case 'c':
			if ai < len(args) {
				n, err := strconv.Atoi(args[ai])
				if err != nil {
					return "", false
				}
				b.WriteRune(rune(n))
				ai++
			}
			continue
		default:
			return "", false
		}
		if ai >= len(args) {
			return "", false
		}
		b.WriteString(args[ai])
		ai++
	}
	return b.String(), true
}

func slice(v string, e jinja.Slice, f func(jinja.Expr) (string, bool)) (string, bool) {
	r := []rune(v)
	idx := func(x jinja.Expr, def int) (int, bool) {
		if x == nil {
			return def, true
		}
		if u, ok := x.(jinja.Unary); ok && u.Op == "-" {
			s, ok := f(u.X)
			n, err := strconv.Atoi(s)
			return -n, ok && err == nil
		}
		s, ok := f(x)
		n, err := strconv.Atoi(s)
		return n, ok && err == nil
	}
	step, ok := idx(e.Step, 1)
	if !ok || step == 0 {
		return "", false
	}
	if step == -1 && e.Lo == nil && e.Hi == nil {
		return reverse(v), true
	}
	lo, ok1 := idx(e.Lo, 0)
	hi, ok2 := idx(e.Hi, len(r))
	if !ok1 || !ok2 || step != 1 {
		return "", false
	}
	if lo < 0 {
		lo += len(r)
	}
	if hi < 0 {
		hi += len(r)
	}
	lo, hi = max(0, min(lo, len(r))), max(0, min(hi, len(r)))
	if lo > hi {
		return "", true
	}
	return string(r[lo:hi]), true
}

func reverse(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

func isNumber(s string) bool {
	_, err := strconv.ParseFloat(s, 64)
	return err == nil
}

func hasLetters(s string) bool {
	n := 0
	for _, r := range s {
		if unicode.IsLetter(r) {
			n++
		}
	}
	return n >= 3
}

// splitsWord reports a concatenation that cuts through the middle of a word,
// as in 'Ign' ~ 'ore previous instructions'.
func splitsWord(l, r string) bool {
	lr, _ := utf8.DecodeLastRuneInString(l)
	rr, _ := utf8.DecodeRuneInString(r)
	if !unicode.IsLetter(lr) || !unicode.IsLetter(rr) {
		return false
	}
	return hasLetters(l+r) && len(strings.Fields(l+r)) >= 2
}

// hiddenRune finds a zero-width, invisible, or bidirectional control
// character: the characters Trojan Source and zero-width evasion use.
func hiddenRune(s string) (rune, bool) {
	for _, r := range s {
		switch {
		case r >= 0x200B && r <= 0x200F, r >= 0x202A && r <= 0x202E,
			r >= 0x2060 && r <= 0x2064, r >= 0x2066 && r <= 0x2069,
			r == 0xFEFF, r == 0x00AD, r == 0x180E:
			return r, true
		}
	}
	return 0, false
}

// normalize removes invisible characters and maps fullwidth ASCII and common
// Cyrillic and Greek lookalikes to Latin, so a lead phrase matches however it
// was disguised.
func normalize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if _, hidden := hiddenRune(string(r)); hidden {
			continue
		}
		if r >= 0xFF01 && r <= 0xFF5E {
			r -= 0xFEE0
		}
		if l, ok := confusable[r]; ok {
			r = l
		}
		b.WriteRune(r)
	}
	return b.String()
}

var confusable = map[rune]rune{
	'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j',
	'ѕ': 's', 'ԁ': 'd', 'ɡ': 'g', 'һ': 'h', 'ӏ': 'l', 'ո': 'n', 'ν': 'v', 'ο': 'o', 'ρ': 'p',
	'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O', 'Р': 'P', 'С': 'C',
	'Т': 'T', 'Х': 'X', 'І': 'I', 'Ј': 'J', 'Ѕ': 'S', 'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ι': 'I',
	'Κ': 'K', 'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Χ': 'X', 'Υ': 'Y', 'Ζ': 'Z',
}

// mixedScriptWord returns a word that mixes Latin letters with lookalikes
// from Cyrillic or Greek. A template written in Russian is fine; one word
// spelled with both alphabets is a disguise.
func mixedScriptWord(s string) string {
	for _, w := range strings.FieldsFunc(s, func(r rune) bool { return !unicode.IsLetter(r) }) {
		latin, other := false, false
		for _, r := range w {
			switch {
			case unicode.Is(unicode.Latin, r):
				latin = true
			case unicode.Is(unicode.Cyrillic, r), unicode.Is(unicode.Greek, r):
				other = true
			}
		}
		if latin && other {
			return w
		}
	}
	return ""
}

func excerptS(s string) string { return excerpt(s, 0, len(s)) }

// title upper-cases the first letter of each word and lower-cases the rest,
// as Jinja's title filter does.
func title(s string) string {
	var b strings.Builder
	prev := ' '
	for _, r := range s {
		if unicode.IsLetter(r) && !unicode.IsLetter(prev) && !unicode.IsDigit(prev) {
			b.WriteRune(unicode.ToUpper(r))
		} else {
			b.WriteRune(unicode.ToLower(r))
		}
		prev = r
	}
	return b.String()
}
