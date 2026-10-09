// Package jinja parses the Jinja subset that chat templates use into a syntax
// tree, for static analysis, and evaluates that tree (Render) on given
// variables. The evaluator is Socair's own: values are Go values with no
// Python object model behind them, a dunder name is refused, and every
// render is bounded. A construct it does not model stops the render with an
// *UnsupportedError; nothing is ever handed to another Jinja engine.
//
// The subset covers what Hugging Face and llama.cpp chat templates use: text,
// output, comments, raw blocks, if/elif/else, for (with else, a filter
// condition, and unpacking), set (expression and block form), macro, call,
// filter blocks, generation, break, continue, and do. Anything else is a parse
// error, so an unsupported construct is reported, never silently skipped.
package jinja

// Node is a template statement or a run of text.
type Node interface{ node() }

// Expr is a template expression.
type Expr interface{ expr() }

// Text is literal template text. S is the text as written, which the static
// analysis reads. Out is what a render emits: S after whitespace control
// ({%- -%}) and the settings Hugging Face renders with (trim_blocks and
// lstrip_blocks on, newlines normalized, no trailing newline).
type Text struct{ S, Out string }

// Output is an {{ expression }}.
type Output struct{ X Expr }

// If is if/elif/else. Each branch is a condition and a body.
type If struct {
	Branches []Branch
	Else     []Node
}

// Branch is one if or elif arm.
type Branch struct {
	Cond Expr
	Body []Node
}

// For is a for loop.
type For struct {
	Targets []string
	Iter    Expr
	Filter  Expr // the optional "if" condition, nil when absent
	Body    []Node
	Else    []Node
}

// Set assigns an expression, or with Body set, a captured block. Filter is a
// captured block's filter chain ({% set x | trim %}), applied to a Name with
// an empty N; nil when absent.
type Set struct {
	Targets []Expr
	X       Expr
	Body    []Node
	Filter  Expr
}

// Macro defines a macro.
type Macro struct {
	Name     string
	Params   []string
	Defaults []Expr
	Body     []Node
}

// CallBlock is {% call %}.
type CallBlock struct {
	Call Expr
	Body []Node
}

// FilterBlock is {% filter %}.
type FilterBlock struct {
	Filter Expr
	Body   []Node
}

// Generation is Hugging Face's {% generation %} block.
type Generation struct{ Body []Node }

// Do evaluates an expression for its side effect.
type Do struct{ X Expr }

// Break and Continue are loop controls.
type Break struct{}
type Continue struct{}

func (Text) node()        {}
func (Output) node()      {}
func (If) node()          {}
func (For) node()         {}
func (Set) node()         {}
func (Macro) node()       {}
func (CallBlock) node()   {}
func (FilterBlock) node() {}
func (Generation) node()  {}
func (Do) node()          {}
func (Break) node()       {}
func (Continue) node()    {}

// Str is a string literal, escapes already decoded.
type Str struct{ V string }

// Num is a numeric literal, kept as written.
type Num struct{ V string }

// Const is true, false, or none.
type Const struct{ V string }

// Name is a variable reference.
type Name struct{ N string }

// Attr is x.name.
type Attr struct {
	X    Expr
	Name string
}

// Index is x[i].
type Index struct{ X, I Expr }

// Slice is x[lo:hi:step]; absent parts are nil.
type Slice struct{ X, Lo, Hi, Step Expr }

// Call is f(args, k=v).
type Call struct {
	F    Expr
	Args []Expr
	Kw   []Kw
}

// Kw is a keyword argument.
type Kw struct {
	Name string
	X    Expr
}

// Filter is x|name(args).
type Filter struct {
	X    Expr
	Name string
	Args []Expr
	Kw   []Kw
}

// Test is x is [not] name(args).
type Test struct {
	X    Expr
	Name string
	Args []Expr
	Not  bool
}

// Bin is a binary operator: arithmetic, ~, comparison, in, not in, and, or.
type Bin struct {
	Op   string
	L, R Expr
}

// Unary is not, unary minus, or unary plus.
type Unary struct {
	Op string
	X  Expr
}

// Cond is a if c else b.
type Cond struct{ Then, If, Else Expr }

// List, Tuple, and Dict are container literals.
type List struct{ Items []Expr }
type Tuple struct{ Items []Expr }
type Dict struct{ Keys, Vals []Expr }

func (Str) expr()    {}
func (Num) expr()    {}
func (Const) expr()  {}
func (Name) expr()   {}
func (Attr) expr()   {}
func (Index) expr()  {}
func (Slice) expr()  {}
func (Call) expr()   {}
func (Filter) expr() {}
func (Test) expr()   {}
func (Bin) expr()    {}
func (Unary) expr()  {}
func (Cond) expr()   {}
func (List) expr()   {}
func (Tuple) expr()  {}
func (Dict) expr()   {}
