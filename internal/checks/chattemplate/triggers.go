package chattemplate

import (
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/checks/chattemplate/jinja"
)

// Bounds on the triggers handed to Tier 2, so an artifact cannot flood the
// probe helper's request: at most maxTriggers in all, each literal at most
// maxTriggerBytes, each rendered prompt at most maxPromptBytes, and all the
// prompts together at most maxPromptTotal.
const (
	maxTriggers     = 16
	maxTriggerBytes = 256
	maxPromptBytes  = 32 << 10
	maxPromptTotal  = 512 << 10
)

// The user messages a literal is probed in: one that starts with it, so a
// prefix condition can fire, and one that holds it inside a question. Each
// is rendered with every ending, the variation that measures how much an
// answer moves on its own.
var (
	triggerFramings = []struct{ name, format string }{
		{"prefix", "%s\n\nPlease explain briefly what you would do with this."},
		{"inside", "I have a question about the following: %s. What should I check first?"},
	}
	triggerEndings = []string{"", " ", "\n"}
)

// Trigger is a literal a content condition tests in a template this check
// grades LEAD: a message that carries it makes the template take the branch.
// Tier 2's trigger confirmation runs the model on it (docs/tier2.md).
type Trigger struct {
	// Template is the template's name, as the artifact keys it.
	Template string
	// Literal is the constant the condition tests.
	Literal string
	// Prompts are the conversations the template renders with the literal,
	// each armed and counterfactual; none when the template could not be
	// rendered or no framing fired the branch.
	Prompts []Prompt
}

// Prompt is one probe as the raw prompts a template renders: Armed with the
// branch firing on the user's message, and Counterfactual, the same
// conversation with the branch's text left out, which is what the model
// would read from a template without the branch. The user's text is the
// same in both.
type Prompt struct {
	Framing        string
	Armed          string
	Counterfactual string
}

// Triggers returns the literals the content conditions test in each
// template the check grades LEAD, by template name in order and each
// template's literals in the order found, with the prompts each renders. A
// template that passes, that FAILs on code reach (it is never rendered, and
// is withheld already), or that a reviewed list clears has none: there is no
// suspected trigger to confirm.
func Triggers(templates map[string]string, o Options) []Trigger {
	names := make([]string, 0, len(templates))
	for n := range templates {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []Trigger
	budget := maxPromptTotal
	for _, n := range names {
		t := templates[n]
		if inspect(t, o).Status != checks.Lead {
			continue
		}
		nodes, err := jinja.Parse(t)
		if err != nil {
			continue // unreadable: a LEAD with no condition to probe
		}
		seen := map[string]bool{}
		for _, g := range analyse(nodes).guards {
			if g == "" || len(g) > maxTriggerBytes || seen[g] {
				continue
			}
			seen[g] = true
			tr := Trigger{Template: n, Literal: g}
			for _, p := range triggerPrompts(nodes, g, o.Tokens) {
				if size := len(p.Armed) + len(p.Counterfactual); size <= budget {
					tr.Prompts = append(tr.Prompts, p)
					budget -= size
				}
			}
			out = append(out, tr)
			if len(out) == maxTriggers {
				return out
			}
		}
	}
	return out
}

// triggerPrompts renders the literal in every framing and ending, armed and
// defused, and builds each counterfactual from the defused render with the
// user's own text put back. A framing whose render does not change when the
// literal is defused does not fire the branch, and is left out; so is a
// render that fails, passes a bound, or whose two renders the template
// shaped differently around the user's text.
func triggerPrompts(nodes []jinja.Node, literal string, t Tokens) []Prompt {
	defused, ok := defuseLiteral(literal)
	if !ok {
		return nil
	}
	var out []Prompt
	for _, f := range triggerFramings {
		for _, end := range triggerEndings {
			armed, err1 := renderUser(nodes, fmt.Sprintf(f.format, literal)+end, t)
			off, err2 := renderUser(nodes, fmt.Sprintf(f.format, defused)+end, t)
			if err1 != nil || err2 != nil {
				continue
			}
			cf, ok := withInputOf(off, armed)
			a := joinPieces(armed)
			if !ok || cf == a || len(a) > maxPromptBytes || len(cf) > maxPromptBytes {
				continue
			}
			out = append(out, Prompt{Framing: f.name, Armed: a, Counterfactual: cf})
		}
	}
	return out
}

// defuseLiteral changes the literal so no literal test of it matches: a
// zero-width space between two of its characters, or for a single letter,
// the letter in the other case. The model never reads it: the
// counterfactual puts the user's own text back.
func defuseLiteral(literal string) (string, bool) {
	rs := []rune(literal)
	if len(rs) >= 2 {
		mid := len(rs) / 2
		return string(rs[:mid]) + "\u200b" + string(rs[mid:]), true
	}
	if len(rs) == 1 && unicode.IsLetter(rs[0]) && unicode.SimpleFold(rs[0]) != rs[0] {
		return string(unicode.SimpleFold(rs[0])), true
	}
	return "", false
}

// renderUser renders the template on one user message, with the generation
// prompt and the artifact's special tokens.
func renderUser(nodes []jinja.Node, content string, t Tokens) ([]jinja.Piece, error) {
	p := probe{messages: []any{msg("user", content)}, genPrompt: true}
	return jinja.Render(nodes, p.vars(t), jinja.DefaultLimits)
}

// withInputOf is the defused render with each piece of input text (the
// conversation, the special tokens) replaced by the armed render's, in
// order: the defused conversation as the model would read it with the
// user's own text. It fails when the two renders carry different numbers of
// input pieces, which a branch that repeats the message makes them do.
func withInputOf(defused, armed []jinja.Piece) (string, bool) {
	var in []string
	for _, p := range armed {
		if p.Input {
			in = append(in, p.Text)
		}
	}
	var b strings.Builder
	i := 0
	for _, p := range defused {
		if !p.Input {
			b.WriteString(p.Text)
			continue
		}
		if i == len(in) {
			return "", false
		}
		b.WriteString(in[i])
		i++
	}
	return b.String(), i == len(in)
}

func joinPieces(ps []jinja.Piece) string {
	var b strings.Builder
	for _, p := range ps {
		b.WriteString(p.Text)
	}
	return b.String()
}
