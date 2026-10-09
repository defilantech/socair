package chattemplate

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/checks/chattemplate/jinja"
)

// ProbeSet names the fixed probe conversations a template is rendered on.
// Change it whenever a probe changes, so a note says which ones ran.
const ProbeSet = "probes/v1"

// Options are what the check reads beyond the templates.
type Options struct {
	// Reviewed are reviewed template hashes from a verified feed, each with
	// its label (repo and revision, by convention; may be ""). Like the
	// embedded allowlist, they clear language leads, never code.
	Reviewed map[string]string
	// References are reviewed templates with their text. A template is
	// rendered beside each and compared on every probe.
	References []Reference
	// Tokens are the artifact's special tokens.
	Tokens Tokens
}

// Reference is a reviewed template and its label.
type Reference struct {
	Label string
	Text  string
}

// Tokens are an artifact's special tokens, as a render needs them.
type Tokens struct {
	// Named are the special-token variables a serving stack passes a
	// template (bos_token, eos_token, ...), by variable name.
	Named map[string]string
	// Markers are the text of every special or added token. A template
	// writes them as structure, so they are never counted as added text.
	Markers []string
}

// The probe conversations' content. Every string a probe passes is input to
// the render, so its bytes are attributed to the conversation wherever the
// template moves them; the sentinels make that readable in a note.
const (
	probeSystem    = "SOCAIR_PROBE_SYSTEM"
	probeUser1     = "SOCAIR_PROBE_USER_1"
	probeUser2     = "SOCAIR_PROBE_USER_2"
	probeAssistant = "SOCAIR_PROBE_ASSISTANT"
	probeToolDesc  = "SOCAIR_PROBE_TOOL_DESCRIPTION"
	probeToolParam = "SOCAIR_PROBE_TOOL_PARAMETER"
	probeToolArg   = "SOCAIR_PROBE_TOOL_ARGUMENT"
	probeToolOut   = "SOCAIR_PROBE_TOOL_RESULT"
	probeToolName  = "socair_probe_tool"
)

// probe is one conversation a template is rendered on.
type probe struct {
	name      string
	messages  []any
	tools     bool
	genPrompt bool
	// guard is set on a trigger probe: every message's content is this
	// literal, which a content condition in the template tests.
	guard string
}

func msg(role, content string) jinja.Map { return jinja.M("role", role, "content", content) }

func probeTool() jinja.Map {
	return jinja.M("type", "function", "function", jinja.M(
		"name", probeToolName,
		"description", probeToolDesc,
		"parameters", jinja.M("type", "object",
			"properties", jinja.M("query", jinja.M("type", "string", "description", probeToolParam)),
			"required", []any{"query"})))
}

// multiTurn is the conversation a trigger probe is compared against.
func multiTurn(content func(string) string) []any {
	return []any{msg("system", content(probeSystem)), msg("user", content(probeUser1)),
		msg("assistant", content(probeAssistant)), msg("user", content(probeUser2))}
}

// probes are the standard conversations, with the tool conversations when
// the template mentions tools, and a trigger probe per content guard.
func probes(template string, guards []string) []probe {
	same := func(s string) string { return s }
	ps := []probe{
		{name: "system and user", messages: []any{msg("system", probeSystem), msg("user", probeUser1)}, genPrompt: true},
		{name: "user only", messages: []any{msg("user", probeUser1)}, genPrompt: true},
		{name: "multi-turn", messages: multiTurn(same), genPrompt: true},
		{name: "assistant turn, no generation prompt", messages: []any{msg("user", probeUser1), msg("assistant", probeAssistant)}},
	}
	if strings.Contains(template, "tool") {
		call := jinja.M("role", "assistant", "content", "", "tool_calls", []any{jinja.M("type", "function", "id", "call_1",
			"function", jinja.M("name", probeToolName, "arguments", jinja.M("query", probeToolArg)))})
		result := jinja.M("role", "tool", "tool_call_id", "call_1", "name", probeToolName, "content", probeToolOut)
		ps = append(ps,
			probe{name: "tools offered", messages: []any{msg("user", probeUser1)}, tools: true, genPrompt: true},
			probe{name: "tool call and result", messages: []any{msg("system", probeSystem), msg("user", probeUser1), call, result},
				tools: true, genPrompt: true})
	}
	for _, g := range guards {
		ps = append(ps, probe{name: "trigger " + g, messages: multiTurn(func(string) string { return g }), genPrompt: true, guard: g})
	}
	return ps
}

func (p probe) vars(t Tokens) map[string]any {
	v := map[string]any{"messages": p.messages, "add_generation_prompt": p.genPrompt, "tools": nil, "documents": nil}
	if p.tools {
		v["tools"] = []any{probeTool()}
	}
	for k, s := range t.Named {
		v[k] = s
	}
	return v
}

// outcome is one probe's render: its pieces, or why it did not render.
type outcome struct {
	pieces []jinja.Piece
	err    error
}

func (o outcome) text() string {
	if o.err != nil {
		return "\x00error: " + o.err.Error()
	}
	var b strings.Builder
	for _, p := range o.pieces {
		b.WriteString(p.Text)
	}
	return b.String()
}

// renderAll renders a template on every probe. A construct the evaluator
// does not model, or a passed bound, stops it: a partial render is never
// compared. A probe the template refuses (raise_exception) or fails on is
// kept as that outcome.
func renderAll(nodes []jinja.Node, ps []probe, t Tokens) ([]outcome, error) {
	out := make([]outcome, len(ps))
	for i, p := range ps {
		pieces, err := jinja.Render(nodes, p.vars(t), jinja.DefaultLimits)
		var unsupported *jinja.UnsupportedError
		var bound *jinja.LimitError
		if errors.As(err, &unsupported) || errors.As(err, &bound) {
			return nil, err
		}
		out[i] = outcome{pieces: pieces, err: err}
	}
	return out, nil
}

// fragment is one distinct piece of added text and how many standard probes
// it appeared in.
type fragment struct {
	text   string
	probes int
}

// triggerDelta is the text a content condition adds: what the template
// emits under a trigger probe and not under the conversation it varies.
type triggerDelta struct {
	guard string
	adds  []string
}

// renderResult is what rendering found, for the row's notes and findings.
type renderResult struct {
	skipped  string // why the template was not rendered; "" when it was
	rendered int    // probes rendered
	refused  []string
	added    []fragment
	triggers []triggerDelta
	compared string // the comparison with reviewed templates, as a note
	findings []checks.Finding
}

// renderCheck renders a parsed template on the probe conversations,
// inventories the text it adds, concretizes what each content condition
// adds, and compares it with the reviewed templates.
func renderCheck(template string, nodes []jinja.Node, an analysis, o Options) renderResult {
	var res renderResult
	ps := probes(template, an.guards)
	outs, err := renderAll(nodes, ps, o.Tokens)
	if err != nil {
		res.skipped = err.Error()
		return res
	}
	markers := markerSet(template, o.Tokens)
	baseline := -1
	counts := map[string]int{}
	var order []string
	for i, p := range ps {
		oc := outs[i]
		if oc.err != nil {
			res.refused = append(res.refused, fmt.Sprintf("%s (%s)", p.name, oc.err))
			continue
		}
		if p.guard != "" {
			continue
		}
		res.rendered++
		if p.name == "multi-turn" {
			baseline = i
		}
		seen := map[string]bool{}
		for _, f := range addedText(oc.pieces, markers) {
			if seen[f] {
				continue
			}
			seen[f] = true
			if counts[f] == 0 {
				order = append(order, f)
			}
			counts[f]++
		}
	}
	if res.rendered == 0 {
		res.skipped = "the template refused every probe conversation: " + strings.Join(res.refused, "; ")
		return res
	}
	for _, f := range order {
		res.added = append(res.added, fragment{text: f, probes: counts[f]})
	}
	// Prose first: an instruction is what a reviewer needs to see.
	sort.SliceStable(res.added, func(i, j int) bool {
		return prose.MatchString(res.added[i].text) && !prose.MatchString(res.added[j].text)
	})

	if baseline >= 0 {
		for i, p := range ps {
			if p.guard == "" || outs[i].err != nil {
				continue
			}
			adds := distinct(delta(addedText(outs[i].pieces, markers), addedText(outs[baseline].pieces, markers)))
			if len(adds) > 0 {
				res.triggers = append(res.triggers, triggerDelta{guard: p.guard, adds: adds})
			}
			// Only a system turn the condition opens is a LEAD: the Pillar
			// shape, which also covers a condition that promotes the
			// message itself to a system turn. Text a condition adds inside
			// a turn is listed, not judged: SmolLM3 swaps its default system
			// prompt on /think and /no_think (docs/false-positive-baseline.md).
			if systemTurns(outs[i].pieces) > systemTurns(outs[baseline].pieces) {
				res.findings = append(res.findings, checks.Finding{Pattern: "content-conditional-injection",
					Span:   excerptS(fmt.Sprintf("%q adds a system turn %q", p.guard, strings.Join(adds, " "))),
					Detail: "a message containing a condition's literal makes the rendered prompt gain a system turn"})
			}
		}
	}
	res.compared = compare(template, ps, outs, o, &res)
	return res
}

// compare states how the template relates to the reviewed templates: byte
// for byte, render for render, a near-miss that adds a content-conditional
// branch (a LEAD, with the diff), or none of them (no verdict).
func compare(template string, ps []probe, outs []outcome, o Options, res *renderResult) string {
	h := templateHash(template)
	if label, ok := reviewed(h, o); ok {
		return "Byte-identical to the reviewed template " + labelOr(label, h) + "."
	}
	if len(o.References) == 0 {
		return "No reviewed template text was available, so it was not compared."
	}
	var near, partial []string
	unreadable := 0
	for _, ref := range o.References {
		rh := templateHash(ref.Text)
		label := labelOr(ref.Label, rh)
		if rh == h {
			return "Byte-identical to the reviewed template " + label + "."
		}
		rnodes, err := jinja.Parse(ref.Text)
		if err != nil {
			unreadable++
			continue
		}
		rguards := analyse(rnodes).guards
		routs, err := renderAll(rnodes, ps, o.Tokens)
		if err != nil {
			unreadable++
			continue
		}
		standard, added := true, ""
		var shared []string
		for i, p := range ps {
			a, b := outs[i].text(), routs[i].text()
			if a == b {
				continue
			}
			switch {
			case p.guard == "":
				standard = false
			case contains(rguards, p.guard):
				shared = append(shared, p.guard)
			case added == "":
				added = fmt.Sprintf("when a message contains %q, %s", p.guard, firstDiff(b, a))
			}
			if !standard {
				break
			}
		}
		switch {
		case !standard:
		case added != "":
			near = append(near, label)
			res.findings = append(res.findings, checks.Finding{Pattern: "reviewed-template-mismatch", Span: excerptLong(added),
				Detail: "renders like the reviewed template " + label + " on every standard probe, but adds a content-conditional branch"})
		case len(shared) > 0:
			partial = append(partial, fmt.Sprintf("%s, except when a message contains %q, a condition both templates test", label, shared[0]))
		default:
			return fmt.Sprintf("Renders identically to the reviewed template %s on all %d probe conversations.", label, len(ps))
		}
	}
	switch {
	case len(near) > 0:
		return "Renders like the reviewed template " + near[0] + " on every standard probe but differs under a content condition it adds; needs review."
	case len(partial) > 0:
		return "Renders like the reviewed template " + partial[0] + "."
	}
	note := fmt.Sprintf("Matches none of the %d reviewed template(s) with text, byte for byte or on every probe, so it was not compared further.", len(o.References))
	if unreadable > 0 {
		note += fmt.Sprintf(" %d reviewed template(s) could not be rendered.", unreadable)
	}
	return note
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func labelOr(label, hash string) string {
	if strings.TrimSpace(label) != "" {
		return label
	}
	return hash[:16]
}

// firstDiff describes the first difference between the reviewed template's
// render (want) and this one's (got): text this one inserts, text it drops,
// or, failing both, what each renders from that point.
func firstDiff(want, got string) string {
	const errMark = "\x00error: "
	switch {
	case strings.HasPrefix(got, errMark):
		return "this template refuses the conversation (" + strings.TrimPrefix(got, errMark) + ") and the reviewed one renders it"
	case strings.HasPrefix(want, errMark):
		return "this template renders a conversation the reviewed one refuses"
	}
	p := 0
	for p < len(want) && p < len(got) && want[p] == got[p] {
		p++
	}
	for p > 0 && ((p < len(got) && !utf8RuneStart(got[p])) || (p < len(want) && !utf8RuneStart(want[p]))) {
		p--
	}
	if k := inserted(want[p:], got[p:]); k > 0 {
		return fmt.Sprintf("this template adds %q, which the reviewed template does not render", excerptS(got[p:p+k]))
	}
	if k := inserted(got[p:], want[p:]); k > 0 {
		return fmt.Sprintf("this template drops %q, which the reviewed template renders", excerptS(want[p:p+k]))
	}
	return fmt.Sprintf("this template renders %q where the reviewed template renders %q", excerptS(got[p:]), excerptS(want[p:]))
}

// inserted is the length of the run at the start of b that, removed, lines
// b up with a again; 0 when no run up to a few kilobytes does.
func inserted(a, b string) int {
	const window = 32
	n := min(window, len(a))
	for k := 1; k <= len(b) && k <= 4096; k++ {
		rest := b[k:]
		if strings.HasPrefix(rest, a[:n]) && (n == window || rest == a) {
			return k
		}
	}
	return 0
}

func excerptLong(s string) string {
	if len(s) <= 240 {
		return s
	}
	cut := 240
	for cut > 0 && !utf8RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}

// delta is the fragments of got that want lacks, counting repeats.
func delta(got, want []string) []string {
	have := map[string]int{}
	for _, w := range want {
		have[w]++
	}
	var out []string
	for _, g := range got {
		if have[g] > 0 {
			have[g]--
			continue
		}
		out = append(out, g)
	}
	return out
}

// systemTurns counts the system turns the template's own text opens in a
// render. Input is left out, so a probe message that quotes a system marker
// is not counted.
func systemTurns(pieces []jinja.Piece) int {
	var b strings.Builder
	for _, p := range pieces {
		if p.Input {
			b.WriteString("\x00")
			continue
		}
		b.WriteString(p.Text)
	}
	return len(systemTurn.FindAllStringIndex(normalize(b.String()), -1))
}

// distinct keeps the first of each repeated string.
func distinct(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

// roleWords are the labels templates write for a turn's role. A fragment
// that is only one of them is structure, like a special token.
var roleWords = map[string]bool{"system": true, "user": true, "assistant": true, "tool": true, "tools": true,
	"ipython": true, "model": true, "human": true, "developer": true, "function": true, "bot": true}

// tokenLike is text written like a special token. It is taken as one only
// when the artifact supplies no token list (a template inspected on its
// own).
var tokenLike = regexp.MustCompile(`<[|｜][^<>\s]{0,60}?[|｜]>|<[A-Za-z_/][^<>\s]{0,40}>|\[/?[A-Z][A-Z_]{1,30}\]`)

// markerSet is the special-token text that can appear in this template's
// output: the declared tokens it writes, and, with no token list, what is
// written like one.
func markerSet(template string, t Tokens) *regexp.Regexp {
	var ms []string
	for _, m := range t.Markers {
		if m != "" && strings.Contains(template, m) {
			ms = append(ms, m)
		}
	}
	for _, v := range t.Named {
		if v != "" && strings.Contains(template, v) {
			ms = append(ms, v)
		}
	}
	sort.Slice(ms, func(i, j int) bool { return len(ms[i]) > len(ms[j]) })
	for i, m := range ms {
		ms[i] = regexp.QuoteMeta(m)
	}
	if len(t.Markers) == 0 {
		ms = append(ms, tokenLike.String())
	}
	if len(ms) == 0 {
		return nil
	}
	return regexp.MustCompile(strings.Join(ms, "|"))
}

// addedText is the template's own text in a render, split at input and at
// special tokens, with structure removed: whitespace, punctuation, and bare
// role names. What is left is text the template adds to the prompt.
func addedText(pieces []jinja.Piece, markers *regexp.Regexp) []string {
	var out []string
	for _, p := range pieces {
		if p.Input {
			continue
		}
		segs := []string{p.Text}
		if markers != nil {
			segs = markers.Split(p.Text, -1)
		}
		for _, s := range segs {
			s = stripRoles(strings.TrimSpace(s))
			if !hasLetter(s) {
				continue
			}
			out = append(out, s)
		}
	}
	return out
}

// roleLabel is a role name written as a turn's label: alone, or ended by a
// colon or a line break ("system\n", "Human: ").
var (
	leadingRole  = regexp.MustCompile(`^(?i:(\w+)):?(\s*\n|:\s*|$)`)
	trailingRole = regexp.MustCompile(`(^|\n)\s*(?i:(\w+)):?$`)
)

// stripRoles removes role labels from the ends of a fragment.
func stripRoles(s string) string {
	for {
		m := leadingRole.FindStringSubmatchIndex(s)
		if m == nil || !roleWords[strings.ToLower(s[m[2]:m[3]])] {
			break
		}
		s = strings.TrimSpace(s[m[1]:])
	}
	for {
		m := trailingRole.FindStringSubmatchIndex(s)
		if m == nil || !roleWords[strings.ToLower(s[m[4]:m[5]])] {
			break
		}
		s = strings.TrimSpace(s[:m[0]])
	}
	return s
}

func hasLetter(s string) bool {
	for _, r := range s {
		if unicode.IsLetter(r) {
			return true
		}
	}
	return false
}

// Bounds on what the notes quote, so a template that adds a book does not
// fill the report.
const (
	maxFragments  = 6
	maxFragment   = 120
	maxTriggerAdd = 3
)

func quote(s string) string {
	if len(s) > maxFragment {
		cut := maxFragment
		for cut > 0 && !utf8RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut] + "..."
	}
	return fmt.Sprintf("%q", s)
}

func utf8RuneStart(b byte) bool { return b&0xC0 != 0x80 }

// semantics says what the render modelled, so a reader knows which engine's
// behaviour the notes describe.
const semantics = "Socair's own Jinja evaluator, modelling transformers' sandbox settings"

// note is the render's sentence for the row.
func (res renderResult) note() string {
	if res.skipped != "" {
		return "Not rendered: " + res.skipped + "."
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Rendered on %d %s probe conversation(s) with %s.", res.rendered, ProbeSet, semantics)
	if len(res.added) == 0 {
		b.WriteString(" It adds no text of its own beyond special tokens and role names.")
	} else {
		b.WriteString(" This template adds to the prompt: ")
		for i, f := range res.added {
			if i == maxFragments {
				fmt.Fprintf(&b, "; and %d more", len(res.added)-maxFragments)
				break
			}
			if i > 0 {
				b.WriteString("; ")
			}
			fmt.Fprintf(&b, "%s (%d of %d)", quote(f.text), f.probes, res.rendered)
		}
		b.WriteString(". Listed for review, not judged.")
	}
	for _, d := range res.triggers {
		var adds []string
		for i, a := range d.adds {
			if i == maxTriggerAdd {
				adds = append(adds, fmt.Sprintf("and %d more", len(d.adds)-maxTriggerAdd))
				break
			}
			adds = append(adds, quote(a))
		}
		fmt.Fprintf(&b, " When a message contains %s, the template adds: %s.", quote(d.guard), strings.Join(adds, ", "))
	}
	if len(res.refused) > 0 {
		fmt.Fprintf(&b, " It refused %d probe(s): %s.", len(res.refused), excerptLong(strings.Join(res.refused, "; ")))
	}
	if res.compared != "" {
		b.WriteString(" " + res.compared)
	}
	return b.String()
}
