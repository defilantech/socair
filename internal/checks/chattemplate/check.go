// Package chattemplate inspects a GGUF chat template for dangerous content.
// This is the hero check.
//
// Three classes of signal, in this order of precedence:
//
//   - Structural code-execution indicators (object escape, process exec) are
//     positive evidence and return FAIL. This runs first and the allowlist
//     cannot override it: the allowlist clears language, never code.
//   - A template whose SHA256 is on the reviewed allowlist returns PASS.
//   - Instruction-language phrases are a LEAD, never a FAIL and never a gap an
//     acceptance can clear: it needs a person's review. The patterns are
//     narrow: they require concealment of something sensitive, because a
//     corpus sweep proved that ordinary templates contain bare "do not tell"
//     and that a loose "requests" pattern matches inside PULL_REQUESTS.
//
// A template with no code reach is then rendered on fixed probe conversations
// by Socair's own evaluator (render.go). The text it adds to the prompt is
// listed, never judged. Two rendered signals are LEADs: a content condition
// that opens a system turn, and a template that renders like a reviewed one on
// every standard probe but adds a content-conditional branch.
//
// Disciplined this way, a clean result is still not a proof of absence.
package chattemplate

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/checks/chattemplate/jinja"
)

type pattern struct {
	name   string
	re     *regexp.Regexp
	detail string
}

// lead patterns are a signal for a person to review, never a FAIL. They require
// concealment of something sensitive, or a real code call, not a bare phrase.
var leads = []pattern{
	{
		name:   "instruction-override",
		re:     regexp.MustCompile(`(?i)(ignore|disregard)\s+(all\s+)?(previous|prior|above)\b`),
		detail: "instruction language that overrides earlier content",
	},
	{
		name: "secrecy-instruction",
		re: regexp.MustCompile(`(?i)do\s+not\s+(reveal|disclose|mention|tell)\b[^\n]{0,40}\b` +
			`(system prompt|instructions|prompt|rules|training data|secrets?|passwords?|credentials?|hidden)\b`),
		detail: "instruction language about concealing something sensitive",
	},
	{
		name:   "external-access",
		re:     regexp.MustCompile(`(?i)\bimport\s+requests\b|\brequests\.(get|post|put)\s*\(|\burllib\.request\b|\bcurl\s+-`),
		detail: "template can read external resources",
	},
}

//go:embed known-good-templates.txt
var allowlistRaw string

// allowlist maps each reviewed template hash to its label.
var allowlist = parseAllowlist(allowlistRaw)

// Inspect analyses one chat template string and returns the hero-check result.
func Inspect(template string) checks.Result {
	return inspect(template, Options{})
}

// InspectAll analyses the default template and every named template (such as
// tool_use or rag), and reports the worst result: a payload in any template
// the serving stack can select is a payload in the artifact. nonString names
// chat-template keys stored as something other than a string, which cannot be
// inspected.
func InspectAll(templates map[string]string, nonString []string) checks.Result {
	return inspectAll(templates, nonString, Options{})
}

// InspectAllWith is InspectAll with the artifact's special tokens and the
// reference data: reviewed template hashes from a verified feed, alongside
// the embedded allowlist (like it, they clear language leads only;
// structural evidence still FAILs), and reviewed templates with their text,
// which each template's render is compared with.
func InspectAllWith(templates map[string]string, nonString []string, o Options) checks.Result {
	return inspectAll(templates, nonString, o)
}

func inspectAll(templates map[string]string, nonString []string, o Options) checks.Result {
	r := checks.Result{Name: resultName, LooksFor: resultLooksFor}
	if len(templates) == 0 && len(nonString) == 0 {
		r.Status = checks.NotTested
		r.Notes = "no chat template present in artifact metadata"
		return r
	}
	names := make([]string, 0, len(templates))
	for n := range templates {
		names = append(names, n)
	}
	sort.Strings(names)
	if len(names) == 1 && len(nonString) == 0 {
		return inspect(templates[names[0]], o)
	}

	rank := map[checks.Status]int{checks.Pass: 0, checks.NotTested: 1, checks.Lead: 2, checks.Fail: 3}
	r.Status = checks.Pass
	var notes []string
	for _, n := range names {
		one := inspect(templates[n], o)
		label := "template " + n
		for _, f := range one.Findings {
			f.Detail = label + ": " + f.Detail
			r.Findings = append(r.Findings, f)
		}
		if rank[one.Status] > rank[r.Status] {
			r.Status = one.Status
		}
		notes = append(notes, label+": "+string(one.Status)+", "+one.Notes)
	}
	for _, n := range nonString {
		if rank[checks.NotTested] > rank[r.Status] {
			r.Status = checks.NotTested
		}
		notes = append(notes, "template "+n+": stored as a non-string metadata value, not inspected")
	}
	r.Notes = strings.Join(notes, " | ")
	return r
}

// maxTemplateBytes bounds the template the analyser reads. Real templates are
// tens of kilobytes.
const maxTemplateBytes = 1 << 20

const (
	resultName     = "Chat template (hero)"
	resultLooksFor = "Code reach, hidden or obfuscated text, and override or content-triggered instructions in the chat template"
)

// reviewed reports whether a template hash is on the embedded allowlist or
// the feed's reviewed list, and its label there.
func reviewed(hash string, o Options) (string, bool) {
	if label, ok := allowlist[hash]; ok {
		return label, true
	}
	for h, label := range o.Reviewed {
		if strings.EqualFold(h, hash) {
			return label, true
		}
	}
	return "", false
}

func inspect(template string, o Options) checks.Result {
	r := checks.Result{Name: resultName, LooksFor: resultLooksFor}

	if strings.TrimSpace(template) == "" {
		r.Status = checks.NotTested
		r.Notes = "no chat template present in artifact metadata"
		return r
	}
	// A template the analyser cannot read is a LEAD, not a gap. Every real
	// template in the baseline parses, and a serving stack may still render
	// one this parser rejects, so unreadability is itself the evasion to
	// watch for: as NOT_TESTED, a blanket acceptance would clear it.
	unreadable := func(why string) checks.Result {
		r.Status = checks.Lead
		r.Findings = append(r.Findings, checks.Finding{Pattern: "unanalysable-template", Span: excerptS(why),
			Detail: "the template could not be analysed; a human must review it"})
		r.Notes = "template could not be analysed, so it needs review: " + why
		return r
	}
	if len(template) > maxTemplateBytes {
		return unreadable(fmt.Sprintf("template is %d bytes, over the %d-byte analysis limit", len(template), maxTemplateBytes))
	}
	if !utf8.ValidString(template) {
		return unreadable("template bytes are not valid UTF-8")
	}
	nodes, err := jinja.Parse(template)
	if err != nil {
		return unreadable("template does not parse: " + err.Error())
	}
	an := analyse(nodes)
	if an.exhausted {
		return unreadable("template exceeds the analysis work budget")
	}

	// Structural evidence first, and only from the parsed template: code the
	// template can execute, never words in its text. The allowlist cannot
	// clear code.
	for _, s := range an.signals {
		if s.fail {
			r.Findings = append(r.Findings, checks.Finding{Pattern: s.pattern, Span: s.span, Detail: s.detail})
		}
	}
	if len(r.Findings) > 0 {
		r.Status = checks.Fail
		r.Notes = fmt.Sprintf("%d structural code-execution indicator(s). Positive evidence. "+
			"Not rendered: a template that reaches code is never evaluated.", len(r.Findings))
		return r
	}

	// Rendering runs after the analysis, on templates with no code reach.
	// What it finds is added to the row: the text the template adds is
	// listed, never judged; a content condition that adds instructions, or
	// a near-miss of a reviewed template, is a LEAD.
	rend := renderCheck(template, nodes, an, o)

	if _, ok := reviewed(templateHash(template), o); ok {
		r.Status = checks.Pass
		r.Notes = "template hash is on the reviewed allowlist. Heuristic; not a proof of absence. " + rend.note()
		return r
	}

	var leadHits []string
	for _, s := range an.signals {
		r.Findings = append(r.Findings, checks.Finding{Pattern: s.pattern, Span: s.span, Detail: s.detail})
		leadHits = append(leadHits, fmt.Sprintf("%s: %q", s.pattern, s.span))
	}
	for _, f := range rend.findings {
		r.Findings = append(r.Findings, f)
		leadHits = append(leadHits, fmt.Sprintf("%s (rendered): %q", f.Pattern, f.Span))
	}
	if len(leadHits) > 0 {
		r.Status = checks.Lead
		r.Notes = "suspicious template structure or language, not conclusive; needs review: " +
			strings.Join(leadHits, "; ") + ". " + rend.note()
		return r
	}

	r.Status = checks.Pass
	r.Notes = "template parsed; no code-execution reach, content-conditional injection, hidden or obfuscated text, " +
		"or instruction-language lead found. Structural heuristic; not a proof of absence."
	// The render's inventory supersedes the static list of default text;
	// it stays only when the template could not be rendered.
	if len(an.outsideText) > 0 && rend.skipped != "" {
		r.Notes += fmt.Sprintf(" It emits %d default text segment(s) outside the message loop, for review: %q",
			len(an.outsideText), an.outsideText[0])
	}
	r.Notes += " " + rend.note()
	return r
}

func templateHash(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

// parseAllowlist reads "<sha256> [label]" lines; the label, by convention
// the repo and revision the template was reviewed at, names it in a note.
func parseAllowlist(raw string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		out[strings.ToLower(f[0])] = strings.Join(f[1:], " ")
	}
	return out
}

func excerpt(t string, start, end int) string {
	const max = 80
	s := t[start:end]
	if len(s) > max {
		s = s[:max] + "..."
	}
	return s
}
