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
//     acceptance can clear: only escalation clears it. The patterns are
//     narrow: they require concealment of something sensitive, because a
//     corpus sweep proved that ordinary templates contain bare "do not tell"
//     and that a loose "requests" pattern matches inside PULL_REQUESTS.
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

// lead patterns are a signal to escalate, never a FAIL. They require
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

var allowlist = parseAllowlist(allowlistRaw)

// Inspect analyses one chat template string and returns the hero-check result.
func Inspect(template string) checks.Result {
	return inspect(template, allowlist)
}

// InspectAll analyses the default template and every named template (such as
// tool_use or rag), and reports the worst result: a payload in any template
// the serving stack can select is a payload in the artifact. nonString names
// chat-template keys stored as something other than a string, which cannot be
// inspected.
func InspectAll(templates map[string]string, nonString []string) checks.Result {
	return inspectAll(templates, nonString, allowlist)
}

// InspectAllWith is InspectAll with more reviewed template hashes, from a
// verified feed, alongside the embedded allowlist. Like the embedded list,
// they clear language leads only; structural evidence still FAILs.
func InspectAllWith(templates map[string]string, nonString []string, reviewed map[string]struct{}) checks.Result {
	if len(reviewed) == 0 {
		return InspectAll(templates, nonString)
	}
	allow := make(map[string]struct{}, len(allowlist)+len(reviewed))
	for h := range allowlist {
		allow[h] = struct{}{}
	}
	for h := range reviewed {
		allow[strings.ToLower(h)] = struct{}{}
	}
	return inspectAll(templates, nonString, allow)
}

func inspectAll(templates map[string]string, nonString []string, allow map[string]struct{}) checks.Result {
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

	rank := map[checks.Status]int{checks.Pass: 0, checks.NotTested: 1, checks.Lead: 2, checks.Fail: 3}
	r.Status = checks.Pass
	var notes []string
	for _, n := range names {
		one := inspect(templates[n], allow)
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
	if len(names) == 1 && len(nonString) == 0 {
		return inspect(templates[names[0]], allow)
	}
	r.Notes = strings.Join(notes, " | ")
	return r
}

// maxTemplateBytes bounds the template the analyser reads. Real templates are
// tens of kilobytes.
const maxTemplateBytes = 1 << 20

const (
	resultName     = "Chat template (hero)"
	resultLooksFor = "Instructions in GGUF metadata that act before user input"
)

func inspect(template string, allow map[string]struct{}) checks.Result {
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
		r.Notes = fmt.Sprintf("%d structural code-execution indicator(s). Positive evidence.",
			len(r.Findings))
		return r
	}

	if _, ok := allow[templateHash(template)]; ok {
		r.Status = checks.Pass
		r.Notes = "template hash is on the reviewed allowlist. Heuristic; not a proof of absence."
		return r
	}

	var leadHits []string
	for _, s := range an.signals {
		r.Findings = append(r.Findings, checks.Finding{Pattern: s.pattern, Span: s.span, Detail: s.detail})
		leadHits = append(leadHits, fmt.Sprintf("%s: %q", s.pattern, s.span))
	}
	if len(leadHits) > 0 {
		r.Status = checks.Lead
		r.Notes = "suspicious template structure or language, not conclusive; escalate: " + strings.Join(leadHits, "; ")
		return r
	}

	r.Status = checks.Pass
	r.Notes = "template parsed; no code-execution reach, content-conditional injection, hidden or obfuscated text, " +
		"or instruction-language lead found. Structural heuristic; not a proof of absence."
	if len(an.outsideText) > 0 {
		r.Notes += fmt.Sprintf(" It emits %d default text segment(s) outside the message loop, for review: %q",
			len(an.outsideText), an.outsideText[0])
	}
	return r
}

func templateHash(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

func parseAllowlist(raw string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out[strings.ToLower(line)] = struct{}{}
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
