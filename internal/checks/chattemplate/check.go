// Package chattemplate inspects a GGUF chat template for instructions that act
// before user input. This is the hero check.
//
// Detection is heuristic over a known-pattern library. A clean result means no
// known pattern matched in the inspected bytes; it is not a proof of absence.
package chattemplate

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/defilantech/socair/internal/checks"
)

type pattern struct {
	name   string
	re     *regexp.Regexp
	detail string
}

// Patterns are high-confidence markers of a template that can act before the
// user, or can reach outside the model. Kept tight on purpose: a false FAIL
// costs more than a missed lead, which escalates instead.
var patterns = []pattern{
	{
		name:   "system-override-instruction",
		re:     regexp.MustCompile(`(?i)(ignore|disregard)\s+(all\s+)?(previous|prior|above)`),
		detail: "template overrides earlier instructions, the classic pre-user-input backdoor shape",
	},
	{
		name:   "secrecy-instruction",
		re:     regexp.MustCompile(`(?i)do\s+not\s+(reveal|disclose|mention|tell)`),
		detail: "template instructs concealment of content from the user",
	},
	{
		name:   "python-object-escape",
		re:     regexp.MustCompile(`__globals__|__subclasses__|__class__`),
		detail: "template reaches into Python object internals",
	},
	{
		name:   "process-execution",
		re:     regexp.MustCompile(`(?i)\bos\.system\s*\(|\bsubprocess\b|\beval\s*\(|\bexec\s*\(`),
		detail: "template can invoke process execution",
	},
}

// Inspect analyses one chat template string and returns the hero-check result.
func Inspect(template string) checks.Result {
	r := checks.Result{
		Name:     "Chat template (hero)",
		LooksFor: "Instructions in GGUF metadata that act before user input",
	}

	if strings.TrimSpace(template) == "" {
		r.Status = checks.NotTested
		r.Notes = "no chat template present in artifact metadata"
		return r
	}
	if !utf8.ValidString(template) {
		r.Status = checks.NotTested
		r.Notes = "template bytes are not valid UTF-8; cannot inspect"
		return r
	}
	if reason := imbalance(template); reason != "" {
		r.Status = checks.NotTested
		r.Notes = "template is not well-formed; cannot inspect: " + reason
		return r
	}

	for _, p := range patterns {
		if loc := p.re.FindStringIndex(template); loc != nil {
			r.Findings = append(r.Findings, checks.Finding{
				Pattern: p.name,
				Span:    excerpt(template, loc[0], loc[1]),
				Detail:  p.detail,
			})
		}
	}

	if len(r.Findings) > 0 {
		r.Status = checks.Fail
		r.Notes = fmt.Sprintf("%d high-risk pattern(s) matched. Heuristic over a known-pattern library.", len(r.Findings))
		return r
	}

	r.Status = checks.Pass
	r.Notes = "no high-risk pattern matched. Heuristic; not a proof of absence."
	return r
}

// imbalance reports a structural reason the template cannot be parsed as a
// template, or empty when the braces are balanced.
func imbalance(t string) string {
	if strings.Count(t, "{{") != strings.Count(t, "}}") {
		return "unbalanced {{ }}"
	}
	if strings.Count(t, "{%") != strings.Count(t, "%}") {
		return "unbalanced {% %}"
	}
	return ""
}

func excerpt(t string, start, end int) string {
	const max = 80
	s := t[start:end]
	if len(s) > max {
		s = s[:max] + "..."
	}
	return s
}
