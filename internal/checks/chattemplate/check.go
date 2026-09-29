// Package chattemplate inspects a GGUF chat template for dangerous content.
// This is the hero check.
//
// Two classes of signal, and they are not the same thing:
//
//   - Structural code-execution indicators (object escape, process exec) are
//     positive evidence and return FAIL.
//   - Instruction-language phrases ("do not tell", "ignore previous") are a
//     lead only. A corpus sweep proved that ordinary, benign templates contain
//     such phrases, so a phrase match cannot be a FAIL. It returns NOT_TESTED
//     with the lead recorded, which is what escalates to a human.
//
// Disciplined this way, a clean result is still not a proof of absence, and a
// FAIL means the template can run code.
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

// structural patterns are positive evidence: a template that reaches into
// Python internals or invokes process execution.
var structural = []pattern{
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

// lead patterns are a signal to escalate, never a FAIL. Benign templates
// contain this language, so a match is not evidence on its own.
var leads = []pattern{
	{
		name:   "instruction-override",
		re:     regexp.MustCompile(`(?i)(ignore|disregard)\s+(all\s+)?(previous|prior|above)`),
		detail: "instruction language that overrides earlier content",
	},
	{
		name:   "secrecy-instruction",
		re:     regexp.MustCompile(`(?i)do\s+not\s+(reveal|disclose|mention|tell)`),
		detail: "instruction language about concealment",
	},
	{
		name:   "external-access",
		re:     regexp.MustCompile(`(?i)\bopen\s*\(|\.read\s*\(|\brequests\b|\burllib\b|\bcurl\b`),
		detail: "template can read external resources",
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

	for _, p := range structural {
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
		r.Notes = fmt.Sprintf("%d structural code-execution indicator(s). Positive evidence.",
			len(r.Findings))
		return r
	}

	var leadHits []string
	for _, p := range leads {
		if loc := p.re.FindStringIndex(template); loc != nil {
			leadHits = append(leadHits, fmt.Sprintf("%s: %q", p.name, excerpt(template, loc[0], loc[1])))
		}
	}
	if len(leadHits) > 0 {
		r.Status = checks.NotTested
		r.Notes = "instruction-language lead, not conclusive; escalate: " + strings.Join(leadHits, "; ")
		return r
	}

	r.Status = checks.Pass
	r.Notes = "no structural indicator and no instruction-language lead matched. Heuristic; not a proof of absence."
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
