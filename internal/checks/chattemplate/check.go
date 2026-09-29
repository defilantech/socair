// Package chattemplate inspects a GGUF chat template for dangerous content.
// This is the hero check.
//
// Three classes of signal, in this order of precedence:
//
//   - Structural code-execution indicators (object escape, process exec) are
//     positive evidence and return FAIL. This runs first and the allowlist
//     cannot override it: the allowlist clears language, never code.
//   - A template whose SHA256 is on the reviewed allowlist returns PASS.
//   - Instruction-language phrases are a lead only, and the patterns are
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

func inspect(template string, allow map[string]struct{}) checks.Result {
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

	// Structural evidence first. The allowlist cannot clear code.
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

	if _, ok := allow[templateHash(template)]; ok {
		r.Status = checks.Pass
		r.Notes = "template hash is on the reviewed allowlist. Heuristic; not a proof of absence."
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
