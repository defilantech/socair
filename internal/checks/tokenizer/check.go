// Package tokenizer inspects the tokenizer a GGUF carries.
//
// A tokenizer can be tampered with without touching the weights: a special
// token id pointed outside the vocabulary, a token-type table that no longer
// lines up with the tokens, or a control token whose text is an instruction
// that the serving stack will treat as a single privileged symbol. This check
// reads the vocabulary, the token types, the score and merge counts, and the
// special-token ids, and judges them:
//
//   - FAIL on positive evidence the tables are inconsistent: a special id out
//     of range, a type or score table whose length is not the vocabulary's, or
//     a token type llama.cpp does not define;
//   - LEAD on a control or user-defined token carrying prose or an
//     instruction phrase;
//   - PASS when those checks ran and found nothing;
//   - NOT_TESTED when there is no vocabulary to read, or only a family label.
package tokenizer

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/gguf"
)

const (
	resultName = "Tokenizer config"
	looksFor   = "Tampered tokenizer tables: special-token ids, token types, control tokens"
)

// known is the set of tokenizer families we can reason about.
var known = map[string]struct{}{
	"llama": {}, "gpt2": {}, "bert": {}, "t5": {}, "rwkv": {}, "unigram": {},
}

// Inspect reports on the declared tokenizer family alone. A label is not an
// inspection, so it never PASSes; InspectGGUF is the inspection.
func Inspect(model string) checks.Result {
	r := checks.Result{Name: resultName, LooksFor: looksFor, Status: checks.NotTested}
	switch _, ok := known[model]; {
	case model == "":
		r.Notes = "no tokenizer family declared in metadata"
	case !ok:
		r.Notes = "tokenizer family '" + model + "' is not in our library"
	default:
		r.Notes = "tokenizer family '" + model + "' is declared and recognized; the token list, special and control tokens, merges, and BOS/EOS ids were not inspected"
	}
	return r
}

var (
	// instruction is instruction or concealment language a token should
	// never carry.
	instruction = regexp.MustCompile(`(?i)\b(ignore|disregard)\s+(all\s+)?(previous|prior|above)\b|\bdo\s+not\s+(reveal|disclose|tell)\b|\byou\s+(are|must)\b|\balways\s+(include|respond|answer)\b`)
	// marker is a special-token marker as chat templates write them, with
	// ASCII or full-width bars.
	marker = regexp.MustCompile(`<[|｜][^|｜<>\s]{1,40}[|｜]>`)
)

// InspectGGUF inspects a GGUF's tokenizer, with its chat templates for
// context. model is the declared family, reported but not judged.
func InspectGGUF(model string, t gguf.Tokenizer, templates map[string]string) checks.Result {
	r := checks.Result{Name: resultName, LooksFor: looksFor}
	n := len(t.Tokens)
	if n == 0 {
		res := Inspect(model)
		res.Notes = "no tokenizer.ggml.tokens vocabulary to inspect; " + res.Notes
		return res
	}

	fail := func(pattern, span, detail string) {
		r.Findings = append(r.Findings, checks.Finding{Pattern: pattern, Span: span, Detail: detail})
	}
	if t.TokenTypes != nil && len(t.TokenTypes) != n {
		fail("tokenizer-table-mismatch", fmt.Sprintf("%d types for %d tokens", len(t.TokenTypes), n),
			"tokenizer.ggml.token_type does not line up with the vocabulary")
	}
	if t.Scores >= 0 && t.Scores != int64(n) {
		fail("tokenizer-table-mismatch", fmt.Sprintf("%d scores for %d tokens", t.Scores, n),
			"tokenizer.ggml.scores does not line up with the vocabulary")
	}
	names := make([]string, 0, len(t.SpecialIDs))
	for k := range t.SpecialIDs {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		if id := t.SpecialIDs[k]; id >= uint64(n) {
			fail("special-token-out-of-range", fmt.Sprintf("%s_token_id = %d", k, id),
				fmt.Sprintf("the %s token id points outside the %d-token vocabulary", k, n))
		}
	}
	for i, ty := range t.TokenTypes {
		if ty < gguf.TokenUndefined || ty > gguf.TokenByte {
			fail("tokenizer-bad-type", fmt.Sprintf("token %d type %d", i, ty), "a token type llama.cpp does not define")
			break
		}
	}
	if len(r.Findings) > 0 {
		r.Status = checks.Fail
		r.Notes = fmt.Sprintf("%d tokenizer inconsistenc(ies): %s. llama.cpp would misread or reject these tables.", len(r.Findings), spans(r.Findings))
		return r
	}

	// Control and user-defined tokens are matched as single privileged
	// symbols. Real ones are markers (<|im_start|>, [INST], <think>); none in
	// the baseline carries three or more words.
	var leads []checks.Finding
	controls := 0
	for i, ty := range t.TokenTypes {
		if ty != gguf.TokenControl && ty != gguf.TokenUserDefined {
			continue
		}
		if ty == gguf.TokenControl {
			controls++
		}
		text := t.Tokens[i]
		switch {
		case instruction.MatchString(text):
			leads = append(leads, checks.Finding{Pattern: "token-instruction", Span: excerpt(text),
				Detail: fmt.Sprintf("special token %d carries instruction language", i)})
		case ty == gguf.TokenControl && len(strings.Fields(text)) >= 3:
			leads = append(leads, checks.Finding{Pattern: "control-token-prose", Span: excerpt(text),
				Detail: fmt.Sprintf("control token %d carries prose rather than a marker", i)})
		}
		if len(leads) >= 10 {
			break
		}
	}
	if len(leads) > 0 {
		r.Findings = leads
		r.Status = checks.Lead
		r.Notes = fmt.Sprintf("%d special token(s) carry text a marker should not: %s. Needs review.", len(leads), spans(leads))
		return r
	}

	r.Status = checks.Pass
	r.Notes = fmt.Sprintf("%d tokens (sha256 %s), %d control; token types, scores, and %d special-token ids are consistent; no special token carries prose or instructions. No canonical tokenizer reference was compared.",
		n, vocabHash(t.Tokens)[:16], controls, len(t.SpecialIDs))
	if missing := missingMarkers(t.Tokens, templates); len(missing) > 0 {
		r.Notes += " The chat template uses markers not in the vocabulary (informational; real templates do this): " + strings.Join(missing, ", ")
	}
	return r
}

func vocabHash(tokens []string) string {
	h := sha256.New()
	for _, s := range tokens {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func missingMarkers(tokens []string, templates map[string]string) []string {
	vocab := make(map[string]bool, len(tokens))
	for _, s := range tokens {
		vocab[s] = true
	}
	seen := map[string]bool{}
	var out []string
	for _, tmpl := range templates {
		for _, m := range marker.FindAllString(tmpl, -1) {
			if !vocab[m] && !seen[m] {
				seen[m] = true
				out = append(out, m)
			}
		}
	}
	sort.Strings(out)
	if len(out) > 5 {
		out = append(out[:5], fmt.Sprintf("and %d more", len(out)-5))
	}
	return out
}

func spans(fs []checks.Finding) string {
	parts := make([]string, 0, len(fs))
	for _, f := range fs {
		parts = append(parts, f.Span)
	}
	return strings.Join(parts, "; ")
}

func excerpt(s string) string {
	if len(s) > 80 {
		return s[:80] + "..."
	}
	return s
}
