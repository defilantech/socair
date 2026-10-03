// Package tokenizer reports the tokenizer family declared in artifact
// metadata.
//
// Today it reads only the tokenizer.ggml.model label, so it never returns PASS:
// a label is not an inspection of the tokens, special tokens, merges, or
// BOS/EOS ids, and a PASS would claim one. It never returns FAIL either: an
// unrecognized family is outside our library, not evidence of malice.
package tokenizer

import (
	"github.com/defilantech/socair/internal/checks"
)

// known is the set of tokenizer families we can reason about. Anything else is
// a NOT_TESTED, not a guess.
var known = map[string]struct{}{
	"llama":   {},
	"gpt2":    {},
	"bert":    {},
	"t5":      {},
	"rwkv":    {},
	"unigram": {},
}

// Inspect reports a result for the declared tokenizer family.
func Inspect(model string) checks.Result {
	r := checks.Result{
		Name:     "Tokenizer config",
		LooksFor: "Tokenizer metadata anomalies",
	}
	if model == "" {
		r.Status = checks.NotTested
		r.Notes = "no tokenizer family declared in metadata"
		return r
	}
	if _, ok := known[model]; !ok {
		r.Status = checks.NotTested
		r.Notes = "tokenizer family '" + model + "' is not in our library"
		return r
	}
	r.Status = checks.NotTested
	r.Notes = "tokenizer family '" + model + "' is declared and recognized; the token list, special and control tokens, merges, and BOS/EOS ids were not inspected"
	return r
}
