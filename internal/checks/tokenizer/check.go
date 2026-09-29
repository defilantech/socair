// Package tokenizer inspects the tokenizer family declared in artifact
// metadata.
//
// It yields PASS for a recognized family and NOT_TESTED otherwise. It never
// returns FAIL: an unrecognized family is outside our library, not evidence of
// malice.
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
	r.Status = checks.Pass
	r.Notes = "tokenizer family '" + model + "' is recognized; no anomaly in the declared family"
	return r
}
