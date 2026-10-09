package chattemplate

import (
	"sort"

	"github.com/defilantech/socair/internal/gguf"
)

// ggufSpecialVars maps a GGUF tokenizer.ggml.<name>_token_id to the template
// variable a serving stack passes for it. llama.cpp spells separator
// "seperator".
var ggufSpecialVars = map[string]string{
	"bos": "bos_token", "eos": "eos_token", "unknown": "unk_token", "padding": "pad_token",
	"seperator": "sep_token", "separator": "sep_token", "cls": "cls_token", "mask": "mask_token",
}

// TokensFromGGUF reads a GGUF tokenizer's special tokens: the named ones a
// template reads as variables, and every control, user-defined, or unknown
// token as a marker.
func TokensFromGGUF(t gguf.Tokenizer) Tokens {
	out := Tokens{Named: map[string]string{}}
	for name, id := range t.SpecialIDs {
		v, ok := ggufSpecialVars[name]
		if !ok || id >= uint64(len(t.Tokens)) {
			continue
		}
		out.Named[v] = t.Tokens[id]
	}
	for id, typ := range t.TokenTypes {
		if id >= len(t.Tokens) {
			break
		}
		switch typ {
		case gguf.TokenUnknown, gguf.TokenControl, gguf.TokenUserDefined:
			out.Markers = append(out.Markers, t.Tokens[id])
		}
	}
	return out
}

// TokensFromHF reads a Hugging Face tokenizer's special tokens: named holds
// the tokenizer config's bos_token, eos_token, and friends by name; added
// are the added tokens' text, which are the markers.
func TokensFromHF(named map[string]string, added []string) Tokens {
	out := Tokens{Named: map[string]string{}}
	for k, v := range named {
		out.Named[k] = v
	}
	out.Markers = append(out.Markers, added...)
	sort.Strings(out.Markers)
	return out
}
