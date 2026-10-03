package gguf

import (
	"errors"
	"fmt"
	"io"
	"strings"
)

// Tokenizer is the tokenizer a GGUF carries, as llama.cpp reads it.
type Tokenizer struct {
	// Tokens is tokenizer.ggml.tokens, the vocabulary in id order.
	Tokens []string `json:"-"`
	// TokenTypes is tokenizer.ggml.token_type; nil when absent.
	TokenTypes []int32 `json:"-"`
	// Scores and Merges are the element counts of tokenizer.ggml.scores and
	// tokenizer.ggml.merges, or -1 when absent.
	Scores int64 `json:"scores"`
	Merges int64 `json:"merges"`
	// SpecialIDs holds every tokenizer.ggml.*_token_id, by its middle name
	// (bos, eos, padding, ...).
	SpecialIDs map[string]uint64 `json:"special_ids,omitempty"`
}

// Token types, from llama.cpp's llama_token_type.
const (
	TokenUndefined   = 0
	TokenNormal      = 1
	TokenUnknown     = 2
	TokenControl     = 3
	TokenUserDefined = 4
	TokenUnused      = 5
	TokenByte        = 6
)

// maxVocab bounds the vocabulary read into memory. The largest real
// vocabularies are a few hundred thousand tokens.
const maxVocab = 1 << 22

// tokenizerArray reports whether key is a tokenizer array this reader keeps.
func tokenizerArray(key string) bool {
	switch key {
	case "tokenizer.ggml.tokens", "tokenizer.ggml.token_type", "tokenizer.ggml.scores", "tokenizer.ggml.merges":
		return true
	}
	return false
}

// specialIDKey maps tokenizer.ggml.<name>_token_id to <name>.
func specialIDKey(key string) (string, bool) {
	rest, ok := strings.CutPrefix(key, "tokenizer.ggml.")
	if !ok {
		return "", false
	}
	name, ok := strings.CutSuffix(rest, "_token_id")
	return name, ok && name != ""
}

// readTokenizerArray reads one tokenizer array into m.Tokenizer. Strings and
// ints are kept for the vocabulary and token types; scores and merges are
// counted, not kept.
func readTokenizerArray(r io.Reader, key string, m *Manifest) error {
	elemType, err := readU32(r)
	if err != nil {
		return err
	}
	if elemType == typeArray {
		return errors.New("gguf: nested array in metadata is not valid GGUF")
	}
	count, err := readU64(r)
	if err != nil {
		return err
	}
	if count > maxVocab {
		return fmt.Errorf("gguf: %s has %d elements, over the %d limit", key, count, maxVocab)
	}
	t := &m.Tokenizer
	switch key {
	case "tokenizer.ggml.tokens":
		if elemType != typeString {
			return fmt.Errorf("gguf: %s is not a string array", key)
		}
		t.Tokens = make([]string, 0, min(count, 1<<16))
		for i := uint64(0); i < count; i++ {
			s, err := readString(r)
			if err != nil {
				return fmt.Errorf("gguf: reading token %d: %w", i, err)
			}
			t.Tokens = append(t.Tokens, s)
		}
		return nil
	case "tokenizer.ggml.token_type":
		w := fixedWidth(elemType)
		if w != 4 {
			return fmt.Errorf("gguf: %s is not a 32-bit integer array", key)
		}
		t.TokenTypes = make([]int32, 0, min(count, 1<<16))
		for i := uint64(0); i < count; i++ {
			v, err := readU32(r)
			if err != nil {
				return fmt.Errorf("gguf: reading token type %d: %w", i, err)
			}
			t.TokenTypes = append(t.TokenTypes, int32(v))
		}
		return nil
	}
	// scores and merges: count them and skip their bodies.
	if key == "tokenizer.ggml.scores" {
		t.Scores = int64(count)
	} else {
		t.Merges = int64(count)
	}
	if w := fixedWidth(elemType); w > 0 {
		return skipN(r, int64(count)*int64(w))
	}
	for i := uint64(0); i < count; i++ {
		if _, err := scanValue(r, elemType, false); err != nil {
			return err
		}
	}
	return nil
}
