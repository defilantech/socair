package tokenizer

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/modeldir"
)

// Read bounds. The largest real tokenizer.json files are tens of megabytes.
const (
	maxTokenizerJSON = 128 << 20
	maxConfigJSON    = 16 << 20
)

// HFResult is the tokenizer row of a model directory and the tokenizer hash
// for the identity section (the SHA-256 of tokenizer.json), empty when there
// is no tokenizer.json.
type HFResult struct {
	checks.Result
	Hash string
}

// hfTokenizer is the part of a tokenizer.json this check reads.
type hfTokenizer struct {
	Model struct {
		Type  string          `json:"type"`
		Vocab json.RawMessage `json:"vocab"`
	} `json:"model"`
	AddedTokens []struct {
		ID      int64  `json:"id"`
		Content string `json:"content"`
		Special bool   `json:"special"`
	} `json:"added_tokens"`
	Normalizer    any `json:"normalizer"`
	PostProcessor any `json:"post_processor"`
}

// specialIDKeys are the token ids configs name.
var specialIDKeys = []string{"bos_token_id", "eos_token_id", "pad_token_id", "sep_token_id", "unk_token_id", "decoder_start_token_id"}

// specialNameKeys are the special tokens tokenizer configs name by text.
var specialNameKeys = []string{"bos_token", "eos_token", "unk_token", "pad_token", "sep_token", "cls_token", "mask_token"}

// InspectHF inspects the Hugging Face tokenizer of a model directory
// snapshot rooted at root: tokenizer.json, with tokenizer_config.json,
// special_tokens_map.json, and the special-token ids in config.json and
// generation_config.json.
//
// FAIL is positive evidence the tables disagree: a special-token id that
// names no token, an id two files map to different tokens, a declared special
// token absent from the vocabulary, or a template whose ids and tokens
// disagree. Each was measured at zero on 59 real tokenizers (see
// docs/false-positive-baseline.md). LEAD is a token or rule that injects text
// a reviewer should see: a special or added token carrying prose or an
// instruction, a normalizer that rewrites input into special-token text, or a
// post-processor that inserts a non-special token into every input. PASS only
// when tokenizer.json was read and every rule ran; without it (a sentencepiece
// or slow-tokenizer-only repo) the row is NOT_TESTED, naming what is there.
func InspectHF(root string, files []modeldir.File) HFResult {
	out := HFResult{Result: checks.Result{Name: resultName, LooksFor: looksFor}}
	r := &out.Result
	at := func(rel string) string { return filepath.Join(root, filepath.FromSlash(rel)) }

	tj, ok := findTop(files, "tokenizer.json")
	if !ok {
		var present []string
		for _, f := range files {
			if f.Role == modeldir.RoleTokenizer {
				present = append(present, f.Path)
			}
		}
		r.Status = checks.NotTested
		if len(present) == 0 {
			r.Notes = "no tokenizer file in the directory"
		} else {
			r.Notes = "no tokenizer.json, so the tokenizer the loader builds was not inspected; present: " + strings.Join(present, ", ")
		}
		return out
	}
	if tj.Size > maxTokenizerJSON {
		r.Status, r.Notes = checks.NotTested, fmt.Sprintf("tokenizer.json is %d bytes, over the %d-byte limit", tj.Size, maxTokenizerJSON)
		return out
	}
	raw, err := os.ReadFile(at(tj.Path))
	if err != nil {
		r.Status, r.Notes = checks.NotTested, "could not read tokenizer.json: "+err.Error()
		return out
	}
	sum := sha256.Sum256(raw)
	out.Hash = hex.EncodeToString(sum[:])

	var t hfTokenizer
	if err := json.Unmarshal(raw, &t); err != nil {
		r.Status, r.Notes = checks.NotTested, "tokenizer.json does not parse: "+err.Error()
		return out
	}
	vocab, dupIDs, err := readVocab(t.Model.Vocab)
	if err != nil {
		r.Status, r.Notes = checks.NotTested, "tokenizer.json model vocabulary is unreadable: "+err.Error()
		return out
	}

	if len(vocab) == 0 && len(t.AddedTokens) == 0 {
		r.Status, r.Notes = checks.NotTested, "tokenizer.json holds no vocabulary, so there is no tokenizer to inspect"
		return out
	}
	fail := func(pattern, span, detail string) {
		r.Findings = append(r.Findings, checks.Finding{Pattern: pattern, Span: span, Detail: detail})
	}
	// LEADs are gathered apart from FAILs: a FAIL decides the row first.
	var leads []checks.Finding
	for _, id := range dupIDs {
		fail("tokenizer-duplicate-id", fmt.Sprintf("id %d", id), "two vocabulary entries share one id, so which token it means depends on the reader")
	}

	// The full id -> token table the loader builds: the model vocabulary
	// with added tokens laid over it.
	full := make(map[int64]string, len(vocab)+len(t.AddedTokens))
	for id, tok := range vocab {
		full[id] = tok
	}
	special := map[string]bool{}
	added := map[int64]string{}
	for _, a := range t.AddedTokens {
		if base, ok := vocab[a.ID]; ok && base != a.Content {
			fail("tokenizer-id-conflict", fmt.Sprintf("id %d: vocabulary %q, added token %q", a.ID, excerpt(base), excerpt(a.Content)),
				"an added token reuses a vocabulary id with different text")
		}
		full[a.ID] = a.Content
		added[a.ID] = a.Content
		if a.Special {
			special[a.Content] = true
		}
	}
	var size int64
	for id := range full {
		size = max(size, id+1)
	}
	contents := make(map[string]bool, len(full))
	for _, tok := range full {
		contents[tok] = true
	}

	// Special-token ids in config.json and generation_config.json must name
	// a token.
	for _, name := range []string{"config.json", "generation_config.json"} {
		cfg, ok := readObject(root, files, name)
		if !ok {
			continue
		}
		for _, k := range specialIDKeys {
			for _, id := range intsOf(cfg[k]) {
				if _, ok := full[id]; !ok {
					fail("special-token-out-of-range", fmt.Sprintf("%s %s = %d", name, k, id),
						fmt.Sprintf("the id names no token in the %d-entry tokenizer", size))
				}
			}
		}
	}

	// tokenizer_config.json's added_tokens_decoder must agree with
	// tokenizer.json, and every declared special token must exist.
	declared := map[string]bool{}
	for _, name := range []string{"tokenizer_config.json", "special_tokens_map.json"} {
		cfg, ok := readObject(root, files, name)
		if !ok {
			continue
		}
		if name == "tokenizer_config.json" {
			if dec, ok := cfg["added_tokens_decoder"].(map[string]any); ok {
				ids := make([]string, 0, len(dec))
				for k := range dec {
					ids = append(ids, k)
				}
				sort.Strings(ids)
				for _, k := range ids {
					entry, _ := dec[k].(map[string]any)
					content, _ := entry["content"].(string)
					isSpecial, _ := entry["special"].(bool)
					id, err := strconv.ParseInt(k, 10, 64)
					if err != nil {
						fail("tokenizer-config-mismatch", "added_tokens_decoder "+k, "a key that is not a token id")
						continue
					}
					got, inFull := full[id]
					switch {
					case !inFull:
						fail("tokenizer-config-mismatch", fmt.Sprintf("added_tokens_decoder %d = %q", id, excerpt(content)), "tokenizer.json has no token with this id")
					case got != content:
						fail("tokenizer-config-mismatch", fmt.Sprintf("id %d: tokenizer.json %q, tokenizer_config.json %q", id, excerpt(got), excerpt(content)),
							"the two files map one id to different tokens")
					case added[id] != "" && special[content] != isSpecial:
						fail("tokenizer-config-mismatch", fmt.Sprintf("id %d %q", id, excerpt(content)), "the two files disagree on whether the token is special")
					}
					if isSpecial {
						special[content] = true
					}
					if added[id] == "" {
						leads = checkProse(leads, "added_tokens_decoder", id, content)
					}
				}
			}
		}
		for _, k := range specialNameKeys {
			if s := tokenText(cfg[k]); s != "" {
				declared[s] = true
				if !contents[s] {
					fail("special-token-missing", fmt.Sprintf("%s %s = %q", name, k, excerpt(s)), "a declared special token is not in the vocabulary")
				}
			}
		}
		for _, k := range []string{"additional_special_tokens", "extra_special_tokens"} {
			for _, s := range tokenTexts(cfg[k]) {
				declared[s] = true
				if !contents[s] {
					fail("special-token-missing", fmt.Sprintf("%s %s %q", name, k, excerpt(s)), "a declared special token is not in the vocabulary")
				}
			}
		}
	}

	// Templates must insert the tokens they name.
	templateTokens := map[string]bool{}
	walk(t.PostProcessor, func(n map[string]any) {
		if n["type"] != "TemplateProcessing" {
			return
		}
		sts, _ := n["special_tokens"].(map[string]any)
		keys := make([]string, 0, len(sts))
		for k := range sts {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			st, _ := sts[k].(map[string]any)
			ids, _ := st["ids"].([]any)
			toks, _ := st["tokens"].([]any)
			if len(ids) != len(toks) {
				fail("tokenizer-template-mismatch", "post_processor "+k, "a template token's ids and tokens differ in number")
				continue
			}
			for i := range ids {
				id, idOK := asInt(ids[i])
				tok, _ := toks[i].(string)
				templateTokens[tok] = true
				if !idOK || full[id] != tok {
					fail("tokenizer-template-mismatch", fmt.Sprintf("post_processor %s: id %v is %q, template says %q", k, ids[i], excerpt(full[id]), excerpt(tok)),
						"the template inserts a different token than it names")
				}
			}
		}
	})

	if len(r.Findings) > 0 {
		r.Status = checks.Fail
		r.Notes = fmt.Sprintf("%d tokenizer inconsistenc(ies): %s. A loader would read these tables differently from a reviewer.", len(r.Findings), spans(firstN(r.Findings, 5)))
		return out
	}

	// LEADs: text injected where a reviewer would not see it.
	ids := make([]int64, 0, len(t.AddedTokens))
	for _, a := range t.AddedTokens {
		ids = append(ids, a.ID)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		leads = checkProse(leads, "added token", id, added[id])
	}
	marks := map[string]bool{}
	for s := range special {
		marks[s] = true
	}
	for s := range declared {
		marks[s] = true
	}
	walk(t.Normalizer, func(n map[string]any) {
		switch n["type"] {
		case "Replace":
			content, _ := n["content"].(string)
			if m := containsAny(content, marks); m != "" {
				leads = append(leads, checks.Finding{Pattern: "normalizer-injects-special", Span: fmt.Sprintf("Replace %v -> %q", n["pattern"], excerpt(content)),
					Detail: "the normalizer rewrites input text into the special token " + m})
			}
		case "Precompiled":
			s, _ := n["precompiled_charsmap"].(string)
			for _, target := range charsmapTargets(s) {
				if m := containsAny(target, marks); m != "" {
					leads = append(leads, checks.Finding{Pattern: "normalizer-injects-special", Span: fmt.Sprintf("precompiled charsmap -> %q", excerpt(target)),
						Detail: "the precompiled normalizer maps input text to the special token " + m})
					break
				}
			}
		}
	})
	for tok := range templateTokens {
		if !special[tok] && !declared[tok] {
			leads = append(leads, checks.Finding{Pattern: "template-injects-token", Span: fmt.Sprintf("post_processor inserts %q", excerpt(tok)),
				Detail: "the post-processor adds a token that is not a special token to every input"})
		}
	}
	if len(leads) > 0 {
		sort.SliceStable(leads, func(i, j int) bool { return leads[i].Span < leads[j].Span })
		r.Findings = leads
		r.Status = checks.Lead
		r.Notes = fmt.Sprintf("%d tokenizer entr(ies) inject text a reviewer should see: %s. Needs review.", len(r.Findings), spans(firstN(r.Findings, 5)))
		if len(r.Findings) > 20 {
			r.Findings = r.Findings[:20]
		}
		return out
	}

	r.Status = checks.Pass
	r.Notes = fmt.Sprintf("tokenizer.json (sha256 %s, %s model): %d tokens, %d added (%d special); special-token ids, added-token tables, declared special tokens, and template tokens agree; no token, normalizer, or template injects text. No canonical tokenizer reference was compared.",
		out.Hash[:16], orUnknown(t.Model.Type), size, len(t.AddedTokens), len(special))
	return out
}

func orUnknown(s string) string {
	if s == "" {
		return "untyped"
	}
	return s
}

// checkProse adds a LEAD for a token carrying an instruction or prose.
func checkProse(leads []checks.Finding, where string, id int64, text string) []checks.Finding {
	switch {
	case text == "":
	case instruction.MatchString(text):
		leads = append(leads, checks.Finding{Pattern: "token-instruction", Span: fmt.Sprintf("%s %d: %q", where, id, excerpt(text)),
			Detail: "a token carries instruction language"})
	case len(strings.Fields(text)) >= 3:
		leads = append(leads, checks.Finding{Pattern: "token-prose", Span: fmt.Sprintf("%s %d: %q", where, id, excerpt(text)),
			Detail: "an added token carries prose rather than a marker"})
	}
	return leads
}

// readVocab reads a model vocabulary: an object of token -> id (BPE,
// WordPiece, WordLevel) or a list of [piece, score] pairs (Unigram). It
// returns the ids that two tokens share.
func readVocab(raw json.RawMessage) (map[int64]string, []int64, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return map[int64]string{}, nil, nil
	}
	if raw[0] == '[' {
		var pairs [][]json.RawMessage
		if err := json.Unmarshal(raw, &pairs); err != nil {
			return nil, nil, err
		}
		out := make(map[int64]string, len(pairs))
		for i, p := range pairs {
			if len(p) == 0 {
				return nil, nil, fmt.Errorf("entry %d is empty", i)
			}
			var s string
			if err := json.Unmarshal(p[0], &s); err != nil {
				return nil, nil, fmt.Errorf("entry %d: %w", i, err)
			}
			out[int64(i)] = s
		}
		return out, nil, nil
	}
	var m map[string]int64
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, nil, err
	}
	out := make(map[int64]string, len(m))
	var dups []int64
	for tok, id := range m {
		if prev, ok := out[id]; ok && prev != tok {
			dups = append(dups, id)
			continue
		}
		out[id] = tok
	}
	sort.Slice(dups, func(i, j int) bool { return dups[i] < dups[j] })
	return out, dups, nil
}

// charsmapTargets returns the replacement strings of a sentencepiece
// precompiled charsmap: a little-endian uint32 trie size, the trie, then the
// NUL-separated normalized strings the trie points into. An unreadable map
// yields none.
func charsmapTargets(b64 string) []string {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(b) < 4 {
		return nil
	}
	n := binary.LittleEndian.Uint32(b[:4])
	if uint64(n) > uint64(len(b)-4) {
		return nil
	}
	var out []string
	for _, s := range bytes.Split(b[4+n:], []byte{0}) {
		if len(s) > 0 {
			out = append(out, string(s))
		}
	}
	return out
}

func containsAny(s string, marks map[string]bool) string {
	if s == "" {
		return ""
	}
	keys := make([]string, 0, len(marks))
	for m := range marks {
		keys = append(keys, m)
	}
	sort.Strings(keys)
	for _, m := range keys {
		// A one-character mark (an Unigram "▁" or a byte) is ordinary text.
		if len([]rune(m)) > 1 && strings.Contains(s, m) {
			return m
		}
	}
	return ""
}

// walk visits every object in a decoded JSON tree.
func walk(n any, visit func(map[string]any)) {
	switch v := n.(type) {
	case map[string]any:
		visit(v)
		for _, c := range v {
			walk(c, visit)
		}
	case []any:
		for _, c := range v {
			walk(c, visit)
		}
	}
}

func findTop(files []modeldir.File, name string) (modeldir.File, bool) {
	for _, f := range files {
		if f.Path == name {
			return f, true
		}
	}
	return modeldir.File{}, false
}

// readObject reads a top-level JSON object from the snapshot, bounded.
func readObject(root string, files []modeldir.File, name string) (map[string]any, bool) {
	f, ok := findTop(files, name)
	if !ok || f.Size > maxConfigJSON {
		return nil, false
	}
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path.Clean(f.Path))))
	if err != nil {
		return nil, false
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return nil, false
	}
	return m, true
}

func asInt(v any) (int64, bool) {
	f, ok := v.(float64)
	if !ok || f != float64(int64(f)) {
		return 0, false
	}
	return int64(f), true
}

// intsOf reads a token id or a list of them.
func intsOf(v any) []int64 {
	switch t := v.(type) {
	case float64:
		if id, ok := asInt(t); ok {
			return []int64{id}
		}
	case []any:
		var out []int64
		for _, x := range t {
			if id, ok := asInt(x); ok {
				out = append(out, id)
			}
		}
		return out
	}
	return nil
}

// tokenText reads a special token written as a string or {"content": ...}.
func tokenText(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case map[string]any:
		s, _ := t["content"].(string)
		return s
	}
	return ""
}

// tokenTexts reads a list, or a name -> token object, of special tokens.
func tokenTexts(v any) []string {
	var out []string
	switch t := v.(type) {
	case []any:
		for _, x := range t {
			if s := tokenText(x); s != "" {
				out = append(out, s)
			}
		}
	case map[string]any:
		for _, x := range t {
			if s := tokenText(x); s != "" {
				out = append(out, s)
			}
		}
		sort.Strings(out)
	}
	return out
}

func firstN(fs []checks.Finding, n int) []checks.Finding {
	if len(fs) > n {
		return fs[:n]
	}
	return fs
}
