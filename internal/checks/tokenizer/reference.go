package tokenizer

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/gguf"
)

// TableFormat names a canonical tokenizer table file.
const TableFormat = "socair.tokenizer-table/v1"

// Table is a canonical tokenizer: its vocabulary in id order, as the trusted
// upstream ships it. Ids the upstream leaves unassigned are "".
type Table struct {
	Format string   `json:"format"`
	Name   string   `json:"name"`
	Tokens []string `json:"tokens"`
}

// maxTableTokens bounds a table read into memory, like maxVocab for a GGUF.
const maxTableTokens = 1 << 22

// ParseTable reads a canonical tokenizer table. It accepts the table format
// (TableFormat) or a Hugging Face tokenizer.json, whose vocabulary and added
// tokens are laid out in id order; name names a tokenizer.json, which has no
// name of its own.
func ParseTable(raw []byte, name string) (Table, error) {
	var probe struct {
		Format string          `json:"format"`
		Model  json.RawMessage `json:"model"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return Table{}, fmt.Errorf("tokenizer table does not parse: %w", err)
	}
	switch {
	case probe.Format == TableFormat:
		var t Table
		if err := json.Unmarshal(raw, &t); err != nil {
			return Table{}, fmt.Errorf("tokenizer table does not parse: %w", err)
		}
		if strings.TrimSpace(t.Name) == "" || len(t.Tokens) == 0 {
			return Table{}, errors.New("tokenizer table needs a name and tokens")
		}
		if len(t.Tokens) > maxTableTokens {
			return Table{}, fmt.Errorf("tokenizer table has %d tokens, over the %d limit", len(t.Tokens), maxTableTokens)
		}
		return t, nil
	case len(probe.Model) > 0:
		tokens, err := hfTokens(raw)
		if err != nil {
			return Table{}, err
		}
		return Table{Format: TableFormat, Name: name, Tokens: tokens}, nil
	}
	return Table{}, fmt.Errorf("not a %s table or a tokenizer.json", TableFormat)
}

// TableFromGGUF is the table a GGUF's vocabulary gives, for building a
// reference from a trusted GGUF.
func TableFromGGUF(name string, t gguf.Tokenizer) Table {
	return Table{Format: TableFormat, Name: name, Tokens: t.Tokens}
}

// hfTokens lays a tokenizer.json's vocabulary and added tokens out in id
// order.
func hfTokens(raw []byte) ([]string, error) {
	var t hfTokenizer
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, fmt.Errorf("tokenizer.json does not parse: %w", err)
	}
	vocab, _, err := readVocab(t.Model.Vocab)
	if err != nil {
		return nil, err
	}
	tokens, _, err := hfLayout(vocab, t)
	return tokens, err
}

// hfLayout lays a parsed vocabulary and its added tokens out in id order, and
// names the added-token ids, which fine-tunes rename legitimately.
func hfLayout(base map[int64]string, t hfTokenizer) ([]string, map[int]bool, error) {
	vocab := make(map[int64]string, len(base)+len(t.AddedTokens))
	for id, s := range base {
		vocab[id] = s
	}
	added := map[int]bool{}
	for _, a := range t.AddedTokens {
		vocab[a.ID] = a.Content
		if a.ID >= 0 && a.ID < maxTableTokens {
			added[int(a.ID)] = true
		}
	}
	var maxID int64 = -1
	for id := range vocab {
		if id < 0 {
			return nil, nil, fmt.Errorf("tokenizer.json has a negative token id %d", id)
		}
		if id > maxID {
			maxID = id
		}
	}
	if maxID < 0 {
		return nil, nil, errors.New("tokenizer.json has no vocabulary")
	}
	if maxID >= maxTableTokens {
		return nil, nil, fmt.Errorf("tokenizer.json token id %d is over the %d limit", maxID, maxTableTokens)
	}
	tokens := make([]string, maxID+1)
	for id, s := range vocab {
		tokens[id] = s
	}
	return tokens, added, nil
}

// LoadTables reads the tables at path: a table file or tokenizer.json, or a
// directory of them (*.json). It is how an operator supplies references
// without a feed (SOCAIR_TOKENIZER_REFERENCE).
func LoadTables(path string) ([]Table, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	files := []string{path}
	if info.IsDir() {
		files, err = filepath.Glob(filepath.Join(path, "*.json"))
		if err != nil {
			return nil, err
		}
		sort.Strings(files)
		if len(files) == 0 {
			return nil, fmt.Errorf("%s holds no .json tokenizer table", path)
		}
	}
	var out []Table
	for _, f := range files {
		raw, err := readBoundedFile(f)
		if err != nil {
			return nil, err
		}
		name := strings.TrimSuffix(filepath.Base(f), ".json")
		if name == "tokenizer" {
			name = filepath.Base(filepath.Dir(f))
		}
		t, err := ParseTable(raw, name)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		out = append(out, t)
	}
	return out, nil
}

func readBoundedFile(p string) ([]byte, error) {
	info, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if info.Size() > maxTokenizerJSON {
		return nil, fmt.Errorf("%s is %d bytes, over the %d-byte limit", p, info.Size(), maxTokenizerJSON)
	}
	return os.ReadFile(p)
}

// minFamilyMatch is the share of ids a reference must agree on before it is
// taken as this tokenizer's family. Below it, the reference is a different
// tokenizer and a diff would be noise.
const minFamilyMatch = 0.98

// specialText is how special and reserved tokens are written: <|...|>, <...>,
// [...], with full-width bars too.
var specialText = regexp.MustCompile(`^(<[|｜].*[|｜]>|<[^<>\s]{1,40}>|\[[A-Z_/0-9]{1,40}\])$`)

// Comparison is a tokenizer diffed against its best-matching reference.
type Comparison struct {
	// Reference is the matched table's name; "" when none matched.
	Reference string
	// Match is the share of shared ids that agree with the reference.
	Match float64
	// Changed are ordinary tokens whose text differs from the reference.
	Changed []checks.Finding
	// SpecialChanged counts special or reserved tokens that differ, which
	// fine-tunes rename legitimately.
	SpecialChanged int
	// Added and Missing count ids past the reference's end, and reference
	// ids the tokenizer lacks.
	Added, Missing int
	// Candidates is how many references were compared.
	Candidates int
}

// Compare diffs a vocabulary (id order) against the best-matching reference.
// special reports whether an id is a special token by the artifact's own
// tables (GGUF token types, or a tokenizer.json's added tokens); a token
// written like a marker is special either way.
func Compare(tokens []string, special func(id int) bool, refs []Table) Comparison {
	c := Comparison{Candidates: len(refs)}
	best := -1
	for i, ref := range refs {
		m := agreement(tokens, ref.Tokens)
		if m > c.Match {
			c.Match, best = m, i
		}
	}
	if best < 0 || c.Match < minFamilyMatch {
		return c
	}
	ref := refs[best]
	c.Reference = ref.Name
	n := min(len(tokens), len(ref.Tokens))
	for id := 0; id < n; id++ {
		want, got := ref.Tokens[id], tokens[id]
		if want == got {
			continue
		}
		if want == "" || special(id) || specialText.MatchString(want) || specialText.MatchString(got) {
			c.SpecialChanged++
			continue
		}
		if len(c.Changed) < 20 {
			c.Changed = append(c.Changed, checks.Finding{
				Pattern: "tokenizer-token-changed",
				Span:    fmt.Sprintf("id %d: %q -> %q", id, excerpt(want), excerpt(got)),
				Detail:  "an ordinary token's text differs from the canonical " + ref.Name + " tokenizer",
			})
		}
	}
	if len(tokens) > len(ref.Tokens) {
		c.Added = len(tokens) - len(ref.Tokens)
	} else {
		c.Missing = len(ref.Tokens) - len(tokens)
	}
	return c
}

// agreement is the share of shared, assigned ids whose text agrees.
func agreement(a, b []string) float64 {
	n := min(len(a), len(b))
	same, counted := 0, 0
	for i := 0; i < n; i++ {
		if b[i] == "" {
			continue
		}
		counted++
		if a[i] == b[i] {
			same++
		}
	}
	if counted == 0 {
		return 0
	}
	return float64(same) / float64(counted)
}

// ApplyReference folds a comparison into a tokenizer row. A changed ordinary
// token or a missing part of the vocabulary is a LEAD: positive evidence the
// tables differ from the canonical tokenizer, sent for review. Every other
// outcome is stated in the notes, so the row says what it compared. A FAIL or
// NOT_TESTED row is left as it is; it already says more.
func ApplyReference(r checks.Result, c Comparison) checks.Result {
	if r.Status == checks.Fail || r.Status == checks.NotTested {
		return r
	}
	if c.Candidates == 0 {
		r.Notes += " No canonical tokenizer reference was configured, so its tokens were not compared."
		return r
	}
	if c.Reference == "" {
		r.Notes += fmt.Sprintf(" No canonical reference matches this tokenizer (best agreement %.1f%% across %d reference(s)), so its tokens were not compared.",
			100*c.Match, c.Candidates)
		return r
	}
	var leads []checks.Finding
	leads = append(leads, c.Changed...)
	if c.Missing > 0 {
		leads = append(leads, checks.Finding{Pattern: "tokenizer-vocabulary-shorter",
			Span:   fmt.Sprintf("%d of the reference's tokens absent", c.Missing),
			Detail: "the vocabulary ends before the canonical " + c.Reference + " tokenizer does"})
	}
	summary := fmt.Sprintf("Compared with the canonical %s tokenizer (%.2f%% of ids agree): %d ordinary token(s) changed, %d special or reserved token(s) renamed, %d token(s) added past the reference.",
		c.Reference, 100*c.Match, len(c.Changed), c.SpecialChanged, c.Added)
	if len(leads) > 0 {
		r.Findings = append(r.Findings, leads...)
		r.Status = checks.Lead
		r.Notes = summary + " Changed: " + spans(leads) + ". Needs review. " + r.Notes
		return r
	}
	r.Notes += " " + summary
	return r
}

// GGUFSpecial reports whether a GGUF token is special by its token type.
func GGUFSpecial(t gguf.Tokenizer) func(int) bool {
	return func(id int) bool {
		if id >= len(t.TokenTypes) {
			return false
		}
		switch t.TokenTypes[id] {
		case gguf.TokenUnknown, gguf.TokenControl, gguf.TokenUserDefined, gguf.TokenUnused:
			return true
		}
		return false
	}
}
