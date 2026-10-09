package airlock

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Selection narrows a whole-repo pull to the files an operator means to carry
// across: the weights, configs, and tokenizer a serving stack loads, without a
// repo's reference code, papers, or alternate copies of the weights.
//
// Patterns match a file's path in the repo the way huggingface_hub's
// allow_patterns and ignore_patterns do (Python's fnmatch), so habits from
// `hf download --include` carry over: * matches any run of characters,
// slashes included; ? matches one character; [seq] and [!seq] match one
// character in or not in seq; and a pattern ending in / matches everything
// under that directory. With Include set, a file must match one of them; a
// file matching any Exclude is left out either way.
type Selection struct {
	Include []string `json:"include,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
}

func (s Selection) empty() bool { return len(s.Include) == 0 && len(s.Exclude) == 0 }

// String renders the selection as the pull's flags, for the log.
func (s Selection) String() string {
	var parts []string
	for _, p := range s.Include {
		parts = append(parts, "--include "+p)
	}
	for _, p := range s.Exclude {
		parts = append(parts, "--exclude "+p)
	}
	return strings.Join(parts, " ")
}

type selector struct{ include, exclude []*regexp.Regexp }

func (s Selection) compile() (*selector, error) {
	var m selector
	for _, list := range []struct {
		patterns []string
		into     *[]*regexp.Regexp
	}{{s.Include, &m.include}, {s.Exclude, &m.exclude}} {
		for _, p := range list.patterns {
			r, err := globRegexp(p)
			if err != nil {
				return nil, err
			}
			*list.into = append(*list.into, r)
		}
	}
	return &m, nil
}

func (m *selector) keeps(p string) bool {
	if len(m.include) > 0 && !anyMatch(m.include, p) {
		return false
	}
	return !anyMatch(m.exclude, p)
}

func anyMatch(rs []*regexp.Regexp, p string) bool {
	for _, r := range rs {
		if r.MatchString(p) {
			return true
		}
	}
	return false
}

// globRegexp translates one pattern to an anchored regular expression, as
// fnmatch.translate does. An unclosed [ is refused rather than read as a
// literal, so a typo is not silently a pattern that matches nothing.
func globRegexp(pattern string) (*regexp.Regexp, error) {
	if strings.TrimSpace(pattern) == "" {
		return nil, errors.New("an empty selection pattern")
	}
	glob := pattern
	if strings.HasSuffix(glob, "/") {
		glob += "*"
	}
	rs := []rune(glob)
	var b strings.Builder
	b.WriteString(`(?s)^`)
	for i := 0; i < len(rs); i++ {
		switch r := rs[i]; r {
		case '*':
			b.WriteString(`.*`)
		case '?':
			b.WriteString(`.`)
		case '[':
			j := i + 1
			if j < len(rs) && rs[j] == '!' {
				j++
			}
			if j < len(rs) && rs[j] == ']' {
				j++
			}
			for j < len(rs) && rs[j] != ']' {
				j++
			}
			if j >= len(rs) {
				return nil, fmt.Errorf("selection pattern %q has an unclosed [", pattern)
			}
			class := rs[i+1 : j]
			b.WriteByte('[')
			if len(class) > 0 && class[0] == '!' {
				b.WriteByte('^')
				class = class[1:]
			}
			for k, c := range class {
				if c == '\\' || c == ']' || c == '[' || (c == '^' && k == 0) {
					b.WriteByte('\\')
				}
				b.WriteRune(c)
			}
			b.WriteByte(']')
			i = j
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString(`$`)
	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil, fmt.Errorf("selection pattern %q: %w", pattern, err)
	}
	return re, nil
}
