package license

import (
	"bytes"
	"strings"
)

// Card is what a model card's YAML front matter says about the model's
// license and lineage: the license, license_name, license_link, and
// base_model keys. Nothing else in the card is read.
type Card struct {
	License     []string
	LicenseName []string
	LicenseLink []string
	BaseModels  []string
}

// maxValue bounds one front-matter value kept from a card.
const maxValue = 512

// ReadCard reads a README.md's front matter: the lines between a leading
// "---" and the next. It understands what model cards write for these keys:
// a plain or quoted value, an inline [a, b] list, a "- item" block list, and
// a folded or literal block scalar (>-, |). Indented keys belong to another
// key's value and are not read. A card with no front matter says nothing.
func ReadCard(readme []byte) Card {
	text := string(bytes.TrimPrefix(readme, []byte("\xef\xbb\xbf")))
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != "---" {
		return Card{}
	}
	var c Card
	for i := 1; i < len(lines); i++ {
		line := lines[i]
		if t := strings.TrimSpace(line); t == "---" || t == "..." {
			break
		}
		if line == "" || line[0] == ' ' || line[0] == '\t' || line[0] == '#' || line[0] == '-' {
			continue
		}
		key, raw, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		var dst *[]string
		switch strings.TrimSpace(key) {
		case "license":
			dst = &c.License
		case "license_name":
			dst = &c.LicenseName
		case "license_link":
			dst = &c.LicenseLink
		case "base_model":
			dst = &c.BaseModels
		default:
			continue
		}
		vals, next := values(raw, lines, i+1)
		*dst = append(*dst, vals...)
		i = next - 1
	}
	return c
}

// values reads one key's value starting on its own line (raw) and the lines
// after it (from index next), returning the values and the index of the
// first line it did not consume.
func values(raw string, lines []string, next int) ([]string, int) {
	v := strings.TrimSpace(raw)
	switch {
	case v == "":
		// A block list on the following lines.
		var out []string
		for next < len(lines) {
			t := strings.TrimSpace(lines[next])
			item, ok := strings.CutPrefix(t, "-")
			if !ok || (len(item) > 0 && item[0] != ' ') {
				break
			}
			if s := scalar(item); s != "" {
				out = append(out, s)
			}
			next++
		}
		return out, next
	case strings.HasPrefix(v, ">") || strings.HasPrefix(v, "|"):
		// A block scalar: the indented lines that follow, folded.
		var parts []string
		for next < len(lines) && (lines[next] == "" || lines[next][0] == ' ' || lines[next][0] == '\t') {
			if t := strings.TrimSpace(lines[next]); t != "" {
				parts = append(parts, t)
			}
			next++
		}
		if s := bound(strings.Join(parts, " ")); s != "" {
			return []string{s}, next
		}
		return nil, next
	case strings.HasPrefix(v, "["):
		var out []string
		for _, item := range strings.Split(strings.TrimSuffix(strings.TrimPrefix(v, "["), "]"), ",") {
			if s := scalar(item); s != "" {
				out = append(out, s)
			}
		}
		return out, next
	}
	if s := scalar(v); s != "" {
		return []string{s}, next
	}
	return nil, next
}

// scalar unquotes a plain or quoted YAML scalar and drops a trailing comment.
func scalar(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') {
		if end := strings.IndexByte(s[1:], s[0]); end >= 0 {
			return bound(s[1 : end+1])
		}
	}
	if i := strings.Index(s, " #"); i >= 0 {
		s = s[:i]
	}
	return bound(strings.TrimSpace(s))
}

func bound(s string) string { return clip(s, maxValue) }
