// Command atlasgen writes the pinned list of MITRE ATLAS IDs and names that
// the report package's tests hold Socair's mappings and docs to
// (internal/report/testdata/atlas-ids.txt). It reads one release's data file
// in ATLAS's v6 format, which the release attaches as ATLAS-<version>.yaml
// (the same bytes as dist/v6/ATLAS-<version>.yaml at the release tag; the
// older dist/ATLAS.yaml is deprecated and frozen at 5.6.0), and keeps only the
// ID and name of each technique, sub-technique, mitigation, and case study:
//
//	curl -fsSLO https://github.com/mitre-atlas/atlas-data/releases/download/v2026.09/ATLAS-2026.09.yaml
//	go run ./internal/report/atlasgen -tag v2026.09 \
//	  -source https://github.com/mitre-atlas/atlas-data/releases/download/v2026.09/ATLAS-2026.09.yaml \
//	  -notice "Copyright 2021-2026 MITRE" \
//	  ATLAS-2026.09.yaml > internal/report/testdata/atlas-ids.txt
//
// The notice is the copyright line of LICENSE at the same tag. The reader
// handles only the YAML that file uses for these keys (one mapping per
// section, two-space indentation, a name as a plain or single-quoted scalar
// that may fold onto further lines) and stops on anything else rather than
// guess.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
)

type entry struct {
	id, kind, name string
}

var (
	topKey   = regexp.MustCompile(`^([a-z-]+):(.*)$`)
	entryKey = regexp.MustCompile(`^  (AML\.(?:T|M|CS)[0-9]{4}(?:\.[0-9]{3})?):$`)
	fieldKey = regexp.MustCompile(`^    ([a-z-]+):(.*)$`)
	version  = regexp.MustCompile(`^  version:(.*)$`)
)

// sectionPrefix is the ID prefix every entry of a section must have.
var sectionPrefix = map[string]string{"techniques": "AML.T", "mitigations": "AML.M", "case-studies": "AML.CS"}

func kindOf(id string) string {
	switch {
	case strings.HasPrefix(id, "AML.CS"):
		return "case-study"
	case strings.HasPrefix(id, "AML.M"):
		return "mitigation"
	case strings.Count(id, ".") == 2:
		return "sub-technique"
	default:
		return "technique"
	}
}

// scalar decodes a plain or single-quoted YAML scalar that began on one line
// and may continue on more-indented lines (folded with single spaces).
func scalar(first string, more []string) (string, error) {
	parts := []string{strings.TrimSpace(first)}
	for _, m := range more {
		m = strings.TrimSpace(m)
		if m == "" {
			return "", fmt.Errorf("blank line inside a scalar")
		}
		parts = append(parts, m)
	}
	s := strings.Join(parts, " ")
	if s == "" {
		return "", fmt.Errorf("empty scalar")
	}
	switch s[0] {
	case '\'':
		if len(s) < 2 || s[len(s)-1] != '\'' {
			return "", fmt.Errorf("unterminated single-quoted scalar %q", s)
		}
		inner := s[1 : len(s)-1]
		if strings.Contains(strings.ReplaceAll(inner, "''", ""), "'") {
			return "", fmt.Errorf("stray quote in %q", s)
		}
		return strings.ReplaceAll(inner, "''", "'"), nil
	case '"', '|', '>', '&', '*', '!', '[', '{', '%', '@', '`':
		return "", fmt.Errorf("unsupported scalar %q", s)
	}
	if strings.Contains(s, ": ") || strings.Contains(s, " #") {
		return "", fmt.Errorf("unsupported plain scalar %q", s)
	}
	return s, nil
}

// continuation returns the lines after i that continue a scalar begun at
// indent: lines indented further than it.
func continuation(lines []string, i, indent int) []string {
	var more []string
	for j := i + 1; j < len(lines); j++ {
		l := lines[j]
		if len(l)-len(strings.TrimLeft(l, " ")) <= indent || strings.TrimSpace(l) == "" {
			break
		}
		more = append(more, l)
	}
	return more
}

func parse(data []byte) (format, ver string, entries []entry, err error) {
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	section := ""
	var cur *entry
	var curID string
	flush := func() error {
		if cur == nil {
			return nil
		}
		if cur.name == "" || curID != cur.id {
			return fmt.Errorf("%s: missing name, or id field %q does not match its key", cur.id, curID)
		}
		entries = append(entries, *cur)
		cur, curID = nil, ""
		return nil
	}
	for i, l := range lines {
		if m := topKey.FindStringSubmatch(l); m != nil {
			if err := flush(); err != nil {
				return "", "", nil, err
			}
			section = m[1]
			if section == "format-version" {
				format = strings.TrimSpace(m[2])
			}
			continue
		}
		if section == "collection" {
			if m := version.FindStringSubmatch(l); m != nil {
				if ver, err = scalar(m[1], continuation(lines, i, 2)); err != nil {
					return "", "", nil, fmt.Errorf("collection version: %v", err)
				}
			}
			continue
		}
		prefix, tracked := sectionPrefix[section]
		if !tracked {
			continue
		}
		if m := entryKey.FindStringSubmatch(l); m != nil {
			if err := flush(); err != nil {
				return "", "", nil, err
			}
			if !strings.HasPrefix(m[1], prefix) || (prefix == "AML.T" && strings.HasPrefix(m[1], "AML.TA")) {
				return "", "", nil, fmt.Errorf("line %d: %s in section %s", i+1, m[1], section)
			}
			cur = &entry{id: m[1], kind: kindOf(m[1])}
			continue
		}
		if strings.HasPrefix(l, "  ") && !strings.HasPrefix(l, "   ") && strings.TrimSpace(l) != "" {
			return "", "", nil, fmt.Errorf("line %d: unexpected key %q in section %s", i+1, strings.TrimSpace(l), section)
		}
		if cur == nil {
			continue
		}
		if m := fieldKey.FindStringSubmatch(l); m != nil {
			switch m[1] {
			case "name":
				if cur.name != "" {
					return "", "", nil, fmt.Errorf("%s: two names", cur.id)
				}
				if cur.name, err = scalar(m[2], continuation(lines, i, 4)); err != nil {
					return "", "", nil, fmt.Errorf("%s name: %v", cur.id, err)
				}
			case "id":
				if curID, err = scalar(m[2], nil); err != nil {
					return "", "", nil, fmt.Errorf("%s id: %v", cur.id, err)
				}
			}
		}
	}
	if err := flush(); err != nil {
		return "", "", nil, err
	}
	if format == "" || ver == "" || len(entries) == 0 {
		return "", "", nil, fmt.Errorf("not an ATLAS v6 data file: format-version %q, version %q, %d entries", format, ver, len(entries))
	}
	return format, ver, entries, nil
}

var group = map[string]int{"technique": 0, "sub-technique": 0, "mitigation": 1, "case-study": 2}

func main() {
	tag := flag.String("tag", "", "atlas-data release tag the file came from, v<version>")
	source := flag.String("source", "", "URL the file was downloaded from")
	notice := flag.String("notice", "", "copyright line of the atlas-data LICENSE at that tag")
	flag.Parse()
	if *tag == "" || *source == "" || *notice == "" || flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: atlasgen -tag <tag> -source <url> -notice <copyright line> <ATLAS-<version>.yaml>")
		os.Exit(2)
	}
	data, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	format, ver, entries, err := parse(data)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *tag != "v"+ver {
		fmt.Fprintf(os.Stderr, "the file is ATLAS %s, not the release tagged %s\n", ver, *tag)
		os.Exit(1)
	}
	names := map[string]string{}
	count := map[string]int{}
	for _, e := range entries {
		if _, dup := names[e.id]; dup {
			fmt.Fprintf(os.Stderr, "%s appears twice\n", e.id)
			os.Exit(1)
		}
		names[e.id] = e.name
		count[e.kind]++
	}
	for i, e := range entries {
		if e.kind == "sub-technique" {
			parent, ok := names[e.id[:strings.LastIndex(e.id, ".")]]
			if !ok {
				fmt.Fprintf(os.Stderr, "%s has no parent technique\n", e.id)
				os.Exit(1)
			}
			entries[i].name = parent + ": " + e.name
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if gi, gj := group[entries[i].kind], group[entries[j].kind]; gi != gj {
			return gi < gj
		}
		return entries[i].id < entries[j].id
	})
	sum := sha256.Sum256(data)

	w := bufio.NewWriter(os.Stdout)
	fmt.Fprintf(w, "# MITRE ATLAS %s: the ID and name of every technique, sub-technique, mitigation,\n", ver)
	fmt.Fprintf(w, "# and case study, pruned from the release's data file (every other field dropped).\n")
	fmt.Fprintf(w, "# A sub-technique is named \"<technique>: <sub-technique>\", as ATLAS shows it.\n")
	fmt.Fprintf(w, "# ATLAS data: %s, licensed under the Apache License, Version 2.0:\n", *notice)
	fmt.Fprintf(w, "# https://github.com/mitre-atlas/atlas-data/blob/%s/LICENSE\n", *tag)
	fmt.Fprintf(w, "# Regenerate with internal/report/atlasgen:\n")
	fmt.Fprintf(w, "#   curl -fsSLO %s\n", *source)
	fmt.Fprintf(w, "#   go run ./internal/report/atlasgen -tag %s -source %s -notice %q %s > internal/report/testdata/atlas-ids.txt\n",
		*tag, *source, *notice, path.Base(*source))
	fmt.Fprintf(w, "# source: %s\n", *source)
	fmt.Fprintf(w, "# tag: %s\n", *tag)
	fmt.Fprintf(w, "# sha256: %s\n", hex.EncodeToString(sum[:]))
	fmt.Fprintf(w, "# format-version: %s\n", format)
	fmt.Fprintf(w, "# version: %s\n", ver)
	fmt.Fprintf(w, "# counts: %d techniques, %d sub-techniques, %d mitigations, %d case studies\n",
		count["technique"], count["sub-technique"], count["mitigation"], count["case-study"])
	for _, e := range entries {
		fmt.Fprintf(w, "%s\t%s\t%s\n", e.id, e.kind, e.name)
	}
	if err := w.Flush(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
