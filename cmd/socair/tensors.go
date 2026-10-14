package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/defilantech/socair/internal/tensors"
)

// errNotIdentical is tensors diff's result when the two differ: exit status
// 1, with the comparison printed, and no "error:" line.
var errNotIdentical = errors.New("not identical")

// tensorsCmd writes a model's tensor manifest, or compares two models (or
// manifests) tensor by tensor. docs/tensors.md describes both.
//
//	socair tensors <path> [--out m.json]
//	socair tensors diff <artifact|manifest> <reference artifact|manifest> [--out c.json]
func tensorsCmd(args []string) error {
	fs := parseFlags(args)
	for k := range fs.vals {
		if k != "out" {
			return fmt.Errorf("unknown flag --%s", k)
		}
	}
	if len(fs.pos) > 0 && fs.pos[0] == "diff" {
		if len(fs.pos) != 3 {
			return errors.New("usage: socair tensors diff <artifact|manifest> <reference artifact|manifest> [--out <file>]")
		}
		a, err := tensors.Open(fs.pos[1])
		if err != nil {
			return err
		}
		r, err := tensors.Open(fs.pos[2])
		if err != nil {
			return err
		}
		c := tensors.Compare(a, r)
		if err := writeJSON(c, fs.val("out")); err != nil {
			return err
		}
		keys := []tensors.Outcome{tensors.Identical, tensors.SameValues, tensors.Differs, tensors.NotComparable, tensors.OnlyArtifact, tensors.OnlyReference}
		line := ""
		for _, k := range keys {
			if n := c.Counts[k]; n > 0 {
				if line != "" {
					line += ", "
				}
				line += fmt.Sprintf("%d %s", n, k)
			}
		}
		if c.Identical() {
			fmt.Fprintf(os.Stderr, "identical: every tensor matches under its own name (%s)\n", line)
			return nil
		}
		if c.CrossFormat {
			line += "; across file formats, so names were not compared"
		}
		fmt.Fprintf(os.Stderr, "not identical: %s\n", line)
		return errNotIdentical
	}
	if len(fs.pos) != 1 {
		return errors.New("usage: socair tensors <path> [--out <file>]")
	}
	m, err := tensors.Open(fs.pos[0])
	if err != nil {
		return err
	}
	if err := writeJSON(m, fs.val("out")); err != nil {
		return err
	}
	withValues := 0
	for _, t := range m.Tensors {
		if t.Values != "" {
			withValues++
		}
	}
	fmt.Fprintf(os.Stderr, "%d tensors (%d with value hashes), %d unread\n", len(m.Tensors), withValues, len(m.Unread))
	return nil
}

func writeJSON(v any, out string) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if out == "" {
		_, err = os.Stdout.Write(b)
		return err
	}
	return os.WriteFile(out, b, 0o644)
}
