package main

import (
	"fmt"
	"sort"

	"github.com/defilantech/socair/internal/engine"
)

// corpus sweeps every GGUF under a directory in header-only mode and prints a
// table. It is the false-positive baseline tool and never touches the network.
func corpus(root string) error {
	entries, err := engine.Corpus(root, engine.ModeHeaders)
	if err != nil {
		return err
	}

	fmt.Printf("%-46s %-14s %-9s %-11s %-14s\n", "model", "hero", "structure", "tokenizer", "quant")
	fmt.Println("-----------------------------------------------------------------------------------------------------------")
	for _, e := range entries {
		if e.Error != "" {
			fmt.Printf("%-46s ERROR: %s\n", shortPath(e.Path), e.Error)
			continue
		}
		fmt.Printf("%-46s %-14s %-9s %-11s %-14s\n",
			shortPath(e.Path),
			e.Checks["Chat template (hero)"],
			e.Checks["Format and structure"],
			e.Checks["Tokenizer config"],
			e.Checks["Quant match"],
		)
	}

	c := engine.Counts(entries)
	fmt.Printf("\nfiles=%d pass=%d fail=%d not_tested=%d error=%d\n",
		len(entries), c["PASS"], c["FAIL"], c["NOT_TESTED"], c["error"])

	fmt.Println("\nper-check tally (PASS / FAIL / NOT_TESTED):")
	tally := map[string]map[string]int{}
	for _, e := range entries {
		if e.Error != "" {
			continue
		}
		for name, status := range e.Checks {
			if tally[name] == nil {
				tally[name] = map[string]int{}
			}
			tally[name][status]++
		}
	}
	names := make([]string, 0, len(tally))
	for name := range tally {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		t := tally[name]
		fmt.Printf("  %-30s %d / %d / %d\n", name, t["PASS"], t["FAIL"], t["NOT_TESTED"])
	}

	fmt.Println("\nFAILs (these are the false positives to investigate):")
	any := false
	for _, e := range entries {
		if len(e.Fails) == 0 {
			continue
		}
		any = true
		fmt.Printf("  %s -> %v\n", shortPath(e.Path), e.Fails)
	}
	if !any {
		fmt.Println("  none")
	}
	return nil
}

func shortPath(p string) string {
	const max = 44
	if len(p) <= max {
		return p
	}
	return "..." + p[len(p)-(max-3):]
}
