package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/defilantech/socair/internal/engine"
	"github.com/defilantech/socair/internal/render/cyclonedx"
	"github.com/defilantech/socair/internal/report"
)

// scan runs the engine over one artifact (Tier 1, and Tier 2 when
// SOCAIR_TIER2_HELPER is set) and prints the report document as JSON, or with
// --format cyclonedx the CycloneDX ML-BOM derived from it. Output is gated on
// the document validating. With --store or SOCAIR_STORE, a configured feed
// is held to the store's record of the newest feed it has used.
func scan(args []string) error {
	var path, format, store string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--format":
			i++
			if i >= len(args) {
				return fmt.Errorf("--format needs report or cyclonedx")
			}
			format = args[i]
		case strings.HasPrefix(a, "--format="):
			format = strings.TrimPrefix(a, "--format=")
		case a == "--store":
			i++
			if i >= len(args) || strings.HasPrefix(args[i], "-") {
				return fmt.Errorf("--store needs a path")
			}
			store = args[i]
		case strings.HasPrefix(a, "--store="):
			store = strings.TrimPrefix(a, "--store=")
		case strings.HasPrefix(a, "-"):
			return fmt.Errorf("unknown flag %q", a)
		default:
			if path != "" {
				return fmt.Errorf("unexpected extra argument %q", a)
			}
			path = a
		}
	}
	if path == "" {
		return fmt.Errorf("usage: socair scan <path> [--format report|cyclonedx] [--store <path>]")
	}
	// With a store (--store, then SOCAIR_STORE), a configured feed is checked
	// against the newest feed the store has used; without one, nothing is.
	if store == "" {
		store = strings.TrimSpace(os.Getenv("SOCAIR_STORE"))
	}
	switch format {
	case "", "report", "cyclonedx":
	default:
		return fmt.Errorf("unknown --format %q: want report or cyclonedx", format)
	}

	d, err := engine.ScanWith(path, engine.ModeFull, engine.Inputs{Feed: feedHook(store)})
	if err != nil {
		return err
	}
	if problems := report.Validate(d); len(problems) != 0 {
		return fmt.Errorf("report did not validate: %v", problems)
	}
	// The report goes to standard output; what would close each gap goes to
	// standard error, for the person reading, and is no part of the report.
	defer fmt.Fprint(os.Stderr, engine.Summary(d))
	if format == "cyclonedx" {
		return cyclonedx.Render(os.Stdout, d)
	}
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}
