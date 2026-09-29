package main

import (
	"encoding/json"
	"fmt"

	"github.com/defilantech/socair/internal/engine"
	"github.com/defilantech/socair/internal/report"
)

// scan runs the Tier 1 engine over one artifact and prints the report document
// as JSON. The render step is gated on the document validating.
func scan(path string) error {
	d, err := engine.Scan(path)
	if err != nil {
		return err
	}
	if problems := report.Validate(d); len(problems) != 0 {
		return fmt.Errorf("report did not validate: %v", problems)
	}
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}
