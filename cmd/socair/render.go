package main

import (
	"fmt"
	"os"

	"github.com/defilantech/socair/internal/engine"
	"github.com/defilantech/socair/internal/render"
	"github.com/defilantech/socair/internal/report"
)

// renderCmd scans a full artifact and writes the HTML attestation. It is gated
// on the document validating, so an unfilable report is never rendered.
func renderCmd(path string) error {
	d, err := engine.Scan(path)
	if err != nil {
		return err
	}
	if problems := report.Validate(d); len(problems) != 0 {
		return fmt.Errorf("report did not validate, refusing to render: %v", problems)
	}
	return render.Render(os.Stdout, d)
}
