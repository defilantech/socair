package main

import (
	"fmt"
	"os"

	"github.com/defilantech/socair/internal/demo"
	"github.com/defilantech/socair/internal/render"
	"github.com/defilantech/socair/internal/report"
)

// demoCmd renders the fabricated sample attestation for a sales conversation,
// marked SAMPLE on every page. No real artifact is read.
func demoCmd() error {
	d, err := demo.Document()
	if err != nil {
		return err
	}
	if problems := report.Validate(d); len(problems) != 0 {
		return fmt.Errorf("sample report did not validate: %v", problems)
	}
	return render.RenderWith(os.Stdout, d, render.Options{Sample: true})
}
