package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/defilantech/socair/internal/engine"
	"github.com/defilantech/socair/internal/render"
	"github.com/defilantech/socair/internal/render/cyclonedx"
	"github.com/defilantech/socair/internal/render/pdf"
	"github.com/defilantech/socair/internal/render/sarif"
	"github.com/defilantech/socair/internal/report"
)

// renderCmd scans a full artifact and writes the attestation. Output is gated
// on the document validating, so an unfilable report is never rendered.
//
//	socair render <path>                   HTML to stdout
//	socair render <path> --pdf out.pdf     PDF
//	socair render <path> --sarif out.json  SARIF
//	socair render <path> --cyclonedx out.json  CycloneDX 1.6 ML-BOM
//
// Flags may appear before or after the path.
func renderCmd(args []string) error {
	var path, pdfOut, sarifOut, bomOut string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--pdf":
			i++
			if i >= len(args) {
				return fmt.Errorf("--pdf needs a file path")
			}
			pdfOut = args[i]
		case strings.HasPrefix(a, "--pdf="):
			pdfOut = strings.TrimPrefix(a, "--pdf=")
		case a == "--sarif":
			i++
			if i >= len(args) {
				return fmt.Errorf("--sarif needs a file path")
			}
			sarifOut = args[i]
		case strings.HasPrefix(a, "--sarif="):
			sarifOut = strings.TrimPrefix(a, "--sarif=")
		case a == "--cyclonedx":
			i++
			if i >= len(args) {
				return fmt.Errorf("--cyclonedx needs a file path")
			}
			bomOut = args[i]
		case strings.HasPrefix(a, "--cyclonedx="):
			bomOut = strings.TrimPrefix(a, "--cyclonedx=")
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
		return fmt.Errorf("usage: socair render <path> [--pdf out.pdf] [--sarif out.json] [--cyclonedx out.json]")
	}

	d, err := engine.Scan(path)
	if err != nil {
		return err
	}
	if problems := report.Validate(d); len(problems) != 0 {
		return fmt.Errorf("report did not validate, refusing to render: %v", problems)
	}

	wrote := false
	if pdfOut != "" {
		if err := writeFile(pdfOut, func(f *os.File) error { return pdf.RenderPDF(f, d) }); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "wrote", pdfOut)
		wrote = true
	}
	if sarifOut != "" {
		if err := writeFile(sarifOut, func(f *os.File) error { return sarif.Render(f, d) }); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "wrote", sarifOut)
		wrote = true
	}
	if bomOut != "" {
		if err := writeFile(bomOut, func(f *os.File) error { return cyclonedx.Render(f, d) }); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "wrote", bomOut)
		wrote = true
	}
	if wrote {
		return nil
	}
	return render.Render(os.Stdout, d)
}

func writeFile(path string, fn func(*os.File) error) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return fn(f)
}
