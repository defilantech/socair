package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/engine"
	"github.com/defilantech/socair/internal/render"
	"github.com/defilantech/socair/internal/render/cyclonedx"
	"github.com/defilantech/socair/internal/render/pdf"
	"github.com/defilantech/socair/internal/render/sarif"
	"github.com/defilantech/socair/internal/report"
)

// renderCmd writes a report as HTML, PDF, SARIF, or a CycloneDX BOM. The
// report comes from exactly one source: a scan of the artifact at a path, a
// saved report document (--report), or a signed attestation (--attestation),
// which is verified as verify verifies it before anything is written. Output
// is gated on the document validating, so an unfilable report is never
// rendered.
//
//	socair render <path>                   scan, then HTML to stdout (unsigned)
//	socair render --report r.json          a saved report, unsigned
//	socair render --attestation r.dsse.json (--trusted <key.pub|dir> | --store <path>) [--artifact <path>]
//	                                       the signed attestation, verified
//	  --pdf out.pdf  --sarif out.json  --cyclonedx out.json   instead of HTML to stdout
//
// Flags may appear before or after the path.
func renderCmd(args []string) error {
	fs := parseFlags(args)
	for k := range fs.vals {
		switch k {
		case "pdf", "sarif", "cyclonedx", "report", "attestation", "trusted", "store", "artifact":
		default:
			return fmt.Errorf("unknown flag %q", "--"+k)
		}
	}
	for _, k := range []string{"pdf", "sarif", "cyclonedx", "report", "attestation", "trusted", "store", "artifact"} {
		if fs.bare[k] {
			return fmt.Errorf("--%s needs a value", k)
		}
	}
	if len(fs.pos) > 1 {
		return fmt.Errorf("unexpected extra argument %q", fs.pos[1])
	}
	pdfOut, sarifOut, bomOut := fs.val("pdf"), fs.val("sarif"), fs.val("cyclonedx")

	sources := 0
	for _, given := range []bool{len(fs.pos) == 1, fs.val("report") != "", fs.val("attestation") != ""} {
		if given {
			sources++
		}
	}
	if sources != 1 {
		return fmt.Errorf("usage: socair render (<path> | --report <report.json> | --attestation <r.dsse.json> (--trusted <key.pub|dir> | --store <path>) [--artifact <path>]) [--pdf out.pdf] [--sarif out.json] [--cyclonedx out.json]")
	}

	var d *report.Document
	switch {
	case fs.val("attestation") != "":
		v, err := renderAttestation(fs)
		if err != nil {
			return err
		}
		d = v
	case fs.val("report") != "":
		v, err := renderReportFile(fs.val("report"))
		if err != nil {
			return err
		}
		d = v
	default:
		v, err := engine.Scan(fs.pos[0])
		if err != nil {
			return err
		}
		d = v
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

// renderAttestation verifies a signed attestation against the issuer keys
// the flags name, exactly as verify does (the signature, the statement, the
// recorded document hash, the document's validity, and the issuer it
// claims), and, with --artifact, that the file or directory is its subject.
// Only then is its document rendered, as signed.
func renderAttestation(fs *flagSet) (*report.Document, error) {
	if fs.val("trusted") == "" && fs.val("store") == "" {
		return nil, fmt.Errorf("--attestation needs --trusted <key.pub|dir> or --store <path> to verify it against")
	}
	env, err := os.ReadFile(fs.val("attestation"))
	if err != nil {
		return nil, err
	}
	ring, names, err := issuerKeys(fs)
	if err != nil {
		return nil, err
	}
	v, err := attest.Verify(env, ring)
	if err != nil {
		return nil, err
	}
	if _, _, err := v.Issuer(names); err != nil {
		return nil, err
	}
	if a := fs.val("artifact"); a != "" {
		if err := bindArtifact(a, v.SHA256, v.Document.Artifact.Files, attest.ErrVerify, "the attestation"); err != nil {
			return nil, err
		}
	} else {
		fmt.Fprintln(os.Stderr, "the artifact itself was not checked; pass --artifact <path> to bind it")
	}
	return &v.Document, nil
}

// renderReportFile reads a saved report document, strictly, as a draft. A
// signature is proven by its envelope, never by a report's own fields, so a
// document that names a signer or a signed document hash is refused rather
// than rendered without the UNSIGNED mark.
func renderReportFile(path string) (*report.Document, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var d report.Document
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("%s is not a Socair report document: %v", path, err)
	}
	if d.Verification.SignerKeyID != "" || d.Verification.DocumentHash != "" || d.Header.DocumentHash != "" {
		return nil, fmt.Errorf("%s names a signature, which only its envelope can prove; render the signed attestation with --attestation <r.dsse.json> --trusted <key.pub|dir>", path)
	}
	return &d, nil
}

func writeFile(path string, fn func(*os.File) error) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return fn(f)
}
