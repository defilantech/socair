// Command socair is the engine and CLI for Socair model assurance.
//
// The CLI is a thin caller of the same engine the click-ops wizard uses. It is
// not the product surface; it is the harness.
package main

import (
	"fmt"
	"github.com/defilantech/socair/internal/engine"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version":
		fmt.Printf("socair %s\n", engine.Version)
	case "inspect":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: socair inspect <path>")
			os.Exit(2)
		}
		if err := inspect(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "scan":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: socair scan <path> [--format report|cyclonedx]")
			os.Exit(2)
		}
		if err := scan(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "corpus":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: socair corpus <dir>")
			os.Exit(2)
		}
		if err := corpus(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "template":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: socair template <path>")
			os.Exit(2)
		}
		if err := templateDump(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "render":
		if err := renderCmd(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "airlock":
		if err := airlockCmd(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "serve":
		if err := serveCmd(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "key":
		if err := keyCmd(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "sign":
		if err := signCmd(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "feed":
		if err := feedCmd(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "accept":
		if err := acceptCmd(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "verify":
		if err := verifyCmd(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "demo":
		if err := demoCmd(); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `socair, model assurance engine

Usage:
  socair version
  socair inspect <path>    read an artifact and print its manifest as JSON
  socair scan <path>       run the Tier 1 checks and print the report as JSON
  socair corpus <dir>      sweep every GGUF under a directory, headers only
  socair template <path>   print the chat template and hero-check findings
  socair render <path>     scan and write the HTML attestation to stdout
  socair key gen --out <prefix> [--issuer <name>]   create an Ed25519 signing key pair
  socair sign --key <key> --report <report.json>   sign a report as a DSSE attestation
  socair feed sign <dir> --key <key> --issuer <name> --version <v> --expires <time>
                           sign a reference-data feed (denylist, templates, tokenizers)
  socair feed verify <dir> --keys <key.pub|dir>   check a feed before importing it
  socair feed tokenizer-table <tokenizer.json|model.gguf> --name <name>
                           write a canonical tokenizer table for a feed or SOCAIR_TOKENIZER_REFERENCE
  socair accept --attestation <r.dsse.json> --key <acceptor.key> --by <name> --expires <time>
                           sign an acceptance of a withheld report's untested surfaces
  socair sign --key <key> --attestation <r.dsse.json> --acceptance <a.dsse.json>
                           re-issue it as authorized with conditions
  socair verify <attestation> --trusted <key.pub|dir> [--artifact <path>]
                           verify an attestation, and that a file is its artifact
  socair airlock init <store>   create the store, staging, and activity log
  socair airlock pull      pull a file, or a whole repo at a pinned commit, into staging
  socair airlock ingest    resolve a local file or directory, or an offline HF cache entry
  socair airlock trust add <key.pub>   trust a signing key for promotion
  socair airlock promote   promote a file or model directory with a signed attestation
  socair airlock log       print the airlock activity log (--verify checks its hash chain)
  socair serve             run the engine HTTP/JSON API for the click-ops wizard
  socair demo              write the SAMPLE attestation for sales
`)
}
