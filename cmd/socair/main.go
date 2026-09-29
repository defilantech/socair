// Command socair is the engine and CLI for Socair model assurance.
//
// The CLI is a thin caller of the same engine the click-ops wizard uses. It is
// not the product surface; it is the harness.
package main

import (
	"fmt"
	"os"
)

const version = "0.1.0-dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version":
		fmt.Printf("socair %s\n", version)
	case "inspect":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: socair inspect <path>")
			os.Exit(2)
		}
		if err := inspect(os.Args[2]); err != nil {
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
`)
}
