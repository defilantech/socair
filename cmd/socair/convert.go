package main

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/defilantech/socair/internal/airlock"
	"github.com/defilantech/socair/internal/attest"
)

// airlockConvert rebuilds a pickle checkpoint as safetensors in staging:
// socair airlock convert <checkpoint> --attestation <a.dsse.json> --key <op.key> [--store <p>].
func airlockConvert(args []string) error {
	fs := parseFlags(args)
	if err := fs.allow("attestation", "key", "store"); err != nil {
		return err
	}
	if len(fs.pos) != 1 || fs.val("attestation") == "" || fs.val("key") == "" || fs.bare["attestation"] || fs.bare["key"] {
		return errors.New("usage: socair airlock convert <checkpoint> --attestation <attestation.dsse.json> --key <operator.key> [--store <path>]")
	}
	s, err := airlock.Open(storeRoot(fs))
	if err != nil {
		return err
	}
	k, err := attest.LoadPrivateKey(fs.val("key"))
	if err != nil {
		return err
	}
	c, err := airlock.Convert(s, fs.pos[0], fs.val("attestation"), k)
	if err != nil {
		return err
	}
	d := c.Derivation
	aliases := 0
	for _, t := range d.Tensors {
		if t.AliasOf != "" {
			aliases++
		}
	}
	fmt.Printf("converted %s (sha256 %s)\n  to %s (sha256 %s)\n  %d tensor(s), %d exact alias(es) written once\nstaged at %s\nderivation record %s\n",
		d.Input.Name, d.Input.Digest["sha256"], d.Output.Name, d.Output.Digest["sha256"], len(d.Tensors), aliases, c.Path, c.Record)
	if len(d.NotCarried) > 0 {
		fmt.Println("not carried from the input:")
		for _, n := range d.NotCarried {
			fmt.Println("  - " + n)
		}
	}
	fmt.Printf("the output is a new artifact: scan, sign, and promote it like any other:\n  socair scan %s > %s\n",
		c.Path, filepath.Join(filepath.Dir(c.Path), airlock.StagedReport))
	return nil
}
