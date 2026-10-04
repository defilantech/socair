package main

import (
	"errors"
	"fmt"

	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/inventory"
)

// inventoryCmd: socair inventory verify <dir> --trusted <key.pub|dir> [--allow-unsigned]
func inventoryCmd(args []string) error {
	const usage = "usage: socair inventory verify <dir> --trusted <key.pub|dir> [--allow-unsigned]"
	if len(args) == 0 || args[0] != "verify" {
		return errors.New(usage)
	}
	fs := parseFlags(args[1:])
	if len(fs.pos) != 1 || fs.val("trusted") == "" {
		return errors.New(usage)
	}
	ring, err := attest.LoadKeyring(fs.val("trusted"))
	if err != nil {
		return err
	}
	v, err := inventory.Verify(fs.pos[0], ring, inventory.VerifyOptions{AllowUnsigned: fs.has("allow-unsigned")})
	if err != nil {
		return err
	}
	signer := "UNSIGNED (checked with --allow-unsigned)"
	if v.SignerKeyID != "" {
		signer = "signed by key " + attest.ShortID(v.SignerKeyID)
	}
	fmt.Printf("verified: %d approved model(s) as of %s, log head %s, %s\n", len(v.Predicate.Models), v.Predicate.GeneratedUTC, v.Predicate.LogHead, signer)
	return nil
}
