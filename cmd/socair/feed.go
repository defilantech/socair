package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/feed"
)

// feedCmd builds and checks signed feeds.
//
//	socair feed sign <dir> --key <key> --issuer <name> --version <v> --expires <RFC 3339> [--description <text>]
//	socair feed verify <dir> --keys <key.pub|dir>
func feedCmd(args []string) error {
	const usage = "usage: socair feed sign <dir> --key <key> --issuer <name> --version <v> --expires <RFC 3339> [--description <text>]\n" +
		"       socair feed verify <dir> --keys <key.pub|dir>"
	if len(args) == 0 {
		return errors.New(usage)
	}
	fs := parseFlags(args[1:])
	if len(fs.pos) != 1 {
		return errors.New(usage)
	}
	dir := fs.pos[0]
	switch args[0] {
	case "sign":
		if fs.val("key") == "" || fs.val("issuer") == "" || fs.val("version") == "" || fs.val("expires") == "" {
			return errors.New(usage)
		}
		k, err := attest.LoadPrivateKey(fs.val("key"))
		if err != nil {
			return err
		}
		info := feed.Info{
			Issuer: fs.val("issuer"), Version: fs.val("version"), Description: fs.val("description"),
			Issued: time.Now().UTC().Format(time.RFC3339), Expires: fs.val("expires"),
		}
		if err := feed.Sign(dir, info, k.ID, k.Sign); err != nil {
			return err
		}
		fmt.Printf("signed feed %s %s in %s with key %s\n", info.Issuer, info.Version, dir, attest.ShortID(k.ID))
		return nil
	case "verify":
		if fs.val("keys") == "" {
			return errors.New(usage)
		}
		keys, err := attest.LoadKeyring(fs.val("keys"))
		if err != nil {
			return err
		}
		f, err := feed.Load(dir, keys, time.Now())
		if err != nil {
			return err
		}
		fmt.Printf("verified: %s\n  %d known-bad hashes, %d reviewed templates, %d canonical tokenizers\n",
			f.Describe(), len(f.Denylist), len(f.Templates), len(f.Tokenizers))
		return nil
	}
	return errors.New(usage)
}
