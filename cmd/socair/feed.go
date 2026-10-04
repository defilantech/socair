package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/checks/tokenizer"
	"github.com/defilantech/socair/internal/feed"
	"github.com/defilantech/socair/internal/gguf"
)

// feedCmd builds and checks signed feeds.
//
//	socair feed sign <dir> --key <key> --issuer <name> --version <v> --expires <RFC 3339> [--description <text>]
//	socair feed verify <dir> --keys <key.pub|dir>
//	socair feed tokenizer-table <tokenizer.json|model.gguf> --name <name>
func feedCmd(args []string) error {
	const usage = "usage: socair feed sign <dir> --key <key> --issuer <name> --version <v> --expires <RFC 3339> [--description <text>]\n" +
		"       socair feed verify <dir> --keys <key.pub|dir>\n" +
		"       socair feed tokenizer-table <tokenizer.json|model.gguf> --name <name>   write a canonical tokenizer table to stdout"
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
		fmt.Printf("verified: %s\n  %d known-bad hashes, %d reviewed templates, %d canonical tokenizers, %d tokenizer tables\n",
			f.Describe(), len(f.Denylist), len(f.Templates), len(f.Tokenizers), len(f.TokenizerTables))
		return nil
	case "tokenizer-table":
		return tokenizerTable(dir, fs.val("name"))
	}
	return errors.New(usage)
}

// tokenizerTable writes the canonical table for a trusted tokenizer: a
// publisher's tokenizer.json, or the vocabulary of a GGUF taken from it. The
// output goes into a feed's tokenizers/<name>.json, or a directory named by
// SOCAIR_TOKENIZER_REFERENCE.
func tokenizerTable(src, name string) error {
	if name == "" {
		return errors.New("tokenizer-table needs --name, the family it is the reference for (for example qwen3)")
	}
	var t tokenizer.Table
	if strings.HasSuffix(strings.ToLower(src), ".gguf") {
		m, err := gguf.ReadHeader(src)
		if err != nil {
			return err
		}
		if len(m.Tokenizer.Tokens) == 0 {
			return fmt.Errorf("%s has no tokenizer.ggml.tokens vocabulary", src)
		}
		t = tokenizer.TableFromGGUF(name, m.Tokenizer)
	} else {
		raw, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		if t, err = tokenizer.ParseTable(raw, name); err != nil {
			return err
		}
		t.Name = name
	}
	enc := json.NewEncoder(os.Stdout)
	return enc.Encode(t)
}
