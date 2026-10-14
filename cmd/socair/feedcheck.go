package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/defilantech/socair/internal/airlock"
	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/feed"
)

// feedHook is what a CLI scan does with the verified feed before it reads the
// artifact: with a store, it checks the feed against the newest feed the
// store has used (a refusal stops the scan), and it warns on stderr when the
// feed is in the last third of its validity. The warning changes nothing
// else. The store is opened only when a feed is configured.
func feedHook(storeRoot string) func(*feed.Feed) error {
	return func(f *feed.Feed) error {
		if storeRoot != "" {
			s, err := airlock.Open(storeRoot)
			if err != nil {
				return fmt.Errorf("the feed cannot be checked against the store's record: %w", err)
			}
			if err := s.CheckFeed(f); err != nil {
				return err
			}
		}
		warnFeedExpiry(f.Info)
		return nil
	}
}

// warnFeedExpiry prints the feed's expiry notice on stderr, when it has one.
func warnFeedExpiry(i feed.Info) {
	if n := i.ExpiryNotice(time.Now()); n != "" {
		fmt.Fprintln(os.Stderr, "warning:", n)
	}
}

// warnRecheckFeed warns about the feed a recheck read, when it expires soon.
func warnRecheckFeed(f *airlock.RecheckFeed) {
	if f != nil {
		warnFeedExpiry(feed.Info{Issuer: f.Issuer, Version: f.Version, Issued: f.Issued, Expires: f.Expires})
	}
}

// reviewFeed says whether a scan with the store at root would accept f, from
// the store's record, without writing anything.
func reviewFeed(root string, f *feed.Feed) error {
	s, err := airlock.Open(root)
	if err != nil {
		return err
	}
	rec, err := s.ReviewFeed(f)
	if rec != nil {
		fmt.Printf("store %s: the newest feed it has used is %s\n", s.Root, rec.String())
	}
	if err != nil {
		return err
	}
	if rec == nil {
		fmt.Printf("store %s has used no feed yet; the first scan with it records this one\n", s.Root)
	} else {
		fmt.Println("a scan with this store accepts this feed")
	}
	return nil
}

// requestedStore is the store a scan or feed check was asked to use: --store,
// then SOCAIR_STORE, or "" for none. Unlike the airlock commands, these do
// not fall back to ~/.socair/store: without a store, nothing is recorded.
func requestedStore(fs *flagSet) (string, error) {
	if fs.bare["store"] {
		return "", errors.New("--store needs a path")
	}
	if v := fs.val("store"); v != "" {
		return v, nil
	}
	return strings.TrimSpace(os.Getenv("SOCAIR_STORE")), nil
}

// airlockFeed is the deliberate way to move a store's feed record:
//
//	socair airlock feed accept <feed dir> --keys <key.pub|dir> --reason <why> [--store <path>]
//
// It records the feed as the newest the store has used, older or not, and
// logs the reason. A feed that does not verify or has expired is refused.
func airlockFeed(args []string) error {
	const usage = "usage: socair airlock feed accept <feed dir> --keys <key.pub|dir> --reason <why> [--store <path>]"
	if len(args) == 0 || args[0] != "accept" {
		return errors.New(usage)
	}
	fs := parseFlags(args[1:])
	if len(fs.pos) != 1 || fs.bare["keys"] || fs.val("keys") == "" || fs.bare["reason"] || strings.TrimSpace(fs.val("reason")) == "" {
		return errors.New(usage)
	}
	s, err := airlock.Open(storeRoot(fs))
	if err != nil {
		return err
	}
	keys, err := attest.LoadKeyring(fs.val("keys"))
	if err != nil {
		return err
	}
	f, err := feed.Load(fs.pos[0], keys, time.Now())
	if err != nil {
		return err
	}
	prev, err := s.AcceptFeed(f, fs.val("reason"))
	if err != nil {
		return err
	}
	replaced := "it had no record"
	if prev != nil {
		replaced = "replacing " + prev.String()
	}
	fmt.Printf("store %s now records %s as the newest feed it has used (%s).\nThe activity log names the reason. A scan with this store now refuses any feed issued before it.\n",
		s.Root, f.Record().String(), replaced)
	warnFeedExpiry(f.Info)
	return nil
}
