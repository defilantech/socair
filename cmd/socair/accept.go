package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/defilantech/socair/internal/acceptance"
	"github.com/defilantech/socair/internal/airlock"
	"github.com/defilantech/socair/internal/attest"
)

// trustedFor loads a keyring from --<flag> (a key or a directory), else from
// the store's directory for that role.
func trustedFor(fs *flagSet, flag string, fromStore func(*airlock.Store) (attest.Keyring, error)) (attest.Keyring, error) {
	if p := fs.val(flag); p != "" && p != "true" {
		return attest.LoadKeyring(p)
	}
	if fs.val("store") != "" {
		s, err := airlock.Open(fs.val("store"))
		if err != nil {
			return nil, err
		}
		return fromStore(s)
	}
	return nil, fmt.Errorf("pass --%s <key.pub|dir> or --store <path>", flag)
}

// acceptCmd signs the acceptor's acceptance of a reviewed, withheld report.
//
//	socair accept --attestation <r.dsse.json> --key <acceptor.key> --by <name>
//	              --expires <RFC 3339> [--rationale <text>]
//	              (--trusted <key.pub|dir> | --store <path>) [--out <acceptance.dsse.json>]
//
// The attestation is verified first, against the keys that sign reports: an
// acceptor accepts only a report they can trust is the operator's.
func acceptCmd(args []string) error {
	fs := parseFlags(args)
	in, keyPath, by, exp := fs.val("attestation"), fs.val("key"), fs.val("by"), fs.val("expires")
	if in == "" || keyPath == "" || by == "" || exp == "" {
		return errors.New("usage: socair accept --attestation <r.dsse.json> --key <acceptor.key> --by <name> --expires <RFC 3339> (--trusted <key.pub|dir> | --store <path>) [--rationale <text>] [--out <path>]")
	}
	expires, err := time.Parse(time.RFC3339, exp)
	if err != nil {
		return fmt.Errorf("--expires %q is not RFC 3339, e.g. 2027-01-31T00:00:00Z", exp)
	}
	ring, err := trustedFor(fs, "trusted", (*airlock.Store).TrustedKeys)
	if err != nil {
		return err
	}
	env, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	v, err := attest.Verify(env, ring)
	if err != nil {
		return err
	}
	k, err := attest.LoadPrivateKey(keyPath)
	if err != nil {
		return err
	}
	raw, err := attest.Accept(v, k, by, expires, fs.val("rationale"), time.Now())
	if err != nil {
		return err
	}
	out := fs.val("out")
	if out == "" {
		out = strings.TrimSuffix(in, ".dsse.json") + ".acceptance.dsse.json"
	}
	if err := os.WriteFile(out, raw, 0o644); err != nil {
		return err
	}
	// The surfaces come from the acceptance just signed: the withheld report
	// lists its gaps as NOT_TESTED rows, not as accepted surfaces.
	a, err := acceptance.Parse(raw)
	if err != nil {
		return err
	}
	fmt.Printf("%s accepted %d untested surface(s) of %s until %s, with key %s\n  %s\n  %s\nthe operator re-issues it with their key:\n  %s\n",
		by, len(a.AcceptedSurfaces), v.Document.Header.DocumentID, expires.UTC().Format(time.RFC3339), attest.ShortID(k.ID),
		strings.Join(a.AcceptedSurfaces, ", "), out, reissueHint(fs, keyPath, in, out))
	return nil
}

// reissueHint is the sign command that re-issues the reviewed attestation
// with the acceptance just written. It carries the trust source accept used,
// the store or the trusted keys, and for trusted keys the acceptor's public
// key beside their private one, so it runs as printed once the operator puts
// in their key. Placeholders carry no shell metacharacters.
func reissueHint(fs *flagSet, keyPath, in, out string) string {
	cmd := "socair sign --key OPERATOR_KEY --attestation " + shellQuote(in) + " --acceptance " + shellQuote(out)
	if t := fs.val("trusted"); t == "" || t == "true" {
		return cmd + " --store " + shellQuote(fs.val("store"))
	}
	acceptors := "ACCEPTOR_PUB"
	if base, ok := strings.CutSuffix(keyPath, ".key"); ok {
		if _, err := os.Stat(base + ".pub"); err == nil {
			acceptors = base + ".pub"
		}
	}
	return cmd + " --trusted " + shellQuote(fs.val("trusted")) + " --acceptors " + shellQuote(acceptors)
}

// shellQuote quotes p for a POSIX shell when it holds anything but plain path
// characters, as the console quotes the commands it shows.
func shellQuote(p string) string {
	if p != "" && strings.IndexFunc(p, func(r rune) bool {
		return !(r == '/' || r == '.' || r == '-' || r == '_' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z')
	}) < 0 {
		return p
	}
	return "'" + strings.ReplaceAll(p, "'", `'\''`) + "'"
}
