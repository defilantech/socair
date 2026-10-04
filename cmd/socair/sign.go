package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/defilantech/socair/internal/airlock"
	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/modeldir"
	"github.com/defilantech/socair/internal/report"
)

// keyCmd manages operator signing keys.
func keyCmd(args []string) error {
	const usage = "usage: socair key gen --out <prefix> [--issuer <name>]   (writes <prefix>.key and <prefix>.pub)"
	if len(args) == 0 || args[0] != "gen" {
		return errors.New(usage)
	}
	fs := parseFlags(args[1:])
	prefix := fs.val("out")
	if prefix == "" {
		return errors.New(usage)
	}
	issuer := fs.val("issuer")
	if issuer == "true" {
		return errors.New(usage)
	}
	id, err := attest.GenerateNamedKey(prefix, issuer)
	if err != nil {
		return err
	}
	fmt.Printf("key id %s\n  private: %s.key (keep it secret; mode 0600)\n  public:  %s.pub (share it; add it to a store with `socair airlock trust add`)\n",
		id, prefix, prefix)
	if issuer != "" {
		fmt.Printf("  issuer:  %s (reports signed with this key name it as their issuer)\n", issuer)
	} else {
		fmt.Println("  no issuer name: reports signed with it name the key id; pass --issuer to name who signs")
	}
	return nil
}

// signCmd signs a report document into a DSSE attestation.
func signCmd(args []string) error {
	fs := parseFlags(args)
	if fs.val("acceptance") != "" {
		return reissueCmd(fs)
	}
	keyPath, in := fs.val("key"), fs.val("report")
	if keyPath == "" || in == "" {
		return errors.New("usage: socair sign --key <key> --report <report.json> [--out <attestation.dsse.json>]\n" +
			"       socair sign --key <key> --attestation <r.dsse.json> --acceptance <a.dsse.json> (--trusted <dir> --acceptors <dir> | --store <path>) [--out <path>]")
	}
	k, err := attest.LoadPrivateKey(keyPath)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	var d report.Document
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return fmt.Errorf("%s is not a report document: %w", in, err)
	}
	env, err := attest.Sign(d, k)
	if err != nil {
		return err
	}
	out := fs.val("out")
	if out == "" {
		out = strings.TrimSuffix(in, ".json") + ".dsse.json"
	}
	if err := os.WriteFile(out, env, 0o644); err != nil {
		return err
	}
	fmt.Printf("signed %s for artifact %s with key %s\n  %s\n", in, d.Artifact.SHA256, attest.ShortID(k.ID), out)
	return nil
}

// verifyCmd verifies an attestation against trusted keys, and optionally that
// a file on disk is the artifact it attests.
func verifyCmd(args []string) error {
	fs := parseFlags(args)
	if len(fs.pos) != 1 || (fs.val("trusted") == "" && fs.val("store") == "") {
		return errors.New("usage: socair verify <attestation.dsse.json> (--trusted <key.pub|dir> | --store <path>) [--artifact <path>]")
	}
	env, err := os.ReadFile(fs.pos[0])
	if err != nil {
		return err
	}
	var ring attest.Keyring
	var names attest.Names
	if t := fs.val("trusted"); t != "" {
		ring, names, err = attest.LoadNamedKeyring(t)
	} else {
		var s *airlock.Store
		if s, err = airlock.Open(fs.val("store")); err == nil {
			ring, names, err = s.TrustedIssuers()
		}
	}
	if err != nil {
		return err
	}
	v, err := attest.Verify(env, ring)
	if err != nil {
		return err
	}
	issuer, confirmed, err := v.Issuer(names)
	if err != nil {
		return err
	}
	if a := fs.val("artifact"); a != "" {
		if fi, err := os.Stat(a); err == nil && fi.IsDir() {
			// A model directory: recompute the manifest digest, and on a
			// mismatch name the files that differ from the attested list.
			got, files, err := modeldir.Hash(a)
			if err != nil {
				return err
			}
			if got != v.SHA256 {
				var attested []modeldir.File
				for _, f := range v.Document.Artifact.Files {
					attested = append(attested, modeldir.File{Path: f.Path, SHA256: f.SHA256, Size: f.SizeBytes})
				}
				return fmt.Errorf("%w: directory %s has manifest digest %s, but the attestation is for %s: %s",
					attest.ErrVerify, a, got, v.SHA256, strings.Join(modeldir.Diff(attested, files), "; "))
			}
		} else {
			got, err := sha256File(a)
			if err != nil {
				return err
			}
			if got != v.SHA256 {
				return fmt.Errorf("%w: %s hashes to %s, but the attestation is for %s", attest.ErrVerify, a, got, v.SHA256)
			}
		}
	}
	d := v.Document
	how := "confirmed: your trust list names this key"
	if !confirmed {
		how = "claimed: your trust list does not name this key"
	}
	fmt.Printf("verified: issued by %s (%s)\n  signed by key %s\n  artifact %s (%s)\n  promotion %s, %d check(s), document %s\n",
		issuer, how, v.KeyID, v.SHA256, d.Artifact.FileName, d.PromotionAuthorization.State, len(d.Checks), d.Verification.DocumentHash)
	if pa := d.PromotionAuthorization; pa.State == report.StateAuthorizedWithConditions {
		switch {
		case !pa.Signed():
			fmt.Printf("  acceptance by %s is UNSIGNED (named at scan time); the airlock will not promote it\n", pa.AcceptedBy)
		case fs.val("acceptors") == "" && fs.val("store") == "":
			fmt.Printf("  acceptance by %s is signed; pass --acceptors <key.pub|dir> to verify it\n", pa.AcceptedBy)
		default:
			acceptors, err := trustedFor(fs, "acceptors", (*airlock.Store).AcceptorKeys)
			if err != nil {
				return err
			}
			a, err := attest.VerifyAcceptance(v, acceptors, time.Now())
			if err != nil {
				return fmt.Errorf("%w: acceptance: %v", attest.ErrVerify, err)
			}
			fmt.Printf("  acceptance verified: %s, acceptor key %s, until %s, of %s\n", a.AcceptedBy, attest.ShortID(a.KeyID), a.Expires, strings.Join(a.AcceptedSurfaces, ", "))
		}
	}
	if fs.val("artifact") == "" {
		fmt.Println("  the artifact itself was not checked; pass --artifact <path> to bind it")
	}
	return nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// reissueCmd re-issues a reviewed, withheld attestation as
// authorized_with_conditions, carrying the acceptor's signed acceptance, and
// signs it with the operator's key.
func reissueCmd(fs *flagSet) error {
	keyPath, in, accPath := fs.val("key"), fs.val("attestation"), fs.val("acceptance")
	if keyPath == "" || in == "" {
		return errors.New("usage: socair sign --key <key> --attestation <r.dsse.json> --acceptance <a.dsse.json> (--trusted <dir> --acceptors <dir> | --store <path>) [--out <path>]")
	}
	signers, err := trustedFor(fs, "trusted", (*airlock.Store).TrustedKeys)
	if err != nil {
		return err
	}
	acceptors, err := trustedFor(fs, "acceptors", (*airlock.Store).AcceptorKeys)
	if err != nil {
		return err
	}
	env, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	v, err := attest.Verify(env, signers)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(accPath)
	if err != nil {
		return err
	}
	d, err := attest.Conditional(v, raw, acceptors, time.Now())
	if err != nil {
		return err
	}
	k, err := attest.LoadPrivateKey(keyPath)
	if err != nil {
		return err
	}
	out, err := attest.Sign(d, k)
	if err != nil {
		return err
	}
	dst := fs.val("out")
	if dst == "" {
		dst = strings.TrimSuffix(in, ".dsse.json") + ".conditional.dsse.json"
	}
	if err := os.WriteFile(dst, out, 0o644); err != nil {
		return err
	}
	pa := d.PromotionAuthorization
	fmt.Printf("re-issued %s as authorized_with_conditions: %s accepted %s until %s\n  %s\n",
		v.Document.Header.DocumentID, pa.AcceptedBy, strings.Join(pa.AcceptedSurfaces, ", "), pa.AcceptanceExpires, dst)
	return nil
}
