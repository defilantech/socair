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

	"github.com/defilantech/socair/internal/airlock"
	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/modeldir"
	"github.com/defilantech/socair/internal/report"
)

// keyCmd manages operator signing keys.
func keyCmd(args []string) error {
	if len(args) == 0 || args[0] != "gen" {
		return errors.New("usage: socair key gen --out <prefix>   (writes <prefix>.key and <prefix>.pub)")
	}
	fs := parseFlags(args[1:])
	prefix := fs.val("out")
	if prefix == "" {
		return errors.New("usage: socair key gen --out <prefix>")
	}
	id, err := attest.GenerateKey(prefix)
	if err != nil {
		return err
	}
	fmt.Printf("key id %s\n  private: %s.key (keep it secret; mode 0600)\n  public:  %s.pub (share it; add it to a store with `socair airlock trust add`)\n",
		id, prefix, prefix)
	return nil
}

// signCmd signs a report document into a DSSE attestation.
func signCmd(args []string) error {
	fs := parseFlags(args)
	keyPath, in := fs.val("key"), fs.val("report")
	if keyPath == "" || in == "" {
		return errors.New("usage: socair sign --key <key> --report <report.json> [--out <attestation.dsse.json>]")
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
	if t := fs.val("trusted"); t != "" {
		ring, err = attest.LoadKeyring(t)
	} else {
		var s *airlock.Store
		if s, err = airlock.Open(fs.val("store")); err == nil {
			ring, err = s.TrustedKeys()
		}
	}
	if err != nil {
		return err
	}
	v, err := attest.Verify(env, ring)
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
	fmt.Printf("verified: signed by %s\n  artifact %s (%s)\n  promotion %s, %d check(s), document %s\n",
		v.KeyID, v.SHA256, d.Artifact.FileName, d.PromotionAuthorization.State, len(d.Checks), d.Verification.DocumentHash)
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
