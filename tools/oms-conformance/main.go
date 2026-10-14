// Command oms-conformance is the adapter the OpenSSF Model Signing (OMS)
// conformance suite runs against Socair's verifier. It is a test harness,
// not part of the product: it translates the suite's adapter protocol
// (github.com/ossf/model-signing-spec, conformance/docs/adapter_cli_protocol.md)
// into calls to internal/oms, and exits 0 when the signature verifies and
// every file matches, 1 when it does not, and 2 on a usage error.
//
// verify-model runs the verification a scan runs: oms.Verify against the
// trust material the suite names, at the current time, then oms.CheckFiles
// (a directory) or oms.CheckFile (one file). The suite's --ignore-paths and
// --ignore-unsigned-files map to oms.Compare; a scan sets neither.
//
// sign-model exists because the suite makes the bundles for its verify tests
// with the adapter's own signer. It uses internal/oms/omstest, Socair's test
// signer; Socair does not sign models.
//
// The sigstore method is not supported here (exit 2): Socair verifies
// keyless signatures through the separate socair-sigstore helper.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/defilantech/socair/internal/modeldir"
	"github.com/defilantech/socair/internal/oms"
	"github.com/defilantech/socair/internal/oms/omstest"
)

type paths []string

func (p *paths) String() string     { return strings.Join(*p, ",") }
func (p *paths) Set(v string) error { *p = append(*p, v); return nil }

type usageError struct{ error }

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: oms-conformance sign-model|verify-model [flags]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "verify-model":
		err = verifyModel(os.Args[2:])
	case "sign-model":
		err = signModel(os.Args[2:])
	default:
		err = usageError{fmt.Errorf("unknown subcommand %q", os.Args[1])}
	}
	var u usageError
	switch {
	case errors.As(err, &u):
		fmt.Fprintln(os.Stderr, "oms-conformance:", err)
		os.Exit(2)
	case err != nil:
		fmt.Fprintln(os.Stderr, "oms-conformance:", err)
		os.Exit(1)
	}
}

func verifyModel(args []string) error {
	fs := flag.NewFlagSet("verify-model", flag.ContinueOnError)
	method := fs.String("method", "", "key, certificate, or sigstore")
	model := fs.String("model-path", "", "model directory or file")
	bundle := fs.String("bundle", "", "the OMS bundle")
	publicKey := fs.String("public-key", "", "trusted EC public key (method key)")
	var certChain, ignore paths
	fs.Var(&certChain, "cert-chain", "trusted CA certificate (method certificate); repeatable")
	fs.Var(&ignore, "ignore-paths", "absolute path left out of the comparison; repeatable")
	ignoreUnsigned := fs.Bool("ignore-unsigned-files", false, "tolerate files the manifest does not list")
	fs.String("identity", "", "sigstore only; not supported")
	fs.String("identity-provider", "", "sigstore only; not supported")
	fs.Bool("use-staging", false, "sigstore only; not supported")
	if err := fs.Parse(args); err != nil {
		return usageError{err}
	}
	if *model == "" || *bundle == "" {
		return usageError{errors.New("--model-path and --bundle are required")}
	}

	var trust oms.Trust
	var err error
	switch *method {
	case "key":
		if *publicKey == "" {
			return usageError{errors.New("--public-key is required for method key")}
		}
		trust, err = oms.LoadTrustFrom([]string{*publicKey}, nil)
	case "certificate":
		if len(certChain) == 0 {
			return usageError{errors.New("--cert-chain is required for method certificate")}
		}
		trust, err = oms.LoadTrustFrom(nil, certChain)
	case "sigstore":
		return usageError{errors.New("the sigstore method is verified by the socair-sigstore helper, not this adapter")}
	default:
		return usageError{fmt.Errorf("unknown method %q", *method)}
	}
	if err != nil {
		return err
	}
	trust.Now = time.Now()

	raw, err := readBounded(*bundle, oms.MaxBundle)
	if err != nil {
		return err
	}
	o := oms.Verify(raw, trust)
	if !o.Recognized {
		return errors.New("not an OMS signature: " + o.Detail)
	}
	if o.State != oms.Verified {
		return fmt.Errorf("signature %s: %s", o.State, o.Detail)
	}
	if o.Method != *method {
		return fmt.Errorf("signed with the %s method, verified as %s", o.Method, *method)
	}

	fi, err := os.Stat(*model)
	if err != nil {
		return err
	}
	var diffs []string
	if !fi.IsDir() {
		sum, err := fileSHA256(*model)
		if err != nil {
			return err
		}
		if diffs, err = oms.CheckFile(o.Manifest, sum); err != nil {
			return err
		}
	} else {
		_, files, err := modeldir.Hash(*model)
		if err != nil {
			return err
		}
		c := oms.Compare{Signature: inside(*model, *bundle), AllowUnsigned: *ignoreUnsigned}
		for _, p := range ignore {
			if rel := inside(*model, p); rel != "" {
				c.Exclude = append(c.Exclude, oms.Exclusion{Path: rel, Why: "excluded by the verifier"})
			}
		}
		if diffs, _, err = oms.CheckFiles(o.Manifest, *model, files, c); err != nil {
			return err
		}
	}
	if len(diffs) > 0 {
		return errors.New("the files differ from the signed manifest: " + strings.Join(diffs, "; "))
	}
	fmt.Println("verified:", o.Signer)
	return nil
}

func signModel(args []string) error {
	fs := flag.NewFlagSet("sign-model", flag.ContinueOnError)
	method := fs.String("method", "", "key or certificate")
	model := fs.String("model-path", "", "model directory or file")
	out := fs.String("output-bundle", "", "where to write the bundle")
	privateKey := fs.String("private-key", "", "EC private key, PEM")
	signingCert := fs.String("signing-cert", "", "leaf certificate, PEM (method certificate)")
	var certChain, ignore paths
	fs.Var(&certChain, "cert-chain", "chain certificate, PEM; repeatable, leaf to root")
	fs.Var(&ignore, "ignore-paths", "absolute path left out of the signature; repeatable")
	fs.String("identity-token", "", "sigstore only; not supported")
	fs.Bool("use-staging", false, "sigstore only; not supported")
	if err := fs.Parse(args); err != nil {
		return usageError{err}
	}
	if *model == "" || *out == "" || *privateKey == "" {
		return usageError{errors.New("--model-path, --output-bundle, and --private-key are required")}
	}
	kb, err := os.ReadFile(*privateKey)
	if err != nil {
		return err
	}
	key, err := omstest.ParsePrivateKey(kb)
	if err != nil {
		return err
	}
	o := omstest.Options{Key: key}
	switch *method {
	case "key":
	case "certificate":
		if *signingCert == "" {
			return usageError{errors.New("--signing-cert is required for method certificate")}
		}
		for _, p := range append([]string{*signingCert}, certChain...) {
			ders, err := certificates(p)
			if err != nil {
				return err
			}
			o.Chain = append(o.Chain, ders...)
		}
	case "sigstore":
		return usageError{errors.New("this adapter does not sign with the sigstore method")}
	default:
		return usageError{fmt.Errorf("unknown method %q", *method)}
	}
	for _, p := range append(append([]string{}, ignore...), *out) {
		if rel := inside(*model, p); rel != "" {
			o.Ignore = append(o.Ignore, rel)
		}
	}
	b, err := omstest.Sign(*model, o)
	if err != nil {
		return err
	}
	return os.WriteFile(*out, b, 0o644)
}

// inside is p relative to dir, "/"-separated, when p is inside dir.
func inside(dir, p string) string {
	ad, err1 := filepath.Abs(dir)
	ap, err2 := filepath.Abs(p)
	if err1 != nil || err2 != nil {
		return ""
	}
	rel, err := filepath.Rel(ad, ap)
	if err != nil {
		return ""
	}
	rel = filepath.ToSlash(rel)
	if rel == "." || rel == ".." || strings.HasPrefix(rel, "../") {
		return ""
	}
	return rel
}

func certificates(p string) ([][]byte, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var out [][]byte
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			break
		}
		if blk.Type == "CERTIFICATE" {
			out = append(out, blk.Bytes)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no CERTIFICATE block in %s", p)
	}
	return out, nil
}

func readBounded(p string, limit int64) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is over %d bytes", p, limit)
	}
	return b, nil
}

func fileSHA256(p string) (string, error) {
	f, err := os.Open(p)
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
