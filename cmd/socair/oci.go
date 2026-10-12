package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/defilantech/socair/internal/airlock"
	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/engine"
	"github.com/defilantech/socair/internal/ociattest"
	"github.com/defilantech/socair/internal/registry"
)

const (
	attachUsage    = "usage: socair attach <registry/repository:tag|@sha256:digest> --attestation <r.dsse.json> --key <operator.key> (--trusted <key.pub|dir> | --store <path>) [--acceptors <key.pub|dir>]"
	ociVerifyUsage = "usage: socair verify <registry/repository:tag|@sha256:digest> (--trusted <key.pub|dir> | --store <path>) [--acceptors <key.pub|dir>]"
)

// isOCIRef reports whether verify's argument names an OCI artifact rather
// than an attestation file: it is not a file, and it parses as a reference
// with a registry and a tag or digest.
func isOCIRef(arg string) bool {
	if _, err := os.Stat(arg); err == nil {
		return false
	}
	return registry.LooksLikeReference(arg)
}

func registryClient() (*registry.Client, error) {
	creds, err := registry.LoadDockerConfig(registry.DockerConfigPath())
	if err != nil {
		return nil, err
	}
	return registry.New(registry.Options{Credentials: creds}), nil
}

// signerKeys loads the keys an attestation must verify against, and the
// issuer names the trust list gives them.
func signerKeys(fs *flagSet) (attest.Keyring, attest.Names, error) {
	if t := fs.val("trusted"); t != "" && t != "true" {
		return attest.LoadNamedKeyring(t)
	}
	if fs.val("store") != "" {
		s, err := airlock.Open(fs.val("store"))
		if err != nil {
			return nil, nil, err
		}
		return s.TrustedIssuers()
	}
	return nil, nil, errors.New("pass --trusted <key.pub|dir> or --store <path>")
}

// acceptorKeys loads acceptor keys when they were named, or nil.
func acceptorKeys(fs *flagSet) (attest.Keyring, error) {
	if fs.val("acceptors") == "" && fs.val("store") == "" {
		return nil, nil
	}
	return trustedFor(fs, "acceptors", (*airlock.Store).AcceptorKeys)
}

// attachCmd binds a signed attestation to an OCI artifact and pushes both as
// a referrer.
func attachCmd(args []string) error {
	fs := parseFlags(args)
	if len(fs.pos) != 1 || fs.val("attestation") == "" || fs.val("key") == "" {
		return errors.New(attachUsage)
	}
	ref, err := registry.ParseReference(fs.pos[0])
	if err != nil {
		return err
	}
	env, err := os.ReadFile(fs.val("attestation"))
	if err != nil {
		return err
	}
	k, err := attest.LoadPrivateKey(fs.val("key"))
	if err != nil {
		return err
	}
	ring, names, err := signerKeys(fs)
	if err != nil {
		return err
	}
	acceptors, err := acceptorKeys(fs)
	if err != nil {
		return err
	}
	c, err := registryClient()
	if err != nil {
		return err
	}
	a, err := ociattest.Attach(context.Background(), c, ref, env, ociattest.AttachOptions{
		Key: k, Trusted: ring, Names: names, Acceptors: acceptors, ToolVersion: "socair " + engine.Version,
	})
	if err != nil {
		return err
	}
	printAttached(os.Stdout, a, k.ID)
	return nil
}

func printAttached(w io.Writer, a *ociattest.Attached, keyID string) {
	b := a.Binding
	fmt.Fprintf(w, "attached to %s\n", a.Ref)
	fmt.Fprintf(w, "  attestation for %s (sha256:%s), issued by %s, promotion %s\n",
		b.Attestation.SubjectName, b.Attestation.SubjectSHA256, b.Attestation.Issuer, b.Attestation.PromotionState)
	fmt.Fprintf(w, "  bound: %s\n", describeMatch(b.Artifact.Match, b.Artifact.Layers))
	fmt.Fprintf(w, "  binding signed with key %s (%s)\n", attest.ShortID(keyID), ociattest.BindingPredicateType)
	fmt.Fprintf(w, "  Socair referrer %s, via the %s\n", a.Referrer.Digest, a.Via)
	fmt.Fprintf(w, "  Sigstore bundle referrer %s, via the %s (what cosign verify-attestation and Kyverno read)\n", a.Bundle.Digest, a.BundleVia)
	fmt.Fprintf(w, "  not covered: the manifest's config blob (%s)\n", b.Artifact.ConfigMediaType)
}

func describeMatch(kind string, layers []ociattest.Layer) string {
	if kind == ociattest.MatchDirectory {
		return fmt.Sprintf("each of the manifest's %d layers is an attested file, at its path, and every attested file is a layer", len(layers))
	}
	return fmt.Sprintf("the manifest's one layer (%s) is the attested file", layers[0].MediaType)
}

// ociVerifyCmd finds and verifies the Socair attestations on an OCI
// artifact.
func ociVerifyCmd(fs *flagSet) error {
	if len(fs.pos) != 1 {
		return errors.New(ociVerifyUsage)
	}
	if fs.val("artifact") != "" {
		return errors.New("--artifact checks a local file; for an OCI artifact the bytes checked are its layers, by digest")
	}
	ref, err := registry.ParseReference(fs.pos[0])
	if err != nil {
		return err
	}
	ring, names, err := signerKeys(fs)
	if err != nil {
		return fmt.Errorf("%w\n%s", err, ociVerifyUsage)
	}
	acceptors, err := acceptorKeys(fs)
	if err != nil {
		return err
	}
	c, err := registryClient()
	if err != nil {
		return err
	}
	res, err := ociattest.Verify(context.Background(), c, ref, ociattest.VerifyOptions{Trusted: ring, Names: names, Acceptors: acceptors})
	if res != nil {
		printVerified(os.Stdout, res, acceptors != nil)
	}
	return err
}

func printVerified(w io.Writer, res *ociattest.Result, acceptorsGiven bool) {
	n := len(res.Verified())
	fmt.Fprintf(w, "%s: %d of %d Socair attestation(s) verified (referrers listed via the %s)\n", res.Ref, n, len(res.Found), res.Via)
	for _, f := range res.Found {
		if f.Err != nil {
			fmt.Fprintf(w, "  not verified: referrer %s: %v\n", f.Referrer.Digest, f.Err)
			continue
		}
		b, d := f.Binding, f.Attestation.Document
		how := "confirmed: your trust list names this key"
		if !f.IssuerConfirmed {
			how = "claimed: your trust list does not name this key"
		}
		fmt.Fprintf(w, "  verified: referrer %s\n", f.Referrer.Digest)
		fmt.Fprintf(w, "    binding signed by key %s at %s, for this manifest digest\n", attest.ShortID(b.KeyID), b.BoundUTC)
		fmt.Fprintf(w, "    attestation issued by %s (%s), signed by key %s\n", f.Issuer, how, attest.ShortID(f.Attestation.KeyID))
		fmt.Fprintf(w, "    artifact sha256:%s (%s): %s\n", f.Attestation.SHA256, d.Artifact.FileName, describeMatch(f.Match.Kind, f.Match.Layers))
		fmt.Fprintf(w, "    promotion %s, %d check(s), document %s\n", d.PromotionAuthorization.State, len(d.Checks), d.Verification.DocumentHash)
		if pa := d.PromotionAuthorization; pa.State == "authorized_with_conditions" {
			switch {
			case f.Acceptance != nil:
				fmt.Fprintf(w, "    acceptance verified: %s, acceptor key %s, until %s, of %s\n", f.Acceptance.AcceptedBy, attest.ShortID(f.Acceptance.KeyID), f.Acceptance.Expires, strings.Join(f.Acceptance.AcceptedSurfaces, ", "))
			case !pa.Signed():
				fmt.Fprintf(w, "    acceptance by %s is UNSIGNED (named at scan time)\n", pa.AcceptedBy)
			case !acceptorsGiven:
				fmt.Fprintf(w, "    acceptance by %s is signed; pass --acceptors <key.pub|dir> to verify it\n", pa.AcceptedBy)
			}
		}
		if f.Bundle != nil {
			fmt.Fprintf(w, "    Sigstore bundle copy for cosign-based verifiers: %s\n", f.Bundle.Digest)
		} else {
			fmt.Fprintln(w, "    no Sigstore bundle copy found: cosign-based verifiers will not find this binding")
		}
	}
	if res.Unchecked > 0 {
		fmt.Fprintf(w, "  %d more Socair referrer(s) listed and not checked (at most %d are)\n", res.Unchecked, ociattest.MaxReferrers)
	}
	if n > 0 {
		fmt.Fprintln(w, "  not covered: the manifest's config blob, and anything a consumer reads from outside the layers")
	}
}
