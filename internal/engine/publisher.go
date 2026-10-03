package engine

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/defilantech/socair/internal/checks/provenance"
	"github.com/defilantech/socair/internal/modeldir"
	"github.com/defilantech/socair/internal/oms"
)

// publisherTrust is the operator's trust policy for publisher signatures:
// SOCAIR_PUBLISHER_KEYS (EC public keys) and SOCAIR_PUBLISHER_ROOTS (CA
// certificates), each a PEM file or a directory of them. There is no default:
// no system roots, no built-in keys.
func publisherTrust() (oms.Trust, error) {
	t, err := oms.LoadTrust(strings.TrimSpace(os.Getenv("SOCAIR_PUBLISHER_KEYS")), strings.TrimSpace(os.Getenv("SOCAIR_PUBLISHER_ROOTS")))
	if err != nil {
		return t, err
	}
	if v := strings.TrimSpace(os.Getenv("SOCAIR_SIGSTORE_VERIFIER")); v != "" {
		k, err := keylessVerifier(v, strings.TrimSpace(os.Getenv("SOCAIR_SIGSTORE_TRUSTED_ROOT")), strings.TrimSpace(os.Getenv("SOCAIR_SIGSTORE_IDENTITIES")))
		if err != nil {
			return t, err
		}
		t.Keyless = k
	}
	return t, nil
}

// keylessTimeout bounds one call to the keyless verifier.
const keylessTimeout = 2 * time.Minute

type keylessIdentity struct {
	Issuer       string `json:"issuer,omitempty"`
	IssuerRegexp string `json:"issuer_regexp,omitempty"`
	SAN          string `json:"san,omitempty"`
	SANRegexp    string `json:"san_regexp,omitempty"`
}

// keylessVerifier configures the optional socair-sigstore helper. The trust
// root and the identity policy are required with it: a keyless signature
// verified against no identity would accept anyone who can sign in to an
// OIDC provider. The identities file holds one "<issuer> <subject>" pair per
// line, either side optionally "regexp:<pattern>"; # starts a comment.
func keylessVerifier(bin, trustedRoot, identities string) (func([]byte) oms.KeylessVerdict, error) {
	if trustedRoot == "" || identities == "" {
		return nil, errors.New("SOCAIR_SIGSTORE_VERIFIER needs SOCAIR_SIGSTORE_TRUSTED_ROOT (a Sigstore trusted_root.json) and SOCAIR_SIGSTORE_IDENTITIES (accepted signers)")
	}
	if fi, err := os.Stat(bin); err != nil || fi.IsDir() {
		return nil, fmt.Errorf("SOCAIR_SIGSTORE_VERIFIER %q is not a file", bin)
	}
	rootAbs, err := filepath.Abs(trustedRoot)
	if err != nil {
		return nil, err
	}
	if b, err := os.ReadFile(rootAbs); err != nil || !json.Valid(b) {
		return nil, fmt.Errorf("SOCAIR_SIGSTORE_TRUSTED_ROOT %q is not a readable JSON trust root", trustedRoot)
	}
	ids, err := readIdentities(identities)
	if err != nil {
		return nil, err
	}
	return func(bundle []byte) oms.KeylessVerdict {
		req, err := json.Marshal(map[string]any{
			"bundle":       base64.StdEncoding.EncodeToString(bundle),
			"trusted_root": rootAbs,
			"identities":   ids,
		})
		if err != nil {
			return oms.KeylessVerdict{State: oms.Unverified, Detail: err.Error()}
		}
		ctx, cancel := context.WithTimeout(context.Background(), keylessTimeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin)
		cmd.Stdin = bytes.NewReader(req)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			return oms.KeylessVerdict{State: oms.Unverified, Detail: "the keyless verifier did not run: " + strings.TrimSpace(err.Error()+" "+stderr.String())}
		}
		var v oms.KeylessVerdict
		var out struct {
			State  string `json:"state"`
			Signer string `json:"signer"`
			Detail string `json:"detail"`
		}
		if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
			return oms.KeylessVerdict{State: oms.Unverified, Detail: "the keyless verifier's answer is unreadable"}
		}
		switch out.State {
		case oms.Verified, oms.Invalid, oms.Unverified:
			v = oms.KeylessVerdict{State: out.State, Signer: out.Signer, Detail: out.Detail}
		default:
			v = oms.KeylessVerdict{State: oms.Unverified, Detail: fmt.Sprintf("the keyless verifier answered %q", out.State)}
		}
		return v
	}, nil
}

func readIdentities(p string) ([]keylessIdentity, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("SOCAIR_SIGSTORE_IDENTITIES: %w", err)
	}
	var ids []keylessIdentity
	for n, line := range strings.Split(string(b), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if len(f) != 2 {
			return nil, fmt.Errorf("SOCAIR_SIGSTORE_IDENTITIES line %d: want \"<issuer> <subject>\"", n+1)
		}
		var id keylessIdentity
		if re, ok := strings.CutPrefix(f[0], "regexp:"); ok {
			id.IssuerRegexp = re
		} else {
			id.Issuer = f[0]
		}
		if re, ok := strings.CutPrefix(f[1], "regexp:"); ok {
			id.SANRegexp = re
		} else {
			id.SAN = f[1]
		}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("SOCAIR_SIGSTORE_IDENTITIES %s names no signer", p)
	}
	return ids, nil
}

func readBundle(p string) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, oms.MaxBundle+1))
	if err != nil {
		return nil, err
	}
	if len(b) > oms.MaxBundle {
		return nil, fmt.Errorf("signature %s is over %d bytes", p, oms.MaxBundle)
	}
	return b, nil
}

// fileSignature checks an OMS signature over a single-file artifact:
// SOCAIR_OMS_SIGNATURE, else <artifact>.sig beside the original. It returns
// nil when there is no OMS signature.
func fileSignature(original, sha string) (*provenance.Signature, error) {
	p := strings.TrimSpace(os.Getenv("SOCAIR_OMS_SIGNATURE"))
	if p == "" {
		p = original + ".sig"
		if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
	}
	raw, err := readBundle(p)
	if err != nil {
		return nil, err
	}
	trust, err := publisherTrust()
	if err != nil {
		return nil, err
	}
	o := oms.Verify(raw, trust)
	if !o.Recognized {
		return nil, nil
	}
	if o.State != oms.Verified {
		return signatureOf(o, nil, nil, nil), nil
	}
	diffs, cerr := oms.CheckFile(o.Manifest, sha)
	return signatureOf(o, diffs, nil, cerr), nil
}

// dirSignature checks an OMS signature over a model directory snapshot:
// SOCAIR_OMS_SIGNATURE, else model.sig at the directory's root, the
// model_signing default.
func dirSignature(dir, root string, files []modeldir.File) (*provenance.Signature, error) {
	p, sigRel := strings.TrimSpace(os.Getenv("SOCAIR_OMS_SIGNATURE")), ""
	if p != "" {
		if rel, err := filepath.Rel(dir, p); err == nil && !strings.HasPrefix(rel, "..") {
			sigRel = filepath.ToSlash(rel)
		}
	} else {
		if _, ok := find(files, "model.sig"); !ok {
			return nil, nil
		}
		p, sigRel = filepath.Join(root, "model.sig"), "model.sig"
	}
	raw, err := readBundle(p)
	if err != nil {
		return nil, err
	}
	trust, err := publisherTrust()
	if err != nil {
		return nil, err
	}
	o := oms.Verify(raw, trust)
	if !o.Recognized {
		return nil, nil
	}
	if o.State != oms.Verified {
		return signatureOf(o, nil, nil, nil), nil
	}
	diffs, ignored, cerr := oms.CheckFiles(o.Manifest, root, files, sigRel)
	return signatureOf(o, diffs, ignored, cerr), nil
}

// signatureOf turns a verification outcome and a file comparison into the
// provenance row's input. A trusted signature whose files differ is invalid;
// one whose manifest cannot be compared is unverified.
func signatureOf(o oms.Outcome, diffs, ignored []string, cerr error) *provenance.Signature {
	s := &provenance.Signature{Format: "OMS", Signer: o.Signer, Detail: o.Detail}
	switch {
	case o.State == oms.Invalid:
		s.State = provenance.SignatureInvalid
	case o.State != oms.Verified:
		s.State = provenance.SignatureUnverified
	case cerr != nil:
		s.State, s.Detail = provenance.SignatureUnverified, "signed by a trusted "+o.Method+", but "+cerr.Error()
	case len(diffs) > 0:
		shown := diffs
		if len(shown) > 8 {
			shown = append(append([]string{}, shown[:8]...), fmt.Sprintf("and %d more", len(diffs)-8))
		}
		s.State, s.Detail = provenance.SignatureInvalid, "the files differ from the signed manifest: "+strings.Join(shown, "; ")
	default:
		s.State, s.Uncovered = provenance.SignatureVerified, ignored
	}
	return s
}

// signingState is the identity section's publisher signing status.
func signingState(s *provenance.Signature) string {
	switch s.State {
	case provenance.SignatureVerified:
		return "verified (" + s.Format + ", " + s.Signer + ")"
	case provenance.SignatureInvalid:
		return "invalid (" + s.Format + "): " + s.Detail
	default:
		return "present, not verified (" + s.Format + "): " + s.Detail
	}
}
