package engine

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/defilantech/socair/internal/checks/provenance"
	"github.com/defilantech/socair/internal/modeldir"
	"github.com/defilantech/socair/internal/oms"
)

// publisherTrust is the operator's trust policy for publisher signatures:
// SOCAIR_PUBLISHER_KEYS (EC public keys) and SOCAIR_PUBLISHER_ROOTS (CA
// certificates), each a PEM file or a directory of them. There is no default:
// no system roots, no built-in keys.
func publisherTrust() (oms.Trust, error) {
	return oms.LoadTrust(strings.TrimSpace(os.Getenv("SOCAIR_PUBLISHER_KEYS")), strings.TrimSpace(os.Getenv("SOCAIR_PUBLISHER_ROOTS")))
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
