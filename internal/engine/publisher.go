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
	"sort"
	"strings"
	"time"

	"github.com/defilantech/socair/internal/checks/provenance"
	"github.com/defilantech/socair/internal/hostpath"
	"github.com/defilantech/socair/internal/modeldir"
	"github.com/defilantech/socair/internal/oms"
)

// publisherTrust is the operator's trust policy for publisher signatures:
// SOCAIR_PUBLISHER_KEYS (EC public keys) and SOCAIR_PUBLISHER_ROOTS (CA
// certificates), each a PEM file or a directory of them. There is no default:
// no system roots, no built-in keys, and no publisher's root (NVIDIA's
// included) until the operator supplies it. A certificate chain must be valid
// at now, the scan's time.
func publisherTrust(now time.Time) (oms.Trust, error) {
	t, err := oms.LoadTrust(strings.TrimSpace(os.Getenv("SOCAIR_PUBLISHER_KEYS")), strings.TrimSpace(os.Getenv("SOCAIR_PUBLISHER_ROOTS")))
	if err != nil {
		return t, err
	}
	t.Now = now
	if v := strings.TrimSpace(os.Getenv("SOCAIR_SIGSTORE_VERIFIER")); v != "" {
		k, err := keylessVerifier(v, strings.TrimSpace(os.Getenv("SOCAIR_SIGSTORE_TRUSTED_ROOT")), strings.TrimSpace(os.Getenv("SOCAIR_SIGSTORE_IDENTITIES")))
		if err != nil {
			return t, err
		}
		t.Keyless = k
	}
	return t, nil
}

// keylessTimeout bounds one call to the keyless verifier. A variable so a
// test can shorten it.
var keylessTimeout = 2 * time.Minute

// keylessStderr bounds how much of the verifier's standard error a report
// quotes when it fails.
const keylessStderr = 400

// keylessMaxAnswer bounds the verifier's answer on standard output. A real
// verdict is a few hundred bytes: the largest socair-sigstore gives on the
// reference vectors and their tampered copies is 349. The verdict's detail
// can quote the bundle, which comes with the artifact, so without a bound an
// artifact could size what Socair reads into memory and into the report. An
// answer past the bound is refused whole, never read in part.
const keylessMaxAnswer = 64 << 10

// keylessEnvKeys are the variables of Socair's environment the keyless
// verifier is given. There are none. socair-sigstore verifies offline from
// its request alone (the bundle, the trust root's path, and the identities)
// and needs nothing from the environment: what it and its libraries read
// there serves the online trust-root fetch Socair never uses, system
// certificate roots it never trusts, runtime tuning, how a time reads, or
// debugging (docs/provenance-bundle.md lists them). GODEBUG would be worse than
// unneeded, since it can loosen the verifier's X.509 and RSA checks. A
// variable is added here only when the verifier needs it, and never a
// credential such as HF_TOKEN.
var keylessEnvKeys = map[string]bool{}

// verifierEnv is the keyless verifier's environment: the variables of
// environ that keylessEnvKeys allows. It is never nil, because a nil
// environment would hand the verifier all of Socair's.
func verifierEnv(environ []string) []string {
	env := []string{}
	for _, kv := range environ {
		if k, _, _ := strings.Cut(kv, "="); keylessEnvKeys[k] {
			env = append(env, kv)
		}
	}
	return env
}

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
	env := verifierEnv(os.Environ())
	names := keylessNames(bin, rootAbs, env)
	return func(bundle []byte) oms.KeylessVerdict {
		v := runKeyless(bin, rootAbs, ids, bundle, env, names)
		// What the verifier says reaches the provenance row and the signing
		// state; a path it repeats does not.
		names.Walk(&v)
		return v
	}, nil
}

// keylessNames are the host paths Socair hands the keyless verifier, each with
// the name a report gives it (#170): the verifier by its file name and its
// directory by its own, the trust root by its file name, and each absolute
// path in the environment it is given by its variable ("$HOME").
func keylessNames(bin, trustedRoot string, environ []string) *hostpath.Names {
	n := &hostpath.Names{}
	n.Base(bin)
	n.Base(trustedRoot)
	n.Base(filepath.Dir(bin))
	n.Env(environ)
	return n
}

// runKeyless runs the verifier on one bundle, with env as its whole
// environment. A failure is unverified, with a reason that names no host path
// of its own: a verifier that could not be started is named by its file name
// with the cause, and the end of its standard error is quoted with names'
// paths replaced. An answer over keylessMaxAnswer is a failure too.
func runKeyless(bin, trustedRoot string, ids []keylessIdentity, bundle []byte, env []string, names *hostpath.Names) oms.KeylessVerdict {
	req, err := json.Marshal(map[string]any{
		"bundle":       base64.StdEncoding.EncodeToString(bundle),
		"trusted_root": trustedRoot,
		"identities":   ids,
	})
	if err != nil {
		return oms.KeylessVerdict{State: oms.Unverified, Detail: err.Error()}
	}
	ctx, cancel := context.WithTimeout(context.Background(), keylessTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin)
	cmd.Env = env
	cmd.Stdin = bytes.NewReader(req)
	stdout := &boundedOutput{max: keylessMaxAnswer}
	var stderr hostpath.Stderr
	cmd.Stdout, cmd.Stderr = stdout, &stderr
	cmd.WaitDelay = 2 * time.Second
	err = cmd.Run()
	var detail string
	switch {
	case err != nil && cmd.Process == nil:
		detail = "the keyless verifier " + filepath.Base(bin) + " could not be started: " + hostpath.Reason(err)
	case stdout.over:
		detail = fmt.Sprintf("the keyless verifier's answer is over %d bytes", keylessMaxAnswer)
	case err != nil && errors.Is(ctx.Err(), context.DeadlineExceeded):
		detail = "the keyless verifier did not answer within " + keylessTimeout.String()
	case err != nil:
		detail = "the keyless verifier failed: " + err.Error()
		if q := stderr.Quote(names, keylessStderr); q != "" {
			detail += ": " + q
		}
	}
	if detail != "" {
		return oms.KeylessVerdict{State: oms.Unverified, Detail: detail}
	}
	var out struct {
		State  string `json:"state"`
		Signer string `json:"signer"`
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(stdout.buf.Bytes(), &out); err != nil {
		return oms.KeylessVerdict{State: oms.Unverified, Detail: "the keyless verifier's answer is unreadable"}
	}
	switch out.State {
	case oms.Verified, oms.Invalid, oms.Unverified:
		return oms.KeylessVerdict{State: out.State, Signer: out.Signer, Detail: out.Detail}
	default:
		return oms.KeylessVerdict{State: oms.Unverified, Detail: fmt.Sprintf("the keyless verifier answered %q", out.State)}
	}
}

// boundedOutput keeps at most max bytes and fails the write that would pass
// them, which closes the pipe on a verifier that keeps writing.
type boundedOutput struct {
	buf  bytes.Buffer
	max  int
	over bool
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	if b.over || b.buf.Len()+len(p) > b.max {
		b.over = true
		return 0, errors.New("answer over its bound")
	}
	return b.buf.Write(p)
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
func fileSignature(original, sha string, now time.Time) (*provenance.Signature, error) {
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
	trust, err := publisherTrust(now)
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

// dirSignatureNames are the signature files a directory scan looks for at its
// root: model.sig, the model_signing default, and result.sigstore, the name
// NVIDIA's NGC CLI gives a model's signature. `ngc registry model
// download-version-signature` writes it to <dest>/<model>_v<version>/, which
// is the model's own directory when the model was downloaded to the same
// --dest.
var dirSignatureNames = []string{"model.sig", "result.sigstore"}

// dirSignature checks an OMS signature over a model directory snapshot:
// SOCAIR_OMS_SIGNATURE, else model.sig or result.sigstore at the directory's
// root. Only the root is searched; a signature file deeper in the tree is a
// model file like any other. When both root files are OMS signatures and
// SOCAIR_OMS_SIGNATURE names neither, it does not choose between them: the
// signature is named, not judged. A root signature file that is not the one
// verified is never compared as a model file, and is named as not covered.
func dirSignature(dir, root string, files []modeldir.File, now time.Time) (*provenance.Signature, error) {
	var atRoot []string
	for _, n := range dirSignatureNames {
		if _, ok := find(files, n); ok {
			atRoot = append(atRoot, n)
		}
	}
	p, sigRel := strings.TrimSpace(os.Getenv("SOCAIR_OMS_SIGNATURE")), ""
	if p != "" {
		// A named signature inside the directory is read from the snapshot,
		// so the bytes verified are the bytes the scan holds.
		if sigRel = relInside(dir, p); sigRel != "" {
			if _, ok := find(files, sigRel); ok {
				p = filepath.Join(root, filepath.FromSlash(sigRel))
			}
		}
	} else {
		var found []string
		for _, n := range atRoot {
			raw, err := readBundle(filepath.Join(root, n))
			if err != nil {
				return nil, err
			}
			if oms.Recognize(raw) {
				found = append(found, n)
			}
		}
		switch len(found) {
		case 0:
			return nil, nil
		case 1:
			p, sigRel = filepath.Join(root, found[0]), found[0]
		default:
			return &provenance.Signature{State: provenance.SignatureUnverified, Format: "OMS",
				Detail: "two OMS signatures at the directory's root, " + strings.Join(found, " and ") +
					", and Socair does not choose between them; name the one to verify with SOCAIR_OMS_SIGNATURE"}, nil
		}
	}
	raw, err := readBundle(p)
	if err != nil {
		return nil, err
	}
	trust, err := publisherTrust(now)
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
	cmp := oms.Compare{Signature: sigRel}
	for _, n := range atRoot {
		if n != sigRel {
			cmp.Exclude = append(cmp.Exclude, oms.Exclusion{Path: n, Why: "a signature file, not the one verified"})
		}
	}
	// The walk does not read download-tool metadata, such as the
	// .cache/huggingface/ that `hf download --local-dir` writes into the
	// directory, so the snapshot holds no bytes for a signed file there: it
	// is left out of the comparison and named, not reported missing. It is
	// not among the attested files whether it is on disk or not. Every other
	// signed file is compared.
	m, unread := o.Manifest.Without(func(p string) bool {
		_, _, ok := modeldir.DownloadMetadata(p)
		return ok
	})
	diffs, ignored, cerr := oms.CheckFiles(m, root, files, cmp)
	s := signatureOf(o, diffs, ignored, cerr)
	if s.State == provenance.SignatureVerified {
		s.NotCompared = notCompared(unread)
	}
	return s, nil
}

// notCompared groups signed paths the scan does not read by the directory it
// leaves out, each as "dir/ (N signed files: why)".
func notCompared(paths []string) []string {
	n, why := map[string]int{}, map[string]string{}
	var dirs []string
	for _, p := range paths {
		dir, reason, _ := modeldir.DownloadMetadata(p)
		if n[dir] == 0 {
			dirs = append(dirs, dir)
			why[dir] = reason
		}
		n[dir]++
	}
	sort.Strings(dirs)
	out := make([]string, 0, len(dirs))
	for _, d := range dirs {
		files := "files"
		if n[d] == 1 {
			files = "file"
		}
		out = append(out, fmt.Sprintf("%s (%d signed %s: %s)", d, n[d], files, why[d]))
	}
	return out
}

// relInside is p relative to dir, "/"-separated, when p is inside dir, and
// "" when it is not. Symlinks are resolved first, so /tmp and /private/tmp
// name one place.
func relInside(dir, p string) string {
	real := func(s string) (string, error) {
		if r, err := filepath.EvalSymlinks(s); err == nil {
			s = r
		}
		return filepath.Abs(s)
	}
	ad, err1 := real(dir)
	ap, err2 := real(p)
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
