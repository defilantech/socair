package airlock

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/checks/pickle"
	"github.com/defilantech/socair/internal/convert"
	"github.com/defilantech/socair/internal/derivation"
	"github.com/defilantech/socair/internal/diskfree"
	"github.com/defilantech/socair/internal/engine"
	"github.com/defilantech/socair/internal/report"
)

// DerivationFile is the signed derivation record a conversion writes beside
// its output in staging.
const DerivationFile = "derivation.dsse.json"

// ErrConvertRefused marks a conversion the airlock declined. The reason is
// in the error, and in the log.
var ErrConvertRefused = errors.New("conversion refused")

// convertSnapshotted is a test hook, called with the input's path once its
// bytes are copied and hashed and before the converter reads the copy.
var convertSnapshotted func(input string)

// Converted is a conversion that landed in staging.
type Converted struct {
	Event Event
	// Path is the staged output, Record the signed derivation record beside
	// it, and Derivation what it says.
	Path, Record string
	Derivation   *derivation.Record
}

// Convert rebuilds a pickle checkpoint as safetensors inside the airlock,
// without unpickling it, and stages the output with a signed derivation
// record that binds it to the input.
//
// The input crosses the same gate a promotion does, and more: its
// attestation must verify against the store's trust policy (Assess), carry
// no FAIL or LEAD on any row, and hold a PASS on the Pickle opcode scan,
// whose grammar the conversion reads the tensors from. NOT_TESTED rows on
// other checks do not block it, because the conversion authorizes nothing:
// they are named in the record, and the output faces its own scan and gate.
// The input's bytes are copied into the store's work area and hashed as they
// are copied; the copy must hash to the attested subject, and the converter
// reads only the copy, so the bytes converted are the bytes that were
// scanned. The converter re-runs the pickle check on the copy and refuses
// anything it does not handle, naming why.
//
// The output is a new artifact. It lands in incoming/<sha256>/ beside its
// record (DerivationFile), unscanned and unsigned, and is scanned and
// promoted like any other. The record is signed with key, which must be one
// the store trusts, so it verifies against the store's own trust policy.
// Every outcome is logged.
func Convert(s *Store, inputPath, envelopePath string, key *attest.PrivateKey) (*Converted, error) {
	inSHA := ""
	// wrapping refuses for a reason and returns cause too, so a caller can
	// tell, say, a short volume (diskfree.ShortError) from other refusals.
	wrapping := func(cause error, format string, a ...any) (*Converted, error) {
		reason := fmt.Sprintf(format, a...)
		e := Event{Action: ActionConvert, Outcome: OutcomeRefused, SHA256: inSHA, Detail: reason}
		if err := s.Record(e); err != nil {
			return nil, fmt.Errorf("%w: %s (also failed to log: %v)", ErrConvertRefused, reason, err)
		}
		if cause != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrConvertRefused, strings.TrimSuffix(reason, ": "+cause.Error()), cause)
		}
		return nil, fmt.Errorf("%w: %s", ErrConvertRefused, reason)
	}
	refuse := func(format string, a ...any) (*Converted, error) { return wrapping(nil, format, a...) }

	if key == nil {
		return nil, errors.New("convert needs a signing key for the derivation record")
	}
	envelope, err := os.ReadFile(envelopePath)
	if err != nil {
		return nil, fmt.Errorf("read attestation %q: %w", envelopePath, err)
	}
	ring, err := s.TrustedKeys()
	if err != nil {
		return refuse("%v", err)
	}
	if _, ok := ring[key.ID]; !ok {
		return refuse("the signing key %s is not in the store's trust policy (%s); the derivation record must verify against it", attest.ShortID(key.ID), s.TrustPath())
	}
	a, err := s.Assess(envelope, now())
	if a != nil {
		inSHA = a.SHA256
	}
	if err != nil {
		return refuse("the input's attestation: %v", err)
	}
	d := &a.Verified.Document
	if len(d.Artifact.Files) > 0 {
		return refuse("the attestation is for a model directory; convert converts one checkpoint file")
	}
	notTested, err := convertible(d)
	if err != nil {
		return refuse("%v", err)
	}
	name := d.Artifact.FileName
	if err := validFileName(name); err != nil {
		return refuse("the attested file name: %v", err)
	}
	outName := strings.TrimSuffix(name, filepath.Ext(name)) + ".safetensors"
	if err := notEvidenceName(outName); err != nil {
		return refuse("%v", err)
	}
	fi, err := os.Stat(inputPath)
	if err != nil {
		return nil, fmt.Errorf("read input %q: %w", inputPath, err)
	}
	if !fi.Mode().IsRegular() {
		return refuse("%s is not a regular file", inputPath)
	}

	tmp, err := s.tmpRoot()
	if err != nil {
		return nil, err
	}
	if err := diskfree.Need(tmp, fi.Size()); err != nil {
		return wrapping(err, "copy the input: %v", err)
	}
	work, err := os.MkdirTemp(tmp, "convert-")
	if err != nil {
		return nil, err
	}
	defer removeTree(work)
	snap, got, err := snapshotFile(inputPath, filepath.Join(work, "in"), name)
	if err != nil {
		return nil, fmt.Errorf("copy the input: %w", err)
	}
	if got != inSHA {
		return refuse("the input hashes to %s, but the attestation is for %s: these are not the bytes that were scanned", got, inSHA)
	}
	if convertSnapshotted != nil {
		convertSnapshotted(inputPath)
	}

	plan, err := convert.PlanFile(snap)
	if reason, ok := convert.IsRefused(err); ok {
		return refuse("%s", reason)
	}
	if err != nil {
		return nil, err
	}
	if err := diskfree.Need(tmp, plan.Size); err != nil {
		return wrapping(err, "write the output: %v", err)
	}
	stage := filepath.Join(work, "stage")
	if err := os.Mkdir(stage, 0o755); err != nil {
		return nil, err
	}
	out, err := plan.Write(filepath.Join(stage, outName))
	if reason, ok := convert.IsRefused(err); ok {
		return refuse("%s", reason)
	}
	if err != nil {
		return refuse("the conversion did not verify: %v", err)
	}

	pred := predicate(a, notTested, name, outName, plan, out)
	record, err := derivation.Sign(pred, key.ID, key.Sign)
	if err != nil {
		return nil, fmt.Errorf("sign the derivation record: %w", err)
	}
	rec, err := derivation.Verify(record, ring)
	if err != nil {
		return nil, fmt.Errorf("the derivation record just signed does not verify: %w", err)
	}
	if err := writeBytes(stage, filepath.Join(stage, DerivationFile), record); err != nil {
		return nil, err
	}
	staged, err := s.placeConverted(stage, out.SHA256, outName)
	if err != nil {
		var exists *otherArtifactError
		if errors.As(err, &exists) {
			return refuse("%v", err)
		}
		return nil, err
	}

	aliases := 0
	for _, t := range out.Tensors {
		if t.AliasOf != "" {
			aliases++
		}
	}
	e := Event{Action: ActionConvert, Outcome: OutcomeOK, SHA256: out.SHA256, Detail: fmt.Sprintf(
		"converted %s (sha256 %s, attestation %s, %s) to %s: %d tensor(s), %d of them exact aliases written once; "+
			"derivation record signed by %s. The output is staged unscanned: it needs its own scan and attestation",
		name, inSHA, d.Header.DocumentID, a.State, outName, len(out.Tensors), aliases, attest.ShortID(key.ID))}
	if err := s.Record(e); err != nil {
		return nil, err
	}
	return &Converted{Event: e, Path: filepath.Join(staged, outName), Record: filepath.Join(staged, DerivationFile), Derivation: rec}, nil
}

// convertible is the input gate on the attestation's rows: no FAIL or LEAD
// on any row, and a PASS on the Pickle opcode scan. It returns the NOT_TESTED
// rows, which do not block.
func convertible(d *report.Document) ([]string, error) {
	var flagged, gaps []string
	pickleRow := ""
	for _, c := range d.Checks {
		switch c.Status {
		case report.StatusFail, report.StatusLead:
			flagged = append(flagged, string(c.Status)+" on "+c.Name)
		case report.StatusNotTested:
			gaps = append(gaps, c.Name)
		}
		if c.Name == pickle.CheckName {
			pickleRow = string(c.Status)
		}
	}
	switch {
	case len(flagged) > 0:
		return nil, fmt.Errorf("the input's attestation has %s; no conversion runs on an input with a FAIL or LEAD", strings.Join(flagged, "; "))
	case pickleRow == "":
		return nil, fmt.Errorf("the input's attestation has no %s row: the input is not a pickle checkpoint", pickle.CheckName)
	case pickleRow != string(report.StatusPass):
		return nil, fmt.Errorf("the input's %s row is %s; conversion reads the tensors from the grammar's model, which only a PASS shows complete", pickle.CheckName, pickleRow)
	}
	return gaps, nil
}

// predicate is the derivation record of a conversion.
func predicate(a *Assessment, notTested []string, inName, outName string, plan *convert.Plan, out *convert.Output) derivation.Predicate {
	d := a.Verified.Document
	p := derivation.Predicate{
		Converter: derivation.Converter{Name: "socair airlock convert", Version: engine.Version, Rules: convert.Rules, Grammar: pickle.Grammar},
		Input: derivation.Input{
			Name: inName, Digest: map[string]string{"sha256": a.SHA256}, Format: "torch.save zip", ByteOrder: plan.ByteOrder,
			Attestation: derivation.Attestation{
				DocumentID: d.Header.DocumentID, DocumentHash: d.Verification.DocumentHash, SignerKeyID: a.Verified.KeyID,
				State: a.State, CheckSetVersion: d.Scope.CheckSetVersion, PickleRow: string(report.StatusPass), NotTested: notTested,
			},
		},
		Output:      derivation.Output{Name: outName, Digest: map[string]string{"sha256": out.SHA256}, Format: "safetensors", SizeBytes: out.Size},
		ConvertedAt: now().UTC().Format(time.RFC3339),
		Metadata:    out.Metadata,
		NotCarried:  plan.NotCarried,
	}
	for _, t := range out.Tensors {
		p.Tensors = append(p.Tensors, derivation.Tensor{
			Name: t.Name, Dtype: t.Dtype, SourceDtype: t.SourceDtype, Shape: t.Shape,
			Source:    derivation.Source{Record: t.Record, OffsetBytes: t.Offset},
			SizeBytes: t.Size, SHA256: t.SHA256, DataOffsets: [2]int64{t.Begin, t.End}, AliasOf: t.AliasOf,
		})
	}
	return p
}

// snapshotFile copies src into dir/name, hashing the bytes as it copies
// them, and makes the copy read-only. What is read from the copy is what was
// hashed, whatever happens to src afterwards.
func snapshotFile(src, dir, name string) (string, string, error) {
	in, err := os.Open(src)
	if err != nil {
		return "", "", err
	}
	defer in.Close()
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", "", err
	}
	dst := filepath.Join(dir, name)
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", "", err
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(out, h), in); err != nil {
		out.Close()
		return "", "", err
	}
	if err := out.Close(); err != nil {
		return "", "", err
	}
	if err := os.Chmod(dst, 0o400); err != nil {
		return "", "", err
	}
	return dst, hex.EncodeToString(h.Sum(nil)), nil
}

// otherArtifactError is a staging entry that already holds another artifact
// under the output's hash.
type otherArtifactError struct{ id, name string }

func (e *otherArtifactError) Error() string {
	return fmt.Sprintf("incoming/%s already holds %s, the same bytes under another name; the output was not staged", e.id, e.name)
}

// placeConverted moves a finished staging directory (the output and its
// record) to incoming/<sha>/. A new entry is renamed into place whole; an
// entry that already exists (the same input converted again, which gives the
// same bytes) gets the record first, then the output, so an output is never
// staged without its record.
func (s *Store) placeConverted(stage, sha, outName string) (string, error) {
	dst := s.StagingPath(sha)
	if _, err := os.Stat(dst); errors.Is(err, os.ErrNotExist) {
		if err := os.Rename(stage, dst); err == nil {
			return dst, nil
		} else if _, serr := os.Stat(dst); serr != nil {
			return "", err
		}
		// Another conversion placed it first: fall through and join it.
	}
	entries, err := os.ReadDir(dst)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if !IsEvidence(e.Name()) && e.Name() != outName {
			return "", &otherArtifactError{id: sha, name: e.Name()}
		}
	}
	rec, err := os.ReadFile(filepath.Join(stage, DerivationFile))
	if err != nil {
		return "", err
	}
	if err := writeBytes(dst, filepath.Join(dst, DerivationFile), rec); err != nil {
		return "", err
	}
	return dst, os.Rename(filepath.Join(stage, outName), filepath.Join(dst, outName))
}
