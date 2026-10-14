package airlock

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/checks/pickle"
	"github.com/defilantech/socair/internal/checks/pickle/pickletest"
	"github.com/defilantech/socair/internal/derivation"
	"github.com/defilantech/socair/internal/engine"
	"github.com/defilantech/socair/internal/report"
)

// quietScan clears every engine input, so a scan of a fixture reads only the
// fixture.
func quietScan(t *testing.T) {
	t.Helper()
	for _, k := range []string{"SOCAIR_ACCEPTANCE_EXPIRES", "SOCAIR_ACCEPTED_BY", "SOCAIR_DENYLIST", "SOCAIR_FEED", "SOCAIR_FEED_KEYS",
		"SOCAIR_INTAKE_POLICY", "SOCAIR_LICENSE_POLICY", "SOCAIR_OMS_SIGNATURE", "SOCAIR_PROVENANCE", "SOCAIR_PUBLISHER_ROOTS",
		"SOCAIR_REPO_MIRROR", "SOCAIR_SCAN_TMP", "SOCAIR_SIGSTORE_IDENTITIES", "SOCAIR_SIGSTORE_VERIFIER",
		"SOCAIR_TEMPLATE_REFERENCE", "SOCAIR_TOKENIZER_REFERENCE", "SOCAIR_TIER2_HELPER", "SOCAIR_TIER2_ENDPOINT", "SOCAIR_ROOM_CHECK"} {
		t.Setenv(k, "")
	}
}

// operator is a signing key the store trusts.
func operator(t *testing.T, s *Store) *attest.PrivateKey {
	t.Helper()
	prefix := filepath.Join(t.TempDir(), "op")
	if _, err := attest.GenerateNamedKey(prefix, "Test Operator"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Trust(prefix + ".pub"); err != nil {
		t.Fatal(err)
	}
	k, err := attest.LoadPrivateKey(prefix + ".key")
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// checkpoint is a module state dict: an OrderedDict root, tied weights, two
// views of a fused buffer, and a bf16 parameter.
func checkpoint() pickletest.Checkpoint {
	return pickletest.Checkpoint{
		Ordered: true,
		Storages: []pickletest.Storage{
			{Dtype: "float32", Data: pickletest.Seq(48, 1)},
			{Dtype: "bfloat16", Data: pickletest.Seq(16, 2)},
			{Dtype: "float32", Data: pickletest.Seq(16, 3)},
		},
		Tensors: []pickletest.Tensor{
			{Name: "embed.weight", Storage: 0, Shape: []int{3, 4}},
			{Name: "lm_head.weight", Storage: 0, Shape: []int{3, 4}},
			{Name: "attn.q", Storage: 1, Shape: []int{4}, Param: true},
			{Name: "attn.k", Storage: 1, Shape: []int{4}, Offset: 4},
			{Name: "norm.weight", Storage: 2, Shape: []int{4}},
		},
	}
}

// staged pulls a checkpoint into the store as a pull would, scans it, and
// signs the report. It returns the staged path, its envelope, and the report.
func staged(t *testing.T, s *Store, k *attest.PrivateKey, file []byte) (string, string, *report.Document) {
	t.Helper()
	sum := sha256.Sum256(file)
	dst, err := s.StagingFile(hex.EncodeToString(sum[:]), "pytorch_model.bin")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, file, 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := engine.Scan(dst)
	if err != nil {
		t.Fatal(err)
	}
	env, err := attest.Sign(*d, k)
	if err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(filepath.Dir(dst), StagedAttestation)
	if err := os.WriteFile(envPath, env, 0o600); err != nil {
		t.Fatal(err)
	}
	return dst, envPath, d
}

func row(d *report.Document, name string) report.CheckResult {
	for _, c := range d.Checks {
		if c.Name == name {
			return c
		}
	}
	return report.CheckResult{}
}

// TestConvertStagesTheOutputWithItsRecord is the issue's outcome: a
// checkpoint whose Pickle row PASSed is converted, the output lands in
// staging under its own hash with a signed record binding it to the input,
// and the log records it. The output is a new artifact: the input's ticket
// does not admit it, and its own scan grades it afresh.
func TestConvertStagesTheOutputWithItsRecord(t *testing.T) {
	quietScan(t)
	s, _ := Init(t.TempDir())
	k := operator(t, s)
	c := checkpoint()
	in, env, d := staged(t, s, k, c.Zip())
	if row(d, pickle.CheckName).Status != report.StatusPass || d.PromotionAuthorization.State != report.StateWithheld {
		t.Fatalf("setup: pickle row %s, state %s; want a PASS on a withheld report", row(d, pickle.CheckName).Status, d.PromotionAuthorization.State)
	}

	got, err := Convert(s, in, env, k)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(got.Path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	outSHA := hex.EncodeToString(sum[:])
	if got.Path != filepath.Join(s.StagingPath(outSHA), "pytorch_model.safetensors") {
		t.Fatalf("output at %s, want incoming/%s/pytorch_model.safetensors", got.Path, outSHA)
	}

	ring, _ := s.TrustedKeys()
	raw, _ := os.ReadFile(got.Record)
	rec, err := derivation.Verify(raw, ring)
	if err != nil {
		t.Fatal(err)
	}
	pa := rec.Input.Attestation
	switch {
	case rec.Input.Digest["sha256"] != d.Artifact.SHA256 || rec.Output.Digest["sha256"] != outSHA:
		t.Errorf("record binds %s to %s, want %s to %s", rec.Input.Digest, rec.Output.Digest, d.Artifact.SHA256, outSHA)
	case pa.SignerKeyID != k.ID || pa.State != report.StateWithheld || pa.PickleRow != "PASS" || pa.DocumentID != d.Header.DocumentID:
		t.Errorf("record's attestation %+v", pa)
	case !strings.Contains(strings.Join(pa.NotTested, ","), "Format and structure"):
		t.Errorf("record's not-tested rows %v do not name the input's gaps", pa.NotTested)
	case len(rec.Tensors) != len(c.Tensors) || rec.Metadata["lm_head.weight"] != "embed.weight":
		t.Errorf("record maps %d tensors, metadata %v", len(rec.Tensors), rec.Metadata)
	case rec.Converter.Rules == "" || rec.Converter.Grammar != pickle.Grammar:
		t.Errorf("converter %+v", rec.Converter)
	}
	for _, rt := range rec.Tensors {
		for _, ct := range c.Tensors {
			if ct.Name == rt.Name {
				h := sha256.Sum256(c.Bytes(ct))
				if rt.SHA256 != hex.EncodeToString(h[:]) {
					t.Errorf("%s: record hash %s does not hash the checkpoint's bytes", rt.Name, rt.SHA256)
				}
			}
		}
	}

	if e := lastEvent(t, s); e.Action != ActionConvert || e.Outcome != OutcomeOK || e.SHA256 != outSHA || !strings.Contains(e.Detail, d.Artifact.SHA256) {
		t.Errorf("log %+v", e)
	}
	models, err := s.Models(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var m *Model
	for i := range models {
		if models[i].ID == outSHA {
			m = &models[i]
		}
	}
	if m == nil || m.Stage != StageStaged || m.Name != "pytorch_model.safetensors" {
		t.Fatalf("the output's entry %+v, want a staged, unscanned model", m)
	}
	if evidence, _ := s.Evidence(outSHA); strings.Join(evidence, ",") != DerivationFile {
		t.Errorf("the output's evidence %v, want only its record", evidence)
	}
	left, _ := os.ReadDir(filepath.Join(s.Root, tmpDir))
	if len(left) != 0 {
		t.Errorf("the work area holds %d leftover entries", len(left))
	}

	// The input's ticket is not the output's.
	if _, err := Promote(s, got.Path, env); !errors.Is(err, ErrRefused) {
		t.Errorf("promoting the output on the input's attestation: %v, want a refusal", err)
	}
	out, err := engine.Scan(got.Path)
	if err != nil {
		t.Fatal(err)
	}
	if out.Artifact.SHA256 != outSHA || out.Artifact.Format != "safetensors" || row(out, "Format and structure").Status != report.StatusPass {
		t.Errorf("the output scans as %s %s, structure %s", out.Artifact.SHA256, out.Artifact.Format, row(out, "Format and structure").Status)
	}
	if out.PromotionAuthorization.State == report.StateAuthorized {
		t.Errorf("the output's own scan reads authorized with no inputs; nothing about the conversion should carry over")
	}
}

// TestConvertRefusesALeadOrFail: a checkpoint whose attestation has a LEAD
// or FAIL on any row is refused, the Pickle row's or another's, and nothing
// is staged. Falsification: drop the flagged rows from convertible and these
// convert (the denylist case's pickle is clean).
func TestConvertRefusesALeadOrFail(t *testing.T) {
	quietScan(t)
	clean := checkpoint().Zip()
	sum := sha256.Sum256(clean)
	deny := filepath.Join(t.TempDir(), "denylist.txt")
	if err := os.WriteFile(deny, []byte(hex.EncodeToString(sum[:])+"  known-bad\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hooked := checkpoint()
	hooked.Tensors[4].Hook = true
	overrun := checkpoint()
	overrun.Tensors[4].Stride = []int{2}
	cases := []struct {
		name, want string
		file       []byte
		denylist   string
	}{
		{"a backward hook", "LEAD on " + pickle.CheckName, hooked.Zip(), ""},
		{"a view past its storage", "FAIL on " + pickle.CheckName, overrun.Zip(), ""},
		{"a denylisted hash", "FAIL on Known-bad hash match", clean, deny},
	}
	for _, c := range cases {
		t.Setenv("SOCAIR_DENYLIST", c.denylist)
		s, _ := Init(t.TempDir())
		k := operator(t, s)
		in, env, _ := staged(t, s, k, c.file)
		before, _ := os.ReadDir(s.StagingRoot())
		_, err := Convert(s, in, env, k)
		if !errors.Is(err, ErrConvertRefused) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want a refusal naming %q", c.name, err, c.want)
		}
		if after, _ := os.ReadDir(s.StagingRoot()); len(after) != len(before) {
			t.Errorf("%s: a refused conversion staged something", c.name)
		}
		if e := lastEvent(t, s); e.Action != ActionConvert || e.Outcome != OutcomeRefused || !strings.Contains(e.Detail, c.want) {
			t.Errorf("%s: log %+v", c.name, e)
		}
	}
}

// TestConvertRefusesAChangedStorage: a storage byte changed after the scan is
// detected, because the input is re-hashed against the attested subject,
// and the conversion is refused. Falsification: skip the comparison in
// Convert and the changed bytes convert.
func TestConvertRefusesAChangedStorage(t *testing.T) {
	quietScan(t)
	c := checkpoint()
	flipped := func(b []byte) []byte {
		b = append([]byte(nil), b...)
		data := c.Storages[2].Data
		b[bytes.Index(b, data)+len(data)-1] ^= 0x01
		return b
	}
	// The second rewrites the checkpoint whole, so its CRC-32s hold and only
	// the hash shows the change.
	rewritten := checkpoint()
	rewritten.Storages[2].Data = flipped(rewritten.Storages[2].Data)
	for name, changed := range map[string][]byte{
		"one byte flipped in place":       flipped(c.Zip()),
		"rewritten with one byte changed": rewritten.Zip(),
	} {
		s, _ := Init(t.TempDir())
		k := operator(t, s)
		in, env, d := staged(t, s, k, c.Zip())
		if err := os.WriteFile(in, changed, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := Convert(s, in, env, k)
		if !errors.Is(err, ErrConvertRefused) || !strings.Contains(err.Error(), "but the attestation is for "+d.Artifact.SHA256) {
			t.Errorf("%s: %v, want a refusal naming the attested hash", name, err)
		}
	}
}

// TestConvertReadsTheBytesItHashed: bytes changed after the input is copied
// and hashed do not reach the output. Falsification: convert inputPath
// instead of the copy and the output carries the change.
func TestConvertReadsTheBytesItHashed(t *testing.T) {
	quietScan(t)
	s, _ := Init(t.TempDir())
	k := operator(t, s)
	c := checkpoint()
	file := c.Zip()
	in, env, _ := staged(t, s, k, file)
	t.Cleanup(func() { convertSnapshotted = nil })
	convertSnapshotted = func(p string) {
		changed := append([]byte(nil), file...)
		data := c.Storages[0].Data
		changed[bytes.Index(changed, data)] ^= 0xff
		if err := os.WriteFile(p, changed, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := Convert(s, in, env, k)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(c.Bytes(c.Tensors[0]))
	for _, rt := range got.Derivation.Tensors {
		if rt.Name == "embed.weight" && rt.SHA256 != hex.EncodeToString(h[:]) {
			t.Fatal("the output carries bytes changed after the input was hashed")
		}
	}
}

// TestConvertNeedsTrustedKeys: the input's attestation must verify against
// the store's trust policy, and the record's signing key must be in it.
func TestConvertNeedsTrustedKeys(t *testing.T) {
	quietScan(t)
	s, _ := Init(t.TempDir())
	k := operator(t, s)
	in, env, _ := staged(t, s, k, checkpoint().Zip())

	prefix := filepath.Join(t.TempDir(), "stranger")
	if _, err := attest.GenerateKey(prefix); err != nil {
		t.Fatal(err)
	}
	stranger, _ := attest.LoadPrivateKey(prefix + ".key")
	if _, err := Convert(s, in, env, stranger); !errors.Is(err, ErrConvertRefused) || !strings.Contains(err.Error(), "not in the store's trust policy") {
		t.Errorf("an untrusted record key: %v", err)
	}

	other, _ := Init(t.TempDir())
	ok := operator(t, other)
	if _, err := Convert(other, in, env, ok); !errors.Is(err, ErrConvertRefused) || !strings.Contains(err.Error(), "attestation") {
		t.Errorf("an attestation by a key this store does not trust: %v", err)
	}
}

// TestConvertChecksRoom: a conversion that cannot fit is refused before the
// copy, naming the volume.
func TestConvertChecksRoom(t *testing.T) {
	quietScan(t)
	s, _ := Init(t.TempDir())
	k := operator(t, s)
	in, env, _ := staged(t, s, k, checkpoint().Zip())
	fullDisk(t, 3)
	_, err := Convert(s, in, env, k)
	wantShort(t, "convert", err, filepath.Join(s.Root, tmpDir))
	if !errors.Is(err, ErrConvertRefused) {
		t.Errorf("%v is not a refusal", err)
	}
}

// TestConvertAgainJoinsTheEntry: converting the same input again gives the
// same bytes, and the entry keeps one artifact.
func TestConvertAgainJoinsTheEntry(t *testing.T) {
	quietScan(t)
	s, _ := Init(t.TempDir())
	k := operator(t, s)
	in, env, _ := staged(t, s, k, checkpoint().Zip())
	a, err := Convert(s, in, env, k)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Convert(s, in, env, k)
	if err != nil {
		t.Fatal(err)
	}
	if a.Path != b.Path || a.Event.SHA256 != b.Event.SHA256 {
		t.Fatalf("two conversions staged %s and %s", a.Path, b.Path)
	}
	if _, err := s.stagedArtifact(a.Event.SHA256); err != nil {
		t.Fatal(err)
	}
}

// TestConvertRefusesADirectoryAttestation: a model directory's attestation
// names many files; convert takes one checkpoint.
func TestConvertRefusesADirectoryAttestation(t *testing.T) {
	quietScan(t)
	s, _ := Init(t.TempDir())
	k := operator(t, s)
	dir := filepath.Join(t.TempDir(), "model")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pytorch_model.bin"), checkpoint().Zip(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := engine.Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	env, err := attest.Sign(*d, k)
	if err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(t.TempDir(), "a.dsse.json")
	_ = os.WriteFile(envPath, env, 0o600)
	if _, err := Convert(s, filepath.Join(dir, "pytorch_model.bin"), envPath, k); !errors.Is(err, ErrConvertRefused) || !strings.Contains(err.Error(), "model directory") {
		t.Fatalf("%v", err)
	}
}
