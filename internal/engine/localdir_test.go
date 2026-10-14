package engine

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/oms/omstest"
	"github.com/defilantech/socair/internal/report"
)

// hfLayouts are where huggingface_hub's `hf download <repo> --local-dir <dir>`
// writes its download metadata inside <dir>: .cache/huggingface/ from 0.24.0
// on, .huggingface/ in 0.23.x (src/huggingface_hub/_local_folder.py,
// _huggingface_dir). Before 0.23.0 it wrote nothing into the directory.
var hfLayouts = []string{".cache/huggingface", ".huggingface"}

// hfMetadata is what huggingface_hub writes under meta for the files it
// downloads: a .gitignore holding "*", and per file a .metadata record (the
// commit, the etag, and a timestamp) and a .lock. 2.2.0 also writes a
// CACHEDIR.TAG and the repo tree it listed.
func hfMetadata(meta string, at string) map[string]string {
	out := map[string]string{
		meta + "/.gitignore":   "*",
		meta + "/CACHEDIR.TAG": "Signature: 8a477f597d28d172789f06886806bc55\n",
		meta + "/trees/71034c5d8bde858ff824298bdedc65515b97d2b9.json": `[]`,
	}
	for _, f := range []string{"config.json", "model.safetensors", "tokenizer_config.json", "tokenizer.json"} {
		out[meta+"/download/"+f+".metadata"] = "71034c5d8bde858ff824298bdedc65515b97d2b9\n4ff64fe5192d88c0b5dbfc578c775c0ce05dd7d0\n" + at + "\n"
		out[meta+"/download/"+f+".lock"] = ""
	}
	return out
}

// signedLocalDir writes modelRepo with download metadata in the given layout
// and signs it, metadata and all, as `model_signing sign key` signs a
// directory: every file but the OMS default exclusions, the signature
// written to model.sig at the root afterwards. With meta "" the directory
// carries no metadata when signed. It sets SOCAIR_PUBLISHER_KEYS to the key.
func signedLocalDir(t *testing.T, meta string, extra map[string]string) string {
	t.Helper()
	files := map[string]string{}
	if meta != "" {
		files = hfMetadata(meta, "1791963133.985419")
	}
	for k, v := range extra {
		files[k] = v
	}
	dir := modelRepo(t, files)
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := omstest.Sign(dir, omstest.Options{Key: k})
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureAt(t, filepath.Join(dir, "model.sig"), sig)
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pub := filepath.Join(t.TempDir(), "publisher.pub")
	writeFixtureAt(t, pub, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	for _, k := range []string{"SOCAIR_PROVENANCE", "SOCAIR_OMS_SIGNATURE", "SOCAIR_PUBLISHER_ROOTS", "SOCAIR_SIGSTORE_VERIFIER"} {
		t.Setenv(k, "")
	}
	t.Setenv("SOCAIR_PUBLISHER_KEYS", pub)
	return dir
}

func writeUnder(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for rel, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFixtureAt(t, p, []byte(body))
	}
}

// A directory downloaded with `hf download --local-dir` and then signed with
// model_signing carries signed files under huggingface_hub's metadata
// directory, which the scan does not read. They are not compared, and named,
// rather than reported missing: the signature holds over every file the scan
// read, so provenance PASSes. Re-running the download rewrites each .metadata
// timestamp, and copying the model without the directory removes them; the
// verdict is the same, since the attested files are the same. Falsification:
// compare them as the scan's files and every case FAILs "missing: ...".
func TestSignedDownloadMetadataIsNotCompared(t *testing.T) {
	top := func(meta string) string { return strings.SplitN(meta, "/", 2)[0] + "/" }
	for _, meta := range hfLayouts {
		for _, after := range []string{"as signed", "metadata rewritten", "metadata removed"} {
			dir := signedLocalDir(t, meta, nil)
			switch after {
			case "metadata rewritten":
				writeUnder(t, dir, hfMetadata(meta, "1792000000.5"))
			case "metadata removed":
				if err := os.RemoveAll(filepath.Join(dir, top(meta))); err != nil {
					t.Fatal(err)
				}
			}
			d, err := Scan(dir)
			if err != nil {
				t.Fatal(err)
			}
			r := row(d, provRow)
			if r.Status != report.StatusPass || !strings.Contains(r.Notes, "every signed file the scan read matches") {
				t.Errorf("%s, %s: provenance %s (%s)", meta, after, r.Status, r.Notes)
				continue
			}
			want := "Signed but not compared, as the scan does not read them: " + top(meta) + " (11 signed files: "
			if !strings.Contains(r.Notes, want) {
				t.Errorf("%s, %s: notes %q, want %q", meta, after, r.Notes, want)
			}
			if s := d.Artifact.PublisherSigningState; !strings.HasPrefix(s, "verified (OMS, key ") {
				t.Errorf("%s, %s: publisher_signing_status %q", meta, after, s)
			}
			for _, f := range d.Artifact.Files {
				if strings.HasPrefix(f.Path, top(meta)) {
					t.Errorf("%s, %s: %s is among the attested files", meta, after, f.Path)
				}
			}
		}
	}
}

// The reverse: signed before the download wrote its metadata, scanned after.
// The metadata is no file of the scan's and the signature does not list it,
// so every signed file is compared and matches, and the note claims nothing
// more. (model_signing 1.1.1's own verify fails this one on the extra files.)
func TestDownloadMetadataAddedAfterSigning(t *testing.T) {
	for _, meta := range hfLayouts {
		dir := signedLocalDir(t, "", nil)
		writeUnder(t, dir, hfMetadata(meta, "1791963133.985419"))
		d, err := Scan(dir)
		if err != nil {
			t.Fatal(err)
		}
		r := row(d, provRow)
		if r.Status != report.StatusPass || !strings.Contains(r.Notes, "every signed file matches") || strings.Contains(r.Notes, "not compared") {
			t.Errorf("%s: provenance %s (%s)", meta, r.Status, r.Notes)
		}
	}
}

// Falsification: the download metadata is the only thing left out. With
// signed metadata present, a changed, missing, or unsigned model file still
// FAILs, and so does a signed file under a directory that only resembles the
// metadata's, or under another directory the scan skips that is not download
// metadata (__pycache__).
func TestDownloadMetadataHidesNoModelFile(t *testing.T) {
	near := map[string]string{
		".cache-old/huggingface/weights.txt": "near 1",
		"huggingface/download/notes.txt":     "near 2",
		"cache/huggingface/notes.txt":        "near 3",
	}
	for _, meta := range hfLayouts {
		for _, c := range []struct {
			name string
			edit func(dir string) error
			want string
		}{
			{"changed weights", func(dir string) error {
				return os.WriteFile(filepath.Join(dir, "model.safetensors"), []byte("other weights"), 0o644)
			}, "changed: model.safetensors"},
			{"missing config", func(dir string) error { return os.Remove(filepath.Join(dir, "config.json")) }, "missing: config.json"},
			{"unsigned code", func(dir string) error {
				return os.WriteFile(filepath.Join(dir, "modeling_extra.py"), []byte("import os\n"), 0o644)
			}, "not signed: modeling_extra.py"},
			{"near-miss directory", func(dir string) error {
				return os.WriteFile(filepath.Join(dir, ".cache-old", "huggingface", "weights.txt"), []byte("changed"), 0o644)
			}, "changed: .cache-old/huggingface/weights.txt"},
			{"near-miss missing", func(dir string) error {
				return os.Remove(filepath.Join(dir, "huggingface", "download", "notes.txt"))
			}, "missing: huggingface/download/notes.txt"},
			{"other skipped directory", func(dir string) error {
				return os.MkdirAll(filepath.Join(dir, "__pycache__"), 0o755)
			}, "missing: __pycache__/modeling.cpython-312.pyc"},
		} {
			extra := near
			if c.name == "other skipped directory" {
				extra = map[string]string{"__pycache__/modeling.cpython-312.pyc": "compiled"}
			}
			dir := signedLocalDir(t, meta, extra)
			if err := c.edit(dir); err != nil {
				t.Fatal(err)
			}
			d, err := Scan(dir)
			if err != nil {
				t.Fatal(err)
			}
			r := row(d, provRow)
			if r.Status != report.StatusFail || !strings.Contains(r.Notes, c.want) {
				t.Errorf("%s, %s: provenance %s (%s), want FAIL naming %q", meta, c.name, r.Status, r.Notes, c.want)
			}
			if strings.Contains(r.Notes, "missing: "+strings.SplitN(meta, "/", 2)[0]) {
				t.Errorf("%s, %s: the metadata is reported missing: %s", meta, c.name, r.Notes)
			}
			if d.PromotionAuthorization.Authorized {
				t.Errorf("%s, %s: promotion authorized", meta, c.name)
			}
		}
	}
}
