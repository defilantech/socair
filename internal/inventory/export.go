package inventory

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"time"

	"github.com/defilantech/socair/internal/airlock"
	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/render"
)

//go:embed index.html
var indexTmpl string

var index = template.Must(template.New("index").Parse(indexTmpl))

// Export writes a snapshot of the store to dir: index.html, each approved
// model's report and attestation files, the log and its head, and the
// inventory statement, signed when key is set. It never copies model bytes or
// keys, and it refuses a store whose log chain is broken: a snapshot of a
// tampered log would not verify.
func Export(s *airlock.Store, dir string, key *attest.PrivateKey, at time.Time, toolVersion string) (*Statement, error) {
	if entries, err := os.ReadDir(dir); err == nil && len(entries) > 0 {
		return nil, fmt.Errorf("%s exists and is not empty; export into a new or empty directory", dir)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(dir, "models"), 0o755); err != nil {
		return nil, err
	}
	// The log is read once: the copy in the snapshot is the copy whose chain
	// is checked and whose head is recorded.
	logBytes, err := os.ReadFile(s.LogPath())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	logCopy := filepath.Join(dir, "log.jsonl")
	if err := os.WriteFile(logCopy, logBytes, 0o644); err != nil {
		return nil, err
	}
	chain, err := airlock.VerifyFile(logCopy, airlock.VerifyOptions{})
	if err != nil {
		return nil, err
	}
	if chain.Broken != 0 {
		_ = os.RemoveAll(dir) // dir was absent or empty on entry
		return nil, fmt.Errorf("the activity log chain is broken at line %d (%s); resolve it before exporting", chain.Broken, chain.Reason)
	}
	models, err := s.Models(at)
	if err != nil {
		return nil, err
	}
	attestations := map[string][]byte{}
	for _, m := range models {
		// Only clean entries carry an attestation to copy; a staging entry
		// whose staged acceptance lapsed is listed under other by Build.
		if m.Location != "clean" || (m.Stage != airlock.StageApproved && m.Stage != airlock.StageAcceptanceExpired) {
			continue
		}
		out := filepath.Join(dir, "models", m.ID)
		if err := os.MkdirAll(out, 0o755); err != nil {
			return nil, err
		}
		for _, name := range []string{"attestation.dsse.json", "attestation.json"} {
			p, err := s.EvidencePath(m.ID, name)
			if err != nil {
				return nil, err
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return nil, err
			}
			if err := os.WriteFile(filepath.Join(out, name), b, 0o644); err != nil {
				return nil, err
			}
			if name == "attestation.dsse.json" {
				attestations[m.ID] = b
			}
		}
		_, d, err := s.Model(m.ID, at)
		if err != nil || d == nil {
			return nil, errors.New(m.ID + ": no verified report to render")
		}
		var html bytes.Buffer
		if err := render.Render(&html, d); err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(out, "report.html"), html.Bytes(), 0o644); err != nil {
			return nil, err
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "log-head.txt"), []byte(chain.Head+"\n"), 0o644); err != nil {
		return nil, err
	}

	st := Build(models, attestations, chain.Head, toolVersion, at)
	var payload, envelope []byte
	if key != nil {
		payload, envelope, err = Sign(st, key)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(dir, "inventory.dsse.json"), envelope, 0o644); err != nil {
			return nil, err
		}
	} else if payload, err = jsonIndent(st); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "inventory.json"), payload, 0o644); err != nil {
		return nil, err
	}

	var page bytes.Buffer
	if err := index.Execute(&page, struct {
		St     Statement
		Signed bool
	}{st, key != nil}); err != nil {
		return nil, err
	}
	return &st, os.WriteFile(filepath.Join(dir, "index.html"), page.Bytes(), 0o644)
}
