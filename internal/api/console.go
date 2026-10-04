package api

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/defilantech/socair/internal/airlock"
	"github.com/defilantech/socair/internal/engine"
	"github.com/defilantech/socair/internal/inventory"
)

func (o Options) consoleModels(w http.ResponseWriter, r *http.Request) {
	s, err := o.storeFor(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ms, err := s.Models(time.Now())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if ms == nil {
		ms = []airlock.Model{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"models": ms})
}

func (o Options) consoleModel(w http.ResponseWriter, r *http.Request) {
	s, err := o.storeFor(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	id := r.PathValue("id")
	m, d, err := s.Model(id, time.Now())
	if errors.Is(err, airlock.ErrNoModel) {
		writeError(w, http.StatusNotFound, "no model "+id+" in the store")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	all, err := s.Events()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	events := []airlock.Event{}
	for _, e := range all {
		if e.SHA256 == id {
			events = append(events, e)
		}
	}
	evidence, err := s.Evidence(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"model": m, "report": d, "events": events, "evidence": evidence})
}

func (o Options) consoleFile(w http.ResponseWriter, r *http.Request) {
	s, err := o.storeFor(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	name := r.PathValue("name")
	p, err := s.EvidencePath(r.PathValue("id"), name)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	b, err := os.ReadFile(p)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	_, _ = w.Write(b)
}

// maxEnvelope bounds an uploaded attestation: real ones are kilobytes.
const maxEnvelope = 4 << 20

func (o Options) consoleScan(w http.ResponseWriter, r *http.Request) {
	s, err := o.storeFor(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	id := r.PathValue("id")
	// The staged copy, never the clean entry: an id can be in both (Promote
	// leaves the staged copy), and a rescan acts on what is staged.
	m, _, err := s.StagedModel(id, time.Now())
	if errors.Is(err, airlock.ErrNoModel) {
		writeError(w, http.StatusNotFound, "no staged model "+id)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if m.ArtifactPath == "" {
		writeError(w, http.StatusUnprocessableEntity, m.StageReason)
		return
	}
	prov := filepath.Join(filepath.Dir(m.ArtifactPath), airlock.ProvenanceFile)
	d, err := engine.ScanWith(m.ArtifactPath, engine.ModeFull, engine.Inputs{Provenance: prov})
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if err := s.SaveReport(id, d); err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	m, _, _ = s.StagedModel(id, time.Now())
	writeJSON(w, http.StatusOK, map[string]any{"report": d, "model": m})
}

func (o Options) consoleAttestation(w http.ResponseWriter, r *http.Request) {
	s, err := o.storeFor(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxEnvelope+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(raw) > maxEnvelope {
		writeError(w, http.StatusRequestEntityTooLarge, "an attestation is at most 4 MiB")
		return
	}
	if !json.Valid(raw) {
		writeError(w, http.StatusBadRequest, "the body is not a JSON DSSE envelope")
		return
	}
	id := r.PathValue("id")
	name, err := s.SaveAttestation(id, raw, time.Now())
	if errors.Is(err, airlock.ErrNoModel) {
		writeError(w, http.StatusNotFound, "no staged model "+id)
		return
	}
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	m, _, _ := s.StagedModel(id, time.Now())
	writeJSON(w, http.StatusOK, map[string]any{"file": name, "model": m})
}

func (o Options) consoleExport(w http.ResponseWriter, r *http.Request) {
	s, err := o.storeFor(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	tmp, err := os.MkdirTemp("", "socair-export-*")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer os.RemoveAll(tmp)
	at := time.Now()
	if _, err := inventory.Export(s, tmp, nil, at, "socair "+o.Version); err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	err = filepath.WalkDir(tmp, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(tmp, p)
		f, err := zw.Create(filepath.ToSlash(rel))
		if err != nil {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		_, err = f.Write(b)
		return err
	})
	if err == nil {
		err = zw.Close()
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="socair-inventory-`+at.UTC().Format("20060102T150405Z")+`.zip"`)
	_, _ = w.Write(buf.Bytes())
}
