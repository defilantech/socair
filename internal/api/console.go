package api

import (
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/defilantech/socair/internal/airlock"
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
	writeJSON(w, http.StatusOK, map[string]any{"model": m, "report": d, "events": events})
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
