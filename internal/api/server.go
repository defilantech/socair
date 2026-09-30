// Package api serves the Socair engine over HTTP/JSON for the click-ops
// wizard. It is a thin client of internal/engine: it invents no report shape
// and holds no session.
//
// The API is stateless. A scan returns the report document; a render takes that
// document back and returns bytes. Nothing is stored server-side, so the wizard
// can hold a document and hand it back without the engine keeping state.
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/defilantech/socair/internal/airlock"
	"github.com/defilantech/socair/internal/engine"
	"github.com/defilantech/socair/internal/render"
	"github.com/defilantech/socair/internal/render/pdf"
	"github.com/defilantech/socair/internal/render/sarif"
	"github.com/defilantech/socair/internal/report"
)

// DefaultAddr binds loopback only. The API has no authentication, so the
// default must not be reachable from another host.
const DefaultAddr = "127.0.0.1:8080"

// Options configures the API.
type Options struct {
	// WebDir is a SvelteKit static build to serve at /. Empty serves the API
	// alone.
	WebDir string
	// Version is what /api/version reports.
	Version string
	// StoreRoot is the airlock store. Empty means the airlock endpoints and the
	// store half of the health check are absent, not failed.
	StoreRoot string
}

// Handler returns the HTTP handler for the API. A static web directory, when
// set, is served at / with the SPA fallback, and never shadows /api.
func (o Options) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/version", o.version)
	mux.HandleFunc("GET /api/health", o.health)
	mux.HandleFunc("POST /api/scan", o.scan)
	mux.HandleFunc("POST /api/render", o.render)
	mux.HandleFunc("GET /api/airlock/log", o.airlockLog)
	mux.HandleFunc("POST /api/airlock/ingest", o.airlockIngest)
	mux.HandleFunc("POST /api/airlock/pull", o.airlockPull)
	mux.HandleFunc("POST /api/airlock/promote", o.airlockPromote)

	if strings.TrimSpace(o.WebDir) != "" {
		mux.Handle("/", spaHandler(o.WebDir))
	}
	return mux
}

// CheckAddr reports whether the API may bind addr. The API has no
// authentication, so a non-loopback address needs SOCAIR_API_ALLOW_PUBLIC=1.
func CheckAddr(addr string) error {
	if strings.TrimSpace(addr) == "" {
		return nil
	}
	if !isLoopback(addr) && os.Getenv("SOCAIR_API_ALLOW_PUBLIC") != "1" {
		return fmt.Errorf("refusing to bind %s: the API has no authentication. Bind loopback, or set SOCAIR_API_ALLOW_PUBLIC=1 to override", addr)
	}
	return nil
}

// Serve runs the API. It refuses a non-loopback address unless
// SOCAIR_API_ALLOW_PUBLIC=1 is set, so the engine is not exposed by accident.
func Serve(addr string, opts Options) error {
	if strings.TrimSpace(addr) == "" {
		addr = DefaultAddr
	}
	if err := CheckAddr(addr); err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           opts.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return srv.ListenAndServe()
}

func (o Options) version(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"version": o.Version})
}

// health reports whether the engine and a configured store are usable. It is
// not a constant: a configured store that cannot open is a degraded engine, and
// the wizard must be able to see that.
func (o Options) health(w http.ResponseWriter, _ *http.Request) {
	resp := map[string]any{"ok": true, "version": o.Version, "store": "absent"}
	if strings.TrimSpace(o.StoreRoot) != "" {
		if _, err := airlock.Open(o.StoreRoot); err != nil {
			resp["ok"] = false
			resp["store"] = "unopenable"
			resp["error"] = err.Error()
			writeJSON(w, http.StatusServiceUnavailable, resp)
			return
		}
		resp["store"] = "ready"
	}
	writeJSON(w, http.StatusOK, resp)
}

func (o Options) scan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path  string `json:"path"`
		Local string `json:"local"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	path := strings.TrimSpace(req.Path)
	if path == "" {
		path = strings.TrimSpace(req.Local)
	}
	if path == "" {
		writeError(w, http.StatusBadRequest, "path is required")
		return
	}

	d, err := engine.Scan(path)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if problems := report.Validate(d); len(problems) != 0 {
		writeError(w, http.StatusInternalServerError, "report did not validate: "+strings.Join(problems, "; "))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"report": d})
}

func (o Options) render(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Report *report.Document `json:"report"`
		Format string           `json:"format"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Report == nil {
		writeError(w, http.StatusBadRequest, "report is required")
		return
	}
	if problems := report.Validate(req.Report); len(problems) != 0 {
		writeError(w, http.StatusUnprocessableEntity, "report did not validate: "+strings.Join(problems, "; "))
		return
	}

	switch req.Format {
	case "", "html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := render.Render(w, req.Report); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
		}
	case "pdf":
		w.Header().Set("Content-Type", "application/pdf")
		if err := pdf.RenderPDF(w, req.Report); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
		}
	case "sarif":
		w.Header().Set("Content-Type", "application/sarif+json")
		if err := sarif.Render(w, req.Report); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
		}
	default:
		writeError(w, http.StatusBadRequest, "unknown format "+req.Format)
	}
}

func (o Options) airlockLog(w http.ResponseWriter, _ *http.Request) {
	s, err := o.store()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ev, err := s.Events()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if ev == nil {
		ev = []airlock.Event{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": ev})
}

func (o Options) airlockIngest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Local    string `json:"local"`
		Repo     string `json:"repo"`
		File     string `json:"file"`
		Revision string `json:"revision"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s, err := o.store()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var resolved, source string
	switch {
	case strings.TrimSpace(req.Local) != "":
		source = "local"
		resolved, err = airlock.IngestLocal(req.Local)
	case strings.TrimSpace(req.Repo) != "":
		source = "cache"
		resolved, err = airlock.ResolveCache(airlock.DefaultCacheDir(), req.Repo, req.Revision, req.File)
	default:
		writeError(w, http.StatusBadRequest, "local or repo is required")
		return
	}
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	e := airlock.Event{Action: airlock.ActionIngest, Outcome: airlock.OutcomeOK, Source: source, Detail: resolved}
	if err := s.Record(e); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"path": resolved, "event": e})
}

func (o Options) airlockPull(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Repo     string `json:"repo"`
		File     string `json:"file"`
		SHA256   string `json:"sha256"`
		Revision string `json:"revision"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Repo == "" || req.File == "" || req.SHA256 == "" {
		writeError(w, http.StatusBadRequest, "repo, file, and sha256 are required")
		return
	}
	s, err := o.store()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	dst := filepath.Join(s.StagingPath(req.SHA256), filepath.Base(req.File))
	e, err := airlock.Pull(r.Context(), s, dst, req.Repo, req.Revision, req.SHA256, airlock.DefaultEgressPolicy())
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"path": dst, "event": e})
}

func (o Options) airlockPromote(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Artifact string           `json:"artifact"`
		Report   *report.Document `json:"report"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.Artifact) == "" || req.Report == nil {
		writeError(w, http.StatusBadRequest, "artifact and report are required")
		return
	}
	s, err := o.store()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// The gate reads an attestation from disk. The wizard holds a document, so
	// stage it to a temp file and hand the path to the one gate implementation.
	b, err := json.MarshalIndent(req.Report, "", "  ")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	tmp, err := os.CreateTemp("", "socair-attest-*.json")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	tmp.Close()

	e, err := airlock.Promote(s, req.Artifact, tmpName)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, airlock.ErrRefused) {
			status = http.StatusUnprocessableEntity
		}
		writeError(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"event": e})
}

func (o Options) store() (*airlock.Store, error) {
	if strings.TrimSpace(o.StoreRoot) == "" {
		return nil, errors.New("no airlock store configured; run socair serve with --store")
	}
	return airlock.Open(o.StoreRoot)
}

// spaHandler serves a SvelteKit static build with the SPA fallback. It never
// serves a path outside the build directory.
func spaHandler(dir string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := path.Clean("/" + r.URL.Path)
		p := filepath.Join(dir, filepath.FromSlash(clean))
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			http.ServeFile(w, r, p)
			return
		}
		fallback := filepath.Join(dir, "200.html")
		if _, err := os.Stat(fallback); err != nil {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, fallback)
	})
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	switch host {
	case "127.0.0.1", "localhost", "::1":
		return true
	}
	return false
}

func readJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 32<<20))
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
