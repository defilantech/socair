package api

import (
	"context"
	"net/http"

	"github.com/defilantech/socair/internal/airlock"
)

// access is what a route needs: reading the store, or changing it. Step 1
// grants both to the local operator; a login (Step 1b) or roles (paid)
// decide per route here, without touching handlers.
type access int

const (
	readAccess access = iota
	writeAccess
)

type route struct {
	pattern string
	access  access
	handler http.HandlerFunc
}

// LocalOperator is the actor of every request in Step 1: the console binds
// loopback and has no login.
const LocalOperator = "local-operator"

type actorKey struct{}

// identify attaches the caller's identity to the request. Step 1b replaces
// this with an OIDC session; nothing else reads identity.
func identify(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), actorKey{}, LocalOperator))
}

func actorFrom(r *http.Request) string {
	if a, ok := r.Context().Value(actorKey{}).(string); ok {
		return a
	}
	return ""
}

// authorize is the one place access is decided. In Step 1 every identified
// caller may read and write.
func authorize(_ access, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { next(w, r) }
}

// storeFor opens the configured store with the request's actor, so every log
// entry the request causes names who caused it.
func (o Options) storeFor(r *http.Request) (*airlock.Store, error) {
	s, err := o.store()
	if err != nil {
		return nil, err
	}
	s.Actor = actorFrom(r)
	return s, nil
}

func (o Options) routes(limit func(http.HandlerFunc) http.HandlerFunc) []route {
	return []route{
		{"GET /api/version", readAccess, o.version},
		{"GET /api/health", readAccess, o.health},
		{"POST /api/scan", readAccess, limit(o.scan)},
		{"POST /api/render", readAccess, o.render},
		{"GET /api/airlock/log", readAccess, o.airlockLog},
		{"POST /api/airlock/ingest", writeAccess, limit(o.airlockIngest)},
		{"POST /api/airlock/pull", writeAccess, limit(o.airlockPull)},
		{"POST /api/airlock/promote", writeAccess, limit(o.airlockPromote)},
		{"GET /api/airlock/models", readAccess, o.consoleModels},
		{"GET /api/airlock/models/{id}", readAccess, o.consoleModel},
		{"GET /api/airlock/models/{id}/files/{name}", readAccess, o.consoleFile},
	}
}
