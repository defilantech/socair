package api

import (
	"net/http"
	"strings"
	"testing"
)

// Every API route is classified, GETs are reads, and the identity hook names
// the local operator. Roles later map onto access without touching handlers.
func TestRoutesAreClassified(t *testing.T) {
	rs := Options{}.routes(func(h http.HandlerFunc) http.HandlerFunc { return h })
	if len(rs) < 8 {
		t.Fatalf("only %d routes", len(rs))
	}
	for _, r := range rs {
		method, path, _ := strings.Cut(r.pattern, " ")
		if !strings.HasPrefix(path, "/api/") {
			t.Errorf("%s is not an API route", r.pattern)
		}
		if method == "GET" && r.access != readAccess {
			t.Errorf("%s is a GET but not a read", r.pattern)
		}
	}
}

func TestActorIsTheLocalOperator(t *testing.T) {
	req, _ := http.NewRequest("GET", "/api/version", nil)
	if got := actorFrom(identify(req)); got != LocalOperator {
		t.Fatalf("actor %q", got)
	}
}
