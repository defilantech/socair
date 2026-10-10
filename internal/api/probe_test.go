package api

import (
	"net"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defilantech/socair/internal/airlock"
)

// addrOf is the host:port a test server listens on.
func addrOf(ts *httptest.Server) string { return strings.TrimPrefix(ts.URL, "http://") }

// TestProbeHealthy: a container's probe runs `socair health` against the API
// on the pod's loopback, so a healthy engine and store must answer nil.
// Falsification: have Probe return an error for every answer and this fails.
func TestProbeHealthy(t *testing.T) {
	store := filepath.Join(t.TempDir(), "store")
	if _, err := airlock.Init(store); err != nil {
		t.Fatal(err)
	}
	ts := server(t, Options{Version: "test", StoreRoot: store})
	if err := Probe(addrOf(ts), time.Second); err != nil {
		t.Fatalf("Probe on a healthy API = %v, want nil", err)
	}
}

// TestProbeUnhealthyStore: a store that cannot open answers 503, and the probe
// must fail with the reason, so the kubelet restarts the pod or holds traffic.
// Falsification: have Probe accept any HTTP answer and this fails.
func TestProbeUnhealthyStore(t *testing.T) {
	ts := server(t, Options{Version: "test", StoreRoot: filepath.Join(t.TempDir(), "never-initialized")})
	err := Probe(addrOf(ts), time.Second)
	if err == nil || !strings.Contains(err.Error(), "unopenable") {
		t.Fatalf("Probe on an unopenable store = %v, want an error naming it", err)
	}
}

// TestProbeNoServer: nothing listening is unhealthy, within the timeout.
func TestProbeNoServer(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	start := time.Now()
	if err := Probe(addr, 2*time.Second); err == nil {
		t.Fatal("Probe with no server = nil, want an error")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("Probe did not respect its timeout")
	}
}
