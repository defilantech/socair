package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Probe asks the API at addr for its health and returns nil only for a 200.
// It is what a container's liveness and readiness probes run (`socair
// health`): the API binds the pod's loopback by default, which a kubelet's
// HTTP probe cannot reach, and the image has no shell or curl.
func Probe(addr string, timeout time.Duration) error {
	c := &http.Client{Timeout: timeout}
	resp, err := c.Get("http://" + addr + "/api/health")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	var h struct {
		Store string `json:"store"`
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &h) == nil && h.Store != "" {
		return fmt.Errorf("unhealthy (%d): store %s: %s", resp.StatusCode, h.Store, h.Error)
	}
	return fmt.Errorf("unhealthy (%d)", resp.StatusCode)
}
