package main

import (
	"fmt"
	"time"

	"github.com/defilantech/socair/internal/api"
)

// healthCmd checks a running API and exits non-zero unless it is healthy.
//
//	socair health [--addr 127.0.0.1:8080]
//
// It is the container image's probe: the image has no shell or curl, and the
// API binds the pod's loopback, which a kubelet's HTTP probe cannot reach.
func healthCmd(args []string) error {
	fs := parseFlags(args)
	addr := fs.val("addr")
	if addr == "" {
		addr = api.DefaultAddr
	}
	if err := api.Probe(addr, 5*time.Second); err != nil {
		return err
	}
	fmt.Println("ok")
	return nil
}
