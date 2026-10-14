package main

import (
	"fmt"
	"os"

	"github.com/defilantech/socair/internal/airlock"
)

// airlockServeHub serves the clean store's admitted models, read-only, over
// the subset of the Hugging Face Hub API that huggingface_hub downloads
// through (docs/hub-endpoint.md).
//
//	socair airlock serve-hub [--addr 127.0.0.1:8081] [--allow-public] [--authorized-only] [--store <path>]
func airlockServeHub(args []string) error {
	fs := parseFlags(args)
	if len(fs.pos) > 0 {
		return fmt.Errorf("usage: socair airlock serve-hub [--addr %s] [--allow-public] [--authorized-only] [--store <path>]", airlock.DefaultHubAddr)
	}
	s, err := airlock.Open(storeRoot(fs))
	if err != nil {
		return err
	}
	addr := fs.val("addr")
	if addr == "" {
		addr = airlock.DefaultHubAddr
	}
	opts := airlock.HubOptions{AuthorizedOnly: fs.val("authorized-only") == "true", Log: os.Stderr}
	fmt.Fprintf(os.Stderr, "socair hub endpoint on http://%s, read-only over %s (set HF_ENDPOINT to it)\n", addr, s.Root)
	return airlock.ServeHub(addr, s, opts, fs.val("allow-public") == "true")
}
