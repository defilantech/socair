package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/defilantech/socair/internal/api"
	"github.com/defilantech/socair/internal/engine"
)

// serveCmd runs the engine HTTP/JSON API that the click-ops wizard consumes.
//
//	socair serve [--addr 127.0.0.1:8080] [--web <dir>] [--store <path>]
//
// With --web it also serves a SvelteKit static build at /, so the box runs one
// process.
func serveCmd(args []string) error {
	fs := parseFlags(args)
	opts := api.Options{Version: engine.Version}

	if fs.has("web") {
		abs, err := filepath.Abs(fs.val("web"))
		if err != nil {
			return err
		}
		if fi, err := os.Stat(abs); err != nil || !fi.IsDir() {
			return fmt.Errorf("web dir %q is not a directory", fs.val("web"))
		}
		opts.WebDir = abs
	}
	// Claim the store only when it was asked for, so a plain API run does not
	// report a degraded engine over an airlock nobody configured.
	if fs.has("store") || os.Getenv("SOCAIR_STORE") != "" {
		opts.StoreRoot = storeRoot(fs)
	}

	addr := fs.val("addr")
	if addr == "" {
		addr = api.DefaultAddr
	}
	if err := api.CheckAddr(addr); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "socair api on http://%s\n", addr)
	if opts.WebDir != "" {
		fmt.Fprintf(os.Stderr, "serving the wizard from %s\n", opts.WebDir)
	}
	return api.Serve(addr, opts)
}
