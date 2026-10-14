package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/defilantech/socair/internal/api"
	"github.com/defilantech/socair/internal/engine"
)

// serveCmd runs the engine HTTP/JSON API that the click-ops wizard consumes.
//
//	socair serve [--addr 127.0.0.1:8080] [--web <dir>] [--store <path>] [--scan-root <dir>]...
//
// With --web it also serves a SvelteKit static build at /, so the box runs one
// process. The API reads a path a request names only under a --scan-root
// (repeatable; else SOCAIR_SCAN_ROOTS, a list like PATH) or the store's
// incoming/.
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
	roots, err := scanRootArgs(fs)
	if err != nil {
		return err
	}
	if opts.ScanRoots, err = api.ResolveScanRoots(roots); err != nil {
		return err
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
	if roots := opts.EffectiveScanRoots(); len(roots) > 0 {
		fmt.Fprintf(os.Stderr, "scan roots: %s\n", strings.Join(roots, ", "))
	} else {
		fmt.Fprintln(os.Stderr, "no scan roots: the API refuses every path a request names (add --scan-root <dir>)")
	}
	return api.Serve(addr, opts)
}

// scanRootArgs is every --scan-root, or SOCAIR_SCAN_ROOTS when none is given.
func scanRootArgs(fs *flagSet) ([]string, error) {
	if fs.bare["scan-root"] {
		return nil, errors.New("--scan-root needs a directory")
	}
	if dirs := fs.all["scan-root"]; len(dirs) > 0 {
		return dirs, nil
	}
	return filepath.SplitList(os.Getenv("SOCAIR_SCAN_ROOTS")), nil
}
