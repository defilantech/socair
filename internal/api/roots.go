package api

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/defilantech/socair/internal/airlock"
)

// Scan roots bound what the API reads.
//
// The scan, ingest, and promote routes take a path from the request body, and
// the API has no authentication, so whoever reaches it would otherwise choose
// any file the process can read. Those routes read a path only when it lies
// under a scan root: a directory the operator names with socair serve
// --scan-root, or the store's staging area when a store is configured.
//
// A path must be under a root twice over: as written, so the name the engine
// opens starts at a root, and once every symlink in it is resolved, so a link
// inside a root cannot lead out of it. A path that is not under a root as
// written is refused before it is resolved. Every refusal of a named path
// reads the same whether or not the path exists, so the API answers no
// question about the filesystem outside its roots.
//
// The check and the read are two steps: the engine opens the returned path by
// name afterwards. docs/api.md ("Scan roots") states what that leaves open.

// errNoScanRoots refuses every caller-named path when no root is configured.
var errNoScanRoots = errors.New("no scan roots are configured, so the API reads no path a caller names; start socair serve with --scan-root <dir>")

// refusedPath is the one refusal for a path the API will not read. Its text
// depends only on the path as the caller wrote it, never on whether it
// exists or where it leads.
func refusedPath(p string) error {
	return fmt.Errorf("%q is not an existing path under a scan root; the API reads only under the directories socair serve was started with (--scan-root, and the store's incoming/ with --store)", p)
}

// ResolveScanRoots checks the directories an operator names as scan roots and
// returns them as absolute paths. Each must exist and be a directory, so a
// typo stops the server instead of leaving it refusing every path.
func ResolveScanRoots(dirs []string) ([]string, error) {
	out := make([]string, 0, len(dirs))
	for _, d := range dirs {
		if strings.TrimSpace(d) == "" {
			return nil, errors.New("a scan root is empty; name a directory")
		}
		abs, err := filepath.Abs(d)
		if err != nil {
			return nil, fmt.Errorf("scan root %q: %w", d, err)
		}
		fi, err := os.Stat(abs)
		if err != nil {
			return nil, fmt.Errorf("scan root %q: %w", d, err)
		}
		if !fi.IsDir() {
			return nil, fmt.Errorf("scan root %q is not a directory", d)
		}
		out = append(out, abs)
	}
	return out, nil
}

// EffectiveScanRoots are the roots the path-taking routes read under, as
// absolute paths: the configured ones and, with a store, its staging area.
func (o Options) EffectiveScanRoots() []string {
	var roots []string
	for _, r := range o.ScanRoots {
		if strings.TrimSpace(r) == "" {
			continue
		}
		if abs, err := filepath.Abs(r); err == nil {
			roots = append(roots, abs)
		}
	}
	if strings.TrimSpace(o.StoreRoot) != "" {
		s := airlock.Store{Root: o.StoreRoot}
		if abs, err := filepath.Abs(s.StagingRoot()); err == nil {
			roots = append(roots, abs)
		}
	}
	return roots
}

// contain returns the path to read for a path a caller named, or the refusal.
func (o Options) contain(p string) (string, error) {
	return containedPath(o.EffectiveScanRoots(), p)
}

// containedPath returns p, cleaned, when it lies under one of roots both as
// written and once its symlinks are resolved. Roots are resolved here, per
// request, so a store initialized after the server started still counts.
func containedPath(roots []string, p string) (string, error) {
	if len(roots) == 0 {
		return "", errNoScanRoots
	}
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("%q is not an absolute path; the API resolves no path against its own working directory", p)
	}
	// A root is matched as configured and as resolved, so a request may name
	// a path through either (a root that is itself a symlink, or /var and
	// /private/var on macOS).
	var written, resolved []string
	for _, r := range roots {
		written = append(written, r)
		if real, err := filepath.EvalSymlinks(r); err == nil {
			written = append(written, real)
			resolved = append(resolved, real)
		}
	}
	named, ok := under(written, p)
	if !ok {
		return "", refusedPath(p)
	}
	real, err := filepath.EvalSymlinks(named)
	if err != nil {
		return "", refusedPath(p)
	}
	if _, ok := under(resolved, real); !ok {
		return "", refusedPath(p)
	}
	return named, nil
}

// under returns p rebuilt as the first of roots it lies under joined with the
// rest of it, when the rest is local (filepath.IsLocal: not empty, not
// absolute, and no ".." that climbs out). A path equal to a root is under it.
func under(roots []string, p string) (string, bool) {
	for _, root := range roots {
		rel, err := filepath.Rel(root, p)
		if err == nil && filepath.IsLocal(rel) {
			return filepath.Join(root, rel), true
		}
	}
	return "", false
}
