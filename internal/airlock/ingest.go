package airlock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// IngestLocal validates a local artifact path, a file or a model directory,
// and returns its absolute path, so a scan reads the bytes that are actually
// on disk. A missing path is a clean, named error, never a silently empty
// report.
func IngestLocal(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("no local path given")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve local path %q: %w", path, err)
	}
	fi, err := os.Stat(abs)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("local path %q does not exist", path)
		}
		return "", fmt.Errorf("read local path %q: %w", path, err)
	}
	if !fi.IsDir() && !fi.Mode().IsRegular() {
		return "", fmt.Errorf("local path %q is not a file or a directory", path)
	}
	return abs, nil
}

// ResolveCache maps a Hugging Face hub cache to a local artifact, for
// air-gapped sites who ship a cache in rather than pull. The layout is
// <cache>/models--<org>--<name>/snapshots/<commit>/<file>, with a branch or
// tag name resolved through <cache>/models--<org>--<name>/refs/<name>. An
// empty file resolves the whole snapshot directory, for a directory scan.
func ResolveCache(cacheDir, repo, revision, file string) (string, error) {
	if strings.TrimSpace(repo) == "" {
		return "", errors.New("repo is required to resolve the cache")
	}
	if strings.TrimSpace(revision) == "" {
		revision = "main"
	}
	if cacheDir == "" {
		cacheDir = DefaultCacheDir()
	}
	if cacheDir == "" {
		return "", errors.New("no cache directory: set SOCAIR_HF_CACHE or HF_HOME")
	}

	if err := validRepo(repo); err != nil {
		return "", err
	}
	if err := validRevision(revision); err != nil {
		return "", err
	}
	// A cache file may sit in a repo subfolder, so file is a relative path,
	// but never absolute and never with a ".." segment.
	if filepath.IsAbs(file) || strings.Contains(file, `\`) || hasDotDot(filepath.ToSlash(file)) {
		return "", fmt.Errorf("artifact file %q must be a relative path inside the repo", file)
	}
	snap := filepath.Join(cacheDir, repoCacheDir(repo), "snapshots")
	if _, err := os.Stat(filepath.Join(snap, revision)); err != nil {
		// Snapshots are named by commit; a branch or tag maps to one in refs/.
		if b, rerr := os.ReadFile(filepath.Join(cacheDir, repoCacheDir(repo), "refs", filepath.FromSlash(revision))); rerr == nil {
			if commit := strings.TrimSpace(string(b)); validRevision(commit) == nil && !strings.Contains(commit, "/") {
				revision = commit
			}
		}
	}
	p := filepath.Join(snap, revision, file)
	if !within(snap, p) {
		return "", fmt.Errorf("cache path %q escapes the cache", p)
	}
	fi, err := os.Stat(p)
	if err != nil {
		return "", fmt.Errorf("no cached artifact %s/%s (%s) under %s; run a pull first or point --local at the file",
			repo, file, revision, cacheDir)
	}
	if fi.IsDir() != (strings.TrimSpace(file) == "") {
		if fi.IsDir() {
			return "", fmt.Errorf("cached path %q is a directory, want an artifact file (omit --file to resolve the whole snapshot)", p)
		}
		return "", fmt.Errorf("cached path %q is not a snapshot directory", p)
	}
	return p, nil
}

// DefaultCacheDir resolves the Hugging Face hub cache root.
func DefaultCacheDir() string {
	if h := strings.TrimSpace(os.Getenv("SOCAIR_HF_CACHE")); h != "" {
		return h
	}
	if h := strings.TrimSpace(os.Getenv("HF_HOME")); h != "" {
		return filepath.Join(h, "hub")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".cache", "huggingface", "hub")
}

// repoCacheDir is the hub's directory name for a repo id.
func repoCacheDir(repo string) string {
	return "models--" + strings.ReplaceAll(strings.TrimSpace(repo), "/", "--")
}
