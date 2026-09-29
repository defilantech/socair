package airlock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// IngestLocal validates a local artifact path and returns its absolute path, so
// a scan reads the bytes that are actually on disk. A missing path is a clean,
// named error, never a silently empty report.
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
	if fi.IsDir() {
		return "", fmt.Errorf("local path %q is a directory, want an artifact file", path)
	}
	return abs, nil
}

// ResolveCache maps a Hugging Face hub cache to a local artifact file, for
// air-gapped customers who ship a cache in rather than pull. The layout is
// <cache>/models--<org>--<name>/snapshots/<rev>/<file>.
func ResolveCache(cacheDir, repo, revision, file string) (string, error) {
	if strings.TrimSpace(repo) == "" {
		return "", errors.New("repo is required to resolve the cache")
	}
	if strings.TrimSpace(file) == "" {
		return "", errors.New("artifact file is required to resolve the cache")
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

	p := filepath.Join(cacheDir, repoCacheDir(repo), "snapshots", revision, file)
	fi, err := os.Stat(p)
	if err != nil {
		return "", fmt.Errorf("no cached artifact %s/%s (%s) under %s; run a pull first or point --local at the file",
			repo, file, revision, cacheDir)
	}
	if fi.IsDir() {
		return "", fmt.Errorf("cached path %q is a directory, want an artifact file", p)
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
