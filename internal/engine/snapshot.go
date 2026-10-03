package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
)

// snapshots counts artifacts read into a snapshot, so a test can hold a full
// scan to one read.
var snapshots atomic.Int64

// afterSnapshot is a test hook, called with the original path once its
// snapshot is taken and before any check runs.
var afterSnapshot func(original string)

// snapshot copies the artifact into a private, read-only file, hashing the
// bytes as it copies them, and returns the copy's path, the digest, and a
// cleanup function.
//
// This is what makes an attestation describe one artifact. Hashing a path and
// then letting each check re-open it lets a file swapped or rewritten in
// between earn a clean report under the hash of other bytes. The checks read
// the snapshot, so the bytes hashed are the bytes checked. The copy keeps the
// original's base name, because the quant row reads the declared quant from
// it. It costs one extra write of the artifact's size; SOCAIR_SCAN_TMP points
// it at a volume with room.
func snapshot(path string) (string, string, func(), error) {
	src, err := os.Open(path)
	if err != nil {
		return "", "", nil, err
	}
	defer src.Close()
	if fi, err := src.Stat(); err != nil {
		return "", "", nil, err
	} else if !fi.Mode().IsRegular() {
		return "", "", nil, fmt.Errorf("%s is not a regular file", path)
	}

	dir := strings.TrimSpace(os.Getenv("SOCAIR_SCAN_TMP"))
	tmp, err := os.MkdirTemp(dir, "socair-scan-")
	if err != nil {
		return "", "", nil, fmt.Errorf("create scan snapshot directory (set SOCAIR_SCAN_TMP to a volume with room): %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(tmp) }

	dst := filepath.Join(tmp, filepath.Base(path))
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		cleanup()
		return "", "", nil, err
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(out, h), src); err != nil {
		out.Close()
		cleanup()
		return "", "", nil, fmt.Errorf("snapshot %s (set SOCAIR_SCAN_TMP to a volume with room): %w", path, err)
	}
	if err := out.Close(); err != nil {
		cleanup()
		return "", "", nil, err
	}
	if err := os.Chmod(dst, 0o400); err != nil {
		cleanup()
		return "", "", nil, err
	}
	snapshots.Add(1)
	return dst, hex.EncodeToString(h.Sum(nil)), cleanup, nil
}
