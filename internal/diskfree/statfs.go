//go:build linux || darwin

package diskfree

import (
	"path/filepath"
	"syscall"
)

// available reads the volume of dir, or of its nearest existing parent when
// dir is a destination not created yet.
func available(dir string) (uint64, bool) {
	dir = filepath.Clean(dir)
	for {
		var st syscall.Statfs_t
		if err := syscall.Statfs(dir, &st); err == nil {
			return bytesOf(uint64(st.Bavail), blockSize(&st)), true
		} else if err != syscall.ENOENT && err != syscall.ENOTDIR {
			return 0, false
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return 0, false
		}
		dir = parent
	}
}
