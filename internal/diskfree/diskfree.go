// Package diskfree checks for room before a large copy. A scan snapshot, a
// pull, and a promotion each write a model's full size, and open-weight models
// now run to hundreds of gigabytes, so a copy that cannot fit should fail at
// the start, naming the volume and the shortfall, not hours in on a full disk.
package diskfree

import (
	"fmt"
	"math/bits"
	"os"
	"strings"
)

// Available reports the bytes an unprivileged writer can use on the file
// system holding dir, and whether the platform could say. It is a variable so
// a test can stand in a full disk.
var Available = available

// ShortError is a volume without room for a copy.
type ShortError struct {
	Dir             string
	Need, Available uint64
}

func (e *ShortError) Error() string {
	return fmt.Sprintf("not enough free space in %s: needs %s, %s available", e.Dir, Human(e.Need), Human(e.Available))
}

// Need returns a *ShortError when the file system holding dir has fewer than
// n bytes available. When the platform cannot report free space it returns
// nil: the copy itself still fails on a full disk, only later. Some network
// and FUSE file systems report no free space at all, so SOCAIR_ROOM_CHECK=off
// turns the check off for an operator who knows the volume has room.
func Need(dir string, n int64) error {
	if n <= 0 || strings.EqualFold(strings.TrimSpace(os.Getenv("SOCAIR_ROOM_CHECK")), "off") {
		return nil
	}
	free, ok := Available(dir)
	if !ok || free >= uint64(n) {
		return nil
	}
	return &ShortError{Dir: dir, Need: uint64(n), Available: free}
}

// bytesOf is blocks times block size, saturating rather than wrapping.
func bytesOf(blocks, size uint64) uint64 {
	hi, lo := bits.Mul64(blocks, size)
	if hi != 0 {
		return ^uint64(0)
	}
	return lo
}

// Human formats a byte count in decimal units, as the hub lists file sizes.
func Human(n uint64) string {
	switch {
	case n >= 1e9:
		return fmt.Sprintf("%.1f GB", float64(n)/1e9)
	case n >= 1e6:
		return fmt.Sprintf("%.1f MB", float64(n)/1e6)
	}
	return fmt.Sprintf("%d bytes", n)
}
