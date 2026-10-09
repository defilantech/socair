package diskfree

import "syscall"

// blockSize is the unit Linux counts free blocks in: the fragment size, which
// differs from the preferred I/O size on some network and FUSE file systems.
func blockSize(st *syscall.Statfs_t) uint64 {
	if st.Frsize > 0 {
		return uint64(st.Frsize)
	}
	return uint64(st.Bsize)
}
