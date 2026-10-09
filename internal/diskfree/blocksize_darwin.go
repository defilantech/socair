package diskfree

import "syscall"

// blockSize is the unit Darwin counts free blocks in.
func blockSize(st *syscall.Statfs_t) uint64 { return uint64(st.Bsize) }
