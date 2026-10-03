//go:build unix

package airlock

import (
	"os"
	"syscall"
)

// lockFile takes an exclusive advisory lock on f, so concurrent processes
// appending to the log read the same last line and never fork the chain.
func lockFile(f *os.File) (func(), error) {
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return nil, err
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }, nil
}
