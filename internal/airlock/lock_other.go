//go:build !unix

package airlock

import (
	"os"
	"sync"
)

var logMu sync.Mutex

// lockFile serializes appends within this process. Without flock, concurrent
// processes can fork the chain, which Verify then reports.
func lockFile(*os.File) (func(), error) {
	logMu.Lock()
	return logMu.Unlock, nil
}
