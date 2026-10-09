//go:build !linux && !darwin

package diskfree

func available(string) (uint64, bool) { return 0, false }
