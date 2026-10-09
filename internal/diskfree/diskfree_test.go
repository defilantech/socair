package diskfree

import (
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func stub(t *testing.T, free uint64, ok bool) {
	t.Helper()
	prev := Available
	Available = func(string) (uint64, bool) { return free, ok }
	t.Cleanup(func() { Available = prev })
}

// Falsification: make Need return nil unconditionally and the short case
// passes.
func TestNeedRefusesAShortVolume(t *testing.T) {
	stub(t, 2_000_000_000, true)
	err := Need("/srv/store", 755_000_000_000)
	var short *ShortError
	if !errors.As(err, &short) {
		t.Fatalf("want a *ShortError, got %v", err)
	}
	for _, want := range []string{"/srv/store", "755.0 GB", "2.0 GB"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error must name %q: %s", want, err)
		}
	}
}

func TestNeedPassesWhenThereIsRoom(t *testing.T) {
	stub(t, 10_000, true)
	if err := Need(t.TempDir(), 10_000); err != nil {
		t.Fatalf("exactly enough room must pass: %v", err)
	}
}

// A platform that cannot report free space does not block the copy; the copy
// itself still fails on a full disk.
func TestNeedPassesWhenThePlatformCannotSay(t *testing.T) {
	stub(t, 0, false)
	if err := Need(t.TempDir(), 1<<40); err != nil {
		t.Fatalf("unknown free space must not refuse: %v", err)
	}
}

func TestAvailableReadsTheRealVolume(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("free space is read on linux and darwin")
	}
	free, ok := Available(t.TempDir())
	if !ok || free == 0 {
		t.Fatalf("Available = %d, %v on a writable temp dir", free, ok)
	}
	// A copy's destination often does not exist yet; its volume is the
	// nearest existing parent's.
	if free, ok := Available(filepath.Join(t.TempDir(), "not", "yet")); !ok || free == 0 {
		t.Fatalf("Available = %d, %v for a directory still to be created", free, ok)
	}
}

func TestHumanSizes(t *testing.T) {
	for n, want := range map[uint64]string{
		512:             "512 bytes",
		1_500_000:       "1.5 MB",
		755_200_000_000: "755.2 GB",
	} {
		if got := Human(n); got != want {
			t.Errorf("Human(%d) = %q, want %q", n, got, want)
		}
	}
}

// Some network and FUSE file systems report no free space at all. An
// operator who knows the volume has room can turn the check off.
// Falsification: ignore SOCAIR_ROOM_CHECK and the short case refuses.
func TestNeedCanBeTurnedOff(t *testing.T) {
	stub(t, 0, true)
	t.Setenv("SOCAIR_ROOM_CHECK", "off")
	if err := Need(t.TempDir(), 1<<40); err != nil {
		t.Fatalf("SOCAIR_ROOM_CHECK=off must not refuse: %v", err)
	}
	t.Setenv("SOCAIR_ROOM_CHECK", "")
	if err := Need(t.TempDir(), 1<<40); err == nil {
		t.Fatal("the check is on by default")
	}
}

func TestBytesSaturates(t *testing.T) {
	if got := bytesOf(1<<40, 1<<40); got != ^uint64(0) {
		t.Fatalf("an overflowing product must saturate, got %d", got)
	}
	if got := bytesOf(3, 4096); got != 12288 {
		t.Fatalf("bytesOf(3, 4096) = %d", got)
	}
}
