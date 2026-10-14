package tarwalk_test

import (
	"archive/tar"
	"fmt"
	"testing"
)

// FuzzWalk feeds arbitrary bytes to the strict reader. It reads untrusted
// layers, so it may not panic, and it must be deterministic. And it is a
// differential test: whatever it accepts, Go's archive/tar (containerd's and
// CRI-O's reader) must read to the same entries, names, link targets, sizes,
// and bytes. (TestPythonAgrees checks Python's tarfile, opt-in.)
func FuzzWalk(f *testing.F) {
	for _, format := range []tar.Format{tar.FormatUSTAR, tar.FormatPAX, tar.FormatGNU} {
		f.Add(goWritten(f, format))
	}
	ok := file("models/a", []byte("x"))
	f.Add(cat(ok, end()))
	f.Add(cat(pax("path", "models/b", "size", "1"), header("x", '0', 1), data([]byte("y")), end()))
	f.Add(cat(long('L', "models/"+string(make([]byte, 120))), ok, end()))
	f.Add(cat(long('L', "models/long"), long('K', "target"), header("l", '1', 0, linkTo("t")), end()))
	f.Add(cat(header("a", '0', 0, prefix("models")), end()))
	f.Add(cat(header("a", '0', 0, gnu()), header("d/", '5', 0), header("s", '2', 0, linkTo("../x")), end()))
	f.Fuzz(func(t *testing.T, b []byte) {
		mine, err := walk(b)
		again, err2 := walk(b)
		if fmt.Sprint(mine, err) != fmt.Sprint(again, err2) {
			t.Fatalf("not deterministic: %v %v / %v %v", mine, err, again, err2)
		}
		if err != nil {
			return
		}
		theirs, gerr := goWalk(b)
		if gerr != nil {
			t.Fatalf("tarwalk accepted an archive Go's archive/tar refuses (%v): %v", gerr, mine)
		}
		if fmt.Sprint(mine) != fmt.Sprint(theirs) {
			t.Fatalf("tarwalk and archive/tar disagree:\n tarwalk     %v\n archive/tar %v", mine, theirs)
		}
	})
}

// FuzzWalkHeaders is FuzzWalk with every header's checksum recomputed after
// mutation, so the fuzzer explores header fields instead of stopping at the
// checksum.
func FuzzWalkHeaders(f *testing.F) {
	for _, format := range []tar.Format{tar.FormatUSTAR, tar.FormatPAX, tar.FormatGNU} {
		f.Add(goWritten(f, format))
	}
	f.Add(cat(pax("path", "models/b", "size", "1"), header("x", '0', 1), data([]byte("y")), end()))
	f.Add(cat(long('L', "models/long"), long('K', "target"), header("l", '1', 0, linkTo("t")), end()))
	f.Add(cat(header("a", '0', 0, prefix("models")), header("d/", '5', 0, gnu()), end()))
	f.Fuzz(func(t *testing.T, b []byte) {
		b = fixChecksums(b)
		mine, err := walk(b)
		if err != nil {
			return
		}
		theirs, gerr := goWalk(b)
		if gerr != nil {
			t.Fatalf("tarwalk accepted an archive Go's archive/tar refuses (%v): %v", gerr, mine)
		}
		if fmt.Sprint(mine) != fmt.Sprint(theirs) {
			t.Fatalf("tarwalk and archive/tar disagree:\n tarwalk     %v\n archive/tar %v", mine, theirs)
		}
	})
}

// fixChecksums walks b as a tar stream by its headers' own size fields and
// rewrites each header's checksum. It approximates the layout (a PAX size is
// not followed), which is enough to let mutated headers through.
func fixChecksums(in []byte) []byte {
	b := append([]byte(nil), in...)
	for off := 0; off+512 <= len(b); {
		blk := (*block)(b[off : off+512])
		zero := true
		for _, c := range blk {
			if c != 0 {
				zero = false
				break
			}
		}
		if zero {
			off += 512
			continue
		}
		sum(blk)
		var size int64
		for _, c := range blk[124:136] {
			if c >= '0' && c <= '7' {
				size = size*8 + int64(c-'0')
			}
			if size > 1<<24 {
				return b
			}
		}
		switch blk[156] {
		case '0', 'x', 'L', 'K', 'g', 'X', '7', 0:
		default:
			size = 0
		}
		off += 512 + int(size+511)/512*512
	}
	return b
}
