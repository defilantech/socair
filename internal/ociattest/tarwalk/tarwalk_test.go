package tarwalk_test

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/ociattest/tarwalk"
)

// got is one entry as a reader returned it, with a hash of its data.
type got struct {
	Name, Linkname string
	Kind           tarwalk.Kind
	Size           int64
	Data           [32]byte
}

// walk reads a whole archive with tarwalk, through Finish.
func walk(b []byte) ([]got, error) {
	tr := tarwalk.NewReader(bytes.NewReader(b))
	var out []got
	for {
		e, err := tr.Next()
		if err == io.EOF {
			return out, tr.Finish()
		}
		if err != nil {
			return out, err
		}
		h := sha256.New()
		if _, err := io.Copy(h, tr); err != nil {
			return out, err
		}
		g := got{Name: e.Name, Linkname: e.Linkname, Kind: e.Kind, Size: e.Size}
		copy(g.Data[:], h.Sum(nil))
		out = append(out, g)
	}
}

// goWalk reads the same archive with Go's archive/tar, the reader containerd
// and CRI-O unpack layers with.
func goWalk(b []byte) ([]got, error) {
	tr := tar.NewReader(bytes.NewReader(b))
	var out []got
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		var k tarwalk.Kind
		switch h.Typeflag {
		case tar.TypeReg:
			k = tarwalk.Regular
		case tar.TypeDir:
			k = tarwalk.Directory
		case tar.TypeSymlink:
			k = tarwalk.Symlink
		case tar.TypeLink:
			k = tarwalk.Hardlink
		case tar.TypeChar:
			k = tarwalk.CharDevice
		case tar.TypeBlock:
			k = tarwalk.BlockDevice
		case tar.TypeFifo:
			k = tarwalk.FIFO
		default:
			return out, fmt.Errorf("type %q", h.Typeflag)
		}
		hs := sha256.New()
		n, err := io.Copy(hs, tr)
		if err != nil {
			return out, err
		}
		size := h.Size
		if k != tarwalk.Regular {
			size = n
		}
		g := got{Name: h.Name, Linkname: h.Linkname, Kind: k, Size: size}
		copy(g.Data[:], hs.Sum(nil))
		out = append(out, g)
	}
}

// goWritten is an archive Go's tar.Writer writes in a format: what BuildKit,
// containerd, and crane write layers with.
func goWritten(t testing.TB, format tar.Format) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	long := strings.Repeat("d", 120) + "/" + strings.Repeat("f", 90) // fits a ustar prefix split
	longer := strings.Repeat("x/", 150) + "file"                     // needs PAX or GNU
	add := func(h *tar.Header, body string) {
		h.Format = format
		if h.Typeflag == tar.TypeReg {
			h.Size = int64(len(body))
		}
		if h.Mode == 0 {
			h.Mode = 0o644
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if body != "" {
			tw.Write([]byte(body))
		}
	}
	add(&tar.Header{Name: "models/", Typeflag: tar.TypeDir, Mode: 0o755}, "")
	add(&tar.Header{Name: "models/config.json", Typeflag: tar.TypeReg}, `{"a":1}`)
	add(&tar.Header{Name: "bin/ln", Typeflag: tar.TypeLink, Linkname: "bin/busybox"}, "")
	add(&tar.Header{Name: "lib64", Typeflag: tar.TypeSymlink, Linkname: "lib"}, "")
	add(&tar.Header{Name: "models/empty", Typeflag: tar.TypeReg}, "")
	if format != tar.FormatUSTAR {
		add(&tar.Header{Name: longer, Typeflag: tar.TypeReg}, "deep")
		add(&tar.Header{Name: "link-to-deep", Typeflag: tar.TypeSymlink, Linkname: longer}, "")
	}
	if format != tar.FormatGNU {
		add(&tar.Header{Name: long, Typeflag: tar.TypeReg}, "prefixed")
	}
	if format == tar.FormatPAX {
		add(&tar.Header{Name: "models/naïve.txt", Typeflag: tar.TypeReg, PAXRecords: map[string]string{"SCHILY.xattr.security.capability": "x"}}, "utf8")
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestReadsWhatGoWrites: the archives image builders write are read, entry
// for entry, as Go's archive/tar reads them.
func TestReadsWhatGoWrites(t *testing.T) {
	for _, f := range []tar.Format{tar.FormatUSTAR, tar.FormatPAX, tar.FormatGNU} {
		b := goWritten(t, f)
		mine, err := walk(b)
		if err != nil {
			t.Fatalf("%v: %v", f, err)
		}
		theirs, err := goWalk(b)
		if err != nil {
			t.Fatalf("%v: archive/tar: %v", f, err)
		}
		if fmt.Sprint(mine) != fmt.Sprint(theirs) {
			t.Errorf("%v:\n tarwalk  %v\n archive/tar %v", f, mine, theirs)
		}
		if len(mine) < 5 {
			t.Errorf("%v: %d entries", f, len(mine))
		}
	}
}

// TestReadsGNUBase256AndLargePAXSizes: a size that does not fit the ustar
// field is written base-256 (GNU) or as a PAX record over a zero field (Go's
// writer); both are read.
func TestReadsLargeSizes(t *testing.T) {
	big := int64(1) << 34
	h := header("big", '0', 0, raw(124, append([]byte{0x80}, []byte{0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0}...)))
	tr := tarwalk.NewReader(bytes.NewReader(h))
	e, err := tr.Next()
	if err != nil || e.Size != big {
		t.Fatalf("base-256 size: %+v, %v", e, err)
	}
	tr = tarwalk.NewReader(bytes.NewReader(cat(pax("size", fmt.Sprint(big)), header("big", '0', 0))))
	if e, err = tr.Next(); err != nil || e.Size != big {
		t.Fatalf("PAX size: %+v, %v", e, err)
	}
}

// TestRefusals: every input the readers read differently, or that Socair
// does not read, is refused with its reason. Each case is otherwise a valid
// archive, so it is a falsification test for its check: remove the check
// and the case reads.
func TestRefusals(t *testing.T) {
	ok := file("models/a", []byte("x"))
	zero := make([]byte, 512)
	nulPAX := paxRaw(paxRecord("path", "models/a") + "\x00\x00")
	cases := []struct {
		name string
		in   []byte
		want string
	}{
		{"no end-of-archive marker", ok, "without tar's end-of-archive marker"},
		{"one zero block", cat(ok, zero), "one zero block"},
		{"a zero block, then a header", cat(ok, zero, header("b/", '5', 0), end()), "zero block is followed by a header"},
		{"data after the marker", cat(ok, end(), []byte{0, 0, 7}), "data follows the end-of-archive marker"},
		{"truncated data", header("models/a", '0', 1000), "ends inside"},
		{"two PAX headers", cat(pax("path", "a"), pax("path", "b"), ok, end()), "two PAX headers in a row"},
		{"PAX, then a GNU long name", cat(pax("path", "a"), long('L', "b"), ok, end()), "opposite orders"},
		{"a GNU long name, then PAX", cat(long('L', "b"), pax("path", "a"), ok, end()), "opposite orders"},
		{"two GNU long names", cat(long('L', "a"), long('L', "b"), ok, end()), "two GNU long name headers"},
		{"two GNU long links", cat(long('K', "a"), long('K', "b"), header("l", '2', 0, linkTo("x")), end()), "two GNU long link headers"},
		{"bytes after a long name's NUL", cat(append(header("././@LongLink", 'L', 4, gnu()), data([]byte("a\x00b\x00"))...), ok, end()), "after its name's terminating NUL"},
		{"an empty long name", cat(append(header("././@LongLink", 'L', 1, gnu()), data([]byte{0})...), ok, end()), "an empty GNU long name"},
		{"a long name header with no data", cat(header("././@LongLink", 'L', 0, gnu()), ok, end()), "a GNU long name header of 0 bytes"},
		{"a long name over PATH_MAX", cat(long('L', strings.Repeat("a/", 2100)), ok, end()), "a GNU long name header of 4201 bytes"},
		{"PAX, then the marker", cat(pax("path", "a"), end()), "followed by the end-of-archive marker"},
		{"PAX, then the end of the stream", pax("path", "a"), "ends after a PAX or long-name header"},
		{"a PAX global header", cat(header("g", 'g', 0), ok, end()), "PAX global header"},
		{"a Solaris extended header", cat(header("X", 'X', 0), ok, end()), "Solaris extended header"},
		{"a GNU sparse file", cat(header("s", 'S', 0, gnu()), end()), "sparse"},
		{"a device that claims data", cat(header("dev/null", '3', 4), end()), "claims 4 bytes"},
		{"a contiguous file", cat(header("c", '7', 0), end()), "contiguous"},
		{"the NUL type flag", cat(header("models/", 0, 0), end()), "old regular-file type flag"},
		{"an unknown type flag", cat(header("z", 'Z', 0), end()), "type flag"},
		{"a star header", cat(header("a", '0', 0, raw(508, []byte("tar\x00"))), end()), "star header"},
		{"a GNU header with a prefix", cat(header("a", '0', 0, gnu(), prefix("models")), end()), "prepends them"},
		{"a V7 header", cat(header("a", '0', 0, field(257, 265, "")), end()), "neither a POSIX"},
		{"a wrong checksum", cat(func() []byte { h := header("a", '0', 0); h[0] = 'b'; return h }(), end()), "checksum does not match"},
		{"a checksum that is not octal", cat(func() []byte { h := header("a", '0', 0); copy(h[148:150], "zz"); return h }(), end()), "checksum field is not an octal number"},
		{"a size field with a NUL before its digits", cat(header("a", '0', 0, raw(124, []byte("\x00\x0000000001\x00"))), data([]byte("x")), end()), "size field is not a number"},
		{"a size field with digits after a space", cat(header("a", '0', 0, raw(124, []byte("0000 0000001"))), data([]byte("x")), end()), "size field is not a number"},
		{"a mode field Python reads as base-256 and Go does not", cat(header("a", '0', 0, raw(100, []byte{0x81, 0, 0, 0, 0, 0, 0, 0})), end()), "mode field"},
		{"a negative base-256 size", cat(header("a", '0', 0, raw(124, bytes.Repeat([]byte{0xff}, 12))), end()), "size field"},
		{"a PAX header with NULs after its records", cat(nulPAX, ok, end()), "does not start with its length"},
		{"a NUL in a PAX path", cat(pax("path", "models/a\x00b"), ok, end()), "holds a NUL byte"},
		{"a NUL in a PAX key", cat(paxRaw(paxRecord("SCHILY.xattr.a\x00b", "v")), ok, end()), "PAX key holding a NUL"},
		{"a PAX key set twice", cat(paxRaw(paxRecord("path", "a")+paxRecord("path", "b")), ok, end()), "sets path twice"},
		{"a PAX record with a bad length", cat(paxRaw("99 path=a\n"), ok, end()), "does not frame it"},
		{"a PAX record with no newline", cat(paxRaw("9 path=ab"), ok, end()), "does not frame it"},
		{"a PAX record with no length", cat(paxRaw("path=a\n"), ok, end()), "does not start with its length"},
		{"a PAX record with no key", cat(paxRaw(paxRecord("", "a")), ok, end()), "no key"},
		{"an empty PAX path", cat(pax("path", ""), ok, end()), "is empty"},
		{"a PAX size Python reads as 10 and Go refuses", cat(pax("size", "1_0"), ok, end()), "not a decimal number"},
		{"a PAX size over a smaller size field", cat(pax("size", "1"), header("models/a", '0', 0), data([]byte("x")), end()), "a reader that ignores PAX records"},
		{"hdrcharset", cat(pax("hdrcharset", "BINARY"), ok, end()), "decodes names by it"},
		{"a GNU sparse PAX record", cat(pax("GNU.sparse.major", "1"), ok, end()), "GNU extension"},
		{"an overlay opaque attribute", cat(pax("SCHILY.xattr.trusted.overlay.opaque", "y"), header("models/", '5', 0), end()), "overlayfs attribute"},
		{"an overlay attribute in the user namespace", cat(pax("SCHILY.xattr.user.overlay.whiteout", "y"), ok, end()), "overlayfs attribute"},
		{"a PAX time that is not decimal", cat(pax("mtime", "1e3"), ok, end()), "not a decimal time"},
		{"a directory that claims data", cat(header("models/", '5', 5), end()), "claims 5 bytes"},
		{"a symbolic link with no target", cat(header("l", '2', 0), end()), "no target"},
		{"a hard link that claims data", cat(header("l", '1', 3, linkTo("a")), end()), "claims 3 bytes"},
		{"an entry with no name", cat(header("", '5', 0), end()), "no name"},
		{"a name over PATH_MAX", cat(pax("path", strings.Repeat("a/", 2100)), ok, end()), "over 4096"},
		{"a PAX header over the bound", header("x", 'x', tarwalk.MaxPAX+1), "over the"},
		{"bytes in a PAX header's padding", cat(func() []byte { p := pax("path", "models/b"); p[len(p)-1] = '9'; return p }(), ok, end()), "padding after a PAX or long-name header"},
		{"bytes in a long name's padding", cat(append(header("././@LongLink", 'L', 3, gnu()), data([]byte("abc\x00\x00x"))...), ok, end()), "padding after a PAX or long-name header"},
	}
	for _, c := range cases {
		_, err := walk(c.in)
		var te *tarwalk.Error
		if !errors.As(err, &te) {
			t.Errorf("%s: %v, want a refusal", c.name, err)
			continue
		}
		if !strings.Contains(te.Reason, c.want) {
			t.Errorf("%s: %q does not say %q", c.name, te.Reason, c.want)
		}
	}
}

// TestRefusalCasesAreOtherwiseValid: the same archives with the one problem
// removed read, so each refusal above is the check it names.
func TestRefusalCasesAreOtherwiseValid(t *testing.T) {
	ok := file("models/a", []byte("x"))
	for name, in := range map[string][]byte{
		"one PAX header":         cat(pax("path", "b"), ok, end()),
		"one GNU long name":      cat(long('L', "b"), ok, end()),
		"a long name and a link": cat(long('L', "a"), long('K', "b"), header("l", '2', 0, linkTo("x")), end()),
		"a POSIX prefix":         cat(header("a", '0', 0, prefix("models")), end()),
		"a GNU header":           cat(header("a", '0', 0, gnu()), end()),
		"padded size fields":     cat(header("a", '0', 0, raw(124, []byte("          1\x00"))), data([]byte("x")), end()),
		"a matching PAX size":    cat(pax("size", "1"), header("models/a", '0', 1), data([]byte("x")), end()),
		"an ordinary xattr":      cat(pax("SCHILY.xattr.security.capability", "x"), ok, end()),
		"devices and a FIFO":     cat(header("dev/null", '3', 0), header("dev/sda", '4', 0), header("run/fifo", '6', 0), end()),
		"a binary xattr value":   cat(pax("SCHILY.xattr.security.capability", "\x01\x00\x00\x02"), ok, end()),
		"a PAX time":             cat(pax("mtime", "1700000000.123456789"), ok, end()),
		"zero padding after":     cat(ok, end(), bytes.Repeat([]byte{0}, 10240)),
	} {
		if _, err := walk(in); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}
