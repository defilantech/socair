package tarwalk_test

import (
	"archive/tar"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// pythonReader reads every archive in a directory with Python's tarfile in
// stream mode ("r|"), as KServe's oci+fetch storage initializer opens a
// layer, and prints one JSON line per archive: its entries, or its error.
const pythonReader = `
import hashlib, json, os, sys, tarfile
d = sys.argv[1]
for n in sorted(os.listdir(d)):
    out = {"file": n, "entries": [], "error": None}
    try:
        with open(os.path.join(d, n), "rb") as f, tarfile.open(fileobj=f, mode="r|") as t:
            for m in t:
                data = b""
                if m.isreg():
                    data = t.extractfile(m).read()
                b = lambda v: v.encode("utf-8", "surrogateescape").hex()
                out["entries"].append([b(m.name), m.type.decode("latin-1"), b(m.linkname), m.size, hashlib.sha256(data).hexdigest()])
    except Exception as e:
        out["error"] = type(e).__name__ + ": " + str(e)
    print(json.dumps(out))
`

// TestPythonAgrees is opt-in: SOCAIR_TEST_PYTHON names a Python 3 (or a
// wrapper that runs one, such as one in KServe's storage-initializer base
// image, python:3.11-slim-bookworm; SOCAIR_TEST_PYTHON_N and _SEED set how
// many archives and which). Every archive tarwalk accepts, from the
// seeds and from mutated seeds with their checksums fixed, must read the same
// in Python's tarfile: the same names (trailing slashes aside, which Python
// strips), types, link targets, sizes, and bytes. Names are compared as
// bytes: tarfile decodes a name that is not UTF-8 with surrogateescape, which
// writes the same bytes back to the filesystem.
func TestPythonAgrees(t *testing.T) {
	py := os.Getenv("SOCAIR_TEST_PYTHON")
	if py == "" {
		t.Skip("set SOCAIR_TEST_PYTHON to a Python 3 to compare with tarfile")
	}
	seeds := [][]byte{goWritten(t, tar.FormatUSTAR), goWritten(t, tar.FormatPAX), goWritten(t, tar.FormatGNU),
		cat(pax("path", "models/b", "size", "1"), header("x", '0', 1), data([]byte("y")), end()),
		cat(long('L', "models/long"), long('K', "target"), header("l", '1', 0, linkTo("t")), end()),
		cat(header("a", '0', 0, prefix("models")), header("d/", '5', 0, gnu()), end()),
		cat(header("a", '0', 0, raw(124, []byte("          1\x00"))), data([]byte("x")), end()),
		cat(pax("SCHILY.xattr.security.capability", "\x01\x00\x00\x02"), header("bin/ping", '0', 0), header("dev/null", '3', 0), header("run/f", '6', 0), end()),
	}
	dir := t.TempDir()
	accepted := map[string][]got{}
	n, seed := 4000, int64(1)
	if s := os.Getenv("SOCAIR_TEST_PYTHON_N"); s != "" {
		fmt.Sscan(s, &n)
	}
	if s := os.Getenv("SOCAIR_TEST_PYTHON_SEED"); s != "" {
		fmt.Sscan(s, &seed)
	}
	r := rand.New(rand.NewSource(seed))
	for i := 0; i < n; i++ {
		b := append([]byte(nil), seeds[i%len(seeds)]...)
		if i >= len(seeds) {
			for m := 0; m < 1+r.Intn(4); m++ {
				b[r.Intn(len(b))] = mutateByte(r)
			}
			b = fixChecksums(b)
		}
		mine, err := walk(b)
		if err != nil {
			continue
		}
		name := fmt.Sprintf("%05d.tar", i)
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
		accepted[name] = mine
	}
	script := filepath.Join(dir, "..", "read.py")
	if err := os.WriteFile(script, []byte(pythonReader), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(py, script, dir).Output()
	if err != nil {
		t.Fatalf("%s: %v", py, err)
	}
	seen := 0
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		var res struct {
			File    string
			Entries [][]any
			Error   *string
		}
		if err := json.Unmarshal([]byte(line), &res); err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		mine, ok := accepted[res.File]
		if !ok {
			continue
		}
		seen++
		if res.Error != nil {
			t.Errorf("%s: tarwalk accepted it, Python's tarfile: %s", res.File, *res.Error)
			continue
		}
		var theirs []string
		for _, e := range res.Entries {
			name, _ := hex.DecodeString(e[0].(string))
			theirs = append(theirs, fmt.Sprintf("%x|%s|%s|%v|%s", strings.TrimRight(string(name), "/"), e[1], e[2], e[3], e[4]))
		}
		var ours []string
		for _, g := range mine {
			ty := map[int]string{1: "0", 2: "5", 3: "2", 4: "1", 5: "3", 6: "4", 7: "6"}[int(g.Kind)]
			ours = append(ours, fmt.Sprintf("%x|%s|%x|%v|%s", strings.TrimRight(g.Name, "/"), ty, g.Linkname, float64(g.Size), hex.EncodeToString(g.Data[:])))
		}
		if strings.Join(ours, "\n") != strings.Join(theirs, "\n") {
			i := 0
			for i < len(ours) && i < len(theirs) && ours[i] == theirs[i] {
				i++
			}
			t.Errorf("%s: tarwalk and Python's tarfile disagree at entry %d of %d/%d:\n tarwalk %v\n tarfile %v", res.File, i, len(ours), len(theirs), ours[i:], theirs[i:])
		}
	}
	if seen != len(accepted) {
		t.Fatalf("Python read %d of %d archives", seen, len(accepted))
	}
	t.Logf("%d archives tarwalk accepted read alike in %s", seen, py)
}

// mutateByte favours the bytes tar fields are made of.
func mutateByte(r *rand.Rand) byte {
	pool := []byte{0, ' ', '/', '.', '0', '1', '5', '7', 'x', 'L', 'K', 'g', 0x80, 0xff, '=', '\n'}
	if r.Intn(4) == 0 {
		return byte(r.Intn(256))
	}
	return pool[r.Intn(len(pool))]
}
