package provenance

import (
	"bytes"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// improper is GNU sha256sum's --warn line for a line it does not read.
var improper = regexp.MustCompile(`: (\d+): improperly formatted SHA256 checksum line$`)

// TestParserAgreesWithSHA256SUM runs GNU coreutils' sha256sum --check over
// every parser case and a few thousand generated lists, and holds the parser
// to what it reads: the same lines refused, and, line by line, the same file
// opened and judged the same. SOCAIR_TEST_SHA256SUM names a GNU sha256sum
// (coreutils 9.12 was measured; macOS's own sha256sum is another program).
//
//	SOCAIR_TEST_SHA256SUM=<path> go test ./internal/checks/provenance -run SHA256SUM -v
func TestParserAgreesWithSHA256SUM(t *testing.T) {
	bin := os.Getenv("SOCAIR_TEST_SHA256SUM")
	if bin == "" {
		t.Skip("set SOCAIR_TEST_SHA256SUM to a GNU coreutils sha256sum")
	}
	if out, err := exec.Command(bin, "--version").Output(); err != nil || !bytes.Contains(out, []byte("GNU coreutils")) {
		t.Fatalf("%s is not GNU coreutils' sha256sum: %v %s", bin, err, out)
	}
	var lists []string
	for _, c := range parseCases {
		// The one difference by design: sha256sum names a file by a C
		// string, so it cuts a name at a NUL byte and opens the rest; the
		// parser refuses the line instead of reading a name that is not the
		// one written.
		if c.bareFor == "" && !strings.Contains(c.list, "\x00") {
			lists = append(lists, c.list)
		}
	}
	rng := rand.New(rand.NewSource(263))
	for i := 0; i < 3000; i++ {
		lists = append(lists, randomList(rng))
	}
	for i, list := range lists {
		agreeWithGNU(t, bin, i, list)
	}
	t.Logf("%d lists agree with %s", len(lists), bin)
}

// agreeWithGNU checks one list. Every name the parser reads that can be a
// file is created, holding "a", so a GNU line that opens another name fails
// to open where the parser's would be judged.
func agreeWithGNU(t *testing.T, bin string, i int, list string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "LIST"), []byte(list), 0o600); err != nil {
		t.Fatal(err)
	}
	p := parseChecksumList([]byte(list), "")
	var want []string
	for _, e := range p.entries {
		if !creatable(e.name) {
			want = append(want, "FAILED open or read")
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, e.name), []byte("a"), 0o600); err != nil {
			t.Fatalf("list %d: create %q: %v", i, e.name, err)
		}
	}
	// A second pass, once every file exists: two lines may name one file.
	want = want[:0]
	for _, e := range p.entries {
		switch {
		case !creatable(e.name):
			want = append(want, "FAILED open or read")
		case e.sum == hA:
			want = append(want, "OK")
		default:
			want = append(want, "FAILED")
		}
	}
	cmd := exec.Command(bin, "--check", "--warn", "LIST")
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	_ = cmd.Run() // a FAILED line exits non-zero
	var got []string
	for _, line := range strings.Split(strings.TrimRight(stdout.String(), "\n"), "\n") {
		switch {
		case line == "":
		case strings.HasSuffix(line, ": FAILED open or read"):
			got = append(got, "FAILED open or read")
		case strings.HasSuffix(line, ": FAILED"):
			got = append(got, "FAILED")
		case strings.HasSuffix(line, ": OK"):
			got = append(got, "OK")
		default:
			t.Fatalf("list %d: unexpected sha256sum output %q", i, line)
		}
	}
	var refused []int
	for _, line := range strings.Split(stderr.String(), "\n") {
		if m := improper.FindStringSubmatch(line); m != nil {
			n, _ := strconv.Atoi(m[1])
			refused = append(refused, n)
		}
	}
	sort.Ints(refused)
	if !reflect.DeepEqual(got, want) && !(len(got) == 0 && len(want) == 0) || !sameInts(refused, p.malformed) {
		t.Errorf("list %d %q:\n  sha256sum: %v, refused lines %v\n  parser:    %v, refused lines %v (entries %+v)\n  stderr: %s",
			i, list, got, refused, want, p.malformed, p.entries, stderr.String())
	}
}

func sameInts(a, b []int) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return reflect.DeepEqual(a, b)
}

// creatable reports whether a parsed name can be made a file in the test's
// directory: one path element that is not "." or "..", with no NUL.
func creatable(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, "/\x00") && len(name) < 200
}

// randomList builds one to four lines from the pieces a checksum line is made
// of, and some that break it, so the generated lists cover the forms, their
// mixing, and the edges between them.
func randomList(rng *rand.Rand) string {
	hashes := []string{hA, hB, strings.ToUpper(hA), hA[:63], hA + "0", strings.Repeat("g", 64)}
	names := []string{"m", "a b", " lead", "trail ", "*star", "x)y", "p(q", "back\\slash", `a\nb`, `a\\b`, `a\rb`, `bad\t`, "", "#hash", "=", "SHA256"}
	blanks := []string{"", " ", "  ", "\t", " \t"}
	pick := func(s []string) string { return s[rng.Intn(len(s))] }
	var b strings.Builder
	n := 1 + rng.Intn(4)
	for i := 0; i < n; i++ {
		if rng.Intn(6) == 0 {
			b.WriteString(pick(blanks))
		}
		if rng.Intn(5) == 0 {
			b.WriteString(`\`)
		}
		switch rng.Intn(4) {
		case 0: // tagged
			b.WriteString(pick([]string{"SHA256", "SHA256 ", "SHA512 ", "SHA256  ", "sha256 "}))
			b.WriteString(pick([]string{"(", "", " ("}))
			b.WriteString(pick(names))
			b.WriteString(pick([]string{")", "", ") ", " )"}))
			b.WriteString(pick([]string{" = ", "= ", "=", " =\t", " - "}))
			b.WriteString(pick(hashes))
			b.WriteString(pick([]string{"", "", " "}))
		default: // untagged
			b.WriteString(pick(hashes))
			b.WriteString(pick([]string{" ", "  ", " *", "\t", "\t*", "", "   "}))
			b.WriteString(pick(names))
		}
		b.WriteString(pick([]string{"\n", "\n", "\r\n", "\n\n", ""}))
	}
	return b.String()
}
