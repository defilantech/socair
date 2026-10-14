package hostpath

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// A path is replaced where it stands whole, longest first, and nowhere it is
// part of a longer name. Falsification: drop either boundary test or the
// longest-first order and a case fails.
func TestScrubReplacesWholePathsOnly(t *testing.T) {
	n := &Names{}
	n.Add("/srv/alice/models", "models")
	n.Add("/srv/alice/models/model.gguf", "model.gguf")
	n.Add("/tmp", "$TMPDIR")
	for in, want := range map[string]string{
		"open /srv/alice/models/model.gguf: permission denied": "open model.gguf: permission denied",
		"File \"/srv/alice/models/sub/x.py\", line 3":          "File \"models/sub/x.py\", line 3",
		"'/srv/alice/models'":                                  "'models'",
		"/srv/alice/models.bak and /srv/alice/modelsx":         "/srv/alice/models.bak and /srv/alice/modelsx",
		"/tmp/x, /tmpfs, /a/tmp, and /tmp":                     "$TMPDIR/x, /tmpfs, /a/tmp, and $TMPDIR",
		"file:///tmp/y":                                        "file://$TMPDIR/y",
		"no path here":                                         "no path here",
	} {
		if got := n.Scrub(in); got != want {
			t.Errorf("Scrub(%q) = %q, want %q", in, got, want)
		}
	}
	var none *Names
	if got := none.Scrub("/tmp/x"); got != "/tmp/x" {
		t.Errorf("a nil Names changed %q", got)
	}
}

// A path is also replaced in the form a helper may print it in: absolute, and
// with symlinks resolved, including a file that does not exist under a
// directory that does. A path added first keeps its name, and a root is
// never added.
func TestAddCoversEachFormOfAPath(t *testing.T) {
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatal(err)
	}
	n := &Names{}
	n.Add(filepath.Join(link, "absent.json"), "absent.json")
	n.Add(filepath.Join(link, "absent.json"), "other")
	n.Add("/", "root")
	got := n.Scrub("read " + filepath.Join(resolved, "absent.json") + " and " + filepath.Join(link, "absent.json") + " under /")
	if want := "read absent.json and absent.json under /"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}

	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	r := &Names{}
	r.Base("relative.txt")
	if got := r.Scrub(filepath.Join(wd, "relative.txt")); got != "relative.txt" {
		t.Errorf("a relative path is not replaced in its absolute form: %q", got)
	}
}

// Env names each environment value that is one absolute path by its
// variable. A list, a relative value, and a root are left alone.
func TestEnvNamesPathsByVariable(t *testing.T) {
	n := &Names{}
	n.Env([]string{"HOME=/home/alice", "TMPDIR=/var/tmp/alice", "PATH=/home/alice/bin:/usr/bin", "LANG=C.UTF-8", "REL=a/b", "ROOT=/", "EMPTY="})
	in := "/home/alice/.local/x.py /var/tmp/alice/y /usr/bin/python3 a/b"
	if got, want := n.Scrub(in), "$HOME/.local/x.py $TMPDIR/y /usr/bin/python3 a/b"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// A helper's standard error is quoted from its end with paths replaced
// first, so a cut cannot leave the tail of a path that would no longer
// match. Falsification: cut before replacing, or keep the window's first
// line after the window was cut, and the sentinel's tail survives.
func TestStderrQuoteCannotSplitAPath(t *testing.T) {
	const p = "/srv/SOCAIRHOSTPATH/helper"
	n := &Names{}
	n.Add(p, "helper")

	// 422 bytes: the last 400 begin at "HOSTPATH" if the cut came first.
	var short Stderr
	short.Write([]byte("Traceback: " + p + " " + strings.Repeat("y", 383) + "\n"))
	if q := short.Quote(n, 400); strings.Contains(q, "HOSTPATH") || !strings.HasSuffix(q, "y") {
		t.Errorf("a 400-byte quote kept part of a path: %q", q)
	}

	// The window keeps the last stderrWindow bytes; these put its first byte
	// five bytes into p, so it begins with "SOCAIRHOSTPATH/helper".
	var long Stderr
	long.Write([]byte(p + "\n"))
	long.Write([]byte(strings.Repeat("z", stderrWindow-len(p)-6) + "\nlast line"))
	q := long.Quote(n, stderrWindow)
	if strings.Contains(q, "HOSTPATH") || !strings.HasSuffix(q, "last line") {
		t.Errorf("a cut window kept part of a path: %q...", q[:min(len(q), 40)])
	}

	var ctl Stderr
	ctl.Write([]byte("bad \x1b[31mthing\x1b[0m\n"))
	if q := ctl.Quote(nil, 400); q != "bad  [31mthing [0m" {
		t.Errorf("control characters: %q", q)
	}
	var empty Stderr
	if q := empty.Quote(n, 400); q != "" {
		t.Errorf("nothing written, quoted %q", q)
	}
}

type inner struct {
	Note    string
	Metrics map[string]float64
}

type outer struct {
	Name    string
	Ptr     *inner
	List    []inner
	Env     map[string]string
	private string
}

// Walk replaces paths in every exported string a value reaches, map keys
// included, and leaves an unexported field alone.
func TestWalkReachesEveryString(t *testing.T) {
	n := &Names{}
	n.Add("/srv/x/model.gguf", "model.gguf")
	v := outer{
		Name:    "/srv/x/model.gguf",
		Ptr:     &inner{Note: "read /srv/x/model.gguf"},
		List:    []inner{{Metrics: map[string]float64{"/srv/x/model.gguf": 1, "agreement": 0.5}}},
		Env:     map[string]string{"/srv/x/model.gguf": "at /srv/x/model.gguf"},
		private: "/srv/x/model.gguf",
	}
	n.Walk(&v)
	if v.Name != "model.gguf" || v.Ptr.Note != "read model.gguf" || v.List[0].Metrics["model.gguf"] != 1 ||
		v.List[0].Metrics["agreement"] != 0.5 || len(v.List[0].Metrics) != 2 || v.Env["model.gguf"] != "at model.gguf" || len(v.Env) != 1 {
		t.Errorf("walked %+v %+v %+v", v, *v.Ptr, v.List)
	}
	if v.private != "/srv/x/model.gguf" {
		t.Error("an unexported field was changed")
	}
}

// Reason gives an operating-system or exec error's cause without its path.
func TestReasonDropsThePath(t *testing.T) {
	for err, want := range map[error]string{
		&fs.PathError{Op: "fork/exec", Path: "/srv/x/helper", Err: syscall.EACCES}: "permission denied",
		&exec.Error{Name: "/srv/x/helper", Err: exec.ErrNotFound}:                  "executable file not found in $PATH",
		// The errno's text differs by platform: "cross-device link" on
		// macOS, "invalid cross-device link" on Linux.
		&os.LinkError{Op: "rename", Old: "/srv/a", New: "/srv/b", Err: syscall.EXDEV}: syscall.EXDEV.Error(),
		errors.New("plain"): "plain",
		errors.Join(errors.New("ctx"), &fs.PathError{Op: "open", Path: "/srv/x", Err: fs.ErrNotExist}): "file does not exist",
	} {
		if got := Reason(err); got != want {
			t.Errorf("Reason(%v) = %q, want %q", err, got, want)
		}
	}
}
