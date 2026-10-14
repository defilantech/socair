// Package hostpath keeps paths on the scanning host out of a report. A filed
// report travels, and a path can carry a username and a directory layout
// (#170).
//
// Reason gives an operating-system error's cause without the path it names,
// for a note that names the file itself. Names replaces the paths Socair
// handed out (to a check, which reads the scan's snapshot, or to an external
// helper: its executable, the files its request names, and the paths in its
// environment) wherever they occur in text that came back. That text is free
// form, so nothing in it is guessed at: a path is replaced only where it
// stands whole, and a path Socair did not hand out, such as one a helper
// found for itself, is not recognised.
package hostpath

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"unicode"
)

// Reason is an operating-system or exec error's cause without the path it
// names: "permission denied" for "fork/exec /opt/x: permission denied".
// Any other error is given whole.
func Reason(err error) string {
	var ee *exec.Error
	var pe *fs.PathError
	var le *os.LinkError
	switch {
	case errors.As(err, &ee):
		return ee.Err.Error()
	case errors.As(err, &pe):
		return pe.Err.Error()
	case errors.As(err, &le):
		return le.Err.Error()
	}
	return err.Error()
}

// Names is a set of host paths, each with the name a report gives it. The
// zero value replaces nothing. Once built, it is safe for concurrent use.
type Names struct {
	subs []sub // longest path first
}

type sub struct{ path, name string }

// Add replaces path with name. The path is taken in absolute form and, when
// it resolves through a symlink (macOS's /var is /private/var), in resolved
// form too. A path added earlier keeps its name, and a root, which is part of
// every path, is never added.
func (n *Names) Add(path, name string) {
	if path == "" || name == "" {
		return
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return
	}
	forms := []string{abs}
	if r, err := filepath.EvalSymlinks(abs); err == nil {
		forms = append(forms, r)
	} else if r, err := filepath.EvalSymlinks(filepath.Dir(abs)); err == nil {
		// A file that does not exist, such as one an error names, is
		// still under a directory that resolves.
		forms = append(forms, filepath.Join(r, filepath.Base(abs)))
	}
	for _, p := range forms {
		if filepath.Dir(p) == p || n.has(p) {
			continue
		}
		n.subs = append(n.subs, sub{p, name})
	}
	sort.SliceStable(n.subs, func(i, j int) bool { return len(n.subs[i].path) > len(n.subs[j].path) })
}

func (n *Names) has(p string) bool {
	for _, s := range n.subs {
		if s.path == p {
			return true
		}
	}
	return false
}

// Base replaces path with its base name: a file by its file name, a
// directory by its own name, so a path under it reads as relative to it.
func (n *Names) Base(path string) {
	n.Add(path, filepath.Base(filepath.Clean(path)))
}

// Env replaces each environment value that is one absolute path with the
// variable that holds it, "$HOME" for HOME. A list such as PATH is not one
// path and is left alone.
func (n *Names) Env(environ []string) {
	for _, kv := range environ {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" || !filepath.IsAbs(v) || strings.ContainsRune(v, os.PathListSeparator) {
			continue
		}
		n.Add(v, "$"+k)
	}
}

// Scrub returns s with each added path replaced by its name wherever the path
// stands whole: not inside a longer name (/tmp in /tmpfs or /a/tmp), though a
// path under it (/tmp/x) reads from its name (tmp/x). The longest path that
// stands at a place is replaced, so a file under an added directory is named
// as the file.
func (n *Names) Scrub(s string) string {
	if n == nil || len(n.subs) == 0 {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		matched := false
		if i == 0 || !nameByte(s[i-1]) {
			for _, x := range n.subs {
				end := i + len(x.path)
				if strings.HasPrefix(s[i:], x.path) && (end == len(s) || s[end] == '/' || s[end] == filepath.Separator || !nameByte(s[end])) {
					b.WriteString(x.name)
					i, matched = end, true
					break
				}
			}
		}
		if !matched {
			b.WriteByte(s[i])
			i++
		}
	}
	return b.String()
}

// nameByte reports whether c can continue a file name, so a path that ends
// or begins next to it is part of a longer name. A byte of a multibyte
// character can.
func nameByte(c byte) bool {
	return c >= 0x80 || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		strings.IndexByte("._-~+@%", c) >= 0
}

// Walk scrubs, in place, every string v reaches: v is a pointer, and the
// walk follows struct fields, pointers, slices, arrays, and maps, keys and
// values. It is how a whole report, or a helper's whole answer, is held to
// the names.
func (n *Names) Walk(v any) {
	if n == nil || len(n.subs) == 0 {
		return
	}
	n.walk(reflect.ValueOf(v))
}

func (n *Names) walk(v reflect.Value) {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			n.walk(v.Elem())
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() {
				n.walk(v.Field(i))
			}
		}
	case reflect.Slice, reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return // bytes, not text
		}
		for i := 0; i < v.Len(); i++ {
			n.walk(v.Index(i))
		}
	case reflect.Map:
		if v.IsNil() {
			return
		}
		for _, k := range v.MapKeys() {
			val := reflect.New(v.Type().Elem()).Elem()
			val.Set(v.MapIndex(k))
			n.walk(val)
			key := k
			if k.Kind() == reflect.String {
				if s := n.Scrub(k.String()); s != k.String() {
					key = reflect.New(k.Type()).Elem()
					key.SetString(s)
					v.SetMapIndex(k, reflect.Value{})
				}
			}
			v.SetMapIndex(key, val)
		}
	case reflect.String:
		if v.CanSet() {
			v.SetString(n.Scrub(v.String()))
		}
	}
}

// stderrWindow is how much of a helper's standard error is kept. Paths are
// replaced in the window before the quote is cut from its end, so the cut
// never leaves the tail of a path that would no longer match.
const stderrWindow = 64 << 10

// Stderr keeps the end of a helper's standard error, for a report to quote.
type Stderr struct {
	b   []byte
	cut bool
}

func (s *Stderr) Write(p []byte) (int, error) {
	s.b = append(s.b, p...)
	if len(s.b) > stderrWindow {
		s.b = s.b[len(s.b)-stderrWindow:]
		s.cut = true
	}
	return len(p), nil
}

// Quote is the last max bytes of what the helper wrote, with n's paths
// replaced and control characters blanked; "" when it wrote nothing. When the
// window was cut, its first line is dropped, since the cut may have split a
// path there.
func (s *Stderr) Quote(n *Names, max int) string {
	text := string(s.b)
	if s.cut {
		if i := strings.IndexAny(text, "\n \t"); i >= 0 {
			text = text[i+1:]
		} else {
			text = ""
		}
	}
	text = n.Scrub(text)
	if len(text) > max {
		text = text[len(text)-max:]
	}
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == unicode.ReplacementChar {
			return ' '
		}
		return r
	}, text))
}
