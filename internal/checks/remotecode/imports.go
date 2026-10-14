package remotecode

import (
	"bytes"
	"regexp"
	"strings"
)

// pyImport is one module an import statement names: level is the number of
// leading dots (0 for an absolute import), module the dotted name after them,
// and names what a from-import takes from it, any of which may be a
// submodule.
type pyImport struct {
	level  int
	module string
	names  []string
}

var (
	// `import a.b as c, d` and transformers' `import .x` form.
	importStmt = regexp.MustCompile(`^\s*import\s+(.+)$`)
	// `from .a.b import c, d`, `from . import (c, d)`.
	fromStmt = regexp.MustCompile(`^\s*from\s+(\.*)\s*([\w.]*)\s+import\s*(.*)$`)
	// importlib.import_module("x"), __import__("x"): a literal name.
	dynamicImport = regexp.MustCompile(`(?:import_module|__import__)\s*\(\s*[rRbBuU]*['"](\.*[\w.]+)['"]`)
	dottedName    = regexp.MustCompile(`^\.*[\w.]*$`)
)

// scanImports lists the modules a Python source names in import statements
// and in importlib.import_module or __import__ calls with a literal name.
// It reads every line, docstrings and comments included, as transformers'
// own regular expressions do: a name it reports that Python would not import
// only widens the list of files a reviewer is pointed at. A parenthesised
// from-import may span lines, and a backslash continues a line.
func scanImports(src []byte) []pyImport {
	var out []pyImport
	lines := logicalLines(src)
	for _, line := range lines {
		for _, m := range dynamicImport.FindAllStringSubmatch(line, -1) {
			out = append(out, dotted(m[1], nil))
		}
		for _, stmt := range strings.Split(line, ";") {
			if m := fromStmt.FindStringSubmatch(stmt); m != nil {
				var names []string
				for _, n := range strings.Split(strings.Trim(strings.TrimSpace(m[3]), "()"), ",") {
					n = strings.TrimSpace(n)
					if i := strings.IndexAny(n, " \t"); i >= 0 {
						n = n[:i] // "x as y"
					}
					if n != "" && n != "*" && dottedName.MatchString(n) {
						names = append(names, n)
					}
				}
				out = append(out, pyImport{level: len(m[1]), module: strings.Trim(m[2], "."), names: names})
				continue
			}
			if m := importStmt.FindStringSubmatch(stmt); m != nil {
				for _, n := range strings.Split(m[1], ",") {
					n = strings.TrimSpace(n)
					if i := strings.IndexAny(n, " \t"); i >= 0 {
						n = n[:i]
					}
					if n != "" && dottedName.MatchString(n) {
						out = append(out, dotted(n, nil))
					}
				}
			}
		}
	}
	return out
}

func dotted(name string, names []string) pyImport {
	level := len(name) - len(strings.TrimLeft(name, "."))
	return pyImport{level: level, module: strings.Trim(name[level:], "."), names: names}
}

// maxLogicalLine bounds a joined line, so an unclosed parenthesis cannot
// swallow the rest of a file into one statement.
const maxLogicalLine = 8 << 10

// logicalLines splits src into lines with their comments cut, joining a
// backslash continuation and the lines of a from-import whose parenthesis is
// still open.
func logicalLines(src []byte) []string {
	var out []string
	var cur strings.Builder
	open := false
	for _, raw := range bytes.Split(src, []byte("\n")) {
		line := strings.TrimRight(string(raw), "\r")
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimRight(line, " \t")
		cont := strings.HasSuffix(line, "\\")
		line = strings.TrimSuffix(line, "\\")
		if cur.Len() > 0 {
			cur.WriteByte(' ')
		}
		cur.WriteString(line)
		s := cur.String()
		if !open && fromStmt.MatchString(s) {
			open = strings.Count(s, "(") > strings.Count(s, ")")
		} else if open {
			open = strings.Count(s, "(") > strings.Count(s, ")")
		}
		if (cont || open) && cur.Len() < maxLogicalLine {
			continue
		}
		out = append(out, cur.String())
		cur.Reset()
		open = false
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}
