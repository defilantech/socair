package engine

import (
	"path/filepath"

	"github.com/defilantech/socair/internal/hostpath"
	"github.com/defilantech/socair/internal/report"
)

// nameSnapshot holds a finished document to the artifact's name wherever the
// scan's snapshot path stands in its text (#170). Every check reads the
// snapshot, so the snapshot's path is the host path a check can put in a
// row: an operating-system error names the file it failed on ("open
// /tmp/socair-dir-1/config.json/x: not a directory"), and a check that could
// not read a file quotes it. The reference inputs are named by file name and
// hash where they are read, and the helpers' text is held to the paths each
// was handed, so this is the last host path a check's text can carry.
//
// snap is the snapshot (a file, or a directory's root) and is named by the
// artifact's name. private says snap's parent is the scan's own snapshot
// directory, named by its own name; it is false when snap is the operator's
// path, as in a header-only sweep, whose parent may be any directory and is
// left alone, as is the text the artifact supplies.
func nameSnapshot(d *report.Document, snap string, private bool) {
	n := &hostpath.Names{}
	name := d.Artifact.FileName
	if name == "" {
		name = filepath.Base(snap)
	}
	n.Add(snap, name)
	if private {
		n.Base(filepath.Dir(snap))
	}
	n.Walk(d)
}
