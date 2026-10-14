package hdf5

import (
	"fmt"
	"math/bits"
	"sort"
	"strings"
)

// Violation is positive evidence that a dataset's storage does not hold:
// Pattern is tensor-size (storage of another size than the dataset's type
// and shape need) or tensor-layout (storage outside the HDF5 data, or
// overlapping other storage or the file's own structures, or bytes after
// the HDF5 data).
type Violation struct {
	Pattern, Where, Detail string
}

// Layout is what Check found of the datasets' storage.
type LayoutCheck struct {
	Violations []Violation
	// Unchecked names what could not be checked, with the reason.
	Unchecked []string
	// Counts of datasets by storage, and the bytes of storage checked.
	Datasets, Contiguous, Chunked, Compact, Unallocated, Chunks int
	Bytes                                                       uint64
}

// maxViolations bounds the violations listed per pattern.
const maxViolations = 20

// Check checks every dataset's storage: that it lies inside the HDF5 data
// the superblock records, that its size is what its datatype and dataspace
// need, and that no two datasets' storage, and no storage and the
// structures the reader read, overlap. It also reports bytes after the end
// of the HDF5 data. It reads no dataset data.
func (f *File) Check() LayoutCheck {
	var lc LayoutCheck
	per := map[string]int{}
	add := func(pattern, where, detail string) {
		per[pattern]++
		if per[pattern] <= maxViolations {
			lc.Violations = append(lc.Violations, Violation{pattern, where, detail})
		}
	}
	truncated := f.Size < f.EOF
	switch {
	case truncated:
		lc.Unchecked = append(lc.Unchecked, fmt.Sprintf("the file is %d bytes, and its superblock says the HDF5 data runs to %d: truncated, or not the file that was written", f.Size, f.EOF))
	case f.Size > f.EOF:
		add("tensor-layout", "after the HDF5 data", fmt.Sprintf("%d bytes after the end of the HDF5 data the superblock records (%d); no HDF5 reader reads them, and a reader of another format can (a zip is read from its end)", f.Size-f.EOF, f.EOF))
	}
	var data []Extent
	for _, o := range f.Objects {
		ds := o.Dataset
		if ds == nil {
			continue
		}
		lc.Datasets++
		where := o.Path
		if why := datasetUnread(ds); why != "" {
			lc.Unchecked = append(lc.Unchecked, where+": "+why)
			continue
		}
		n, _ := ds.Space.Elements()
		hi, need := bits.Mul64(n, uint64(ds.Type.Size))
		if hi != 0 || need > 1<<62 {
			lc.Unchecked = append(lc.Unchecked, where+": a shape whose byte size overflows")
			continue
		}
		l := &ds.Layout
		switch l.Class {
		case LayoutCompact:
			lc.Compact++
			lc.Bytes += l.Size
			if l.Size != need {
				add("tensor-size", where, fmt.Sprintf("compact data of %d bytes; its type (%s) and shape %s need %d, and the HDF5 library refuses the dataset", l.Size, ds.Type.Name(), ds.Space, need))
			}
		case LayoutContiguous:
			lc.Contiguous++
			if l.Addr == undefined {
				lc.Unallocated++
				continue
			}
			size := l.Size
			if l.Version < 3 {
				size = need // versions 1 and 2 record none; the library computes it
			}
			if size != need {
				add("tensor-size", where, fmt.Sprintf("contiguous storage of %d bytes; its type (%s) and shape %s need %d: bytes no reader reads, or a read past its storage", size, ds.Type.Name(), ds.Space, need))
			}
			end := l.Addr + int64(max(size, need))
			switch {
			case end > f.EOF || end < l.Addr:
				add("tensor-layout", where, fmt.Sprintf("storage [%d, %d) runs past the end of the HDF5 data the superblock records (%d); the HDF5 library refuses to read it", l.Addr, end, f.EOF))
				continue
			case truncated && end > f.Size:
				lc.Unchecked = append(lc.Unchecked, where+": storage past the end of the truncated file")
				continue
			}
			lc.Bytes += need
			data = append(data, Extent{l.Addr, end, where})
		case LayoutChunked:
			lc.Chunked++
			if l.Addr == undefined {
				lc.Unallocated++
				continue
			}
			if l.Unread != "" {
				lc.Unchecked = append(lc.Unchecked, where+": "+l.Unread)
				continue
			}
			if l.ElemSize != uint64(ds.Type.Size) {
				add("tensor-size", where, fmt.Sprintf("a chunked layout that records elements of %d bytes for a %s type of %d", l.ElemSize, ds.Type.Name(), ds.Type.Size))
				continue
			}
			if len(ds.Filters) > 0 {
				lc.Unchecked = append(lc.Unchecked, fmt.Sprintf("%s: filtered with %s, which this reader does not decode, so its chunks' data sizes were not checked", where, FilterList(ds.Filters)))
			}
			want := chunkBytes(l)
			seen := map[string]bool{}
			for i, ch := range l.Chunks {
				lc.Chunks++
				cw := fmt.Sprintf("%s chunk %v", where, ch.Offset)
				if bad := chunkPlace(ds, ch); bad != "" && l.Index == IndexBTree1 {
					add("tensor-layout", cw, bad+"; no reader reads it")
					continue
				}
				key := fmt.Sprint(ch.Offset)
				if seen[key] {
					add("tensor-layout", cw, "two chunks at one offset; readers disagree on which they read")
					continue
				}
				seen[key] = true
				if len(ds.Filters) == 0 && l.Index != IndexImplicit && ch.Size != want {
					add("tensor-size", cw, fmt.Sprintf("an unfiltered chunk of %d bytes; its dimensions %v of %s need %d", ch.Size, l.ChunkDims, ds.Type.Name(), want))
				}
				end := ch.Addr + int64(ch.Size)
				switch {
				case end > f.EOF || end < ch.Addr || ch.Size > 1<<62:
					add("tensor-layout", cw, fmt.Sprintf("chunk storage [%d, %d) runs past the end of the HDF5 data the superblock records (%d)", ch.Addr, end, f.EOF))
					continue
				case truncated && end > f.Size:
					lc.Unchecked = append(lc.Unchecked, cw+": storage past the end of the truncated file")
					continue
				}
				lc.Bytes += ch.Size
				if ch.Size > 0 {
					data = append(data, Extent{ch.Addr, end, fmt.Sprintf("%s chunk %d", where, i)})
				}
			}
		}
	}
	for _, v := range overlaps(data, f.meta) {
		add("tensor-layout", v.Where, v.Detail)
	}
	for p, n := range per {
		if n > maxViolations {
			lc.Unchecked = append(lc.Unchecked, fmt.Sprintf("%d more %s violation(s) not listed", n-maxViolations, p))
		}
	}
	sort.SliceStable(lc.Violations, func(i, j int) bool { return lc.Violations[i].Pattern < lc.Violations[j].Pattern })
	return lc
}

// datasetUnread says why a dataset's storage cannot be checked, or "".
func datasetUnread(ds *Dataset) string {
	switch {
	case ds.Type.Unread != "":
		return "its datatype is " + ds.Type.Unread + ", which this reader does not resolve"
	case ds.Space.Kind == SpaceUnread:
		return "its dataspace is shared, which this reader does not resolve"
	case ds.Type.Size == 0:
		return "a datatype of size 0, which the HDF5 library refuses"
	case len(ds.External) > 0:
		names := make([]string, 0, len(ds.External))
		for _, e := range ds.External {
			names = append(names, fmt.Sprintf("%q", clip(e.Name, 120)))
		}
		return "its data is in external file(s) " + capJoin(names, 3) + ", which a reader opens outside this file"
	case ds.Layout.Class == LayoutVirtual:
		return "a virtual dataset, whose data is mapped from other datasets, possibly in other files"
	}
	if _, ok := ds.Space.Elements(); !ok {
		return "a shape whose element count overflows"
	}
	if ds.Layout.Class == LayoutChunked && ds.Space.Kind != SpaceSimple {
		return "a chunked dataset with a scalar or null dataspace"
	}
	return ""
}

// chunkPlace says why a chunk is not where a reader looks for one, or "".
func chunkPlace(ds *Dataset, ch Chunk) string {
	l := &ds.Layout
	if len(ch.Offset) != len(l.ChunkDims) {
		return "a chunk key of the wrong rank"
	}
	for i, v := range ch.Offset {
		c := l.ChunkDims[i]
		if c == 0 {
			return "a chunk dimension of 0"
		}
		if v%c != 0 {
			return fmt.Sprintf("a chunk at offset %v, not on a chunk boundary", ch.Offset)
		}
		if v >= ds.Space.Dims[i] && !(v == 0 && ds.Space.Dims[i] == 0) {
			return fmt.Sprintf("a chunk at offset %v, outside the dataset's shape %s", ch.Offset, ds.Space)
		}
	}
	return ""
}

// overlaps finds data extents that overlap each other or a metadata
// structure, naming the first it overlaps.
func overlaps(data, meta []Extent) []Violation {
	var out []Violation
	sort.SliceStable(data, func(i, j int) bool { return data[i].Start < data[j].Start })
	// reach is the extent so far that ends furthest.
	var reach Extent
	for i := 1; i < len(data); i++ {
		if data[i-1].End > reach.End {
			reach = data[i-1]
		}
		if data[i].Start < reach.End {
			out = append(out, Violation{"tensor-layout", data[i].What,
				fmt.Sprintf("storage [%d, %d) overlaps %s's [%d, %d): two datasets read the same bytes", data[i].Start, data[i].End, reach.What, reach.Start, reach.End)})
		}
	}
	ms := append([]Extent(nil), meta...)
	sort.SliceStable(ms, func(i, j int) bool { return ms[i].Start < ms[j].Start })
	// best[i] is the index of the structure reaching furthest among ms[:i+1].
	best := make([]int, len(ms))
	for i := range ms {
		best[i] = i
		if i > 0 && ms[best[i-1]].End >= ms[i].End {
			best[i] = best[i-1]
		}
	}
	for _, e := range data {
		k := sort.Search(len(ms), func(i int) bool { return ms[i].Start >= e.End })
		if k == 0 {
			continue
		}
		if m := ms[best[k-1]]; m.End > e.Start {
			out = append(out, Violation{"tensor-layout", e.What,
				fmt.Sprintf("storage [%d, %d) overlaps the file's %s at [%d, %d)", e.Start, e.End, m.What, m.Start, m.End)})
		}
	}
	return out
}

// clip cuts s to at most n bytes.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func capJoin(items []string, n int) string {
	if len(items) <= n {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:n], ", ") + fmt.Sprintf(" and %d more", len(items)-n)
}
