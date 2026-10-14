package pickle

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/defilantech/socair/internal/checks"
)

// zipRead is a torch.save zip's data.pkl as the grammar read it: the record
// directory, the pickle's record name, and what validating it found.
type zipRead struct {
	dir, data string
	g         *validation
}

// ErrNotStateDict marks a file StateDict does not read: its Pickle opcode
// scan did not PASS, it is not a torch.save zip, or its pickle builds
// something other than a dict of names to tensors. The reason is in the
// error.
var ErrNotStateDict = errors.New("not a state dict the grammar read")

// StateDict is a torch.save zip whose Pickle opcode scan PASSed, as
// torch.load reads it: the root dict's entries in stream order, each tensor's
// view of its storage, and the storage records. Everything here comes from
// the grammar's validated model of data.pkl; nothing was unpickled.
type StateDict struct {
	// Result is the Pickle opcode scan on these bytes: a PASS.
	Result checks.Result
	// Archive is the directory the zip's records sit in, and Pickle the
	// record torch.load unpickles (<Archive>/data.pkl).
	Archive, Pickle string
	// ByteOrder is the byteorder record's content, or "" when HasByteOrder
	// is false and the zip has none.
	ByteOrder    string
	HasByteOrder bool
	// Root is the root dict's class: "dict" or "collections.OrderedDict".
	// RootAttributes names the attributes an OrderedDict root carries, such
	// as a module state dict's _metadata.
	Root           string
	RootAttributes []string
	Tensors        []StateTensor
	// Storages are keyed by storage key, the record <Archive>/data/<key>.
	Storages map[string]StateStorage
}

// StateTensor is one root entry: a name and the tensor torch.load builds
// for it.
type StateTensor struct {
	Name string
	// Dtype is the torch dtype as the stream names it (a storage class's
	// dtype, or the dtype argument of _rebuild_tensor_v3), and Itemsize its
	// element size in bytes.
	Dtype    string
	Itemsize int64
	// Shape and Stride are the view, in elements; Offset is the storage
	// offset, in elements of Dtype.
	Shape, Stride []int64
	Offset        int64
	// Storage is the storage key, "" for a tensor without storage.
	Storage string
	// Parameter is a torch.nn.Parameter. Metadata is a non-empty metadata
	// argument, which sets torch's conj or neg bit; Attributes are Python
	// attributes set on the tensor.
	Parameter, Metadata, Attributes bool
}

// StateStorage is one storage a persistent id names.
type StateStorage struct {
	Key, Record string
	// Class is the storage class (torch.FloatStorage, torch.UntypedStorage),
	// Dtype the dtype its elements are, and Numel how many it holds.
	Class, Dtype    string
	Itemsize, Numel int64
}

func notStateDict(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrNotStateDict, fmt.Sprintf(format, a...))
}

// ReadStateDict reads a torch.save zip whose Pickle opcode scan PASSes, with
// no reviewed classes, and whose pickle builds a dict of names to tensors.
// It runs the full check on path, so its verdict is the check's own. Any
// other file is ErrNotStateDict with the reason.
func ReadStateDict(path string) (*StateDict, error) {
	r, s := inspect(path, Options{})
	if r.Status != checks.Pass {
		return nil, notStateDict("the %s row is %s: %s", CheckName, r.Status, r.Notes)
	}
	if s == nil || s.zip == nil {
		return nil, notStateDict("not a torch.save zip (the format since PyTorch 1.6); the pickle check read it as %s", excerpt(r.Notes))
	}
	z := s.zip
	g := z.g
	sd := &StateDict{Result: r, Archive: z.dir, Pickle: z.data, Storages: map[string]StateStorage{}}

	root := g.root
	if root.kind != kDict || (root.class != "dict" && root.class != "collections.OrderedDict") {
		return nil, notStateDict("its pickle builds %s, not a dict of names to tensors", describe(root))
	}
	sd.Root = root.class
	if root.x != nil && root.x.attrs != nil {
		for i := 0; i < len(root.x.attrs.items); i += 2 {
			sd.RootAttributes = append(sd.RootAttributes, root.x.attrs.items[i].s)
		}
	}
	for i := 0; i+1 < len(root.items); i += 2 {
		k, val := root.items[i], root.items[i+1]
		switch {
		case k.kind != kStr:
			return nil, notStateDict("entry %d has %s as its key, not a name", i/2+1, describe(k))
		case k.x != nil && k.x.long:
			return nil, notStateDict("entry %d has a name longer than %d bytes", i/2+1, maxStr)
		case val.kind != kTensor || val.x == nil || val.x.t == nil:
			return nil, notStateDict("entry %q is %s, not a tensor", excerpt(k.s), describe(val))
		}
		t := val.x.t
		sd.Tensors = append(sd.Tensors, StateTensor{
			Name: k.s, Dtype: t.dtype, Itemsize: t.itemsize,
			Shape: append([]int64(nil), t.shape...), Stride: append([]int64(nil), t.stride...),
			Offset: t.offset, Storage: t.key,
			Parameter: t.param, Metadata: t.meta, Attributes: t.attrs,
		})
	}
	for _, key := range g.order {
		st := g.storages[key]
		sd.Storages[key] = StateStorage{Key: key, Record: z.dir + "/data/" + key, Class: st.stype,
			Dtype: st.dtype, Itemsize: st.itemsize, Numel: st.numel}
	}

	bo, has, err := byteOrder(path, z.dir+"/byteorder")
	if err != nil {
		return nil, err
	}
	sd.ByteOrder, sd.HasByteOrder = bo, has
	return sd, nil
}

// byteOrder reads the byteorder record torch.save writes beside data.pkl.
// The check accepted the archive only with that record at most 64 bytes.
func byteOrder(path, name string) (string, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", false, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", false, err
	}
	zr, err := zip.NewReader(f, fi.Size())
	if err != nil {
		return "", false, err
	}
	for _, zf := range zr.File {
		if zf.Name != name {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			return "", false, err
		}
		defer rc.Close()
		b, err := io.ReadAll(io.LimitReader(rc, 65))
		if err != nil {
			return "", false, fmt.Errorf("read %s: %w", name, err)
		}
		return string(b), true, nil
	}
	return "", false, nil
}
