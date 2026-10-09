package pickle

import (
	"fmt"
	"math"
	"math/bits"
	"regexp"
	"strconv"
	"strings"

	"github.com/defilantech/socair/internal/checks"
)

// reducer checks one callable's arguments against its signature and returns
// what the call builds, or an unknown value after recording why not. It
// returns nil when validation must stop: the stream broke, or the model's
// budget ran out.
type reducer func(v *validator, fn string, args []*value) *value

// reducers are the callables of grammar socair-wo/1 and their signatures.
// The allowed set follows PyTorch's weights-only unpickler
// (torch/_weights_only_unpickler.py), which checks the callable but not its
// arguments; each entry here also checks the arguments. numpy's array, dtype,
// and scalar reconstruction are added, since rng_state.pth and some state
// dicts carry them.
var reducers map[string]reducer

func init() {
	reducers = map[string]reducer{
		"torch._utils._rebuild_tensor":                        rebuildTensor,
		"torch._utils._rebuild_tensor_v2":                     rebuildTensor,
		"torch._utils._rebuild_tensor_v3":                     rebuildTensor,
		"torch._utils._rebuild_parameter":                     rebuildParameter,
		"torch._utils._rebuild_parameter_with_state":          rebuildParameter,
		"torch.nn.parameter.Parameter":                        newParameter,
		"torch._utils._rebuild_meta_tensor_no_storage":        rebuildMeta,
		"torch._utils._rebuild_device_tensor_from_cpu_tensor": rebuildFromCPU,
		"torch._tensor._rebuild_from_type_v2":                 rebuildFromType,
		"torch.Size":                                          torchSize,
		"torch.device":                                        torchDevice,
		"collections.OrderedDict":                             orderedDict,
		"collections.Counter":                                 counter,
		"builtins.set":                                        setOf,
		"builtins.frozenset":                                  setOf,
		"builtins.bytearray":                                  bytearrayOf,
		"builtins.bytes":                                      emptyBytes,
		"builtins.complex":                                    complexOf,
		"_codecs.encode":                                      codecsEncode,
		"numpy.core.multiarray._reconstruct":                  ndarrayShell,
		"numpy._core.multiarray._reconstruct":                 ndarrayShell,
		"numpy.dtype":                                         npDtype,
		"numpy.core.multiarray.scalar":                        npScalar,
		"numpy._core.multiarray.scalar":                       npScalar,
	}
}

type dtypeInfo struct {
	dtype    string
	itemsize int64
}

// storageTypes are torch's storage classes and the dtype each holds
// (torch.storage._dtype_to_storage_type_map). UntypedStorage holds bytes.
var storageTypes = map[string]dtypeInfo{
	"DoubleStorage": {"float64", 8}, "FloatStorage": {"float32", 4}, "HalfStorage": {"float16", 2},
	"LongStorage": {"int64", 8}, "IntStorage": {"int32", 4}, "ShortStorage": {"int16", 2},
	"CharStorage": {"int8", 1}, "ByteStorage": {"uint8", 1}, "BoolStorage": {"bool", 1},
	"BFloat16Storage": {"bfloat16", 2}, "ComplexDoubleStorage": {"complex128", 16},
	"ComplexFloatStorage": {"complex64", 8}, "QInt8Storage": {"qint8", 1}, "QInt32Storage": {"qint32", 4},
	"QUInt8Storage": {"quint8", 1}, "QUInt4x2Storage": {"quint4x2", 1}, "QUInt2x4Storage": {"quint2x4", 1},
	"UntypedStorage": {"uint8", 1},
}

// torchDtypes are the torch dtypes a stream names as globals, with their
// element sizes.
var torchDtypes = map[string]int64{
	"float32": 4, "float": 4, "float64": 8, "double": 8, "float16": 2, "half": 2, "bfloat16": 2,
	"complex32": 4, "chalf": 4, "complex64": 8, "cfloat": 8, "complex128": 16, "cdouble": 16,
	"uint8": 1, "int8": 1, "int16": 2, "short": 2, "int32": 4, "int": 4, "int64": 8, "long": 8, "bool": 1,
	"uint16": 2, "uint32": 4, "uint64": 8, "qint8": 1, "quint8": 1, "qint32": 4, "quint4x2": 1, "quint2x4": 1,
	"float8_e5m2": 1, "float8_e4m3fn": 1, "float8_e5m2fnuz": 1, "float8_e4m3fnuz": 1, "float8_e8m0fnu": 1,
	"float4_e2m1fn_x2": 1, "bits8": 1, "bits16": 2, "bits1x8": 1, "bits2x4": 1, "bits4x2": 1,
	"uint1": 1, "uint2": 1, "uint3": 1, "uint4": 1, "uint5": 1, "uint6": 1, "uint7": 1,
	"int1": 1, "int2": 1, "int3": 1, "int4": 1, "int5": 1, "int6": 1, "int7": 1,
}

// valueGlobals are globals the grammar admits as values only: storage
// classes, dtypes, quantization schemes, and the types a tensor rebuild names.
func valueGlobal(full string) bool {
	mod, name, _ := cutLast(full)
	switch mod {
	case "torch", "torch.cuda":
		if _, ok := storageTypes[name]; ok {
			return true
		}
		if mod == "torch.cuda" {
			return false
		}
		if _, ok := torchDtypes[name]; ok {
			return true
		}
		switch name {
		case "Tensor", "per_tensor_affine", "per_tensor_symmetric", "per_channel_affine",
			"per_channel_symmetric", "per_channel_affine_float_qparams":
			return true
		}
	case "numpy":
		return name == "ndarray"
	}
	return false
}

func cutLast(full string) (string, string, bool) {
	i := strings.LastIndex(full, ".")
	if i < 0 {
		return "", full, false
	}
	return full[:i], full[i+1:], true
}

func isModeled(full string) bool {
	_, ok := reducers[full]
	return ok || valueGlobal(full)
}

// harmless are callables reviewed as reaching no code, that the grammar does
// not model: the import scan accepts them, and a stream that calls one is
// outside the grammar (NOT_TESTED), not suspicious.
var harmless = map[string]bool{
	"builtins.int": true, "builtins.float": true, "builtins.str": true, "builtins.list": true,
	"builtins.dict": true, "builtins.tuple": true, "builtins.range": true, "builtins.bool": true,
	"builtins.slice": true, "collections.defaultdict": true, "copyreg._reconstructor": true,
	"torch._utils._rebuild_qtensor": true, "torch._utils._rebuild_sparse_tensor": true,
	"torch._utils._rebuild_wrapper_subclass": true, "torch._utils._rebuild_device_tensor_from_numpy": true,
	"torch._utils._rebuild_nested_tensor": true, "torch.serialization._get_layout": true,
	"numpy.core.numeric._frombuffer": true, "numpy._core.numeric._frombuffer": true,
}

func isHarmless(full string) bool { return harmless[full] }

// spelling is how a writer at proto spells a global: below protocol 3,
// CPython's pickler writes Python 2 module names (builtins as __builtin__).
func spelling(mod, name string, proto int) string {
	if proto < 3 && mod == "builtins" {
		mod = "__builtin__"
	}
	return mod + "." + name
}

// codeLike matches strings that read as code or a shell command. It is
// applied only to a string where a signature forbids one, to tell a payload
// (FAIL) from a malformed argument (LEAD); strings in places a signature
// allows them are data and are not judged.
var codeLike = regexp.MustCompile(`(?i)(\bimport\s+[a-z_]|__import__|\b(exec|eval|compile|getattr|setattr|open|system|popen|spawn[a-z]*|fork|loads?|run)\s*\(|\bos\.[a-z_]+|\bsubprocess\b|\bbuiltins\b|__[a-z]+__|\blambda\b|/bin/[a-z]*sh\b|^\s*(echo|sh|bash|zsh|curl|wget|nc|ncat|python[0-9.]*|perl|ruby|php|node|powershell|pwsh|cmd|rm|chmod|chown|touch|cat|cp|mv|id|whoami|uname|env|nohup|sudo)(\s|$)|[;&|]\s*(echo|sh|bash|curl|wget|rm|cat|python[0-9.]*)\b|\$\(|` + "`" + `)`)

// argViolation reports arguments that do not match a signature: a FAIL when
// a forbidden string reads as code, the ShadowPickle shape of an OrderedDict
// handed a command, and a LEAD otherwise.
func (v *validator) argViolation(fn string, args []*value, detail string) {
	for _, a := range args {
		for _, s := range stringsIn(a) {
			if codeLike.MatchString(s) {
				v.violate(checks.Fail, "pickle-code-argument", fmt.Sprintf("%s(%q)", fn, excerpt(s)),
					detail+"; the argument reads as code, which a patched or tampered "+fn+" would run")
				return
			}
		}
	}
	v.violate(checks.Lead, "pickle-grammar", fn, detail)
}

func stringsIn(a *value) []string {
	switch a.kind {
	case kStr, kBytes:
		return []string{a.s}
	case kTuple, kList:
		var out []string
		for _, it := range a.items {
			if it.kind == kStr || it.kind == kBytes {
				out = append(out, it.s)
			}
		}
		return out
	}
	return nil
}

func intArg(a *value) (int64, bool) {
	if a.kind != kInt || (a.x != nil && a.x.big != nil) {
		return 0, false
	}
	return a.num, true
}

func intTuple(a *value) ([]int64, bool) {
	if a.kind != kTuple {
		return nil, false
	}
	out := make([]int64, len(a.items))
	for i, it := range a.items {
		n, ok := intArg(it)
		if !ok || n < 0 {
			return nil, false
		}
		out[i] = n
	}
	return out, true
}

func (v *validator) unknown() *value {
	x, err := v.alloc(kUnknown)
	if err != nil {
		return nil
	}
	return x
}

// viewNeeds is how many elements a view needs from its storage: none when
// any dimension is empty, else one past its furthest element. It reports
// false on overflow.
func viewNeeds(offset int64, size, stride []int64) (int64, bool) {
	for _, s := range size {
		if s == 0 {
			return 0, true
		}
	}
	need := uint64(offset) + 1
	for i := range size {
		hi, lo := bits.Mul64(uint64(stride[i]), uint64(size[i]-1))
		if hi != 0 || lo > math.MaxInt64 {
			return 0, false
		}
		sum, carry := bits.Add64(need, lo, 0)
		if carry != 0 || sum > math.MaxInt64 {
			return 0, false
		}
		need = sum
	}
	return int64(need), true
}

var tensorArity = map[string][2]int{
	"torch._utils._rebuild_tensor":    {4, 4},
	"torch._utils._rebuild_tensor_v2": {6, 7},
	"torch._utils._rebuild_tensor_v3": {7, 8},
}

// rebuildTensor checks _rebuild_tensor, _rebuild_tensor_v2, and
// _rebuild_tensor_v3: (storage, storage_offset, size, stride[, requires_grad,
// backward_hooks][, dtype][, metadata]). The view must fit in its storage,
// and the hooks must be an empty OrderedDict.
func rebuildTensor(v *validator, fn string, args []*value) *value {
	arity := tensorArity[fn]
	if len(args) < arity[0] || len(args) > arity[1] {
		v.argViolation(fn, args, fmt.Sprintf("%d arguments, where the signature takes %d to %d", len(args), arity[0], arity[1]))
		return v.unknown()
	}
	st := storageArg(args[0])
	offset, okOff := intArg(args[1])
	size, okSize := intTuple(args[2])
	stride, okStride := intTuple(args[3])
	if st == nil || !okOff || offset < 0 || !okSize || !okStride || len(size) != len(stride) {
		v.argViolation(fn, args, "arguments that are not (storage, offset, size, stride) with a non-negative offset and equal-length size and stride")
		return v.unknown()
	}
	dtype, itemsize := st.dtype, st.itemsize
	untyped := st.stype == "torch.UntypedStorage"
	if fn == "torch._utils._rebuild_tensor_v3" {
		d, ok := dtypeArg(args[6])
		if !ok || !untyped {
			v.argViolation(fn, args, "a v3 tensor needs an untyped storage and a torch dtype")
			return v.unknown()
		}
		dtype, itemsize = d, torchDtypes[d]
	} else if untyped && !st.opaque {
		v.argViolation(fn, args, "an untyped storage where the signature takes a typed one")
		return v.unknown()
	}
	if len(args) >= 6 {
		if args[4].kind != kBool {
			v.argViolation(fn, args, "requires_grad that is not a bool")
			return v.unknown()
		}
		if !v.hooks(fn, args[5]) {
			return v.unknown()
		}
	}
	if meta := len(args) == arity[1] && arity[0] != arity[1]; meta && !tensorMetadata(args[len(args)-1]) {
		v.argViolation(fn, args, "metadata that is not None or a dict of names to bools")
		return v.unknown()
	}
	if !st.opaque {
		// A typed storage counts elements of its own dtype; a v3 tensor reads
		// elements of its dtype from an untyped storage's bytes.
		need, ok := viewNeeds(offset, size, stride)
		have := st.numel
		if st.view != nil {
			have = st.view.size
		}
		if fn == "torch._utils._rebuild_tensor_v3" {
			have /= max(itemsize, 1)
		}
		if !ok || need > have {
			v.violate(checks.Fail, "pickle-storage-layout", "data/"+st.key,
				fmt.Sprintf("%s: a view of size %v, stride %v, offset %d needs %s element(s) of %s; its storage holds %d. The loader rejects the file or reads outside the storage",
					fn, size, stride, offset, needString(need, ok), dtype, have))
			return v.unknown()
		}
	}
	return v.tensor(dtype, size, st.key, offset)
}

func needString(n int64, ok bool) string {
	if !ok {
		return "more than 2^63"
	}
	return strconv.FormatInt(n, 10)
}

func (v *validator) tensor(dtype string, shape []int64, key string, offset int64) *value {
	x, err := v.alloc(kTensor)
	if err != nil {
		return nil
	}
	t := &tensorInfo{dtype: dtype, shape: shape, key: key, offset: offset}
	x.ext().t = t
	v.out.tensors = append(v.out.tensors, t)
	return x
}

func storageArg(a *value) *storageRef {
	if a.kind != kStorage || a.x == nil {
		return nil
	}
	return a.x.st
}

func dtypeArg(a *value) (string, bool) {
	if a.kind != kGlobal {
		return "", false
	}
	mod, name, _ := cutLast(a.class)
	if _, ok := torchDtypes[name]; !ok || mod != "torch" {
		return "", false
	}
	return name, true
}

func tensorMetadata(a *value) bool {
	if a.kind == kNone {
		return true
	}
	if a.kind != kDict || a.class != "dict" {
		return false
	}
	for i := 0; i < len(a.items); i += 2 {
		if a.items[i].kind != kStr || a.items[i+1].kind != kBool {
			return false
		}
	}
	return true
}

// hooks checks a backward_hooks argument. torch.save writes an empty
// OrderedDict; hooks are callables a training run invokes.
func (v *validator) hooks(fn string, h *value) bool {
	if h.kind != kDict || h.class != "collections.OrderedDict" || (h.x != nil && h.x.attrs != nil) {
		v.argViolation(fn, []*value{h}, "backward_hooks that are "+describe(h)+", where torch.save writes an empty OrderedDict")
		return false
	}
	if len(h.items) > 0 {
		v.violate(checks.Lead, "pickle-backward-hooks", fn,
			fmt.Sprintf("%d backward hook(s), where torch.save writes none: hooks are callables a training run invokes", len(h.items)/2))
	}
	return true
}

// rebuildParameter checks _rebuild_parameter (data, requires_grad, hooks)
// and _rebuild_parameter_with_state, which adds Python attributes.
func rebuildParameter(v *validator, fn string, args []*value) *value {
	n := 3
	if fn == "torch._utils._rebuild_parameter_with_state" {
		n = 4
	}
	if len(args) != n || args[0].kind != kTensor || args[1].kind != kBool {
		v.argViolation(fn, args, "arguments that are not (tensor, requires_grad, backward_hooks)")
		return v.unknown()
	}
	if !v.hooks(fn, args[2]) {
		return v.unknown()
	}
	if n == 4 && !attrState(args[3]) {
		v.argViolation(fn, args, "parameter state that is not None or a dict of attribute names to plain values")
		return v.unknown()
	}
	return v.param(args[0])
}

// newParameter checks torch.nn.Parameter(data[, requires_grad]), by REDUCE
// or NEWOBJ, which weights-only also admits.
func newParameter(v *validator, fn string, args []*value) *value {
	if len(args) < 1 || len(args) > 2 || args[0].kind != kTensor || (len(args) == 2 && args[1].kind != kBool) {
		v.argViolation(fn, args, "arguments that are not (tensor[, requires_grad])")
		return v.unknown()
	}
	return v.param(args[0])
}

func (v *validator) param(t *value) *value {
	x, err := v.alloc(kTensor)
	if err != nil {
		return nil
	}
	x.ext().t = t.x.t
	t.x.t.param = true
	return x
}

func rebuildMeta(v *validator, fn string, args []*value) *value {
	if len(args) != 4 {
		v.argViolation(fn, args, "arguments that are not (dtype, size, stride, requires_grad)")
		return v.unknown()
	}
	d, okD := dtypeArg(args[0])
	size, okSize := intTuple(args[1])
	stride, okStride := intTuple(args[2])
	if !okD || !okSize || !okStride || len(size) != len(stride) || args[3].kind != kBool {
		v.argViolation(fn, args, "arguments that are not (dtype, size, stride, requires_grad)")
		return v.unknown()
	}
	return v.tensor(d, size, "", 0)
}

func rebuildFromCPU(v *validator, fn string, args []*value) *value {
	if len(args) != 4 || args[0].kind != kTensor || args[3].kind != kBool || args[2].kind != kStr || !deviceName.MatchString(args[2].s) {
		v.argViolation(fn, args, "arguments that are not (tensor, dtype, device, requires_grad)")
		return v.unknown()
	}
	if _, ok := dtypeArg(args[1]); !ok {
		v.argViolation(fn, args, "a dtype that is not a torch dtype")
		return v.unknown()
	}
	x, err := v.alloc(kTensor)
	if err != nil {
		return nil
	}
	x.ext().t = args[0].x.t
	return x
}

// tensorRebuilds are the callables _rebuild_from_type_v2 may call.
var tensorRebuilds = map[string]bool{
	"torch._utils._rebuild_tensor": true, "torch._utils._rebuild_tensor_v2": true,
	"torch._utils._rebuild_tensor_v3": true, "torch._utils._rebuild_parameter": true,
	"torch._utils._rebuild_parameter_with_state": true, "torch._utils._rebuild_meta_tensor_no_storage": true,
	"torch._utils._rebuild_device_tensor_from_cpu_tensor": true,
}

// rebuildFromType checks _rebuild_from_type_v2(func, new_type, args, state):
// a tensor with Python attributes. func must be a tensor rebuild, new_type
// torch.Tensor or torch.nn.Parameter (a subclass is an unreviewed global),
// and the attributes plain values.
func rebuildFromType(v *validator, fn string, args []*value) *value {
	if len(args) != 4 || args[0].kind != kGlobal || !tensorRebuilds[args[0].class] || args[1].kind != kGlobal ||
		(args[1].class != "torch.Tensor" && args[1].class != "torch.nn.parameter.Parameter") || args[2].kind != kTuple {
		v.argViolation(fn, args, "arguments that are not (a tensor rebuild, torch.Tensor or Parameter, its arguments, attributes)")
		return v.unknown()
	}
	if !attrState(args[3]) {
		v.argViolation(fn, args, "tensor attributes that are not a dict of attribute names to plain values")
		return v.unknown()
	}
	res := reducers[args[0].class](v, args[0].class, args[2].items)
	if res != nil && res.kind == kTensor && args[1].class == "torch.nn.parameter.Parameter" {
		res.x.t.param = true
	}
	return res
}

// attrState is Python object state setattr would apply: None, a dict of
// attribute names to plain values, or that and a slots dict.
func attrState(s *value) bool {
	if s.kind == kNone {
		return true
	}
	if s.kind == kTuple && len(s.items) == 2 {
		return (s.items[0].kind == kNone || attrDict(s.items[0])) && (s.items[1].kind == kNone || attrDict(s.items[1]))
	}
	return attrDict(s)
}

func attrDict(d *value) bool {
	if d.kind != kDict || d.class != "dict" {
		return false
	}
	b := newBudget()
	for i := 0; i < len(d.items); i += 2 {
		k := d.items[i]
		if k.kind != kStr || !plainName.MatchString(k.s) || strings.HasPrefix(k.s, "__") || !plain(d.items[i+1], b) {
			return false
		}
	}
	return true
}

// plain is a value with no behavior: a constant, or a container of them. A
// value too large to walk within the budget is not shown plain.
func plain(x *value, b *budget) bool {
	if !b.spend() {
		return false
	}
	switch x.kind {
	case kNone, kBool, kInt, kFloat, kStr, kBytes:
		return true
	case kTuple, kList, kDict:
		if x.kind == kDict && x.class != "dict" {
			return false
		}
		for _, it := range x.items {
			if !plain(it, b) {
				return false
			}
		}
		return true
	case kGlobal:
		_, ok := dtypeArg(x)
		return ok
	}
	return false
}

var deviceName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}(:[0-9]{1,5})?$`)

func torchSize(v *validator, fn string, args []*value) *value {
	if len(args) != 1 {
		v.argViolation(fn, args, "arguments that are not one tuple of sizes")
		return v.unknown()
	}
	if _, ok := intTuple(args[0]); !ok {
		v.argViolation(fn, args, "a size that is not a tuple of non-negative ints")
		return v.unknown()
	}
	return v.obj(fn)
}

func torchDevice(v *validator, fn string, args []*value) *value {
	ok := len(args) >= 1 && len(args) <= 2 && args[0].kind == kStr && deviceName.MatchString(args[0].s)
	if ok && len(args) == 2 {
		n, isInt := intArg(args[1])
		ok = isInt && n >= -1
	}
	if !ok {
		v.argViolation(fn, args, "arguments that are not a device type and an optional index")
		return v.unknown()
	}
	return v.obj(fn)
}

func (v *validator) obj(class string) *value {
	x, err := v.alloc(kObj)
	if err != nil {
		return nil
	}
	x.class = class
	return x
}

// orderedDict checks collections.OrderedDict(): torch.save writes no
// arguments and sets the items after; pairs are accepted too. A string is
// never an OrderedDict's argument.
func orderedDict(v *validator, fn string, args []*value) *value {
	d, err := v.alloc(kDict)
	if err != nil {
		return nil
	}
	d.class = fn
	if len(args) == 0 {
		return d
	}
	if len(args) != 1 || (args[0].kind != kList && args[0].kind != kTuple) {
		v.argViolation(fn, args, "an argument that is not a list of pairs")
		return v.unknown()
	}
	for _, p := range args[0].items {
		if (p.kind != kTuple && p.kind != kList) || len(p.items) != 2 {
			v.argViolation(fn, args, "an argument that is not a list of pairs")
			return v.unknown()
		}
		if err := v.addKey(d, p.items[0], fn); err != nil {
			return nil
		}
		d.items = append(d.items, p.items[0], p.items[1])
	}
	return d
}

// counter checks collections.Counter(), which pickles as Counter(dict).
func counter(v *validator, fn string, args []*value) *value {
	if len(args) > 1 || (len(args) == 1 && (args[0].kind != kDict || args[0].class != "dict")) {
		v.argViolation(fn, args, "an argument that is not a dict")
		return v.unknown()
	}
	d, err := v.alloc(kDict)
	if err != nil {
		return nil
	}
	d.class = fn
	if len(args) == 1 {
		d.items = append(d.items, args[0].items...)
	}
	return d
}

// setOf checks set(list) and frozenset(list), which is how protocol 2
// pickles both.
func setOf(v *validator, fn string, args []*value) *value {
	if len(args) > 1 || (len(args) == 1 && args[0].kind != kList) {
		v.argViolation(fn, args, "an argument that is not a list")
		return v.unknown()
	}
	s := v.obj(fn)
	if s == nil {
		return nil
	}
	if len(args) == 1 {
		for _, it := range args[0].items {
			if err := v.addKey(s, it, fn); err != nil {
				return nil
			}
		}
		s.items = args[0].items
	}
	return s
}

// bytearrayOf checks bytearray(), bytearray(bytes), or the older
// bytearray(str, "latin-1").
func bytearrayOf(v *validator, fn string, args []*value) *value {
	ok := len(args) == 0 || (len(args) == 1 && args[0].kind == kBytes) ||
		(len(args) == 2 && args[0].kind == kStr && args[1].kind == kStr && args[1].s == "latin-1" && args[0].ext().maxRune < 256)
	if !ok {
		v.argViolation(fn, args, "arguments that are not bytes or a latin-1 string")
		return v.unknown()
	}
	return v.obj(fn)
}

// emptyBytes checks bytes(), how protocol 2 pickles b"".
func emptyBytes(v *validator, fn string, args []*value) *value {
	if len(args) != 0 {
		v.argViolation(fn, args, "arguments, where protocol 2 pickles only empty bytes this way")
		return v.unknown()
	}
	x, err := v.alloc(kBytes)
	if err != nil {
		return nil
	}
	return x
}

func complexOf(v *validator, fn string, args []*value) *value {
	num := func(a *value) (float64, bool) {
		switch a.kind {
		case kFloat:
			return a.f, true
		case kInt:
			if a.x == nil || a.x.big == nil {
				return float64(a.num), true
			}
		}
		return 0, false
	}
	if len(args) != 2 {
		v.argViolation(fn, args, "arguments that are not (real, imag)")
		return v.unknown()
	}
	re, ok1 := num(args[0])
	im, ok2 := num(args[1])
	if !ok1 || !ok2 {
		v.argViolation(fn, args, "arguments that are not (real, imag)")
		return v.unknown()
	}
	x := v.obj(fn)
	if x != nil {
		x.f = re
		x.ext().imag = im
	}
	return x
}

// codecsEncode checks _codecs.encode(str, "latin1"), how protocol 2 pickles
// bytes. Any other codec is not what a writer emits.
func codecsEncode(v *validator, fn string, args []*value) *value {
	if len(args) != 2 || args[0].kind != kStr || args[1].kind != kStr || args[1].s != "latin1" {
		v.argViolation(fn, args, "arguments that are not (string, \"latin1\")")
		return v.unknown()
	}
	if args[0].ext().maxRune > 0xff {
		_ = v.broke("_codecs.encode of a string latin1 cannot encode")
		return nil
	}
	x, err := v.alloc(kBytes)
	if err != nil {
		return nil
	}
	x.num = args[0].x.runes
	if args[0].x.long {
		x.ext().long = true
		x.x.digest = args[0].x.digest
		return x
	}
	b := make([]byte, 0, x.num)
	for _, r := range args[0].s {
		b = append(b, byte(r))
	}
	x.s = string(b)
	return x
}

// ndarrayShell checks numpy's _reconstruct(ndarray, (0,), b"b"): an empty
// array that BUILD then fills.
func ndarrayShell(v *validator, fn string, args []*value) *value {
	if len(args) != 3 || args[0].kind != kGlobal || args[0].class != "numpy.ndarray" || args[1].kind != kTuple ||
		!((args[2].kind == kBytes || args[2].kind == kStr) && args[2].s == "b") {
		v.argViolation(fn, args, "arguments that are not (numpy.ndarray, shape, b\"b\")")
		return v.unknown()
	}
	if _, ok := intTuple(args[1]); !ok {
		v.argViolation(fn, args, "a shape that is not a tuple of non-negative ints")
		return v.unknown()
	}
	x := v.obj("numpy.ndarray")
	if x != nil {
		x.ext().np = &npInfo{}
	}
	return x
}

// npDtype checks numpy.dtype(code, False, True); BUILD then gives its byte
// order and size.
func npDtype(v *validator, fn string, args []*value) *value {
	if len(args) != 3 || args[0].kind != kStr || args[1].kind != kBool || args[1].num != 0 || args[2].kind != kBool || args[2].num != 1 {
		v.argViolation(fn, args, "arguments that are not (code, False, True)")
		return v.unknown()
	}
	size, object, ok := npReduceCode(args[0].s)
	if !ok {
		v.out.gap("numpy dtype " + strconv.Quote(excerpt(args[0].s)) + ", which " + Grammar + " does not model")
		return v.unknown()
	}
	x := v.obj("numpy.dtype")
	if x != nil {
		x.ext().np = &npInfo{itemsize: size, object: object, code: args[0].s}
	}
	return x
}

var npCodeRe = regexp.MustCompile(`^([biufcOSUV])([0-9]{1,6})$`)

// npReduceCode reads a numpy dtype code as dtype.__reduce__ gives it: a kind
// and a size in bytes.
func npReduceCode(code string) (int64, bool, bool) {
	m := npCodeRe.FindStringSubmatch(code)
	if m == nil {
		return 0, false, false
	}
	n, _ := strconv.ParseInt(m[2], 10, 64)
	switch m[1] {
	case "b":
		return n, false, n == 1
	case "i", "u":
		return n, false, n == 1 || n == 2 || n == 4 || n == 8
	case "f":
		return n, false, n == 2 || n == 4 || n == 8 || n == 16
	case "c":
		return n, false, n == 8 || n == 16 || n == 32
	case "O":
		return n, true, n == 4 || n == 8
	}
	return n, false, true // S, U, V: flexible, sized in bytes
}

// buildNPDtype checks a dtype's BUILD state, (3, byteorder, subdescr, names,
// fields, elsize, alignment, flags), for a dtype without fields.
func (v *validator) buildNPDtype(d, state *value) error {
	info := d.x.np
	if state.kind == kTuple && len(state.items) == 9 {
		v.out.gap("a numpy dtype with metadata, which " + Grammar + " does not model")
		return nil
	}
	ok := state.kind == kTuple && len(state.items) == 8
	var elsize int64
	if ok {
		it := state.items
		ver, _ := intArg(it[0])
		var okE bool
		elsize, okE = intArg(it[5])
		ok = ver == 3 && okE && it[1].kind == kStr && len(it[1].s) == 1 && strings.Contains("<>|=", it[1].s)
	}
	if !ok {
		v.violate(checks.Lead, "pickle-grammar", "numpy.dtype", "a dtype state that is not the 8-tuple numpy writes")
		return nil
	}
	if it := state.items; it[2].kind != kNone || it[3].kind != kNone || it[4].kind != kNone {
		v.out.gap("a structured numpy dtype, which " + Grammar + " does not model")
		return nil
	}
	flexible := strings.ContainsAny(info.code[:1], "SUV")
	if (flexible && elsize != info.itemsize) || (!flexible && elsize != -1) {
		v.violate(checks.Lead, "pickle-grammar", "numpy.dtype", fmt.Sprintf("a dtype %s whose state gives size %d", info.code, elsize))
	}
	return nil
}

// buildNDArray checks an array's BUILD state, (1, shape, dtype, is_fortran,
// data): raw bytes of exactly shape x itemsize, or for an object dtype a list
// of that many values. numpy rejects any other length.
func (v *validator) buildNDArray(a, state *value) error {
	ok := state.kind == kTuple && len(state.items) == 5
	var shape []int64
	if ok {
		ver, _ := intArg(state.items[0])
		var okShape bool
		shape, okShape = intTuple(state.items[1])
		ok = ver == 1 && okShape && state.items[3].kind == kBool
	}
	if !ok {
		v.violate(checks.Lead, "pickle-grammar", "numpy.ndarray", "an array state that is not the 5-tuple numpy writes")
		return nil
	}
	dt, data := state.items[2], state.items[4]
	if dt.kind == kUnknown {
		return nil // an unmodeled dtype already left a gap
	}
	if dt.kind != kObj || dt.class != "numpy.dtype" || !dt.x.built {
		v.violate(checks.Lead, "pickle-grammar", "numpy.ndarray", "an array whose dtype is "+describe(dt))
		return nil
	}
	count, ok := elements(shape)
	info := dt.x.np
	switch {
	case !ok:
		return v.broke("an array shape whose element count overflows")
	case info.object:
		if data.kind != kList || int64(len(data.items)) != count {
			return v.broke("an object array whose data is not a list of %d values", count)
		}
	default:
		size := max(info.itemsize, 1)
		if data.kind != kBytes || data.num%size != 0 || data.num/size != count {
			return v.broke("an array of %d element(s) of %d bytes with %s of data", count, info.itemsize, describe(data))
		}
	}
	a.x.np = &npInfo{itemsize: info.itemsize, object: info.object, dtype: dt, shape: shape, code: info.code}
	return nil
}

func elements(shape []int64) (int64, bool) {
	n := int64(1)
	for _, s := range shape {
		hi, lo := bits.Mul64(uint64(n), uint64(s))
		if hi != 0 || lo > math.MaxInt64 {
			return 0, false
		}
		n = int64(lo)
	}
	return n, true
}

// npScalar checks numpy's scalar(dtype, data): itemsize bytes, or for an
// object dtype any value.
func npScalar(v *validator, fn string, args []*value) *value {
	if len(args) != 2 || args[0].kind != kObj || args[0].class != "numpy.dtype" || !args[0].x.built {
		if len(args) == 2 && args[0].kind == kUnknown {
			return v.unknown()
		}
		v.argViolation(fn, args, "arguments that are not (dtype, data)")
		return v.unknown()
	}
	info := args[0].x.np
	if !info.object && (args[1].kind != kBytes || args[1].num != info.itemsize) {
		_ = v.broke("a numpy scalar of %d bytes with %s of data", info.itemsize, describe(args[1]))
		return nil
	}
	return v.obj("numpy.scalar")
}

// reviewedNew builds an instance of a reviewed class: NEWOBJ with plain
// arguments (a default __new__), or a call with plain arguments (an enum
// member). Its state is checked at BUILD.
func (v *validator) reviewedNew(class string, args *value, isNew bool) *value {
	b := newBudget()
	for _, a := range args.items {
		if !plain(a, b) {
			v.violate(checks.Lead, "pickle-reviewed-class-state", class,
				"a reviewed class constructed from "+describe(a)+", where its review covers plain arguments")
			return v.unknown()
		}
	}
	if v.out.reviewed == nil {
		v.out.reviewed = map[string]bool{}
	}
	v.out.reviewed[class] = true
	x := v.obj(class)
	if x != nil {
		x.ext().sym = &symCall{fn: class, isNew: isNew, args: args}
	}
	return x
}

// reviewedState is the state a reviewed class's review covers: a dict of
// attribute names to plain values, other reviewed instances, and devices.
func reviewedState(s *value, reviewed map[string]bool, b *budget) bool {
	if s.kind != kDict || s.class != "dict" {
		return false
	}
	for i := 0; i < len(s.items); i += 2 {
		if s.items[i].kind != kStr || !reviewedValue(s.items[i+1], reviewed, b) {
			return false
		}
	}
	return true
}

func reviewedValue(x *value, reviewed map[string]bool, b *budget) bool {
	if !b.spend() {
		return false
	}
	switch x.kind {
	case kNone, kBool, kInt, kFloat, kStr, kBytes:
		return true
	case kGlobal:
		_, ok := dtypeArg(x)
		return ok
	case kObj:
		return reviewed[x.class] || x.class == "torch.device"
	case kTuple, kList, kDict:
		if x.kind == kDict && x.class != "dict" {
			return false
		}
		for _, it := range x.items {
			if !reviewedValue(it, reviewed, b) {
				return false
			}
		}
		return true
	}
	return false
}

var storageKey = regexp.MustCompile(`^[0-9]{1,20}$`)

// legacyView reads a legacy storage id's view metadata, (key, offset, size).
func legacyView(vm *value) (*storageView, bool) {
	if vm.kind != kTuple || len(vm.items) != 3 || vm.items[0].kind != kStr || !storageKey.MatchString(vm.items[0].s) {
		return nil, false
	}
	off, ok1 := intArg(vm.items[1])
	size, ok2 := intArg(vm.items[2])
	if !ok1 || !ok2 || off < 0 || size < 0 {
		return nil, false
	}
	return &storageView{key: vm.items[0].s, offset: off, size: size}, true
}

// storageRef checks a persistent id against what the container's loader
// accepts, and records the storage it names.
func (v *validator) storageRef(pid *value) *storageRef {
	if v.opts.pids == pidTar {
		switch {
		case pid.kind == kStr && storageKey.MatchString(pid.s):
			return &storageRef{key: pid.s, opaque: true}
		case pid.kind == kInt:
			return &storageRef{key: strconv.FormatInt(pid.num, 10), opaque: true}
		}
	}
	if pid.kind != kTuple || len(pid.items) == 0 || pid.items[0].kind != kStr || pid.items[0].s != "storage" {
		what := describe(pid)
		if pid.kind == kTuple && len(pid.items) > 0 && pid.items[0].kind == kStr {
			what = "a " + strconv.Quote(excerpt(pid.items[0].s)) + " id"
		}
		v.violate(checks.Lead, "pickle-grammar", "BINPERSID",
			"a persistent id that is "+what+", not a storage reference; a full-model pickle loads classes this way")
		return nil
	}
	n := 5
	if v.opts.pids == pidLegacy {
		n = 6
	}
	it := pid.items
	if len(it) != n {
		v.argViolation("persistent id", it, fmt.Sprintf("a storage id of %d fields, where this container's loader reads %d", len(it), n))
		return nil
	}
	st := &storageRef{}
	if it[1].kind == kGlobal {
		mod, name, _ := cutLast(it[1].class)
		if d, ok := storageTypes[name]; ok && (mod == "torch" || mod == "torch.cuda") {
			st.stype, st.dtype, st.itemsize = "torch."+name, d.dtype, d.itemsize
		}
	}
	numel, okN := intArg(it[4])
	if st.stype == "" || it[2].kind != kStr || !storageKey.MatchString(it[2].s) || it[3].kind != kStr ||
		!deviceName.MatchString(it[3].s) || !okN || numel < 0 {
		if it[1].kind == kUnknown {
			return nil
		}
		v.argViolation("persistent id", it, "a storage id that is not (\"storage\", storage class, numeric key, device, element count)")
		return nil
	}
	st.key, st.numel = it[2].s, numel
	if n == 6 && it[5].kind != kNone {
		view, ok := legacyView(it[5])
		if !ok {
			v.argViolation("persistent id", it, "view metadata that is not (key, offset, size)")
			return nil
		}
		if view.size > numel-view.offset {
			v.violate(checks.Fail, "pickle-storage-layout", "storage "+st.key,
				fmt.Sprintf("a view of %d element(s) at offset %d of a storage of %d", view.size, view.offset, numel))
			return nil
		}
		st.view = view
	}
	if prev, seen := v.out.storages[st.key]; seen {
		if prev.dtype != st.dtype || prev.numel != st.numel {
			if prev.numel*prev.itemsize != 0 || st.numel*st.itemsize != 0 {
				v.violate(checks.Fail, "pickle-storage-layout", "data/"+st.key,
					fmt.Sprintf("one storage referenced as %d %s and as %d %s; the loader keeps the first, so later views read the wrong bytes",
						prev.numel, prev.dtype, st.numel, st.dtype))
				return nil
			}
		}
		st.numel, st.dtype, st.itemsize = prev.numel, prev.dtype, prev.itemsize
	} else {
		v.out.storages[st.key] = st
		v.out.order = append(v.out.order, st.key)
	}
	return st
}
