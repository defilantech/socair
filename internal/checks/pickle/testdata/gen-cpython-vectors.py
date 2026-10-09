#!/usr/bin/env python3
"""Records CPython's reading of pickle streams for the grammar's differential test.

Run once, from this directory, with any CPython 3.8+ and no third-party
packages:

    python3 gen-cpython-vectors.py > cpython-vectors.json

Nothing here imports torch or numpy, and nothing is executed while loading.
torch.save-shaped streams are written by CPython's own pickler (protocol 2, as
torch.save uses) from stand-in modules registered under the same names, so the
bytes are what torch.save writes. Every stream is then loaded by CPython's
Unpickler with find_class and persistent_load overridden: a global becomes a
symbol, a call records its arguments, and BUILD and SETITEMS record what they
were given. The rendering of that symbolic load is what the Go validator must
reproduce for any stream it accepts.

Each vector carries:
  name      a label
  pids      the persistent-id form the stream may carry: none, zip, legacy
  hex       the stream
  cpython   CPython's symbolic reading, or "error: <type>"
  conform   whether the stream is inside grammar socair-wo/1
"""

import collections
import io
import json
import pickle
import struct
import sys
import types

# --- stand-in modules ---------------------------------------------------------


def module(name):
    m = types.ModuleType(name)
    sys.modules[name] = m
    return m


torch = module("torch")
torch_utils = module("torch._utils")
torch_tensor = module("torch._tensor")
module("torch.nn")
torch_nn_parameter = module("torch.nn.parameter")
numpy = module("numpy")
module("numpy.core")
numpy_multiarray = module("numpy.core.multiarray")


def function(mod, name):
    def f(*args):
        raise RuntimeError("stand-in")

    f.__module__ = mod.__name__
    f.__qualname__ = f.__name__ = name
    setattr(mod, name, f)
    return f


def klass(mod, name):
    c = type(name, (), {"__module__": mod.__name__})
    setattr(mod, name, c)
    return c


rebuild_v2 = function(torch_utils, "_rebuild_tensor_v2")
rebuild_v3 = function(torch_utils, "_rebuild_tensor_v3")
rebuild_parameter = function(torch_utils, "_rebuild_parameter")
reconstruct = function(numpy_multiarray, "_reconstruct")
np_scalar = function(numpy_multiarray, "scalar")
FloatStorage = klass(torch, "FloatStorage")
LongStorage = klass(torch, "LongStorage")
BFloat16Storage = klass(torch, "BFloat16Storage")
ByteStorage = klass(torch, "ByteStorage")
UntypedStorage = klass(torch, "UntypedStorage")
ndarray = klass(numpy, "ndarray")
np_dtype = klass(numpy, "dtype")


class Dtype:
    """A torch dtype: pickled as the global torch.<name>, as torch does."""

    def __init__(self, name):
        self.name = name
        setattr(torch, name, self)

    def __reduce__(self):
        return self.name


Dtype.__module__ = "torch"
float8_e4m3fn = Dtype("float8_e4m3fn")


class Storage:
    def __init__(self, stype, key, numel, location="cpu"):
        self.stype, self.key, self.numel, self.location = stype, key, numel, location


class Tensor:
    """Reduces exactly as torch.Tensor._reduce_ex_internal does."""

    def __init__(self, storage, offset, size, stride, dtype=None):
        self.storage, self.offset, self.size, self.stride, self.dtype = storage, offset, size, stride, dtype

    def __reduce_ex__(self, proto):
        args = (self.storage, self.offset, tuple(self.size), tuple(self.stride), False, collections.OrderedDict())
        if self.dtype is not None:
            return (rebuild_v3, args + (self.dtype,))
        return (rebuild_v2, args)


class Parameter:
    def __init__(self, data):
        self.data = data

    def __reduce_ex__(self, proto):
        return (rebuild_parameter, (self.data, True, collections.OrderedDict()))


class NPDtype:
    def __init__(self, code, endian, elsize=-1, flags=0):
        self.code, self.endian, self.elsize, self.flags = code, endian, elsize, flags

    def __reduce__(self):
        return (np_dtype, (self.code, False, True), (3, self.endian, None, None, None, self.elsize, -1, self.flags))


class NDArray:
    """Reduces as numpy.ndarray.__reduce__ does below protocol 5."""

    def __init__(self, shape, dtype, data):
        self.shape, self.dtype, self.data = shape, dtype, data

    def __reduce__(self):
        return (reconstruct, (ndarray, (0,), b"b"), (1, self.shape, self.dtype, False, self.data))


class NPScalar:
    """Reduces as a numpy scalar does: numpy.core.multiarray.scalar(dtype, bytes)."""

    def __init__(self, dtype, data):
        self.dtype, self.data = dtype, data

    def __reduce__(self):
        return (np_scalar, (self.dtype, self.data))


class TorchPickler(pickle.Pickler):
    def persistent_id(self, obj):
        if isinstance(obj, Storage):
            return ("storage", obj.stype, obj.key, obj.location, obj.numel)
        return None


class LegacyPickler(pickle.Pickler):
    def persistent_id(self, obj):
        if isinstance(obj, Storage):
            return ("storage", obj.stype, obj.key, obj.location, obj.numel, None)
        return None


def torch_pickle(obj, protocol=2, pickler=TorchPickler):
    b = io.BytesIO()
    pickler(b, protocol=protocol).dump(obj)
    return b.getvalue()


def plain(obj, protocol=2):
    return pickle.dumps(obj, protocol=protocol)


# --- symbolic load ------------------------------------------------------------


class Pid:
    def __init__(self, pid):
        self.pid = pid


class SymBase:
    pass


def symbol(qual):
    class Sym(SymBase):
        _qual = qual

        def __new__(cls, *args):
            o = object.__new__(cls)
            o.kind, o.args, o.items, o.state, o.built = "new", args, [], None, False
            return o

        def __init__(self, *args):
            self.kind = "call"

        def __setstate__(self, state):
            self.state, self.built = state, True

        def __setitem__(self, k, v):
            self.items.append((k, v))

    Sym.__name__ = Sym.__qualname__ = qual
    return Sym


class SymbolicUnpickler(pickle.Unpickler):
    """CPython's C unpickler (what torch.load uses) with find_class and
    persistent_load replaced, so loading imports nothing and calls nothing.
    The C unpickler does not expose its protocol, so the stream's leading
    PROTO is passed in to apply fix_imports as find_class would."""

    def __init__(self, f, pids, proto):
        super().__init__(f)
        self.pids = pids
        self.proto_seen = proto
        self.symbols = {}

    def find_class(self, mod, name):
        if self.proto_seen < 3:
            from _compat_pickle import IMPORT_MAPPING, NAME_MAPPING

            if (mod, name) in NAME_MAPPING:
                mod, name = NAME_MAPPING[(mod, name)]
            elif mod in IMPORT_MAPPING:
                mod = IMPORT_MAPPING[mod]
        qual = mod + "." + name
        if qual not in self.symbols:
            self.symbols[qual] = symbol(qual)
        return self.symbols[qual]

    def persistent_load(self, pid):
        if self.pids == "none":
            raise pickle.UnpicklingError("no persistent_load")
        return Pid(pid)


def render(x, depth=0):
    if depth > 200:
        raise RecursionError("too deep")
    d = depth + 1
    if x is None:
        return "None"
    if x is True:
        return "True"
    if x is False:
        return "False"
    t = type(x)
    if t is int:
        return str(x)
    if t is float:
        return "f" + struct.pack(">d", x).hex()
    if t is str:
        return "s" + x.encode("utf-8", "surrogatepass").hex()
    if t is bytes:
        return "b" + x.hex()
    if t is tuple:
        return "(" + ",".join(render(i, d) for i in x) + ")"
    if t is list:
        return "[" + ",".join(render(i, d) for i in x) + "]"
    if t is dict:
        return "{" + ",".join(render(k, d) + ":" + render(v, d) for k, v in x.items()) + "}"
    if isinstance(x, Pid):
        return "pid" + render(x.pid, d)
    if isinstance(x, type) and issubclass(x, SymBase):
        return "g:" + x._qual
    if isinstance(x, SymBase):
        s = x.kind + ":" + type(x)._qual + render(x.args, d)
        if x.items:
            s += ".items{" + ",".join(render(k, d) + ":" + render(v, d) for k, v in x.items) + "}"
        if x.built:
            s += ".state(" + render(x.state, d) + ")"
        return s
    raise TypeError("unrenderable " + t.__name__)


def reading(data, pids):
    proto = data[1] if len(data) > 1 and data[0] == 0x80 else 0
    try:
        u = SymbolicUnpickler(io.BytesIO(data), pids, proto)
        return render(u.load())
    except Exception as e:  # what CPython does with the stream is the record
        return "error: " + type(e).__name__


# --- vectors ------------------------------------------------------------------


def state_dict(tensors, metadata=True):
    sd = collections.OrderedDict()
    for k, v in tensors:
        sd[k] = v
    if metadata:
        sd._metadata = collections.OrderedDict([("", {"version": 1})])
    return sd


s0 = Storage(FloatStorage, "0", 4)
s1 = Storage(FloatStorage, "1", 6)
canonical = [
    ("torch-one-tensor", "zip", torch_pickle(state_dict([("w", Tensor(s0, 0, [4], [1]))]))),
    ("torch-one-tensor-dict", "zip", torch_pickle({"w": Tensor(Storage(FloatStorage, "0", 4), 0, [4], [1])})),
    ("torch-shared-storage", "zip", torch_pickle(state_dict([
        ("a", Tensor(s1, 0, [2, 3], [3, 1])),
        ("b", Tensor(s1, 2, [2], [3])),
        ("c", Tensor(Storage(LongStorage, "2", 1), 0, [], [])),
    ]))),
    ("torch-plain-dict", "zip", torch_pickle({"weight": Tensor(Storage(BFloat16Storage, "0", 8), 0, [2, 4], [4, 1]), "step": 3})),
    ("torch-v3-float8", "zip", torch_pickle({"q": Tensor(Storage(UntypedStorage, "0", 16), 0, [4, 4], [4, 1], dtype=float8_e4m3fn)})),
    ("torch-parameter", "zip", torch_pickle({"p": Parameter(Tensor(Storage(FloatStorage, "0", 2), 0, [2], [1]))})),
    ("torch-optimizer-state", "zip", torch_pickle({
        "state": {0: {"step": Tensor(Storage(FloatStorage, "0", 1), 0, [], []), "exp_avg": Tensor(Storage(FloatStorage, "1", 4), 0, [4], [1])}},
        "param_groups": [{"lr": 0.001, "betas": (0.9, 0.999), "eps": 1e-08, "weight_decay": 0.0, "amsgrad": False, "foreach": None, "params": [0]}],
    })),
    ("torch-rng-state", "zip", torch_pickle({
        "python": (3, tuple(range(5)), None),
        "numpy": ("MT19937", NDArray((4,), NPDtype("u4", "<"), bytes(range(16))), 2, 0, 0.0),
        "cpu": Tensor(Storage(ByteStorage, "0", 8), 0, [8], [1]),
    })),
    ("numpy-scalar", "none", plain({"best": NPScalar(NPDtype("f8", "<"), struct.pack("<d", 0.5))})),
    ("ints-at-every-width", "none", plain([0, 1, 255, 256, 65535, 65536, -1, -128, -129, -2**31, 2**31 - 1, 2**31, -2**31 - 1, 2**63, -2**63, 2**64, 10**40, -10**40])),
    ("floats", "none", plain([0.0, -0.0, 1.5, float("inf"), float("-inf"), float("nan"), 1e-300, 1e300])),
    ("strings", "none", plain(["", "a", "layer.0.weight", "café", "漢字", "\U0001f600", "x" * 300])),
    ("bytes-protocol-2", "none", plain([b"", b"abc", bytes(range(256))])),
    ("bytes-protocol-3", "none", plain([b"", b"abc", bytes(range(256))], protocol=3)),
    ("containers", "none", plain({"t0": (), "t1": (1,), "t2": (1, 2), "t3": (1, 2, 3), "t5": (1, 2, 3, 4, 5), "l": [[], [1], [1, 2]], "d": {}, "n": None, "b": [True, False]})),
    ("sets", "none", plain([set(), {1, 2, 3}, frozenset(), frozenset(["a"])])),
    ("bytearray-and-complex", "none", plain([bytearray(b"xy"), bytearray(), complex(1.5, -2.0)])),
    ("shared-references", "none", plain((lambda l: [l, l, {"k": l}])([1, 2]))),
    ("ordered-dict", "none", plain(collections.OrderedDict([("a", 1), ("b", [2, 3])]))),
    ("counter", "none", plain(collections.Counter({"a": 2, "b": 1}))),
    ("long-memo", "none", plain([str(i) for i in range(300)] + ["0"])),
]

# Legacy torch stream: magic number, protocol version, sys_info, the object,
# the storage keys, then each storage as an 8-byte little-endian element count
# and its bytes.
MAGIC = 0x1950A86A20F9469CFC6C
legacy_storage = Storage(FloatStorage, "140234", 3)
legacy_main = torch_pickle(state_dict([("w", Tensor(legacy_storage, 0, [3], [1]))]), pickler=LegacyPickler)
legacy = (plain(MAGIC) + plain(1001) + plain({"protocol_version": 1001, "little_endian": True, "type_sizes": {"short": 2, "int": 4, "long": 4}})
          + legacy_main + plain(["140234"]) + struct.pack("<q", 3) + struct.pack("<3f", 1.0, 2.0, 3.0))

hostile = [
    # Memo slot written twice: CPython reads ('a', 'b', 'b'); a reader that
    # keeps the first value reads ('a', 'b', 'a').
    ("re-put-memo-key", "none", b"\x80\x02X\x01\x00\x00\x00aq\x00X\x01\x00\x00\x00bq\x00h\x00\x87."),
    ("nul-in-global", "none", b"\x80\x02ccollections\x00x\nOrderedDict\nq\x00)Rq\x01."),
    ("text-int-in-binary-stream", "none", b"\x80\x02I01\n."),
    ("non-minimal-binint", "none", b"\x80\x02J\x05\x00\x00\x00."),
    ("non-minimal-long1", "none", b"\x80\x02\x8a\x02\x05\x00."),
    ("mark-tuple-for-two", "none", b"\x80\x02(K\x01K\x02tq\x00."),
    ("second-proto", "none", b"\x80\x02K\x01\x80\x02\x85q\x00."),
    ("junk-under-stop", "none", b"\x80\x02K\x01K\x02."),
    ("pop", "none", b"\x80\x02K\x01K\x020."),
    ("setitems-on-list", "none", b"\x80\x02]q\x00(K\x00K\x07u."),
    ("appends-on-dict", "none", b"\x80\x02}q\x00(K\x00K\x07e."),
    ("reduce-list-args", "none", b"\x80\x02c__builtin__\nset\nq\x00]q\x01]q\x02K\x01aaR."),
    ("protocol-4-opcode-in-protocol-2", "none", b"\x80\x02\x8c\x01a\x94."),
    ("missing-memo", "none", b"\x80\x02h\x05."),
    ("truncated", "none", b"\x80\x02]q\x00(K\x01"),
    ("odd-setitems", "none", b"\x80\x02}q\x00(K\x01u."),
    ("unhashable-key", "none", b"\x80\x02}q\x00]q\x01K\x01s."),
    ("persid-without-loader", "none", b"\x80\x02X\x01\x00\x00\x000q\x00Q."),
    ("duplicate-dict-key", "none", b"\x80\x02}q\x00(K\x01K\x02\x88K\x03u."),
]

out = []
for name, pids, data in canonical:
    out.append({"name": name, "pids": pids, "hex": data.hex(), "cpython": reading(data, pids), "conform": True})
out.append({"name": "legacy-stream", "pids": "legacy", "hex": legacy.hex(), "cpython": reading(legacy_main, "legacy"), "conform": True})
for name, pids, data in hostile:
    out.append({"name": name, "pids": pids, "hex": data.hex(), "cpython": reading(data, pids), "conform": False})

json.dump({"python": sys.version.split()[0], "vectors": out}, sys.stdout, indent=1)
sys.stdout.write("\n")
