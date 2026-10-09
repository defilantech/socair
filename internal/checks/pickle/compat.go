package pickle

import "strings"

// CPython's unpickler renames Python 2 modules and names to their Python 3
// homes before it imports them (Lib/_compat_pickle.py, applied by find_class
// when the stream's protocol is below 3; PyTorch's weights-only unpickler
// applies it at every protocol). A scanner that judges the spelled name
// misses what is imported: "cPickle.loads" is pickle.loads, and
// "__builtin__.reduce" is functools.reduce. These tables are that mapping.

var importMapping = map[string]string{
	"__builtin__": "builtins", "copy_reg": "copyreg", "Queue": "queue",
	"SocketServer": "socketserver", "ConfigParser": "configparser", "repr": "reprlib",
	"tkFileDialog": "tkinter.filedialog", "tkSimpleDialog": "tkinter.simpledialog",
	"tkColorChooser": "tkinter.colorchooser", "tkCommonDialog": "tkinter.commondialog",
	"Dialog": "tkinter.dialog", "Tkdnd": "tkinter.dnd", "tkFont": "tkinter.font",
	"tkMessageBox": "tkinter.messagebox", "ScrolledText": "tkinter.scrolledtext",
	"Tkconstants": "tkinter.constants", "ttk": "tkinter.ttk", "Tkinter": "tkinter",
	"markupbase": "_markupbase", "_winreg": "winreg", "thread": "_thread",
	"dummy_thread": "_dummy_thread", "dbhash": "dbm.bsd", "dumbdbm": "dbm.dumb",
	"dbm": "dbm.ndbm", "gdbm": "dbm.gnu", "xmlrpclib": "xmlrpc.client",
	"SimpleXMLRPCServer": "xmlrpc.server", "httplib": "http.client",
	"htmlentitydefs": "html.entities", "HTMLParser": "html.parser", "Cookie": "http.cookies",
	"cookielib": "http.cookiejar", "BaseHTTPServer": "http.server",
	"test.test_support": "test.support", "commands": "subprocess", "urlparse": "urllib.parse",
	"robotparser": "urllib.robotparser", "urllib2": "urllib.request", "anydbm": "dbm",
	"_abcoll": "collections.abc", "cPickle": "pickle", "_elementtree": "xml.etree.ElementTree",
	"FileDialog": "tkinter.filedialog", "SimpleDialog": "tkinter.simpledialog",
	"DocXMLRPCServer": "xmlrpc.server", "SimpleHTTPServer": "http.server",
	"UserDict": "collections", "UserList": "collections", "UserString": "collections",
	"whichdb": "dbm", "StringIO": "io", "cStringIO": "io",
}

// nameRenames are CPython's NAME_MAPPING: "old-module old-name new-module
// new-name".
var nameRenames = []string{
	"__builtin__ xrange builtins range", "__builtin__ reduce functools reduce",
	"__builtin__ intern sys intern", "__builtin__ unichr builtins chr",
	"__builtin__ unicode builtins str", "__builtin__ long builtins int",
	"__builtin__ basestring builtins str",
	"itertools izip builtins zip", "itertools imap builtins map",
	"itertools ifilter builtins filter", "itertools ifilterfalse itertools filterfalse",
	"itertools izip_longest itertools zip_longest",
	"UserDict IterableUserDict collections UserDict", "UserDict UserDict collections UserDict",
	"UserList UserList collections UserList", "UserString UserString collections UserString",
	"whichdb whichdb dbm whichdb", "_socket fromfd socket fromfd",
	"_multiprocessing Connection multiprocessing.connection Connection",
	"multiprocessing.process Process multiprocessing.context Process",
	"multiprocessing.forking Popen multiprocessing.popen_fork Popen",
	"urllib ContentTooShortError urllib.error ContentTooShortError",
	"urllib getproxies urllib.request getproxies", "urllib pathname2url urllib.request pathname2url",
	"urllib quote_plus urllib.parse quote_plus", "urllib quote urllib.parse quote",
	"urllib unquote_plus urllib.parse unquote_plus", "urllib unquote urllib.parse unquote",
	"urllib url2pathname urllib.request url2pathname", "urllib urlcleanup urllib.request urlcleanup",
	"urllib urlencode urllib.parse urlencode", "urllib urlopen urllib.request urlopen",
	"urllib urlretrieve urllib.request urlretrieve",
	"urllib2 HTTPError urllib.error HTTPError", "urllib2 URLError urllib.error URLError",
	"exceptions StandardError builtins Exception", "socket _socketobject socket SocketType",
}

var nameMapping = map[[2]string][2]string{}

// python2Exceptions are the exception names CPython maps from the Python 2
// "exceptions" module to builtins, and multiprocessingExceptions those it
// maps from multiprocessing to multiprocessing.context.
var (
	python2Exceptions = []string{"ArithmeticError", "AssertionError", "AttributeError", "BaseException",
		"BufferError", "BytesWarning", "DeprecationWarning", "EOFError", "EnvironmentError", "Exception",
		"FloatingPointError", "FutureWarning", "GeneratorExit", "IOError", "ImportError", "ImportWarning",
		"IndentationError", "IndexError", "KeyError", "KeyboardInterrupt", "LookupError", "MemoryError",
		"NameError", "NotImplementedError", "OSError", "OverflowError", "PendingDeprecationWarning",
		"ReferenceError", "RuntimeError", "RuntimeWarning", "StopIteration", "SyntaxError", "SyntaxWarning",
		"SystemError", "SystemExit", "TabError", "TypeError", "UnboundLocalError", "UnicodeDecodeError",
		"UnicodeEncodeError", "UnicodeError", "UnicodeTranslateError", "UnicodeWarning", "UserWarning",
		"ValueError", "Warning", "ZeroDivisionError"}
	multiprocessingExceptions = []string{"AuthenticationError", "BufferTooShort", "ProcessError", "TimeoutError"}
)

func init() {
	for _, r := range nameRenames {
		f := strings.Fields(r)
		nameMapping[[2]string{f[0], f[1]}] = [2]string{f[2], f[3]}
	}
	for _, e := range python2Exceptions {
		nameMapping[[2]string{"exceptions", e}] = [2]string{"builtins", e}
	}
	for _, e := range multiprocessingExceptions {
		nameMapping[[2]string{"multiprocessing", e}] = [2]string{"multiprocessing.context", e}
	}
}

// pyResolve is the module and name CPython's find_class imports for a global
// spelled mod.name, with fix_imports on.
func pyResolve(mod, name string) (string, string) {
	if m, ok := nameMapping[[2]string{mod, name}]; ok {
		return m[0], m[1]
	}
	if m, ok := importMapping[mod]; ok {
		return m, name
	}
	return mod, name
}
