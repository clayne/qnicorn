# Unicorn Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

import ctypes
import ctypes.util
import distutils.sysconfig
from functools import wraps
import pkg_resources
import inspect
import os.path
import sys
import weakref
import functools

from . import x86_const, arm64_const, qnicorn_const as qc

if not hasattr(sys.modules[__name__], "__file__"):
    __file__ = inspect.getfile(inspect.currentframe())

_python2 = sys.version_info[0] < 3
if _python2:
    range = xrange

_lib = { 'darwin': 'libqnicorn.dylib',
         'win32': 'qnicorn.dll',
         'cygwin': 'cygqnicorn.dll',
         'linux': 'libqnicorn.so',
         'linux2': 'libqnicorn.so' }


# Windows DLL in dependency order
_all_windows_dlls = (
    "libwinpthread-1.dll",
    "libgcc_s_seh-1.dll",
    "libgcc_s_dw2-1.dll",
)

_loaded_windows_dlls = set()

def _load_win_support(path):
    for dll in _all_windows_dlls:
        if dll in _loaded_windows_dlls:
            continue

        lib_file = os.path.join(path, dll)
        if ('/' not in path and '\\' not in path) or os.path.exists(lib_file):
            try:
                #print('Trying to load Windows library', lib_file)
                ctypes.cdll.LoadLibrary(lib_file)
                #print('SUCCESS')
                _loaded_windows_dlls.add(dll)
            except OSError as e:
                #print('FAIL to load %s' %lib_file, e)
                continue

# Initial attempt: load all dlls globally
if sys.platform in ('win32', 'cygwin'):
    _load_win_support('')

def _load_lib(path):
    try:
        if sys.platform in ('win32', 'cygwin'):
            _load_win_support(path)

        lib_file = os.path.join(path, _lib.get(sys.platform, 'libqnicorn.so'))
        dll = ctypes.cdll.LoadLibrary(lib_file)
        #print('SUCCESS')
        return dll
    except OSError as e:
        #print('FAIL to load %s' %lib_file, e)
        return None

_qc = None

# Loading attempts, in order
# - user-provided environment variable
# - pkg_resources can get us the path to the local libraries
# - we can get the path to the local libraries by parsing our filename
# - global load
# - python's lib directory
# - last-gasp attempt at some hardcoded paths on darwin and linux

_path_list = [os.getenv('LIBQNICORN_PATH', None),
              pkg_resources.resource_filename(__name__, 'lib'),
              os.path.join(os.path.split(__file__)[0], 'lib'),
              '',
              distutils.sysconfig.get_python_lib(),
              "/usr/local/lib/" if sys.platform == 'darwin' else '/usr/lib64',
              os.getenv('PATH', '')]

#print(_path_list)
#print("-" * 80)

for _path in _path_list:
    if _path is None: continue
    _qc = _load_lib(_path)
    if _qc is not None: break
else:
    raise ImportError("ERROR: fail to load the dynamic library.")

__version__ = "%u.%u.%u" % (qc.QC_VERSION_MAJOR, qc.QC_VERSION_MINOR, qc.QC_VERSION_EXTRA)

# setup all the function prototype
def _setup_prototype(lib, fname, restype, *argtypes):
    try:
        getattr(lib, fname).restype = restype
        getattr(lib, fname).argtypes = argtypes
    except AttributeError:
        raise ImportError("ERROR: Fail to setup some function prototypes. Make sure you have cleaned your unicorn1 installation.")

ucerr = ctypes.c_int
qc_mode = ctypes.c_int
qc_arch = ctypes.c_int
qc_engine = ctypes.c_void_p
qc_context = ctypes.c_void_p
qc_hook_h = ctypes.c_size_t

class _qc_mem_region(ctypes.Structure):
    _fields_ = [
        ("begin", ctypes.c_uint64),
        ("end",   ctypes.c_uint64),
        ("perms", ctypes.c_uint32),
    ]

class qc_tb(ctypes.Structure):
    """"TranslationBlock"""
    _fields_ = [
        ("pc", ctypes.c_uint64),
        ("icount", ctypes.c_uint16),
        ("size", ctypes.c_uint16)
    ]

_setup_prototype(_qc, "qc_version", ctypes.c_uint, ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int))
_setup_prototype(_qc, "qc_arch_supported", ctypes.c_bool, ctypes.c_int)
_setup_prototype(_qc, "qc_open", ucerr, ctypes.c_uint, ctypes.c_uint, ctypes.POINTER(qc_engine))
_setup_prototype(_qc, "qc_close", ucerr, qc_engine)
_setup_prototype(_qc, "qc_strerror", ctypes.c_char_p, ucerr)
_setup_prototype(_qc, "qc_errno", ucerr, qc_engine)
_setup_prototype(_qc, "qc_reg_read", ucerr, qc_engine, ctypes.c_int, ctypes.c_void_p)
_setup_prototype(_qc, "qc_reg_write", ucerr, qc_engine, ctypes.c_int, ctypes.c_void_p)
_setup_prototype(_qc, "qc_mem_read", ucerr, qc_engine, ctypes.c_uint64, ctypes.POINTER(ctypes.c_char), ctypes.c_size_t)
_setup_prototype(_qc, "qc_mem_write", ucerr, qc_engine, ctypes.c_uint64, ctypes.POINTER(ctypes.c_char), ctypes.c_size_t)
_setup_prototype(_qc, "qc_emu_start", ucerr, qc_engine, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_size_t)
_setup_prototype(_qc, "qc_emu_stop", ucerr, qc_engine)
_setup_prototype(_qc, "qc_hook_del", ucerr, qc_engine, qc_hook_h)
_setup_prototype(_qc, "qc_mmio_map", ucerr, qc_engine, ctypes.c_uint64, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
_setup_prototype(_qc, "qc_mem_map", ucerr, qc_engine, ctypes.c_uint64, ctypes.c_size_t, ctypes.c_uint32)
_setup_prototype(_qc, "qc_mem_map_ptr", ucerr, qc_engine, ctypes.c_uint64, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_void_p)
_setup_prototype(_qc, "qc_mem_unmap", ucerr, qc_engine, ctypes.c_uint64, ctypes.c_size_t)
_setup_prototype(_qc, "qc_mem_protect", ucerr, qc_engine, ctypes.c_uint64, ctypes.c_size_t, ctypes.c_uint32)
_setup_prototype(_qc, "qc_query", ucerr, qc_engine, ctypes.c_uint32, ctypes.POINTER(ctypes.c_size_t))
_setup_prototype(_qc, "qc_context_alloc", ucerr, qc_engine, ctypes.POINTER(qc_context))
_setup_prototype(_qc, "qc_free", ucerr, ctypes.c_void_p)
_setup_prototype(_qc, "qc_context_save", ucerr, qc_engine, qc_context)
_setup_prototype(_qc, "qc_context_restore", ucerr, qc_engine, qc_context)
_setup_prototype(_qc, "qc_context_size", ctypes.c_size_t, qc_engine)
_setup_prototype(_qc, "qc_context_reg_read", ucerr, qc_context, ctypes.c_int, ctypes.c_void_p)
_setup_prototype(_qc, "qc_context_reg_write", ucerr, qc_context, ctypes.c_int, ctypes.c_void_p)
_setup_prototype(_qc, "qc_context_free", ucerr, qc_context)
_setup_prototype(_qc, "qc_mem_regions", ucerr, qc_engine, ctypes.POINTER(ctypes.POINTER(_qc_mem_region)), ctypes.POINTER(ctypes.c_uint32))
# https://bugs.python.org/issue42880
_setup_prototype(_qc, "qc_hook_add", ucerr, qc_engine, ctypes.POINTER(qc_hook_h), ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint64)
_setup_prototype(_qc, "qc_ctl", ucerr, qc_engine, ctypes.c_int)

QC_HOOK_CODE_CB = ctypes.CFUNCTYPE(None, qc_engine, ctypes.c_uint64, ctypes.c_size_t, ctypes.c_void_p)
QC_HOOK_INSN_INVALID_CB = ctypes.CFUNCTYPE(ctypes.c_bool, qc_engine, ctypes.c_void_p)
QC_HOOK_MEM_INVALID_CB = ctypes.CFUNCTYPE(
    ctypes.c_bool, qc_engine, ctypes.c_int,
    ctypes.c_uint64, ctypes.c_int, ctypes.c_int64, ctypes.c_void_p
)
QC_HOOK_MEM_ACCESS_CB = ctypes.CFUNCTYPE(
    None, qc_engine, ctypes.c_int,
    ctypes.c_uint64, ctypes.c_int, ctypes.c_int64, ctypes.c_void_p
)
QC_HOOK_INTR_CB = ctypes.CFUNCTYPE(
    None, qc_engine, ctypes.c_uint32, ctypes.c_void_p
)
QC_HOOK_INSN_IN_CB = ctypes.CFUNCTYPE(
    ctypes.c_uint32, qc_engine, ctypes.c_uint32, ctypes.c_int, ctypes.c_void_p
)
QC_HOOK_INSN_OUT_CB = ctypes.CFUNCTYPE(
    None, qc_engine, ctypes.c_uint32,
    ctypes.c_int, ctypes.c_uint32, ctypes.c_void_p
)
QC_HOOK_INSN_SYSCALL_CB = ctypes.CFUNCTYPE(None, qc_engine, ctypes.c_void_p)
QC_MMIO_READ_CB = ctypes.CFUNCTYPE(
    ctypes.c_uint64, qc_engine, ctypes.c_uint64, ctypes.c_int, ctypes.c_void_p
)
QC_MMIO_WRITE_CB = ctypes.CFUNCTYPE(
    None, qc_engine, ctypes.c_uint64, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p
)
QC_HOOK_EDGE_GEN_CB = ctypes.CFUNCTYPE(
    None, qc_engine, ctypes.POINTER(qc_tb), ctypes.POINTER(qc_tb), ctypes.c_void_p
)
QC_HOOK_TCG_OPCODE_CB = ctypes.CFUNCTYPE(
    None, qc_engine, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p
)

# access to error code via @errno of QcError
class QcError(Exception):
    def __init__(self, errno):
        self.errno = errno

    def __str__(self):
        return _qc.qc_strerror(self.errno).decode('ascii')

# return the core's version
def qc_version():
    major = ctypes.c_int()
    minor = ctypes.c_int()
    combined = _qc.qc_version(ctypes.byref(major), ctypes.byref(minor))
    return (major.value, minor.value, combined)


# return the binding's version
def version_bind():
    return (
        qc.QC_API_MAJOR, qc.QC_API_MINOR,
        (qc.QC_API_MAJOR << 8) + qc.QC_API_MINOR,
    )


# check to see if this engine supports a particular arch
def qc_arch_supported(query):
    return _qc.qc_arch_supported(query)

# qc_reg_read/write and qc_context_reg_read/write.
def reg_read(reg_read_func, arch, reg_id, opt=None):
    if arch == qc.QC_ARCH_X86:
        if reg_id in [x86_const.QC_X86_REG_IDTR, x86_const.QC_X86_REG_GDTR, x86_const.QC_X86_REG_LDTR, x86_const.QC_X86_REG_TR]:
            reg = qc_x86_mmr()
            status = reg_read_func(reg_id, ctypes.byref(reg))
            if status != qc.QC_ERR_OK:
                raise QcError(status)
            return reg.selector, reg.base, reg.limit, reg.flags
        if reg_id in range(x86_const.QC_X86_REG_FP0, x86_const.QC_X86_REG_FP0+8):
            reg = qc_x86_float80()
            status = reg_read_func(reg_id, ctypes.byref(reg))
            if status != qc.QC_ERR_OK:
                raise QcError(status)
            return reg.mantissa, reg.exponent
        if reg_id in range(x86_const.QC_X86_REG_XMM0, x86_const.QC_X86_REG_XMM0+8):
            reg = qc_x86_xmm()
            status = reg_read_func(reg_id, ctypes.byref(reg))
            if status != qc.QC_ERR_OK:
                raise QcError(status)
            return reg.low_qword | (reg.high_qword << 64)
        if reg_id in range(x86_const.QC_X86_REG_YMM0, x86_const.QC_X86_REG_YMM0+16):
            reg = qc_x86_ymm()
            status = reg_read_func(reg_id, ctypes.byref(reg))
            if status != qc.QC_ERR_OK:
                raise QcError(status)
            return reg.first_qword | (reg.second_qword << 64) | (reg.third_qword << 128) | (reg.fourth_qword << 192)
        if reg_id is x86_const.QC_X86_REG_MSR:
            if opt is None:
                raise QcError(qc.QC_ERR_ARG)
            reg = qc_x86_msr()
            reg.rid = opt
            status = reg_read_func(reg_id, ctypes.byref(reg))
            if status != qc.QC_ERR_OK:
                raise QcError(status)
            return reg.value

    if arch == qc.QC_ARCH_ARM64:
        if reg_id in range(arm64_const.QC_ARM64_REG_Q0, arm64_const.QC_ARM64_REG_Q31+1) or range(arm64_const.QC_ARM64_REG_V0, arm64_const.QC_ARM64_REG_V31+1):
            reg = qc_arm64_neon128()
            status = reg_read_func(reg_id, ctypes.byref(reg))
            if status != qc.QC_ERR_OK:
                raise QcError(status)
            return reg.low_qword | (reg.high_qword << 64)

    # read to 64bit number to be safe
    reg = ctypes.c_uint64(0)
    status = reg_read_func(reg_id, ctypes.byref(reg))
    if status != qc.QC_ERR_OK:
        raise QcError(status)
    return reg.value

def reg_write(reg_write_func, arch, reg_id, value):
    reg = None

    if arch == qc.QC_ARCH_X86:
        if reg_id in [x86_const.QC_X86_REG_IDTR, x86_const.QC_X86_REG_GDTR, x86_const.QC_X86_REG_LDTR, x86_const.QC_X86_REG_TR]:
            assert isinstance(value, tuple) and len(value) == 4
            reg = qc_x86_mmr()
            reg.selector = value[0]
            reg.base = value[1]
            reg.limit = value[2]
            reg.flags = value[3]
        if reg_id in range(x86_const.QC_X86_REG_FP0, x86_const.QC_X86_REG_FP0+8):
            reg = qc_x86_float80()
            reg.mantissa = value[0]
            reg.exponent = value[1]
        if reg_id in range(x86_const.QC_X86_REG_XMM0, x86_const.QC_X86_REG_XMM0+8):
            reg = qc_x86_xmm()
            reg.low_qword = value & 0xffffffffffffffff
            reg.high_qword = value >> 64
        if reg_id in range(x86_const.QC_X86_REG_YMM0, x86_const.QC_X86_REG_YMM0+16):
            reg = qc_x86_ymm()
            reg.first_qword = value & 0xffffffffffffffff
            reg.second_qword = (value >> 64) & 0xffffffffffffffff
            reg.third_qword = (value >> 128) & 0xffffffffffffffff
            reg.fourth_qword = value >> 192
        if reg_id is x86_const.QC_X86_REG_MSR:
            reg = qc_x86_msr()
            reg.rid = value[0]
            reg.value = value[1]

    if arch == qc.QC_ARCH_ARM64:
        if reg_id in range(arm64_const.QC_ARM64_REG_Q0, arm64_const.QC_ARM64_REG_Q31+1) or range(arm64_const.QC_ARM64_REG_V0, arm64_const.QC_ARM64_REG_V31+1):
            reg = qc_arm64_neon128()
            reg.low_qword = value & 0xffffffffffffffff
            reg.high_qword = value >> 64

    if reg is None:
        # convert to 64bit number to be safe
        reg = ctypes.c_uint64(value)

    status = reg_write_func(reg_id, ctypes.byref(reg))
    if status != qc.QC_ERR_OK:
        raise QcError(status)

    return

def _catch_hook_exception(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        """Catches exceptions raised in hook functions.

        If an exception is raised, it is saved to the Qc object and a call to stop
        emulation is issued.
        """
        try:
            return func(self, *args, **kwargs)
        except Exception as e:
            # If multiple hooks raise exceptions, just use the first one
            if self._hook_exception is None:
                self._hook_exception = e

            self.emu_stop()

    return wrapper



class qc_x86_mmr(ctypes.Structure):
    """Memory-Management Register for instructions IDTR, GDTR, LDTR, TR."""
    _fields_ = [
        ("selector", ctypes.c_uint16),  # not used by GDTR and IDTR
        ("base", ctypes.c_uint64),      # handle 32 or 64 bit CPUs
        ("limit", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),     # not used by GDTR and IDTR
    ]

class qc_x86_msr(ctypes.Structure):
    _fields_ = [
        ("rid", ctypes.c_uint32),
        ("value", ctypes.c_uint64),
    ]

class qc_x86_float80(ctypes.Structure):
    """Float80"""
    _fields_ = [
        ("mantissa", ctypes.c_uint64),
        ("exponent", ctypes.c_uint16),
    ]


class qc_x86_xmm(ctypes.Structure):
    """128-bit xmm register"""
    _fields_ = [
        ("low_qword", ctypes.c_uint64),
        ("high_qword", ctypes.c_uint64),
    ]

class qc_x86_ymm(ctypes.Structure):
    """256-bit ymm register"""
    _fields_ = [
        ("first_qword", ctypes.c_uint64),
        ("second_qword", ctypes.c_uint64),
        ("third_qword", ctypes.c_uint64),
        ("fourth_qword", ctypes.c_uint64),
    ]

class qc_arm64_neon128(ctypes.Structure):
    """128-bit neon register"""
    _fields_ = [
        ("low_qword", ctypes.c_uint64),
        ("high_qword", ctypes.c_uint64),
    ]

# Subclassing ref to allow property assignment.
class QcRef(weakref.ref):
    pass

# This class tracks Uc instance destruction and releases handles.
class QcCleanupManager(object):
    def __init__(self):
        self._refs = {}

    def register(self, qc):
        ref = QcRef(qc, self._finalizer)
        ref._qch = qc._qch
        ref._class = qc.__class__
        self._refs[id(ref)] = ref

    def _finalizer(self, ref):
        # note: this method must be completely self-contained and cannot have any references
        # to anything else in this module.
        #
        # This is because it may be called late in the Python interpreter's shutdown phase, at
        # which point the module's variables may already have been deinitialized and set to None.
        #
        # Not respecting that can lead to errors such as:
        #     Exception AttributeError:
        #       "'NoneType' object has no attribute 'release_handle'"
        #       in <bound method QcCleanupManager._finalizer of
        #       <unicorn.unicorn.QcCleanupManager object at 0x7f0bb83e4310>> ignored
        #
        # For that reason, we do not try to access the `Uc` class directly here but instead use
        # the saved `._class` reference.
        del self._refs[id(ref)]
        ref._class.release_handle(ref._qch)

class Qc(object):
    _cleanup = QcCleanupManager()

    def __init__(self, arch, mode):
        # verify version compatibility with the core before doing anything
        (major, minor, _combined) = qc_version()
        # print("core version =", qc_version())
        # print("binding version =", qc.QC_API_MAJOR, qc.QC_API_MINOR)
        if major != qc.QC_API_MAJOR or minor != qc.QC_API_MINOR:
            self._qch = None
            # our binding version is different from the core's API version
            raise QcError(qc.QC_ERR_VERSION)

        self._arch, self._mode = arch, mode
        self._qch = ctypes.c_void_p()
        status = _qc.qc_open(arch, mode, ctypes.byref(self._qch))
        if status != qc.QC_ERR_OK:
            self._qch = None
            raise QcError(status)
        # internal mapping table to save callback & userdata
        self._callbacks = {}
        self._ctype_cbs = []
        self._callback_count = 0
        self._cleanup.register(self)
        self._hook_exception = None  # The exception raised in a hook

    @staticmethod
    def release_handle(uch):
        if uch:
            try:
                status = _qc.qc_close(uch)
                if status != qc.QC_ERR_OK:
                    raise QcError(status)
            except:  # _qc might be pulled from under our feet
                pass

    # emulate from @begin, and stop when reaching address @until
    def emu_start(self, begin, until, timeout=0, count=0):
        status = _qc.qc_emu_start(self._qch, begin, until, timeout, count)
        if status != qc.QC_ERR_OK:
            raise QcError(status)

        if self._hook_exception is not None:
            raise self._hook_exception

    # stop emulation
    def emu_stop(self):
        status = _qc.qc_emu_stop(self._qch)
        if status != qc.QC_ERR_OK:
            raise QcError(status)

    # return the value of a register
    def reg_read(self, reg_id, opt=None):
        return reg_read(functools.partial(_qc.qc_reg_read, self._qch), self._arch, reg_id, opt)

    # write to a register
    def reg_write(self, reg_id, value):
        return reg_write(functools.partial(_qc.qc_reg_write, self._qch), self._arch, reg_id, value)

    # read from MSR - X86 only
    def msr_read(self, msr_id):
        return self.reg_read(x86_const.QC_X86_REG_MSR, msr_id)

    # write to MSR - X86 only
    def msr_write(self, msr_id, value):
        return self.reg_write(x86_const.QC_X86_REG_MSR, (msr_id, value))

    # read data from memory
    def mem_read(self, address, size):
        data = ctypes.create_string_buffer(size)
        status = _qc.qc_mem_read(self._qch, address, data, size)
        if status != qc.QC_ERR_OK:
            raise QcError(status)
        return bytearray(data)

    # write to memory
    def mem_write(self, address, data):
        status = _qc.qc_mem_write(self._qch, address, data, len(data))
        if status != qc.QC_ERR_OK:
            raise QcError(status)

    def _mmio_map_read_cb(self, handle, offset, size, user_data):
        (cb, data) = self._callbacks[user_data]
        return cb(self, offset, size, data)

    def _mmio_map_write_cb(self, handle, offset, size, value, user_data):
        (cb, data) = self._callbacks[user_data]
        cb(self, offset, size, value, data)

    def mmio_map(self, address, size, read_cb, user_data_read, write_cb, user_data_write):
        internal_read_cb = ctypes.cast(QC_MMIO_READ_CB(self._mmio_map_read_cb), QC_MMIO_READ_CB)
        internal_write_cb = ctypes.cast(QC_MMIO_WRITE_CB(self._mmio_map_write_cb), QC_MMIO_WRITE_CB)

        self._callback_count += 1
        self._callbacks[self._callback_count] = (read_cb, user_data_read)
        read_count = self._callback_count
        self._callback_count += 1
        self._callbacks[self._callback_count] = (write_cb, user_data_write)
        write_count = self._callback_count

        status = _qc.qc_mmio_map(self._qch, address, size, internal_read_cb, read_count, internal_write_cb, write_count)
        if status != qc.QC_ERR_OK:
            raise QcError(status)
        
        # https://docs.python.org/3/library/ctypes.html#callback-functions
        self._ctype_cbs.append(internal_read_cb)
        self._ctype_cbs.append(internal_write_cb)

    # map a range of memory
    def mem_map(self, address, size, perms=qc.QC_PROT_ALL):
        status = _qc.qc_mem_map(self._qch, address, size, perms)
        if status != qc.QC_ERR_OK:
            raise QcError(status)

    # map a range of memory from a raw host memory address
    def mem_map_ptr(self, address, size, perms, ptr):
        status = _qc.qc_mem_map_ptr(self._qch, address, size, perms, ptr)
        if status != qc.QC_ERR_OK:
            raise QcError(status)

    # unmap a range of memory
    def mem_unmap(self, address, size):
        status = _qc.qc_mem_unmap(self._qch, address, size)
        if status != qc.QC_ERR_OK:
            raise QcError(status)

    # protect a range of memory
    def mem_protect(self, address, size, perms=qc.QC_PROT_ALL):
        status = _qc.qc_mem_protect(self._qch, address, size, perms)
        if status != qc.QC_ERR_OK:
            raise QcError(status)

    # return CPU mode at runtime
    def query(self, query_mode):
        result = ctypes.c_size_t(0)
        status = _qc.qc_query(self._qch, query_mode, ctypes.byref(result))
        if status != qc.QC_ERR_OK:
            raise QcError(status)
        return result.value

    @_catch_hook_exception
    def _hook_tcg_op_cb(self, handle, address, arg1, arg2, user_data):
        (cb, data) = self._callbacks[user_data]
        cb(self, address, arg1, arg2, user_data)

    @_catch_hook_exception
    def _hook_edge_gen_cb(self, handle, cur, prev, user_data):
        (cb, data) = self._callbacks[user_data]
        cb(self, cur.contents, prev.contents, user_data)

    @_catch_hook_exception
    def _hookcode_cb(self, handle, address, size, user_data):
        # call user's callback with self object
        (cb, data) = self._callbacks[user_data]
        cb(self, address, size, data)

    @_catch_hook_exception
    def _hook_mem_invalid_cb(self, handle, access, address, size, value, user_data):
        # call user's callback with self object
        (cb, data) = self._callbacks[user_data]
        return cb(self, access, address, size, value, data)

    @_catch_hook_exception
    def _hook_mem_access_cb(self, handle, access, address, size, value, user_data):
        # call user's callback with self object
        (cb, data) = self._callbacks[user_data]
        cb(self, access, address, size, value, data)

    @_catch_hook_exception
    def _hook_intr_cb(self, handle, intno, user_data):
        # call user's callback with self object
        (cb, data) = self._callbacks[user_data]
        cb(self, intno, data)

    @_catch_hook_exception
    def _hook_insn_invalid_cb(self, handle, user_data):
        # call user's callback with self object
        (cb, data) = self._callbacks[user_data]
        return cb(self, data)

    @_catch_hook_exception
    def _hook_insn_in_cb(self, handle, port, size, user_data):
        # call user's callback with self object
        (cb, data) = self._callbacks[user_data]
        return cb(self, port, size, data)

    @_catch_hook_exception
    def _hook_insn_out_cb(self, handle, port, size, value, user_data):
        # call user's callback with self object
        (cb, data) = self._callbacks[user_data]
        cb(self, port, size, value, data)

    @_catch_hook_exception
    def _hook_insn_syscall_cb(self, handle, user_data):
        # call user's callback with self object
        (cb, data) = self._callbacks[user_data]
        cb(self, data)

    def ctl(self, control, *args):
        status = _qc.qc_ctl(self._qch, control, *args)
        if status != qc.QC_ERR_OK:
            raise QcError(status)
        return status

    def __ctl(self, ctl, nr, rw):
        return ctl | (nr << 26) | (rw << 30)

    def __ctl_r(self, ctl, nr):
        return self.__ctl(ctl, nr, qc.QC_CTL_IO_READ)
    
    def __ctl_w(self, ctl, nr):
        return self.__ctl(ctl, nr, qc.QC_CTL_IO_WRITE)
    
    def __ctl_rw(self, ctl, nr):
        return self.__ctl(ctl, nr, qc.QC_CTL_IO_READ_WRITE) 

    def __ctl_r_1_arg(self, ctl, ctp):
        arg = ctp()
        self.ctl(self.__ctl_r(ctl, 1), ctypes.byref(arg))
        return arg.value

    def __ctl_w_1_arg(self, ctl, val, ctp):
        arg = ctp(val)
        self.ctl(self.__ctl_w(ctl, 1), arg)
    
    def __ctl_rw_1_1_arg(self, ctl, val, ctp1, ctp2):
        arg1 = ctp1(val)
        arg2 = ctp2()
        self.ctl(self.__ctl_rw(ctl, 2), arg1, ctypes.byref(arg2))
        return arg2

    def ctl_get_mode(self):
        return self.__ctl_r_1_arg(qc.QC_CTL_QC_MODE, ctypes.c_int)

    def ctl_get_page_size(self):
        return self.__ctl_r_1_arg(qc.QC_CTL_QC_PAGE_SIZE, ctypes.c_uint32)
    
    def ctl_set_page_size(self, val):
        self.__ctl_w_1_arg(qc.QC_CTL_QC_PAGE_SIZE, val, ctypes.c_uint32)

    def ctl_get_arch(self):
        return self.__ctl_r_1_arg(qc.QC_CTL_QC_ARCH, ctypes.c_int)

    def ctl_get_timeout(self):
        return self.__ctl_r_1_arg(qc.QC_CTL_QC_TIMEOUT, ctypes.c_uint64)
    
    def ctl_exits_enabled(self, val):
        self.__ctl_w_1_arg(qc.QC_CTL_QC_USE_EXITS, val, ctypes.c_int)
    
    def ctl_get_exits_cnt(self):
        return self.__ctl_r_1_arg(qc.QC_CTL_QC_EXITS_CNT, ctypes.c_size_t)

    def ctl_get_exits(self):
        l = self.ctl_get_exits_cnt()
        arr = (ctypes.c_uint64 * l)()
        self.ctl(self.__ctl_r(qc.QC_CTL_QC_EXITS, 2), ctypes.cast(arr, ctypes.c_void_p), ctypes.c_size_t(l))
        return [i for i in arr]

    def ctl_set_exits(self, exits):
        arr = (ctypes.c_uint64 * len(exits))()
        for idx, exit in enumerate(exits):
            arr[idx] = exit
        self.ctl(self.__ctl_w(qc.QC_CTL_QC_EXITS, 2), ctypes.cast(arr, ctypes.c_void_p), ctypes.c_size_t(len(exits)))

    def ctl_get_cpu_model(self):
        return self.__ctl_r_1_arg(qc.QC_CTL_CPU_MODEL, ctypes.c_int)
    
    def ctl_set_cpu_model(self, val):
        self.__ctl_w_1_arg(qc.QC_CTL_CPU_MODEL, val, ctypes.c_int)

    def ctl_remove_cache(self, addr):
        self.__ctl_w_1_arg(qc.QC_CTL_TB_REMOVE_CACHE, addr, ctypes.c_uint64)

    def ctl_request_cache(self, addr):
        return self.__ctl_rw_1_1_arg(qc.QC_CTL_TB_REQUEST_CACHE, addr, ctypes.c_uint64, qc_tb)

    # add a hook
    def hook_add(self, htype, callback, user_data=None, begin=1, end=0, arg1=0, arg2=0):
        _h2 = qc_hook_h()

        # save callback & user_data
        self._callback_count += 1
        self._callbacks[self._callback_count] = (callback, user_data)
        cb = None

        if htype == qc.QC_HOOK_INSN:
            insn = ctypes.c_int(arg1)
            if arg1 == x86_const.QC_X86_INS_IN:  # IN instruction
                cb = ctypes.cast(QC_HOOK_INSN_IN_CB(self._hook_insn_in_cb), QC_HOOK_INSN_IN_CB)
            if arg1 == x86_const.QC_X86_INS_OUT:  # OUT instruction
                cb = ctypes.cast(QC_HOOK_INSN_OUT_CB(self._hook_insn_out_cb), QC_HOOK_INSN_OUT_CB)
            if arg1 in (x86_const.QC_X86_INS_SYSCALL, x86_const.QC_X86_INS_SYSENTER):  # SYSCALL/SYSENTER instruction
                cb = ctypes.cast(QC_HOOK_INSN_SYSCALL_CB(self._hook_insn_syscall_cb), QC_HOOK_INSN_SYSCALL_CB)
            status = _qc.qc_hook_add(
                self._qch, ctypes.byref(_h2), htype, cb,
                ctypes.cast(self._callback_count, ctypes.c_void_p),
                ctypes.c_uint64(begin), ctypes.c_uint64(end), insn
            )
        elif htype == qc.QC_HOOK_TCG_OPCODE:
            opcode = ctypes.c_int(arg1)
            flags = ctypes.c_int(arg2)

            status = _qc.qc_hook_add(
                self._qch, ctypes.byref(_h2), htype, ctypes.cast(QC_HOOK_TCG_OPCODE_CB(self._hook_tcg_op_cb), QC_HOOK_TCG_OPCODE_CB),
                ctypes.cast(self._callback_count, ctypes.c_void_p),
                ctypes.c_uint64(begin), ctypes.c_uint64(end), opcode, flags
            )
        elif htype == qc.QC_HOOK_INTR:
            cb = ctypes.cast(QC_HOOK_INTR_CB(self._hook_intr_cb), QC_HOOK_INTR_CB)
            status = _qc.qc_hook_add(
                self._qch, ctypes.byref(_h2), htype, cb,
                ctypes.cast(self._callback_count, ctypes.c_void_p),
                ctypes.c_uint64(begin), ctypes.c_uint64(end)
            )
        elif htype == qc.QC_HOOK_INSN_INVALID:
            cb = ctypes.cast(QC_HOOK_INSN_INVALID_CB(self._hook_insn_invalid_cb), QC_HOOK_INSN_INVALID_CB)
            status = _qc.qc_hook_add(
                self._qch, ctypes.byref(_h2), htype, cb,
                ctypes.cast(self._callback_count, ctypes.c_void_p),
                ctypes.c_uint64(begin), ctypes.c_uint64(end)
            )
        elif htype == qc.QC_HOOK_EDGE_GENERATED:
            cb = ctypes.cast(QC_HOOK_EDGE_GEN_CB(self._hook_edge_gen_cb), QC_HOOK_EDGE_GEN_CB)
            status = _qc.qc_hook_add(
                self._qch, ctypes.byref(_h2), htype, cb,
                ctypes.cast(self._callback_count, ctypes.c_void_p),
                ctypes.c_uint64(begin), ctypes.c_uint64(end)
            )
        else:
            if htype in (qc.QC_HOOK_BLOCK, qc.QC_HOOK_CODE):
                # set callback with wrapper, so it can be called
                # with this object as param
                cb = ctypes.cast(QC_HOOK_CODE_CB(self._hookcode_cb), QC_HOOK_CODE_CB)
                status = _qc.qc_hook_add(
                    self._qch, ctypes.byref(_h2), htype, cb,
                    ctypes.cast(self._callback_count, ctypes.c_void_p),
                    ctypes.c_uint64(begin), ctypes.c_uint64(end)
                )
            elif htype & (qc.QC_HOOK_MEM_READ_UNMAPPED |
                          qc.QC_HOOK_MEM_WRITE_UNMAPPED |
                          qc.QC_HOOK_MEM_FETCH_UNMAPPED |
                          qc.QC_HOOK_MEM_READ_PROT |
                          qc.QC_HOOK_MEM_WRITE_PROT |
                          qc.QC_HOOK_MEM_FETCH_PROT):
                cb = ctypes.cast(QC_HOOK_MEM_INVALID_CB(self._hook_mem_invalid_cb), QC_HOOK_MEM_INVALID_CB)
                status = _qc.qc_hook_add(
                    self._qch, ctypes.byref(_h2), htype, cb,
                    ctypes.cast(self._callback_count, ctypes.c_void_p),
                    ctypes.c_uint64(begin), ctypes.c_uint64(end)
                )
            else:
                cb = ctypes.cast(QC_HOOK_MEM_ACCESS_CB(self._hook_mem_access_cb), QC_HOOK_MEM_ACCESS_CB)
                status = _qc.qc_hook_add(
                    self._qch, ctypes.byref(_h2), htype, cb,
                    ctypes.cast(self._callback_count, ctypes.c_void_p),
                    ctypes.c_uint64(begin), ctypes.c_uint64(end)
                )

        # save the ctype function so gc will leave it alone.
        self._ctype_cbs.append(cb)

        if status != qc.QC_ERR_OK:
            raise QcError(status)

        return _h2.value

    # delete a hook
    def hook_del(self, h):
        _h = qc_hook_h(h)
        status = _qc.qc_hook_del(self._qch, _h)
        if status != qc.QC_ERR_OK:
            raise QcError(status)
        h = 0

    def context_save(self):
        context = QcContext(self._qch, self._arch, self._mode)
        status = _qc.qc_context_save(self._qch, context.context)
        if status != qc.QC_ERR_OK:
            raise QcError(status)

        return context

    def context_update(self, context):
        status = _qc.qc_context_save(self._qch, context.context)
        if status != qc.QC_ERR_OK:
            raise QcError(status)

    def context_restore(self, context):
        status = _qc.qc_context_restore(self._qch, context.context)
        if status != qc.QC_ERR_OK:
            raise QcError(status)

    # this returns a generator of regions in the form (begin, end, perms)
    def mem_regions(self):
        regions = ctypes.POINTER(_qc_mem_region)()
        count = ctypes.c_uint32()
        status = _qc.qc_mem_regions(self._qch, ctypes.byref(regions), ctypes.byref(count))
        if status != qc.QC_ERR_OK:
            raise QcError(status)

        try:
            for i in range(count.value):
                yield (regions[i].begin, regions[i].end, regions[i].perms)
        finally:
            _qc.qc_free(regions)


class QcContext:
    def __init__(self, h, arch, mode):
        self._context = qc_context()
        self._size = _qc.qc_context_size(h)
        self._to_free = True
        status = _qc.qc_context_alloc(h, ctypes.byref(self._context))
        if status != qc.QC_ERR_OK:
            raise QcError(status)
        self._arch = arch
        self._mode = mode

    @property
    def context(self):
        return self._context

    @property
    def size(self):
        return self._size

    @property
    def arch(self):
        return self._arch
    
    @property
    def mode(self):
        return self._mode

    # return the value of a register
    def reg_read(self, reg_id, opt=None):
        return reg_read(functools.partial(_qc.qc_context_reg_read, self._context), self.arch, reg_id, opt)

    # write to a register
    def reg_write(self, reg_id, value):
        return reg_write(functools.partial(_qc.qc_context_reg_write, self._context), self.arch, reg_id, value)

    # Make QcContext picklable
    def __getstate__(self):
        return (bytes(self), self.size, self.arch, self.mode)

    def __setstate__(self, state):
        self._size = state[1]
        self._context = ctypes.cast(ctypes.create_string_buffer(state[0], self._size), qc_context)
        # __init__ won'e be invoked, so we are safe to set it here.
        self._to_free = False
        self._arch = state[2]
        self._mode = state[3]

    def __bytes__(self):
        return ctypes.string_at(self.context, self.size)

    def __del__(self):
        # We need this property since we shouldn't free it if the object is constructed from pickled bytes.
        if self._to_free:
            _qc.qc_context_free(self._context)


# print out debugging info
def debug():
    archs = {
        "arm": qc.QC_ARCH_ARM,
        "arm64": qc.QC_ARCH_ARM64,
        "mips": qc.QC_ARCH_MIPS,
        "sparc": qc.QC_ARCH_SPARC,
        "m68k": qc.QC_ARCH_M68K,
        "x86": qc.QC_ARCH_X86,
        "riscv": qc.QC_ARCH_RISCV,
        "ppc": qc.QC_ARCH_PPC,
    }

    all_archs = ""
    keys = archs.keys()
    for k in sorted(keys):
        if qc_arch_supported(archs[k]):
            all_archs += "-%s" % k

    major, minor, _combined = qc_version()

    return "python-%s-c%u.%u-b%u.%u" % (
        all_archs, major, minor, qc.QC_API_MAJOR, qc.QC_API_MINOR
    )


# For Unicorn compatibility
# To be removed in the future
Uc = Qc
uc_version = qc_version
uc_arch_supported = qc_arch_supported
uc_tb = qc_tb
UcError = QcError
UcContect = QcContext
uc_x86_mmr = qc_x86_mmr
uc_x86_msr = qc_x86_msr
uc_x86_float80 = qc_x86_float80
uc_x86_xmm = qc_x86_xmm
uc_x86_ymm = qc_x86_ymm
uc_arm64_neon128 = qc_arm64_neon128