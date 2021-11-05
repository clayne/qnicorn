# Unicorn Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>
from . import arm_const, arm64_const, mips_const, sparc_const, m68k_const, x86_const
from .qnicorn_const import *
from .qnicorn import Qc, qc_version, qc_arch_supported, version_bind, debug, QcError, __version__

# For Unicorn compatibilty
from .qnicorn import Uc, uc_version, uc_arch_supported, version_bind, debug, UcError, __version__