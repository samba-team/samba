# waf build tool for building IDL files with pidl

from TaskGen import taskgen, before
import Build, os, string, Utils
from samba_utils import *
from samba_autoconf import *


def SAMBA_PYTHON(bld, name,
                 source='',
                 deps='',
                 public_deps='',
                 realname=None,
                 cflags='',
                 includes='',
                 init_function_sentinal=None,
                 local_include=True,
                 enabled=True):
    '''build a python extension for Samba'''

    if not enabled:
        SET_TARGET_TYPE(bld, name, 'DISABLED')
        return

    if not SET_TARGET_TYPE(bld, name, 'PYTHON'):
        return

    deps += ' ' + public_deps

    # when we support static python modules we'll need to gather
    # the list from all the SAMBA_PYTHON() targets
    if init_function_sentinal is not None:
        cflags += '-DSTATIC_LIBPYTHON_MODULES="%s"' % init_function_sentinal

    t = bld(
        features       = 'cc cshlib pyext',
        source         = source,
        target         = name,
        ccflags        = CURRENT_CFLAGS(bld, name, cflags),
        samba_includes = includes,
        local_include  = local_include,
        samba_deps     = TO_LIST(deps)
        )
Build.BuildContext.SAMBA_PYTHON = SAMBA_PYTHON
