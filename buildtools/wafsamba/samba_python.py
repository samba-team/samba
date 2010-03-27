# waf build tool for building IDL files with pidl

import Build
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
                 vars=None,
                 enabled=True):
    '''build a python extension for Samba'''

    # when we support static python modules we'll need to gather
    # the list from all the SAMBA_PYTHON() targets
    if init_function_sentinal is not None:
        cflags += '-DSTATIC_LIBPYTHON_MODULES=%s' % init_function_sentinal

    source = bld.EXPAND_VARIABLES(source, vars=vars)

    if realname is None:
        # a SAMBA_PYTHON target without a realname is just a
        # subsystem with needs_python=True
        return bld.SAMBA_SUBSYSTEM(name,
                                   source=source,
                                   deps=deps,
                                   public_deps=public_deps,
                                   cflags=cflags,
                                   includes=includes,
                                   init_function_sentinal=init_function_sentinal,
                                   local_include=local_include,
                                   needs_python=True,
                                   enabled=enabled)

    if not enabled:
        SET_TARGET_TYPE(bld, name, 'DISABLED')
        return

    if not SET_TARGET_TYPE(bld, name, 'PYTHON'):
        return

    deps += ' ' + public_deps

    if realname is None:
        realname = '%s.so' % name
    link_name = 'python/%s' % realname

    bld.SET_BUILD_GROUP('main')

    t = bld(
        features       = 'cc cshlib pyext symlink_lib',
        source         = source,
        target         = name,
        samba_cflags   = CURRENT_CFLAGS(bld, name, cflags),
        samba_includes = includes,
        local_include  = local_include,
        samba_deps     = TO_LIST(deps),
        link_name      = link_name,
        name	       = name,
        install_path   = None
        )

    destdir='${PYTHONDIR}'
    dname=os.path.dirname(realname)
    if dname:
        destdir += '/' + dname
    bld.INSTALL_FILES(destdir, name + '.so', destname=os.path.basename(realname))

Build.BuildContext.SAMBA_PYTHON = SAMBA_PYTHON
