# waf build tool for building IDL files with pidl

import os, sys
from waflib import Build, Logs, Utils, Configure, Errors
from waflib.Configure import conf

@conf
def SAMBA_CHECK_PYTHON(conf, version=(3,5,0)):

    if conf.env.disable_python:
        version=(2,6,0)

    # enable tool to build python extensions
    if conf.env.HAVE_PYTHON_H:
        conf.check_python_version(version)
        return

    interpreters = []

    conf.find_program('python3', var='PYTHON',
                      mandatory=not conf.env.disable_python)
    conf.load('python')
    path_python = conf.find_program('python3')

    conf.env.PYTHON_SPECIFIED = (conf.env.PYTHON != path_python)
    conf.check_python_version(version)

    interpreters.append(conf.env['PYTHON'])
    conf.env.python_interpreters = interpreters


@conf
def SAMBA_CHECK_PYTHON_HEADERS(conf):
    if conf.env.disable_python:

        conf.msg("python headers", "Check disabled due to --disable-python")
        # we don't want PYTHONDIR in config.h, as otherwise changing
        # --prefix causes a complete rebuild
        conf.env.DEFINES = [x for x in conf.env.DEFINES
            if not x.startswith('PYTHONDIR=')
            and not x.startswith('PYTHONARCHDIR=')]

        return

    if conf.env["python_headers_checked"] == []:
        _check_python_headers(conf)
        conf.env["python_headers_checked"] = "yes"

    else:
        conf.msg("python headers", "using cache")

    # we don't want PYTHONDIR in config.h, as otherwise changing
    # --prefix causes a complete rebuild
    conf.env.DEFINES = [x for x in conf.env.DEFINES
        if not x.startswith('PYTHONDIR=')
        and not x.startswith('PYTHONARCHDIR=')]

def _check_python_headers(conf):
    conf.check_python_headers()

    if conf.env['PYTHON_VERSION'] > '3':
        abi_pattern = os.path.splitext(conf.env['pyext_PATTERN'])[0]
        conf.env['PYTHON_SO_ABI_FLAG'] = abi_pattern % ''
    else:
        conf.env['PYTHON_SO_ABI_FLAG'] = ''
    conf.env['PYTHON_LIBNAME_SO_ABI_FLAG'] = (
        conf.env['PYTHON_SO_ABI_FLAG'].replace('_', '-'))

    for lib in conf.env['LINKFLAGS_PYEMBED']:
        if lib.startswith('-L'):
            conf.env.append_unique('LIBPATH_PYEMBED', lib[2:]) # strip '-L'
            conf.env['LINKFLAGS_PYEMBED'].remove(lib)

    # same as in waf 1.5, keep only '-fno-strict-aliasing'
    # and ignore defines such as NDEBUG _FORTIFY_SOURCE=2
    conf.env.DEFINES_PYEXT = []
    conf.env.CFLAGS_PYEXT = ['-fno-strict-aliasing']

    return

def PYTHON_BUILD_IS_ENABLED(self):
    return self.CONFIG_SET('HAVE_PYTHON_H')

Build.BuildContext.PYTHON_BUILD_IS_ENABLED = PYTHON_BUILD_IS_ENABLED


def SAMBA_PYTHON(bld, name,
                 source='',
                 deps='',
                 public_deps='',
                 realname=None,
                 cflags='',
                 cflags_end=None,
                 includes='',
                 init_function_sentinel=None,
                 local_include=True,
                 vars=None,
                 install=True,
                 enabled=True):
    '''build a python extension for Samba'''

    # force-disable when we can't build python modules, so
    # every single call doesn't need to pass this in.
    if not bld.PYTHON_BUILD_IS_ENABLED():
        enabled = False

    # Save time, no need to build python bindings when fuzzing
    if bld.env.enable_fuzzing:
        enabled = False

    # when we support static python modules we'll need to gather
    # the list from all the SAMBA_PYTHON() targets
    if init_function_sentinel is not None:
        cflags += ' -DSTATIC_LIBPYTHON_MODULES=%s' % init_function_sentinel

    # From https://docs.python.org/2/c-api/arg.html:
    # Starting with Python 2.5 the type of the length argument to
    # PyArg_ParseTuple(), PyArg_ParseTupleAndKeywords() and PyArg_Parse()
    # can be controlled by defining the macro PY_SSIZE_T_CLEAN before
    # including Python.h. If the macro is defined, length is a Py_ssize_t
    # rather than an int.

    # Because <Python.h> if often included before includes.h/config.h
    # This must be in the -D compiler options
    cflags += ' -DPY_SSIZE_T_CLEAN=1'

    source = bld.EXPAND_VARIABLES(source, vars=vars)

    if realname is not None:
        link_name = 'python/%s' % realname
    else:
        link_name = None

    bld.SAMBA_LIBRARY(name,
                      source=source,
                      deps=deps,
                      public_deps=public_deps,
                      includes=includes,
                      cflags=cflags,
                      cflags_end=cflags_end,
                      local_include=local_include,
                      vars=vars,
                      realname=realname,
                      link_name=link_name,
                      pyext=True,
                      target_type='PYTHON',
                      install_path='${PYTHONARCHDIR}',
                      allow_undefined_symbols=True,
                      install=install,
                      enabled=enabled)

Build.BuildContext.SAMBA_PYTHON = SAMBA_PYTHON


def pyembed_libname(bld, name):
    if bld.env['PYTHON_SO_ABI_FLAG']:
        return name + bld.env['PYTHON_SO_ABI_FLAG']
    else:
        return name

Build.BuildContext.pyembed_libname = pyembed_libname


