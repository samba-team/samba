# waf build tool for building IDL files with pidl

import os
import Build, Logs, Utils, Configure
from Configure import conf

@conf
def SAMBA_CHECK_PYTHON(conf, mandatory=True, version=(2,4,2)):
    # enable tool to build python extensions
    if conf.env.HAVE_PYTHON_H:
        conf.check_python_version(version)
        return

    interpreters = []

    if conf.env['EXTRA_PYTHON']:
        conf.all_envs['extrapython'] = conf.env.copy()
        conf.setenv('extrapython')
        conf.env['PYTHON'] = conf.env['EXTRA_PYTHON']
        conf.env['IS_EXTRA_PYTHON'] = 'yes'
        conf.find_program('python', var='PYTHON', mandatory=True)
        conf.check_tool('python')
        try:
            conf.check_python_version((3, 3, 0))
        except Exception:
            Logs.warn('extra-python needs to be Python 3.3 or later')
            raise
        interpreters.append(conf.env['PYTHON'])
        conf.setenv('default')

    conf.find_program('python', var='PYTHON', mandatory=mandatory)
    conf.check_tool('python')
    path_python = conf.find_program('python')
    conf.env.PYTHON_SPECIFIED = (conf.env.PYTHON != path_python)
    conf.check_python_version(version)

    interpreters.append(conf.env['PYTHON'])
    conf.env.python_interpreters = interpreters


@conf
def SAMBA_CHECK_PYTHON_HEADERS(conf, mandatory=True):
    if conf.env.disable_python:
        if mandatory:
            raise Utils.WafError("Cannot check for python headers when "
                                 "--disable-python specified")

        conf.msg("python headers", "Check disabled due to --disable-python")
        # we don't want PYTHONDIR in config.h, as otherwise changing
        # --prefix causes a complete rebuild
        del(conf.env.defines['PYTHONDIR'])
        del(conf.env.defines['PYTHONARCHDIR'])
        return

    if conf.env["python_headers_checked"] == []:
        if conf.env['EXTRA_PYTHON']:
            conf.setenv('extrapython')
            _check_python_headers(conf, mandatory=True)
            conf.setenv('default')

        _check_python_headers(conf, mandatory)
        conf.env["python_headers_checked"] = "yes"

        if conf.env['EXTRA_PYTHON']:
            extraversion = conf.all_envs['extrapython']['PYTHON_VERSION']
            if extraversion == conf.env['PYTHON_VERSION']:
                raise Utils.WafError("extrapython %s is same as main python %s" % (
                    extraversion, conf.env['PYTHON_VERSION']))
    else:
        conf.msg("python headers", "using cache")

    # we don't want PYTHONDIR in config.h, as otherwise changing
    # --prefix causes a complete rebuild
    del(conf.env.defines['PYTHONDIR'])
    del(conf.env.defines['PYTHONARCHDIR'])

def _check_python_headers(conf, mandatory):
    try:
        Configure.ConfigurationError
        conf.check_python_headers(mandatory=mandatory)
    except Configure.ConfigurationError:
        if mandatory:
             raise

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

    if bld.env['IS_EXTRA_PYTHON']:
        name = 'extra-' + name

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
        link_name = 'python_modules/%s' % realname
    else:
        link_name = None

    bld.SAMBA_LIBRARY(name,
                      source=source,
                      deps=deps,
                      public_deps=public_deps,
                      includes=includes,
                      cflags=cflags,
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


def pyembed_libname(bld, name, extrapython=False):
    if bld.env['PYTHON_SO_ABI_FLAG']:
        return name + bld.env['PYTHON_SO_ABI_FLAG']
    else:
        return name

Build.BuildContext.pyembed_libname = pyembed_libname


def gen_python_environments(bld, extra_env_vars=()):
    """Generate all Python environments

    To be used in a for loop. Normally, the loop body will be executed once.

    When --extra-python is used, the body will additionaly be executed
    with the extra-python environment active.
    """
    yield

    if bld.env['EXTRA_PYTHON']:
        copied = ('GLOBAL_DEPENDENCIES', 'TARGET_TYPE') + tuple(extra_env_vars)
        for name in copied:
            bld.all_envs['extrapython'][name] = bld.all_envs['default'][name]
        default_env = bld.all_envs['default']
        bld.all_envs['default'] = bld.all_envs['extrapython']
        yield
        bld.all_envs['default'] = default_env

Build.BuildContext.gen_python_environments = gen_python_environments
