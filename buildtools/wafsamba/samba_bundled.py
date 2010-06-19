# functions to support bundled libraries

from Configure import conf
import Logs
from samba_utils import *

def BUNDLED_NAME(bld, name, bundled_extension):
    '''possibly rename a library to include a bundled extension'''
    if bld.env.DISABLE_SHARED or not bundled_extension:
        return name
    if name in bld.env.BUNDLED_EXTENSION_EXCEPTION:
        return name
    extension = getattr(bld.env, 'BUNDLED_EXTENSION', '')
    if extension:
        return name + '-' + extension
    return name


def target_in_list(target, lst, default):
    for l in lst:
        if target == l:
            return True
        if '!' + target == l:
            return False
        if l == 'ALL':
            return True
        if l == 'NONE':
            return False
    return default


def BUILTIN_LIBRARY(bld, name):
    '''return True if a library should be builtin
       instead of being built as a shared lib'''
    if bld.env.DISABLE_SHARED:
        return True
    return target_in_list(name, bld.env.BUILTIN_LIBRARIES, False)
Build.BuildContext.BUILTIN_LIBRARY = BUILTIN_LIBRARY


def BUILTIN_DEFAULT(opt, builtins):
    '''set a comma separated default list of builtin libraries for this package'''
    if 'BUILTIN_LIBRARIES_DEFAULT' in Options.options:
        return
    Options.options['BUILTIN_LIBRARIES_DEFAULT'] = builtins
Options.Handler.BUILTIN_DEFAULT = BUILTIN_DEFAULT


def BUNDLED_EXTENSION_DEFAULT(opt, extension, noextension=''):
    '''set a default bundled library extension'''
    if 'BUNDLED_EXTENSION_DEFAULT' in Options.options:
        return
    Options.options['BUNDLED_EXTENSION_DEFAULT'] = extension
    Options.options['BUNDLED_EXTENSION_EXCEPTION'] = noextension
Options.Handler.BUNDLED_EXTENSION_DEFAULT = BUNDLED_EXTENSION_DEFAULT


def minimum_library_version(conf, libname, default):
    '''allow override of mininum system library version'''

    minlist = Options.options.MINIMUM_LIBRARY_VERSION
    if not minlist:
        return default

    for m in minlist.split(','):
        a = m.split(':')
        if len(a) != 2:
            Logs.error("Bad syntax for --minimum-library-version of %s" % m)
            sys.exit(1)
        if a[0] == libname:
            return a[1]
    return default


@conf
def LIB_MAY_BE_BUNDLED(conf, libname):
    return ('NONE' not in conf.env.BUNDLED_LIBS and
            '!%s' % libname not in conf.env.BUNDLED_LIBS)


@conf
def LIB_MUST_BE_BUNDLED(conf, libname):
    return ('ALL' in conf.env.BUNDLED_LIBS or 
            libname in conf.env.BUNDLED_LIBS)


@runonce
@conf
def CHECK_BUNDLED_SYSTEM(conf, libname, minversion='0.0.0',
                         checkfunctions=None, headers=None,
                         onlyif=None, implied_deps=None,
                         require_headers=True):
    '''check if a library is available as a system library.
    this first tries via pkg-config, then if that fails
    tries by testing for a specified function in the specified lib
    '''
    if conf.LIB_MUST_BE_BUNDLED(libname):
        return False
    found = 'FOUND_SYSTEMLIB_%s' % libname
    if found in conf.env:
        return conf.env[found]

    # see if the library should only use a system version if another dependent
    # system version is found. That prevents possible use of mixed library
    # versions
    if onlyif:
        for syslib in TO_LIST(onlyif):
            f = 'FOUND_SYSTEMLIB_%s' % syslib
            if not f in conf.env:
                if not conf.LIB_MAY_BE_BUNDLED(libname):
                    Logs.error('ERROR: Use of system library %s depends on missing system library %s' % (libname, syslib))
                    sys.exit(1)
                conf.env[found] = False
                return False

    minversion = minimum_library_version(conf, libname, minversion)

    # try pkgconfig first
    if conf.check_cfg(package=libname,
                      args='"%s >= %s" --cflags --libs' % (libname, minversion),
                      msg='Checking for system %s >= %s' % (libname, minversion)):
        conf.SET_TARGET_TYPE(libname, 'SYSLIB')
        conf.env[found] = True
        if implied_deps:
            conf.SET_SYSLIB_DEPS(libname, implied_deps)
        return True
    if checkfunctions is not None:
        headers_ok = True
        if require_headers and headers and not conf.CHECK_HEADERS(headers):
            headers_ok = False
        if headers_ok and conf.CHECK_FUNCS_IN(checkfunctions, libname, headers=headers, empty_decl=False):
            conf.env[found] = True
            if implied_deps:
                conf.SET_SYSLIB_DEPS(libname, implied_deps)
            return True
    conf.env[found] = False
    if not conf.LIB_MAY_BE_BUNDLED(libname):
        Logs.error('ERROR: System library %s of version %s not found, and bundling disabled' % (libname, minversion))
        sys.exit(1)
    return False

def NONSHARED_BINARY(bld, name):
    '''return True if a binary should be built without non-system shared libs'''
    if bld.env.DISABLE_SHARED:
        return True
    return target_in_list(name, bld.env.NONSHARED_BINARIES, False)
Build.BuildContext.NONSHARED_BINARY = NONSHARED_BINARY


