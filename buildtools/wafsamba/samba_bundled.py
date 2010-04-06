# functions to support bundled libraries

from Configure import conf
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


def BUILTIN_DEFAULT(opt, builtins):
    '''set a comma separated default list of builtin libraries for this package'''
    if 'BUILTIN_LIBRARIES_DEFAULT' in Options.options:
        return
    Options.options['BUILTIN_LIBRARIES_DEFAULT'] = builtins
Options.Handler.BUILTIN_DEFAULT = BUILTIN_DEFAULT


def BUNDLED_EXTENSION_DEFAULT(opt, extension, noextenion=''):
    '''set a default bundled library extension'''
    if 'BUNDLED_EXTENSION_DEFAULT' in Options.options:
        return
    Options.options['BUNDLED_EXTENSION_DEFAULT'] = extension
    Options.options['BUNDLED_EXTENSION_EXCEPTION'] = noextenion
Options.Handler.BUNDLED_EXTENSION_DEFAULT = BUNDLED_EXTENSION_DEFAULT



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
    if 'ALL' in conf.env.BUNDLED_LIBS or libname in conf.env.BUNDLED_LIBS:
        return False
    found = 'FOUND_SYSTEMLIB_%s' % libname
    if found in conf.env:
        return conf.env[found]

    # see if the library should only use a system version if another dependent
    # system version is found. That prevents possible use of mixed library
    # versions
    if onlyif:
        for syslib in TO_LIST(onlyif):
            f = 'FOUND_SYSTEM_%s' % syslib
            if not f in conf.env:
                if 'NONE' in conf.env.BUNDLED_LIBS or '!'+libname in conf.env.BUNDLED_LIBS:
                    print('ERROR: Use of system library %s depends on missing system library %s' % (libname, syslib))
                    sys.exit(1)
                conf.env[found] = False
                return False

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
    if 'NONE' in conf.env.BUNDLED_LIBS or '!'+libname in conf.env.BUNDLED_LIBS:
        print('ERROR: System library %s of version %s not found, and bundling disabled' % (libname, minversion))
        sys.exit(1)
    return False
