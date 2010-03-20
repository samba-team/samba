# a waf tool to add autoconf-like macros to the configure section
# and for SAMBA_ macros for building libraries, binaries etc

import Build, os, Logs, sys, Configure, Options, string, Task, Utils, optparse
from Configure import conf
from Logs import debug
from TaskGen import extension

# bring in the other samba modules
from samba_utils import *
from samba_autoconf import *
from samba_patterns import *
from samba_pidl import *
from samba_asn1 import *
from samba_autoproto import *
from samba_python import *
from samba_deps import *

LIB_PATH="shared"


#################################################################
# create the samba build environment
@conf
def SAMBA_BUILD_ENV(conf):
    libpath="%s/%s" % (conf.blddir, LIB_PATH)
    conf.env['BUILD_DIRECTORY'] = conf.blddir
    if not os.path.exists(libpath):
        os.mkdir(libpath)

################################################################
# add an init_function to the list for a subsystem
def ADD_INIT_FUNCTION(bld, subsystem, init_function):
    if init_function is None:
        return
    bld.ASSERT(subsystem is not None, "You must specify a subsystem for init_function '%s'" % init_function)
    cache = LOCAL_CACHE(bld, 'INIT_FUNCTIONS')
    if not subsystem in cache:
        cache[subsystem] = []
    cache[subsystem].append(init_function)
Build.BuildContext.ADD_INIT_FUNCTION = ADD_INIT_FUNCTION


#################################################################
# define a Samba library
def SAMBA_LIBRARY(bld, libname, source,
                  deps='',
                  public_deps='',
                  includes='',
                  public_headers=None,
                  vnum=None,
                  cflags='',
                  output_type=None,
                  realname=None,
                  autoproto=None,
                  group='main',
                  depends_on='',
                  local_include=True):

    # remember empty libraries, so we can strip the dependencies
    if (source == '') or (source == []):
        SET_TARGET_TYPE(bld, libname, 'EMPTY')
        return

    if not SET_TARGET_TYPE(bld, libname, 'LIBRARY'):
        return

    deps += ' ' + public_deps

    # this print below should show that we're runnig this code
    bld.SET_BUILD_GROUP(group)
    t = bld(
        features        = 'cc cshlib symlink_lib',
        source          = source,
        target          = libname,
        ccflags         = CURRENT_CFLAGS(bld, libname, cflags),
        depends_on      = depends_on,
        samba_deps      = TO_LIST(deps),
        samba_includes  = includes,
        local_include   = local_include,
        vnum            = vnum
        )
    if autoproto is not None:
        bld.SAMBA_AUTOPROTO(autoproto, source)

Build.BuildContext.SAMBA_LIBRARY = SAMBA_LIBRARY

#################################################################
# define a Samba binary
def SAMBA_BINARY(bld, binname, source,
                 deps='',
                 includes='',
                 public_headers=None,
                 modules=None,
                 installdir=None,
                 ldflags=None,
                 cflags='',
                 autoproto=None,
                 use_hostcc=None,
                 compiler=None,
                 group='main',
                 manpages=None,
                 local_include=True,
                 subsystem=None,
                 needs_python=False):

    if not SET_TARGET_TYPE(bld, binname, 'BINARY'):
        return

    features = 'cc cprogram copy_bin'
    if needs_python:
        features += ' pyembed'

    bld.SET_BUILD_GROUP(group)
    bld(
        features       = features,
        source         = source,
        target         = binname,
        ccflags        = CURRENT_CFLAGS(bld, binname, cflags),
        samba_deps     = TO_LIST(deps),
        samba_includes = includes,
        local_include  = local_include,
        samba_modules  = modules,
        top            = True,
        samba_subsystem= subsystem
        )

    if autoproto is not None:
        bld.SAMBA_AUTOPROTO(autoproto, source)
Build.BuildContext.SAMBA_BINARY = SAMBA_BINARY


#################################################################
# define a Samba ET target
def SAMBA_ERRTABLE(bld, name, source,
               options='',
               directory=''):
#    print "Skipping ERRTABLE rule for %s with source=%s" % (name, source)
#    return
    if not SET_TARGET_TYPE(bld, name, 'ET'):
        return
    bld.SET_BUILD_GROUP('build_source')
    bld(
        features = 'cc',
        source   = source,
        target   = name,
        includes = '# #source4/heimdal_build #source4 #lib/replace'
    )
Build.BuildContext.SAMBA_ERRTABLE = SAMBA_ERRTABLE

#################################################################
# define a Samba module.
def SAMBA_MODULE(bld, modname, source,
                 deps='',
                 includes='',
                 subsystem=None,
                 init_function=None,
                 autoproto=None,
                 autoproto_extra_source='',
                 aliases=None,
                 cflags='',
                 output_type=None,
                 local_include=True,
                 enabled=True):

    if output_type == 'MERGED_OBJ':
        # treat merged object modules as subsystems for now
        SAMBA_SUBSYSTEM(bld, modname, source,
                        deps=deps,
                        includes=includes,
                        autoproto=autoproto,
                        autoproto_extra_source=autoproto_extra_source,
                        cflags=cflags,
                        local_include=local_include,
                        enabled=enabled)
        # even though we're treating it as a subsystem, we need to
        # add it to the init_function list
        # TODO: we should also create an implicit dependency
        # between the subsystem target and this target
        bld.ADD_INIT_FUNCTION(subsystem, init_function)
        return

    if not enabled:
        SET_TARGET_TYPE(bld, modname, 'DISABLED')
        return

    # remember empty modules, so we can strip the dependencies
    if (source == '') or (source == []):
        SET_TARGET_TYPE(bld, modname, 'EMPTY')
        return

    if not SET_TARGET_TYPE(bld, modname, 'MODULE'):
        return


    bld.ADD_INIT_FUNCTION(subsystem, init_function)

    if subsystem is not None:
        deps += ' ' + subsystem

    bld.SET_BUILD_GROUP('main')
    bld(
        features       = 'cc',
        source         = source,
        target         = modname,
        ccflags        = CURRENT_CFLAGS(bld, modname, cflags),
        samba_includes = includes,
        local_include  = local_include,
        samba_deps     = TO_LIST(deps)
        )

    if autoproto is not None:
        bld.SAMBA_AUTOPROTO(autoproto, source + ' ' + autoproto_extra_source)

Build.BuildContext.SAMBA_MODULE = SAMBA_MODULE


#################################################################
# define a Samba subsystem
def SAMBA_SUBSYSTEM(bld, modname, source,
                    deps='',
                    public_deps='',
                    includes='',
                    public_headers=None,
                    cflags='',
                    group='main',
                    config_option=None,
                    init_function_sentinal=None,
                    heimdal_autoproto=None,
                    heimdal_autoproto_options=None,
                    heimdal_autoproto_private=None,
                    autoproto=None,
                    autoproto_extra_source='',
                    depends_on='',
                    local_include=True,
                    local_include_first=True,
                    enabled=True):

    if not enabled:
        SET_TARGET_TYPE(bld, modname, 'DISABLED')
        return

    # if the caller specifies a config_option, then we create a blank
    # subsystem if that configuration option was found at configure time
    if (config_option is not None) and bld.CONFIG_SET(config_option):
        SET_TARGET_TYPE(bld, modname, 'EMPTY')
        return

    # remember empty subsystems, so we can strip the dependencies
    if (source == '') or (source == []):
        SET_TARGET_TYPE(bld, modname, 'EMPTY')
        return

    if not SET_TARGET_TYPE(bld, modname, 'SUBSYSTEM'):
        return

    deps += ' ' + public_deps

    bld.SET_BUILD_GROUP(group)

    t = bld(
        features       = 'cc',
        source         = source,
        target         = modname,
        ccflags        = CURRENT_CFLAGS(bld, modname, cflags),
        depends_on     = depends_on,
        samba_deps     = TO_LIST(deps),
        samba_includes = includes,
        local_include  = local_include,
        local_include_first  = local_include_first
        )

    if heimdal_autoproto is not None:
        bld.HEIMDAL_AUTOPROTO(heimdal_autoproto, source, options=heimdal_autoproto_options)
    if heimdal_autoproto_private is not None:
        bld.HEIMDAL_AUTOPROTO_PRIVATE(heimdal_autoproto_private, source)
    if autoproto is not None:
        bld.SAMBA_AUTOPROTO(autoproto, source + ' ' + autoproto_extra_source)
    return t

Build.BuildContext.SAMBA_SUBSYSTEM = SAMBA_SUBSYSTEM


def SAMBA_GENERATOR(bld, name, rule, source, target,
                    group='build_source'):
    '''A generic source generator target'''

    if not SET_TARGET_TYPE(bld, name, 'GENERATOR'):
        return

    bld.SET_BUILD_GROUP(group)
    bld(
        rule=rule,
        source=source,
        target=target,
        before='cc',
        ext_out='.c')
Build.BuildContext.SAMBA_GENERATOR = SAMBA_GENERATOR



###############################################################
# add a new set of build rules from a subdirectory
# the @runonce decorator ensures we don't end up
# with duplicate rules
def BUILD_SUBDIR(bld, dir):
    path = os.path.normpath(bld.curdir + '/' + dir)
    cache = LOCAL_CACHE(bld, 'SUBDIR_LIST')
    if path in cache: return
    cache[path] = True
    debug("build: Processing subdirectory %s" % dir)
    bld.add_subdirs(dir)

Build.BuildContext.BUILD_SUBDIR = BUILD_SUBDIR


##########################################################
# add a new top level command to waf
def ADD_COMMAND(opt, name, function):
    Utils.g_module.__dict__[name] = function
    opt.name = function
Options.Handler.ADD_COMMAND = ADD_COMMAND

###########################################################
# setup build groups used to ensure that the different build
# phases happen consecutively
@runonce
def SETUP_BUILD_GROUPS(bld):
    bld.p_ln = bld.srcnode # we do want to see all targets!
    bld.env['USING_BUILD_GROUPS'] = True
    bld.add_group('setup')
    bld.add_group('base_libraries')
    bld.add_group('build_compilers')
    bld.add_group('build_source')
    bld.add_group('prototypes')
    bld.add_group('main')
    bld.add_group('final')
Build.BuildContext.SETUP_BUILD_GROUPS = SETUP_BUILD_GROUPS


###########################################################
# set the current build group
def SET_BUILD_GROUP(bld, group):
    if not 'USING_BUILD_GROUPS' in bld.env:
        return
    bld.set_group(group)
Build.BuildContext.SET_BUILD_GROUP = SET_BUILD_GROUP


def h_file(filename):
    import stat
    st = os.stat(filename)
    if stat.S_ISDIR(st[stat.ST_MODE]): raise IOError('not a file')
    m = Utils.md5()
    m.update(str(st.st_mtime))
    m.update(str(st.st_size))
    m.update(filename)
    return m.digest()

@conf
def ENABLE_TIMESTAMP_DEPENDENCIES(conf):
    Utils.h_file = h_file
