# a waf tool to add autoconf-like macros to the configure section
# and for SAMBA_ macros for building libraries, binaries etc

import Build, os, Options, Task, Utils, cc, TaskGen
from Configure import conf
from Logs import debug
from samba_utils import SUBST_VARS_RECURSIVE

# bring in the other samba modules
from samba_optimisation import *
from samba_utils import *
from samba_autoconf import *
from samba_patterns import *
from samba_pidl import *
from samba_errtable import *
from samba_asn1 import *
from samba_autoproto import *
from samba_python import *
from samba_deps import *

LIB_PATH="shared"



#################################################################
# create the samba build environment
@conf
def SAMBA_BUILD_ENV(conf):
    conf.env['BUILD_DIRECTORY'] = conf.blddir
    mkdir_p(os.path.join(conf.blddir, LIB_PATH))
    mkdir_p(os.path.join(conf.blddir, 'python/samba/dcerpc'))
    # this allows all of the bin/shared and bin/python targets
    # to be expressed in terms of build directory paths
    for p in ['python','shared']:
        link_target = os.path.join(conf.blddir, 'default/' + p)
        if not os.path.lexists(link_target):
            os.symlink('../' + p, link_target)



################################################################
# add an init_function to the list for a subsystem
def ADD_INIT_FUNCTION(bld, subsystem, target, init_function):
    if init_function is None:
        return
    bld.ASSERT(subsystem is not None, "You must specify a subsystem for init_function '%s'" % init_function)
    cache = LOCAL_CACHE(bld, 'INIT_FUNCTIONS')
    if not subsystem in cache:
        cache[subsystem] = []
    cache[subsystem].append( { 'TARGET':target, 'INIT_FUNCTION':init_function } )
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
                  external_library=False,
                  realname=None,
                  autoproto=None,
                  group='main',
                  depends_on='',
                  local_include=True,
                  install_path=None,
                  install=True,
                  enabled=True):

    if not enabled:
        SET_TARGET_TYPE(bld, libname, 'DISABLED')
        return

    # remember empty libraries, so we can strip the dependencies
    if (source == '') or (source == []):
        SET_TARGET_TYPE(bld, libname, 'EMPTY')
        return

    if not SET_TARGET_TYPE(bld, libname, 'LIBRARY'):
        return

    obj_target = libname + '.objlist'

    # first create a target for building the object files for this library
    # by separating in this way, we avoid recompiling the C files
    # separately for the install library and the build library
    bld.SAMBA_SUBSYSTEM(obj_target,
                        source         = source,
                        deps           = deps,
                        public_deps    = public_deps,
                        includes       = includes,
                        public_headers = public_headers,
                        cflags         = cflags,
                        group          = group,
                        autoproto      = autoproto,
                        depends_on     = depends_on,
                        local_include  = local_include)

    # the library itself will depend on that object target
    deps += ' ' + public_deps
    deps = TO_LIST(deps)
    deps.append(obj_target)

    bld.SET_BUILD_GROUP(group)
    t = bld(
        features        = 'cc cshlib symlink_lib',
        source          = [],
        target          = libname,
        samba_cflags    = CURRENT_CFLAGS(bld, libname, cflags),
        depends_on      = depends_on,
        samba_deps      = deps,
        samba_includes  = includes,
        local_include   = local_include,
        vnum            = vnum,
        install_path    = None
        )

    if install_path is None:
        install_path = '${LIBDIR}'
    install_path = SUBST_VARS_RECURSIVE(install_path, bld.env)

    if install:
        # create a separate install library, which may have
        # different rpath settings
        SET_TARGET_TYPE(bld, libname + '.inst', 'LIBRARY')
        t = bld(
            features        = 'cc cshlib',
            source          = [],
            target          = libname + '.inst',
            samba_cflags    = CURRENT_CFLAGS(bld, libname, cflags),
            depends_on      = depends_on,
            samba_deps      = deps,
            samba_includes  = includes,
            local_include   = local_include,
            vnum            = vnum,
            install_as	    = libname,
            install_path    = None,
            )
        t.env['RPATH'] = install_rpath(bld)

        if vnum:
            vnum_base = vnum.split('.')[0]
            install_name = 'lib%s.so.%s' % (libname, vnum)
            install_link = 'lib%s.so.%s' % (libname, vnum_base)
        else:
            install_name = 'lib%s.so' % libname
            install_link = None

        bld.install_as(os.path.join(install_path, install_name),
                       'lib%s.inst.so' % libname)
        if install_link:
            bld.symlink_as(os.path.join(install_path, install_link), install_name)


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
                 group='binaries',
                 manpages=None,
                 local_include=True,
                 subsystem_name=None,
                 needs_python=False,
                 install=True,
                 install_path=None):

    if not SET_TARGET_TYPE(bld, binname, 'BINARY'):
        return

    features = 'cc cprogram'
    if needs_python:
        features += ' pyembed'

    bld.SET_BUILD_GROUP(group)

    obj_target = binname + '.objlist'

    # first create a target for building the object files for this binary
    # by separating in this way, we avoid recompiling the C files
    # separately for the install binary and the build binary
    bld.SAMBA_SUBSYSTEM(obj_target,
                        source         = source,
                        deps           = deps,
                        includes       = includes,
                        cflags         = cflags,
                        group          = group,
                        autoproto      = autoproto,
                        subsystem_name = subsystem_name,
                        needs_python   = needs_python,
                        local_include  = local_include)

    # the library itself will depend on that object target
    deps = TO_LIST(deps)
    deps.append(obj_target)

    bld(
        features       = features + ' symlink_bin',
        source         = [],
        target         = binname,
        samba_cflags   = CURRENT_CFLAGS(bld, binname, cflags),
        samba_deps     = deps,
        samba_includes = includes,
        local_include  = local_include,
        samba_modules  = modules,
        top            = True,
        samba_subsystem= subsystem_name,
        install_path   = None
        )

    if install_path is None:
        install_path = '${BINDIR}'
    install_path = SUBST_VARS_RECURSIVE(install_path, bld.env)

    if install:
        # we create a separate 'install' binary, which
        # will have different rpath settings
        SET_TARGET_TYPE(bld, binname + '.inst', 'BINARY')
        t = bld(
            features       = features,
            source         = [],
            target         = binname + '.inst',
            samba_cflags   = CURRENT_CFLAGS(bld, binname, cflags),
            samba_deps     = deps,
            samba_includes = includes,
            local_include  = local_include,
            samba_modules  = modules,
            top            = True,
            samba_subsystem= subsystem_name,
            install_path   = None
            )
        t.env['RPATH'] = install_rpath(bld)

        bld.install_as(os.path.join(install_path, binname),
                       binname + '.inst',
                       chmod=0755)

    # setup the subsystem_name as an alias for the real
    # binary name, so it can be found when expanding
    # subsystem dependencies
    if subsystem_name is not None:
        bld.TARGET_ALIAS(subsystem_name, binname)

    if autoproto is not None:
        bld.SAMBA_AUTOPROTO(autoproto, source)
Build.BuildContext.SAMBA_BINARY = SAMBA_BINARY


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
                 internal_module=True,
                 local_include=True,
                 enabled=True):

    # we add the init function regardless of whether the module
    # is enabled or not, as we need to generate a null list if
    # all disabled
    bld.ADD_INIT_FUNCTION(subsystem, modname, init_function)

    if internal_module:
        # treat internal modules as subsystems for now
        SAMBA_SUBSYSTEM(bld, modname, source,
                        deps=deps,
                        includes=includes,
                        autoproto=autoproto,
                        autoproto_extra_source=autoproto_extra_source,
                        cflags=cflags,
                        local_include=local_include,
                        enabled=enabled)
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

    if subsystem is not None:
        deps += ' ' + subsystem

    bld.SET_BUILD_GROUP('main')
    bld(
        features       = 'cc',
        source         = source,
        target         = modname,
        samba_cflags   = CURRENT_CFLAGS(bld, modname, cflags),
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
                    cflags_end=None,
                    group='main',
                    init_function_sentinal=None,
                    heimdal_autoproto=None,
                    heimdal_autoproto_options=None,
                    heimdal_autoproto_private=None,
                    autoproto=None,
                    autoproto_extra_source='',
                    depends_on='',
                    local_include=True,
                    local_include_first=True,
                    subsystem_name=None,
                    enabled=True,
                    needs_python=False):

    if not enabled:
        SET_TARGET_TYPE(bld, modname, 'DISABLED')
        return

    # remember empty subsystems, so we can strip the dependencies
    if (source == '') or (source == []):
        SET_TARGET_TYPE(bld, modname, 'EMPTY')
        return

    if not SET_TARGET_TYPE(bld, modname, 'SUBSYSTEM'):
        return

    deps += ' ' + public_deps

    bld.SET_BUILD_GROUP(group)

    features = 'cc'
    if needs_python:
        features += ' pyext'

    t = bld(
        features       = features,
        source         = source,
        target         = modname,
        samba_cflags   = CURRENT_CFLAGS(bld, modname, cflags),
        depends_on     = depends_on,
        samba_deps     = TO_LIST(deps),
        samba_includes = includes,
        local_include  = local_include,
        local_include_first  = local_include_first,
        samba_subsystem= subsystem_name
        )

    if cflags_end is not None:
        t.samba_cflags.extend(TO_LIST(cflags_end))

    if heimdal_autoproto is not None:
        bld.HEIMDAL_AUTOPROTO(heimdal_autoproto, source, options=heimdal_autoproto_options)
    if heimdal_autoproto_private is not None:
        bld.HEIMDAL_AUTOPROTO_PRIVATE(heimdal_autoproto_private, source)
    if autoproto is not None:
        bld.SAMBA_AUTOPROTO(autoproto, source + ' ' + autoproto_extra_source)
    return t

Build.BuildContext.SAMBA_SUBSYSTEM = SAMBA_SUBSYSTEM


def SAMBA_GENERATOR(bld, name, rule, source, target,
                    group='build_source', enabled=True):
    '''A generic source generator target'''

    if not SET_TARGET_TYPE(bld, name, 'GENERATOR'):
        return

    if not enabled:
        return False

    bld.SET_BUILD_GROUP(group)
    bld(
        rule=rule,
        source=source,
        target=target,
        before='cc',
        ext_out='.c',
        name=name)
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
    bld.add_group('binaries')
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


##############################
# handle the creation of links for libraries and binaries
# note that we use a relative symlink path to allow the whole tree
# to me moved/copied elsewhere without breaking the links
t = Task.simple_task_type('symlink_lib', 'ln -sf ${LINK_SOURCE} ${LINK_TARGET}',
                          color='PINK', ext_in='.bin')
t.quiet = True

@feature('symlink_lib')
@after('apply_link')
def symlink_lib(self):
    tsk = self.create_task('symlink_lib', self.link_task.outputs[0])

    # calculat the link target and put it in the environment
    soext=""
    vnum = getattr(self, 'vnum', None)
    if vnum is not None:
        soext = '.' + vnum.split('.')[0]

    link_target = getattr(self, 'link_name', '')
    if link_target == '':
        link_target = '%s/lib%s.so%s' % (LIB_PATH, self.sname, soext)


    link_source = os_path_relpath(self.link_task.outputs[0].abspath(self.env),
                                  os.path.join(self.env.BUILD_DIRECTORY, link_target))

    tsk.env.LINK_TARGET = link_target
    tsk.env.LINK_SOURCE = link_source[3:]
    debug('task_gen: LINK for %s is %s -> %s',
          self.name, tsk.env.LINK_SOURCE, tsk.env.LINK_TARGET)


t = Task.simple_task_type('symlink_bin', 'ln -sf ${SRC} ${BIN_TARGET}',
                          color='PINK', ext_in='.bin')
t.quiet = True

@feature('symlink_bin')
@after('apply_link')
def symlink_bin(self):
    if Options.is_install:
        # we don't want to copy the install binary, as
        # that has the install rpath, not the build rpath
        # The rpath of the binaries in bin/default/foo/blah is different
        # during the install phase, as distros insist on not using rpath in installed binaries
        return
    tsk = self.create_task('symlink_bin', self.link_task.outputs[0])

    tsk.env.BIN_TARGET = self.target
    debug('task_gen: BIN_TARGET for %s is %s', self.name, tsk.env.BIN_TARGET)




t = Task.simple_task_type('copy_script', 'ln -sf ${SRC[0].abspath(env)} ${LINK_TARGET}',
                          color='PINK', ext_in='.bin', shell=True)
t.quiet = True

@feature('copy_script')
@before('apply_link')
def copy_script(self):
    tsk = self.create_task('copy_script', self.allnodes[0])
    tsk.env.TARGET = self.target

def SAMBA_SCRIPT(bld, name, pattern, installdir, installname=None):
    '''used to copy scripts from the source tree into the build directory
       for use by selftest'''

    source = bld.path.ant_glob(pattern)

    bld.SET_BUILD_GROUP('build_source')
    for s in TO_LIST(source):
        iname = s
        if installname != None:
            iname = installname
        target = os.path.join(installdir, iname)
        tgtdir = os.path.dirname(os.path.join(bld.srcnode.abspath(bld.env), '..', target))
        mkdir_p(tgtdir)
        t = bld(features='copy_script',
                source       = s,
                target       = target,
                always       = True,
                install_path = None)
        t.env.LINK_TARGET = target

Build.BuildContext.SAMBA_SCRIPT = SAMBA_SCRIPT

