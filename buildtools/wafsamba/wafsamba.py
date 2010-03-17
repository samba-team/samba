# a waf tool to add autoconf-like macros to the configure section
# and for SAMBA_ macros for building libraries, binaries etc

import Build, os, Options, Task, Utils, cc
from Configure import conf
from Logs import debug

# bring in the other samba modules
from samba_includes import *
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
        samba_cflags    = CURRENT_CFLAGS(bld, libname, cflags),
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
                 group='binaries',
                 manpages=None,
                 local_include=True,
                 subsystem_name=None,
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
        samba_cflags   = CURRENT_CFLAGS(bld, binname, cflags),
        samba_deps     = TO_LIST(deps),
        samba_includes = includes,
        local_include  = local_include,
        samba_modules  = modules,
        top            = True,
        samba_subsystem= subsystem_name
        )

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
        # even though we're treating it as a subsystem, we need to
        # add it to the init_function list
        # TODO: we should also create an implicit dependency
        # between the subsystem target and this target
        if enabled:
            bld.ADD_INIT_FUNCTION(subsystem, modname, init_function)
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


    bld.ADD_INIT_FUNCTION(subsystem, modname, init_function)

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

# for binaries we need to copy the executable to avoid the rpath changing
# in the local bin/ directory on install
t = Task.simple_task_type('copy_bin', 'rm -f ${BIN_TARGET} && cp ${SRC} ${BIN_TARGET}', color='PINK',
                          ext_in='.bin', shell=True)
t.quiet = True

@feature('copy_bin')
@after('apply_link')
def copy_bin(self):
    if Options.is_install:
        # we don't want to copy the install binary, as
        # that has the install rpath, not the build rpath
        # The rpath of the binaries in bin/default/foo/blah is different
        # during the install phase, as distros insist on not using rpath in installed binaries
        return
    tsk = self.create_task('copy_bin', self.link_task.outputs[0])

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
                source=s,
                target = target,
                always=True)
        t.env.LINK_TARGET = target

Build.BuildContext.SAMBA_SCRIPT = SAMBA_SCRIPT

