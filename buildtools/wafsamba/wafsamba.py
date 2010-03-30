# a waf tool to add autoconf-like macros to the configure section
# and for SAMBA_ macros for building libraries, binaries etc

import Build, os, Options, Task, Utils, cc, TaskGen, fnmatch, re, shutil, Logs
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
from samba_bundled import *
import samba_conftests

LIB_PATH="shared"

os.putenv('PYTHONUNBUFFERED', '1')

@conf
def SAMBA_BUILD_ENV(conf):
    '''create the samba build environment'''
    conf.env['BUILD_DIRECTORY'] = conf.blddir
    mkdir_p(os.path.join(conf.blddir, LIB_PATH))
    mkdir_p(os.path.join(conf.blddir, 'python/samba/dcerpc'))
    # this allows all of the bin/shared and bin/python targets
    # to be expressed in terms of build directory paths
    for p in ['python','shared']:
        link_target = os.path.join(conf.blddir, 'default/' + p)
        if not os.path.lexists(link_target):
            os.symlink('../' + p, link_target)

    # get perl to put the blib files in the build directory
    blib_bld = os.path.join(conf.blddir, 'default/pidl/blib')
    blib_src = os.path.join(conf.srcdir, 'pidl/blib')
    mkdir_p(blib_bld + '/man1')
    mkdir_p(blib_bld + '/man3')
    if os.path.islink(blib_src):
        os.unlink(blib_src)
    elif os.path.exists(blib_src):
        shutil.rmtree(blib_src)
    os.symlink(blib_bld, blib_src)



def ADD_INIT_FUNCTION(bld, subsystem, target, init_function):
    '''add an init_function to the list for a subsystem'''
    if init_function is None:
        return
    bld.ASSERT(subsystem is not None, "You must specify a subsystem for init_function '%s'" % init_function)
    cache = LOCAL_CACHE(bld, 'INIT_FUNCTIONS')
    if not subsystem in cache:
        cache[subsystem] = []
    cache[subsystem].append( { 'TARGET':target, 'INIT_FUNCTION':init_function } )
Build.BuildContext.ADD_INIT_FUNCTION = ADD_INIT_FUNCTION



#################################################################
def SAMBA_LIBRARY(bld, libname, source,
                  deps='',
                  public_deps='',
                  includes='',
                  public_headers=None,
                  header_path=None,
                  pc_files=None,
                  vnum=None,
                  cflags='',
                  external_library=False,
                  realname=None,
                  autoproto=None,
                  group='main',
                  depends_on='',
                  local_include=True,
                  vars=None,
                  install_path=None,
                  install=True,
                  needs_python=False,
                  target_type='LIBRARY',
                  bundled_extension=True,
                  link_name=None,
                  enabled=True):
    '''define a Samba library'''

    if not enabled:
        SET_TARGET_TYPE(bld, libname, 'DISABLED')
        return

    source = bld.EXPAND_VARIABLES(source, vars=vars)

    # remember empty libraries, so we can strip the dependencies
    if (source == '') or (source == []):
        SET_TARGET_TYPE(bld, libname, 'EMPTY')
        return

    if BUILTIN_LIBRARY(bld, libname):
        obj_target = libname
    else:
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
                        header_path    = header_path,
                        cflags         = cflags,
                        group          = group,
                        autoproto      = autoproto,
                        depends_on     = depends_on,
                        needs_python   = needs_python,
                        local_include  = local_include)

    if BUILTIN_LIBRARY(bld, libname):
        return

    if not SET_TARGET_TYPE(bld, libname, target_type):
        return

    # the library itself will depend on that object target
    deps += ' ' + public_deps
    deps = TO_LIST(deps)
    deps.append(obj_target)

    if needs_python:
        bundled_name = libname
    else:
        bundled_name = BUNDLED_NAME(bld, libname, bundled_extension)

    features = 'cc cshlib'
    if needs_python:
        features += ' pyext'

    bld.SET_BUILD_GROUP(group)
    t = bld(
        features        = features + ' symlink_lib',
        source          = [],
        target          = bundled_name,
        samba_cflags    = CURRENT_CFLAGS(bld, libname, cflags),
        depends_on      = depends_on,
        samba_deps      = deps,
        samba_includes  = includes,
        local_include   = local_include,
        vnum            = vnum,
        install_path    = None,
        ldflags         = build_rpath(bld),
        name	        = libname
        )

    if link_name:
        t.link_name = link_name

    if install_path is None:
        install_path = '${LIBDIR}'
    install_path = SUBST_VARS_RECURSIVE(install_path, bld.env)

    # we don't need the double libraries if rpath is off
    if (bld.env.RPATH_ON_INSTALL == False and
        bld.env.RPATH_ON_BUILD == False):
        install_target = bundled_name
    else:
        install_target = bundled_name + '.inst'

    if install and install_target != bundled_name:
        # create a separate install library, which may have
        # different rpath settings
        SET_TARGET_TYPE(bld, install_target, target_type)
        t = bld(
            features        = features,
            source          = [],
            target          = install_target,
            samba_cflags    = CURRENT_CFLAGS(bld, libname, cflags),
            depends_on      = depends_on,
            samba_deps      = deps,
            samba_includes  = includes,
            local_include   = local_include,
            vnum            = vnum,
            install_as	    = bundled_name,
            install_path    = None,
            ldflags         = install_rpath(bld)
            )

    if install:
        if realname:
            install_name = realname
            install_link = None
            inst_name    = install_target + '.so'
        elif vnum:
            vnum_base = vnum.split('.')[0]
            install_name = 'lib%s.so.%s' % (bundled_name, vnum)
            install_link = 'lib%s.so.%s' % (bundled_name, vnum_base)
            inst_name    = 'lib%s.so' % install_target
        else:
            install_name = 'lib%s.so' % bundled_name
            install_link = None
            inst_name    = 'lib%s.so' % install_target

        bld.install_as(os.path.join(install_path, install_name), inst_name)
        if install_link:
            bld.symlink_as(os.path.join(install_path, install_link), install_name)

    if autoproto is not None:
        bld.SAMBA_AUTOPROTO(autoproto, source)

    if public_headers is not None:
        bld.PUBLIC_HEADERS(public_headers, header_path=header_path)

    if pc_files is not None:
        bld.PKG_CONFIG_FILES(pc_files, vnum=vnum)

Build.BuildContext.SAMBA_LIBRARY = SAMBA_LIBRARY


#################################################################
def SAMBA_BINARY(bld, binname, source,
                 deps='',
                 includes='',
                 public_headers=None,
                 header_path=None,
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
                 vars=None,
                 install=True,
                 install_path=None):
    '''define a Samba binary'''

    if not SET_TARGET_TYPE(bld, binname, 'BINARY'):
        return

    features = 'cc cprogram'
    if needs_python:
        features += ' pyembed'

    bld.SET_BUILD_GROUP(group)

    obj_target = binname + '.objlist'

    source = bld.EXPAND_VARIABLES(source, vars=vars)

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
        install_path   = None,
        ldflags        = build_rpath(bld)
        )

    if install_path is None:
        install_path = '${BINDIR}'
    install_path = SUBST_VARS_RECURSIVE(install_path, bld.env)

    # we don't need the double binaries if rpath is off
    if (bld.env.RPATH_ON_INSTALL == False and
        bld.env.RPATH_ON_BUILD == False):
        install_target = binname
    else:
        install_target = binname + '.inst'

    if install and install_target != binname:
        # we create a separate 'install' binary, which
        # will have different rpath settings
        SET_TARGET_TYPE(bld, install_target, 'BINARY')
        t = bld(
            features       = features,
            source         = [],
            target         = install_target,
            samba_cflags   = CURRENT_CFLAGS(bld, binname, cflags),
            samba_deps     = deps,
            samba_includes = includes,
            local_include  = local_include,
            samba_modules  = modules,
            top            = True,
            samba_subsystem= subsystem_name,
            install_path   = None,
            ldflags        = install_rpath(bld)
            )

    if install:
        bld.install_as(os.path.join(install_path, binname),
                       install_target,
                       chmod=0755)

    # setup the subsystem_name as an alias for the real
    # binary name, so it can be found when expanding
    # subsystem dependencies
    if subsystem_name is not None:
        bld.TARGET_ALIAS(subsystem_name, binname)

    if autoproto is not None:
        bld.SAMBA_AUTOPROTO(autoproto, source)
    if public_headers is not None:
        bld.PUBLIC_HEADERS(public_headers, header_path=header_path)
Build.BuildContext.SAMBA_BINARY = SAMBA_BINARY


#################################################################
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
                 vars=None,
                 enabled=True):
    '''define a Samba module.'''

    # we add the init function regardless of whether the module
    # is enabled or not, as we need to generate a null list if
    # all disabled
    bld.ADD_INIT_FUNCTION(subsystem, modname, init_function)

    if internal_module or BUILTIN_LIBRARY(bld, modname):
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

    source = bld.EXPAND_VARIABLES(source, vars=vars)

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
def SAMBA_SUBSYSTEM(bld, modname, source,
                    deps='',
                    public_deps='',
                    includes='',
                    public_headers=None,
                    header_path=None,
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
                    vars=None,
                    needs_python=False):
    '''define a Samba subsystem'''

    if not enabled:
        SET_TARGET_TYPE(bld, modname, 'DISABLED')
        return

    # remember empty subsystems, so we can strip the dependencies
    if (source == '') or (source == []):
        SET_TARGET_TYPE(bld, modname, 'EMPTY')
        return

    if not SET_TARGET_TYPE(bld, modname, 'SUBSYSTEM'):
        return

    source = bld.EXPAND_VARIABLES(source, vars=vars)

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
    if public_headers is not None:
        bld.PUBLIC_HEADERS(public_headers, header_path=header_path)
    return t


Build.BuildContext.SAMBA_SUBSYSTEM = SAMBA_SUBSYSTEM


def SAMBA_GENERATOR(bld, name, rule, source, target,
                    group='build_source', enabled=True,
                    public_headers=None,
                    header_path=None,
                    vars=None):
    '''A generic source generator target'''

    if not SET_TARGET_TYPE(bld, name, 'GENERATOR'):
        return

    if not enabled:
        return

    bld.SET_BUILD_GROUP(group)
    t = bld(
        rule=rule,
        source=bld.EXPAND_VARIABLES(source, vars=vars),
        target=target,
        shell=isinstance(rule, str),
        on_results=True,
        before='cc',
        ext_out='.c',
        name=name)

    if public_headers is not None:
        bld.PUBLIC_HEADERS(public_headers, header_path=header_path)
    return t
Build.BuildContext.SAMBA_GENERATOR = SAMBA_GENERATOR



def BUILD_SUBDIR(bld, dir):
    '''add a new set of build rules from a subdirectory'''
    path = os.path.normpath(bld.curdir + '/' + dir)
    cache = LOCAL_CACHE(bld, 'SUBDIR_LIST')
    if path in cache: return
    cache[path] = True
    debug("build: Processing subdirectory %s" % dir)
    bld.add_subdirs(dir)
Build.BuildContext.BUILD_SUBDIR = BUILD_SUBDIR



@runonce
def SETUP_BUILD_GROUPS(bld):
    '''setup build groups used to ensure that the different build
    phases happen consecutively'''
    bld.p_ln = bld.srcnode # we do want to see all targets!
    bld.env['USING_BUILD_GROUPS'] = True
    bld.add_group('setup')
    bld.add_group('build_compiler_source')
    bld.add_group('base_libraries')
    bld.add_group('build_compilers')
    bld.add_group('build_source')
    bld.add_group('prototypes')
    bld.add_group('main')
    bld.add_group('binaries')
    bld.add_group('final')
Build.BuildContext.SETUP_BUILD_GROUPS = SETUP_BUILD_GROUPS


def SET_BUILD_GROUP(bld, group):
    '''set the current build group'''
    if not 'USING_BUILD_GROUPS' in bld.env:
        return
    bld.set_group(group)
Build.BuildContext.SET_BUILD_GROUP = SET_BUILD_GROUP



@conf
def ENABLE_TIMESTAMP_DEPENDENCIES(conf):
    """use timestamps instead of file contents for deps
    this currently doesn't work"""
    def h_file(filename):
        import stat
        st = os.stat(filename)
        if stat.S_ISDIR(st[stat.ST_MODE]): raise IOError('not a file')
        m = Utils.md5()
        m.update(str(st.st_mtime))
        m.update(str(st.st_size))
        m.update(filename)
        return m.digest()
    Utils.h_file = h_file



##############################
# handle the creation of links for libraries and binaries
# note that we use a relative symlink path to allow the whole tree
# to me moved/copied elsewhere without breaking the links
t = Task.simple_task_type('symlink_lib', 'rm -f ${LINK_TARGET} && ln -s ${LINK_SOURCE} ${LINK_TARGET}',
                          shell=True, color='PINK', ext_in='.bin')
t.quiet = True

@feature('symlink_lib')
@after('apply_link')
def symlink_lib(self):
    '''symlink a shared lib'''
    tsk = self.create_task('symlink_lib', self.link_task.outputs[0])

    # calculat the link target and put it in the environment
    soext=""
    vnum = getattr(self, 'vnum', None)
    if vnum is not None:
        soext = '.' + vnum.split('.')[0]

    link_target = getattr(self, 'link_name', '')
    if link_target == '':
        link_target = '%s/lib%s.so%s' % (LIB_PATH, self.target, soext)


    link_source = os_path_relpath(self.link_task.outputs[0].abspath(self.env),
                                  os.path.join(self.env.BUILD_DIRECTORY, link_target))

    tsk.env.LINK_TARGET = link_target
    tsk.env.LINK_SOURCE = link_source[3:]
    debug('task_gen: LINK for %s is %s -> %s',
          self.name, tsk.env.LINK_SOURCE, tsk.env.LINK_TARGET)


t = Task.simple_task_type('symlink_bin', 'rm -f ${BIN_TARGET} && ln -s ${SRC} ${BIN_TARGET}',
                          shell=True, color='PINK', ext_in='.bin')
t.quiet = True

@feature('symlink_bin')
@after('apply_link')
def symlink_bin(self):
    '''symlink a binary'''
    if Options.is_install:
        # we don't want to copy the install binary, as
        # that has the install rpath, not the build rpath
        # The rpath of the binaries in bin/default/foo/blah is different
        # during the install phase, as distros insist on not using rpath in installed binaries
        return
    tsk = self.create_task('symlink_bin', self.link_task.outputs[0])

    tsk.env.BIN_TARGET = self.target
    debug('task_gen: BIN_TARGET for %s is %s', self.name, tsk.env.BIN_TARGET)




t = Task.simple_task_type('copy_script', 'rm -f ${LINK_TARGET} && ln -s ${SRC[0].abspath(env)} ${LINK_TARGET}',
                          shell=True, color='PINK', ext_in='.bin')
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


def install_file(bld, destdir, file, chmod=0644, flat=False,
                 python_fixup=False, destname=None):
    '''install a file'''
    destdir = bld.EXPAND_VARIABLES(destdir)
    if not destname:
        destname = file
        if flat:
            destname = os.path.basename(destname)
    dest = os.path.join(destdir, destname)
    if python_fixup:
        # fixup the python path it will use to find Samba modules
        inst_file = file + '.inst'
        bld.SAMBA_GENERATOR('python_%s' % destname,
                            rule="sed 's|\(sys.path.insert.*\)bin/python\(.*\)$|\\1${PYTHONDIR}\\2|g' < ${SRC} > ${TGT}",
                            source=file,
                            target=inst_file)
        file = inst_file
    bld.install_as(dest, file, chmod=chmod)


def INSTALL_FILES(bld, destdir, files, chmod=0644, flat=False,
                  python_fixup=False, destname=None):
    '''install a set of files'''
    for f in TO_LIST(files):
        install_file(bld, destdir, f, chmod=chmod, flat=flat,
                     python_fixup=python_fixup, destname=destname)
Build.BuildContext.INSTALL_FILES = INSTALL_FILES


def INSTALL_WILDCARD(bld, destdir, pattern, chmod=0644, flat=False,
                     python_fixup=False, exclude=None):
    '''install a set of files matching a wildcard pattern'''
    files=TO_LIST(bld.path.ant_glob(pattern))
    if exclude:
        for f in files[:]:
            if fnmatch.fnmatch(f, exclude):
                files.remove(f)
    INSTALL_FILES(bld, destdir, files, chmod=chmod, flat=flat, python_fixup=python_fixup)
Build.BuildContext.INSTALL_WILDCARD = INSTALL_WILDCARD


def PUBLIC_HEADERS(bld, public_headers, header_path=None):
    '''install some headers

    header_path may either be a string that is added to the INCLUDEDIR,
    or it can be a dictionary of wildcard patterns which map to destination
    directories relative to INCLUDEDIR
    '''
    dest = '${INCLUDEDIR}'
    if isinstance(header_path, str):
        dest += '/' + header_path
    for h in TO_LIST(public_headers):
        hdest = dest
        if isinstance(header_path, list):
            for (p1, dir) in header_path:
                found_match=False
                lst = TO_LIST(p1)
                for p2 in lst:
                    if fnmatch.fnmatch(h, p2):
                        if dir:
                            hdest = os.path.join(hdest, dir)
                        found_match=True
                        break
                if found_match: break
        if h.find(':') != -1:
            hs=h.split(':')
            INSTALL_FILES(bld, hdest, hs[0], flat=True, destname=hs[1])
        else:
            INSTALL_FILES(bld, hdest, h, flat=True)
Build.BuildContext.PUBLIC_HEADERS = PUBLIC_HEADERS


def subst_at_vars(task):
    '''substiture @VAR@ style variables in a file'''
    src = task.inputs[0].srcpath(task.env)
    tgt = task.outputs[0].bldpath(task.env)

    f = open(src, 'r')
    s = f.read()
    f.close()
    # split on the vars
    a = re.split('(@\w+@)', s)
    out = []
    for v in a:
        if re.match('@\w+@', v):
            vname = v[1:-1]
            if not vname in task.env and vname.upper() in task.env:
                vname = vname.upper()
            if not vname in task.env:
                print "Unknown substitution %s in %s" % (v, task.name)
                raise
            v = task.env[vname]
        out.append(v)
    contents = ''.join(out)
    f = open(tgt, 'w')
    s = f.write(contents)
    f.close()
    return 0



def PKG_CONFIG_FILES(bld, pc_files, vnum=None):
    '''install some pkg_config pc files'''
    dest = '${PKGCONFIGDIR}'
    dest = bld.EXPAND_VARIABLES(dest)
    for f in TO_LIST(pc_files):
        base=os.path.basename(f)
        t = bld.SAMBA_GENERATOR('PKGCONFIG_%s' % base,
                                rule=subst_at_vars,
                                source=f+'.in',
                                target=f)
        if vnum:
            t.env.PACKAGE_VERSION = vnum
        INSTALL_FILES(bld, dest, f, flat=True, destname=base)
Build.BuildContext.PKG_CONFIG_FILES = PKG_CONFIG_FILES



#############################################################
# give a nicer display when building different types of files
def progress_display(self, msg, fname):
    col1 = Logs.colors(self.color)
    col2 = Logs.colors.NORMAL
    total = self.position[1]
    n = len(str(total))
    fs = '[%%%dd/%%%dd] %s %%s%%s%%s\n' % (n, n, msg)
    return fs % (self.position[0], self.position[1], col1, fname, col2)

def link_display(self):
    if Options.options.progress_bar != 0:
        return Task.Task.old_display(self)
    fname = self.outputs[0].bldpath(self.env)
    return progress_display(self, 'Linking', fname)
Task.TaskBase.classes['cc_link'].display = link_display

def samba_display(self):
    if Options.options.progress_bar != 0:
        return Task.Task.old_display(self)
    fname = self.inputs[0].bldpath(self.env)
    if fname[0:3] == '../':
        fname = fname[3:]
    ext_loc = fname.rfind('.')
    if ext_loc == -1:
        return Task.Task.old_display(self)
    ext = fname[ext_loc:]

    ext_map = { '.idl' : 'Compiling IDL',
                '.et'  : 'Compiling ERRTABLE',
                '.asn1': 'Compiling ASN1',
                '.c'   : 'Compiling' }
    if ext in ext_map:
        return progress_display(self, ext_map[ext], fname)
    return Task.Task.old_display(self)

Task.TaskBase.classes['Task'].old_display = Task.TaskBase.classes['Task'].display
Task.TaskBase.classes['Task'].display = samba_display
