# a waf tool to add autoconf-like macros to the configure section
# and for SAMBA_ macros for building libraries, binaries etc

import Build, os, Options, Task, Utils, cc, TaskGen, fnmatch, re, shutil, Logs, Constants
from Configure import conf
from Logs import debug
from samba_utils import SUBST_VARS_RECURSIVE
TaskGen.task_gen.apply_verif = Utils.nada

# bring in the other samba modules
from samba_optimisation import *
from samba_utils import *
from samba_version import *
from samba_autoconf import *
from samba_patterns import *
from samba_pidl import *
from samba_errtable import *
from samba_asn1 import *
from samba_autoproto import *
from samba_python import *
from samba_deps import *
from samba_bundled import *
import samba_install
import samba_conftests
import samba_abi
import tru64cc
import irixcc
import generic_cc
import samba_dist
import samba_wildcard

# some systems have broken threading in python
if os.environ.get('WAF_NOTHREADS') == '1':
    import nothreads

LIB_PATH="shared"

os.putenv('PYTHONUNBUFFERED', '1')


if Constants.HEXVERSION < 0x105016:
    Logs.error('''
Please use the version of waf that comes with Samba, not
a system installed version. See http://wiki.samba.org/index.php/Waf
for details.

Alternatively, please use ./autogen-waf.sh, and then
run ./configure and make as usual. That will call the right version of waf.
''')
    sys.exit(1)


@conf
def SAMBA_BUILD_ENV(conf):
    '''create the samba build environment'''
    conf.env.BUILD_DIRECTORY = conf.blddir
    mkdir_p(os.path.join(conf.blddir, LIB_PATH))
    mkdir_p(os.path.join(conf.blddir, 'python/samba/dcerpc'))
    # this allows all of the bin/shared and bin/python targets
    # to be expressed in terms of build directory paths
    mkdir_p(os.path.join(conf.blddir, 'default'))
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
                  abi_file=None,
                  abi_match=None,
                  hide_symbols=False,
                  is_bundled=False,
                  manpages=None,
                  enabled=True):
    '''define a Samba library'''

    if not enabled:
        SET_TARGET_TYPE(bld, libname, 'DISABLED')
        return

    source = bld.EXPAND_VARIABLES(source, vars=vars)

    # remember empty libraries, so we can strip the dependencies
    if ((source == '') or (source == [])) and deps == '' and public_deps == '':
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
                        hide_symbols   = hide_symbols,
                        local_include  = local_include)

    if BUILTIN_LIBRARY(bld, libname):
        return

    if not SET_TARGET_TYPE(bld, libname, target_type):
        return

    # the library itself will depend on that object target
    deps += ' ' + public_deps
    deps = TO_LIST(deps)
    deps.append(obj_target)

    if target_type == 'PYTHON' or realname or not is_bundled:
        # Sanitize the library name
        bundled_name = libname.lower().replace('_', '-')
        while bundled_name.startswith("lib"):
            bundled_name = bundled_name[3:]
    else:
        bundled_name = BUNDLED_NAME(bld, libname, bundled_extension)

    features = 'cc cshlib symlink_lib install_lib'
    if target_type == 'PYTHON':
        features += ' pyext'
    elif needs_python:
        features += ' pyembed'
    if abi_file:
        features += ' abi_check'

    if abi_file:
        abi_file = os.path.join(bld.curdir, abi_file)

    bld.SET_BUILD_GROUP(group)
    t = bld(
        features        = features,
        source          = [],
        target          = bundled_name,
        samba_cflags    = CURRENT_CFLAGS(bld, libname, cflags),
        depends_on      = depends_on,
        samba_deps      = deps,
        samba_includes  = includes,
        local_include   = local_include,
        vnum            = vnum,
        install_path    = None,
        samba_inst_path = install_path,
        name            = libname,
        samba_realname  = realname,
        samba_install   = install,
        abi_file        = abi_file,
        abi_match       = abi_match,
        is_bundled      = is_bundled
        )

    if realname and not link_name:
        link_name = 'shared/%s' % realname

    if link_name:
        t.link_name = link_name

    if pc_files is not None:
        bld.PKG_CONFIG_FILES(pc_files, vnum=vnum)

    if manpages is not None and 'XSLTPROC_MANPAGES' in bld.env and bld.env['XSLTPROC_MANPAGES']:
        bld.MANPAGES(manpages)


Build.BuildContext.SAMBA_LIBRARY = SAMBA_LIBRARY


#################################################################
def SAMBA_BINARY(bld, binname, source,
                 deps='',
                 includes='',
                 public_headers=None,
                 header_path=None,
                 modules=None,
                 ldflags=None,
                 cflags='',
                 autoproto=None,
                 use_hostcc=False,
                 use_global_deps=True,
                 compiler=None,
                 group='binaries',
                 manpages=None,
                 local_include=True,
                 subsystem_name=None,
                 needs_python=False,
                 vars=None,
                 install=True,
                 install_path=None,
                 enabled=True):
    '''define a Samba binary'''

    if not enabled:
        SET_TARGET_TYPE(bld, binname, 'DISABLED')
        return

    if not SET_TARGET_TYPE(bld, binname, 'BINARY'):
        return

    features = 'cc cprogram symlink_bin install_bin'
    if needs_python:
        features += ' pyembed'

    obj_target = binname + '.objlist'

    source = bld.EXPAND_VARIABLES(source, vars=vars)
    source = unique_list(TO_LIST(source))

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
                        local_include  = local_include,
                        use_hostcc     = use_hostcc,
                        use_global_deps= use_global_deps)

    bld.SET_BUILD_GROUP(group)

    # the binary itself will depend on that object target
    deps = TO_LIST(deps)
    deps.append(obj_target)

    t = bld(
        features       = features,
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
        samba_inst_path= install_path,
        samba_install  = install
        )

    # setup the subsystem_name as an alias for the real
    # binary name, so it can be found when expanding
    # subsystem dependencies
    if subsystem_name is not None:
        bld.TARGET_ALIAS(subsystem_name, binname)

    if manpages is not None and 'XSLTPROC_MANPAGES' in bld.env and bld.env['XSLTPROC_MANPAGES']:
        bld.MANPAGES(manpages)

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

    source = bld.EXPAND_VARIABLES(source, vars=vars)

    if internal_module or BUILTIN_LIBRARY(bld, modname):
        # treat internal modules as subsystems for now
        if subsystem is not None:
            deps += ' ' + subsystem

        bld.SAMBA_SUBSYSTEM(modname, source,
                    deps=deps,
                    includes=includes,
                    autoproto=autoproto,
                    autoproto_extra_source=autoproto_extra_source,
                    cflags=cflags,
                    local_include=local_include,
                    enabled=enabled)

        bld.ADD_INIT_FUNCTION(subsystem, modname, init_function)
        return

    if not enabled:
        SET_TARGET_TYPE(bld, modname, 'DISABLED')
        return

    if not SET_TARGET_TYPE(bld, modname, 'MODULE'):
        return

    obj_target = modname + '.objlist'

    bld.SAMBA_SUBSYSTEM(obj_target, source,
                    deps=deps,
                    includes=includes,
                    autoproto=autoproto,
                    autoproto_extra_source=autoproto_extra_source,
                    cflags=cflags,
                    local_include=local_include,
                    enabled=enabled)

    deps = TO_LIST(deps)
    deps.append(obj_target)
    realname = modname 
    if subsystem is not None:
        deps.append(subsystem)
        while realname.startswith("lib"+subsystem+"_"):
            realname = realname[len("lib"+subsystem+"_"):]
        while realname.startswith(subsystem+"_"):
            realname = realname[len(subsystem+"_"):]
        while realname.startswith("lib"):
            realname = realname[len("lib"):]

    bld.SET_BUILD_GROUP('main')
    t = bld(
        features       = 'cc cshlib install_lib',
        source         = [],
        target         = realname,
        name           = modname,
        link_name      = "modules/%s/%s.${SHLIBEXT}" % (subsystem, realname),
        samba_cflags   = CURRENT_CFLAGS(bld, modname, cflags),
        samba_includes = includes,
        local_include  = local_include,
        samba_deps     = deps,
        install_path   = None,
        samba_inst_path= "${MODULESDIR}/%s" % subsystem,
        samba_realname = realname+ ".${SHLIBEXT}",
        vnum           = None,
        samba_install  = True,
        is_bundled     = False,
        )

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
                    use_hostcc=False,
                    use_global_deps=True,
                    vars=None,
                    hide_symbols=False,
                    needs_python=False):
    '''define a Samba subsystem'''

    if not enabled:
        SET_TARGET_TYPE(bld, modname, 'DISABLED')
        return

    # remember empty subsystems, so we can strip the dependencies
    if ((source == '') or (source == [])) and deps == '' and public_deps == '':
        SET_TARGET_TYPE(bld, modname, 'EMPTY')
        return

    if not SET_TARGET_TYPE(bld, modname, 'SUBSYSTEM'):
        return

    source = bld.EXPAND_VARIABLES(source, vars=vars)
    source = unique_list(TO_LIST(source))

    deps += ' ' + public_deps

    bld.SET_BUILD_GROUP(group)

    features = 'cc'
    if needs_python:
        features += ' pyext'

    t = bld(
        features       = features,
        source         = source,
        target         = modname,
        samba_cflags   = CURRENT_CFLAGS(bld, modname, cflags, hide_symbols=hide_symbols),
        depends_on     = depends_on,
        samba_deps     = TO_LIST(deps),
        samba_includes = includes,
        local_include  = local_include,
        local_include_first  = local_include_first,
        samba_subsystem= subsystem_name,
        samba_use_hostcc = use_hostcc,
        samba_use_global_deps = use_global_deps
        )

    if cflags_end is not None:
        t.samba_cflags.extend(TO_LIST(cflags_end))

    if heimdal_autoproto is not None:
        bld.HEIMDAL_AUTOPROTO(heimdal_autoproto, source, options=heimdal_autoproto_options)
    if heimdal_autoproto_private is not None:
        bld.HEIMDAL_AUTOPROTO_PRIVATE(heimdal_autoproto_private, source)
    if autoproto is not None:
        bld.SAMBA_AUTOPROTO(autoproto, source + TO_LIST(autoproto_extra_source))
    if public_headers is not None:
        bld.PUBLIC_HEADERS(public_headers, header_path=header_path)
    return t


Build.BuildContext.SAMBA_SUBSYSTEM = SAMBA_SUBSYSTEM


def SAMBA_GENERATOR(bld, name, rule, source='', target='',
                    group='generators', enabled=True,
                    public_headers=None,
                    header_path=None,
                    vars=None,
                    always=False):
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

    if always:
        t.always = True

    if public_headers is not None:
        bld.PUBLIC_HEADERS(public_headers, header_path=header_path)
    return t
Build.BuildContext.SAMBA_GENERATOR = SAMBA_GENERATOR



@runonce
def SETUP_BUILD_GROUPS(bld):
    '''setup build groups used to ensure that the different build
    phases happen consecutively'''
    bld.p_ln = bld.srcnode # we do want to see all targets!
    bld.env['USING_BUILD_GROUPS'] = True
    bld.add_group('setup')
    bld.add_group('build_compiler_source')
    bld.add_group('base_libraries')
    bld.add_group('generators')
    bld.add_group('compiler_prototypes')
    bld.add_group('compiler_libraries')
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
                 python_fixup=False, destname=None, base_name=None):
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
    if base_name:
        file = os.path.join(base_name, file)
    bld.install_as(dest, file, chmod=chmod)


def INSTALL_FILES(bld, destdir, files, chmod=0644, flat=False,
                  python_fixup=False, destname=None, base_name=None):
    '''install a set of files'''
    for f in TO_LIST(files):
        install_file(bld, destdir, f, chmod=chmod, flat=flat,
                     python_fixup=python_fixup, destname=destname,
                     base_name=base_name)
Build.BuildContext.INSTALL_FILES = INSTALL_FILES


def INSTALL_WILDCARD(bld, destdir, pattern, chmod=0644, flat=False,
                     python_fixup=False, exclude=None, trim_path=None):
    '''install a set of files matching a wildcard pattern'''
    files=TO_LIST(bld.path.ant_glob(pattern))
    if trim_path:
        files2 = []
        for f in files:
            files2.append(os_path_relpath(f, trim_path))
        files = files2

    if exclude:
        for f in files[:]:
            if fnmatch.fnmatch(f, exclude):
                files.remove(f)
    INSTALL_FILES(bld, destdir, files, chmod=chmod, flat=flat,
                  python_fixup=python_fixup, base_name=trim_path)
Build.BuildContext.INSTALL_WILDCARD = INSTALL_WILDCARD


def INSTALL_DIRS(bld, destdir, dirs):
    '''install a set of directories'''
    destdir = bld.EXPAND_VARIABLES(destdir)
    dirs = bld.EXPAND_VARIABLES(dirs)
    for d in TO_LIST(dirs):
        bld.install_dir(os.path.join(destdir, d))
Build.BuildContext.INSTALL_DIRS = INSTALL_DIRS


re_header = re.compile('#include[ \t]*"([^"]+)"', re.I | re.M)
class header_task(Task.Task):
    """
    The public headers (the one installed on the system) have both
    different paths and contents, so the rename is not enough.

    Intermediate .inst.h files are created because path manipulation
    may be slow. The substitution is thus performed only once.
    """

    name = 'header'
    color = 'PINK'
    vars = ['INCLUDEDIR', 'HEADER_DEPS']

    def run(self):
        txt = self.inputs[0].read(self.env)

        # hard-coded string, but only present in samba4 (I promise, you won't feel a thing)
        txt = txt.replace('#if _SAMBA_BUILD_ == 4', '#if 1\n')

        # use a regexp to substitute the #include lines in the files
        map = self.generator.bld.hnodemap
        dirnodes = self.generator.bld.hnodedirs
        def repl(m):
            if m.group(1):
                s = m.group(1)

                # pokemon headers: gotta catch'em all!
                fin = s
                if s.startswith('bin/default'):
                    node = self.generator.bld.srcnode.find_resource(s.replace('bin/default/', ''))
                    if not node:
                        Logs.warn('could not find the public header for %r' % s)
                    elif node.id in map:
                        fin = map[node.id]
                    else:
                        Logs.warn('could not find the public header replacement for build header %r' % s)
                else:
                    # this part is more difficult since the path may be relative to anything
                    for dirnode in dirnodes:
                        node = dirnode.find_resource(s)
                        if node:
                             if node.id in map:
                                 fin = map[node.id]
                                 break
                             else:
                                 Logs.warn('could not find the public header replacement for source header %r %r' % (s, node))
                    else:
                        Logs.warn('-> could not find the public header for %r' % s)

                return "#include <%s>" % fin
            return ''

        txt = re_header.sub(repl, txt)

        # and write the output file
        f = None
        try:
            f = open(self.outputs[0].abspath(self.env), 'w')
            f.write(txt)
        finally:
            if f:
                f.close()

@TaskGen.feature('pubh')
def make_public_headers(self):
    """
    collect the public headers to process and to install, then
    create the substitutions (name and contents)
    """

    if not self.bld.is_install:
        # install time only (lazy)
        return

    # keep two variables
    #    hnodedirs: list of folders for searching the headers
    #    hnodemap: node ids and replacement string (node objects are unique)
    try:
        self.bld.hnodedirs.append(self.path)
    except AttributeError:
        self.bld.hnodemap = {}
        self.bld.hnodedirs = [self.bld.srcnode, self.path]

        for k in 'source4 source4/include lib/talloc lib/tevent/ source4/lib/ldb/include/'.split():
            node = self.bld.srcnode.find_dir(k)
            if node:
                self.bld.hnodedirs.append(node)

    header_path = getattr(self, 'header_path', None) or ''

    for x in self.to_list(self.headers):

        # too complicated, but what was the original idea?
        if isinstance(header_path, list):
            add_dir = ''
            for (p1, dir) in header_path:
                lst = self.to_list(p1)
                for p2 in lst:
                    if fnmatch.fnmatch(x, p2):
                        add_dir = dir
                        break
                else:
                    continue
                break
            inst_path = add_dir
        else:
            inst_path = header_path

        dest = ''
        name = x
        if x.find(':') != -1:
            s = x.split(':')
            name = s[0]
            dest = s[1]

        inn = self.path.find_resource(name)

        if not inn:
            raise ValueError("could not find the public header %r in %r" % (name, self.path))
        out = inn.change_ext('.inst.h')
        self.create_task('header', inn, out)

        if not dest:
            dest = inn.name

        if inst_path:
            inst_path = inst_path + '/'
        inst_path = inst_path + dest

        self.bld.install_as('${INCLUDEDIR}/%s' % inst_path, out, self.env)

        self.bld.hnodemap[inn.id] = inst_path

    # create a hash (not md5) to make sure the headers are re-created if something changes
    val = 0
    lst = list(self.bld.hnodemap.keys())
    lst.sort()
    for k in lst:
        val = hash((val, k, self.bld.hnodemap[k]))
    self.bld.env.HEADER_DEPS = val

def PUBLIC_HEADERS(bld, public_headers, header_path=None):
    '''install some headers

    header_path may either be a string that is added to the INCLUDEDIR,
    or it can be a dictionary of wildcard patterns which map to destination
    directories relative to INCLUDEDIR
    '''
    bld.SET_BUILD_GROUP('final')
    ret = bld(features=['pubh'], headers=public_headers, header_path=header_path)
    return ret
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
    done_var = {}
    back_sub = [ ('PREFIX', '${prefix}'), ('EXEC_PREFIX', '${exec_prefix}')]
    for v in a:
        if re.match('@\w+@', v):
            vname = v[1:-1]
            if not vname in task.env and vname.upper() in task.env:
                vname = vname.upper()
            if not vname in task.env:
                Logs.error("Unknown substitution %s in %s" % (v, task.name))
                sys.exit(1)
            v = SUBST_VARS_RECURSIVE(task.env[vname], task.env)
            # now we back substitute the allowed pc vars
            for (b, m) in back_sub:
                s = task.env[b]
                if s == v[0:len(s)]:
                    if not b in done_var:
                        # we don't want to substitute the first usage
                        done_var[b] = True
                    else:
                        v = m + v[len(s):]
                    break
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


def MANPAGES(bld, manpages):
    '''build and install manual pages'''
    bld.env.MAN_XSL = 'http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl'
    for m in manpages.split():
        source = m + '.xml'
        bld.SAMBA_GENERATOR(m,
                            source=source,
                            target=m,
                            group='final',
                            rule='${XSLTPROC} -o ${TGT} --nonet ${MAN_XSL} ${SRC}'
                            )
        bld.INSTALL_FILES('${MANDIR}/man%s' % m[-1], m, flat=True)
Build.BuildContext.MANPAGES = MANPAGES


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

    targets    = LOCAL_CACHE(self, 'TARGET_TYPE')
    if self.name in targets:
        target_type = targets[self.name]
        type_map = { 'GENERATOR' : 'Generating',
                     'PROTOTYPE' : 'Generating'
                     }
        if target_type in type_map:
            return progress_display(self, type_map[target_type], self.name)

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
