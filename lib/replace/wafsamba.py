# a waf tool to add autoconf-like macros to the configure section
# and for SAMBA_ macros for building libraries, binaries etc

import Build, os, Logs, sys, Configure, Options, string
from Configure import conf
from Logs import debug

LIB_PATH="shared"

######################################################
# this is used as a decorator to make functions only
# run once. Based on the idea from
# http://stackoverflow.com/questions/815110/is-there-a-decorator-to-simply-cache-function-return-values
runonce_ret = {}
def runonce(function):
    def wrapper(*args):
        if args in runonce_ret:
            return runonce_ret[args]
        else:
            ret = function(*args)
            runonce_ret[args] = ret
            return ret
    return wrapper


####################################################
# some autoconf like helpers, to make the transition
# to waf a bit easier for those used to autoconf
# m4 files
@runonce
@conf
def DEFUN(conf, d, v):
    conf.define(d, v, quote=False)
    conf.env.append_value('CCDEFINES', d + '=' + str(v))

@runonce
def CHECK_HEADER(conf, h):
    if conf.check(header_name=h):
        conf.env.hlist.append(h)

@conf
def CHECK_HEADERS(conf, list):
    for hdr in list.split():
        CHECK_HEADER(conf, hdr)

@conf
def CHECK_TYPES(conf, list):
    for t in list.split():
        conf.check(type_name=t, header_name=conf.env.hlist)

@conf
def CHECK_TYPE_IN(conf, t, hdr):
    if conf.check(header_name=hdr):
        conf.check(type_name=t, header_name=hdr)

@conf
def CHECK_TYPE(conf, t, alternate):
    if not conf.check(type_name=t, header_name=conf.env.hlist):
        conf.DEFUN(t, alternate)

@runonce
def CHECK_FUNC(conf, f):
    conf.check(function_name=f, header_name=conf.env.hlist)


@conf
def CHECK_FUNCS(conf, list):
    for f in list.split():
        CHECK_FUNC(conf, f)


###########################################################
# check that the functions in 'list' are available in 'library'
# if they are, then make that library available as a dependency
#
# if the library is not available and mandatory==True, then
# raise an error.
#
# If the library is not available and mandatory==False, then
# add the library to the list of dependencies to remove from
# build rules
@conf
def CHECK_FUNCS_IN(conf, list, library, mandatory=False):
    if not conf.check(lib=library, uselib_store=library):
        conf.ASSERT(not mandatory,
                    "Mandatory library '%s' not found for functions '%s'" % (library, list))
        # if it isn't a mandatory library, then remove it from dependency lists
        LOCAL_CACHE_SET(conf, 'EMPTY_TARGETS', library.upper(), True)
        return
    for f in list.split():
        conf.check(function_name=f, lib=library, header_name=conf.env.hlist)
    conf.env['LIB_' + library.upper()] = library
    LOCAL_CACHE_SET(conf, 'TARGET_TYPE', library, 'SYSLIB')


#################################################
# write out config.h in the right directory
@conf
def SAMBA_CONFIG_H(conf, path=None):
    if os.path.normpath(conf.curdir) != os.path.normpath(os.environ.get('PWD')):
        return
    if path is None:
        conf.write_config_header('config.h', top=True)
    else:
        conf.write_config_header(path)


##############################################################
# setup a configurable path
@conf
def CONFIG_PATH(conf, name, default):
    if not name in conf.env:
        conf.env[name] = conf.env['PREFIX'] + default
    conf.define(name, conf.env[name], quote=True)

##############################################################
# add some CFLAGS to the command line
@conf
def ADD_CFLAGS(conf, flags):
    conf.env.append_value('CCFLAGS', flags.split())


################################################################
# magic rpath handling
#
# we want a different rpath when installing and when building
# Note that this should really check if rpath is available on this platform
# and it should also honor an --enable-rpath option
def set_rpath(bld):
    if Options.is_install:
        if bld.env['RPATH_ON_INSTALL']:
            bld.env['RPATH'] = ['-Wl,-rpath=%s/lib' % bld.env.PREFIX]
        else:
            bld.env['RPATH'] = []
    else:
        rpath = os.path.normpath('%s/%s' % (bld.env['BUILD_DIRECTORY'], LIB_PATH))
        bld.env.append_value('RPATH', '-Wl,-rpath=%s' % rpath)
Build.BuildContext.set_rpath = set_rpath


#############################################################
# return a named build cache dictionary, used to store
# state inside the following functions
@conf
def LOCAL_CACHE(ctx, name):
    if name in ctx.env:
        return ctx.env[name]
    ctx.env[name] = {}
    return ctx.env[name]


#############################################################
# set a value in a local cache
@conf
def LOCAL_CACHE_SET(ctx, cachename, key, value):
    cache = LOCAL_CACHE(ctx, cachename)
    cache[key] = value

#############################################################
# set a value in a local cache
# return False if it's already set
def SET_TARGET_TYPE(ctx, target, value):
    cache = LOCAL_CACHE(ctx, 'TARGET_TYPE')
    if target in cache:
        ASSERT(ctx, cache[target] == value,
               "Target '%s' re-defined as %s - was %s" % (target, value, cache[target]))
        debug("task_gen: Skipping duplicate target %s (curdir=%s)" % (target, ctx.curdir))
        return False
    assumed = LOCAL_CACHE(ctx, 'ASSUMED_TARGET')
    if target in assumed:
        #if assumed[target] != value:
        #    print "Target '%s' was assumed of type '%s' but is '%s'" % (target, assumed[target], value)
        ASSERT(ctx, assumed[target] == value,
               "Target '%s' was assumed of type '%s' but is '%s'" % (target, assumed[target], value))
    predeclared = LOCAL_CACHE(ctx, 'PREDECLARED_TARGET')
    if target in predeclared:
        ASSERT(ctx, predeclared[target] == value,
               "Target '%s' was predeclared of type '%s' but is '%s'" % (target, predeclared[target], value))
    LOCAL_CACHE_SET(ctx, 'TARGET_TYPE', target, value)
    debug("task_gen: Target '%s' created of type '%s' in %s" % (target, value, ctx.curdir))
    return True


#############################################################
# a build assert call
@conf
def ASSERT(ctx, expression, msg):
    if not expression:
        sys.stderr.write("ERROR: %s\n" % msg)
        raise AssertionError
Build.BuildContext.ASSERT = ASSERT

################################################################
# create a list of files by pre-pending each with a subdir name
def SUBDIR(bld, subdir, list):
    ret = ''
    for l in list.split():
        ret = ret + subdir + '/' + l + ' '
    return ret
Build.BuildContext.SUBDIR = SUBDIR

#################################################################
# create the samba build environment
@conf
def SAMBA_BUILD_ENV(conf):
    libpath="%s/%s" % (conf.blddir, LIB_PATH)
    conf.env['BUILD_DIRECTORY'] = conf.blddir
    if not os.path.exists(libpath):
        os.mkdir(libpath)

##############################################
# remove .. elements from a path list
def NORMPATH(bld, ilist):
    return " ".join([os.path.normpath(p) for p in ilist.split(" ")])
Build.BuildContext.NORMPATH = NORMPATH

################################################################
# add an init_function to the list for a subsystem
def ADD_INIT_FUNCTION(bld, subsystem, init_function):
    if init_function is None:
        return
    bld.ASSERT(subsystem is not None, "You must specify a subsystem for init_function '%s'" % init_function)
    cache = LOCAL_CACHE(bld, 'INIT_FUNCTIONS')
    if not subsystem in cache:
        cache[subsystem] = ''
    cache[subsystem] += '%s,' % init_function
Build.BuildContext.ADD_INIT_FUNCTION = ADD_INIT_FUNCTION

#######################################################
# d1 += d2
def dict_concat(d1, d2):
    for t in d2:
        if t not in d1:
            d1[t] = d2[t]

################################################################
# recursively build the dependency list for a target
def FULL_DEPENDENCIES(bld, cache, target, chain, path):
    if not target in cache:
        return {}
    deps = cache[target].copy()
    for t in cache[target]:
        bld.ASSERT(t not in chain, "Circular dependency for %s: %s->%s" % (t, path, t));
        c2 = chain.copy()
        c2[t] = True
        dict_concat(deps, FULL_DEPENDENCIES(bld, cache, t, c2, "%s->%s" % (path, t)))
    return deps

############################################################
# check our build dependencies for circular dependencies
def CHECK_TARGET_DEPENDENCY(bld, target):
    cache = LOCAL_CACHE(bld, 'LIB_DEPS')
    return FULL_DEPENDENCIES(bld, cache, target, { target:True }, target)

############################################################
# check that all dependencies have been declared
def CHECK_DEPENDENCIES(bld):
    cache = LOCAL_CACHE(bld, 'LIB_DEPS')
    target_cache = LOCAL_CACHE(bld, 'TARGET_TYPE')
    debug('deps: Checking dependencies')
    for t in cache:
        deps = CHECK_TARGET_DEPENDENCY(bld, t)
        for d in deps:
            #if not d in target_cache:
            #    print "Dependency '%s' of target '%s' not declared" % (d, t)
            ASSERT(bld, d in target_cache,
                   "Dependency '%s' of target '%s' not declared" % (d, t))
    debug("deps: Dependencies checked for %u targets" % len(target_cache))
Build.BuildContext.CHECK_DEPENDENCIES = CHECK_DEPENDENCIES


############################################################
# pre-declare a target as being of a particular type
def PREDECLARE(bld, target, type):
    cache = LOCAL_CACHE(bld, 'PREDECLARED_TARGET')
    target_cache = LOCAL_CACHE(bld, 'TARGET_TYPE')
    ASSERT(bld, not target in target_cache, "Target '%s' is already declared" % target)
    ASSERT(bld, not target in cache, "Target '%s' already predeclared" % target)
    cache[target] = type
Build.BuildContext.PREDECLARE = PREDECLARE



################################################################
# add to the dependency list. Return a new dependency list with
# any circular dependencies removed
# returns a tuple containing (systemdeps, localdeps)
def ADD_DEPENDENCIES(bld, name, deps):
    debug('deps: Calculating dependencies for %s' % name)
    cache = LOCAL_CACHE(bld, 'LIB_DEPS')
    if not name in cache:
        cache[name] = {}
    list = deps.split()
    list2 = []
    for d in list:
        cache[name][d] = True;
        try:
            CHECK_TARGET_DEPENDENCY(bld, name)
            list2.append(d)
        except AssertionError:
            debug("deps: Removing dependency %s from target %s" % (d, name))
            del(cache[name][d])

    # extract out the system dependencies
    sysdeps = []
    localdeps = []
    add_objects = []
    cache = LOCAL_CACHE(bld, 'EMPTY_TARGETS')
    target_cache = LOCAL_CACHE(bld, 'TARGET_TYPE')
    predeclare = LOCAL_CACHE(bld, 'PREDECLARED_TARGET')
    for d in list2:
        # strip out any dependencies on empty libraries
        if d in cache:
            debug("deps: Removing empty dependency '%s' from '%s'" % (d, name))
            continue
        type = None

        if d in target_cache:
            type = target_cache[d]
        elif d in predeclare:
            type = predeclare[d]
        else:
            type = 'SUBSYSTEM'
            LOCAL_CACHE_SET(bld, 'ASSUMED_TARGET', d, type)

        if type == 'SYSLIB':
            sysdeps.append(d)
        elif type == 'LIBRARY':
            localdeps.append(d)
        elif type == 'SUBSYSTEM':
            add_objects.append(d)
        elif type == 'MODULE':
            add_objects.append(d)
        elif type == 'PYTHON':
            pass
        elif type == 'ASN1':
            pass
        else:
            ASSERT(bld, False, "Unknown target type '%s' for dependency %s" % (
                    type, d))
    debug('deps: Dependencies for %s: sysdeps: %u  localdeps: %u  add_objects=%u' % (
            name, len(sysdeps), len(localdeps), len(add_objects)))
    return (' '.join(sysdeps), ' '.join(localdeps), ' '.join(add_objects))


#################################################################
# return a include list for a set of library dependencies
def SAMBA_LIBRARY_INCLUDE_LIST(bld, deps):
    ret = bld.curdir + ' '
    cache = LOCAL_CACHE(bld, 'INCLUDE_LIST')
    for l in deps.split():
        if l in cache:
            ret = ret + cache[l] + ' '
    return ret
Build.BuildContext.SAMBA_LIBRARY_INCLUDE_LIST = SAMBA_LIBRARY_INCLUDE_LIST

#################################################################
# define a Samba library
def SAMBA_LIBRARY(bld, libname, source_list,
                  deps='',
                  public_deps='',
                  include_list='.',
                  public_headers=None,
                  vnum=None,
                  cflags=None,
                  autoproto=None):
    if not SET_TARGET_TYPE(bld, libname, 'LIBRARY'):
        return

    # remember empty libraries, so we can strip the dependencies
    if (source_list == '') or (source_list == []):
        LOCAL_CACHE_SET(bld, 'EMPTY_TARGETS', libname, True)
        return

    (sysdeps, localdeps, add_objects) = ADD_DEPENDENCIES(bld, libname, deps)

    ilist = bld.SAMBA_LIBRARY_INCLUDE_LIST(deps) + bld.SUBDIR(bld.curdir, include_list)
    ilist = bld.NORMPATH(ilist)
    bld(
        features = 'cc cshlib',
        source = source_list,
        target=libname,
        uselib_local = localdeps,
        uselib = sysdeps,
        add_objects = add_objects,
        includes='. ' + bld.env['BUILD_DIRECTORY'] + '/default ' + ilist,
        vnum=vnum)

    # put a link to the library in bin/shared
    soext=""
    if vnum is not None:
        soext = '.' + vnum.split('.')[0]
    bld(
        source = 'lib%s.so' % libname,
        rule = 'ln -sf ../${SRC}%s %s/lib%s.so%s' %
        (soext, LIB_PATH, libname, soext),
        shell = True,
        after = 'cc_link',
        )
    LOCAL_CACHE_SET(bld, 'INCLUDE_LIST', libname, ilist)

Build.BuildContext.SAMBA_LIBRARY = SAMBA_LIBRARY


#################################################################
# define a Samba binary
def SAMBA_BINARY(bld, binname, source_list,
                 deps='',
                 include_list='',
                 public_headers=None,
                 modules=None,
                 installdir=None,
                 ldflags=None,
                 cflags=None,
                 autoproto=None,
                 use_hostcc=None,
                 compiler=None,
                 manpages=None):
    ilist = '. ' + bld.env['BUILD_DIRECTORY'] + '/default ' + bld.SAMBA_LIBRARY_INCLUDE_LIST(deps) + ' ' + include_list
    ilist = bld.NORMPATH(ilist)
    ccflags = ''

    if not SET_TARGET_TYPE(bld, binname, 'BINARY'):
        return

    (sysdeps, localdeps, add_objects) = ADD_DEPENDENCIES(bld, binname, deps)

    cache = LOCAL_CACHE(bld, 'INIT_FUNCTIONS')
    if modules is not None:
        for m in modules.split():
            bld.ASSERT(m in cache,
                       "No init_function defined for module '%s' in binary '%s'" % (m, binname))
            ccflags += ' -DSTATIC_%s_MODULES="%s"' % (m, cache[m])

    bld(
        features = 'cc cprogram',
        source = source_list,
        target = binname,
        uselib_local = localdeps,
        uselib = sysdeps,
        includes = ilist,
        ccflags = ccflags,
        add_objects = add_objects,
        top=True)
    # put a link to the binary in bin/
    if not Options.is_install:
        bld(
            source = binname,
            rule = 'rm -f %s && cp ${SRC} .' % (binname),
            shell = True,
            after = 'cc_link'
            )
Build.BuildContext.SAMBA_BINARY = SAMBA_BINARY


#################################################################
# define a Samba python module
def SAMBA_PYTHON(bld, name, source_list,
                 deps='',
                 public_deps='',
                 realname=''):

    if not SET_TARGET_TYPE(bld, name, 'PYTHON'):
        return

    (sysdeps, localdeps, add_objects) = ADD_DEPENDENCIES(bld, name, deps)

    return
Build.BuildContext.SAMBA_PYTHON = SAMBA_PYTHON


###################################################################
# declare the ASN1 build pattern
@runonce
def SAMBA_ASN1_PATTERN(bld):
    bld(
        name = 'asn1_compile',
        rule = 'echo ASN1_COMPILE ${SRC} > {$TGT}',
        shall = True,
        ext_in = '.asn1',
        ext_out = '.c',
        reentrant = True,
        install = False)


#################################################################
# define a Samba ASN1 target
def SAMBA_ASN1(bld, name, source,
               options='',
               directory=''):
    import string

    if not SET_TARGET_TYPE(bld, name, 'ASN1'):
        return

    cfile = string.replace(source, '.asn1', '.c')

    # declare the pattern rule
    SAMBA_ASN1_PATTERN(bld)

    bld(source=source)

    bld(
        features = 'cc cshlib',
        source = cfile,
        target = name,
        uselib = '',
        after = 'asn1_compile'
        )
Build.BuildContext.SAMBA_ASN1 = SAMBA_ASN1


#################################################################
# define a Samba ERRTABLE target
def SAMBA_ERRTABLE(bld, name, source,
                   directory=''):
    import string
    if not SET_TARGET_TYPE(bld, name, 'ERRTABLE'):
        return
    cfile = string.replace(source, '.et', '.c')
    bld(
        source = source,
        target = cfile,
        rule = 'echo ET_COMPILE ${SRC} > {$TGT}',
        uselib = '',
        name = name)
    return
Build.BuildContext.SAMBA_ERRTABLE = SAMBA_ERRTABLE


#################################################################
# define a PIDL target
def SAMBA_PIDL(bld, directory, source):
    pidl = "../../pidl/pidl"
    idl_dir = os.path.dirname(source)
    base = os.path.basename(string.replace(source, '.idl', ''))
    rule = "pidl --outputdir %s --header --ndr-parser --server --client --python --dcom-proxy --com-header --includedir %s -- %s" % (directory, idl_dir, source)
    output = '%s/ndr_%s.c' % (directory, base)
    tname = 'PIDL_%s' % base.upper()
    bld(
        rule   = rule,
        source = source,
        target = output,
        name   = 'pidl_compile'
        )

Build.BuildContext.SAMBA_PIDL = SAMBA_PIDL



#################################################################
# define a set of Samba PIDL targets
def SAMBA_PIDL_LIST(bld, directory, source_list):
    for p in source_list.split():
        bld.SAMBA_PIDL(directory, p)
Build.BuildContext.SAMBA_PIDL_LIST = SAMBA_PIDL_LIST


################################################################
# build a C prototype file automatically
def AUTOPROTO(bld, header, source_list):
    if header is not None:
        bld(
            source = source_list,
            target = header,
            rule = '../script/mkproto.pl --srcdir=.. --builddir=. --public=/dev/null --private=${TGT} ${SRC}'
            )
Build.BuildContext.AUTOPROTO = AUTOPROTO


#################################################################
# define a Samba module.
def SAMBA_MODULE(bld, modname, source_list,
                 deps='',
                 include_list='.',
                 subsystem=None,
                 init_function=None,
                 autoproto=None,
                 aliases=None,
                 cflags=None,
                 output_type=None):

    if not SET_TARGET_TYPE(bld, modname, 'MODULE'):
        return

    # remember empty modules, so we can strip the dependencies
    if (source_list == '') or (source_list == []):
        LOCAL_CACHE_SET(bld, 'EMPTY_TARGETS', modname, True)
        return

    (sysdeps, localdeps, add_objects) = ADD_DEPENDENCIES(bld, modname, deps)

    ilist = bld.SAMBA_LIBRARY_INCLUDE_LIST(deps) + bld.SUBDIR(bld.curdir, include_list)
    ilist = bld.NORMPATH(ilist)
    bld(
        features = 'cc',
        source = source_list,
        target=modname,
# we don't supply dependencies here, as this is just a compile, not a link
#        uselib_local = localdeps,
#        uselib = sysdeps,
#        add_objects = add_objects,
        includes='. ' + bld.env['BUILD_DIRECTORY'] + '/default ' + ilist)
Build.BuildContext.SAMBA_MODULE = SAMBA_MODULE


#################################################################
# define a Samba subsystem
def SAMBA_SUBSYSTEM(bld, modname, source_list,
                    deps='',
                    public_deps='',
                    include_list='.',
                    public_headers=None,
                    autoproto=None,
                    cflags=None,
                    init_function_sentinal=None):

    if not SET_TARGET_TYPE(bld, modname, 'SUBSYSTEM'):
        return

    # remember empty subsystems, so we can strip the dependencies
    if (source_list == '') or (source_list == []):
        LOCAL_CACHE_SET(bld, 'EMPTY_TARGETS', modname, True)
        return

    (sysdeps, localdeps, add_objects) = ADD_DEPENDENCIES(bld, modname, deps)

    ilist = bld.SAMBA_LIBRARY_INCLUDE_LIST(deps) + bld.SUBDIR(bld.curdir, include_list)
    ilist = bld.NORMPATH(ilist)
    bld(
        features = 'cc',
        source = source_list,
        target=modname,
# we don't supply dependencies here, as this is just a compile, not a link
#        uselib_local = localdeps,
#        uselib = sysdeps,
#        add_objects = add_objects,
        includes='. ' + bld.env['BUILD_DIRECTORY'] + '/default ' + ilist)
Build.BuildContext.SAMBA_SUBSYSTEM = SAMBA_SUBSYSTEM


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


############################################################
# this overrides the 'waf -v' debug output to be in a nice
# unix like format instead of a python list.
# Thanks to ita on #waf for this
def exec_command(self, cmd, **kw):
    import Utils, Logs
    _cmd = cmd
    if isinstance(cmd, list):
        _cmd = ' '.join(cmd)
    debug('runner: %s' % _cmd)
    if self.log:
        self.log.write('%s\n' % cmd)
        kw['log'] = self.log
    try:
        if not kw.get('cwd', None):
            kw['cwd'] = self.cwd
    except AttributeError:
        self.cwd = kw['cwd'] = self.bldnode.abspath()
    return Utils.exec_command(cmd, **kw)
Build.BuildContext.exec_command = exec_command


###########################################################
# list the build targets
def cmd_list(ctx):
    '''List the build targets'''
    import Utils, Environment
    proj = Environment.Environment(Options.lockfile)
    bld_cls = getattr(Utils.g_module, 'build_context', Utils.Context)
    bld = bld_cls()
    bld.load_dirs(proj['srcdir'], proj['blddir'])
    bld.load_envs()
    targets = bld.env['TARGET_TYPE']
    for t in targets:
        print "Target %20s of type %s" % (t, targets[t])


###########################################################
# add some extra top level targets
@runonce
def add_extra_targets():
    import Utils
    setattr(Utils.g_module, 'list', cmd_list)

