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

LIB_PATH="shared"


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
# returns a tuple containing (systemdeps, localdeps, add_objects)
def ADD_DEPENDENCIES(bld, name, deps):
    debug('deps: Calculating dependencies for %s' % name)
    lib_deps = LOCAL_CACHE(bld, 'LIB_DEPS')
    if not name in lib_deps:
        lib_deps[name] = {}
    list = deps.split()
    list2 = []
    for d in list:
        lib_deps[name][d] = True;
        try:
            CHECK_TARGET_DEPENDENCY(bld, name)
            list2.append(d)
        except AssertionError:
            debug("deps: Removing dependency %s from target %s" % (d, name))
            del(lib_deps[name][d])

    # extract out the system dependencies
    sysdeps = []
    localdeps = []
    add_objects = []
    cache = LOCAL_CACHE(bld, 'EMPTY_TARGETS')
    target_cache = LOCAL_CACHE(bld, 'TARGET_TYPE')
    predeclare = LOCAL_CACHE(bld, 'PREDECLARED_TARGET')
    for d in list2:
        recurse = False
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
            recurse = True
        elif type == 'MODULE':
            add_objects.append(d)
            recurse = True
        elif type == 'PYTHON':
            pass
        elif type == 'ASN1':
            pass
        elif type == 'BINARY':
            pass
        else:
            ASSERT(bld, False, "Unknown target type '%s' for dependency %s" % (
                    type, d))

        # for some types we have to build the list recursively
        if recurse and (d in lib_deps):
            rec_deps = ' '.join(lib_deps[d].keys())
            (rec_sysdeps, rec_localdeps, rec_add_objects) = ADD_DEPENDENCIES(bld, d, rec_deps)
            sysdeps.extend(rec_sysdeps.split())
            localdeps.extend(rec_localdeps.split())
            add_objects.extend(rec_add_objects.split())

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
                  cflags='',
                  output_type=None,
                  realname=None,
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
    bld.SET_BUILD_GROUP('main')
    bld(
        features = 'cc cshlib',
        source = source_list,
        target=libname,
        uselib_local = localdeps,
        uselib = sysdeps,
        add_objects = add_objects,
        ccflags = CURRENT_CFLAGS(bld, cflags),
        includes='. ' + bld.env['BUILD_DIRECTORY'] + '/default ' + ilist,
        vnum=vnum)

    # put a link to the library in bin/shared
    soext=""
    if vnum is not None:
        soext = '.' + vnum.split('.')[0]
    bld.SET_BUILD_GROUP('final')
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
                 cflags='',
                 autoproto=None,
                 use_hostcc=None,
                 compiler=None,
                 group='main',
                 manpages=None):
    ilist = '. ' + bld.env['BUILD_DIRECTORY'] + '/default ' + bld.SAMBA_LIBRARY_INCLUDE_LIST(deps) + ' ' + include_list
    ilist = bld.NORMPATH(ilist)

    if not SET_TARGET_TYPE(bld, binname, 'BINARY'):
        return

    (sysdeps, localdeps, add_objects) = ADD_DEPENDENCIES(bld, binname, deps)

    cache = LOCAL_CACHE(bld, 'INIT_FUNCTIONS')
    if modules is not None:
        for m in modules.split():
            bld.ASSERT(m in cache,
                       "No init_function defined for module '%s' in binary '%s'" % (m, binname))
            cflags += ' -DSTATIC_%s_MODULES="%s"' % (m, cache[m])

    bld.SET_BUILD_GROUP(group)
    bld(
        features = 'cc cprogram',
        source = source_list,
        target = binname,
        uselib_local = localdeps,
        uselib = sysdeps,
        includes = ilist,
        ccflags = CURRENT_CFLAGS(bld, cflags),
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



#################################################################
# define a Samba ASN1 target
def SAMBA_ASN1(bld, name, source,
               options='',
               directory=''):
    if not SET_TARGET_TYPE(bld, name, 'ASN1'):
        return
    bld.SET_BUILD_GROUP('build_source')
    bld(
        features       = 'cc',
        source         = source,
        target         = name,
        asn1options    = options,
        asn1directory  = directory
    )
Build.BuildContext.SAMBA_ASN1 = SAMBA_ASN1



#################################################################
# define a Samba ET target
def SAMBA_ERRTABLE(bld, name, source,
               options='',
               directory=''):
    if not SET_TARGET_TYPE(bld, name, 'ET'):
        return
    bld.SET_BUILD_GROUP('build_source')
    bld(
        features = 'cc',
        source   = source,
        target   = name
    )
Build.BuildContext.SAMBA_ERRTABLE = SAMBA_ERRTABLE

##########################################################
# create a node with a new name, based on an existing node
def NEW_NODE(node, name):
    ret = node.parent.find_or_declare([name])
    ASSERT(node, ret is not None, "Unable to find new target with name '%s' from '%s'" % (
            name, node.name))
    return ret

#################################################################
# define a PIDL target
def SAMBA_PIDL(bld, directory, source):
    name = os.path.basename(string.replace(source, '.idl', ''))
    name = "%s/ndr_%s.o" % (directory, name)

    if not SET_TARGET_TYPE(bld, name, 'PIDL'):
        return

    bld.SET_BUILD_GROUP('build_source')
    bld(
        features = 'cc',
        source   = source,
        target   = name
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
        bld.SET_BUILD_GROUP('prototypes')
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
                 cflags='',
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
    bld.SET_BUILD_GROUP('main')
    bld(
        features = 'cc',
        source = source_list,
        target=modname,
        ccflags = CURRENT_CFLAGS(bld, cflags),
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
                    cflags='',
                    group='main',
                    config_option=None,
                    init_function_sentinal=None):

    if not SET_TARGET_TYPE(bld, modname, 'SUBSYSTEM'):
        return

    # if the caller specifies a config_option, then we create a blank
    # subsystem if that configuration option was found at configure time
    if (config_option is not None) and bld.CONFIG_SET(config_option):
            source_list = ''

    # remember empty subsystems, so we can strip the dependencies
    if (source_list == '') or (source_list == []):
        LOCAL_CACHE_SET(bld, 'EMPTY_TARGETS', modname, True)
        return

    (sysdeps, localdeps, add_objects) = ADD_DEPENDENCIES(bld, modname, deps)

    ilist = bld.SAMBA_LIBRARY_INCLUDE_LIST(deps) + bld.SUBDIR(bld.curdir, include_list)
    ilist = bld.NORMPATH(ilist)
    bld.SET_BUILD_GROUP(group)
    bld(
        features = 'cc',
        source = source_list,
        target=modname,
        ccflags = CURRENT_CFLAGS(bld, cflags),
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
    bld.env['USING_BUILD_GROUPS'] = True
    bld.add_group('setup')
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

