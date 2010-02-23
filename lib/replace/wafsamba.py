# a waf tool to add autoconf-like macros to the configure section
# and for SAMBA_ macros for building libraries, binaries etc

import Build, os, Logs, sys, Configure, Options
from Configure import conf

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

@conf
def CHECK_FUNCS_IN(conf, list, library):
    if conf.check(lib=library, uselib_store=library):
        for f in list.split():
            conf.check(function_name=f, lib=library, header_name=conf.env.hlist)
        conf.env['LIB_' + library.upper()] = library


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
        rpath = os.path.normpath('%s/bin/%s' % (bld.curdir, LIB_PATH))
        bld.env.append_value('RPATH', '-Wl,-rpath=%s' % rpath)
Build.BuildContext.set_rpath = set_rpath


#############################################################
# return a named build cache dictionary, used to store
# state inside the following functions
def BUILD_CACHE(bld, name):
    try:
        cache = bld.name
    except AttributeError:
        bld.name = cache = {}
    return cache


#############################################################
# a build assert call
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
    cache = BUILD_CACHE(bld, 'INIT_FUNCTIONS')
    if not subsystem in cache:
        cache[subsystem] = ''
    cache[subsystem] += '%s,' % init_function
Build.BuildContext.ADD_INIT_FUNCTION = ADD_INIT_FUNCTION


#################################################################
# return a include list for a set of library dependencies
def SAMBA_LIBRARY_INCLUDE_LIST(bld, deps):
    ret = bld.curdir + ' '
    cache = BUILD_CACHE(bld, 'INCLUDE_LIST')
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
    # print "Declaring SAMBA_LIBRARY %s" % libname
    ilist = bld.SAMBA_LIBRARY_INCLUDE_LIST(deps) + bld.SUBDIR(bld.curdir, include_list)
    ilist = bld.NORMPATH(ilist)
    bld(
        features = 'cc cshlib',
        source = source_list,
        target=libname,
        uselib_local = deps,
        includes='. ' + os.environ.get('PWD') + '/bin/default ' + ilist,
        vnum=vnum)

    # put a link to the library in bin/shared
    soext=""
    if vnum is not None:
        soext = '.' + vnum.split('.')[0]
    bld(
        source = 'lib%s.so' % libname,
        target = '%s.lnk' % libname,
        rule = 'ln -sf ../${SRC}%s %s/lib%s.so%s && touch ${TGT}' %
        (soext, LIB_PATH, libname, soext),
        shell = True
        )
    cache = BUILD_CACHE(bld, 'INCLUDE_LIST')
    cache[libname] = ilist
Build.BuildContext.SAMBA_LIBRARY = SAMBA_LIBRARY


#################################################################
# define a Samba binary
def SAMBA_BINARY(bld, binname, source_list,
                 deps='',
                 syslibs='',
                 include_list='',
                 public_headers=None,
                 modules=None,
                 installdir=None,
                 ldflags=None,
                 cflags=None,
                 autoproto=None,
                 manpages=None):
    ilist = '. ' + os.environ.get('PWD') + '/bin/default ' + bld.SAMBA_LIBRARY_INCLUDE_LIST(deps) + ' ' + include_list
    ilist = bld.NORMPATH(ilist)
    ccflags = ''

    cache = BUILD_CACHE(bld, 'INIT_FUNCTIONS')
    if modules is not None:
        for m in modules.split():
            bld.ASSERT(m in cache,
                       "No init_function defined for module '%s' in binary '%s'" % (m, binname))
            ccflags += ' -DSTATIC_%s_MODULES="%s"' % (m, cache[m])

    bld(
        features = 'cc cprogram',
        source = source_list,
        target = binname,
        uselib_local = deps,
        uselib = syslibs,
        includes = ilist,
        ccflags = ccflags,
        top=True)
    # put a link to the binary in bin/
    bld(
        source = binname,
        rule = 'ln -sf ${SRC} .',
        )
Build.BuildContext.SAMBA_BINARY = SAMBA_BINARY


#################################################################
# define a Samba python module
def SAMBA_PYTHON(bld, name, source_list,
                 deps='',
                 public_deps='',
                 realname=''):
    Logs.debug('runner: PYTHON_SAMBA not implemented')
    return
Build.BuildContext.SAMBA_PYTHON = SAMBA_PYTHON


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
    bld.ADD_INIT_FUNCTION(subsystem, init_function)
    bld.AUTOPROTO(autoproto, source_list)
    bld.SAMBA_LIBRARY(modname, source_list,
                      deps=deps, include_list=include_list)
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
    bld.SAMBA_LIBRARY(modname, source_list,
                      deps=deps, include_list=include_list)
Build.BuildContext.SAMBA_SUBSYSTEM = SAMBA_SUBSYSTEM


###############################################################
# add a new set of build rules from a subdirectory
# the @runonce decorator ensures we don't end up
# with duplicate rules
@runonce
def BUILD_SUBDIR(bld, dir):
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
    Logs.debug('runner: %s' % _cmd)
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


