# a waf tool to add autoconf-like macros to the configure section
# and for SAMBA_ macros for building libraries, binaries etc

import Build
from Configure import conf


####################################################
# some autoconf like helpers, to make the transition
# to waf a bit easier for those used to autoconf
# m4 files
@conf
def DEFUN(conf, d, v):
    conf.define(d, v, quote=False)
    conf.env.append_value('CCDEFINES', d + '=' + str(v))

@conf
def CHECK_HEADERS(conf, list):
    for hdr in list.split():
        if conf.check(header_name=hdr):
            conf.env.hlist.append(hdr)

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

@conf
def CHECK_FUNCS(conf, list):
    for f in list.split():
        conf.check(function_name=f, header_name=conf.env.hlist)

@conf
def CHECK_FUNCS_IN(conf, list, library):
    if conf.check(lib=library, uselib_store=library):
        for f in list.split():
            conf.check(function_name=f, lib=library, header_name=conf.env.hlist)

#################################################
# write out config.h in the right directory
@conf
def SAMBA_CONFIG_H(conf):
    import os
    if os.path.normpath(conf.curdir) == os.path.normpath(conf.srcdir):
        conf.write_config_header('config.h')


################################################################
# magic rpath handling
#
# we want a different rpath when installing and when building
# Note that this should really check if rpath is available on this platform
# and it should also honor an --enable-rpath option
def set_rpath(bld):
    import Options
    if Options.is_install:
        bld.env['RPATH'] = ['-Wl,-rpath=' + bld.env.PREFIX + '/lib']
    else:
        bld.env.append_value('RPATH', '-Wl,-rpath=build/default')
Build.BuildContext.set_rpath = set_rpath


################################################################
# create a list of files by pre-pending each with a subdir name
def SUBDIR(bld, subdir, list):
    ret = ''
    for l in list.split():
        ret = ret + subdir + '/' + l + ' '
    return ret
Build.BuildContext.SUBDIR = SUBDIR

################################################################
# this will contain the set of includes needed per Samba library
Build.BuildContext.SAMBA_LIBRARY_INCLUDES = {}

################################################################
# this will contain the library dependencies of each Samba library
Build.BuildContext.SAMBA_LIBRARY_DEPS = {}

#################################################################
# return a include list for a set of library dependencies
def SAMBA_LIBRARY_INCLUDE_LIST(bld, libdeps):
    ret = bld.curdir + ' '
    for l in libdeps.split():
        if l in bld.SAMBA_LIBRARY_INCLUDES:
            ret = ret + bld.SAMBA_LIBRARY_INCLUDES[l] + ' '
    return ret
Build.BuildContext.SAMBA_LIBRARY_INCLUDE_LIST = SAMBA_LIBRARY_INCLUDE_LIST


#################################################################
# define a Samba library
def SAMBA_LIBRARY(bld, libname, source_list,
                  libdeps='', include_list='.', vnum=None):
    ilist = bld.SAMBA_LIBRARY_INCLUDE_LIST(libdeps) + bld.SUBDIR(bld.curdir, include_list)
    bld(
        features = 'cc cshlib',
        source = source_list,
        target=libname,
        includes='. ' + ilist,
        vnum=vnum)
    bld.SAMBA_LIBRARY_INCLUDES[libname] = ilist
Build.BuildContext.SAMBA_LIBRARY = SAMBA_LIBRARY

#################################################################
# define a Samba binary
def SAMBA_BINARY(bld, binname, source_list, libdeps='', include_list=''):
    bld(
        features = 'cc cprogram',
        source = source_list,
        target = binname,
        uselib_local = libdeps,
        includes = '. ' + bld.SAMBA_LIBRARY_INCLUDE_LIST(libdeps) + include_list)
Build.BuildContext.SAMBA_BINARY = SAMBA_BINARY

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
