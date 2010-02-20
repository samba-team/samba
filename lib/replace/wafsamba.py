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
    for hdr in list.rsplit(' '):
        if conf.check(header_name=hdr):
            conf.env.hlist.append(hdr)

@conf
def CHECK_TYPES(conf, list):
    for t in list.rsplit(' '):
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
    for f in list.rsplit(' '):
        conf.check(function_name=f, header_name=conf.env.hlist)

@conf
def CHECK_FUNCS_IN(conf, list, library):
    if conf.check(lib=library, uselib_store=library):
        for f in list.rsplit(' '):
            conf.check(function_name=f, lib=library, header_name=conf.env.hlist)

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
# this will contain the set of includes needed per Samba library
Build.BuildContext.SAMBA_LIBRARY_INCLUDES = {}

################################################################
# this will contain the library dependencies of each Samba library
Build.BuildContext.SAMBA_LIBRARY_DEPS = {}

#################################################################
# return a include list for a set of library dependencies
def SAMBA_LIBRARY_INCLUDE_LIST(bld, libdeps):
    ret = bld.curdir + ' '
    for l in libdeps.rsplit(' '):
        if l in bld.SAMBA_LIBRARY_INCLUDES:
            ret = ret + bld.SAMBA_LIBRARY_INCLUDES[l] + ' '
    return ret
Build.BuildContext.SAMBA_LIBRARY_INCLUDE_LIST = SAMBA_LIBRARY_INCLUDE_LIST


#################################################################
# define a Samba library
def SAMBA_LIBRARY(bld, libname, source_list, libdeps='', include_list=''):
    ilist = bld.SAMBA_LIBRARY_INCLUDE_LIST(libdeps) + include_list
    bld(
        features = 'cc cshlib',
        source = source_list,
        target=libname,
        includes=ilist)
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
        includes = bld.SAMBA_LIBRARY_INCLUDE_LIST(libdeps) + include_list)
Build.BuildContext.SAMBA_BINARY = SAMBA_BINARY

############################################################
# this overrides the normal -v debug output to be in a nice
# unix like format. Thanks to ita on #waf for this
def exec_command(self, cmd, **kw):
    import Utils
    from Logs import debug
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

import Build
Build.BuildContext.exec_command = exec_command
