# a waf tool to add autoconf-like macros to the configure section

import Build, os, Logs, sys, Configure, Options
import string, Task, Utils, optparse
from Configure import conf
from Logs import debug
from TaskGen import extension
from samba_utils import *

####################################################
# some autoconf like helpers, to make the transition
# to waf a bit easier for those used to autoconf
# m4 files
@runonce
@conf
def DEFINE(conf, d, v):
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
        conf.DEFINE(t, alternate)

@conf
def CHECK_VARIABLE(conf, v, define=None, always=False):
    hdrs=''
    for h in conf.env.hlist:
        hdrs += '#include <%s>\n' % h
    if define is None:
        define = 'HAVE_%s' % v.upper()
    if conf.check(fragment=
                  '%s\nint main(void) {void *_x; _x=(void *)&%s; return 0;}\n' % (hdrs, v),
                  execute=0,
                  msg="Checking for variable %s" % v):
        conf.DEFINE(define, 1)
    elif always:
        conf.DEFINE(define, 0)


@runonce
def CHECK_FUNC(conf, f):
    conf.check(function_name=f, header_name=conf.env.hlist)


@conf
def CHECK_FUNCS(conf, list):
    for f in list.split():
        CHECK_FUNC(conf, f)


#################################################
# return True if a configuration option was found
@conf
def CONFIG_SET(conf, option):
    return (option in conf.env) and (conf.env[option] != ())
Build.BuildContext.CONFIG_SET = CONFIG_SET


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
    if not 'EXTRA_CFLAGS' in conf.env:
        conf.env['EXTRA_CFLAGS'] = []
    conf.env['EXTRA_CFLAGS'].extend(flags.split())

##############################################################
# add some extra include directories to all builds
@conf
def ADD_EXTRA_INCLUDES(conf, includes):
    if not 'EXTRA_INCLUDES' in conf.env:
        conf.env['EXTRA_INCLUDES'] = []
    conf.env['EXTRA_INCLUDES'].extend(includes.split())


##############################################################
# work out the current flags. local flags are added first
def CURRENT_CFLAGS(bld, cflags):
    if not 'EXTRA_CFLAGS' in bld.env:
        list = []
    else:
        list = bld.env['EXTRA_CFLAGS'];
    ret = cflags.split()
    ret.extend(list)
    return ret
