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
    '''define a config option'''
    conf.define(d, v, quote=False)
    conf.env.append_value('CCDEFINES', d + '=' + str(v))

@runonce
def CHECK_HEADER(conf, h, add_headers=True):
    '''check for a header'''
    if conf.check(header_name=h) and add_headers:
        conf.env.hlist.append(h)
        return True
    return False


@conf
def CHECK_HEADERS(conf, list, add_headers=True):
    '''check for a list of headers'''
    ret = True
    for hdr in to_list(list):
        if not CHECK_HEADER(conf, hdr, add_headers):
            ret = False
    return ret


@conf
def CHECK_TYPES(conf, list):
    '''check for a list of types'''
    ret = True
    for t in to_list(list):
        if not conf.check(type_name=t, header_name=conf.env.hlist):
            ret = False
    return ret


@conf
def CHECK_TYPE_IN(conf, t, hdr):
    '''check for a type in a specific header'''
    if conf.check(header_name=hdr):
        conf.check(type_name=t, header_name=hdr)
        return True
    return False


@conf
def CHECK_TYPE(conf, t, alternate=None, headers=None, define=None):
    '''check for a type with an alternate'''
    if headers is None:
        headers = conf.env.hlist
    if define is not None:
        ret = conf.check(type_name=t, header_name=headers, define_name=define)
    else:
        ret = conf.check(type_name=t, header_name=headers)
    if not ret and alternate is not None:
        conf.DEFINE(t, alternate)
    return ret


@conf
def CHECK_VARIABLE(conf, v, define=None, always=False, headers=None):
    '''check for a variable declaration (or define)'''
    hdrs=''
    if headers is not None:
        hlist = to_list(headers)
    else:
        hlist = conf.env.hlist
    for h in hlist:
        hdrs += '#include <%s>\n' % h
    if define is None:
        define = 'HAVE_%s' % v.upper()
    if conf.check(fragment=
                  '''
                  %s
                  int main(void) {
                    #ifndef %s
                    void *_x; _x=(void *)&%s;
                    #endif
                    return 0;
                  }
                  ''' % (hdrs, v, v),
                  execute=0,
                  msg="Checking for variable %s" % v):
        conf.DEFINE(define, 1)
        return True
    elif always:
        conf.DEFINE(define, 0)
        return False

@conf
def CHECK_DECLS(conf, vars, reverse=False, headers=None):
    '''check a list of variable declarations, using the HAVE_DECL_xxx form
       of define

       When reverse==True then use HAVE_xxx_DECL instead of HAVE_DECL_xxx
       '''
    ret = True
    for v in to_list(vars):
        if not reverse:
            define='HAVE_DECL_%s' % v.upper()
        else:
            define='HAVE_%s_DECL' % v.upper()
        if not CHECK_VARIABLE(conf, v, define=define, headers=headers):
            ret = False
    return ret


@runonce
def CHECK_FUNC(conf, f):
    '''check for a function'''
    return conf.check(function_name=f, header_name=conf.env.hlist)


@conf
def CHECK_FUNCS(conf, list):
    '''check for a list of functions'''
    ret = True
    for f in to_list(list):
        if not CHECK_FUNC(conf, f):
            ret = False
    return ret


@conf
def CHECK_SIZEOF(conf, vars, headers=None, define=None):
    '''check the size of a type'''
    hdrs=''
    if headers is not None:
        hlist = to_list(headers)
    else:
        hlist = conf.env.hlist
    for h in hlist:
        hdrs += '#include <%s>\n' % h
    for v in to_list(vars):
        if define is None:
            define_name = 'SIZEOF_%s' % string.replace(v.upper(), ' ', '_')
        else:
            define_name = define
        conf.check(fragment=
                   '''
                  %s
                  int main(void) {
                    printf("%%u\\n", (unsigned)sizeof(%s));
                    return 0;
                  }
                  ''' % (hdrs, v),
                   execute=1,
                   define_ret=True,
                   define_name=define_name,
                   quote=False,
                   msg="Checking size of %s" % v)


@conf
def CHECK_CODE_COMPILES(conf, code, define,
                        always=False, headers=None):
    '''check if some code compiles'''
    hdrs=''
    if headers is not None:
        hlist = to_list(headers)
    else:
        hlist = conf.env.hlist
    for h in hlist:
        hdrs += '#include <%s>\n' % h
    if conf.check(fragment='''
                  %s
                  int main(void) {
                    %s;
                    return 0;
                  }
                  ''' % (hdrs, code),
                  execute=0,
                  msg="Checking %s" % define):
        conf.DEFINE(define, 1)
        return True
    elif always:
        conf.DEFINE(define, 0)
        return False


@conf
def CHECK_STRUCTURE_MEMBER(conf, structname, member,
                           always=False, define=None, headers=None):
    '''check for a structure member'''
    hdrs=''
    if headers is not None:
        hlist = to_list(headers)
    else:
        hlist = conf.env.hlist
    for h in hlist:
        hdrs += '#include <%s>\n' % h
    if define is None:
        define = 'HAVE_%s' % member.upper()
    if conf.check(fragment=
                  '''
                  %s
                  int main(void) {
                    %s s;
                    void *_x; _x=(void *)&s.%s;
                    return 0;
                  }
                  ''' % (hdrs, structname, member),
                  execute=0,
                  msg="Checking for member %s in %s" % (member, structname)):
        conf.DEFINE(define, 1)
        return True
    elif always:
        conf.DEFINE(define, 0)
        return False


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
#
# optionally check for the functions first in libc
@conf
def CHECK_FUNCS_IN(conf, list, library, mandatory=False, checklibc=False):
    # first see if the functions are in libc
    if checklibc:
        remaining = []
        for f in to_list(list):
            if not CHECK_FUNC(conf, f):
                remaining.append(f)
    else:
        remaining = to_list(list)

    if remaining == []:
        LOCAL_CACHE_SET(conf, 'EMPTY_TARGETS', library.upper(), True)
        return True

    if not conf.check(lib=library, uselib_store=library):
        conf.ASSERT(not mandatory,
                    "Mandatory library '%s' not found for functions '%s'" % (library, list))
        # if it isn't a mandatory library, then remove it from dependency lists
        LOCAL_CACHE_SET(conf, 'EMPTY_TARGETS', library.upper(), True)
        return False

    ret = True
    for f in remaining:
        if not conf.check(function_name=f, lib=library, header_name=conf.env.hlist):
            ret = False
    conf.env['LIB_' + library.upper()] = library
    LOCAL_CACHE_SET(conf, 'TARGET_TYPE', library, 'SYSLIB')
    return ret


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
    conf.env['EXTRA_CFLAGS'].extend(to_list(flags))

##############################################################
# add some extra include directories to all builds
@conf
def ADD_EXTRA_INCLUDES(conf, includes):
    if not 'EXTRA_INCLUDES' in conf.env:
        conf.env['EXTRA_INCLUDES'] = []
    conf.env['EXTRA_INCLUDES'].extend(to_list(includes))


##############################################################
# work out the current flags. local flags are added first
def CURRENT_CFLAGS(bld, cflags):
    if not 'EXTRA_CFLAGS' in bld.env:
        list = []
    else:
        list = bld.env['EXTRA_CFLAGS'];
    ret = to_list(cflags)
    ret.extend(list)
    return ret
