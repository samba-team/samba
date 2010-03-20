# a waf tool to add autoconf-like macros to the configure section

import Build, os, Options
import string
from Configure import conf
from samba_utils import *

####################################################
# some autoconf like helpers, to make the transition
# to waf a bit easier for those used to autoconf
# m4 files

@runonce
@conf
def DEFINE(conf, d, v, add_to_cflags=False):
    '''define a config option'''
    conf.define(d, v, quote=False)
    if add_to_cflags:
        conf.env.append_value('CCDEFINES', d + '=' + str(v))


def CHECK_HEADER(conf, h, add_headers=True):
    '''check for a header'''
    d = 'HAVE_%s' % string.replace(h.upper(), '/', '_')
    if CONFIG_SET(conf, d):
        if add_headers:
            conf.env.hlist.append(h)
            conf.env.hlist = unique_list(conf.env.hlist)
        return True
    ret = conf.check(header_name=h)
    if ret and add_headers:
        conf.env.hlist.append(h)
        conf.env.hlist = unique_list(conf.env.hlist)
    return ret


@conf
def CHECK_HEADERS(conf, list, add_headers=True):
    '''check for a list of headers'''
    ret = True
    for hdr in TO_LIST(list):
        if not CHECK_HEADER(conf, hdr, add_headers):
            ret = False
    return ret


@conf
def CHECK_TYPES(conf, list):
    '''check for a list of types'''
    ret = True
    lst = TO_LIST(list)
    for t in TO_LIST(list):
        if not conf.check(type_name=t, header_name=conf.env.hlist):
            ret = False
    return ret


@conf
def CHECK_TYPE_IN(conf, t, hdr, define=None):
    '''check for a type in a specific header'''
    if conf.check(header_name=hdr):
        if define is None:
            ret = conf.check(type_name=t, header_name=hdr)
        else:
            ret = conf.check(type_name=t, header_name=hdr, define_name=define)
        return ret
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
        hlist = TO_LIST(headers)
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
    for v in TO_LIST(vars):
        if not reverse:
            define='HAVE_DECL_%s' % v.upper()
        else:
            define='HAVE_%s_DECL' % v.upper()
        if not CHECK_VARIABLE(conf, v, define=define, headers=headers):
            ret = False
    return ret


def CHECK_FUNC(conf, f, checklink=False, header=''):
    '''check for a function'''
    hlist = conf.env.hlist[:]
    for h in TO_LIST(header):
        if CHECK_HEADER(conf, h, add_headers=False):
            hlist.append(h)
    define='HAVE_%s' % f.upper()
    if CONFIG_SET(conf, define):
        return True
    if checklink:
        return CHECK_CODE(conf, 'void *x = (void *)%s' % f,
                          execute=False, define=define,
                          msg='Checking for %s' % f)

    return conf.check_cc(function_name=f, header_name=hlist)


@conf
def CHECK_FUNCS(conf, list, checklink=False, header=''):
    '''check for a list of functions'''
    ret = True
    for f in TO_LIST(list):
        if not CHECK_FUNC(conf, f, checklink=checklink, header=header):
            ret = False
    return ret


@conf
def CHECK_SIZEOF(conf, vars, headers=None, define=None):
    '''check the size of a type'''
    hdrs=''
    if headers is not None:
        hlist = TO_LIST(headers)
    else:
        hlist = conf.env.hlist
    for h in hlist:
        hdrs += '#include <%s>\n' % h
    for v in TO_LIST(vars):
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
def CHECK_CODE(conf, code, define,
               always=False, execute=False, addmain=True, mandatory=False,
               headers=None, msg=None, cflags='', includes='# .',
               local_include=True):
    '''check if some code compiles and/or runs'''
    hdrs=''
    if headers is not None:
        hlist = TO_LIST(headers)
    else:
        hlist = conf.env.hlist
    for h in hlist:
        hdrs += '#include <%s>\n' % h

    if execute:
        execute = 1
    else:
        execute = 0

    if addmain:
        fragment='#include "__confdefs.h"\n%s\n int main(void) { %s; return 0; }' % (hdrs, code)
    else:
        fragment='#include "__confdefs.h"\n%s\n%s' % (hdrs, code)

    conf.write_config_header('__confdefs.h', top=True)

    if msg is None:
        msg="Checking for %s" % define

    # include the directory containing __confdefs.h
    cflags += ' -I../../default'

    if local_include:
        cflags += ' -I%s' % conf.curdir

    if conf.check(fragment=fragment,
                  execute=execute,
                  define_name = define,
                  mandatory = mandatory,
                  ccflags=TO_LIST(cflags),
                  includes=includes,
                  msg=msg):
        conf.DEFINE(define, 1)
        return True
    if always:
        conf.DEFINE(define, 0)
    return False



@conf
def CHECK_STRUCTURE_MEMBER(conf, structname, member,
                           always=False, define=None, headers=None):
    '''check for a structure member'''
    hdrs=''
    if headers is not None:
        hlist = TO_LIST(headers)
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


@conf
def CHECK_CFLAGS(conf, cflags, variable):
    '''check if the given cflags are accepted by the compiler'''
    if conf.check(fragment='int main(void) { return 0; }',
                  execute=0,
                  ccflags=cflags,
                  msg="Checking compiler accepts %s" % cflags):
        conf.env[variable] = cflags
        return True
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
def CHECK_FUNCS_IN(conf, list, library, mandatory=False, checklibc=False, header=''):
    remaining = TO_LIST(list)
    liblist   = TO_LIST(library)

    hlist = conf.env.hlist[:]
    for h in TO_LIST(header):
        if CHECK_HEADER(conf, h, add_headers=False):
            hlist.append(h)

    # check if some already found
    for f in remaining[:]:
        if CONFIG_SET(conf, 'HAVE_%s' % f.upper()):
            remaining.remove(f)

    # see if the functions are in libc
    if checklibc:
        for f in remaining[:]:
            if CHECK_FUNC(conf, f, checklink=True, header=header):
                remaining.remove(f)

    if remaining == []:
        for lib in liblist:
            if GET_TARGET_TYPE(conf, lib) != 'SYSLIB':
                SET_TARGET_TYPE(conf, lib, 'EMPTY')
        return True

    ret = True
    for lib in liblist[:]:
        if GET_TARGET_TYPE(conf, lib):
            continue
        if not conf.check(lib=lib, uselib_store=lib):
            conf.ASSERT(not mandatory,
                        "Mandatory library '%s' not found for functions '%s'" % (lib, list))
            # if it isn't a mandatory library, then remove it from dependency lists
            SET_TARGET_TYPE(conf, lib, 'EMPTY')
            ret = False
        else:
            conf.define('HAVE_LIB%s' % string.replace(lib.upper(),'-','_'), 1)
            conf.env['LIB_' + lib.upper()] = lib
            LOCAL_CACHE_SET(conf, 'TARGET_TYPE', lib, 'SYSLIB')

    if not ret:
        return ret

    ret = True
    for f in remaining:
        if not conf.check_cc(function_name=f, lib=liblist, header_name=hlist):
            ret = False

    return ret


#################################################
# write out config.h in the right directory
@conf
def SAMBA_CONFIG_H(conf, path=None):
    # we don't want to produce a config.h in places like lib/replace
    # when we are building projects that depend on lib/replace
    if os.path.realpath(conf.curdir) != os.path.realpath(Options.launch_dir):
        return

    if Options.options.developer:
        # we add these here to ensure that -Wstrict-prototypes is not set during configure
        conf.ADD_CFLAGS('-Wall -g -Wfatal-errors -Wshadow -Wstrict-prototypes -Wpointer-arith -Wcast-qual -Wcast-align -Wwrite-strings -Werror-implicit-function-declaration -Wformat=2 -Wno-format-y2k')

    if path is None:
        conf.write_config_header('config.h', top=True)
    else:
        conf.write_config_header(path)


##############################################################
# setup a configurable path
@conf
def CONFIG_PATH(conf, name, default):
    if not name in conf.env:
        if default[0] == '/':
            conf.env[name] = default
        else:
            conf.env[name] = conf.env['PREFIX'] + default
    conf.define(name, conf.env[name], quote=True)

##############################################################
# add some CFLAGS to the command line
@conf
def ADD_CFLAGS(conf, flags):
    if not 'EXTRA_CFLAGS' in conf.env:
        conf.env['EXTRA_CFLAGS'] = []
    conf.env['EXTRA_CFLAGS'].extend(TO_LIST(flags))

##############################################################
# add some extra include directories to all builds
@conf
def ADD_EXTRA_INCLUDES(conf, includes):
    if not 'EXTRA_INCLUDES' in conf.env:
        conf.env['EXTRA_INCLUDES'] = []
    conf.env['EXTRA_INCLUDES'].extend(TO_LIST(includes))


##############################################################
# work out the current flags. local flags are added first
def CURRENT_CFLAGS(bld, target, cflags):
    if not 'EXTRA_CFLAGS' in bld.env:
        list = []
    else:
        list = bld.env['EXTRA_CFLAGS'];
    ret = TO_LIST(cflags)
    ret.extend(list)
    return ret
