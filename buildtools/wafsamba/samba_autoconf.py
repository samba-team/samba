# a waf tool to add autoconf-like macros to the configure section

import Build, os, Options, preproc
import string
from Configure import conf
from samba_utils import *

missing_headers = set()

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

def hlist_to_string(conf, headers=None):
    '''convert a headers list to a set of #include lines'''
    hdrs=''
    hlist = conf.env.hlist
    if headers:
        hlist = hlist[:]
        hlist.extend(TO_LIST(headers))
    for h in hlist:
        hdrs += '#include <%s>\n' % h
    return hdrs


@feature('nolink')
def nolink(self):
    '''using the nolink type in conf.check() allows us to avoid
       the link stage of a test, thus speeding it up for tests
       that where linking is not needed'''
    pass


def CHECK_HEADER(conf, h, add_headers=False, lib=None):
    '''check for a header'''
    if h in missing_headers:
        return False
    d = h.upper().replace('/', '_')
    d = d.replace('.', '_')
    d = 'HAVE_%s' % d
    if CONFIG_SET(conf, d):
        if add_headers:
            if not h in conf.env.hlist:
                conf.env.hlist.append(h)
        return True

    (ccflags, ldflags) = library_flags(conf, lib)

    hdrs = hlist_to_string(conf, headers=h)
    ret = conf.check(fragment='%s\nint main(void) { return 0; }' % hdrs,
                     type='nolink',
                     execute=0,
                     ccflags=ccflags,
                     msg="Checking for header %s" % h)
    if not ret:
        missing_headers.add(h)
        return False

    conf.DEFINE(d, 1)
    if add_headers and not h in conf.env.hlist:
        conf.env.hlist.append(h)
    return ret


@conf
def CHECK_HEADERS(conf, headers, add_headers=False, together=False, lib=None):
    '''check for a list of headers

    when together==True, then the headers accumulate within this test.
    This is useful for interdependent headers
    '''
    ret = True
    if not add_headers and together:
        saved_hlist = conf.env.hlist[:]
        set_add_headers = True
    else:
        set_add_headers = add_headers
    for hdr in TO_LIST(headers):
        if not CHECK_HEADER(conf, hdr, set_add_headers, lib=lib):
            ret = False
    if not add_headers and together:
        conf.env.hlist = saved_hlist
    return ret


def header_list(conf, headers=None, lib=None):
    '''form a list of headers which exist, as a string'''
    hlist=[]
    if headers is not None:
        for h in TO_LIST(headers):
            if CHECK_HEADER(conf, h, add_headers=False, lib=lib):
                hlist.append(h)
    return hlist_to_string(conf, headers=hlist)


@conf
def CHECK_TYPE(conf, t, alternate=None, headers=None, define=None, lib=None, msg=None):
    '''check for a single type'''
    if define is None:
        define = 'HAVE_' + t.upper().replace(' ', '_')
    if msg is None:
        msg='Checking for %s' % t
    ret = CHECK_CODE(conf, '%s _x' % t,
                     define,
                     execute=False,
                     headers=headers,
                     local_include=False,
                     msg=msg,
                     lib=lib,
                     link=False)
    if not ret and alternate:
        conf.DEFINE(t, alternate)
    return ret


@conf
def CHECK_TYPES(conf, list, headers=None, define=None, alternate=None, lib=None):
    '''check for a list of types'''
    ret = True
    for t in TO_LIST(list):
        if not CHECK_TYPE(conf, t, headers=headers,
                          define=define, alternate=alternate, lib=lib):
            ret = False
    return ret


@conf
def CHECK_TYPE_IN(conf, t, headers=None, alternate=None, define=None):
    '''check for a single type with a header'''
    return CHECK_TYPE(conf, t, headers=headers, alternate=alternate, define=define)


@conf
def CHECK_VARIABLE(conf, v, define=None, always=False,
                   headers=None, msg=None, lib=None):
    '''check for a variable declaration (or define)'''
    if define is None:
        define = 'HAVE_%s' % v.upper()

    if msg is None:
        msg="Checking for variable %s" % v

    return CHECK_CODE(conf,
                      '''
                      #ifndef %s
                      void *_x; _x=(void *)&%s;
                      #endif
                      return 0
                      ''' % (v, v),
                      execute=False,
                      link=False,
                      msg=msg,
                      local_include=False,
                      lib=lib,
                      headers=headers,
                      define=define,
                      always=always)


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
        if not CHECK_VARIABLE(conf, v,
                              define=define,
                              headers=headers,
                              msg='Checking for declaration of %s' % v):
            ret = False
    return ret


def CHECK_FUNC(conf, f, link=None, lib=None, headers=None):
    '''check for a function'''
    define='HAVE_%s' % f.upper()

    # there are two ways to find a function. The first is
    # to see if there is a declaration of the function, the
    # 2nd is to try and link a program that calls the function
    # unfortunately both strategies have problems.
    # the 'check the declaration' approach works fine as long
    # as the function has a declaraion in a header. If there is
    # no header declaration we can get a false negative.
    # The link method works fine as long as the compiler
    # doesn't have a builtin for the function, which could cause
    # a false negative due to mismatched parameters
    # so to be sure, we need to try both
    ret = False

    if link is None or link == True:
        ret = CHECK_CODE(conf,
                         'int main(void) { extern void %s(void); %s(); return 0; }' % (f, f),
                         execute=False,
                         link=True,
                         addmain=False,
                         add_headers=False,
                         define=define,
                         local_include=False,
                         lib=lib,
                         headers=headers,
                         msg='Checking for %s' % f)

    if not ret and (link is None or link == False):
        ret = CHECK_VARIABLE(conf, f,
                             define=define,
                             headers=headers,
                             msg='Checking for declaration of %s' % f)
    return ret


@conf
def CHECK_FUNCS(conf, list, link=None, lib=None, headers=None):
    '''check for a list of functions'''
    ret = True
    for f in TO_LIST(list):
        if not CHECK_FUNC(conf, f, link=link, lib=lib, headers=headers):
            ret = False
    return ret


@conf
def CHECK_SIZEOF(conf, vars, headers=None, define=None):
    '''check the size of a type'''
    ret = True
    for v in TO_LIST(vars):
        v_define = define
        if v_define is None:
            v_define = 'SIZEOF_%s' % v.upper().replace(' ', '_')
        if not CHECK_CODE(conf,
                          'printf("%%u\\n", (unsigned)sizeof(%s))' % v,
                          define=v_define,
                          execute=True,
                          define_ret=True,
                          quote=False,
                          headers=headers,
                          local_include=False,
                          msg="Checking size of %s" % v):
            ret = False
    return ret



@conf
def CHECK_CODE(conf, code, define,
               always=False, execute=False, addmain=True,
               add_headers=True, mandatory=False,
               headers=None, msg=None, cflags='', includes='# .',
               local_include=True, lib=None, link=True,
               define_ret=False, quote=False):
    '''check if some code compiles and/or runs'''

    if CONFIG_SET(conf, define):
        return True

    if headers is not None:
        CHECK_HEADERS(conf, headers=headers, lib=lib)

    if add_headers:
        hdrs = header_list(conf, headers=headers, lib=lib)
    else:
        hdrs = ''
    if execute:
        execute = 1
    else:
        execute = 0

    if addmain:
        fragment='#include "__confdefs.h"\n%s\n int main(void) { %s; return 0; }\n' % (hdrs, code)
    else:
        fragment='#include "__confdefs.h"\n%s\n%s\n' % (hdrs, code)

    conf.write_config_header('__confdefs.h', top=True)

    if msg is None:
        msg="Checking for %s" % define

    # include the directory containing __confdefs.h
    cflags += ' -I../../default'

    if local_include:
        cflags += ' -I%s' % conf.curdir

    if not link:
        type='nolink'
    else:
        type='cprogram'

    uselib = TO_LIST(lib)

    (ccflags, ldflags) = library_flags(conf, uselib)

    cflags = TO_LIST(cflags)
    cflags.extend(ccflags)

    ret = conf.check(fragment=fragment,
                     execute=execute,
                     define_name = define,
                     mandatory = mandatory,
                     ccflags=cflags,
                     ldflags=ldflags,
                     includes=includes,
                     uselib=uselib,
                     type=type,
                     msg=msg,
                     quote=quote,
                     define_ret=define_ret)
    if not ret and CONFIG_SET(conf, define):
        # sometimes conf.check() returns false, but it
        # sets the define. Maybe a waf bug?
        ret = True
    if ret:
        if not define_ret:
            conf.DEFINE(define, 1)
        return True
    if always:
        conf.DEFINE(define, 0)
    return False



@conf
def CHECK_STRUCTURE_MEMBER(conf, structname, member,
                           always=False, define=None, headers=None):
    '''check for a structure member'''
    if define is None:
        define = 'HAVE_%s' % member.upper()
    return CHECK_CODE(conf,
                      '%s s; void *_x; _x=(void *)&s.%s' % (structname, member),
                      define,
                      execute=False,
                      link=False,
                      always=always,
                      headers=headers,
                      local_include=False,
                      msg="Checking for member %s in %s" % (member, structname))


@conf
def CHECK_CFLAGS(conf, cflags):
    '''check if the given cflags are accepted by the compiler
    '''
    return conf.check(fragment='int main(void) { return 0; }\n',
                      execute=0,
                      type='nolink',
                      ccflags=cflags,
                      msg="Checking compiler accepts %s" % cflags)


#################################################
# return True if a configuration option was found
@conf
def CONFIG_SET(conf, option):
    return (option in conf.env) and (conf.env[option] != ())
Build.BuildContext.CONFIG_SET = CONFIG_SET


def library_flags(conf, libs):
    '''work out flags from pkg_config'''
    ccflags = []
    ldflags = []
    for lib in TO_LIST(libs):
        inc_path = None
        inc_path = getattr(conf.env, 'CPPPATH_%s' % lib.upper(), [])
        lib_path = getattr(conf.env, 'LIBPATH_%s' % lib.upper(), [])
        for i in inc_path:
            ccflags.append('-I%s' % i)
        for l in lib_path:
            ldflags.append('-L%s' % l)
    return (ccflags, ldflags)


@conf
def CHECK_LIB(conf, libs, mandatory=False):
    '''check if a set of libraries exist'''

    liblist  = TO_LIST(libs)
    ret = True
    for lib in liblist[:]:
        if GET_TARGET_TYPE(conf, lib):
            continue

        (ccflags, ldflags) = library_flags(conf, lib)

        if not conf.check(lib=lib, uselib_store=lib, ccflags=ccflags, ldflags=ldflags):
            conf.ASSERT(not mandatory,
                        "Mandatory library '%s' not found for functions '%s'" % (lib, list))
            # if it isn't a mandatory library, then remove it from dependency lists
            SET_TARGET_TYPE(conf, lib, 'EMPTY')
            ret = False
        else:
            conf.define('HAVE_LIB%s' % lib.upper().replace('-','_'), 1)
            conf.env['LIB_' + lib.upper()] = lib
            LOCAL_CACHE_SET(conf, 'TARGET_TYPE', lib, 'SYSLIB')

    return ret


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
def CHECK_FUNCS_IN(conf, list, library, mandatory=False, checklibc=False, headers=None, link=None):
    remaining = TO_LIST(list)
    liblist   = TO_LIST(library)

    # check if some already found
    for f in remaining[:]:
        if CONFIG_SET(conf, 'HAVE_%s' % f.upper()):
            remaining.remove(f)

    # see if the functions are in libc
    if checklibc:
        for f in remaining[:]:
            if CHECK_FUNC(conf, f, link=True, headers=headers):
                remaining.remove(f)

    if remaining == []:
        for lib in liblist:
            if GET_TARGET_TYPE(conf, lib) != 'SYSLIB':
                SET_TARGET_TYPE(conf, lib, 'EMPTY')
        return True

    conf.CHECK_LIB(liblist)
    for lib in liblist[:]:
        if not GET_TARGET_TYPE(conf, lib) == 'SYSLIB':
            conf.ASSERT(not mandatory,
                        "Mandatory library '%s' not found for functions '%s'" % (lib, list))
            # if it isn't a mandatory library, then remove it from dependency lists
            liblist.remove(lib)
            continue

    ret = True
    for f in remaining:
        if not CHECK_FUNC(conf, f, lib=' '.join(liblist), headers=headers, link=link):
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
        conf.ADD_CFLAGS('-Wall -g -Wfatal-errors -Wshadow -Wstrict-prototypes -Wpointer-arith -Wcast-qual -Wcast-align -Wwrite-strings -Werror-implicit-function-declaration -Wformat=2 -Wno-format-y2k',
                        testflags=True)

    if Options.options.pedantic:
	conf.ADD_CFLAGS('-W', testflags=True)

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


@conf
def ADD_CFLAGS(conf, flags, testflags=False):
    '''add some CFLAGS to the command line
       optionally set testflags to ensure all the flags work
    '''
    if testflags:
        ok_flags=[]
        for f in flags.split():
            if CHECK_CFLAGS(conf, f):
                ok_flags.append(f)
        flags = ok_flags
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

@conf
def CHECK_RPATH_SUPPORT(conf):
    '''see if the system supports rpath'''
    return conf.CHECK_CODE('int x',
                           define='HAVE_RPATH_SUPPORT',
                           execute=True,
                           local_include=False,
                           msg='Checking for rpath support',
                           cflags='-Wl,-rpath=.')

@conf
def CHECK_CC_ENV(conf):
    '''trim whitespaces from 'CC'.
    The build farm sometimes puts a space at the start'''
    if os.environ.get('CC'):
        conf.env.CC = TO_LIST(os.environ.get('CC'))
        if len(conf.env.CC) == 1:
            # make for nicer logs if just a single command
            conf.env.CC = conf.env.CC[0]


@conf
def SETUP_CONFIGURE_CACHE(conf, enable):
    '''enable/disable cache of configure results'''
    if enable:
        # when -C is chosen, we will use a private cache and will
        # not look into system includes. This roughtly matches what
        # autoconf does with -C
        cache_path = os.path.join(conf.blddir, '.confcache')
        mkdir_p(cache_path)
        Options.cache_global = os.environ['WAFCACHE'] = cache_path
    else:
        # when -C is not chosen we will not cache configure checks
        # We set the recursion limit low to prevent waf from spending
        # a lot of time on the signatures of the files.
        Options.cache_global = os.environ['WAFCACHE'] = ''
        preproc.recursion_limit = 1
    # in either case we don't need to scan system includes
    preproc.go_absolute = False
