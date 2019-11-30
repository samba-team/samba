# a waf tool to add autoconf-like macros to the configure section

import os, sys
from waflib import Build, Options, Logs, Context
from waflib.Configure import conf
from waflib.TaskGen import feature
from waflib.Tools import c_preproc as preproc
from samba_utils import TO_LIST, GET_TARGET_TYPE, SET_TARGET_TYPE, unique_list, mkdir_p

missing_headers = set()

####################################################
# some autoconf like helpers, to make the transition
# to waf a bit easier for those used to autoconf
# m4 files

@conf
def DEFINE(conf, d, v, add_to_cflags=False, quote=False):
    '''define a config option'''
    conf.define(d, v, quote=quote)
    if add_to_cflags:
        conf.env.append_value('CFLAGS', '-D%s=%s' % (d, str(v)))

def hlist_to_string(conf, headers=None):
    '''convert a headers list to a set of #include lines'''
    hlist = conf.env.hlist
    if headers:
        hlist = hlist[:]
        hlist.extend(TO_LIST(headers))
    hdrs = "\n".join('#include <%s>' % h for h in hlist)

    return hdrs


@conf
def COMPOUND_START(conf, msg):
    '''start a compound test'''
    def null_check_message_1(self,*k,**kw):
        return
    def null_check_message_2(self,*k,**kw):
        return

    v = getattr(conf.env, 'in_compound', [])
    if v != [] and v != 0:
        conf.env.in_compound = v + 1
        return
    conf.start_msg(msg)
    conf.saved_check_message_1 = conf.start_msg
    conf.start_msg = null_check_message_1
    conf.saved_check_message_2 = conf.end_msg
    conf.end_msg = null_check_message_2
    conf.env.in_compound = 1


@conf
def COMPOUND_END(conf, result):
    '''start a compound test'''
    conf.env.in_compound -= 1
    if conf.env.in_compound != 0:
        return
    conf.start_msg = conf.saved_check_message_1
    conf.end_msg = conf.saved_check_message_2
    p = conf.end_msg
    if result is True:
        p('ok')
    elif not result:
        p('not found', 'YELLOW')
    else:
        p(result)


@feature('nolink')
def nolink(self):
    '''using the nolink type in conf.check() allows us to avoid
       the link stage of a test, thus speeding it up for tests
       that where linking is not needed'''
    pass


def CHECK_HEADER(conf, h, add_headers=False, lib=None):
    '''check for a header'''
    if h in missing_headers and lib is None:
        return False
    d = h.upper().replace('/', '_')
    d = d.replace('.', '_')
    d = d.replace('-', '_')
    d = 'HAVE_%s' % d
    if CONFIG_SET(conf, d):
        if add_headers:
            if not h in conf.env.hlist:
                conf.env.hlist.append(h)
        return True

    (ccflags, ldflags, cpppath) = library_flags(conf, lib)

    hdrs = hlist_to_string(conf, headers=h)
    if lib is None:
        lib = ""
    ret = conf.check(fragment='%s\nint main(void) { return 0; }\n' % hdrs,
                     type='nolink',
                     execute=0,
                     cflags=ccflags,
                     mandatory=False,
                     includes=cpppath,
                     uselib=lib.upper(),
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
                      # we need to make sure the compiler doesn't
                      # optimize it out...
                      '''
                      #ifndef %s
                      void *_x; _x=(void *)&%s; return (int)_x;
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
def CHECK_DECLS(conf, vars, reverse=False, headers=None, always=False):
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
                              msg='Checking for declaration of %s' % v,
                              always=always):
            if not CHECK_CODE(conf,
                      '''
                      return (int)%s;
                      ''' % (v),
                      execute=False,
                      link=False,
                      msg='Checking for declaration of %s (as enum)' % v,
                      local_include=False,
                      headers=headers,
                      define=define,
                      always=always):
                ret = False
    return ret


def CHECK_FUNC(conf, f, link=True, lib=None, headers=None):
    '''check for a function'''
    define='HAVE_%s' % f.upper()

    ret = False

    in_lib_str = ""
    if lib:
        in_lib_str = " in %s" % lib
    conf.COMPOUND_START('Checking for %s%s' % (f, in_lib_str))

    if link is None or link:
        ret = CHECK_CODE(conf,
                         # this is based on the autoconf strategy
                         '''
                         #define %s __fake__%s
                         #ifdef HAVE_LIMITS_H
                         # include <limits.h>
                         #else
                         # include <assert.h>
                         #endif
                         #undef %s
                         #if defined __stub_%s || defined __stub___%s
                         #error "bad glibc stub"
                         #endif
                         extern char %s();
                         int main() { return %s(); }
                         ''' % (f, f, f, f, f, f, f),
                         execute=False,
                         link=True,
                         addmain=False,
                         add_headers=False,
                         define=define,
                         local_include=False,
                         lib=lib,
                         headers=headers,
                         msg='Checking for %s' % f)

        if not ret:
            ret = CHECK_CODE(conf,
                             # it might be a macro
                             # we need to make sure the compiler doesn't
                             # optimize it out...
                             'void *__x = (void *)%s; return (int)__x' % f,
                             execute=False,
                             link=True,
                             addmain=True,
                             add_headers=True,
                             define=define,
                             local_include=False,
                             lib=lib,
                             headers=headers,
                             msg='Checking for macro %s' % f)

    if not ret and (link is None or not link):
        ret = CHECK_VARIABLE(conf, f,
                             define=define,
                             headers=headers,
                             msg='Checking for declaration of %s' % f)
    conf.COMPOUND_END(ret)
    return ret


@conf
def CHECK_FUNCS(conf, list, link=True, lib=None, headers=None):
    '''check for a list of functions'''
    ret = True
    for f in TO_LIST(list):
        if not CHECK_FUNC(conf, f, link=link, lib=lib, headers=headers):
            ret = False
    return ret


@conf
def CHECK_SIZEOF(conf, vars, headers=None, define=None, critical=True):
    '''check the size of a type'''
    for v in TO_LIST(vars):
        v_define = define
        ret = False
        if v_define is None:
            v_define = 'SIZEOF_%s' % v.upper().replace(' ', '_')
        for size in list((1, 2, 4, 8, 16, 32, 64)):
            if CHECK_CODE(conf,
                      'static int test_array[1 - 2 * !(((long int)(sizeof(%s))) <= %d)];' % (v, size),
                      define=v_define,
                      quote=False,
                      headers=headers,
                      local_include=False,
                      msg="Checking if size of %s == %d" % (v, size)):
                conf.DEFINE(v_define, size)
                ret = True
                break
        if not ret and critical:
            Logs.error("Couldn't determine size of '%s'" % v)
            sys.exit(1)
    return ret

@conf
def CHECK_VALUEOF(conf, v, headers=None, define=None):
    '''check the value of a variable/define'''
    ret = True
    v_define = define
    if v_define is None:
        v_define = 'VALUEOF_%s' % v.upper().replace(' ', '_')
    if CHECK_CODE(conf,
                  'printf("%%u", (unsigned)(%s))' % v,
                  define=v_define,
                  execute=True,
                  define_ret=True,
                  quote=False,
                  headers=headers,
                  local_include=False,
                  msg="Checking value of %s" % v):
        return int(conf.env[v_define])

    return None

@conf
def CHECK_CODE(conf, code, define,
               always=False, execute=False, addmain=True,
               add_headers=True, mandatory=False,
               headers=None, msg=None, cflags='', includes='# .',
               local_include=True, lib=None, link=True,
               define_ret=False, quote=False,
               on_target=True, strict=False):
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
        fragment='%s\n int main(void) { %s; return 0; }\n' % (hdrs, code)
    else:
        fragment='%s\n%s\n' % (hdrs, code)

    if msg is None:
        msg="Checking for %s" % define

    cflags = TO_LIST(cflags)

    # Be strict when relying on a compiler check
    # Some compilers (e.g. xlc) ignore non-supported features as warnings
    if strict:
        if 'WERROR_CFLAGS' in conf.env:
            cflags.extend(conf.env['WERROR_CFLAGS'])

    if local_include:
        cflags.append('-I%s' % conf.path.abspath())

    if not link:
        type='nolink'
    else:
        type='cprogram'

    uselib = TO_LIST(lib)

    (ccflags, ldflags, cpppath) = library_flags(conf, uselib)

    includes = TO_LIST(includes)
    includes.extend(cpppath)

    uselib = [l.upper() for l in uselib]

    cflags.extend(ccflags)

    if on_target:
        test_args = conf.SAMBA_CROSS_ARGS(msg=msg)
    else:
        test_args = []

    conf.COMPOUND_START(msg)

    try:
        ret = conf.check(fragment=fragment,
                     execute=execute,
                     define_name = define,
                     cflags=cflags,
                     ldflags=ldflags,
                     includes=includes,
                     uselib=uselib,
                     type=type,
                     msg=msg,
                     quote=quote,
                     test_args=test_args,
                     define_ret=define_ret)
    except Exception:
        if always:
            conf.DEFINE(define, 0)
        else:
            conf.undefine(define)
        conf.COMPOUND_END(False)
        if mandatory:
            raise
        return False
    else:
        # Success is indicated by ret but we should unset
        # defines set by WAF's c_config.check() because it
        # defines it to int(ret) and we want to undefine it
        if not ret:
            conf.undefine(define)
            conf.COMPOUND_END(False)
            return False
        if not define_ret:
            conf.DEFINE(define, 1)
            conf.COMPOUND_END(True)
        else:
            conf.DEFINE(define, ret, quote=quote)
            conf.COMPOUND_END(ret)
        return True


@conf
def CHECK_STRUCTURE_MEMBER(conf, structname, member,
                           always=False, define=None, headers=None,
                           lib=None):
    '''check for a structure member'''
    if define is None:
        define = 'HAVE_%s' % member.upper()
    return CHECK_CODE(conf,
                      '%s s; void *_x; _x=(void *)&s.%s' % (structname, member),
                      define,
                      execute=False,
                      link=False,
                      lib=lib,
                      always=always,
                      headers=headers,
                      local_include=False,
                      msg="Checking for member %s in %s" % (member, structname))


@conf
def CHECK_CFLAGS(conf, cflags, fragment='int main(void) { return 0; }\n',
                 mandatory=False):
    '''check if the given cflags are accepted by the compiler
    '''
    check_cflags = TO_LIST(cflags)
    if 'WERROR_CFLAGS' in conf.env:
        check_cflags.extend(conf.env['WERROR_CFLAGS'])
    return conf.check(fragment=fragment,
                      execute=0,
                      mandatory=mandatory,
                      type='nolink',
                      cflags=check_cflags,
                      msg="Checking compiler accepts %s" % cflags)

@conf
def CHECK_LDFLAGS(conf, ldflags,
                  mandatory=False):
    '''check if the given ldflags are accepted by the linker
    '''
    return conf.check(fragment='int main(void) { return 0; }\n',
                      execute=0,
                      ldflags=ldflags,
                      mandatory=mandatory,
                      msg="Checking linker accepts %s" % ldflags)


@conf
def CONFIG_GET(conf, option):
    '''return True if a configuration option was found'''
    if (option in conf.env):
        return conf.env[option]
    else:
        return None

@conf
def CONFIG_SET(conf, option):
    '''return True if a configuration option was found'''
    if option not in conf.env:
        return False
    v = conf.env[option]
    if v is None:
        return False
    if v == []:
        return False
    if v == ():
        return False
    return True

@conf
def CONFIG_RESET(conf, option):
    if option not in conf.env:
        return
    del conf.env[option]

Build.BuildContext.CONFIG_RESET = CONFIG_RESET
Build.BuildContext.CONFIG_SET = CONFIG_SET
Build.BuildContext.CONFIG_GET = CONFIG_GET


def library_flags(self, libs):
    '''work out flags from pkg_config'''
    ccflags = []
    ldflags = []
    cpppath = []
    for lib in TO_LIST(libs):
        # note that we do not add the -I and -L in here, as that is added by the waf
        # core. Adding it here would just change the order that it is put on the link line
        # which can cause system paths to be added before internal libraries
        extra_ccflags = TO_LIST(getattr(self.env, 'CFLAGS_%s' % lib.upper(), []))
        extra_ldflags = TO_LIST(getattr(self.env, 'LDFLAGS_%s' % lib.upper(), []))
        extra_cpppath = TO_LIST(getattr(self.env, 'CPPPATH_%s' % lib.upper(), []))
        ccflags.extend(extra_ccflags)
        ldflags.extend(extra_ldflags)
        cpppath.extend(extra_cpppath)

        extra_cpppath = TO_LIST(getattr(self.env, 'INCLUDES_%s' % lib.upper(), []))
        cpppath.extend(extra_cpppath)
    if 'EXTRA_LDFLAGS' in self.env:
        ldflags.extend(self.env['EXTRA_LDFLAGS'])

    ccflags = unique_list(ccflags)
    ldflags = unique_list(ldflags)
    cpppath = unique_list(cpppath)
    return (ccflags, ldflags, cpppath)


@conf
def CHECK_LIB(conf, libs, mandatory=False, empty_decl=True, set_target=True, shlib=False):
    '''check if a set of libraries exist as system libraries

    returns the sublist of libs that do exist as a syslib or []
    '''

    fragment= '''
int foo()
{
    int v = 2;
    return v*2;
}
'''
    ret = []
    liblist  = TO_LIST(libs)
    for lib in liblist[:]:
        if GET_TARGET_TYPE(conf, lib) == 'SYSLIB':
            ret.append(lib)
            continue

        (ccflags, ldflags, cpppath) = library_flags(conf, lib)
        if shlib:
            res = conf.check(features='c cshlib', fragment=fragment, lib=lib, uselib_store=lib, cflags=ccflags, ldflags=ldflags, uselib=lib.upper(), mandatory=False)
        else:
            res = conf.check(lib=lib, uselib_store=lib, cflags=ccflags, ldflags=ldflags, uselib=lib.upper(), mandatory=False)

        if not res:
            if mandatory:
                Logs.error("Mandatory library '%s' not found for functions '%s'" % (lib, list))
                sys.exit(1)
            if empty_decl:
                # if it isn't a mandatory library, then remove it from dependency lists
                if set_target:
                    SET_TARGET_TYPE(conf, lib, 'EMPTY')
        else:
            conf.define('HAVE_LIB%s' % lib.upper().replace('-','_').replace('.','_'), 1)
            conf.env['LIB_' + lib.upper()] = lib
            if set_target:
                conf.SET_TARGET_TYPE(lib, 'SYSLIB')
            ret.append(lib)

    return ret



@conf
def CHECK_FUNCS_IN(conf, list, library, mandatory=False, checklibc=False,
                   headers=None, link=True, empty_decl=True, set_target=True):
    """
    check that the functions in 'list' are available in 'library'
    if they are, then make that library available as a dependency

    if the library is not available and mandatory==True, then
    raise an error.

    If the library is not available and mandatory==False, then
    add the library to the list of dependencies to remove from
    build rules

    optionally check for the functions first in libc
    """
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
            if GET_TARGET_TYPE(conf, lib) != 'SYSLIB' and empty_decl:
                SET_TARGET_TYPE(conf, lib, 'EMPTY')
        return True

    checklist = conf.CHECK_LIB(liblist, empty_decl=empty_decl, set_target=set_target)
    for lib in liblist[:]:
        if not lib in checklist and mandatory:
            Logs.error("Mandatory library '%s' not found for functions '%s'" % (lib, list))
            sys.exit(1)

    ret = True
    for f in remaining:
        if not CHECK_FUNC(conf, f, lib=' '.join(checklist), headers=headers, link=link):
            ret = False

    return ret


@conf
def IN_LAUNCH_DIR(conf):
    '''return True if this rule is being run from the launch directory'''
    return os.path.realpath(conf.path.abspath()) == os.path.realpath(Context.launch_dir)
Options.OptionsContext.IN_LAUNCH_DIR = IN_LAUNCH_DIR


@conf
def SAMBA_CONFIG_H(conf, path=None):
    '''write out config.h in the right directory'''
    # we don't want to produce a config.h in places like lib/replace
    # when we are building projects that depend on lib/replace
    if not IN_LAUNCH_DIR(conf):
        return

    # we need to build real code that can't be optimized away to test
    stack_protect_list = ['-fstack-protector-strong', '-fstack-protector']
    for stack_protect_flag in stack_protect_list:
        flag_supported = conf.check(fragment='''
                                    #include <stdio.h>

                                    int main(void)
                                    {
                                        char t[100000];
                                        while (fgets(t, sizeof(t), stdin));
                                        return 0;
                                    }
                                    ''',
                                    execute=0,
                                    cflags=[ '-Werror', '-Wp,-D_FORTIFY_SOURCE=2', stack_protect_flag],
                                    mandatory=False,
                                    msg='Checking if compiler accepts %s' % (stack_protect_flag))
        if flag_supported:
            conf.ADD_CFLAGS('%s' % (stack_protect_flag))
            break

    flag_supported = conf.check(fragment='''
                                #include <stdio.h>

                                int main(void)
                                {
                                    char t[100000];
                                    while (fgets(t, sizeof(t), stdin));
                                    return 0;
                                }
                                ''',
                                execute=0,
                                cflags=[ '-Werror', '-fstack-clash-protection'],
                                mandatory=False,
                                msg='Checking if compiler accepts -fstack-clash-protection')
    if flag_supported:
        conf.ADD_CFLAGS('-fstack-clash-protection')

    if Options.options.debug:
        conf.ADD_CFLAGS('-g', testflags=True)

    if Options.options.pidl_developer:
        conf.env.PIDL_DEVELOPER_MODE = True

    if Options.options.developer:
        conf.env.DEVELOPER_MODE = True

        conf.ADD_CFLAGS('-g', testflags=True)
        conf.ADD_CFLAGS('-Wall', testflags=True)
        conf.ADD_CFLAGS('-Wshadow', testflags=True)
        conf.ADD_CFLAGS('-Wmissing-prototypes', testflags=True)
        if CHECK_CODE(conf,
                      'struct a { int b; }; struct c { struct a d; } e = { };',
                      'CHECK_C99_INIT',
                      link=False,
                      cflags='-Wmissing-field-initializers -Werror=missing-field-initializers',
                      msg="Checking C99 init of nested structs."):
            conf.ADD_CFLAGS('-Wmissing-field-initializers', testflags=True)
        conf.ADD_CFLAGS('-Wformat-overflow=2', testflags=True)
        conf.ADD_CFLAGS('-Wformat-zero-length', testflags=True)
        conf.ADD_CFLAGS('-Wcast-align -Wcast-qual', testflags=True)
        conf.ADD_CFLAGS('-fno-common', testflags=True)

        conf.ADD_CFLAGS('-Werror=address', testflags=True)
        # we add these here to ensure that -Wstrict-prototypes is not set during configure
        conf.ADD_CFLAGS('-Werror=strict-prototypes -Wstrict-prototypes',
                        testflags=True)
        conf.ADD_CFLAGS('-Werror=write-strings -Wwrite-strings',
                        testflags=True)
        conf.ADD_CFLAGS('-Werror-implicit-function-declaration',
                        testflags=True)
        conf.ADD_CFLAGS('-Werror=pointer-arith -Wpointer-arith',
                        testflags=True)
        conf.ADD_CFLAGS('-Werror=declaration-after-statement -Wdeclaration-after-statement',
                        testflags=True)
        conf.ADD_CFLAGS('-Werror=return-type -Wreturn-type',
                        testflags=True)
        conf.ADD_CFLAGS('-Werror=uninitialized -Wuninitialized',
                        testflags=True)
        conf.ADD_CFLAGS('-Wimplicit-fallthrough',
                        testflags=True)
        conf.ADD_CFLAGS('-Werror=strict-overflow -Wstrict-overflow=2',
                        testflags=True)

        conf.ADD_CFLAGS('-Wformat=2 -Wno-format-y2k', testflags=True)
        conf.ADD_CFLAGS('-Wno-format-zero-length', testflags=True)
        conf.ADD_CFLAGS('-Werror=format-security -Wformat-security',
                        testflags=True, prereq_flags='-Wformat')
        # This check is because for ldb_search(), a NULL format string
        # is not an error, but some compilers complain about that.
        if CHECK_CFLAGS(conf, ["-Werror=format", "-Wformat=2"], '''
int testformat(char *format, ...) __attribute__ ((format (__printf__, 1, 2)));

int main(void) {
        testformat(0);
        return 0;
}

'''):
            if not 'EXTRA_CFLAGS' in conf.env:
                conf.env['EXTRA_CFLAGS'] = []
            conf.env['EXTRA_CFLAGS'].extend(TO_LIST("-Werror=format"))

        if not Options.options.disable_warnings_as_errors:
            conf.ADD_NAMED_CFLAGS('PICKY_CFLAGS', '-Werror -Wno-error=deprecated-declarations', testflags=True)
            conf.ADD_NAMED_CFLAGS('PICKY_CFLAGS', '-Wno-error=tautological-compare', testflags=True)

    if Options.options.fatal_errors:
        conf.ADD_CFLAGS('-Wfatal-errors', testflags=True)

    if Options.options.pedantic:
        conf.ADD_CFLAGS('-W', testflags=True)

    if (Options.options.address_sanitizer or
        Options.options.undefined_sanitizer):
        conf.ADD_CFLAGS('-g -O1', testflags=True)
    if Options.options.address_sanitizer:
        conf.ADD_CFLAGS('-fno-omit-frame-pointer', testflags=True)
        conf.ADD_CFLAGS('-fsanitize=address', testflags=True)
        conf.ADD_LDFLAGS('-fsanitize=address', testflags=True)
        conf.env['ADDRESS_SANITIZER'] = True
    if Options.options.undefined_sanitizer:
        conf.ADD_CFLAGS('-fsanitize=undefined', testflags=True)
        conf.ADD_CFLAGS('-fsanitize=null', testflags=True)
        conf.ADD_CFLAGS('-fsanitize=alignment', testflags=True)
        conf.ADD_LDFLAGS('-fsanitize=undefined', testflags=True)
        conf.env['UNDEFINED_SANITIZER'] = True


    # Let people pass an additional ADDITIONAL_{CFLAGS,LDFLAGS}
    # environment variables which are only used the for final build.
    #
    # The CFLAGS and LDFLAGS environment variables are also
    # used for the configure checks which might impact their results.
    #
    # If these variables don't pass a smoke test, fail the configure

    conf.add_os_flags('ADDITIONAL_CFLAGS')
    if conf.env.ADDITIONAL_CFLAGS:
        conf.CHECK_CFLAGS(conf.env['ADDITIONAL_CFLAGS'],
                          mandatory=True)
        conf.env['EXTRA_CFLAGS'].extend(conf.env['ADDITIONAL_CFLAGS'])

    conf.add_os_flags('ADDITIONAL_LDFLAGS')
    if conf.env.ADDITIONAL_LDFLAGS:
        conf.CHECK_LDFLAGS(conf.env['ADDITIONAL_LDFLAGS'],
                           mandatory=True)
        conf.env['EXTRA_LDFLAGS'].extend(conf.env['ADDITIONAL_LDFLAGS'])

    if path is None:
        conf.write_config_header('default/config.h', top=True, remove=False)
    else:
        conf.write_config_header(os.path.join(conf.variant, path), remove=False)
    for key in conf.env.define_key:
        conf.undefine(key, from_env=False)
    conf.env.define_key = []
    conf.SAMBA_CROSS_CHECK_COMPLETE()


@conf
def CONFIG_PATH(conf, name, default):
    '''setup a configurable path'''
    if not name in conf.env:
        if default[0] == '/':
            conf.env[name] = default
        else:
            conf.env[name] = conf.env['PREFIX'] + default

@conf
def ADD_NAMED_CFLAGS(conf, name, flags, testflags=False, prereq_flags=[]):
    '''add some CFLAGS to the command line
       optionally set testflags to ensure all the flags work
    '''
    prereq_flags = TO_LIST(prereq_flags)
    if testflags:
        ok_flags=[]
        for f in flags.split():
            if CHECK_CFLAGS(conf, [f] + prereq_flags):
                ok_flags.append(f)
        flags = ok_flags
    if not name in conf.env:
        conf.env[name] = []
    conf.env[name].extend(TO_LIST(flags))

@conf
def ADD_CFLAGS(conf, flags, testflags=False, prereq_flags=[]):
    '''add some CFLAGS to the command line
       optionally set testflags to ensure all the flags work
    '''
    ADD_NAMED_CFLAGS(conf, 'EXTRA_CFLAGS', flags, testflags=testflags,
                     prereq_flags=prereq_flags)

@conf
def ADD_LDFLAGS(conf, flags, testflags=False):
    '''add some LDFLAGS to the command line
       optionally set testflags to ensure all the flags work

       this will return the flags that are added, if any
    '''
    if testflags:
        ok_flags=[]
        for f in flags.split():
            if CHECK_LDFLAGS(conf, f):
                ok_flags.append(f)
        flags = ok_flags
    if not 'EXTRA_LDFLAGS' in conf.env:
        conf.env['EXTRA_LDFLAGS'] = []
    conf.env['EXTRA_LDFLAGS'].extend(TO_LIST(flags))
    return flags


@conf
def ADD_EXTRA_INCLUDES(conf, includes):
    '''add some extra include directories to all builds'''
    if not 'EXTRA_INCLUDES' in conf.env:
        conf.env['EXTRA_INCLUDES'] = []
    conf.env['EXTRA_INCLUDES'].extend(TO_LIST(includes))



def CURRENT_CFLAGS(bld, target, cflags, allow_warnings=False, hide_symbols=False):
    '''work out the current flags. local flags are added first'''
    ret = TO_LIST(cflags)
    if not 'EXTRA_CFLAGS' in bld.env:
        list = []
    else:
        list = bld.env['EXTRA_CFLAGS'];
    ret.extend(list)
    if not allow_warnings and 'PICKY_CFLAGS' in bld.env:
        list = bld.env['PICKY_CFLAGS'];
        ret.extend(list)
    if hide_symbols and bld.env.HAVE_VISIBILITY_ATTR:
        ret.append(bld.env.VISIBILITY_CFLAGS)
    return ret


@conf
def CHECK_CC_ENV(conf):
    """trim whitespaces from 'CC'.
    The build farm sometimes puts a space at the start"""
    if os.environ.get('CC'):
        conf.env.CC = TO_LIST(os.environ.get('CC'))


@conf
def SETUP_CONFIGURE_CACHE(conf, enable):
    '''enable/disable cache of configure results'''
    if enable:
        # when -C is chosen, we will use a private cache and will
        # not look into system includes. This roughtly matches what
        # autoconf does with -C
        cache_path = os.path.join(conf.bldnode.abspath(), '.confcache')
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


@conf
def SAMBA_CHECK_UNDEFINED_SYMBOL_FLAGS(conf):
    if Options.options.address_sanitizer or Options.options.enable_libfuzzer:
        # Sanitizers can rely on symbols undefined at library link time and the
        # symbols used for fuzzers are only defined by compiler wrappers.
        return

    if not sys.platform.startswith("openbsd"):
        # we don't want any libraries or modules to rely on runtime
        # resolution of symbols
        conf.env.undefined_ldflags = conf.ADD_LDFLAGS('-Wl,-no-undefined', testflags=True)

        if (conf.env.undefined_ignore_ldflags == [] and
            conf.CHECK_LDFLAGS(['-undefined', 'dynamic_lookup'])):
            conf.env.undefined_ignore_ldflags = ['-undefined', 'dynamic_lookup']
