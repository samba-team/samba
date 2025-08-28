#!/usr/bin/env python

top = '.'
out = 'bin'

APPNAME='samba'
VERSION=None

import sys, os, tempfile
sys.path.insert(0, top+"/buildtools/wafsamba")
import shutil
import wafsamba, samba_dist, samba_git, samba_version, samba_utils
from waflib import Options, Scripting, Logs, Context, Errors
from waflib.Tools import bison
import ssl

samba_dist.DIST_DIRS('.')
samba_dist.DIST_BLACKLIST('.gitignore .bzrignore source4/selftest/provisions')

# A function so the variables are not in global scope
def get_default_private_libs():
    # LDB is used by sssd (was made private by default in Samba 4.21)
    SSSD_LIBS=["ldb"]
    # These following libs without ABI checking were made private by default in Samba 4.21
    # Presumably unused (dcerpc-samr was probably a copy and paste error,
    # and samba-policy has primary use via python bindings).  tevent-util
    # was for openchange but was for PIDL output that is no longer
    # generated
    POSSIBLY_UNUSED_LIBS=["dcerpc-samr","samba-policy","tevent-util"]
    # These were used by mapiproxy in OpenChange (also used LDB and
    # the real public libs tdb, talloc, tevent)
    OPENCHANGE_SERVER_LIBS = ["dcerpc_server","samdb"]
    # These (plus LDB, ndr, talloc, tevent) are used by the OpenChange
    # client, which is still in use (Fedora/Red Hat packages it)
    OPENCHANGE_LIBS = ["dcerpc","samba-hostconfig","samba-credentials"]
    return SSSD_LIBS + POSSIBLY_UNUSED_LIBS + OPENCHANGE_LIBS + OPENCHANGE_SERVER_LIBS

DEFAULT_PRIVATE_LIBS = get_default_private_libs()

# install in /usr/local/samba by default
default_prefix = Options.default_prefix = '/usr/local/samba'

def options(opt):
    opt.BUILTIN_DEFAULT('NONE')
    opt.PRIVATE_EXTENSION_DEFAULT('private-samba')
    opt.RECURSE('lib/replace')
    opt.RECURSE('dynconfig')
    opt.RECURSE('packaging')
    opt.RECURSE('lib/ldb')
    opt.RECURSE('selftest')
    opt.RECURSE('source4/dsdb/samdb/ldb_modules')
    opt.RECURSE('pidl')
    opt.RECURSE('source3')
    opt.RECURSE('lib/util')
    opt.RECURSE('ctdb')

# Optional Libraries
# ------------------
#
# Most of the calls to opt.add_option() use default=True for the --with case
#
# To assist users and distributors to build Samba with the full feature
# set, the build system will abort if our dependent libraries and their
# header files are not found on the target system.  This will mean for
# example, that xattr, acl and ldap headers must be installed for the
# default build to complete.  The configure system will check for these
# headers, and the error message will indicate the option (such as
# --without-acl-support) that can be specified to skip this requirement.
#
# This will assist users and in particular distributors in building fully
# functional packages, while allowing those on systems truly without these
# facilities to continue to build Samba after careful consideration.
#
# It also ensures our container image generation in bootstrap/ is correct
# as otherwise a missing package there would just silently work

    opt.samba_add_onoff_option('pthreadpool', with_name="enable", without_name="disable", default=True)

    opt.add_option('--with-system-mitkrb5',
                   help='build Samba with system MIT Kerberos.',
                   action='store_true',
                   dest='with_system_mitkrb5',
                   default=False)

    opt.add_option('--with-experimental-mit-ad-dc',
                   help='Enable the experimental MIT Kerberos-backed AD DC.  ' +
                   'Note that security patches are not issued for this configuration',
                   action='store_true',
                   dest='with_experimental_mit_ad_dc',
                   default=False)

    opt.add_option('--with-system-mitkdc',
                   help=('Specify the path to the krb5kdc binary from MIT Kerberos'),
                   type=str,
                   dest='with_system_mitkdc',
                   default=None)

    opt.add_option('--with-system-heimdalkrb5',
                   help=('build Samba with system Heimdal Kerberos. ' +
                         'Requires --without-ad-dc' and
                         'conflicts with --with-system-mitkrb5'),
                   action='store_true',
                   dest='with_system_heimdalkrb5',
                   default=False)

    opt.add_option('--without-ad-dc',
                   help='disable AD DC functionality (enables only Samba FS (File Server, Winbind, NMBD) and client utilities.',
                   action='store_true', dest='without_ad_dc', default=False)

    opt.add_option('--with-pie',
                  help=("Build Position Independent Executables " +
                        "(default if supported by compiler)"),
                  action="store_true", dest='enable_pie')
    opt.add_option('--without-pie',
                  help=("Disable Position Independent Executable builds"),
                  action="store_false", dest='enable_pie')

    opt.add_option('--with-relro',
                  help=("Build with full RELocation Read-Only (RELRO)" +
                        "(default if supported by compiler)"),
                  action="store_true", dest='enable_relro')
    opt.add_option('--without-relro',
                  help=("Disable RELRO builds"),
                  action="store_false", dest='enable_relro')

    opt.add_option('--with-kernel-keyring',
                  help=('Enable kernely keyring support for credential storage ' +
                        '(default if keyutils libraries are available)'),
                  action='store_true', dest='enable_keyring')
    opt.add_option('--without-kernel-keyring',
                  help=('Disable kernely keyring support for credential storage'),
                  action='store_false', dest='enable_keyring')

    opt.samba_add_onoff_option('ldap')

    opt.option_group('developer options')

    opt.load('python') # options for disabling pyc or pyo compilation
    # enable options related to building python extensions

    opt.add_option('--with-json',
                   action='store_true', dest='with_json', default=True,
                   help=("Build with JSON support (default=True). This "
                         "requires the jansson development headers."))
    opt.add_option('--without-json',
                   action='store_false', dest='with_json',
                   help=("Build without JSON support."))

    opt.samba_add_onoff_option('smb1-server',
                               dest='with_smb1server',
                               help=("Build smbd with SMB1 support (default=yes)."))

    opt.add_option('--vendor-suffix',
                   help=('Specify a vendor (or packager) name to include in the version string'),
                   type=str,
                   dest='SAMBA_VERSION_VENDOR_SUFFIX',
                   default=None)

    opt.samba_add_onoff_option('systemd-userdb',
                               help=("Build winbind with support for systemd "
                                     "User/Group Record Lookup API via "
                                     "Varlink"),
                               default=False)

def configure(conf):
    if Options.options.SAMBA_VERSION_VENDOR_SUFFIX:
        conf.env.SAMBA_VERSION_VENDOR_SUFFIX = Options.options.SAMBA_VERSION_VENDOR_SUFFIX

    version = samba_version.load_version(env=conf.env)

    conf.DEFINE('CONFIG_H_IS_FROM_SAMBA', 1)
    conf.DEFINE('_SAMBA_BUILD_', version.MAJOR, add_to_cflags=True)
    conf.DEFINE('HAVE_CONFIG_H', 1, add_to_cflags=True)

    if Options.options.developer:
        conf.ADD_CFLAGS('-DDEVELOPER -DDEBUG_PASSWORD')
        conf.env.DEVELOPER = True
        # if we are in a git tree without a pre-commit hook, install a
        # simple default.
        # we need git for 'waf dist'
        githooksdir = None
        conf.find_program('git', var='GIT')
        if 'GIT' in conf.env:
            githooksdir = conf.CHECK_COMMAND('%s rev-parse --git-path hooks' % conf.env.GIT[0],
                               msg='Finding githooks directory',
                               define=None,
                               on_target=False)
        if githooksdir and os.path.isdir(githooksdir):
            pre_commit_hook = os.path.join(githooksdir, 'pre-commit')
            if not os.path.exists(pre_commit_hook):
                Logs.info("Installing script/git-hooks/pre-commit-hook as %s" %
                          pre_commit_hook)
                shutil.copy(os.path.join(Context.g_module.top, 'script/git-hooks/pre-commit-hook'),
                            pre_commit_hook)

    conf.ADD_EXTRA_INCLUDES('#include/public #source4 #lib #source4/lib #source4/include #include #lib/replace')

    conf.env.replace_add_global_pthread = True
    conf.RECURSE('lib/replace')

    conf.RECURSE('examples/fuse')
    conf.RECURSE('examples/winexe')

    conf.SAMBA_CHECK_PERL(mandatory=True)
    conf.CHECK_XSLTPROC_MANPAGES()

    if conf.env.disable_python:
        if not (Options.options.without_ad_dc):
            raise Errors.WafError('--disable-python requires --without-ad-dc')

    conf.SAMBA_CHECK_PYTHON()
    conf.SAMBA_CHECK_PYTHON_HEADERS()

    conf.SAMBA_CHECK_RUST()

    if sys.platform == 'darwin' and not conf.env['HAVE_ENVIRON_DECL']:
        # Mac OSX needs to have this and it's also needed that the python is compiled with this
        # otherwise you face errors about common symbols
        if not conf.CHECK_SHLIB_W_PYTHON("Checking if -fno-common is needed"):
            conf.ADD_CFLAGS('-fno-common')
        if not conf.CHECK_SHLIB_W_PYTHON("Checking if -undefined dynamic_lookup is not need"):
            conf.env.append_value('cshlib_LINKFLAGS', ['-undefined', 'dynamic_lookup'])

    if sys.platform == 'darwin':
        conf.ADD_LDFLAGS('-framework CoreFoundation')

    conf.RECURSE('dynconfig')
    conf.RECURSE('selftest')

    conf.PROCESS_SEPARATE_RULE('system_gnutls')

    conf.CHECK_CFG(package='zlib', minversion='1.2.3',
                   args='--cflags --libs',
                   mandatory=True)
    conf.CHECK_FUNCS_IN('inflateInit2', 'z')

    if Options.options.enable_keyring is not False:
        conf.env['WITH_KERNEL_KEYRING'] = 'auto'
        if Options.options.enable_keyring is True:
            conf.env['WITH_KERNEL_KEYRING'] = True
    else:
        conf.env['WITH_KERNEL_KEYRING'] = False

    if conf.CHECK_FOR_THIRD_PARTY():
        conf.RECURSE('third_party')
    else:

        if not conf.CHECK_POPT():
            raise Errors.WafError('popt development packages have not been found.\nIf third_party is installed, check that it is in the proper place.')
        else:
            conf.define('USING_SYSTEM_POPT', 1)

        if not conf.CHECK_CMOCKA():
            raise Errors.WafError('cmocka development packages has not been found.\nIf third_party is installed, check that it is in the proper place.')
        else:
            conf.define('USING_SYSTEM_CMOCKA', 1)

        if conf.CONFIG_GET('ENABLE_SELFTEST'):
            if not conf.CHECK_SOCKET_WRAPPER():
                raise Errors.WafError('socket_wrapper package has not been found.\nIf third_party is installed, check that it is in the proper place.')
            else:
                conf.define('USING_SYSTEM_SOCKET_WRAPPER', 1)

            if not conf.CHECK_NSS_WRAPPER():
                raise Errors.WafError('nss_wrapper package has not been found.\nIf third_party is installed, check that it is in the proper place.')
            else:
                conf.define('USING_SYSTEM_NSS_WRAPPER', 1)

            if not conf.CHECK_RESOLV_WRAPPER():
                raise Errors.WafError('resolv_wrapper package has not been found.\nIf third_party is installed, check that it is in the proper place.')
            else:
                conf.define('USING_SYSTEM_RESOLV_WRAPPER', 1)

            if not conf.CHECK_UID_WRAPPER():
                raise Errors.WafError('uid_wrapper package has not been found.\nIf third_party is installed, check that it is in the proper place.')
            else:
                conf.define('USING_SYSTEM_UID_WRAPPER', 1)

            if not conf.CHECK_PAM_WRAPPER():
                raise Errors.WafError('pam_wrapper package has not been found.\nIf third_party is installed, check that it is in the proper place.')
            else:
                conf.define('USING_SYSTEM_PAM_WRAPPER', 1)

    # Check for LDAP
    if Options.options.with_ldap:
        conf.CHECK_HEADERS('ldap.h lber.h ldap_pvt.h')
        conf.CHECK_TYPE('ber_tag_t', 'unsigned int', headers='ldap.h lber.h')
        conf.CHECK_FUNCS_IN('ber_scanf ber_sockbuf_add_io', 'lber')
        conf.CHECK_VARIABLE('LDAP_OPT_SOCKBUF', headers='ldap.h')

        # if we LBER_OPT_LOG_PRINT_FN we can intercept ldap logging and print it out
        # for the samba logs
        conf.CHECK_VARIABLE('LBER_OPT_LOG_PRINT_FN',
                            define='HAVE_LBER_LOG_PRINT_FN', headers='lber.h')

        conf.CHECK_FUNCS_IN('ldap_init ldap_init_fd ldap_initialize ldap_set_rebind_proc', 'ldap')
        conf.CHECK_FUNCS_IN('ldap_add_result_entry', 'ldap')

        # Check if ldap_set_rebind_proc() takes three arguments
        if conf.CHECK_CODE('ldap_set_rebind_proc(0, 0, 0)',
                           'LDAP_SET_REBIND_PROC_ARGS',
                           msg="Checking whether ldap_set_rebind_proc takes 3 arguments",
                           headers='ldap.h lber.h', link=False):
            conf.DEFINE('LDAP_SET_REBIND_PROC_ARGS', '3')
        else:
            conf.DEFINE('LDAP_SET_REBIND_PROC_ARGS', '2')

        # last but not least, if ldap_init() exists, we want to use ldap
        if conf.CONFIG_SET('HAVE_LDAP_INIT') and conf.CONFIG_SET('HAVE_LDAP_H'):
            conf.DEFINE('HAVE_LDAP', '1')
            conf.DEFINE('LDAP_DEPRECATED', '1')
            conf.env['HAVE_LDAP'] = '1'
            # if ber_sockbuf_add_io() and LDAP_OPT_SOCKBUF are available, we can add
            # SASL wrapping hooks
            if conf.CONFIG_SET('HAVE_BER_SOCKBUF_ADD_IO') and \
                    conf.CONFIG_SET('HAVE_LDAP_OPT_SOCKBUF'):
                conf.DEFINE('HAVE_LDAP_TRANSPORT_WRAPPING', 1)
            conf.env.ENABLE_LDAP_BACKEND = True
        else:
            conf.fatal("LDAP support not found. "
                       "Try installing libldap2-dev or openldap-devel. "
                       "Otherwise, use --without-ldap to build without "
                       "LDAP support. "
                       "LDAP support is required for the LDAP passdb backend, "
                       "LDAP idmap backends and ADS. "
                       "ADS support improves communication with "
                       "Active Directory domain controllers.")
    else:
        conf.SET_TARGET_TYPE('ldap', 'EMPTY')
        conf.SET_TARGET_TYPE('lber', 'EMPTY')

    conf.RECURSE('lib/tdb')
    conf.RECURSE('lib/tevent')
    conf.RECURSE('lib/ldb')

    if conf.CHECK_LDFLAGS(['-Wl,--wrap=test']):
        conf.env['HAVE_LDWRAP'] = True
        conf.define('HAVE_LDWRAP', 1)

    if not (Options.options.without_ad_dc):
        conf.DEFINE('AD_DC_BUILD_IS_ENABLED', 1)

    # Check for flex before doing the embedded heimdal checks so we can bail if we don't have it.
    Logs.info("Checking for flex")
    conf.find_program('flex', var='FLEX')
    if conf.env['FLEX']:
        conf.CHECK_COMMAND('%s --version' % conf.env.FLEX[0],
                           msg='Using flex version',
                           define=None,
                           on_target=False)
    conf.env.FLEXFLAGS = ['-t']

    # #line statements in these generated files cause issues for lcov
    conf.env.FLEXFLAGS += ["--noline"]

    Logs.info("Checking for bison")
    bison.configure(conf)
    if conf.env['BISON']:
        conf.CHECK_COMMAND('%s --version  | head -n1' % conf.env.BISON[0],
                           msg='Using bison version',
                           define=None,
                           on_target=False)

    # #line statements in these generated files cause issues for lcov
    conf.env.BISONFLAGS += ["--no-line"]

    if Options.options.with_system_mitkrb5:
        if not Options.options.with_experimental_mit_ad_dc and \
           not Options.options.without_ad_dc:
            raise Errors.WafError('The MIT Kerberos build of Samba as an AD DC ' +
                                  'is experimental. Therefore '
                                  '--with-system-mitkrb5 requires either ' +
                                  '--with-experimental-mit-ad-dc or ' +
                                  '--without-ad-dc')

        conf.PROCESS_SEPARATE_RULE('system_mitkrb5')

    if not (Options.options.without_ad_dc or Options.options.with_system_mitkrb5):
        conf.DEFINE('AD_DC_BUILD_IS_ENABLED', 1)

    if Options.options.with_system_heimdalkrb5:
        if Options.options.with_system_mitkrb5:
            raise Errors.WafError('--with-system-heimdalkrb5 conflicts with ' +
                                  '--with-system-mitkrb5')
        if not Options.options.without_ad_dc:
            raise Errors.WafError('--with-system-heimdalkrb5 requires ' +
                                  '--without-ad-dc')
        conf.env.SYSTEM_LIBS += ('heimdal', 'asn1', 'com_err', 'roken',
                                 'hx509', 'wind', 'gssapi', 'hcrypto',
                                 'krb5', 'heimbase', 'asn1_compile',
                                 'compile_et', 'kdc', 'hdb', 'heimntlm')
        conf.PROCESS_SEPARATE_RULE('system_heimdal')

    if not conf.CONFIG_GET('KRB5_VENDOR'):
        conf.PROCESS_SEPARATE_RULE('embedded_heimdal')

    conf.RECURSE('source4/dsdb/samdb/ldb_modules')
    conf.RECURSE('source4/ntvfs/sysdep')
    conf.RECURSE('lib/util')
    conf.RECURSE('lib/util/charset')
    conf.RECURSE('source4/auth')
    conf.RECURSE('nsswitch')
    conf.RECURSE('libcli/smbreadline')
    conf.RECURSE('pidl')
    if conf.CONFIG_GET('ENABLE_SELFTEST'):
        if not (Options.options.without_ad_dc):
            conf.DEFINE('WITH_NTVFS_FILESERVER', 1)
        conf.RECURSE('testsuite/unittests')

    if Options.options.with_pthreadpool:
        if conf.CONFIG_SET('HAVE_PTHREAD'):
            conf.DEFINE('WITH_PTHREADPOOL', '1')
        else:
            Logs.warn("pthreadpool support cannot be enabled when pthread support was not found")
            conf.undefine('WITH_PTHREADPOOL')

    conf.SET_TARGET_TYPE('jansson', 'EMPTY')

    if Options.options.with_json is not False:
        if conf.CHECK_CFG(package='jansson', args='--cflags --libs',
                          msg='Checking for jansson'):
            conf.CHECK_FUNCS_IN('json_object', 'jansson')

    if not conf.CONFIG_GET('HAVE_JSON_OBJECT'):
        if Options.options.with_json is not False:
            conf.fatal("Jansson JSON support not found. "
                       "Try installing libjansson-dev or jansson-devel. "
                       "Otherwise, use --without-json to build without "
                       "JSON support. "
                       "JSON support is required for the JSON "
                       "formatted audit log feature, the AD DC, and "
                       "the JSON printers of the net utility")
        if not Options.options.without_ad_dc:
            raise Errors.WafError('--without-json requires --without-ad-dc. '
                                 'Jansson JSON library is required for '
                                 'building the AD DC')
        Logs.info("Building without Jansson JSON log support")

    conf.RECURSE('source3')
    conf.RECURSE('lib/texpect')
    conf.RECURSE('lib/tsocket')
    conf.RECURSE('python')
    if conf.env.with_ctdb:
        conf.RECURSE('ctdb')
    conf.RECURSE('lib/socket')
    conf.RECURSE('lib/mscat')
    conf.RECURSE('packaging')
    conf.RECURSE('lib/krb5_wrap')

    conf.SAMBA_CHECK_UNDEFINED_SYMBOL_FLAGS()

    # gentoo always adds this. We want our normal build to be as
    # strict as the strictest OS we support, so adding this here
    # allows us to find problems on our development hosts faster.
    # It also results in faster load time.

    if (not Options.options.address_sanitizer
        and conf.CHECK_LDFLAGS('-Wl,--as-needed')):
        conf.env.append_unique('LINKFLAGS', '-Wl,--as-needed')

    if not conf.CHECK_NEED_LC("-lc not needed"):
        conf.ADD_LDFLAGS('-lc', testflags=False)

    if not conf.CHECK_CODE('#include "tests/summary.c"',
                           define='SUMMARY_PASSES',
                           addmain=False,
                           msg='Checking configure summary'):
        raise Errors.WafError('configure summary failed')

    if Options.options.enable_pie is not False:
        if Options.options.enable_pie is True:
                need_pie = True
        else:
                # not specified, only build PIEs if supported by compiler
                need_pie = False
        if conf.check_cc(cflags='-fPIE', ldflags='-pie', mandatory=need_pie,
                         msg="Checking compiler for PIE support"):
            conf.env['ENABLE_PIE'] = True

    if Options.options.enable_relro is not False:
        if Options.options.enable_relro is True:
            need_relro = True
        else:
            # not specified, only build RELROs if supported by compiler
            need_relro = False
        if conf.check_cc(cflags='', ldflags='-Wl,-z,relro,-z,now', mandatory=need_relro,
                         msg="Checking compiler for full RELRO support"):
            conf.env['ENABLE_RELRO'] = True

    if conf.CONFIG_GET('ENABLE_SELFTEST') and \
       Options.options.with_smb1server is False and \
       Options.options.without_ad_dc is not True:
        conf.fatal('--without-smb1-server cannot be specified with '
                   '--enable-selftest/--enable-developer if '
                   '--without-ad-dc is NOT set!')

    if Options.options.with_smb1server is not False:
        conf.DEFINE('WITH_SMB1SERVER', '1')

    conf.env.debug = Options.options.debug
    conf.env.developer = Options.options.developer

    #
    # FreeBSD is broken. It doesn't include 'extern char **environ'
    # in any shared library, but statically inside crt0.o.
    #
    # If we're running on a FreeBSD with the GNU linker ld we
    # can get around this by explicitly telling the linker to
    # ignore 'environ' as an unresolved symbol in a shared library.
    #
    # However, the clang linker ld.lld-XX is broken in that it
    # doesn't have that option.
    #
    # First try to see if have '-Wl,--ignore-unresolved-symbol,environ'
    # and just use that if so.
    #
    # If not, we have to use '-Wl,--allow-shlib-undefined' instead
    # and remove all instances of '-Wl,-no-undefined'.

    if sys.platform.startswith('freebsd'):
        # Do we have Wl,--ignore-unresolved-symbol,environ ?
        flag_added = conf.ADD_LDFLAGS('-Wl,--ignore-unresolved-symbol,environ', testflags=True)
        if not flag_added:
            # No, fall back to -Wl,--allow-shlib-undefined.
            conf.ADD_LDFLAGS('-Wl,--allow-shlib-undefined', testflags=True)
            # Remove any uses of '-Wl,-no-undefined'
            conf.env['EXTRA_LDFLAGS'] = list(filter(('-Wl,-no-undefined').__ne__, conf.env['EXTRA_LDFLAGS']))
            # And make sure we don't try and remove it again when 'allow_undefined_symbols=true'
            conf.env.undefined_ldflags = []

    conf.SAMBA_CONFIG_H('include/config.h')

def etags(ctx):
    '''build TAGS file using etags'''
    source_root = os.path.dirname(Context.g_module.root_path)
    cmd = r'rm -f %s/TAGS && (find %s -name "*.[ch]" | egrep -v \.inst\. | xargs -n 100 etags -a)' % (source_root, source_root)
    print("Running: %s" % cmd)
    status = os.system(cmd)
    if os.WEXITSTATUS(status):
        raise Errors.WafError('etags failed')

def ctags(ctx):
    "build 'tags' file using ctags"
    source_root = os.path.dirname(Context.g_module.root_path)
    cmd = r'ctags --python-kinds=-i $(find %s -name "*.[ch]" | grep -v "*_proto\.h" | egrep -v \.inst\.) $(find %s -name "*.py")' % (source_root, source_root)
    print("Running: %s" % cmd)
    status = os.system(cmd)
    if os.WEXITSTATUS(status):
        raise Errors.WafError('ctags failed')


# putting this here enabled build in the list
# of commands in --help
def build(bld):
    '''build all targets'''
    samba_version.load_version(env=bld.env, is_install=bld.is_install)


def pep8(ctx):
    '''run pep8 validator'''
    cmd='PYTHONPATH=bin/python pep8 -r bin/python/samba'
    print("Running: %s" % cmd)
    status = os.system(cmd)
    if os.WEXITSTATUS(status):
        raise Errors.WafError('pep8 failed')


def dist():
    '''makes a tarball for distribution'''
    sambaversion = samba_version.load_version(env=None)

    os.system("make -C ctdb manpages")
    samba_dist.DIST_FILES('ctdb/doc:ctdb/doc', extend=True)

    os.system("DOC_VERSION='" + sambaversion.STRING + "' " + Context.g_module.top + "/release-scripts/build-manpages-nogit")
    samba_dist.DIST_FILES('bin/docs:docs', extend=True)

    if sambaversion.IS_SNAPSHOT:
        # write .distversion file and add to tar
        if not os.path.isdir(Context.g_module.out):
            os.makedirs(Context.g_module.out)
        distversionf = tempfile.NamedTemporaryFile(mode='w', prefix='.distversion',dir=Context.g_module.out)
        for field in sambaversion.vcs_fields:
            distveroption = field + '=' + str(sambaversion.vcs_fields[field])
            distversionf.write(distveroption + '\n')
        distversionf.flush()
        samba_dist.DIST_FILES('%s:.distversion' % distversionf.name, extend=True)

        samba_dist.dist()
        distversionf.close()
    else:
        samba_dist.dist()


def distcheck():
    '''test that distribution tarball builds and installs'''
    samba_version.load_version(env=None)

def printversion(ctx):
    '''print version'''
    ver = samba_version.load_version(env=None)
    print('Samba Version: ' + ver.STRING_WITH_NICKNAME)

def wildcard_cmd(cmd):
    '''called on a unknown command'''
    from samba_wildcard import run_named_build_task
    run_named_build_task(cmd)

def main():
    from samba_wildcard import wildcard_main

    wildcard_main(wildcard_cmd)
Scripting.main = main

def reconfigure(ctx):
    '''reconfigure if config scripts have changed'''
    samba_utils.reconfigure(ctx)


if os.path.isdir(os.path.join(top, ".git")):
    # Check if there are submodules that are checked out but out of date.
    for submodule, status in samba_git.read_submodule_status(top):
        if status == "out-of-date":
            raise Errors.WafError("some submodules are out of date. Please run 'git submodule update'")
