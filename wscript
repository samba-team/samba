#!/usr/bin/env python

srcdir = '.'
blddir = 'bin'

APPNAME='samba'
VERSION=None

import sys, os, tempfile
sys.path.insert(0, srcdir+"/buildtools/wafsamba")
import wafsamba, Options, samba_dist, Scripting, Utils, samba_version


samba_dist.DIST_DIRS('.')
samba_dist.DIST_BLACKLIST('.gitignore .bzrignore source4/selftest/provisions')

# install in /usr/local/samba by default
Options.default_prefix = '/usr/local/samba'

# This callback optionally takes a list of paths as arguments:
# --with-system_mitkrb5 /path/to/krb5 /another/path
def system_mitkrb5_callback(option, opt, value, parser):
    setattr(parser.values, option.dest, True)
    value = []
    for arg in parser.rargs:
        # stop on --foo like options
        if arg[:2] == "--" and len(arg) > 2:
            break
        value.append(arg)
    if len(value)>0:
        del parser.rargs[:len(value)]
        setattr(parser.values, option.dest, value)

def set_options(opt):
    opt.BUILTIN_DEFAULT('NONE')
    opt.PRIVATE_EXTENSION_DEFAULT('samba4')
    opt.RECURSE('lib/replace')
    opt.RECURSE('dynconfig')
    opt.RECURSE('lib/ldb')
    opt.RECURSE('lib/ntdb')
    opt.RECURSE('selftest')
    opt.RECURSE('source4/lib/tls')
    opt.RECURSE('pidl')
    opt.RECURSE('source3')
    opt.RECURSE('lib/util')
    opt.RECURSE('ctdb')

    opt.add_option('--with-system-mitkrb5',
                   help='enable system MIT krb5 build (includes Samba 4 client and Samba 3 code base).'+
                        'You may specify list of paths where Kerberos is installed (e.g. /usr/local /usr/kerberos) to search krb5-config',
                   action='callback', callback=system_mitkrb5_callback, dest='with_system_mitkrb5', default=False)

    opt.add_option('--without-ad-dc',
                   help='disable AD DC functionality (enables Samba 4 client and Samba 3 code base).',
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

    opt.add_option('--with-systemd',
                   help=("Enable systemd integration"),
                   action='store_true', dest='enable_systemd')

    opt.add_option('--without-systemd',
                   help=("Disable systemd integration"),
                   action='store_false', dest='enable_systemd')

    gr = opt.option_group('developer options')

    opt.tool_options('python') # options for disabling pyc or pyo compilation
    # enable options related to building python extensions


def configure(conf):
    version = samba_version.load_version(env=conf.env)

    conf.DEFINE('CONFIG_H_IS_FROM_SAMBA', 1)
    conf.DEFINE('_SAMBA_BUILD_', version.MAJOR, add_to_cflags=True)
    conf.DEFINE('HAVE_CONFIG_H', 1, add_to_cflags=True)

    if Options.options.developer:
        conf.ADD_CFLAGS('-DDEVELOPER -DDEBUG_PASSWORD')
        conf.env.DEVELOPER = True

    conf.ADD_EXTRA_INCLUDES('#include/public #source4 #lib #source4/lib #source4/include #include #lib/replace')

    conf.env.replace_add_global_pthread = True
    conf.RECURSE('lib/replace')

    conf.SAMBA_CHECK_PERL(mandatory=True)
    conf.find_program('xsltproc', var='XSLTPROC')

    conf.SAMBA_CHECK_PYTHON(mandatory=True, version=(2,5,0))
    conf.SAMBA_CHECK_PYTHON_HEADERS(mandatory=True)

    if sys.platform == 'darwin' and not conf.env['HAVE_ENVIRON_DECL']:
        # Mac OSX needs to have this and it's also needed that the python is compiled with this
        # otherwise you face errors about common symbols
        if not conf.CHECK_SHLIB_W_PYTHON("Checking if -fno-common is needed"):
            conf.ADD_CFLAGS('-fno-common')
        if not conf.CHECK_SHLIB_W_PYTHON("Checking if -undefined dynamic_lookup is not need"):
            conf.env.append_value('shlib_LINKFLAGS', ['-undefined', 'dynamic_lookup'])

    if sys.platform == 'darwin':
        conf.ADD_LDFLAGS('-framework CoreFoundation')

    if int(conf.env['PYTHON_VERSION'][0]) >= 3:
        raise Utils.WafError('Python version 3.x is not supported by Samba yet')

    conf.RECURSE('dynconfig')

    if conf.CHECK_FOR_THIRD_PARTY():
        conf.RECURSE('third_party/zlib')
        conf.RECURSE('third_party/popt')
    else:
        if not conf.CHECK_ZLIB():
            raise Utils.WafError('zlib development packages have not been found.\nIf third_party is installed, check that it is in the proper place.')
        else:
            conf.define('USING_SYSTEM_ZLIB',1)

        if not conf.CHECK_POPT():
            raise Utils.WafError('popt development packages have not been found.\nIf third_party is installed, check that it is in the proper place.')
        else:
            conf.define('USING_SYSTEM_POPT', 1)

    conf.RECURSE('lib/ldb')

    if Options.options.with_system_mitkrb5:
        conf.PROCESS_SEPARATE_RULE('system_mitkrb5')
    if not (Options.options.without_ad_dc or Options.options.with_system_mitkrb5):
        conf.DEFINE('AD_DC_BUILD_IS_ENABLED', 1)
    # Only process heimdal_build for non-MIT KRB5 builds
    # When MIT KRB5 checks are done as above, conf.env.KRB5_VENDOR will be set
    # to the lowcased output of 'krb5-config --vendor'.
    # If it is not set or the output is 'heimdal', we are dealing with
    # system-provided or embedded Heimdal build
    if conf.CONFIG_GET('KRB5_VENDOR') in (None, 'heimdal'):
        conf.RECURSE('source4/heimdal_build')
    conf.RECURSE('source4/lib/tls')
    conf.RECURSE('source4/ntvfs/sysdep')
    conf.RECURSE('lib/util')
    conf.RECURSE('lib/ccan')
    conf.RECURSE('lib/ntdb')
    conf.RECURSE('lib/util/charset')
    conf.RECURSE('source4/auth')
    conf.RECURSE('lib/nss_wrapper')
    conf.RECURSE('nsswitch')
    conf.RECURSE('lib/socket_wrapper')
    conf.RECURSE('lib/uid_wrapper')
    conf.RECURSE('lib/subunit/c')
    conf.RECURSE('libcli/smbreadline')
    conf.RECURSE('lib/crypto')
    conf.RECURSE('pidl')
    conf.RECURSE('selftest')
    conf.RECURSE('source3')
    conf.RECURSE('lib/texpect')
    if conf.env.with_ctdb:
        conf.RECURSE('ctdb')

    conf.SAMBA_CHECK_UNDEFINED_SYMBOL_FLAGS()

    # gentoo always adds this. We want our normal build to be as
    # strict as the strictest OS we support, so adding this here
    # allows us to find problems on our development hosts faster.
    # It also results in faster load time.

    if not sys.platform.startswith("openbsd"):
        conf.env.asneeded_ldflags = conf.ADD_LDFLAGS('-Wl,--as-needed', testflags=True)

    if not conf.CHECK_NEED_LC("-lc not needed"):
        conf.ADD_LDFLAGS('-lc', testflags=False)

    # we don't want PYTHONDIR in config.h, as otherwise changing
    # --prefix causes a complete rebuild
    del(conf.env.defines['PYTHONDIR'])
    del(conf.env.defines['PYTHONARCHDIR'])

    if not conf.CHECK_CODE('#include "tests/summary.c"',
                           define='SUMMARY_PASSES',
                           addmain=False,
                           msg='Checking configure summary'):
        raise Utils.WafError('configure summary failed')

    if Options.options.enable_pie != False:
        if Options.options.enable_pie == True:
                need_pie = True
        else:
                # not specified, only build PIEs if supported by compiler
                need_pie = False
        if conf.check_cc(cflags='-fPIE', ldflags='-pie', mandatory=need_pie,
                         msg="Checking compiler for PIE support"):
		conf.env['ENABLE_PIE'] = True

    if Options.options.enable_relro != False:
        if Options.options.enable_relro == True:
            need_relro = True
        else:
            # not specified, only build RELROs if supported by compiler
            need_relro = False
        if conf.check_cc(cflags='', ldflags='-Wl,-z,relro,-z,now', mandatory=need_relro,
                         msg="Checking compiler for full RELRO support"):
            conf.env['ENABLE_RELRO'] = True

    if Options.options.enable_systemd != False:
        conf.check_cfg(package='libsystemd-daemon', args='--cflags --libs',
                       msg='Checking for libsystemd-daemon', uselib_store="SYSTEMD-DAEMON")
        conf.CHECK_HEADERS('systemd/sd-daemon.h', lib='systemd-daemon')
        conf.CHECK_LIB('systemd-daemon', shlib=True)

    if (conf.CONFIG_SET('HAVE_SYSTEMD_SD_DAEMON_H') and
        conf.CONFIG_SET('HAVE_LIBSYSTEMD_DAEMON')):
        conf.DEFINE('HAVE_SYSTEMD', '1')
        conf.env['ENABLE_SYSTEMD'] = True
    else:
        conf.SET_TARGET_TYPE('systemd-daemon', 'EMPTY')
        conf.undefine('HAVE_SYSTEMD')

    conf.SAMBA_CONFIG_H('include/config.h')

def etags(ctx):
    '''build TAGS file using etags'''
    import Utils
    source_root = os.path.dirname(Utils.g_module.root_path)
    cmd = 'rm -f %s/TAGS && (find %s -name "*.[ch]" | egrep -v \.inst\. | xargs -n 100 etags -a)' % (source_root, source_root)
    print("Running: %s" % cmd)
    status = os.system(cmd)
    if os.WEXITSTATUS(status):
        raise Utils.WafError('etags failed')

def ctags(ctx):
    "build 'tags' file using ctags"
    import Utils
    source_root = os.path.dirname(Utils.g_module.root_path)
    cmd = 'ctags --python-kinds=-i $(find %s -name "*.[ch]" | grep -v "*_proto\.h" | egrep -v \.inst\.) $(find %s -name "*.py")' % (source_root, source_root)
    print("Running: %s" % cmd)
    status = os.system(cmd)
    if os.WEXITSTATUS(status):
        raise Utils.WafError('ctags failed')

# putting this here enabled build in the list
# of commands in --help
def build(bld):
    '''build all targets'''
    samba_version.load_version(env=bld.env, is_install=bld.is_install)
    pass


def pydoctor(ctx):
    '''build python apidocs'''
    bp = os.path.abspath('bin/python')
    mpaths = {}
    for m in ['talloc', 'tdb', 'ldb', 'ntdb']:
        f = os.popen("PYTHONPATH=%s python -c 'import %s; print %s.__file__'" % (bp, m, m), 'r')
        try:
            mpaths[m] = f.read().strip()
        finally:
            f.close()
    cmd='PYTHONPATH=%s pydoctor --introspect-c-modules --project-name=Samba --project-url=http://www.samba.org --make-html --docformat=restructuredtext --add-package bin/python/samba --add-module %s --add-module %s --add-module %s' % (
        bp, mpaths['tdb'], mpaths['ldb'], mpaths['talloc'], mpaths['ntdb'])
    print("Running: %s" % cmd)
    status = os.system(cmd)
    if os.WEXITSTATUS(status):
        raise Utils.WafError('pydoctor failed')


def pep8(ctx):
    '''run pep8 validator'''
    cmd='PYTHONPATH=bin/python pep8 -r bin/python/samba'
    print("Running: %s" % cmd)
    status = os.system(cmd)
    if os.WEXITSTATUS(status):
        raise Utils.WafError('pep8 failed')


def wafdocs(ctx):
    '''build wafsamba apidocs'''
    from samba_utils import recursive_dirlist
    os.system('pwd')
    list = recursive_dirlist('../buildtools/wafsamba', '.', pattern='*.py')

    cmd='PYTHONPATH=bin/python pydoctor --project-name=wafsamba --project-url=http://www.samba.org --make-html --docformat=restructuredtext'
    print(list)
    for f in list:
        cmd += ' --add-module %s' % f
    print("Running: %s" % cmd)
    status = os.system(cmd)
    if os.WEXITSTATUS(status):
        raise Utils.WafError('wafdocs failed')


def dist():
    '''makes a tarball for distribution'''
    sambaversion = samba_version.load_version(env=None)

    os.system("make -C ctdb/doc")
    samba_dist.DIST_FILES('ctdb/doc:ctdb/doc', extend=True)

    os.system(srcdir + "/release-scripts/build-manpages-nogit")
    samba_dist.DIST_FILES('bin/docs:docs', extend=True)

    if sambaversion.IS_SNAPSHOT:
        # write .distversion file and add to tar
        if not os.path.isdir(blddir):
            os.makedirs(blddir)
        distversionf = tempfile.NamedTemporaryFile(mode='w', prefix='.distversion',dir=blddir)
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
    import Scripting
    d = Scripting.distcheck
    d()

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
    import samba_utils
    samba_utils.reconfigure(ctx)
