#!/usr/bin/env python

APPNAME = 'tdb'
VERSION = '1.4.3'

import sys, os

# find the buildtools directory
top = '.'
while not os.path.exists(top+'/buildtools') and len(top.split('/')) < 5:
    top = top + '/..'
sys.path.insert(0, top + '/buildtools/wafsamba')

out = 'bin'

import wafsamba
from wafsamba import samba_dist, samba_utils
from waflib import Options, Logs, Context
import shutil

samba_dist.DIST_DIRS('lib/tdb:. lib/replace:lib/replace buildtools:buildtools third_party/waf:third_party/waf')

tdb1_unit_tests = [
    'run-3G-file',
    'run-bad-tdb-header',
    'run',
    'run-check',
    'run-corrupt',
    'run-die-during-transaction',
    'run-endian',
    'run-incompatible',
    'run-nested-transactions',
    'run-nested-traverse',
    'run-no-lock-during-traverse',
    'run-oldhash',
    'run-open-during-transaction',
    'run-readonly-check',
    'run-rescue',
    'run-rescue-find_entry',
    'run-rdlock-upgrade',
    'run-rwlock-check',
    'run-summary',
    'run-transaction-expand',
    'run-traverse-in-transaction',
    'run-wronghash-fail',
    'run-zero-append',
    'run-fcntl-deadlock',
    'run-marklock-deadlock',
    'run-allrecord-traverse-deadlock',
    'run-mutex-openflags2',
    'run-mutex-trylock',
    'run-mutex-allrecord-bench',
    'run-mutex-allrecord-trylock',
    'run-mutex-allrecord-block',
    'run-mutex-transaction1',
    'run-mutex-die',
    'run-mutex1',
    'run-circular-chain',
    'run-circular-freelist',
    'run-traverse-chain',
]

def options(opt):
    opt.BUILTIN_DEFAULT('replace')
    opt.PRIVATE_EXTENSION_DEFAULT('tdb', noextension='tdb')
    opt.RECURSE('lib/replace')
    opt.add_option('--disable-tdb-mutex-locking',
                   help=("Disable the use of pthread robust mutexes"),
                   action="store_true", dest='disable_tdb_mutex_locking',
                   default=False)


def configure(conf):
    conf.env.disable_tdb_mutex_locking = getattr(Options.options,
                                                 'disable_tdb_mutex_locking',
                                                 False)
    if not conf.env.disable_tdb_mutex_locking:
        conf.env.replace_add_global_pthread = True
    conf.RECURSE('lib/replace')

    conf.env.standalone_tdb = conf.IN_LAUNCH_DIR()
    conf.env.building_tdb = True

    if not conf.env.standalone_tdb:
        if conf.CHECK_BUNDLED_SYSTEM_PKG('tdb', minversion=VERSION,
                                     implied_deps='replace'):
            conf.define('USING_SYSTEM_TDB', 1)
            conf.env.building_tdb = False
            if not conf.env.disable_python and \
                conf.CHECK_BUNDLED_SYSTEM_PYTHON('pytdb', 'tdb', minversion=VERSION):
                conf.define('USING_SYSTEM_PYTDB', 1)

    if (conf.CONFIG_SET('HAVE_ROBUST_MUTEXES') and
        conf.env.building_tdb and
        not conf.env.disable_tdb_mutex_locking):
        conf.define('USE_TDB_MUTEX_LOCKING', 1)

    conf.CHECK_XSLTPROC_MANPAGES()

    conf.SAMBA_CHECK_PYTHON()
    conf.SAMBA_CHECK_PYTHON_HEADERS()

    conf.SAMBA_CONFIG_H()

    conf.SAMBA_CHECK_UNDEFINED_SYMBOL_FLAGS()

def build(bld):
    bld.RECURSE('lib/replace')

    COMMON_FILES='''check.c error.c tdb.c traverse.c
                    freelistcheck.c lock.c dump.c freelist.c
                    io.c open.c transaction.c hash.c summary.c rescue.c
                    mutex.c'''

    COMMON_SRC = bld.SUBDIR('common', COMMON_FILES)

    if bld.env.standalone_tdb:
        bld.env.PKGCONFIGDIR = '${LIBDIR}/pkgconfig'
        private_library = False
    else:
        private_library = True

    if not bld.CONFIG_SET('USING_SYSTEM_TDB'):

        tdb_deps = 'replace'

        if bld.CONFIG_SET('USE_TDB_MUTEX_LOCKING'):
            tdb_deps += ' pthread'

        bld.SAMBA_LIBRARY('tdb',
                          COMMON_SRC,
                          deps=tdb_deps,
                          includes='include',
                          abi_directory='ABI',
                          abi_match='tdb_*',
                          hide_symbols=True,
                          vnum=VERSION,
                          public_headers=('' if private_library else 'include/tdb.h'),
                          public_headers_install=not private_library,
                          pc_files='tdb.pc',
                          private_library=private_library)

        bld.SAMBA_BINARY('tdbtorture',
                         'tools/tdbtorture.c',
                         'tdb',
                         install=False)

        bld.SAMBA_BINARY('tdbrestore',
                         'tools/tdbrestore.c',
                         'tdb', manpages='man/tdbrestore.8')

        bld.SAMBA_BINARY('tdbdump',
                         'tools/tdbdump.c',
                         'tdb', manpages='man/tdbdump.8')

        bld.SAMBA_BINARY('tdbbackup',
                         'tools/tdbbackup.c',
                         'tdb',
                         manpages='man/tdbbackup.8')

        bld.SAMBA_BINARY('tdbtool',
                         'tools/tdbtool.c',
                         'tdb', manpages='man/tdbtool.8')

        if bld.env.standalone_tdb:
            # FIXME: This hardcoded list is stupid, stupid, stupid.
            bld.SAMBA_SUBSYSTEM('tdb-test-helpers',
                                'test/external-agent.c test/lock-tracking.c test/logging.c',
                                tdb_deps,
                                includes='include')

            for t in tdb1_unit_tests:
                b = "tdb1-" + t
                s = "test/" + t + ".c"
                bld.SAMBA_BINARY(b, s, 'replace tdb-test-helpers',
                                 includes='include', install=False)

    if not bld.CONFIG_SET('USING_SYSTEM_PYTDB'):
        bld.SAMBA_PYTHON('pytdb',
                         'pytdb.c',
                         deps='tdb',
                         enabled=not bld.env.disable_python,
                         realname='tdb.so',
                         cflags='-DPACKAGE_VERSION=\"%s\"' % VERSION)

        if not bld.env.disable_python:
            bld.SAMBA_SCRIPT('_tdb_text.py',
                             pattern='_tdb_text.py',
                             installdir='python')
            
            bld.INSTALL_FILES('${PYTHONARCHDIR}', '_tdb_text.py')

def testonly(ctx):
    '''run tdb testsuite'''
    ecode = 0

    blddir = Context.g_module.out
    test_prefix = "%s/st" % (blddir)
    shutil.rmtree(test_prefix, ignore_errors=True)
    os.makedirs(test_prefix)
    os.environ['TEST_DATA_PREFIX'] = test_prefix

    env = samba_utils.LOAD_ENVIRONMENT()
    # FIXME: This is horrible :(
    if env.building_tdb:
        # Create scratch directory for tests.
        testdir = os.path.join(test_prefix, 'tdb-tests')
        samba_utils.mkdir_p(testdir)
        # Symlink back to source dir so it can find tests in test/
        link = os.path.join(testdir, 'test')
        if not os.path.exists(link):
            os.symlink(ctx.path.make_node('test').abspath(), link)

        sh_tests = ["test/test_tdbbackup.sh test/jenkins-be-hash.tdb"]

        for sh_test in sh_tests:
            cmd = "BINDIR=%s %s" % (blddir, sh_test)
            print("shell test: " + cmd)
            ret = samba_utils.RUN_COMMAND(cmd)
            if ret != 0:
                print("%s sh test failed" % cmd)
                ecode = ret
                break

        for t in tdb1_unit_tests:
            f = "tdb1-" + t
            cmd = "cd " + testdir + " && " + os.path.abspath(os.path.join(blddir, f)) + " > test-output 2>&1"
            print("..." + f)
            ret = samba_utils.RUN_COMMAND(cmd)
            if ret != 0:
                print("%s failed:" % f)
                samba_utils.RUN_COMMAND("cat " + os.path.join(testdir, 'test-output'))
                ecode = ret
                break

    if ecode == 0:
        cmd = os.path.join(blddir, 'tdbtorture')
        ret = samba_utils.RUN_COMMAND(cmd)
        print("testsuite returned %d" % ret)
        if ret != 0:
            ecode = ret

    pyret = samba_utils.RUN_PYTHON_TESTS(['python/tests/simple.py'])
    print("python testsuite returned %d" % pyret)
    sys.exit(ecode or pyret)

# WAF doesn't build the unit tests for this, maybe because they don't link with tdb?
# This forces it
def test(ctx):
    Options.commands.append('build')
    Options.commands.append('testonly')

def dist():
    '''makes a tarball for distribution'''
    samba_dist.dist()

def reconfigure(ctx):
    '''reconfigure if config scripts have changed'''
    samba_utils.reconfigure(ctx)
