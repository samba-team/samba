#!/usr/bin/env python3
# run tests on all Samba subprojects and push to a git tree on success
# Copyright Andrew Tridgell 2010
# released under GNU GPL v3 or later

from __future__ import print_function
from subprocess import call, check_call, check_output, Popen, PIPE, CalledProcessError
import os
import tarfile
import sys
import time
import random
from optparse import OptionParser
import smtplib
import email
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from distutils.sysconfig import get_python_lib
import platform

try:
    from waflib.Build import CACHE_SUFFIX
except ImportError:
    sys.path.insert(0, "./third_party/waf")
    from waflib.Build import CACHE_SUFFIX


os.environ["PYTHONUNBUFFERED"] = "1"

# This speeds up testing remarkably.
os.environ['TDB_NO_FSYNC'] = '1'


def find_git_root():
    '''get to the top of the git repo'''
    p = os.getcwd()
    while p != '/':
        if os.path.exists(os.path.join(p, ".git")):
            return p
        p = os.path.abspath(os.path.join(p, '..'))
    return None


gitroot = find_git_root()
if gitroot is None:
    raise Exception("Failed to find git root")


def_testbase = os.getenv("AUTOBUILD_TESTBASE", "/memdisk/%s" % os.getenv('USER'))

parser = OptionParser()
parser.add_option("--tail", help="show output while running", default=False, action="store_true")
parser.add_option("--keeplogs", help="keep logs", default=False, action="store_true")
parser.add_option("--nocleanup", help="don't remove test tree", default=False, action="store_true")
parser.add_option("--testbase", help="base directory to run tests in (default %s)" % def_testbase,
                  default=def_testbase)
parser.add_option("--passcmd", help="command to run on success", default=None)
parser.add_option("--verbose", help="show all commands as they are run",
                  default=False, action="store_true")
parser.add_option("--rebase", help="rebase on the given tree before testing",
                  default=None, type='str')
parser.add_option("--pushto", help="push to a git url on success",
                  default=None, type='str')
parser.add_option("--mark", help="add a Tested-By signoff before pushing",
                  default=False, action="store_true")
parser.add_option("--fix-whitespace", help="fix whitespace on rebase",
                  default=False, action="store_true")
parser.add_option("--retry", help="automatically retry if master changes",
                  default=False, action="store_true")
parser.add_option("--email", help="send email to the given address on failure",
                  type='str', default=None)
parser.add_option("--email-from", help="send email from the given address",
                  type='str', default="autobuild@samba.org")
parser.add_option("--email-server", help="send email via the given server",
                  type='str', default='localhost')
parser.add_option("--always-email", help="always send email, even on success",
                  action="store_true")
parser.add_option("--daemon", help="daemonize after initial setup",
                  action="store_true")
parser.add_option("--branch", help="the branch to work on (default=master)",
                  default="master", type='str')
parser.add_option("--log-base", help="location where the logs can be found (default=cwd)",
                  default=gitroot, type='str')
parser.add_option("--attach-logs", help="Attach logs to mails sent on success/failure?",
                  default=False, action="store_true")
parser.add_option("--restrict-tests", help="run as make test with this TESTS= regex",
                  default='')
parser.add_option("--enable-coverage", dest='enable_coverage',
                  action="store_const", const='--enable-coverage', default='',
                  help="Add --enable-coverage option while configure")

(options, args) = parser.parse_args()

if options.retry:
    if options.rebase is None:
        raise Exception('You can only use --retry if you also rebase')

testbase = "%s/b%u" % (options.testbase, os.getpid())
test_master = "%s/master" % testbase
test_prefix = "%s/prefix" % testbase
test_tmpdir = "%s/tmp" % testbase
os.environ['TMPDIR'] = test_tmpdir

if options.enable_coverage:
    LCOV_CMD = "cd ${TEST_SOURCE_DIR} && lcov --capture --directory . --output-file ${LOG_BASE}/${NAME}.info --rc 'geninfo_adjust_src_path=${TEST_SOURCE_DIR}/'"
else:
    LCOV_CMD = 'echo "lcov skipped since no --enable-coverage specified"'

if args:
    # If we are only running specific test,
    # do not sleep randomly to wait for it to start
    def random_sleep(low, high):
        return 'sleep 1'
else:
    def random_sleep(low, high):
        return 'sleep {}'.format(random.randint(low, high))

cleanup_list = []

builddirs = {
    "ctdb": "ctdb",
    "ldb": "lib/ldb",
    "tdb": "lib/tdb",
    "talloc": "lib/talloc",
    "replace": "lib/replace",
    "tevent": "lib/tevent",
    "pidl": "pidl",
    "docs-xml": "docs-xml"
}

ctdb_configure_params = " --enable-developer ${PREFIX}"
samba_configure_params = " ${ENABLE_COVERAGE} ${PREFIX} --with-profiling-data"

samba_libs_envvars = "PYTHONPATH=${PYTHON_PREFIX}:$PYTHONPATH"
samba_libs_envvars += " PKG_CONFIG_PATH=$PKG_CONFIG_PATH:${PREFIX_DIR}/lib/pkgconfig"
samba_libs_envvars += " ADDITIONAL_CFLAGS='-Wmissing-prototypes'"
samba_libs_configure_base = samba_libs_envvars + " ./configure --abi-check ${ENABLE_COVERAGE} --enable-debug -C ${PREFIX}"
samba_libs_configure_libs = samba_libs_configure_base + " --bundled-libraries=cmocka,popt,NONE"
samba_libs_configure_bundled_libs = " --bundled-libraries=!talloc,!pytalloc-util,!tdb,!pytdb,!ldb,!pyldb,!pyldb-util,!tevent,!pytevent,!popt"
samba_libs_configure_samba = samba_libs_configure_base + samba_libs_configure_bundled_libs


def format_option(name, value=None):
    """Format option as str list."""
    if value is None:  # boolean option
        return [name]
    if not isinstance(value, list):  # single value option
        value = [value]
    # repeatable option
    return ['{}={}'.format(name, item) for item in value]


def make_test(
        cmd='make test',
        TESTS='',
        include_envs=None,
        exclude_envs=None):

    test_options = []
    if include_envs:
        test_options = format_option('--include-env', include_envs)
    if exclude_envs:
        test_options = format_option('--exclude-env', exclude_envs)
    if test_options:
        # join envs options to original test options
        TESTS = (TESTS + ' ' + ' '.join(test_options)).strip()

    _options = []

    # Allow getting a full CI with
    # git push -o ci.variable='AUTOBUILD_FAIL_IMMEDIATELY=0'

    FAIL_IMMEDIATELY = os.getenv("AUTOBUILD_FAIL_IMMEDIATELY", "1")

    if int(FAIL_IMMEDIATELY):
        _options.append('FAIL_IMMEDIATELY=1')
    if TESTS:
        _options.append("TESTS='{}'".format(TESTS))

    return ' '.join([cmd] + _options)


# When updating this list, also update .gitlab-ci.yml to add the job
# and to make it a dependency of 'page' for the coverage report.

tasks = {
    "ctdb": [
        ("random-sleep", random_sleep(300, 900)),
        ("configure", "./configure " + ctdb_configure_params),
        ("make", "make all"),
        ("install", "make install"),
        ("test", "make autotest"),
        ("check-clean-tree", "../script/clean-source-tree.sh"),
        ("clean", "make clean"),
        ],

    "docs-xml": [
        ("random-sleep", random_sleep(300, 900)),
        ("autoconf", "autoconf"),
        ("configure", "./configure"),
        ("make", "make html htmlman"),
        ("clean", "make clean"),
        ],

    # We have 'test' before 'install' because, 'test' should work without 'install (runs all the other envs)'
    "samba": [
        ("random-sleep", random_sleep(300, 900)),
        ("configure", "./configure.developer --with-selftest-prefix=./bin/ab" + samba_configure_params),
        ("make", "make -j"),
        ("test", make_test(exclude_envs=[
            "none",
            "nt4_dc",
            "nt4_dc_smb1",
            "nt4_dc_smb1_done",
            "nt4_dc_schannel",
            "nt4_member",
            "ad_dc",
            "ad_dc_smb1",
            "ad_dc_smb1_done",
            "ad_dc_backup",
            "ad_dc_ntvfs",
            "ad_dc_default",
            "ad_dc_default_smb1",
            "ad_dc_slowtests",
            "ad_dc_no_nss",
            "ad_dc_no_ntlm",
            "fl2003dc",
            "fl2008dc",
            "fl2008r2dc",
            "ad_member",
            "ad_member_idmap_rid",
            "ad_member_idmap_ad",
            "ad_member_rfc2307",
            "chgdcpass",
            "vampire_2000_dc",
            "fl2000dc",
            "fileserver",
            "fileserver_smb1",
            "fileserver_smb1_done",
            "maptoguest",
            "simpleserver",
            "backupfromdc",
            "restoredc",
            "renamedc",
            "offlinebackupdc",
            "labdc",
            "preforkrestartdc",
            "proclimitdc",
            "promoted_dc",
            "vampire_dc",
            "rodc",
            "ad_dc_default",
            "ad_dc_default_smb1",
            "ad_dc_default_smb1_done",
            "ad_dc_slowtests",
            "schema_pair_dc",
            "schema_dc",
            "clusteredmember_smb1",
            ])),
        ("test-slow-none", make_test(cmd='make test', TESTS="--include=selftest/slow-none", include_envs=["none"])),
        ("lcov", LCOV_CMD),
        ("install", "make install"),
        ("check-clean-tree", "script/clean-source-tree.sh"),
        ("clean", "make clean"),
        ],

    # We have 'test' before 'install' because, 'test' should work without 'install (runs all the other envs)'
    "samba-mitkrb5": [
        ("random-sleep", random_sleep(300, 900)),
        ("configure", "./configure.developer --with-selftest-prefix=./bin/ab --with-system-mitkrb5 --with-experimental-mit-ad-dc" + samba_configure_params),
        ("make", "make -j"),
        ("test", make_test(exclude_envs=[
            "none",
            "nt4_dc",
            "nt4_dc_smb1",
            "nt4_dc_smb1_done",
            "nt4_dc_schannel",
            "nt4_member",
            "ad_dc",
            "ad_dc_smb1",
            "ad_dc_smb1_done",
            "ad_dc_backup",
            "ad_dc_ntvfs",
            "ad_dc_default",
            "ad_dc_default_smb1",
            "ad_dc_default_smb1_done",
            "ad_dc_slowtests",
            "ad_dc_no_nss",
            "ad_dc_no_ntlm",
            "fl2003dc",
            "fl2008dc",
            "fl2008r2dc",
            "ad_member",
            "ad_member_idmap_rid",
            "ad_member_idmap_ad",
            "ad_member_rfc2307",
            "chgdcpass",
            "vampire_2000_dc",
            "fl2000dc",
            "fileserver",
            "fileserver_smb1",
            "fileserver_smb1_done",
            "maptoguest",
            "simpleserver",
            "backupfromdc",
            "restoredc",
            "renamedc",
            "offlinebackupdc",
            "labdc",
            "preforkrestartdc",
            "proclimitdc",
            "promoted_dc",
            "vampire_dc",
            "rodc",
            "ad_dc_default",
            "ad_dc_default_smb1",
            "ad_dc_default_smb1_done",
            "ad_dc_slowtests",
            "schema_pair_dc",
            "schema_dc",
            "clusteredmember_smb1",
            ])),
        ("lcov", LCOV_CMD),
        ("install", "make install"),
        ("check-clean-tree", "script/clean-source-tree.sh"),
        ("clean", "make clean"),
        ],

    "samba-nt4": [
        ("random-sleep", random_sleep(300, 900)),
        ("configure", "./configure.developer --without-ad-dc --without-ldap --without-ads --without-json --with-selftest-prefix=./bin/ab" + samba_configure_params),
        ("make", "make -j"),
        ("test", make_test(include_envs=[
            "nt4_dc",
            "nt4_dc_smb1",
            "nt4_dc_smb1_done",
            "nt4_dc_schannel",
            "nt4_member",
            "simpleserver",
            ])),
        ("lcov", LCOV_CMD),
        ("install", "make install"),
        ("check-clean-tree", "script/clean-source-tree.sh"),
        ("clean", "make clean"),
        ],

    "samba-fileserver": [
        ("random-sleep", random_sleep(300, 900)),
        ("configure", "./configure.developer --without-ad-dc --with-system-heimdalkrb5 --with-selftest-prefix=./bin/ab" + samba_configure_params),
        ("make", "make -j"),
        ("test", make_test(include_envs=[
            "fileserver",
            "fileserver_smb1",
            "fileserver_smb1_done",
            "maptoguest",
            "ktest", # ktest is also tested in samba and samba-mitkrb5
                     # but is tested here against a system Heimdal
            ])),
        ("lcov", LCOV_CMD),
        ("check-clean-tree", "script/clean-source-tree.sh"),
        ],

    "samba-admem": [
        ("random-sleep", random_sleep(300, 900)),
        ("configure", "./configure.developer --with-selftest-prefix=./bin/ab" + samba_configure_params),
        ("make", "make -j"),
        ("test", make_test(include_envs=[
            "ad_member",
            "ad_member_idmap_rid",
            "ad_member_idmap_ad",
            "ad_member_rfc2307",
            ])),
        ("lcov", LCOV_CMD),
        ("check-clean-tree", "script/clean-source-tree.sh"),
        ],

    "samba-ad-dc-1": [
        ("random-sleep", random_sleep(1, 1)),
        ("configure", "./configure.developer --with-selftest-prefix=./bin/ab" + samba_configure_params),
        ("make", "make -j"),
        ("test", make_test(include_envs=[
            "ad_dc",
            "ad_dc_smb1",
            "ad_dc_smb1_done",
            "ad_dc_no_nss",
            "ad_dc_no_ntlm",
            ])),
        ("lcov", LCOV_CMD),
        ("check-clean-tree", "script/clean-source-tree.sh"),
        ],

    "samba-ad-dc-2": [
        ("random-sleep", random_sleep(1, 1)),
        ("configure", "./configure.developer --with-selftest-prefix=./bin/ab" + samba_configure_params),
        ("make", "make -j"),
        ("test", make_test(include_envs=[
            "vampire_dc",
            "vampire_2000_dc",
            "rodc",
            ])),
        ("lcov", LCOV_CMD),
        ("check-clean-tree", "script/clean-source-tree.sh"),
        ],

    "samba-ad-dc-3": [
        ("random-sleep", random_sleep(1, 1)),
        ("configure", "./configure.developer --with-selftest-prefix=./bin/ab" + samba_configure_params),
        ("make", "make -j"),
        ("test", make_test(include_envs=[
            "promoted_dc",
            "chgdcpass",
            "preforkrestartdc",
            "proclimitdc",
            ])),
        ("lcov", LCOV_CMD),
        ("check-clean-tree", "script/clean-source-tree.sh"),
        ],

    "samba-ad-dc-4": [
        ("random-sleep", random_sleep(1, 1)),
        ("configure", "./configure.developer --with-selftest-prefix=./bin/ab" + samba_configure_params),
        ("make", "make -j"),
        ("test", make_test(include_envs=[
            "fl2000dc",
            "fl2003dc",
            "fl2008dc",
            "fl2008r2dc",
            ])),
        ("lcov", LCOV_CMD),
        ("check-clean-tree", "script/clean-source-tree.sh"),
        ],

    "samba-ad-dc-5": [
        ("random-sleep", random_sleep(1, 1)),
        ("configure", "./configure.developer --with-selftest-prefix=./bin/ab" + samba_configure_params),
        ("make", "make -j"),
        ("test", make_test(include_envs=[
            "ad_dc_default", "ad_dc_default_smb1", "ad_dc_default_smb1_done"])),
        ("lcov", LCOV_CMD),
        ("check-clean-tree", "script/clean-source-tree.sh"),
        ],

    "samba-ad-dc-6": [
        ("random-sleep", random_sleep(1, 1)),
        ("configure", "./configure.developer --with-selftest-prefix=./bin/ab" + samba_configure_params),
        ("make", "make -j"),
        ("test", make_test(include_envs=["ad_dc_slowtests"])),
        ("lcov", LCOV_CMD),
        ("check-clean-tree", "script/clean-source-tree.sh"),
        ],

    "samba-schemaupgrade": [
        ("random-sleep", random_sleep(1, 1)),
        ("configure", "./configure.developer --with-selftest-prefix=./bin/ab" + samba_configure_params),
        ("make", "make -j"),
        ("test", make_test(include_envs=["schema_dc", "schema_pair_dc"])),
        ("lcov", LCOV_CMD),
        ("check-clean-tree", "script/clean-source-tree.sh"),
        ],

    # We split out the ad_dc_ntvfs tests (which are long) so other test do not wait
    # This is currently the longest task, so we don't randomly delay it.
    "samba-ad-dc-ntvfs": [
        ("random-sleep", random_sleep(1, 1)),
        ("configure", "./configure.developer --with-selftest-prefix=./bin/ab" + samba_configure_params),
        ("make", "make -j"),
        ("test", make_test(include_envs=["ad_dc_ntvfs"])),
        ("lcov", LCOV_CMD),
        ("check-clean-tree", "script/clean-source-tree.sh"),
        ],

    # Test fips compliance
    "samba-fips": [
        ("random-sleep", random_sleep(100, 500)),
        ("configure", "./configure.developer --with-selftest-prefix=./bin/ab --with-system-mitkrb5 --with-experimental-mit-ad-dc" + samba_configure_params),
        ("make", "make -j"),
        ("test", make_test(include_envs=["ad_dc_fips", "ad_member_fips"])),
        ("lcov", LCOV_CMD),
        ("check-clean-tree", "script/clean-source-tree.sh"),
        ],

    # run the backup/restore testenvs separately as they're fairly standalone
    # (and CI seems to max out at ~8 different DCs running at once)
    "samba-ad-dc-backup": [
        ("random-sleep", random_sleep(300, 900)),
        ("configure", "./configure.developer --with-selftest-prefix=./bin/ab" + samba_configure_params),
        ("make", "make -j"),
        ("test", make_test(include_envs=[
            "backupfromdc",
            "restoredc",
            "renamedc",
            "offlinebackupdc",
            "labdc",
            "ad_dc_backup",
            ])),
        ("lcov", LCOV_CMD),
        ("check-clean-tree", "script/clean-source-tree.sh"),
        ],

    "samba-admem-mit": [
        ("random-sleep", random_sleep(1, 1)),
        ("configure", "./configure.developer --with-selftest-prefix=./bin/ab --with-system-mitkrb5 --with-experimental-mit-ad-dc" + samba_configure_params),
        ("make", "make -j"),
        ("test", make_test(include_envs=[
            "ad_member",
            "ad_member_idmap_rid",
            "ad_member_idmap_ad",
            "ad_member_rfc2307",
            ])),
        ("lcov", LCOV_CMD),
        ("check-clean-tree", "script/clean-source-tree.sh"),
        ],

    "samba-ad-dc-1-mitkrb5": [
        ("random-sleep", random_sleep(1, 1)),
        ("configure", "./configure.developer --with-selftest-prefix=./bin/ab --with-system-mitkrb5 --with-experimental-mit-ad-dc" + samba_configure_params),
        ("make", "make -j"),
        ("test", make_test(include_envs=[
            "ad_dc",
            "ad_dc_smb1",
            "ad_dc_smb1_done",
            "ad_dc_no_nss",
            "ad_dc_no_ntlm",
            ])),
        ("lcov", LCOV_CMD),
        ("check-clean-tree", "script/clean-source-tree.sh"),
        ],

    "samba-ad-dc-4-mitkrb5": [
        ("random-sleep", random_sleep(1, 1)),
        ("configure", "./configure.developer --with-selftest-prefix=./bin/ab --with-system-mitkrb5 --with-experimental-mit-ad-dc" + samba_configure_params),
        ("make", "make -j"),
        ("test", make_test(include_envs=[
            "fl2000dc",
            "fl2003dc",
            "fl2008dc",
            "fl2008r2dc",
            ])),
        ("lcov", LCOV_CMD),
        ("check-clean-tree", "script/clean-source-tree.sh"),
        ],

    "samba-test-only": [
        ("configure", "./configure.developer --with-selftest-prefix=./bin/ab  --abi-check-disable" + samba_configure_params),
        ("make", "make -j"),
        ("test", make_test(TESTS="${TESTS}")),
        ("lcov", LCOV_CMD),
        ],

    # Test cross-compile infrastructure
    "samba-xc": [
        ("random-sleep", random_sleep(900, 1500)),
        ("configure-native", "./configure.developer --with-selftest-prefix=./bin/ab" + samba_configure_params),
        ("configure-cross-execute", "./configure.developer --out ./bin-xe --cross-compile --cross-execute=script/identity_cc.sh" \
            " --cross-answers=./bin-xe/cross-answers.txt --with-selftest-prefix=./bin-xe/ab" + samba_configure_params),
        ("verify-cross-execute-output", "grep '^Checking value of NSIG' ./bin-xe/cross-answers.txt"),
        ("configure-cross-answers", "./configure.developer --out ./bin-xa --cross-compile" \
            " --cross-answers=./bin-xe/cross-answers.txt --with-selftest-prefix=./bin-xa/ab" + samba_configure_params),
        ("compare-results", "script/compare_cc_results.py "
            "./bin/c4che/default{} "
            "./bin-xe/c4che/default{} "
            "./bin-xa/c4che/default{}".format(*([CACHE_SUFFIX]*3))),
        ("modify-cross-answers", "sed -i.bak -e 's/^\\(Checking value of NSIG:\\) .*/\\1 \"1234\"/' ./bin-xe/cross-answers.txt"),
        ("configure-cross-answers-modified", "./configure.developer --out ./bin-xa2 --cross-compile" \
            " --cross-answers=./bin-xe/cross-answers.txt --with-selftest-prefix=./bin-xa2/ab" + samba_configure_params),
        ("verify-cross-answers", "test $(sed -n -e 's/VALUEOF_NSIG = \\(.*\\)/\\1/p' ./bin-xa2/c4che/default{})" \
            " = \"'1234'\"".format(CACHE_SUFFIX)),
        ("invalidate-cross-answers", "sed -i.bak -e '/^Checking value of NSIG/d' ./bin-xe/cross-answers.txt"),
        ("configure-cross-answers-fail", "./configure.developer --out ./bin-xa3 --cross-compile" \
            " --cross-answers=./bin-xe/cross-answers.txt --with-selftest-prefix=./bin-xa3/ab" + samba_configure_params + \
            " ; test $? -ne 0"),
        ],

    # test build with -O3 -- catches extra warnings and bugs, tests the ad_dc environments
    "samba-o3": [
        ("random-sleep", random_sleep(300, 900)),
        ("configure", "ADDITIONAL_CFLAGS='-O3 -Wp,-D_FORTIFY_SOURCE=2' ./configure.developer --with-selftest-prefix=./bin/ab --abi-check-disable" + samba_configure_params),
        ("make", "make -j"),
        ("test", make_test(cmd='make test', TESTS="--exclude=selftest/slow-none", include_envs=["none"])),
        ("quicktest", make_test(cmd='make quicktest', include_envs=["ad_dc", "ad_dc_smb1", "ad_dc_smb1_done"])),
        ("lcov", LCOV_CMD),
        ("install", "make install"),
        ("check-clean-tree", "script/clean-source-tree.sh"),
        ("clean", "make clean"),
        ],

    "samba-ctdb": [
        ("random-sleep", random_sleep(900, 1500)),

        # make sure we have tdb around:
        ("tdb-configure", "cd lib/tdb && PYTHONPATH=${PYTHON_PREFIX}:$PYTHONPATH PKG_CONFIG_PATH=$PKG_CONFIG_PATH:${PREFIX_DIR}/lib/pkgconfig ./configure --bundled-libraries=NONE --abi-check --enable-debug -C ${PREFIX}"),
        ("tdb-make", "cd lib/tdb && make"),
        ("tdb-install", "cd lib/tdb && make install"),

        # build samba with cluster support (also building ctdb):
        ("samba-configure",
         "PYTHONPATH=${PYTHON_PREFIX}:$PYTHONPATH "
         "PKG_CONFIG_PATH=${PREFIX_DIR}/lib/pkgconfig:${PKG_CONFIG_PATH} "
         "./configure.developer ${PREFIX} "
         "--with-selftest-prefix=./bin/ab "
         "--with-cluster-support "
         "--without-ad-dc "
         "--bundled-libraries=!tdb"),
        ("samba-make", "make"),
        ("samba-check", "./bin/smbd -b | grep CLUSTER_SUPPORT"),
        ("samba-install", "make install"),
        ("ctdb-check", "test -e ${PREFIX_DIR}/sbin/ctdbd"),

        ("test",
         make_test(cmd='make test',
                   include_envs=["clusteredmember_smb1"])
        ),

        # clean up:
        ("check-clean-tree", "script/clean-source-tree.sh"),
        ("clean", "make clean"),
        ("ctdb-clean", "cd ./ctdb && make clean"),
        ],

    "samba-libs": [
        ("random-sleep", random_sleep(300, 900)),
        ("talloc-configure", "cd lib/talloc && " + samba_libs_configure_libs),
        ("talloc-make", "cd lib/talloc && make"),
        ("talloc-install", "cd lib/talloc && make install"),

        ("tdb-configure", "cd lib/tdb && " + samba_libs_configure_libs),
        ("tdb-make", "cd lib/tdb && make"),
        ("tdb-install", "cd lib/tdb && make install"),

        ("tevent-configure", "cd lib/tevent && " + samba_libs_configure_libs),
        ("tevent-make", "cd lib/tevent && make"),
        ("tevent-install", "cd lib/tevent && make install"),

        ("ldb-configure", "cd lib/ldb && " + samba_libs_configure_libs),
        ("ldb-make", "cd lib/ldb && make"),
        ("ldb-install", "cd lib/ldb && make install"),

        ("nondevel-configure", "./configure ${PREFIX}"),
        ("nondevel-make", "make -j"),
        ("nondevel-check", "./bin/smbd -b | grep WITH_NTVFS_FILESERVER && exit 1; exit 0"),
        ("nondevel-install", "make install"),
        ("nondevel-dist", "make dist"),

        # retry with all modules shared
        ("allshared-distclean", "make distclean"),
        ("allshared-configure", samba_libs_configure_samba + " --with-shared-modules=ALL"),
        ("allshared-make", "make -j"),
        ],

    "samba-static": [
        ("random-sleep", random_sleep(1, 1)),
        # build with all modules static
        ("allstatic-configure", "./configure.developer " + samba_configure_params + " --with-static-modules=ALL"),
        ("allstatic-make", "make -j"),
        ("allstatic-test", make_test(TESTS="samba3.smb2.create.*nt4_dc")),
        ("lcov", LCOV_CMD),

        # retry without any required modules
        ("none-distclean", "make distclean"),
        ("none-configure", "./configure.developer " + samba_configure_params + " --with-static-modules=!FORCED,!DEFAULT --with-shared-modules=!FORCED,!DEFAULT"),
        ("none-make", "make -j"),

        # retry with nonshared smbd and smbtorture
        ("nonshared-distclean", "make distclean"),
        ("nonshared-configure", "./configure.developer " + samba_configure_params + " --bundled-libraries=ALL --with-static-modules=ALL --nonshared-binary=smbtorture,smbd/smbd"),
        ("nonshared-make", "make -j")
        ],

    "samba-fuzz": [
        # build the fuzzers (static) via the oss-fuzz script
        ("fuzzers-mkdir-prefix", "mkdir -p ${PREFIX_DIR}"),
        ("fuzzers-build", "OUT=${PREFIX_DIR} LIB_FUZZING_ENGINE= SANITIZER=address CXX= CFLAGS= ./lib/fuzzing/oss-fuzz/build_samba.sh --enable-afl"),
        ("fuzzers-check", "./lib/fuzzing/oss-fuzz/check_build.sh ${PREFIX_DIR}")
        ],

    # Test Samba without python still builds.  When this test fails
    # due to more use of Python, the expectations is that the newly
    # failing part of the code should be disabled when
    # --disable-python is set (rather than major work being done to
    # support this environment).  The target here is for vendors
    # shipping a minimal smbd.
    "samba-nopython": [
        ("random-sleep", random_sleep(300, 900)),
        ("configure", "./configure.developer ${ENABLE_COVERAGE} ${PREFIX} --with-profiling-data --disable-python --without-ad-dc"),
        ("make", "make -j"),
        ("install", "make install"),
        ("find-python", "script/find_python.sh ${PREFIX}"),
        ("test", "make test-nopython"),
        ("lcov", LCOV_CMD),
        ("check-clean-tree", "script/clean-source-tree.sh"),
        ("clean", "make clean"),

        ("talloc-configure", "cd lib/talloc && " + samba_libs_configure_base + " --bundled-libraries=cmocka,NONE --disable-python"),
        ("talloc-make", "cd lib/talloc && make"),
        ("talloc-install", "cd lib/talloc && make install"),

        ("tdb-configure", "cd lib/tdb && " + samba_libs_configure_base + " --bundled-libraries=cmocka,NONE --disable-python"),
        ("tdb-make", "cd lib/tdb && make"),
        ("tdb-install", "cd lib/tdb && make install"),

        ("tevent-configure", "cd lib/tevent && " + samba_libs_configure_base + " --bundled-libraries=cmocka,NONE --disable-python"),
        ("tevent-make", "cd lib/tevent && make"),
        ("tevent-install", "cd lib/tevent && make install"),

        ("ldb-configure", "cd lib/ldb && " + samba_libs_configure_base + " --bundled-libraries=cmocka,NONE --disable-python"),
        ("ldb-make", "cd lib/ldb && make"),
        ("ldb-install", "cd lib/ldb && make install"),

        # retry against installed library packages
        ("libs-configure", samba_libs_configure_base + samba_libs_configure_bundled_libs + " --disable-python --without-ad-dc"),
        ("libs-make", "make -j"),
        ("libs-install", "make install"),
        ("libs-check-clean-tree", "script/clean-source-tree.sh"),
        ("libs-clean", "make clean"),
        ],

    # check we can do the same thing using python2
    "samba-nopython-py2": [
        ("random-sleep", random_sleep(300, 900)),
        ("configure", "PYTHON=python2 ./configure.developer ${ENABLE_COVERAGE} ${PREFIX} --with-profiling-data --disable-python --without-ad-dc"),
        ("make", "PYTHON=python2 make -j"),
        ("install", "PYTHON=python2 make install"),
        ("find-python", "script/find_python.sh ${PREFIX}"),
        ("test", "make test-nopython"),
        ("lcov", LCOV_CMD),
        ("check-clean-tree", "script/clean-source-tree.sh"),
        ("clean", "PYTHON=python2 make clean"),

        ("talloc-configure", "cd lib/talloc && PYTHON=python2 " + samba_libs_configure_base + " --bundled-libraries=cmocka,NONE --disable-python"),
        ("talloc-make", "cd lib/talloc && PYTHON=python2 make"),
        ("talloc-install", "cd lib/talloc && PYTHON=python2 make install"),

        ("tdb-configure", "cd lib/tdb && PYTHON=python2 " + samba_libs_configure_base + " --bundled-libraries=cmocka,NONE --disable-python"),
        ("tdb-make", "cd lib/tdb && PYTHON=python2 make"),
        ("tdb-install", "cd lib/tdb && PYTHON=python2 make install"),

        ("tevent-configure", "cd lib/tevent && PYTHON=python2 " + samba_libs_configure_base + " --bundled-libraries=cmocka,NONE --disable-python"),
        ("tevent-make", "cd lib/tevent && PYTHON=python2 make"),
        ("tevent-install", "cd lib/tevent && PYTHON=python2 make install"),

        ("ldb-configure", "cd lib/ldb && PYTHON=python2 " + samba_libs_configure_base + " --bundled-libraries=cmocka,NONE --disable-python"),
        ("ldb-make", "cd lib/ldb && PYTHON=python2 make"),
        ("ldb-install", "cd lib/ldb && PYTHON=python2 make install"),

        # retry against installed library packages
        ("libs-configure", "PYTHON=python2 " + samba_libs_configure_base + samba_libs_configure_bundled_libs + " --disable-python --without-ad-dc"),
        ("libs-make", "PYTHON=python2 make -j"),
        ("libs-install", "PYTHON=python2 make install"),
        ("libs-check-clean-tree", "script/clean-source-tree.sh"),
        ("libs-clean", "PYTHON=python2 make clean"),
        ],

    "ldb": [
        ("random-sleep", random_sleep(60, 600)),
        ("configure", "./configure ${ENABLE_COVERAGE} --enable-developer -C ${PREFIX}"),
        ("make", "make"),
        ("install", "make install"),
        ("test", "make test"),
        ("lcov", LCOV_CMD),
        ("clean", "make clean"),
        ("configure-no-lmdb", "./configure ${ENABLE_COVERAGE} --enable-developer --without-ldb-lmdb -C ${PREFIX}"),
        ("make-no-lmdb", "make"),
        ("test-no-lmdb", "make test"),
        ("lcov-no-lmdb", LCOV_CMD),
        ("install-no-lmdb", "make install"),
        ("check-clean-tree", "../../script/clean-source-tree.sh"),
        ("distcheck", "make distcheck"),
        ("clean", "make clean"),
        ],

    "tdb": [
        ("random-sleep", random_sleep(60, 600)),
        ("configure", "./configure ${ENABLE_COVERAGE} --enable-developer -C ${PREFIX}"),
        ("make", "make"),
        ("install", "make install"),
        ("test", "make test"),
        ("lcov", LCOV_CMD),
        ("check-clean-tree", "../../script/clean-source-tree.sh"),
        ("distcheck", "make distcheck"),
        ("clean", "make clean"),
        ],

    "talloc": [
        ("random-sleep", random_sleep(60, 600)),
        ("configure", "./configure ${ENABLE_COVERAGE} --enable-developer -C ${PREFIX}"),
        ("make", "make"),
        ("install", "make install"),
        ("test", "make test"),
        ("lcov", LCOV_CMD),
        ("check-clean-tree", "../../script/clean-source-tree.sh"),
        ("distcheck", "make distcheck"),
        ("clean", "make clean"),
        ],

    "replace": [
        ("random-sleep", random_sleep(60, 600)),
        ("configure", "./configure ${ENABLE_COVERAGE} --enable-developer -C ${PREFIX}"),
        ("make", "make"),
        ("install", "make install"),
        ("test", "make test"),
        ("lcov", LCOV_CMD),
        ("check-clean-tree", "../../script/clean-source-tree.sh"),
        ("distcheck", "make distcheck"),
        ("clean", "make clean"),
        ],

    "tevent": [
        ("random-sleep", random_sleep(60, 600)),
        ("configure", "./configure ${ENABLE_COVERAGE} --enable-developer -C ${PREFIX}"),
        ("make", "make"),
        ("install", "make install"),
        ("test", "make test"),
        ("lcov", LCOV_CMD),
        ("check-clean-tree", "../../script/clean-source-tree.sh"),
        ("distcheck", "make distcheck"),
        ("clean", "make clean"),
        ],

    "pidl": [
        ("random-sleep", random_sleep(60, 600)),
        ("configure", "perl Makefile.PL PREFIX=${PREFIX_DIR}"),
        ("touch", "touch *.yp"),
        ("make", "make"),
        ("test", "make test"),
        ("install", "make install"),
        ("checkout-yapp-generated", "git checkout lib/Parse/Pidl/IDL.pm lib/Parse/Pidl/Expr.pm"),
        ("check-clean-tree", "../script/clean-source-tree.sh"),
        ("clean", "make clean"),
        ],

    # these are useful for debugging autobuild
    'pass': [("pass", 'echo passing && /bin/true')],
    'fail': [("fail", 'echo failing && /bin/false')],
}

defaulttasks = list(tasks.keys())

defaulttasks.remove("pass")
defaulttasks.remove("fail")
defaulttasks.remove("samba-test-only")
defaulttasks.remove("samba-fuzz")
defaulttasks.remove("samba-fips")
if os.environ.get("AUTOBUILD_SKIP_SAMBA_O3", "0") == "1":
    defaulttasks.remove("samba-o3")


def do_print(msg):
    print("%s" % msg)
    sys.stdout.flush()
    sys.stderr.flush()


def run_cmd(cmd, dir=".", show=None, output=False, checkfail=True):
    if show is None:
        show = options.verbose
    if show:
        do_print("Running: '%s' in '%s'" % (cmd, dir))
    if output:
        out = check_output([cmd], shell=True, cwd=dir)
        return out.decode(encoding='utf-8', errors='backslashreplace')
    elif checkfail:
        return check_call(cmd, shell=True, cwd=dir)
    else:
        return call(cmd, shell=True, cwd=dir)

def rmdir_force(dirname, re_raise=True):
    try:
        run_cmd("test -d %s && chmod -R +w %s; rm -rf %s" % (
                dirname, dirname, dirname), output=True, show=True)
    except CalledProcessError as e:
        do_print("Failed: '%s'" % (str(e)))
        run_cmd("tree %s" % dirname, output=True, show=True)
        if re_raise:
            raise
        return False
    return True

class builder(object):
    '''handle build of one directory'''

    def __init__(self, name, sequence, cp=True):
        self.name = name
        self.dir = builddirs.get(name, '.')
        self.tag = self.name.replace('/', '_')
        self.sequence = sequence
        self.next = 0
        self.stdout_path = "%s/%s.stdout" % (gitroot, self.tag)
        self.stderr_path = "%s/%s.stderr" % (gitroot, self.tag)
        if options.verbose:
            do_print("stdout for %s in %s" % (self.name, self.stdout_path))
            do_print("stderr for %s in %s" % (self.name, self.stderr_path))
        run_cmd("rm -f %s %s" % (self.stdout_path, self.stderr_path))
        self.stdout = open(self.stdout_path, 'w')
        self.stderr = open(self.stderr_path, 'w')
        self.stdin  = open("/dev/null", 'r')
        self.test_source_dir = "%s/%s" % (testbase, self.tag)
        self.cwd = "%s/%s" % (self.test_source_dir, self.dir)
        self.prefix = "%s/%s" % (test_prefix, self.tag)
        rmdir_force(self.test_source_dir)
        rmdir_force(self.prefix)
        if cp:
            run_cmd("cp -R -a -l %s %s" % (test_master, self.test_source_dir), dir=test_master, show=True)
        else:
            run_cmd("git clone --recursive --shared %s %s" % (test_master, self.test_source_dir), dir=test_master, show=True)
        self.start_next()

    def start_next(self):
        if self.next == len(self.sequence):
            if not options.nocleanup:
                rmdir_force(self.test_source_dir)
                rmdir_force(self.prefix)
            do_print('%s: Completed OK' % self.name)
            self.done = True
            return
        (self.stage, self.cmd) = self.sequence[self.next]
        self.cmd = self.cmd.replace("${PYTHON_PREFIX}", get_python_lib(plat_specific=1, standard_lib=0, prefix=self.prefix))
        self.cmd = self.cmd.replace("${PREFIX}", "--prefix=%s" % self.prefix)
        self.cmd = self.cmd.replace("${PREFIX_DIR}", "%s" % self.prefix)
        self.cmd = self.cmd.replace("${TESTS}", options.restrict_tests)
        self.cmd = self.cmd.replace("${TEST_SOURCE_DIR}", self.test_source_dir)
        self.cmd = self.cmd.replace("${LOG_BASE}", options.log_base)
        self.cmd = self.cmd.replace("${NAME}", self.name)
        self.cmd = self.cmd.replace("${ENABLE_COVERAGE}", options.enable_coverage)
        do_print('%s: [%s] Running %s in %r' % (self.name, self.stage, self.cmd, self.cwd))
        self.proc = Popen(self.cmd, shell=True,
                          close_fds=True, cwd=self.cwd,
                          stdout=self.stdout, stderr=self.stderr, stdin=self.stdin)
        self.next += 1


class buildlist(object):
    '''handle build of multiple directories'''

    def __init__(self, tasknames, rebase_url, rebase_branch="master"):
        self.tail_proc = None
        self.retry = None
        if not tasknames:
            if options.restrict_tests:
                tasknames = ["samba-test-only"]
            else:
                tasknames = defaulttasks

        self.tlist = [builder(n, tasks[n], cp=(n != "pidl")) for n in tasknames]

        if options.retry:
            rebase_remote = "rebaseon"
            retry_task = [("retry",
                            '''set -e
                            git remote add -t %s %s %s
                            git fetch %s
                            while :; do
                              sleep 60
                              git describe %s/%s > old_remote_branch.desc
                              git fetch %s
                              git describe %s/%s > remote_branch.desc
                              diff old_remote_branch.desc remote_branch.desc
                            done
                           ''' % (
                               rebase_branch, rebase_remote, rebase_url,
                               rebase_remote,
                               rebase_remote, rebase_branch,
                               rebase_remote,
                               rebase_remote, rebase_branch
                            ))]

            self.retry = builder('retry', retry_task, cp=False)
            self.need_retry = False

    def kill_kids(self):
        if self.tail_proc is not None:
            self.tail_proc.terminate()
            self.tail_proc.wait()
            self.tail_proc = None
        if self.retry is not None:
            self.retry.proc.terminate()
            self.retry.proc.wait()
            self.retry = None
        for b in self.tlist:
            if b.proc is not None:
                run_cmd("killbysubdir %s > /dev/null 2>&1" % b.test_source_dir, checkfail=False)
                b.proc.terminate()
                b.proc.wait()
                b.proc = None

    def wait_one(self):
        while True:
            none_running = True
            for b in self.tlist:
                if b.proc is None:
                    continue
                none_running = False
                b.status = b.proc.poll()
                if b.status is None:
                    continue
                b.proc = None
                return b
            if options.retry:
                ret = self.retry.proc.poll()
                if ret is not None:
                    self.need_retry = True
                    self.retry = None
                    return None
            if none_running:
                return None
            time.sleep(0.1)

    def run(self):
        while True:
            b = self.wait_one()
            if options.retry and self.need_retry:
                self.kill_kids()
                do_print("retry needed")
                return (0, None, None, None, "retry")
            if b is None:
                break
            if os.WIFSIGNALED(b.status) or os.WEXITSTATUS(b.status) != 0:
                self.kill_kids()
                return (b.status, b.name, b.stage, b.tag, "%s: [%s] failed '%s' with status %d" % (b.name, b.stage, b.cmd, b.status))
            b.start_next()
        self.kill_kids()
        return (0, None, None, None, "All OK")

    def write_system_info(self, filename):
        with open(filename, 'w') as f:
            for cmd in ['uname -a',
                        'lsb_release -a',
                        'free',
                        'mount',
                        'cat /proc/cpuinfo',
                        'cc --version',
                        'df -m .',
                        'df -m %s' % testbase]:
                try:
                    out = run_cmd(cmd, output=True, checkfail=False)
                except CalledProcessError as e:
                    out = "<failed: %s>" % str(e)
                print('### %s' % cmd, file=f)
                print(out, file=f)
                print(file=f)

    def tarlogs(self, fname):
        with tarfile.open(fname, "w:gz") as tar:
            for b in self.tlist:
                tar.add(b.stdout_path, arcname="%s.stdout" % b.tag)
                tar.add(b.stderr_path, arcname="%s.stderr" % b.tag)
            if os.path.exists("autobuild.log"):
                tar.add("autobuild.log")
            filename = 'system-info.txt'
            self.write_system_info(filename)
            tar.add(filename)

    def remove_logs(self):
        for b in self.tlist:
            os.unlink(b.stdout_path)
            os.unlink(b.stderr_path)

    def start_tail(self):
        cmd = ["tail", "-f"]
        for b in self.tlist:
            cmd.append(b.stdout_path)
            cmd.append(b.stderr_path)
        self.tail_proc = Popen(cmd, close_fds=True)


def cleanup(do_raise=False):
    if options.nocleanup:
        return
    run_cmd("stat %s || true" % test_tmpdir, show=True)
    run_cmd("stat %s" % testbase, show=True)
    do_print("Cleaning up %r" % cleanup_list)
    for d in cleanup_list:
        ok = rmdir_force(d, re_raise=False)
        if ok:
            continue
        if os.path.isdir(d):
            do_print("Killing, waiting and retry")
            run_cmd("killbysubdir %s > /dev/null 2>&1" % d, checkfail=False)
        else:
            do_print("Waiting and retry")
        time.sleep(1)
        rmdir_force(d, re_raise=do_raise)


def daemonize(logfile):
    pid = os.fork()
    if pid == 0:  # Parent
        os.setsid()
        pid = os.fork()
        if pid != 0:  # Actual daemon
            os._exit(0)
    else:  # Grandparent
        os._exit(0)

    import resource      # Resource usage information.
    maxfd = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
    if maxfd == resource.RLIM_INFINITY:
        maxfd = 1024  # Rough guess at maximum number of open file descriptors.
    for fd in range(0, maxfd):
        try:
            os.close(fd)
        except OSError:
            pass
    os.open(logfile, os.O_RDWR | os.O_CREAT)
    os.dup2(0, 1)
    os.dup2(0, 2)


def write_pidfile(fname):
    '''write a pid file, cleanup on exit'''
    with open(fname, mode='w') as f:
        f.write("%u\n" % os.getpid())


def rebase_tree(rebase_url, rebase_branch="master"):
    rebase_remote = "rebaseon"
    do_print("Rebasing on %s" % rebase_url)
    run_cmd("git describe HEAD", show=True, dir=test_master)
    run_cmd("git remote add -t %s %s %s" %
            (rebase_branch, rebase_remote, rebase_url),
            show=True, dir=test_master)
    run_cmd("git fetch %s" % rebase_remote, show=True, dir=test_master)
    if options.fix_whitespace:
        run_cmd("git rebase --force-rebase --whitespace=fix %s/%s" %
                (rebase_remote, rebase_branch),
                show=True, dir=test_master)
    else:
        run_cmd("git rebase --force-rebase %s/%s" %
                (rebase_remote, rebase_branch),
                show=True, dir=test_master)
    diff = run_cmd("git --no-pager diff HEAD %s/%s" %
                   (rebase_remote, rebase_branch),
                   dir=test_master, output=True)
    if diff == '':
        do_print("No differences between HEAD and %s/%s - exiting" %
                 (rebase_remote, rebase_branch))
        sys.exit(0)
    run_cmd("git describe %s/%s" %
            (rebase_remote, rebase_branch),
            show=True, dir=test_master)
    run_cmd("git describe HEAD", show=True, dir=test_master)
    run_cmd("git --no-pager diff --stat HEAD %s/%s" %
            (rebase_remote, rebase_branch),
            show=True, dir=test_master)


def push_to(push_url, push_branch="master"):
    push_remote = "pushto"
    do_print("Pushing to %s" % push_url)
    if options.mark:
        run_cmd("git config --replace-all core.editor script/commit_mark.sh", dir=test_master)
        run_cmd("git commit --amend -c HEAD", dir=test_master)
        # the notes method doesn't work yet, as metze hasn't allowed refs/notes/* in master
        # run_cmd("EDITOR=script/commit_mark.sh git notes edit HEAD", dir=test_master)
    run_cmd("git remote add -t %s %s %s" %
            (push_branch, push_remote, push_url),
            show=True, dir=test_master)
    run_cmd("git push %s +HEAD:%s" %
            (push_remote, push_branch),
            show=True, dir=test_master)


def send_email(subject, text, log_tar):
    if options.email is None:
        do_print("not sending email because the recipient is not set")
        do_print("the text content would have been:\n\nSubject: %s\n\n%s" %
                 (subject, text))
        return
    outer = MIMEMultipart()
    outer['Subject'] = subject
    outer['To'] = options.email
    outer['From'] = options.email_from
    outer['Date'] = email.utils.formatdate(localtime=True)
    outer.preamble = 'Autobuild mails are now in MIME because we optionally attach the logs.\n'
    outer.attach(MIMEText(text, 'plain'))
    if options.attach_logs:
        with open(log_tar, 'rb') as fp:
            msg = MIMEApplication(fp.read(), 'gzip', email.encoders.encode_base64)
        # Set the filename parameter
        msg.add_header('Content-Disposition', 'attachment', filename=os.path.basename(log_tar))
        outer.attach(msg)
    content = outer.as_string()
    s = smtplib.SMTP(options.email_server)
    email_user = os.getenv('SMTP_USERNAME')
    email_password = os.getenv('SMTP_PASSWORD')
    if email_user is not None:
        s.starttls()
        s.login(email_user, email_password)

    s.sendmail(options.email_from, [options.email], content)
    s.set_debuglevel(1)
    s.quit()


def email_failure(status, failed_task, failed_stage, failed_tag, errstr,
                  elapsed_time, log_base=None, add_log_tail=True):
    '''send an email to options.email about the failure'''
    elapsed_minutes = elapsed_time / 60.0
    if log_base is None:
        log_base = gitroot
    text = '''
Dear Developer,

Your autobuild on %s failed after %.1f minutes
when trying to test %s with the following error:

   %s

the autobuild has been abandoned. Please fix the error and resubmit.

A summary of the autobuild process is here:

  %s/autobuild.log
''' % (platform.node(), elapsed_minutes, failed_task, errstr, log_base)

    if options.restrict_tests:
        text += """
The build was restricted to tests matching %s\n""" % options.restrict_tests

    if failed_task != 'rebase':
        text += '''
You can see logs of the failed task here:

  %s/%s.stdout
  %s/%s.stderr

or you can get full logs of all tasks in this job here:

  %s/logs.tar.gz

The top commit for the tree that was built was:

%s

''' % (log_base, failed_tag, log_base, failed_tag, log_base, top_commit_msg)

    if add_log_tail:
        f = open("%s/%s.stdout" % (gitroot, failed_tag), 'r')
        lines = f.readlines()
        log_tail = "".join(lines[-50:])
        num_lines = len(lines)
        if num_lines < 50:
            # Also include stderr (compile failures) if < 50 lines of stdout
            f = open("%s/%s.stderr" % (gitroot, failed_tag), 'r')
            log_tail += "".join(f.readlines()[-(50 - num_lines):])

        text += '''
The last 50 lines of log messages:

%s
    ''' % log_tail
        f.close()

    logs = os.path.join(gitroot, 'logs.tar.gz')
    send_email('autobuild[%s] failure on %s for task %s during %s'
               % (options.branch, platform.node(), failed_task, failed_stage),
               text, logs)


def email_success(elapsed_time, log_base=None):
    '''send an email to options.email about a successful build'''
    if log_base is None:
        log_base = gitroot
    text = '''
Dear Developer,

Your autobuild on %s has succeeded after %.1f minutes.

''' % (platform.node(), elapsed_time / 60.)

    if options.restrict_tests:
        text += """
The build was restricted to tests matching %s\n""" % options.restrict_tests

    if options.keeplogs:
        text += '''

you can get full logs of all tasks in this job here:

  %s/logs.tar.gz

''' % log_base

    text += '''
The top commit for the tree that was built was:

%s
''' % top_commit_msg

    logs = os.path.join(gitroot, 'logs.tar.gz')
    send_email('autobuild[%s] success on %s' % (options.branch, platform.node()),
               text, logs)


# get the top commit message, for emails
top_commit_msg = run_cmd("git log -1", dir=gitroot, output=True)

try:
    os.makedirs(testbase)
except Exception as reason:
    raise Exception("Unable to create %s : %s" % (testbase, reason))
cleanup_list.append(testbase)

if options.daemon:
    logfile = os.path.join(testbase, "log")
    do_print("Forking into the background, writing progress to %s" % logfile)
    daemonize(logfile)

write_pidfile(gitroot + "/autobuild.pid")

start_time = time.time()

while True:
    try:
        run_cmd("rm -rf %s" % test_tmpdir, show=True)
        os.makedirs(test_tmpdir)
        # The waf uninstall code removes empty directories all the way
        # up the tree.  Creating a file in test_tmpdir stops it from
        # being removed.
        run_cmd("touch %s" % os.path.join(test_tmpdir,
                                          ".directory-is-not-empty"), show=True)
        run_cmd("stat %s" % test_tmpdir, show=True)
        run_cmd("stat %s" % testbase, show=True)
        run_cmd("git clone --recursive --shared %s %s" % (gitroot, test_master), show=True, dir=gitroot)
    except Exception:
        cleanup()
        raise

    try:
        if options.rebase is not None:
            rebase_tree(options.rebase, rebase_branch=options.branch)
    except Exception:
        cleanup_list.append(gitroot + "/autobuild.pid")
        cleanup()
        elapsed_time = time.time() - start_time
        email_failure(-1, 'rebase', 'rebase', 'rebase',
                      'rebase on %s failed' % options.branch,
                      elapsed_time, log_base=options.log_base)
        sys.exit(1)

    try:
        blist = buildlist(args, options.rebase, rebase_branch=options.branch)
        if options.tail:
            blist.start_tail()
        (status, failed_task, failed_stage, failed_tag, errstr) = blist.run()
        if status != 0 or errstr != "retry":
            break
        cleanup(do_raise=True)
    except Exception:
        cleanup()
        raise

cleanup_list.append(gitroot + "/autobuild.pid")

do_print(errstr)

blist.kill_kids()
if options.tail:
    do_print("waiting for tail to flush")
    time.sleep(1)

elapsed_time = time.time() - start_time
if status == 0:
    if options.passcmd is not None:
        do_print("Running passcmd: %s" % options.passcmd)
        run_cmd(options.passcmd, dir=test_master)
    if options.pushto is not None:
        push_to(options.pushto, push_branch=options.branch)
    if options.keeplogs or options.attach_logs:
        blist.tarlogs("logs.tar.gz")
        do_print("Logs in logs.tar.gz")
    if options.always_email:
        email_success(elapsed_time, log_base=options.log_base)
    blist.remove_logs()
    cleanup()
    do_print(errstr)
    sys.exit(0)

# something failed, gather a tar of the logs
blist.tarlogs("logs.tar.gz")

if options.email is not None:
    email_failure(status, failed_task, failed_stage, failed_tag, errstr,
                  elapsed_time, log_base=options.log_base)
else:
    elapsed_minutes = elapsed_time / 60.0
    print('''

####################################################################

AUTOBUILD FAILURE

Your autobuild[%s] on %s failed after %.1f minutes
when trying to test %s with the following error:

   %s

the autobuild has been abandoned. Please fix the error and resubmit.

####################################################################

''' % (options.branch, platform.node(), elapsed_minutes, failed_task, errstr))

cleanup()
do_print(errstr)
do_print("Logs in logs.tar.gz")
sys.exit(status)
