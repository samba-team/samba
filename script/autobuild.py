#!/usr/bin/env python3
# run tests on all Samba subprojects and push to a git tree on success
# Copyright Andrew Tridgell 2010
# released under GNU GPL v3 or later

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
from sysconfig import get_path
import platform
import ssl
import shutil

def get_libc_version():
    import ctypes
    libc = ctypes.CDLL("libc.so.6")
    gnu_get_libc_version = libc.gnu_get_libc_version
    gnu_get_libc_version.restype = ctypes.c_char_p
    return gnu_get_libc_version().decode()

import logging

try:
    from waflib.Build import CACHE_SUFFIX
except ImportError:
    sys.path.insert(0, "./third_party/waf")
    from waflib.Build import CACHE_SUFFIX

logging.basicConfig(format='%(asctime)s %(message)s')
logger = logging.getLogger('autobuild')
logger.setLevel(logging.INFO)

os.environ["PYTHONUNBUFFERED"] = "1"

# This speeds up testing remarkably.
os.environ['TDB_NO_FSYNC'] = '1'

# allow autobuild to run within git rebase -i
if "GIT_DIR" in os.environ:
    del os.environ["GIT_DIR"]
if "GIT_WORK_TREE" in os.environ:
    del os.environ["GIT_WORK_TREE"]

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
parser.add_option("--skip-dependencies", help="skip to run task dependency tasks", default=False, action="store_true")
parser.add_option("--testbase", help="base directory to run tests in (default %s)" % def_testbase,
                  default=def_testbase)
parser.add_option("--full-testbase", help="full base directory to run tests in (default %s/b$PID)" % def_testbase,
                  default=None)
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

if options.verbose:
    logger.setLevel(logging.DEBUG)

if options.full_testbase is not None:
    testbase = options.full_testbase
else:
    testbase = "%s/b%u" % (options.testbase, os.getpid())
test_master = "%s/master" % testbase
test_prefix = "%s/prefix" % testbase
test_tmpdir = "%s/tmp" % testbase
os.environ['TMPDIR'] = test_tmpdir

if options.enable_coverage:
    LCOV_CMD = "cd ${TEST_SOURCE_DIR} && lcov --capture --directory . --output-file ${LOG_BASE}/${NAME}.info --rc 'geninfo_adjust_src_path=${TEST_SOURCE_DIR}/'"
else:
    LCOV_CMD = 'echo "lcov skipped since no --enable-coverage specified"'

if options.enable_coverage:
    PUBLISH_DOCS = "mkdir -p ${LOG_BASE}/public && mv output/htmldocs ${LOG_BASE}/public/htmldocs"
else:
    PUBLISH_DOCS = 'echo "HTML documentation publishing skipped since no --enable-coverage specified"'

CLEAN_SOURCE_TREE_CMD = "cd ${TEST_SOURCE_DIR} && script/clean-source-tree.sh"


def check_symbols(sofile, expected_symbols=""):
    return "objdump --dynamic-syms " + sofile + " | " + \
           "awk \'$0 !~ /" + expected_symbols + "/ {if ($2 == \"g\" && $3 ~ /D(F|O)/ && $4 ~ /(.bss|.text)/ && $7 !~ /(__gcov_|mangle_path)/) exit 1}\'"

def check_versioned_symbol(sofile, symvol, version):
    return "objdump --dynamic-syms " + sofile + " | " + \
           "awk \'$7 == \"" + symvol + "\" { " + \
                "if ($2 == \"g\" && $3 ~ /D(F|O)/ && $4 ~ /(.bss|.text)/ && " + \
                     "$6 == \"" + version + "\") print $0 }\'" + \
                "| wc -l | grep -q \'^1$\'"

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
    "tdb": "lib/tdb",
    "talloc": "lib/talloc",
    "replace": "lib/replace",
    "tevent": "lib/tevent",
    "pidl": "pidl",
    "docs-xml": "docs-xml"
}

ctdb_configure_params = " --enable-developer ${PREFIX}"
samba_configure_params = " ${ENABLE_COVERAGE} ${PREFIX} --with-profiling-data --with-prometheus-exporter"

# To test that waf copes with unknown arguments that look like
# environment variables, we add a couple of parameters that should be
# treated environment variables that happen to have no effect.
#
# This is for https://bugzilla.samba.org/show_bug.cgi?id=15990: distro
# build systems do this kind of thing, and older versions of waf
# allowed it.
useless_configure_params = " _foobliosity_over_mud=7 GRISHLIHOOD_77=0"

rust_configure_param = ''
glibc_vers = float('.'.join(get_libc_version().split('.')[:2]))
cargo = shutil.which('cargo')
if glibc_vers >= 2.32 and cargo != None:
    rust_configure_param = ' --enable-rust'

samba_libs_envvars = "PYTHONPATH=${PYTHON_PREFIX}:$PYTHONPATH"
samba_libs_envvars += " PKG_CONFIG_PATH=$PKG_CONFIG_PATH:${PREFIX_DIR}/lib/pkgconfig"
samba_libs_envvars += " ADDITIONAL_CFLAGS='-Wmissing-prototypes'"
samba_libs_configure_base = samba_libs_envvars + " ./configure --abi-check ${ENABLE_COVERAGE} --enable-debug -C ${PREFIX}"
samba_libs_configure_libs = samba_libs_configure_base + " --bundled-libraries=cmocka,popt,NONE"
samba_libs_configure_bundled_libs = " --bundled-libraries=!talloc,!pytalloc-util,!tdb,!pytdb,!tevent,!pytevent,!popt"
samba_libs_configure_samba = samba_libs_configure_base + samba_libs_configure_bundled_libs

is_ubuntu = False
try:
    from landscape.lib.os_release import parse_os_release
    v = parse_os_release()
    if v["distributor-id"] == "Ubuntu":
        is_ubuntu = True
except ImportError:
    pass

# on ubuntu gcc implies _FORTIFY_SOURCE
# before 24.04 it was _FORTIFY_SOURCE=2
# and 24.04 has _FORTIFY_SOURCE=3
# so we do not specify it explicitly.
samba_o3_cflags = "-O3"
if not is_ubuntu:
    samba_o3_cflags += " -Wp,-D_FORTIFY_SOURCE=2"

def format_option(name, value=None):
    """Format option as str list."""
    if value is None:  # boolean option
        return [name]
    if not isinstance(value, list):  # single value option
        value = [value]
    # repeatable option
    return ['{}={}'.format(name, item) for item in value]


def make_test(
        cmd='make testonly',
        INJECT_SELFTEST_PREFIX=1,
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

    if INJECT_SELFTEST_PREFIX:
        _options.append("TEST_OPTIONS='--with-selftest-prefix={}'".format("${SELFTEST_PREFIX}"))
        _options.append("--directory='{}'".format("${TEST_SOURCE_DIR}"))

    return ' '.join([cmd] + _options)


# When updating this list, also update .gitlab-ci.yml to add the job
# and to make it a dependency of 'page' for the coverage report.

tasks = {
    "ctdb": {
        "sequence": [
            ("random-sleep", random_sleep(300, 900)),
            ("configure", "./configure " + ctdb_configure_params),
            ("make", "make all"),
            ("install", "make install"),
            ("test", "make autotest"),
            ("check-clean-tree", CLEAN_SOURCE_TREE_CMD),
            ("clean", "make clean"),
        ],
    },
    "docs-xml": {
        "sequence": [
            ("random-sleep", random_sleep(300, 900)),
            ("autoconf", "autoconf"),
            ("configure", "./configure"),
            ("make", "make html htmlman"),
            ("publish-docs", PUBLISH_DOCS),
            ("clean", "make clean"),
        ],
    },

    "samba-def-build": {
        "git-clone-required": True,
        "sequence": [
            ("configure", "./configure.developer" + samba_configure_params + useless_configure_params),
            ("make", "make -j"),
            ("check-clean-tree", CLEAN_SOURCE_TREE_CMD),
            ("chmod-R-a-w", "chmod -R a-w ."),
        ],
    },

    "samba-mit-build": {
        "git-clone-required": True,
        "sequence": [
            ("configure", "./configure.developer --with-system-mitkrb5 --with-experimental-mit-ad-dc --with-systemd-userdb" + samba_configure_params),
            ("make", "make -j"),
            ("check-clean-tree", CLEAN_SOURCE_TREE_CMD),
            ("chmod-R-a-w", "chmod -R a-w ."),
        ],
    },

    "samba-nt4-build": {
        "git-clone-required": True,
        "sequence": [
            ("configure", "./configure.developer --without-ad-dc --without-ldap --without-ads --without-json" + samba_configure_params),
            ("make", "make -j"),
            ("check-clean-tree", CLEAN_SOURCE_TREE_CMD),
            ("chmod-R-a-w", "chmod -R a-w ."),
        ],
    },

    "samba-h5l-build": {
        "git-clone-required": True,
        "sequence": [
            ("configure", "./configure.developer --without-ad-dc --with-system-heimdalkrb5" + samba_configure_params),
            ("make", "make -j"),
            ("check-clean-tree", CLEAN_SOURCE_TREE_CMD),
            ("chmod-R-a-w", "chmod -R a-w ."),
        ],
    },

    "samba-without-smb1-build": {
        "git-clone-required": True,
        "sequence": [
            ("configure", "./configure.developer --without-smb1-server --without-ad-dc" + samba_configure_params),
            ("make", "make -j"),
            ("check-clean-tree", CLEAN_SOURCE_TREE_CMD),
            ("chmod-R-a-w", "chmod -R a-w ."),
        ],
    },

    "samba-no-opath-build": {
        "git-clone-required": True,
        "sequence": [
            ("configure", "ADDITIONAL_CFLAGS='-DDISABLE_OPATH=1 -DDISABLE_VFS_OPEN_HOW_RESOLVE_NO_SYMLINKS=1 -DDISABLE_VFS_OPEN_HOW_RESOLVE_NO_XDEV=1 -DDISABLE_PROC_FDS=1' ./configure.developer --without-ad-dc " + samba_configure_params),
            ("make", "make -j"),
            ("check-clean-tree", CLEAN_SOURCE_TREE_CMD),
            ("chmod-R-a-w", "chmod -R a-w ."),
        ],
    },

    # We have 'test' before 'install' because, 'test' should work without 'install (runs all the other envs)'
    "samba": {
        "sequence": [
            ("random-sleep", random_sleep(300, 900)),
            ("configure", "./configure.developer" + samba_configure_params),
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
            "admem_idmap_autorid",
            "ad_member_idmap_ad",
            "ad_member_rfc2307",
            "ad_member_idmap_nss",
            "ad_member_oneway",
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
            "clusteredmember",
            "ad_dc_fips",
            "ad_member_fips",
            ])),
            ("test-slow-none", make_test(cmd='make test', TESTS="--include=selftest/slow-none", include_envs=["none"])),
            ("lcov", LCOV_CMD),
            ("install", "make install"),
            ("check-clean-tree", CLEAN_SOURCE_TREE_CMD),
            ("clean", "make clean"),
        ],
    },

    # We have 'test' before 'install' because, 'test' should work without 'install (runs all the other envs)'
    "samba-mitkrb5": {
        "sequence": [
            ("random-sleep", random_sleep(300, 900)),
            ("configure", "./configure.developer --with-system-mitkrb5 --with-experimental-mit-ad-dc" + samba_configure_params),
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
            "admem_idmap_autorid",
            "ad_member_idmap_ad",
            "ad_member_rfc2307",
            "ad_member_idmap_nss",
            "ad_member_oneway",
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
            "clusteredmember",
            "ad_dc_fips",
            "ad_member_fips",
            ])),
            ("lcov", LCOV_CMD),
            ("install", "make install"),
            ("check-clean-tree", CLEAN_SOURCE_TREE_CMD),
            ("clean", "make clean"),
        ],
    },

    "samba-nt4": {
        "dependency": "samba-nt4-build",
        "sequence": [
            ("random-sleep", random_sleep(300, 900)),
            ("test", make_test(include_envs=[
            "nt4_dc",
            "nt4_dc_smb1",
            "nt4_dc_smb1_done",
            "nt4_dc_schannel",
            "nt4_member",
            "simpleserver",
            ])),
            ("lcov", LCOV_CMD),
            ("check-clean-tree", CLEAN_SOURCE_TREE_CMD),
        ],
    },

    "samba-fileserver": {
        "dependency": "samba-h5l-build",
        "sequence": [
            ("random-sleep", random_sleep(300, 900)),
            ("test", make_test(include_envs=[
            "fileserver",
            "fileserver_smb1",
            "fileserver_smb1_done",
            "maptoguest",
            "ktest", # ktest is also tested in samba-ktest-mit samba
                     # and samba-mitkrb5 but is tested here against
                     # a system Heimdal
            ])),
            ("lcov", LCOV_CMD),
            ("check-clean-tree", CLEAN_SOURCE_TREE_CMD),
        ],
    },

    "samba-fileserver-without-smb1": {
        "dependency": "samba-without-smb1-build",
        "sequence": [
            ("random-sleep", random_sleep(300, 900)),
            ("test", make_test(include_envs=["fileserver"])),
            ("lcov", LCOV_CMD),
            ("check-clean-tree", CLEAN_SOURCE_TREE_CMD),
        ],
    },

    # This is a full build without the AD DC so we test the build with
    # MIT Kerberos from the current system.  Runtime behaviour is
    # confirmed via the ktest (static ccache and keytab) environment

    # This environment also used to confirm we can still build with --with-libunwind
    "samba-ktest-mit": {
        "sequence": [
            ("random-sleep", random_sleep(300, 900)),
            ("configure", "./configure.developer --without-ad-dc --with-libunwind --with-system-mitkrb5 " + samba_configure_params),
            ("make", "make -j"),
            ("test", make_test(include_envs=[
            "ktest", # ktest is also tested in fileserver, samba and
                     # samba-mitkrb5 but is tested here against a
                     # system MIT krb5
            ])),
            ("lcov", LCOV_CMD),
            ("check-clean-tree", CLEAN_SOURCE_TREE_CMD),
        ],
    },

    "samba-admem": {
        "dependency": "samba-def-build",
        "sequence": [
            ("random-sleep", random_sleep(300, 900)),
            ("test", make_test(include_envs=[
            "ad_member",
            "ad_member_idmap_rid",
            "admem_idmap_autorid",
            "ad_member_idmap_ad",
            "ad_member_rfc2307",
            "ad_member_idmap_nss",
            "ad_member_offlogon",
            ])),
            ("lcov", LCOV_CMD),
            ("check-clean-tree", CLEAN_SOURCE_TREE_CMD),
        ],
    },

    "samba-no-opath1": {
        "dependency": "samba-no-opath-build",
        "sequence": [
            ("random-sleep", random_sleep(300, 900)),
            ("test", make_test(
                cmd="make testonly DISABLE_OPATH=1",
                include_envs=[
                "nt4_dc",
                "nt4_dc_smb1",
                "nt4_dc_smb1_done",
                "nt4_dc_schannel",
                "nt4_member",
                "simpleserver",
                ])),
            ("lcov", LCOV_CMD),
            ("check-clean-tree", "script/clean-source-tree.sh"),
        ],
    },

    "samba-no-opath2": {
        "dependency": "samba-no-opath-build",
        "sequence": [
            ("random-sleep", random_sleep(300, 900)),
            ("test", make_test(
                cmd="make testonly DISABLE_OPATH=1",
                include_envs=[
                "fileserver",
                "fileserver_smb1",
                "fileserver_smb1_done",
                ])),
            ("lcov", LCOV_CMD),
            ("check-clean-tree", "script/clean-source-tree.sh"),
        ],
    },

    "samba-ad-dc-1": {
        "dependency": "samba-def-build",
        "sequence": [
            ("random-sleep", random_sleep(1, 1)),
            ("test", make_test(include_envs=[
            "ad_dc",
            "ad_dc_smb1",
            "ad_dc_smb1_done",
            "ad_dc_no_nss",
            "ad_dc_no_ntlm",
            ])),
            ("lcov", LCOV_CMD),
            ("check-clean-tree", CLEAN_SOURCE_TREE_CMD),
        ],
    },

    "samba-ad-dc-2": {
        "dependency": "samba-def-build",
        "sequence": [
            ("random-sleep", random_sleep(1, 1)),
            ("test", make_test(include_envs=[
            "vampire_dc",
            "vampire_2000_dc",
            "rodc",
            ])),
            ("lcov", LCOV_CMD),
            ("check-clean-tree", CLEAN_SOURCE_TREE_CMD),
        ],
    },

    "samba-ad-dc-3": {
        "dependency": "samba-def-build",
        "sequence": [
            ("random-sleep", random_sleep(1, 1)),
            ("test", make_test(include_envs=[
            "promoted_dc",
            "chgdcpass",
            "preforkrestartdc",
            "proclimitdc",
            ])),
            ("lcov", LCOV_CMD),
            ("check-clean-tree", CLEAN_SOURCE_TREE_CMD),
        ],
    },

    "samba-ad-dc-4a": {
        "dependency": "samba-def-build",
        "sequence": [
            ("random-sleep", random_sleep(1, 1)),
            ("test", make_test(include_envs=[
            "fl2000dc",
            "ad_member_oneway",
            "fl2003dc",
            ])),
            ("lcov", LCOV_CMD),
            ("check-clean-tree", CLEAN_SOURCE_TREE_CMD),
        ],
    },
    "samba-ad-dc-4b": {
        "dependency": "samba-def-build",
        "sequence": [
            ("random-sleep", random_sleep(1, 1)),
            ("test", make_test(include_envs=[
            "fl2008dc",
            "fl2008r2dc",
            ])),
            ("lcov", LCOV_CMD),
            ("check-clean-tree", CLEAN_SOURCE_TREE_CMD),
        ],
    },

    "samba-ad-dc-5": {
        "dependency": "samba-def-build",
        "sequence": [
            ("random-sleep", random_sleep(1, 1)),
            ("test", make_test(include_envs=[
            "ad_dc_default", "ad_dc_default_smb1", "ad_dc_default_smb1_done"])),
            ("lcov", LCOV_CMD),
            ("check-clean-tree", CLEAN_SOURCE_TREE_CMD),
        ],
    },

    "samba-ad-dc-6": {
        "dependency": "samba-def-build",
        "sequence": [
            ("random-sleep", random_sleep(1, 1)),
            ("test", make_test(include_envs=["ad_dc_slowtests", "ad_dc_backup"])),
            ("lcov", LCOV_CMD),
            ("check-clean-tree", CLEAN_SOURCE_TREE_CMD),
        ],
    },

    "samba-schemaupgrade": {
        "dependency": "samba-def-build",
        "sequence": [
            ("random-sleep", random_sleep(1, 1)),
            ("test", make_test(include_envs=["schema_dc", "schema_pair_dc"])),
            ("lcov", LCOV_CMD),
            ("check-clean-tree", CLEAN_SOURCE_TREE_CMD),
        ],
    },

    # We split out the ad_dc_ntvfs tests (which are long) so other test do not wait
    # This is currently the longest task, so we don't randomly delay it.
    "samba-ad-dc-ntvfs": {
        "dependency": "samba-def-build",
        "sequence": [
            ("random-sleep", random_sleep(1, 1)),
            ("test", make_test(include_envs=["ad_dc_ntvfs"])),
            ("lcov", LCOV_CMD),
            ("check-clean-tree", CLEAN_SOURCE_TREE_CMD),
        ],
    },

    # Test fips compliance
    "samba-fips": {
        "dependency": "samba-mit-build",
        "sequence": [
            ("random-sleep", random_sleep(1, 1)),
            ("test", make_test(include_envs=["ad_dc_fips", "ad_member_fips"])),
            # TODO: This seems to generate only an empty samba-fips.info ("lcov", LCOV_CMD),
            ("check-clean-tree", CLEAN_SOURCE_TREE_CMD),
        ],
    },

    # run the backup/restore testenvs separately as they're fairly standalone
    # (and CI seems to max out at ~3 different DCs running at once)
    "samba-ad-back1": {
        "dependency": "samba-def-build",
        "sequence": [
            ("random-sleep", random_sleep(300, 900)),
            ("test", make_test(include_envs=[
            "backupfromdc",
            "restoredc",
            "renamedc",
            ])),
            ("lcov", LCOV_CMD),
            ("check-clean-tree", CLEAN_SOURCE_TREE_CMD),
        ],
    },
    "samba-ad-back2": {
        "dependency": "samba-def-build",
        "sequence": [
            ("random-sleep", random_sleep(300, 900)),
            ("test", make_test(include_envs=[
            "backupfromdc",
            "offlinebackupdc",
            "labdc",
            ])),
            ("lcov", LCOV_CMD),
            ("check-clean-tree", CLEAN_SOURCE_TREE_CMD),
        ],
    },

    "samba-admem-mit": {
        "dependency": "samba-mit-build",
        "sequence": [
            ("random-sleep", random_sleep(1, 1)),
            ("test", make_test(include_envs=[
            "ad_member",
            "ad_member_idmap_rid",
            "admem_idmap_autorid",
            "ad_member_idmap_ad",
            "ad_member_rfc2307",
            "ad_member_idmap_nss",
            "ad_member_offlogon",
            ])),
            ("lcov", LCOV_CMD),
            ("check-clean-tree", CLEAN_SOURCE_TREE_CMD),
        ],
    },

    "samba-addc-mit-1": {
        "dependency": "samba-mit-build",
        "sequence": [
            ("random-sleep", random_sleep(1, 1)),
            ("test", make_test(include_envs=[
            "ad_dc",
            "ad_dc_smb1",
            "ad_dc_smb1_done",
            "ad_dc_no_nss",
            "ad_dc_no_ntlm",
            ])),
            ("lcov", LCOV_CMD),
            ("check-clean-tree", CLEAN_SOURCE_TREE_CMD),
        ],
    },

    "samba-addc-mit-4a": {
        "dependency": "samba-mit-build",
        "sequence": [
            ("random-sleep", random_sleep(1, 1)),
            ("test", make_test(include_envs=[
            "fl2000dc",
            "ad_member_oneway",
            "fl2003dc",
            ])),
            ("quick-test-ntvfs-krb5",
             make_test(include_envs=["ad_dc_ntvfs"],
                       TESTS='krb5')),
            ("lcov", LCOV_CMD),
            ("check-clean-tree", CLEAN_SOURCE_TREE_CMD),
        ],
    },
    "samba-addc-mit-4b": {
        "dependency": "samba-mit-build",
        "sequence": [
            ("random-sleep", random_sleep(1, 1)),
            ("test", make_test(include_envs=[
            "fl2008dc",
            "fl2008r2dc",
            ])),
            ("quick-test-schema-dc-krb5",
             make_test(include_envs=["schema_dc"],
                       TESTS='krb5')),
            ("lcov", LCOV_CMD),
            ("check-clean-tree", CLEAN_SOURCE_TREE_CMD),
        ],
    },

    "samba-test-only": {
        "sequence": [
            ("configure", "./configure.developer  --abi-check-disable" + samba_configure_params),
            ("make", "make -j"),
            ("test", make_test(TESTS="${TESTS}")),
            ("lcov", LCOV_CMD),
        ],
    },

    # Test cross-compile infrastructure
    "samba-xc": {
        "sequence": [
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
    },

    # test build with -O3 -- catches extra warnings and bugs, tests the ad_dc environments
    "samba-o3": {
        "sequence": [
            ("random-sleep", random_sleep(300, 900)),
            ("configure", "ADDITIONAL_CFLAGS='" + samba_o3_cflags + "' ./configure.developer --abi-check-disable" + samba_configure_params),
            ("make", "make -j"),
            ("test", make_test(cmd='make test', TESTS="--exclude=selftest/slow-none", include_envs=["none"])),
            ("quicktest", make_test(cmd='make quicktest', include_envs=["ad_dc", "ad_dc_smb1", "ad_dc_smb1_done"])),
            ("lcov", LCOV_CMD),
            ("install", "make install"),
            ("check-clean-tree", CLEAN_SOURCE_TREE_CMD),
            ("clean", "make clean"),
        ],
    },

    "samba-32bit": {
        "sequence": [
            ("random-sleep", random_sleep(300, 900)),
            ("configure", "./configure.developer --abi-check-disable --disable-warnings-as-errors" + samba_configure_params),
            ("make", "make -j"),
            ("nonetest", make_test(cmd='make test', TESTS="--exclude=selftest/slow-none", include_envs=["none"])),
            ("quicktest", make_test(cmd='make quicktest', include_envs=["ad_dc", "ad_dc_smb1", "ad_dc_smb1_done"])),
            ("ktest", make_test(cmd='make test', include_envs=["ktest"])),
            ("install", "make install"),
            ("check-clean-tree", CLEAN_SOURCE_TREE_CMD),
            ("clean", "make clean"),
        ],
    },

    "samba-ctdb": {
        "sequence": [
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
         "--with-profiling-data "
         "--with-prometheus-exporter "
         "--bundled-libraries=!tdb"),
            ("samba-make", "make"),
            ("samba-check", "./bin/smbd --configfile=/dev/null -b | grep CLUSTER_SUPPORT"),
            ("samba-install", "make install"),
            ("ctdb-check", "test -e ${PREFIX_DIR}/sbin/ctdbd"),

            ("test", make_test(
                cmd='PYTHONPATH=${PYTHON_PREFIX}:$PYTHONPATH make test',
                INJECT_SELFTEST_PREFIX=0,
                include_envs=["clusteredmember"])
            ),

        # clean up:
            ("check-clean-tree", CLEAN_SOURCE_TREE_CMD),
            ("clean", "make clean"),
            ("ctdb-clean", "cd ./ctdb && make clean"),
        ],
    },

    "samba-libs": {
        "sequence": [
            ("random-sleep", random_sleep(300, 900)),
            ("talloc-configure", "cd lib/talloc && " + samba_libs_configure_libs),
            ("talloc-make", "cd lib/talloc && make"),
            ("talloc-install", "cd lib/talloc && make install"),
            ("talloc-abi-check1",
                check_versioned_symbol(
                    "./lib/talloc/bin/shared/libtalloc.so.2",
                    "talloc_named",
                    "TALLOC_2.0.2"
                )
            ),
            ("talloc-abi-check2",
                check_versioned_symbol(
                    "./lib/talloc/bin/shared/libtalloc.so.2",
                    "talloc_asprintf_addbuf",
                    "TALLOC_2.3.5"
                )
            ),

            ("tdb-configure", "cd lib/tdb && " + samba_libs_configure_libs),
            ("tdb-make", "cd lib/tdb && make"),
            ("tdb-install", "cd lib/tdb && make install"),
            ("tdb-abi-check1",
                check_versioned_symbol(
                    "./lib/tdb/bin/shared/libtdb.so.1",
                    "tdb_errorstr",
                    "TDB_1.2.1"
                )
            ),
            ("tdb-abi-check2",
                check_versioned_symbol(
                    "./lib/tdb/bin/shared/libtdb.so.1",
                    "tdb_traverse_chain",
                    "TDB_1.3.17"
                )
            ),

            ("tevent-configure", "cd lib/tevent && " + samba_libs_configure_libs),
            ("tevent-make", "cd lib/tevent && make"),
            ("tevent-install", "cd lib/tevent && make install"),
            ("tevent-abi-check1",
                check_versioned_symbol(
                    "./lib/tevent/bin/shared/libtevent.so.0",
                    "_tevent_loop_once",
                    "TEVENT_0.9.9"
                )
            ),
            ("tevent-abi-check2",
                check_versioned_symbol(
                    "./lib/tevent/bin/shared/libtevent.so.0",
                    "__tevent_req_create",
                    "TEVENT_0.15.0"
                )
            ),

            ("nondevel-configure", samba_libs_envvars + " ./configure --private-libraries='!ldb' --vendor-suffix=TEST-STRING~5.1.2 ${PREFIX}"),
            ("nondevel-make", "make -j"),
            ("nondevel-check", "./bin/smbd -b | grep WITH_NTVFS_FILESERVER && exit 1; exit 0"),
            ("nondevel-check", "./bin/smbd --version | grep -F 'TEST-STRING~5.1.2' && exit 0; exit 1"),
            ("nondevel-no-libtalloc", "find ./bin | grep -v 'libtalloc-report' | grep 'libtalloc' && exit 1; exit 0"),
            ("nondevel-no-libtdb", "find ./bin | grep -v 'libtdb-wrap' | grep 'libtdb' && exit 1; exit 0"),
            ("nondevel-no-libtevent", "find ./bin | grep -v 'libtevent-util' | grep 'libtevent' && exit 1; exit 0"),
            ("nondevel-no-samba-nss_winbind", "ldd ./bin/plugins/libnss_winbind.so.2 | grep 'samba' && exit 1; exit 0"),
            ("nondevel-no-samba-nss_wins", "ldd ./bin/plugins/libnss_wins.so.2 | grep 'samba' && exit 1; exit 0"),
            ("nondevel-no-samba-libwbclient", "ldd ./bin/shared/libwbclient.so.0 | grep 'samba' && exit 1; exit 0"),
            ("nondevel-no-samba-pam_winbind", "ldd ./bin/plugins/pam_winbind.so | grep -v 'libtalloc.so.2' | grep 'samba' && exit 1; exit 0"),
            ("nondevel-no-public-nss_winbind",
                check_symbols("./bin/plugins/libnss_winbind.so.2", "_nss_winbind_")),
            ("nondevel-no-public-nss_wins",
                check_symbols("./bin/plugins/libnss_wins.so.2", "_nss_wins_")),
            ("nondevel-no-public-libwbclient",
                check_symbols("./bin/shared/libwbclient.so.0", "wbc")),
            ("nondevel-libwbclient-wbcCtxPingDc2@WBCLIENT_0.12",
                check_versioned_symbol("./bin/shared/libwbclient.so.0", "wbcCtxPingDc2", "WBCLIENT_0.12")),
            ("nondevel-no-public-pam_winbind",
                check_symbols("./bin/plugins/pam_winbind.so", "pam_sm_")),
            ("nondevel-no-public-winbind_krb5_locator",
                check_symbols("./bin/plugins/winbind_krb5_locator.so", "service_locator")),
            ("nondevel-no-public-async_dns_krb5_locator",
                check_symbols("./bin/plugins/async_dns_krb5_locator.so", "service_locator")),
            ("nondevel-libndr-krb5pac-ndr_pull_PAC_DATA@NDR_KRB5PAC_0.0.1",
                check_versioned_symbol("./bin/shared/libndr-krb5pac.so.0", "ndr_pull_PAC_DATA", "NDR_KRB5PAC_0.0.1")),
            ("nondevel-install", "make -j install"),
            ("nondevel-dist", "make dist"),

            ("prefix-no-private-libtalloc", "find ${PREFIX_DIR} | grep -v 'libtalloc-report' | grep 'private.*libtalloc' && exit 1; exit 0"),
            ("prefix-no-private-libtdb", "find ${PREFIX_DIR} | grep -v 'libtdb-wrap' | grep 'private.*libtdb' && exit 1; exit 0"),
            ("prefix-no-private-libtevent", "find ${PREFIX_DIR} | grep -v 'libtevent-util' | grep 'private.*libtevent' && exit 1; exit 0"),
            ("prefix-no-private-libldb", "find ${PREFIX_DIR} | grep -v 'module' | grep -v 'libldbsamba' | grep 'private.*libldb.so' && exit 1; exit 0"),
            ("prefix-public-libldb", "find ${PREFIX_DIR} | grep 'lib/libldb.so' && exit 0; exit 1"),
            ("prefix-no-samba-nss_winbind", "ldd ${PREFIX_DIR}/lib/libnss_winbind.so.2 | grep 'samba' && exit 1; exit 0"),
            ("prefix-no-samba-nss_wins", "ldd ${PREFIX_DIR}/lib/libnss_wins.so.2 | grep 'samba' && exit 1; exit 0"),
            ("prefix-no-samba-libwbclient", "ldd ${PREFIX_DIR}/lib/libwbclient.so.0 | grep 'samba' && exit 1; exit 0"),
            ("prefix-no-samba-pam_winbind", "ldd ${PREFIX_DIR}/lib/security/pam_winbind.so | grep -v 'libtalloc.so.2' | grep 'samba' && exit 1; exit 0"),
            ("prefix-no-public-nss_winbind",
                check_symbols("${PREFIX_DIR}/lib/libnss_winbind.so.2", "_nss_winbind_")),
            ("prefix-no-public-nss_wins",
                check_symbols("${PREFIX_DIR}/lib/libnss_wins.so.2", "_nss_wins_")),
            ("prefix-no-public-libwbclient",
                check_symbols("${PREFIX_DIR}/lib/libwbclient.so.0", "wbc")),
            ("prefix-no-public-pam_winbind",
                check_symbols("${PREFIX_DIR}/lib/security/pam_winbind.so", "pam_sm_")),
            ("prefix-no-public-winbind_krb5_locator",
                check_symbols("${PREFIX_DIR}/lib/krb5/winbind_krb5_locator.so",
                              "service_locator")),
            ("prefix-no-public-async_dns_krb5_locator",
                check_symbols("${PREFIX_DIR}/lib/krb5/async_dns_krb5_locator.so",
                              "service_locator")),

            # retry with all modules shared
            ("allshared-distclean", "make distclean"),
            ("allshared-configure", samba_libs_configure_samba + " --with-shared-modules=ALL"),
            ("allshared-make", "make -j"),
            ("allshared-no-libtalloc", "find ./bin | grep -v 'libtalloc-report' | grep 'libtalloc' && exit 1; exit 0"),
            ("allshared-no-libtdb", "find ./bin | grep -v 'libtdb-wrap' | grep 'libtdb' && exit 1; exit 0"),
            ("allshared-no-libtevent", "find ./bin | grep -v 'libtevent-util' | grep 'libtevent' && exit 1; exit 0"),
            ("allshared-no-samba-nss_winbind", "ldd ./bin/plugins/libnss_winbind.so.2 | grep 'samba' && exit 1; exit 0"),
            ("allshared-no-samba-nss_wins", "ldd ./bin/plugins/libnss_wins.so.2 | grep 'samba' && exit 1; exit 0"),
            ("allshared-no-samba-libwbclient", "ldd ./bin/shared/libwbclient.so.0 | grep 'samba' && exit 1; exit 0"),
            ("allshared-no-samba-pam_winbind", "ldd ./bin/plugins/pam_winbind.so | grep -v 'libtalloc.so.2' | grep 'samba' && exit 1; exit 0"),
            ("allshared-no-public-nss_winbind",
                check_symbols("./bin/plugins/libnss_winbind.so.2", "_nss_winbind_")),
            ("allshared-no-public-nss_wins",
                check_symbols("./bin/plugins/libnss_wins.so.2", "_nss_wins_")),
            ("allshared-no-public-libwbclient",
                check_symbols("./bin/shared/libwbclient.so.0", "wbc")),
            ("allshared-no-public-pam_winbind",
                check_symbols("./bin/plugins/pam_winbind.so", "pam_sm_")),
            ("allshared-no-public-winbind_krb5_locator",
                check_symbols("./bin/plugins/winbind_krb5_locator.so", "service_locator")),
            ("allshared-no-public-async_dns_krb5_locator",
                check_symbols("./bin/plugins/async_dns_krb5_locator.so", "service_locator")),
        ],
    },

    "samba-fuzz": {
        "sequence": [
        # build the fuzzers (static) via the oss-fuzz script
            ("fuzzers-mkdir-prefix", "mkdir -p ${PREFIX_DIR}"),
            ("fuzzers-build", "OUT=${PREFIX_DIR} LIB_FUZZING_ENGINE= SANITIZER=address CXX= CFLAGS= ADDITIONAL_LDFLAGS='-fuse-ld=bfd' ./lib/fuzzing/oss-fuzz/build_samba.sh --enable-afl-fuzzer --with-profiling-data --with-prometheus-exporter"),
        ],
    },

    # * Test smbd and smbtorture can build semi-static
    #
    # * Test Samba without python still builds.
    #
    # When this test fails due to more use of Python, the expectations
    # is that the newly failing part of the code should be disabled
    # when --disable-python is set (rather than major work being done
    # to support this environment).
    #
    # The target here is for vendors shipping a minimal smbd.
    "samba-minimal-smbd": {
        "sequence": [
            ("random-sleep", random_sleep(300, 900)),

        # build with all modules static
            ("allstatic-configure", "./configure.developer " + samba_configure_params + " --with-static-modules=ALL"),
            ("allstatic-make", "nice -n 19 make -j 2"),
            ("allstatic-test", make_test(TESTS="samba3.smb2.create.*nt4_dc")),
            ("allstatic-lcov", LCOV_CMD),
            ("allstatic-def-check-clean-tree", CLEAN_SOURCE_TREE_CMD),
            ("allstatic-def-clean", "make clean"),

        # force all libraries as private
            ("allprivate-def-distclean", "make distclean"),
            ("allprivate-def-configure", "./configure.developer " + samba_configure_params + " --private-libraries=ALL"),
            ("allprivate-def-make", "nice -n 19 make -j 2"),
            # note wrapper libraries need to be public
            ("allprivate-def-no-public", "ls ./bin/shared | egrep -v '^private$|lib[npqrsu][saueoi][smiscd].*-wrapper.so$|pam_set_items.so|pam_matrix.so' | wc -l | grep -q '^0'"),
            ("allprivate-def-only-private-ext", "ls ./bin/shared/private | egrep 'private-samba' | wc -l | grep -q '^0' && exit 1; exit 0"),
            ("allprivate-def-no-non-private-ext", "ls ./bin/shared/private | egrep -v 'private-samba|^libpypamtest.so$' | wc -l | grep -q '^0'"),
            ("allprivate-def-test", make_test(TESTS="samba3.smb2.create.*nt4_dc")),
            ("allprivate-def-lcov", LCOV_CMD),
            ("allprivate-def-check-clean-tree", CLEAN_SOURCE_TREE_CMD),
            ("allprivate-def-clean", "make clean"),

        # force all libraries as private with a non default
        # extension and 2 exceptions
            ("allprivate-ext-distclean", "make distclean"),
            ("allprivate-ext-configure", "./configure.developer " + samba_configure_params + " --private-libraries=ALL --private-library-extension=private-library --private-extension-exception=pac,ndr"),
            ("allprivate-ext-make", "nice -n 19 make -j 2"),
            # note wrapper libraries need to be public
            ("allprivate-ext-no-public", "ls ./bin/shared | egrep -v '^private$|lib[npqrsu][saueoi][smiscd].*-wrapper.so$|pam_set_items.so|pam_matrix.so' | wc -l | grep -q '^0'"),
            ("allprivate-ext-no-private-default-ext", "ls ./bin/shared/private | grep 'private-samba' | wc -l | grep -q '^0'"),
            ("allprivate-ext-has-private-ext", "ls ./bin/shared/private | grep 'private-library' | wc -l | grep -q '^0' && exit 1; exit 0"),
            ("allprivate-ext-libndr-no-private-ext", "ls ./bin/shared/private | grep -v 'private-library' | grep 'libndr' | wc -l | grep -q '^1'"),
            ("allprivate-ext-libpac-no-private-ext", "ls ./bin/shared/private | grep -v 'private-library' | grep 'libpac' | wc -l | grep -q '^1'"),
            ("allprivate-ext-test", make_test(TESTS="samba3.smb2.create.*nt4_dc")),
            ("allprivate-ext-lcov", LCOV_CMD),
            ("allprivate-ext-check-clean-tree", CLEAN_SOURCE_TREE_CMD),
            ("allprivate-ext-clean", "make clean"),

        # retry with nonshared smbd and smbtorture
            ("nonshared-distclean", "make distclean"),
            ("nonshared-configure", "./configure.developer " + samba_configure_params + " --bundled-libraries=ALL --with-static-modules=ALL --nonshared-binary=smbtorture,smbd/smbd"),
            ("nonshared-make", "nice -n 19 make -j 2"),
            ("nonshared-test", make_test(TESTS="samba3.smb2.create.*nt4_dc")),
            ("nonshared-lcov", LCOV_CMD),
            ("nonshared-check-clean-tree", CLEAN_SOURCE_TREE_CMD),
            ("nonshared-clean", "make clean"),

        # retry without winbindd
            ("nonwinbind-distclean", "make distclean"),
            ("nonwinbind-configure", "./configure.developer " + samba_configure_params + " --bundled-libraries=ALL --with-static-modules=ALL --without-winbind"),
            ("nonwinbind-make", "nice -n 19 make -j 2"),
            ("nonwinbind-test", make_test(TESTS="samba3.smb2.*.simpleserver")),
            ("nonwinbind-lcov", LCOV_CMD),
            ("nonwinbind-check-clean-tree", CLEAN_SOURCE_TREE_CMD),
            ("nonwinbind-clean", "make clean"),
        ],
    },

    "samba-nopython": {
        "sequence": [
            ("random-sleep", random_sleep(300, 900)),

            ("configure", "./configure.developer " + samba_configure_params + " --disable-python --without-ad-dc"),
            ("make", "make -j"),
            ("find-python", "script/find_python.sh ${PREFIX}"),
            ("test", "make test-nopython"),
            ("lcov", LCOV_CMD),
            ("check-clean-tree", CLEAN_SOURCE_TREE_CMD),
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

        # retry against installed library packages, but no required modules
            ("libs-configure", samba_libs_configure_base + samba_libs_configure_bundled_libs + " --disable-python --without-ad-dc  --with-static-modules=!FORCED,!DEFAULT --with-shared-modules=!FORCED,!DEFAULT"),
            ("libs-make", "make -j"),
            ("libs-install", "make install"),
            ("libs-check-clean-tree", CLEAN_SOURCE_TREE_CMD),
            ("libs-clean", "make clean"),

        ],
    },

    "samba-codecheck": {
        "sequence": [
            ("run", "script/check-shell-scripts.sh ."),
            ("run", "script/codespell.sh ."),
        ],
    },

    "tdb": {
        "sequence": [
            ("random-sleep", random_sleep(60, 600)),
            ("configure", "./configure ${ENABLE_COVERAGE} --enable-developer -C ${PREFIX}"),
            ("make", "make"),
            ("install", "make install"),
            ("test", "make test"),
            ("lcov", LCOV_CMD),
            ("check-clean-tree", CLEAN_SOURCE_TREE_CMD),
            ("distcheck", "make distcheck"),
            ("clean", "make clean"),
        ],
    },

    "talloc": {
        "sequence": [
            ("random-sleep", random_sleep(60, 600)),
            ("configure", "./configure ${ENABLE_COVERAGE} --enable-developer -C ${PREFIX}"),
            ("make", "make"),
            ("install", "make install"),
            ("test", "make test"),
            ("lcov", LCOV_CMD),
            ("check-clean-tree", CLEAN_SOURCE_TREE_CMD),
            ("distcheck", "make distcheck"),
            ("clean", "make clean"),
        ],
    },

    "replace": {
        "sequence": [
            ("random-sleep", random_sleep(60, 600)),
            ("configure", "./configure ${ENABLE_COVERAGE} --enable-developer -C ${PREFIX}"),
            ("make", "make"),
            ("install", "make install"),
            ("test", "make test"),
            ("lcov", LCOV_CMD),
            ("check-clean-tree", CLEAN_SOURCE_TREE_CMD),
            ("distcheck", "make distcheck"),
            ("clean", "make clean"),
        ],
    },

    "tevent": {
        "sequence": [
            ("random-sleep", random_sleep(60, 600)),
            ("configure", "./configure ${ENABLE_COVERAGE} --enable-developer -C ${PREFIX}"),
            ("make", "make"),
            ("install", "make install"),
            ("test", "make test"),
            ("lcov", LCOV_CMD),
            ("check-clean-tree", CLEAN_SOURCE_TREE_CMD),
            ("distcheck", "make distcheck"),
            ("clean", "make clean"),
        ],
    },

    "pidl": {
        "git-clone-required": True,
        "sequence": [
            ("random-sleep", random_sleep(60, 600)),
            ("configure", "perl Makefile.PL PREFIX=${PREFIX_DIR}"),
            ("touch", "touch *.yp"),
            ("make", "make"),
            ("test", "make test"),
            ("install", "make install"),
            ("checkout-yapp-generated", "git checkout lib/Parse/Pidl/IDL.pm lib/Parse/Pidl/Expr.pm"),
            ("check-clean-tree", CLEAN_SOURCE_TREE_CMD),
            ("clean", "make clean"),
        ],
    },

    # these are useful for debugging autobuild
    "pass": {
        "sequence": [
            ("pass", 'echo passing && /bin/true'),
        ],
    },
    "fail": {
        "sequence": [
            ("fail", 'echo failing && /bin/false'),
        ],
    },
}

defaulttasks = list(tasks.keys())

defaulttasks.remove("pass")
defaulttasks.remove("fail")

# The build tasks will be brought in by the test tasks as needed
defaulttasks.remove("samba-def-build")
defaulttasks.remove("samba-nt4-build")
defaulttasks.remove("samba-mit-build")
defaulttasks.remove("samba-h5l-build")
defaulttasks.remove("samba-no-opath-build")

# This is not a normal test, but a task to support manually running
# one test under autobuild
defaulttasks.remove("samba-test-only")

# Only built on GitLab CI and not in the default autobuild because it
# uses too much space (4GB of semi-static binaries)
defaulttasks.remove("samba-fuzz")

# The FIPS build runs only in GitLab CI on a current Fedora Docker
# container where a simulated FIPS mode is possible.
defaulttasks.remove("samba-fips")

# The MIT build runs on a current Fedora where an up to date MIT KDC
# is already packaged.  This avoids needing to backport a current MIT
# to the default Ubuntu 18.04, particularly during development, and
# the need to install on the shared sn-devel-184.

defaulttasks.remove("samba-mitkrb5")
defaulttasks.remove("samba-admem-mit")
defaulttasks.remove("samba-addc-mit-1")
defaulttasks.remove("samba-addc-mit-4a")
defaulttasks.remove("samba-addc-mit-4b")

defaulttasks.remove("samba-32bit")

if os.environ.get("AUTOBUILD_SKIP_SAMBA_O3", "0") == "1":
    defaulttasks.remove("samba-o3")


def do_print(msg):
    logger.info(msg)
    sys.stdout.flush()
    sys.stderr.flush()

def do_debug(msg):
    logger.debug(msg)
    sys.stdout.flush()
    sys.stderr.flush()


def run_cmd(cmd, dir=".", show=None, output=False, checkfail=True):
    if show is None:
        do_debug("Running: '%s' in '%s'" % (cmd, dir))
    elif show:
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

    def __init__(self, name, definition):
        self.name = name
        self.dir = builddirs.get(name, '.')
        self.tag = self.name.replace('/', '_')
        self.definition = definition
        self.sequence = definition["sequence"]
        self.git_clone_required = False
        if "git-clone-required" in definition:
            self.git_clone_required = bool(definition["git-clone-required"])
        self.proc = None
        self.done = False
        self.next = 0
        self.stdout_path = "%s/%s.stdout" % (gitroot, self.tag)
        self.stderr_path = "%s/%s.stderr" % (gitroot, self.tag)
        do_debug("stdout for %s in %s" % (self.name, self.stdout_path))
        do_debug("stderr for %s in %s" % (self.name, self.stderr_path))
        run_cmd("rm -f %s %s" % (self.stdout_path, self.stderr_path))
        self.stdout = open(self.stdout_path, 'w')
        self.stderr = open(self.stderr_path, 'w')
        self.stdin  = open("/dev/null", 'r')
        self.builder_dir = "%s/%s" % (testbase, self.tag)
        self.test_source_dir = self.builder_dir
        self.cwd = "%s/%s" % (self.builder_dir, self.dir)
        self.selftest_prefix = "%s/bin/ab" % (self.cwd)
        self.prefix = "%s/%s" % (test_prefix, self.tag)
        self.consumers = []
        self.producer = None

        if self.git_clone_required:
            assert "dependency" not in definition

    def mark_existing(self):
        do_debug('%s: Mark as existing dependency' % self.name)
        self.next = len(self.sequence)
        self.done = True

    def add_consumer(self, consumer):
        do_debug("%s: add consumer: %s" % (self.name, consumer.name))
        consumer.producer = self
        consumer.test_source_dir = self.test_source_dir
        self.consumers.append(consumer)

    def start_next(self):
        if self.producer is not None:
            if not self.producer.done:
                do_debug("%s: Waiting for producer: %s" % (self.name, self.producer.name))
                return

        if self.next == 0:
            rmdir_force(self.builder_dir)
            rmdir_force(self.prefix)
            if self.producer is not None:
                run_cmd("mkdir %s" % (self.builder_dir), dir=test_master, show=True)
            elif not self.git_clone_required:
                run_cmd("cp -R -a -l %s %s" % (test_master, self.builder_dir), dir=test_master, show=True)
            else:
                run_cmd("git clone --recursive --shared %s %s" % (test_master, self.builder_dir), dir=test_master, show=True)

        if self.next == len(self.sequence):
            if not self.done:
                do_print('%s: Completed OK' % self.name)
                self.done = True
            if not options.nocleanup and len(self.consumers) == 0:
                do_print('%s: Cleaning up' % self.name)
                rmdir_force(self.builder_dir)
                rmdir_force(self.prefix)
            for consumer in self.consumers:
                if consumer.next != 0:
                    continue
                do_print('%s: Starting consumer %s' % (self.name, consumer.name))
                consumer.start_next()
            if self.producer is not None:
                self.producer.consumers.remove(self)
                assert self.producer.done
                self.producer.start_next()
            do_print('%s: Remaining consumers %u' % (self.name, len(self.consumers)))
            return
        (self.stage, self.cmd) = self.sequence[self.next]
        self.cmd = self.cmd.replace("${PYTHON_PREFIX}",
                                    get_path(name='platlib',
                                             scheme="posix_prefix",
                                             vars={"base": self.prefix,
                                                   "platbase": self.prefix}))
        self.cmd = self.cmd.replace("${PREFIX}", "--prefix=%s" % self.prefix)
        self.cmd = self.cmd.replace("${PREFIX_DIR}", "%s" % self.prefix)
        self.cmd = self.cmd.replace("${TESTS}", options.restrict_tests)
        self.cmd = self.cmd.replace("${TEST_SOURCE_DIR}", self.test_source_dir)
        self.cmd = self.cmd.replace("${SELFTEST_PREFIX}", self.selftest_prefix)
        self.cmd = self.cmd.replace("${LOG_BASE}", options.log_base)
        self.cmd = self.cmd.replace("${NAME}", self.name)
        self.cmd = self.cmd.replace("${ENABLE_COVERAGE}", options.enable_coverage)
        do_print('%s: [%s] Running %s in %r' % (self.name, self.stage, self.cmd, self.cwd))
        self.proc = Popen(self.cmd, shell=True,
                          close_fds=True, cwd=self.cwd,
                          stdout=self.stdout, stderr=self.stderr, stdin=self.stdin)
        self.next += 1

def expand_dependencies(n):
    deps = list()
    if "dependency" in tasks[n]:
        depname = tasks[n]["dependency"]
        assert depname in tasks
        sdeps = expand_dependencies(depname)
        assert n not in sdeps
        for sdep in sdeps:
            deps.append(sdep)
        deps.append(depname)
    return deps


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

        given_tasknames = tasknames.copy()
        implicit_tasknames = []
        for n in given_tasknames:
            deps = expand_dependencies(n)
            for dep in deps:
                if dep in given_tasknames:
                    continue
                if dep in implicit_tasknames:
                    continue
                implicit_tasknames.append(dep)

        tasknames = implicit_tasknames.copy()
        tasknames.extend(given_tasknames)
        do_debug("given_tasknames: %s" % given_tasknames)
        do_debug("implicit_tasknames: %s" % implicit_tasknames)
        do_debug("tasknames: %s" % tasknames)
        self.tlist = [builder(n, tasks[n]) for n in tasknames]

        if options.retry:
            rebase_remote = "rebaseon"
            retry_task = {
                    "git-clone-required": True,
                    "sequence": [
                            ("retry",
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
                            ))]}

            self.retry = builder('retry', retry_task)
            self.need_retry = False

        if options.skip_dependencies:
            for b in self.tlist:
                if b.name in implicit_tasknames:
                    b.mark_existing()

        for b in self.tlist:
            do_debug("b.name=%s" % b.name)
            if "dependency" not in b.definition:
                continue
            depname = b.definition["dependency"]
            do_debug("b.name=%s: dependency:%s" % (b.name, depname))
            for p in self.tlist:
                if p.name == depname:
                    p.add_consumer(b)

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
        for b in self.tlist:
            b.start_next()
        if options.retry:
            self.retry.start_next()
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
    outer.attach(MIMEText(text, 'plain', 'utf-8'))
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

    log_stdout = "%s/%s.stdout" % (gitroot, failed_tag)
    if add_log_tail and os.access(log_stdout, os.R_OK):
        f = open(log_stdout, 'r')
        lines = f.readlines()
        log_tail = "".join(lines[-50:])
        num_lines = len(lines)
        log_stderr = "%s/%s.stderr" % (gitroot, failed_tag)
        if num_lines < 50 and os.access(log_stderr, os.R_OK):
            # Also include stderr (compile failures) if < 50 lines of stdout
            f = open(log_stderr, 'r')
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
    if options.skip_dependencies:
        run_cmd("stat %s" % testbase, dir=testbase, output=True)
    else:
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
        if options.skip_dependencies:
            run_cmd("stat %s" % test_master, dir=testbase, output=True)
        else:
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
