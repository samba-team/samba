#!/usr/bin/python
# This script generates a list of testsuites that should be run as part of
# the Samba test suite.

# The output of this script is parsed by selftest.pl, which then decides
# which of the tests to actually run. It will, for example, skip all tests
# listed in selftest/skip or only run a subset during "make quicktest".

# The idea is that this script outputs all of the tests of Samba, not
# just those that are known to pass, and list those that should be skipped
# or are known to fail in selftest/skip or selftest/knownfail. This makes it
# very easy to see what functionality is still missing in Samba and makes
# it possible to run the testsuite against other servers, such as
# Windows that have a different set of features.

# The syntax for a testsuite is "-- TEST --" on a single line, followed
# by the name of the test, the environment it needs and the command to run, all
# three separated by newlines. All other lines in the output are considered
# comments.

from selftesthelpers import *

try:
    config_h = os.environ["CONFIG_H"]
except KeyError:
    samba4bindir = bindir()
    config_h = os.path.join(samba4bindir, "default/include/config.h")

# check available features
config_hash = dict()
f = open(config_h, 'r')
try:
    lines = f.readlines()
    config_hash = dict((x[0], ' '.join(x[1:]))
            for x in map(lambda line: line.strip().split(' ')[1:],
                         filter(lambda line: (line[0:7] == '#define') and (len(line.split(' ')) > 2), lines)))
finally:
    f.close()

have_man_pages_support = ("XSLTPROC_MANPAGES" in config_hash)
with_cmocka = ("HAVE_CMOCKA" in config_hash)
with_pam = ("WITH_PAM" in config_hash)
pam_wrapper_so_path=config_hash["LIBPAM_WRAPPER_SO_PATH"]

planpythontestsuite("none", "samba.tests.source")
if have_man_pages_support:
    planpythontestsuite("none", "samba.tests.docs")

try:
    import testscenarios
except ImportError:
    skiptestsuite("subunit", "testscenarios not available")
else:
    planpythontestsuite("none", "subunit.tests.test_suite")
planpythontestsuite("none", "samba.tests.blackbox.ndrdump")
planpythontestsuite("none", "api", name="ldb.python", extra_path=['lib/ldb/tests/python'])
planpythontestsuite("none", "samba.tests.credentials", py3_compatible=True)
planpythontestsuite("none", "samba.tests.registry")
planpythontestsuite("none", "samba.tests.auth", py3_compatible=True)
planpythontestsuite("none", "samba.tests.get_opt", py3_compatible=True)
planpythontestsuite("none", "samba.tests.security")
planpythontestsuite("none", "samba.tests.dcerpc.misc", py3_compatible=True)
planpythontestsuite("none", "samba.tests.dcerpc.integer")
planpythontestsuite("none", "samba.tests.param", py3_compatible=True)
planpythontestsuite("none", "samba.tests.upgrade")
planpythontestsuite("none", "samba.tests.core", py3_compatible=True)
planpythontestsuite("none", "samba.tests.provision")
planpythontestsuite("none", "samba.tests.samba3")
planpythontestsuite("none", "samba.tests.strings")
planpythontestsuite("none", "samba.tests.netcmd")
planpythontestsuite("none", "samba.tests.dcerpc.rpc_talloc")
planpythontestsuite("none", "samba.tests.dcerpc.array")
planpythontestsuite("none", "samba.tests.dcerpc.string")
planpythontestsuite("none", "samba.tests.hostconfig")
planpythontestsuite("ad_dc_ntvfs:local", "samba.tests.messaging")
planpythontestsuite("none", "samba.tests.samba3sam")
planpythontestsuite(
    "none", "wafsamba.tests.test_suite",
    extra_path=[os.path.join(samba4srcdir, "..", "buildtools"),
                os.path.join(samba4srcdir, "..", "third_party", "waf", "wafadmin")])
plantestsuite(
    "samba4.blackbox.demote-saveddb", "none",
    ["PYTHON=%s" % python, os.path.join(bbdir, "demote-saveddb.sh"),
     '$PREFIX_ABS/demote', configuration])
plantestsuite(
    "samba4.blackbox.dbcheck.alpha13", "none",
    ["PYTHON=%s" % python, os.path.join(bbdir, "dbcheck-oldrelease.sh"),
     '$PREFIX_ABS/provision', 'alpha13', configuration])
plantestsuite(
    "samba4.blackbox.dbcheck.release-4-0-0", "none",
    ["PYTHON=%s" % python, os.path.join(bbdir, "dbcheck-oldrelease.sh"),
     '$PREFIX_ABS/provision', 'release-4-0-0', configuration])
plantestsuite(
    "samba4.blackbox.dbcheck.release-4-1-0rc3", "none",
    ["PYTHON=%s" % python, os.path.join(bbdir, "dbcheck-oldrelease.sh"),
     '$PREFIX_ABS/provision', 'release-4-1-0rc3', configuration])
plantestsuite(
    "samba4.blackbox.dbcheck.release-4-1-6-partial-object", "none",
    ["PYTHON=%s" % python, os.path.join(bbdir, "dbcheck-oldrelease.sh"),
     '$PREFIX_ABS/provision', 'release-4-1-6-partial-object', configuration])
plantestsuite(
    "samba4.blackbox.dbcheck.release-4-5-0-pre1", "none",
    ["PYTHON=%s" % python,
     os.path.join(bbdir, "dbcheck-oldrelease.sh"),
     '$PREFIX_ABS/provision', 'release-4-5-0-pre1', configuration])
plantestsuite(
    "samba4.blackbox.upgradeprovision.alpha13", "none",
    ["PYTHON=%s" % python,
     os.path.join(bbdir, "upgradeprovision-oldrelease.sh"),
     '$PREFIX_ABS/provision', 'alpha13', configuration])
plantestsuite(
    "samba4.blackbox.upgradeprovision.release-4-0-0", "none",
    ["PYTHON=%s" % python,
     os.path.join(bbdir, "upgradeprovision-oldrelease.sh"),
     '$PREFIX_ABS/provision', 'release-4-0-0', configuration])
plantestsuite(
    "samba4.blackbox.tombstones-expunge.release-4-5-0-pre1", "none",
    ["PYTHON=%s" % python,
     os.path.join(bbdir, "tombstones-expunge.sh"),
     '$PREFIX_ABS/provision', 'release-4-5-0-pre1', configuration])
plantestsuite(
    "samba4.blackbox.dbcheck-links.release-4-5-0-pre1", "none",
    ["PYTHON=%s" % python,
     os.path.join(bbdir, "dbcheck-links.sh"),
     '$PREFIX_ABS/provision', 'release-4-5-0-pre1', configuration])
plantestsuite(
    "samba4.blackbox.runtime-links.release-4-5-0-pre1", "none",
    ["PYTHON=%s" % python,
     os.path.join(bbdir, "runtime-links.sh"),
     '$PREFIX_ABS/provision', 'release-4-5-0-pre1', configuration])
planpythontestsuite("none", "samba.tests.upgradeprovision")
planpythontestsuite("none", "samba.tests.xattr")
planpythontestsuite("none", "samba.tests.ntacls")
planpythontestsuite("none", "samba.tests.policy")
planpythontestsuite("none", "samba.tests.kcc.graph")
planpythontestsuite("none", "samba.tests.kcc.graph_utils")
planpythontestsuite("none", "samba.tests.kcc.kcc_utils")
planpythontestsuite("none", "samba.tests.kcc.ldif_import_export")
plantestsuite("wafsamba.duplicate_symbols", "none", [os.path.join(srcdir(), "buildtools/wafsamba/test_duplicate_symbol.sh")])
plantestsuite(
    "script.traffic_summary", "none",
    [os.path.join(srcdir(), "script/tests/test_traffic_summary.sh"),
     configuration])
planpythontestsuite("none", "samba.tests.glue", py3_compatible=True)

if with_pam:
    plantestsuite("samba.tests.pam_winbind(local)", "ad_member",
                  [os.path.join(srcdir(), "python/samba/tests/test_pam_winbind.sh"),
                   valgrindify(python), pam_wrapper_so_path,
                   "$SERVER", "$USERNAME", "$PASSWORD"])
    plantestsuite("samba.tests.pam_winbind(domain)", "ad_member",
                  [os.path.join(srcdir(), "python/samba/tests/test_pam_winbind.sh"),
                   valgrindify(python), pam_wrapper_so_path,
                   "$DOMAIN", "$DC_USERNAME", "$DC_PASSWORD"])

if with_cmocka:
    plantestsuite("samba.unittests.krb5samba", "none",
                  [os.path.join(bindir(), "default/testsuite/unittests/test_krb5samba")])
    plantestsuite("samba.unittests.sambafs_srv_pipe", "none",
                  [os.path.join(bindir(), "default/testsuite/unittests/test_sambafs_srv_pipe")])
    plantestsuite("samba.unittests.lib_util_modules", "none",
                  [os.path.join(bindir(), "default/testsuite/unittests/test_lib_util_modules")])

    plantestsuite("samba.unittests.smb1cli_session", "none",
                  [os.path.join(bindir(), "default/libcli/smb/test_smb1cli_session")])
