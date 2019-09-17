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

import os
from selftesthelpers import bindir, srcdir, python
from selftesthelpers import planpythontestsuite, samba4srcdir
from selftesthelpers import plantestsuite, bbdir
from selftesthelpers import configuration, valgrindify
from selftesthelpers import skiptestsuite

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
                                    list(filter(lambda line: (line[0:7] == '#define') and (len(line.split(' ')) > 2), lines))))
finally:
    f.close()

have_man_pages_support = ("XSLTPROC_MANPAGES" in config_hash)
with_pam = ("WITH_PAM" in config_hash)
pam_wrapper_so_path = config_hash["LIBPAM_WRAPPER_SO_PATH"]
pam_set_items_so_path = config_hash["PAM_SET_ITEMS_SO_PATH"]

planpythontestsuite("none", "samba.tests.source", py3_compatible=True)
if have_man_pages_support:
    planpythontestsuite("none", "samba.tests.docs", py3_compatible=True)

try:
    import testscenarios
except ImportError:
    skiptestsuite("subunit", "testscenarios not available")
else:
    planpythontestsuite("none", "subunit.tests.test_suite")
planpythontestsuite("none", "samba.tests.blackbox.ndrdump", py3_compatible=True)
planpythontestsuite("none", "samba.tests.blackbox.check_output", py3_compatible=True)
planpythontestsuite("none", "api", name="ldb.python", extra_path=['lib/ldb/tests/python'], py3_compatible=True)
planpythontestsuite("none", "samba.tests.credentials", py3_compatible=True)
planpythontestsuite("none", "samba.tests.registry", py3_compatible=True)
planpythontestsuite("ad_dc_ntvfs:local", "samba.tests.auth", py3_compatible=True)
planpythontestsuite("none", "samba.tests.get_opt", py3_compatible=True)
planpythontestsuite("none", "samba.tests.security", py3_compatible=True)
planpythontestsuite("none", "samba.tests.dcerpc.misc", py3_compatible=True)
planpythontestsuite("none", "samba.tests.dcerpc.integer")
planpythontestsuite("none", "samba.tests.param", py3_compatible=True)
planpythontestsuite("none", "samba.tests.upgrade", py3_compatible=True)
planpythontestsuite("none", "samba.tests.core", py3_compatible=True)
planpythontestsuite("none", "samba.tests.common", py3_compatible=True)
planpythontestsuite("none", "samba.tests.provision", py3_compatible=True)
planpythontestsuite("none", "samba.tests.password_quality", py3_compatible=True)
planpythontestsuite("none", "samba.tests.strings")
planpythontestsuite("none", "samba.tests.netcmd")
planpythontestsuite("none", "samba.tests.dcerpc.rpc_talloc", py3_compatible=True)
planpythontestsuite("none", "samba.tests.dcerpc.array", py3_compatible=True)
planpythontestsuite("none", "samba.tests.dcerpc.string_tests", py3_compatible=True)
planpythontestsuite("none", "samba.tests.hostconfig", py3_compatible=True)
planpythontestsuite("ad_dc_ntvfs:local", "samba.tests.messaging",
                    py3_compatible=True)
planpythontestsuite("none", "samba.tests.s3param", py3_compatible=True)
planpythontestsuite("none", "samba.tests.s3passdb", py3_compatible=True)
planpythontestsuite("none", "samba.tests.s3registry", py3_compatible=True)
planpythontestsuite("none", "samba.tests.s3windb", py3_compatible=True)
planpythontestsuite("none", "samba.tests.s3idmapdb", py3_compatible=True)
planpythontestsuite("none", "samba.tests.samba3sam")
planpythontestsuite(
    "none", "wafsamba.tests.test_suite",
    extra_path=[os.path.join(samba4srcdir, "..", "buildtools"),
                os.path.join(samba4srcdir, "..", "third_party", "waf")])
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
plantestsuite(
    "samba4.blackbox.schemaupgrade", "none",
    ["PYTHON=%s" % python,
     os.path.join(bbdir, "schemaupgrade.sh"),
     '$PREFIX_ABS/provision', configuration])
plantestsuite(
    "samba4.blackbox.functionalprep", "none",
    ["PYTHON=%s" % python,
     os.path.join(bbdir, "functionalprep.sh"),
     '$PREFIX_ABS/provision', configuration])
planpythontestsuite("none", "samba.tests.upgradeprovision", py3_compatible=True)
planpythontestsuite("none", "samba.tests.xattr", py3_compatible=True)
planpythontestsuite("none", "samba.tests.ntacls", py3_compatible=True)
planpythontestsuite("none", "samba.tests.policy", py3_compatible=True)
planpythontestsuite("none", "samba.tests.kcc.graph", py3_compatible=True)
planpythontestsuite("none", "samba.tests.kcc.graph_utils", py3_compatible=True)
planpythontestsuite("none", "samba.tests.kcc.ldif_import_export")
planpythontestsuite("none", "samba.tests.graph", py3_compatible=True)
plantestsuite("wafsamba.duplicate_symbols", "none", [os.path.join(srcdir(), "buildtools/wafsamba/test_duplicate_symbol.sh")])
planpythontestsuite("none", "samba.tests.glue", py3_compatible=True)
planpythontestsuite("none", "samba.tests.tdb_util", py3_compatible=True)
planpythontestsuite("none", "samba.tests.samdb_api", py3_compatible=True)

if with_pam:
    plantestsuite("samba.tests.pam_winbind(local)", "ad_member",
                  [os.path.join(srcdir(), "python/samba/tests/test_pam_winbind.sh"),
                   valgrindify(python), pam_wrapper_so_path,
                   "$SERVER", "$USERNAME", "$PASSWORD", "''"])
    plantestsuite("samba.tests.pam_winbind(domain)", "ad_member",
                  [os.path.join(srcdir(), "python/samba/tests/test_pam_winbind.sh"),
                   valgrindify(python), pam_wrapper_so_path,
                   "$DOMAIN", "$DC_USERNAME", "$DC_PASSWORD", "''"])

    for pam_options in ["''", "use_authtok", "try_authtok"]:
        plantestsuite("samba.tests.pam_winbind_chauthtok with options %s" % pam_options, "ad_member",
                      [os.path.join(srcdir(), "python/samba/tests/test_pam_winbind_chauthtok.sh"),
                       valgrindify(python), pam_wrapper_so_path, pam_set_items_so_path,
                       "$DOMAIN", "TestPamOptionsUser", "oldp@ssword0", "newp@ssword0",
                       pam_options, 'yes',
                       "$DC_SERVER", "$DC_USERNAME", "$DC_PASSWORD"])

    plantestsuite("samba.tests.pam_winbind_warn_pwd_expire(domain)", "ad_member",
                  [os.path.join(srcdir(), "python/samba/tests/test_pam_winbind_warn_pwd_expire.sh"),
                   valgrindify(python), pam_wrapper_so_path,
                   "$DOMAIN", "alice", "Secret007", "''"])


plantestsuite("samba.unittests.krb5samba", "none",
              [os.path.join(bindir(), "default/testsuite/unittests/test_krb5samba")])
plantestsuite("samba.unittests.sambafs_srv_pipe", "none",
              [os.path.join(bindir(), "default/testsuite/unittests/test_sambafs_srv_pipe")])
plantestsuite("samba.unittests.lib_util_modules", "none",
              [os.path.join(bindir(), "default/testsuite/unittests/test_lib_util_modules")])

plantestsuite("samba.unittests.smb1cli_session", "none",
              [os.path.join(bindir(), "default/libcli/smb/test_smb1cli_session")])

plantestsuite("samba.unittests.tldap", "none",
              [os.path.join(bindir(), "default/source3/test_tldap")])
plantestsuite("samba.unittests.rfc1738", "none",
              [os.path.join(bindir(), "default/lib/util/test_rfc1738")])
plantestsuite("samba.unittests.kerberos", "none",
              [os.path.join(bindir(), "test_kerberos")])
plantestsuite("samba.unittests.ms_fnmatch", "none",
              [os.path.join(bindir(), "default/lib/util/test_ms_fnmatch")])
plantestsuite("samba.unittests.ntlm_check", "none",
              [os.path.join(bindir(), "default/libcli/auth/test_ntlm_check")])
plantestsuite("samba.unittests.test_registry_regfio", "none",
              [os.path.join(bindir(), "default/source3/test_registry_regfio")])
