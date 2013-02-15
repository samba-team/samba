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

planpythontestsuite("none", "samba.tests.source")
planpythontestsuite("none", "samba.tests.docs")
planpythontestsuite("none", "selftest.tests.test_suite", extra_path=[srcdir()])
planpythontestsuite("none", "subunit")
planpythontestsuite("none", "samba.tests.blackbox.ndrdump")
planpythontestsuite("none", "api", name="ldb.python", extra_path=['lib/ldb/tests/python'])
planpythontestsuite("none", "samba.tests.credentials")
planpythontestsuite("none", "samba.tests.registry")
planpythontestsuite("none", "samba.tests.auth")
planpythontestsuite("none", "samba.tests.getopt")
planpythontestsuite("none", "samba.tests.security")
planpythontestsuite("none", "samba.tests.dcerpc.misc")
planpythontestsuite("none", "samba.tests.param")
planpythontestsuite("none", "samba.tests.upgrade")
planpythontestsuite("none", "samba.tests.core")
planpythontestsuite("none", "samba.tests.provision")
planpythontestsuite("none", "samba.tests.samba3")
planpythontestsuite("none", "samba.tests.strings")
planpythontestsuite("none", "samba.tests.netcmd")
planpythontestsuite("none", "samba.tests.dcerpc.rpc_talloc")
planpythontestsuite("none", "samba.tests.samdb")
planpythontestsuite("none", "samba.tests.hostconfig")
planpythontestsuite("none", "samba.tests.messaging")
planpythontestsuite("none", "samba.tests.samba3sam")
planpythontestsuite("none", "wafsamba.tests.test_suite", extra_path=[os.path.join(samba4srcdir, "..", "buildtools"), os.path.join(samba4srcdir, "..", "buildtools", "wafadmin")])
plantestsuite("samba4.blackbox.dbcheck.alpha13", "none" , ["PYTHON=%s" % python, os.path.join(bbdir, "dbcheck-oldrelease.sh"), '$PREFIX_ABS/provision', 'alpha13', configuration])
plantestsuite("samba4.blackbox.dbcheck.release-4-0-0", "none" , ["PYTHON=%s" % python, os.path.join(bbdir, "dbcheck-oldrelease.sh"), '$PREFIX_ABS/provision', 'release-4-0-0', configuration])
plantestsuite("samba4.blackbox.upgradeprovision.alpha13", "none" , ["PYTHON=%s" % python, os.path.join(bbdir, "upgradeprovision-oldrelease.sh"), '$PREFIX_ABS/provision', 'alpha13', configuration])
plantestsuite("samba4.blackbox.upgradeprovision.release-4-0-0", "none" , ["PYTHON=%s" % python, os.path.join(bbdir, "upgradeprovision-oldrelease.sh"), '$PREFIX_ABS/provision', 'release-4-0-0', configuration])
planpythontestsuite("none", "samba.tests.upgradeprovision")
planpythontestsuite("none", "samba.tests.xattr")
planpythontestsuite("none", "samba.tests.ntacls")
planpythontestsuite("none", "samba.tests.policy")
