#!/usr/bin/python

# This script generates a list of testsuites that should be run to
# test Samba performance.
#
# These tests are not intended to exercise aspect of Samba, but
# perform common simple functions or to ascertain performance.
#

# The syntax for a testsuite is "-- TEST --" on a single line, followed
# by the name of the test, the environment it needs and the command to run, all
# three separated by newlines. All other lines in the output are considered
# comments.

from selftesthelpers import *

samba4srcdir = source4dir()
samba4bindir = bindir()

plantestsuite_loadlist("samba4.ldap.ad_dc_performance.python(ad_dc_ntvfs)",
                       "ad_dc_ntvfs",
                       [python, os.path.join(samba4srcdir,
                                             "dsdb/tests/python/ad_dc_performance.py"),
                        '$SERVER', '-U"$USERNAME%$PASSWORD"',
                        '--workgroup=$DOMAIN',
                        '$LOADLIST', '$LISTOPT'])
