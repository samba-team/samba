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

import os
from selftesthelpers import source4dir, bindir, python, plantestsuite_loadlist

samba4srcdir = source4dir()
samba4bindir = bindir()

plantestsuite_loadlist("samba4.ldap.ad_dc_performance.python(ad_dc_ntvfs)",
                       "ad_dc_ntvfs",
                       [python, os.path.join(samba4srcdir,
                                             "dsdb/tests/python/ad_dc_performance.py"),
                        '$SERVER', '-U"$USERNAME%$PASSWORD"',
                        '--workgroup=$DOMAIN',
                        '$LOADLIST', '$LISTOPT'])

plantestsuite_loadlist("samba4.ndr_pack_performance.python(ad_dc_ntvfs)",
                       "ad_dc_ntvfs",
                       [python, os.path.join(samba4srcdir,
                                             "dsdb/tests/python/ndr_pack_performance.py"),
                        '$SERVER', '-U"$USERNAME%$PASSWORD"',
                        '--workgroup=$DOMAIN',
                        '$LOADLIST', '$LISTOPT'])

plantestsuite_loadlist("samba4.provision_performance.python(ad_dc_ntvfs)",
                       "ad_dc_ntvfs",
                       [python, os.path.join(samba4srcdir,
                                             "dsdb/tests/python/ad_dc_provision_performance.py"),
                        '$SERVER', '-U"$USERNAME%$PASSWORD"',
                        '--workgroup=$DOMAIN',
                        '$LOADLIST', '$LISTOPT'])

plantestsuite_loadlist("samba4.ldap.ad_dc_search_performance.python(ad_dc_ntvfs)",
                       "ad_dc_ntvfs",
                       [python,
                        os.path.join(samba4srcdir,
                                     "dsdb/tests/python/ad_dc_search_performance.py"),
                        '$SERVER', '-U"$USERNAME%$PASSWORD"',
                        '--workgroup=$DOMAIN',
                        '$LOADLIST', '$LISTOPT'])

plantestsuite_loadlist("samba4.ldap.ad_dc_multi_bind.ntlm.python(ad_dc_ntvfs)",
                       "ad_dc_ntvfs",
                       [python, os.path.join(samba4srcdir,
                                             "dsdb/tests/python/ad_dc_multi_bind.py"),
                        '$SERVER', '-U"$USERNAME%$PASSWORD"', '-k no',
                        '--workgroup=$DOMAIN',
                        '$LOADLIST', '$LISTOPT'])

plantestsuite_loadlist("samba4.ldap.ad_dc_multi_bind.krb5.python(ad_dc_ntvfs)",
                       "ad_dc_ntvfs",
                       [python, os.path.join(samba4srcdir,
                                             "dsdb/tests/python/ad_dc_multi_bind.py"),
                        '$SERVER', '-U"$USERNAME%$PASSWORD"', '-k yes',
                        '--realm=$REALM',
                        '$LOADLIST', '$LISTOPT'])

plantestsuite_loadlist("samba4.ldb.multi_connect.python(ad_dc_ntvfs)",
                       "ad_dc_ntvfs",
                       [python, os.path.join(samba4srcdir,
                                             "dsdb/tests/python/ad_dc_multi_bind.py"),
                        'tdb://$PREFIX_ABS/ad_dc_ntvfs/private/sam.ldb'
                        '$LOADLIST', '$LISTOPT'])

plantestsuite_loadlist("samba4.ldap.vlv.python(ad_dc_ntvfs)", "ad_dc_ntvfs",
                       [python,
                        os.path.join(samba4srcdir, "dsdb/tests/python/vlv.py"),
                        '$SERVER', '-U"$USERNAME%$PASSWORD"',
                        '--workgroup=$DOMAIN', '$LOADLIST', '$LISTOPT'])

# this one doesn't tidy itself up fully, so leave it as last unless
# you want a messy database.
plantestsuite_loadlist("samba4.ldap.ad_dc_medley_performance.python(ad_dc_ntvfs)",
                       "ad_dc_ntvfs",
                       [python,
                        os.path.join(samba4srcdir,
                                     "dsdb/tests/python/ad_dc_medley_performance.py"),
                        '$SERVER', '-U"$USERNAME%$PASSWORD"',
                        '--workgroup=$DOMAIN',
                        '$LOADLIST', '$LISTOPT'])

# again with paged search module
plantestsuite_loadlist("samba4.ldap.ad_dc_performance.paged_search."+\
                           "python(ad_dc_ntvfs)",
                       "ad_dc_ntvfs",
                       [python,
                        os.path.join(samba4srcdir,
                              "dsdb/tests/python/ad_dc_medley_performance.py"),
                        '$SERVER', '-U"$USERNAME%$PASSWORD"',
                        '--workgroup=$DOMAIN',
                        '--use-paged-search',
                        '$LOADLIST', '$LISTOPT'])
