#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Unix SMB/CIFS implementation.
# This speed test aims to show difference in execution time for bulk
# creation of user objects. This will help us compare
# Samba4 vs MS Active Directory performance.

# Copyright (C) Zahari Zahariev <zahari.zahariev@postpath.com> 2010
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import optparse
import sys
import time
from decimal import Decimal

sys.path.append("bin/python")
import samba
samba.ensure_external_module("subunit", "subunit/python")
samba.ensure_external_module("testtools", "testtools")

import samba.getopt as options

from ldb import (
            SCOPE_BASE, SCOPE_SUBTREE, LdbError, ERR_NO_SUCH_OBJECT,
                ERR_UNWILLING_TO_PERFORM, ERR_INSUFFICIENT_ACCESS_RIGHTS)
from samba.ndr import ndr_pack, ndr_unpack
from samba.dcerpc import security

from samba.auth import system_session
from samba import gensec
from samba.samdb import SamDB
from samba.credentials import Credentials
import samba.tests
from subunit.run import SubunitTestRunner
import unittest

parser = optparse.OptionParser("speedtest [options] <host>")
sambaopts = options.SambaOptions(parser)
parser.add_option_group(sambaopts)
parser.add_option_group(options.VersionOptions(parser))


# use command line creds if available
credopts = options.CredentialsOptions(parser)
parser.add_option_group(credopts)
opts, args = parser.parse_args()

if len(args) < 1:
    parser.print_usage()
    sys.exit(1)

host = args[0]

lp = sambaopts.get_loadparm()
creds = credopts.get_credentials(lp)
creds.set_gensec_features(creds.get_gensec_features() | gensec.FEATURE_SEAL)

#
# Tests start here
#

class SpeedTest(samba.tests.TestCase):

    def delete_force(self, ldb, dn):
        try:
            ldb.delete(dn)
        except LdbError, (num, _):
            self.assertEquals(num, ERR_NO_SUCH_OBJECT)

    def find_basedn(self, ldb):
        res = ldb.search(base="", expression="", scope=SCOPE_BASE,
                         attrs=["defaultNamingContext"])
        self.assertEquals(len(res), 1)
        return res[0]["defaultNamingContext"][0]

    def find_domain_sid(self, ldb):
        res = ldb.search(base=self.base_dn, expression="(objectClass=*)", scope=SCOPE_BASE)
        return ndr_unpack(security.dom_sid,res[0]["objectSid"][0])

    def setUp(self):
        super(SpeedTest, self).setUp()
        self.ldb_admin = ldb
        self.base_dn = self.find_basedn(self.ldb_admin)
        self.domain_sid = self.find_domain_sid(self.ldb_admin)
        self.user_pass = "samba123@"
        print "baseDN: %s" % self.base_dn

    def create_user(self, user_dn):
        ldif = """
dn: """ + user_dn + """
sAMAccountName: """ + user_dn.split(",")[0][3:] + """
objectClass: user
userPassword: """ + self.user_pass + """
url: www.example.com
"""
        self.ldb_admin.add_ldif(ldif)

    def create_group(self, group_dn, desc=None):
        ldif = """
dn: """ + group_dn + """
objectClass: group
sAMAccountName: """ + group_dn.split(",")[0][3:] + """
objectClass: group
sAMAccountName: """ + group_dn.split(",")[0][3:] + """
groupType: 4
url: www.example.com
"""
        self.ldb_admin.add_ldif(ldif)

    def create_bundle(self, count):
        for i in range(count):
            self.create_user("cn=speedtestuser%d,cn=Users,%s" % (i+1, self.base_dn))

    def remove_bundle(self, count):
        for i in range(count):
            self.delete_force(self.ldb_admin, "cn=speedtestuser%d,cn=Users,%s" % (i+1, self.base_dn))

    def remove_test_users(self):
        res = ldb.search(base="cn=Users,%s" % self.base_dn, expression="(objectClass=user)", scope=SCOPE_SUBTREE)
        dn_list = [item.dn for item in res if "speedtestuser" in str(item.dn)]
        for dn in dn_list:
            self.delete_force(self.ldb_admin, dn)

    def run_bundle(self, num):
        print "\n=== Test ADD/DEL %s user objects ===\n" % num
        avg_add = Decimal("0.0")
        avg_del = Decimal("0.0")
        for x in [1, 2, 3]:
            start = time.time()
            self.create_bundle(num)
            res_add = Decimal( str(time.time() - start) )
            avg_add += res_add
            print "   Attempt %s ADD: %.3fs" % ( x, float(res_add) )
            #
            start = time.time()
            self.remove_bundle(num)
            res_del = Decimal( str(time.time() - start) )
            avg_del += res_del
            print "   Attempt %s DEL: %.3fs" % ( x, float(res_del) )
        print "Average ADD: %.3fs" % float( Decimal(avg_add) / Decimal("3.0") )
        print "Average DEL: %.3fs" % float( Decimal(avg_del) / Decimal("3.0") )
        print ""

    def test_00000(self):
        """ Remove possibly undeleted test users from previous test
        """
        self.remove_test_users()

    def test_00010(self):
        self.run_bundle(10)

    def test_00100(self):
        self.run_bundle(100)

    def test_01000(self):
        self.run_bundle(1000)

    def _test_10000(self):
        """ This test should be enabled preferably against MS Active Directory.
            It takes quite the time against Samba4 (1-2 days).
        """
        self.run_bundle(10000)

# Important unit running information

if not "://" in host:
    host = "ldap://%s" % host

ldb_options = ["modules:paged_searches"]
ldb = SamDB(host, credentials=creds, session_info=system_session(), lp=lp, options=ldb_options)

runner = SubunitTestRunner()
rc = 0
if not runner.run(unittest.makeSuite(SpeedTest)).wasSuccessful():
    rc = 1

sys.exit(rc)
