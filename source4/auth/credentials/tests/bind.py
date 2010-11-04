#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This is unit with tests for LDAP access checks

import optparse
import sys
import base64
import re
import os

sys.path.append("bin/python")
import samba
samba.ensure_external_module("subunit", "subunit/python")
samba.ensure_external_module("testtools", "testtools")

import samba.getopt as options

from ldb import (
    SCOPE_BASE, SCOPE_SUBTREE, LdbError, ERR_NO_SUCH_OBJECT)
from samba.dcerpc import security

from samba.auth import system_session
from samba import gensec
from samba.samdb import SamDB
from samba.credentials import Credentials
import samba.tests
from subunit.run import SubunitTestRunner
import unittest

parser = optparse.OptionParser("ldap [options] <host>")
sambaopts = options.SambaOptions(parser)
parser.add_option_group(sambaopts)

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
creds_machine = creds

class BindTests(samba.tests.TestCase):
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

    def setUp(self):
        super(BindTests, self).setUp()
        self.base_dn = self.find_basedn(ldb)

    def tearDown(self):
        super(BindTests, self).tearDown()

    def test_computer_account_bind(self):
        # create a computer acocount for the test
        self.user_dn = "CN=centos53,CN=Computers,%s" % self.base_dn
        self.password = "P@ssw0rd"
        self.acc_name = "centos53$"

        self.delete_force(ldb, self.user_dn)
        ldb.add_ldif("""
dn: """ + self.user_dn + """
cn: CENTOS53
displayName: CENTOS53$
name: CENTOS53
sAMAccountName: CENTOS53$
countryCode: 0
objectClass: computer
objectClass: organizationalPerson
objectClass: person
objectClass: top
objectClass: user
codePage: 0
userAccountControl: 4096
dNSHostName: centos53.alabala.test
operatingSystemVersion: 5.2 (3790)
operatingSystem: Windows Server 2003
""")
        ldb.modify_ldif("""
dn: """ + self.user_dn + """
changetype: modify
replace: unicodePwd
unicodePwd:: """ + base64.b64encode("\"P@ssw0rd\"".encode('utf-16-le')) + """
""")

        # do a simple bind and search with the machine account
        creds_machine.set_bind_dn(self.user_dn)
        creds_machine.set_password(self.password)
        ldb_machine = SamDB(host, credentials=creds_machine, session_info=system_session(), lp=lp)
        self.find_basedn(ldb_machine)

if not "://" in host:
    host = "ldap://%s" % host
ldb = SamDB(host, credentials=creds, session_info=system_session(), lp=lp)

runner = SubunitTestRunner()
rc = 0
if not runner.run(unittest.makeSuite(BindTests)).wasSuccessful():
    rc = 1

sys.exit(rc)
