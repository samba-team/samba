#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This tests the password changes over LDAP for AD implementations
#
# Copyright Matthias Dieter Wallnoefer 2010
#
# Notice: This tests will also work against Windows Server if the connection is
# secured enough (SASL with a minimum of 128 Bit encryption) - consider
# MS-ADTS 3.1.1.3.1.5

import optparse
import sys
import base64
import os

sys.path.append("bin/python")
import samba
samba.ensure_external_module("subunit", "subunit/python")
samba.ensure_external_module("testtools", "testtools")

import samba.getopt as options

from samba.auth import system_session
from samba.credentials import Credentials
from ldb import SCOPE_BASE, LdbError
from ldb import ERR_NO_SUCH_OBJECT, ERR_ATTRIBUTE_OR_VALUE_EXISTS
from ldb import ERR_UNWILLING_TO_PERFORM, ERR_INSUFFICIENT_ACCESS_RIGHTS
from ldb import ERR_NO_SUCH_ATTRIBUTE
from ldb import ERR_CONSTRAINT_VIOLATION
from ldb import Message, MessageElement, Dn
from ldb import FLAG_MOD_REPLACE, FLAG_MOD_DELETE
from samba import gensec
from samba.samdb import SamDB
import samba.tests
from subunit.run import SubunitTestRunner
import unittest

parser = optparse.OptionParser("passwords [options] <host>")
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

# Force an encrypted connection
creds.set_gensec_features(creds.get_gensec_features() | gensec.FEATURE_SEAL)

#
# Tests start here
#

class PasswordTests(samba.tests.TestCase):

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
        super(PasswordTests, self).setUp()
        self.ldb = ldb
        self.base_dn = self.find_basedn(ldb)

        # (Re)adds the test user "testuser" with the inital password
        # "thatsAcomplPASS1"
        self.delete_force(self.ldb, "cn=testuser,cn=users," + self.base_dn)
        self.ldb.add({
             "dn": "cn=testuser,cn=users," + self.base_dn,
             "objectclass": ["user", "person"],
             "sAMAccountName": "testuser",
             "userPassword": "thatsAcomplPASS1" })
        self.ldb.enable_account("(sAMAccountName=testuser)")

        # Open a second LDB connection with the user credentials. Use the
        # command line credentials for informations like the domain, the realm
        # and the workstation.
        creds2 = Credentials()
        creds2.set_username("testuser")
        creds2.set_password("thatsAcomplPASS1")
        creds2.set_domain(creds.get_domain())
        creds2.set_realm(creds.get_realm())
        creds2.set_workstation(creds.get_workstation())
        creds2.set_gensec_features(creds2.get_gensec_features()
                                                          | gensec.FEATURE_SEAL)
        self.ldb2 = SamDB(url=host, credentials=creds2, lp=lp)

    def test_unicodePwd_hash_set(self):
        print "Performs a password hash set operation on 'unicodePwd' which should be prevented"
        # Notice: Direct hash password sets should never work

        m = Message()
        m.dn = Dn(ldb, "cn=testuser,cn=users," + self.base_dn)
        m["unicodePwd"] = MessageElement("XXXXXXXXXXXXXXXX", FLAG_MOD_REPLACE,
          "unicodePwd")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_UNWILLING_TO_PERFORM)

    def test_unicodePwd_hash_change(self):
        print "Performs a password hash change operation on 'unicodePwd' which should be prevented"
        # Notice: Direct hash password changes should never work

        # Hash password changes should never work
        try:
            self.ldb2.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
delete: unicodePwd
unicodePwd: XXXXXXXXXXXXXXXX
add: unicodePwd
unicodePwd: YYYYYYYYYYYYYYYY
""")
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_CONSTRAINT_VIOLATION)

    def test_unicodePwd_clear_set(self):
        print "Performs a password cleartext set operation on 'unicodePwd'"

        m = Message()
        m.dn = Dn(ldb, "cn=testuser,cn=users," + self.base_dn)
        m["unicodePwd"] = MessageElement("\"thatsAcomplPASS2\"".encode('utf-16-le'),
          FLAG_MOD_REPLACE, "unicodePwd")
        ldb.modify(m)

    def test_unicodePwd_clear_change(self):
        print "Performs a password cleartext change operation on 'unicodePwd'"

        self.ldb2.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
delete: unicodePwd
unicodePwd:: """ + base64.b64encode("\"thatsAcomplPASS1\"".encode('utf-16-le')) + """
add: unicodePwd
unicodePwd:: """ + base64.b64encode("\"thatsAcomplPASS2\"".encode('utf-16-le')) + """
""")

        # A change to the same password again will not work (password history)
        try:
            self.ldb2.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
delete: unicodePwd
unicodePwd:: """ + base64.b64encode("\"thatsAcomplPASS2\"".encode('utf-16-le')) + """
add: unicodePwd
unicodePwd:: """ + base64.b64encode("\"thatsAcomplPASS2\"".encode('utf-16-le')) + """
""")
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_CONSTRAINT_VIOLATION)

    def test_dBCSPwd_hash_set(self):
        print "Performs a password hash set operation on 'dBCSPwd' which should be prevented"
        # Notice: Direct hash password sets should never work

        m = Message()
        m.dn = Dn(ldb, "cn=testuser,cn=users," + self.base_dn)
        m["dBCSPwd"] = MessageElement("XXXXXXXXXXXXXXXX", FLAG_MOD_REPLACE,
          "dBCSPwd")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_UNWILLING_TO_PERFORM)

    def test_dBCSPwd_hash_change(self):
        print "Performs a password hash change operation on 'dBCSPwd' which should be prevented"
        # Notice: Direct hash password changes should never work

        try:
            self.ldb2.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
delete: dBCSPwd
dBCSPwd: XXXXXXXXXXXXXXXX
add: dBCSPwd
dBCSPwd: YYYYYYYYYYYYYYYY
""")
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_UNWILLING_TO_PERFORM)

    def test_userPassword_clear_set(self):
        print "Performs a password cleartext set operation on 'userPassword'"
        # Notice: This works only against Windows if "dSHeuristics" has been set
        # properly

        m = Message()
        m.dn = Dn(ldb, "cn=testuser,cn=users," + self.base_dn)
        m["userPassword"] = MessageElement("thatsAcomplPASS2", FLAG_MOD_REPLACE,
          "userPassword")
        ldb.modify(m)

    def test_userPassword_clear_change(self):
        print "Performs a password cleartext change operation on 'userPassword'"
        # Notice: This works only against Windows if "dSHeuristics" has been set
        # properly

        self.ldb2.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
delete: userPassword
userPassword: thatsAcomplPASS1
add: userPassword
userPassword: thatsAcomplPASS2
""")

        # A change to the same password again will not work (password history)
        try:
            self.ldb2.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
delete: userPassword
userPassword: thatsAcomplPASS2
add: userPassword
userPassword: thatsAcomplPASS2
""")
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_CONSTRAINT_VIOLATION)

    def test_clearTextPassword_clear_set(self):
        print "Performs a password cleartext set operation on 'clearTextPassword'"
        # Notice: This never works against Windows - only supported by us

        try:
            m = Message()
            m.dn = Dn(ldb, "cn=testuser,cn=users," + self.base_dn)
            m["clearTextPassword"] = MessageElement("thatsAcomplPASS2".encode('utf-16-le'),
              FLAG_MOD_REPLACE, "clearTextPassword")
            ldb.modify(m)
            # this passes against s4
        except LdbError, (num, msg):
            # "NO_SUCH_ATTRIBUTE" is returned by Windows -> ignore it
            if num != ERR_NO_SUCH_ATTRIBUTE:
                raise LdbError(num, msg)

    def test_clearTextPassword_clear_change(self):
        print "Performs a password cleartext change operation on 'clearTextPassword'"
        # Notice: This never works against Windows - only supported by us

        try:
            self.ldb2.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
delete: clearTextPassword
clearTextPassword:: """ + base64.b64encode("thatsAcomplPASS1".encode('utf-16-le')) + """
add: clearTextPassword
clearTextPassword:: """ + base64.b64encode("thatsAcomplPASS2".encode('utf-16-le')) + """
""")
            # this passes against s4
        except LdbError, (num, msg):
            # "NO_SUCH_ATTRIBUTE" is returned by Windows -> ignore it
            if num != ERR_NO_SUCH_ATTRIBUTE:
                raise LdbError(num, msg)

        # A change to the same password again will not work (password history)
        try:
            self.ldb2.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
delete: clearTextPassword
clearTextPassword:: """ + base64.b64encode("thatsAcomplPASS2".encode('utf-16-le')) + """
add: clearTextPassword
clearTextPassword:: """ + base64.b64encode("thatsAcomplPASS2".encode('utf-16-le')) + """
""")
            self.fail()
        except LdbError, (num, _):
            # "NO_SUCH_ATTRIBUTE" is returned by Windows -> ignore it
            if num != ERR_NO_SUCH_ATTRIBUTE:
                self.assertEquals(num, ERR_CONSTRAINT_VIOLATION)

    def test_failures(self):
        print "Performs some failure testing"

        try:
            ldb.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
delete: userPassword
userPassword: thatsAcomplPASS1
""")
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_CONSTRAINT_VIOLATION)

        try:
            self.ldb2.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
delete: userPassword
""")
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_CONSTRAINT_VIOLATION)

        try:
            ldb.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
add: userPassword
userPassword: thatsAcomplPASS1
""")
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_UNWILLING_TO_PERFORM)

        try:
            self.ldb2.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
add: userPassword
userPassword: thatsAcomplPASS1
""")
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)

        try:
            ldb.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
delete: userPassword
userPassword: thatsAcomplPASS1
add: userPassword
userPassword: thatsAcomplPASS2
userPassword: thatsAcomplPASS2
""")
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_CONSTRAINT_VIOLATION)

        try:
            self.ldb2.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
delete: userPassword
userPassword: thatsAcomplPASS1
add: userPassword
userPassword: thatsAcomplPASS2
userPassword: thatsAcomplPASS2
""")
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_CONSTRAINT_VIOLATION)

        try:
            ldb.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
delete: userPassword
userPassword: thatsAcomplPASS1
userPassword: thatsAcomplPASS1
add: userPassword
userPassword: thatsAcomplPASS2
""")
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_CONSTRAINT_VIOLATION)

        try:
            self.ldb2.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
delete: userPassword
userPassword: thatsAcomplPASS1
userPassword: thatsAcomplPASS1
add: userPassword
userPassword: thatsAcomplPASS2
""")
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_CONSTRAINT_VIOLATION)

        try:
            ldb.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
delete: userPassword
userPassword: thatsAcomplPASS1
add: userPassword
userPassword: thatsAcomplPASS2
add: userPassword
userPassword: thatsAcomplPASS2
""")
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_UNWILLING_TO_PERFORM)

        try:
            self.ldb2.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
delete: userPassword
userPassword: thatsAcomplPASS1
add: userPassword
userPassword: thatsAcomplPASS2
add: userPassword
userPassword: thatsAcomplPASS2
""")
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)

        try:
            ldb.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
delete: userPassword
userPassword: thatsAcomplPASS1
delete: userPassword
userPassword: thatsAcomplPASS1
add: userPassword
userPassword: thatsAcomplPASS2
""")
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_UNWILLING_TO_PERFORM)

        try:
            self.ldb2.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
delete: userPassword
userPassword: thatsAcomplPASS1
delete: userPassword
userPassword: thatsAcomplPASS1
add: userPassword
userPassword: thatsAcomplPASS2
""")
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)

        try:
            ldb.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
delete: userPassword
userPassword: thatsAcomplPASS1
add: userPassword
userPassword: thatsAcomplPASS2
replace: userPassword
userPassword: thatsAcomplPASS3
""")
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_UNWILLING_TO_PERFORM)

        try:
            self.ldb2.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
delete: userPassword
userPassword: thatsAcomplPASS1
add: userPassword
userPassword: thatsAcomplPASS2
replace: userPassword
userPassword: thatsAcomplPASS3
""")
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)

        # Reverse order does work
        self.ldb2.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
add: userPassword
userPassword: thatsAcomplPASS2
delete: userPassword
userPassword: thatsAcomplPASS1
""")

        try:
            self.ldb2.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
delete: userPassword
userPassword: thatsAcomplPASS2
add: unicodePwd
unicodePwd:: """ + base64.b64encode("\"thatsAcomplPASS3\"".encode('utf-16-le')) + """
""")
             # this passes against s4
        except LdbError, (num, _):
            self.assertEquals(num, ERR_ATTRIBUTE_OR_VALUE_EXISTS)

        try:
            self.ldb2.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
delete: unicodePwd
unicodePwd:: """ + base64.b64encode("\"thatsAcomplPASS3\"".encode('utf-16-le')) + """
add: userPassword
userPassword: thatsAcomplPASS4
""")
             # this passes against s4
        except LdbError, (num, _):
            self.assertEquals(num, ERR_NO_SUCH_ATTRIBUTE)

        # Several password changes at once are allowed
        ldb.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
replace: userPassword
userPassword: thatsAcomplPASS1
userPassword: thatsAcomplPASS2
""")

        # Several password changes at once are allowed
        ldb.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
replace: userPassword
userPassword: thatsAcomplPASS1
userPassword: thatsAcomplPASS2
replace: userPassword
userPassword: thatsAcomplPASS3
replace: userPassword
userPassword: thatsAcomplPASS4
""")

        # This surprisingly should work
        self.delete_force(self.ldb, "cn=testuser2,cn=users," + self.base_dn)
        self.ldb.add({
             "dn": "cn=testuser2,cn=users," + self.base_dn,
             "objectclass": ["user", "person"],
             "userPassword": ["thatsAcomplPASS1", "thatsAcomplPASS2"] })

        # This surprisingly should work
        self.delete_force(self.ldb, "cn=testuser2,cn=users," + self.base_dn)
        self.ldb.add({
             "dn": "cn=testuser2,cn=users," + self.base_dn,
             "objectclass": ["user", "person"],
             "userPassword": ["thatsAcomplPASS1", "thatsAcomplPASS1"] })

    def tearDown(self):
        super(PasswordTests, self).tearDown()
        self.delete_force(self.ldb, "cn=testuser,cn=users," + self.base_dn)
        self.delete_force(self.ldb, "cn=testuser2,cn=users," + self.base_dn)
        # Close the second LDB connection (with the user credentials)
        self.ldb2 = None

if not "://" in host:
    if os.path.isfile(host):
        host = "tdb://%s" % host
    else:
        host = "ldap://%s" % host

ldb = SamDB(url=host, session_info=system_session(), credentials=creds, lp=lp)

# Gets back the configuration basedn
res = ldb.search(base="", expression="", scope=SCOPE_BASE,
                 attrs=["configurationNamingContext"])
configuration_dn = res[0]["configurationNamingContext"][0]

# Gets back the basedn
res = ldb.search(base="", expression="", scope=SCOPE_BASE,
                 attrs=["defaultNamingContext"])
base_dn = res[0]["defaultNamingContext"][0]

# Get the old "dSHeuristics" if it was set
res = ldb.search("CN=Directory Service, CN=Windows NT, CN=Services, "
                 + configuration_dn, scope=SCOPE_BASE, attrs=["dSHeuristics"])
if "dSHeuristics" in res[0]:
  dsheuristics = res[0]["dSHeuristics"][0]
else:
  dsheuristics = None

# Set the "dSHeuristics" to have the tests run against Windows Server
m = Message()
m.dn = Dn(ldb, "CN=Directory Service, CN=Windows NT, CN=Services, "
  + configuration_dn)
m["dSHeuristics"] = MessageElement("000000001", FLAG_MOD_REPLACE,
  "dSHeuristics")
ldb.modify(m)

# Get the old "minPwdAge"
res = ldb.search(base_dn, scope=SCOPE_BASE, attrs=["minPwdAge"])
minPwdAge = res[0]["minPwdAge"][0]

# Set it temporarely to "0"
m = Message()
m.dn = Dn(ldb, base_dn)
m["minPwdAge"] = MessageElement("0", FLAG_MOD_REPLACE, "minPwdAge")
ldb.modify(m)

runner = SubunitTestRunner()
rc = 0
if not runner.run(unittest.makeSuite(PasswordTests)).wasSuccessful():
    rc = 1

# Reset the "dSHeuristics" as they were before
m = Message()
m.dn = Dn(ldb, "CN=Directory Service, CN=Windows NT, CN=Services, "
  + configuration_dn)
if dsheuristics is not None:
    m["dSHeuristics"] = MessageElement(dsheuristics, FLAG_MOD_REPLACE,
      "dSHeuristics")
else:
    m["dSHeuristics"] = MessageElement([], FLAG_MOD_DELETE, "dsHeuristics")
ldb.modify(m)

# Reset the "minPwdAge" as it was before
m = Message()
m.dn = Dn(ldb, base_dn)
m["minPwdAge"] = MessageElement(minPwdAge, FLAG_MOD_REPLACE, "minPwdAge")
ldb.modify(m)

sys.exit(rc)
