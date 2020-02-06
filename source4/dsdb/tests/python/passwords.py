#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This tests the password changes over LDAP for AD implementations
#
# Copyright Matthias Dieter Wallnoefer 2010
#
# Notice: This tests will also work against Windows Server if the connection is
# secured enough (SASL with a minimum of 128 Bit encryption) - consider
# MS-ADTS 3.1.1.3.1.5

from __future__ import print_function
import optparse
import sys
import base64
import time
import os

sys.path.insert(0, "bin/python")
import samba

from samba.tests.subunitrun import SubunitOptions, TestProgram
from samba.tests.password_test import PasswordTestCase

import samba.getopt as options

from samba.auth import system_session
from samba.credentials import Credentials
from ldb import SCOPE_BASE, LdbError
from ldb import ERR_ATTRIBUTE_OR_VALUE_EXISTS
from ldb import ERR_UNWILLING_TO_PERFORM, ERR_INSUFFICIENT_ACCESS_RIGHTS
from ldb import ERR_NO_SUCH_ATTRIBUTE
from ldb import ERR_CONSTRAINT_VIOLATION
from ldb import Message, MessageElement, Dn
from ldb import FLAG_MOD_ADD, FLAG_MOD_REPLACE, FLAG_MOD_DELETE
from samba import gensec
from samba.samdb import SamDB
import samba.tests
from samba.tests import delete_force
from password_lockout_base import BasePasswordTestCase

parser = optparse.OptionParser("passwords.py [options] <host>")
sambaopts = options.SambaOptions(parser)
parser.add_option_group(sambaopts)
parser.add_option_group(options.VersionOptions(parser))
# use command line creds if available
credopts = options.CredentialsOptions(parser)
parser.add_option_group(credopts)
subunitopts = SubunitOptions(parser)
parser.add_option_group(subunitopts)

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


class PasswordTests(PasswordTestCase):

    def setUp(self):
        super(PasswordTests, self).setUp()
        self.ldb = SamDB(url=host, session_info=system_session(lp), credentials=creds, lp=lp)

        # Gets back the basedn
        base_dn = self.ldb.domain_dn()

        # Gets back the configuration basedn
        configuration_dn = self.ldb.get_config_basedn().get_linearized()

        # permit password changes during this test
        self.allow_password_changes()

        self.base_dn = self.ldb.domain_dn()

        # (Re)adds the test user "testuser" with no password atm
        delete_force(self.ldb, "cn=testuser,cn=users," + self.base_dn)
        self.ldb.add({
             "dn": "cn=testuser,cn=users," + self.base_dn,
             "objectclass": "user",
             "sAMAccountName": "testuser"})

        # Tests a password change when we don't have any password yet with a
        # wrong old password
        try:
            self.ldb.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
delete: userPassword
userPassword: noPassword
add: userPassword
userPassword: thatsAcomplPASS2
""")
            self.fail()
        except LdbError as e:
            (num, msg) = e.args
            self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)
            # Windows (2008 at least) seems to have some small bug here: it
            # returns "0000056A" on longer (always wrong) previous passwords.
            self.assertTrue('00000056' in msg)

        # Sets the initial user password with a "special" password change
        # I think that this internally is a password set operation and it can
        # only be performed by someone which has password set privileges on the
        # account (at least in s4 we do handle it like that).
        self.ldb.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
delete: userPassword
add: userPassword
userPassword: thatsAcomplPASS1
""")

        # But in the other way around this special syntax doesn't work
        try:
            self.ldb.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
delete: userPassword
userPassword: thatsAcomplPASS1
add: userPassword
""")
            self.fail()
        except LdbError as e1:
            (num, _) = e1.args
            self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)

        # Enables the user account
        self.ldb.enable_account("(sAMAccountName=testuser)")

        # Open a second LDB connection with the user credentials. Use the
        # command line credentials for information like the domain, the realm
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
        """Performs a password hash set operation on 'unicodePwd' which should be prevented"""
        # Notice: Direct hash password sets should never work

        m = Message()
        m.dn = Dn(self.ldb, "cn=testuser,cn=users," + self.base_dn)
        m["unicodePwd"] = MessageElement("XXXXXXXXXXXXXXXX", FLAG_MOD_REPLACE,
                                         "unicodePwd")
        try:
            self.ldb.modify(m)
            self.fail()
        except LdbError as e2:
            (num, _) = e2.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

    def test_unicodePwd_hash_change(self):
        """Performs a password hash change operation on 'unicodePwd' which should be prevented"""
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
        except LdbError as e3:
            (num, _) = e3.args
            self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)

    def test_unicodePwd_clear_set(self):
        """Performs a password cleartext set operation on 'unicodePwd'"""

        m = Message()
        m.dn = Dn(self.ldb, "cn=testuser,cn=users," + self.base_dn)
        m["unicodePwd"] = MessageElement("\"thatsAcomplPASS2\"".encode('utf-16-le'),
                                         FLAG_MOD_REPLACE, "unicodePwd")
        self.ldb.modify(m)

    def test_unicodePwd_clear_change(self):
        """Performs a password cleartext change operation on 'unicodePwd'"""

        self.ldb2.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
delete: unicodePwd
unicodePwd:: """ + base64.b64encode("\"thatsAcomplPASS1\"".encode('utf-16-le')).decode('utf8') + """
add: unicodePwd
unicodePwd:: """ + base64.b64encode("\"thatsAcomplPASS2\"".encode('utf-16-le')).decode('utf8') + """
""")

        # Wrong old password
        try:
            self.ldb2.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
delete: unicodePwd
unicodePwd:: """ + base64.b64encode("\"thatsAcomplPASS3\"".encode('utf-16-le')).decode('utf8') + """
add: unicodePwd
unicodePwd:: """ + base64.b64encode("\"thatsAcomplPASS4\"".encode('utf-16-le')).decode('utf8') + """
""")
            self.fail()
        except LdbError as e4:
            (num, msg) = e4.args
            self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)
            self.assertTrue('00000056' in msg)

        # A change to the same password again will not work (password history)
        try:
            self.ldb2.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
delete: unicodePwd
unicodePwd:: """ + base64.b64encode("\"thatsAcomplPASS2\"".encode('utf-16-le')).decode('utf8') + """
add: unicodePwd
unicodePwd:: """ + base64.b64encode("\"thatsAcomplPASS2\"".encode('utf-16-le')).decode('utf8') + """
""")
            self.fail()
        except LdbError as e5:
            (num, msg) = e5.args
            self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)
            self.assertTrue('0000052D' in msg)

    def test_dBCSPwd_hash_set(self):
        """Performs a password hash set operation on 'dBCSPwd' which should be prevented"""
        # Notice: Direct hash password sets should never work

        m = Message()
        m.dn = Dn(self.ldb, "cn=testuser,cn=users," + self.base_dn)
        m["dBCSPwd"] = MessageElement("XXXXXXXXXXXXXXXX", FLAG_MOD_REPLACE,
                                      "dBCSPwd")
        try:
            self.ldb.modify(m)
            self.fail()
        except LdbError as e6:
            (num, _) = e6.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

    def test_dBCSPwd_hash_change(self):
        """Performs a password hash change operation on 'dBCSPwd' which should be prevented"""
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
        except LdbError as e7:
            (num, _) = e7.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

    def test_userPassword_clear_set(self):
        """Performs a password cleartext set operation on 'userPassword'"""
        # Notice: This works only against Windows if "dSHeuristics" has been set
        # properly

        m = Message()
        m.dn = Dn(self.ldb, "cn=testuser,cn=users," + self.base_dn)
        m["userPassword"] = MessageElement("thatsAcomplPASS2", FLAG_MOD_REPLACE,
                                           "userPassword")
        self.ldb.modify(m)

    def test_userPassword_clear_change(self):
        """Performs a password cleartext change operation on 'userPassword'"""
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

        # Wrong old password
        try:
            self.ldb2.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
delete: userPassword
userPassword: thatsAcomplPASS3
add: userPassword
userPassword: thatsAcomplPASS4
""")
            self.fail()
        except LdbError as e8:
            (num, msg) = e8.args
            self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)
            self.assertTrue('00000056' in msg)

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
        except LdbError as e9:
            (num, msg) = e9.args
            self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)
            self.assertTrue('0000052D' in msg)

    def test_clearTextPassword_clear_set(self):
        """Performs a password cleartext set operation on 'clearTextPassword'"""
        # Notice: This never works against Windows - only supported by us

        try:
            m = Message()
            m.dn = Dn(self.ldb, "cn=testuser,cn=users," + self.base_dn)
            m["clearTextPassword"] = MessageElement("thatsAcomplPASS2".encode('utf-16-le'),
                                                    FLAG_MOD_REPLACE, "clearTextPassword")
            self.ldb.modify(m)
            # this passes against s4
        except LdbError as e10:
            (num, msg) = e10.args
            # "NO_SUCH_ATTRIBUTE" is returned by Windows -> ignore it
            if num != ERR_NO_SUCH_ATTRIBUTE:
                raise LdbError(num, msg)

    def test_clearTextPassword_clear_change(self):
        """Performs a password cleartext change operation on 'clearTextPassword'"""
        # Notice: This never works against Windows - only supported by us

        try:
            self.ldb2.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
delete: clearTextPassword
clearTextPassword:: """ + base64.b64encode("thatsAcomplPASS1".encode('utf-16-le')).decode('utf8') + """
add: clearTextPassword
clearTextPassword:: """ + base64.b64encode("thatsAcomplPASS2".encode('utf-16-le')).decode('utf8') + """
""")
            # this passes against s4
        except LdbError as e11:
            (num, msg) = e11.args
            # "NO_SUCH_ATTRIBUTE" is returned by Windows -> ignore it
            if num != ERR_NO_SUCH_ATTRIBUTE:
                raise LdbError(num, msg)

        # Wrong old password
        try:
            self.ldb2.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
delete: clearTextPassword
clearTextPassword:: """ + base64.b64encode("thatsAcomplPASS3".encode('utf-16-le')).decode('utf8') + """
add: clearTextPassword
clearTextPassword:: """ + base64.b64encode("thatsAcomplPASS4".encode('utf-16-le')).decode('utf8') + """
""")
            self.fail()
        except LdbError as e12:
            (num, msg) = e12.args
            # "NO_SUCH_ATTRIBUTE" is returned by Windows -> ignore it
            if num != ERR_NO_SUCH_ATTRIBUTE:
                self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)
                self.assertTrue('00000056' in msg)

        # A change to the same password again will not work (password history)
        try:
            self.ldb2.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
delete: clearTextPassword
clearTextPassword:: """ + base64.b64encode("thatsAcomplPASS2".encode('utf-16-le')).decode('utf8') + """
add: clearTextPassword
clearTextPassword:: """ + base64.b64encode("thatsAcomplPASS2".encode('utf-16-le')).decode('utf8') + """
""")
            self.fail()
        except LdbError as e13:
            (num, msg) = e13.args
            # "NO_SUCH_ATTRIBUTE" is returned by Windows -> ignore it
            if num != ERR_NO_SUCH_ATTRIBUTE:
                self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)
                self.assertTrue('0000052D' in msg)

    def test_failures(self):
        """Performs some failure testing"""

        try:
            self.ldb.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
delete: userPassword
userPassword: thatsAcomplPASS1
""")
            self.fail()
        except LdbError as e14:
            (num, _) = e14.args
            self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)

        try:
            self.ldb2.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
delete: userPassword
userPassword: thatsAcomplPASS1
""")
            self.fail()
        except LdbError as e15:
            (num, _) = e15.args
            self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)

        try:
            self.ldb.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
delete: userPassword
""")
            self.fail()
        except LdbError as e16:
            (num, _) = e16.args
            self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)

        try:
            self.ldb2.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
delete: userPassword
""")
            self.fail()
        except LdbError as e17:
            (num, _) = e17.args
            self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)

        try:
            self.ldb.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
add: userPassword
userPassword: thatsAcomplPASS1
""")
            self.fail()
        except LdbError as e18:
            (num, _) = e18.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        try:
            self.ldb2.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
add: userPassword
userPassword: thatsAcomplPASS1
""")
            self.fail()
        except LdbError as e19:
            (num, _) = e19.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)

        try:
            self.ldb.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
delete: userPassword
userPassword: thatsAcomplPASS1
add: userPassword
userPassword: thatsAcomplPASS2
userPassword: thatsAcomplPASS2
""")
            self.fail()
        except LdbError as e20:
            (num, _) = e20.args
            self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)

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
        except LdbError as e21:
            (num, _) = e21.args
            self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)

        try:
            self.ldb.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
delete: userPassword
userPassword: thatsAcomplPASS1
userPassword: thatsAcomplPASS1
add: userPassword
userPassword: thatsAcomplPASS2
""")
            self.fail()
        except LdbError as e22:
            (num, _) = e22.args
            self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)

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
        except LdbError as e23:
            (num, _) = e23.args
            self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)

        try:
            self.ldb.modify_ldif("""
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
        except LdbError as e24:
            (num, _) = e24.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

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
        except LdbError as e25:
            (num, _) = e25.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)

        try:
            self.ldb.modify_ldif("""
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
        except LdbError as e26:
            (num, _) = e26.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

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
        except LdbError as e27:
            (num, _) = e27.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)

        try:
            self.ldb.modify_ldif("""
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
        except LdbError as e28:
            (num, _) = e28.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

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
        except LdbError as e29:
            (num, _) = e29.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)

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
unicodePwd:: """ + base64.b64encode("\"thatsAcomplPASS3\"".encode('utf-16-le')).decode('utf8') + """
""")
            # this passes against s4
        except LdbError as e30:
            (num, _) = e30.args
            self.assertEqual(num, ERR_ATTRIBUTE_OR_VALUE_EXISTS)

        try:
            self.ldb2.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
delete: unicodePwd
unicodePwd:: """ + base64.b64encode("\"thatsAcomplPASS3\"".encode('utf-16-le')).decode('utf8') + """
add: userPassword
userPassword: thatsAcomplPASS4
""")
            # this passes against s4
        except LdbError as e31:
            (num, _) = e31.args
            self.assertEqual(num, ERR_NO_SUCH_ATTRIBUTE)

        # Several password changes at once are allowed
        self.ldb.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
replace: userPassword
userPassword: thatsAcomplPASS1
userPassword: thatsAcomplPASS2
""")

        # Several password changes at once are allowed
        self.ldb.modify_ldif("""
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
        delete_force(self.ldb, "cn=testuser2,cn=users," + self.base_dn)
        self.ldb.add({
             "dn": "cn=testuser2,cn=users," + self.base_dn,
             "objectclass": "user",
             "userPassword": ["thatsAcomplPASS1", "thatsAcomplPASS2"]})

        # This surprisingly should work
        delete_force(self.ldb, "cn=testuser2,cn=users," + self.base_dn)
        self.ldb.add({
             "dn": "cn=testuser2,cn=users," + self.base_dn,
             "objectclass": "user",
             "userPassword": ["thatsAcomplPASS1", "thatsAcomplPASS1"]})

    def test_empty_passwords(self):
        print("Performs some empty passwords testing")

        try:
            self.ldb.add({
                 "dn": "cn=testuser2,cn=users," + self.base_dn,
                 "objectclass": "user",
                 "unicodePwd": []})
            self.fail()
        except LdbError as e32:
            (num, _) = e32.args
            self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)

        try:
            self.ldb.add({
                 "dn": "cn=testuser2,cn=users," + self.base_dn,
                 "objectclass": "user",
                 "dBCSPwd": []})
            self.fail()
        except LdbError as e33:
            (num, _) = e33.args
            self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)

        try:
            self.ldb.add({
                 "dn": "cn=testuser2,cn=users," + self.base_dn,
                 "objectclass": "user",
                 "userPassword": []})
            self.fail()
        except LdbError as e34:
            (num, _) = e34.args
            self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)

        try:
            self.ldb.add({
                 "dn": "cn=testuser2,cn=users," + self.base_dn,
                 "objectclass": "user",
                 "clearTextPassword": []})
            self.fail()
        except LdbError as e35:
            (num, _) = e35.args
            self.assertTrue(num == ERR_CONSTRAINT_VIOLATION or
                            num == ERR_NO_SUCH_ATTRIBUTE)  # for Windows

        delete_force(self.ldb, "cn=testuser2,cn=users," + self.base_dn)

        m = Message()
        m.dn = Dn(self.ldb, "cn=testuser,cn=users," + self.base_dn)
        m["unicodePwd"] = MessageElement([], FLAG_MOD_ADD, "unicodePwd")
        try:
            self.ldb.modify(m)
            self.fail()
        except LdbError as e36:
            (num, _) = e36.args
            self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)

        m = Message()
        m.dn = Dn(self.ldb, "cn=testuser,cn=users," + self.base_dn)
        m["dBCSPwd"] = MessageElement([], FLAG_MOD_ADD, "dBCSPwd")
        try:
            self.ldb.modify(m)
            self.fail()
        except LdbError as e37:
            (num, _) = e37.args
            self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)

        m = Message()
        m.dn = Dn(self.ldb, "cn=testuser,cn=users," + self.base_dn)
        m["userPassword"] = MessageElement([], FLAG_MOD_ADD, "userPassword")
        try:
            self.ldb.modify(m)
            self.fail()
        except LdbError as e38:
            (num, _) = e38.args
            self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)

        m = Message()
        m.dn = Dn(self.ldb, "cn=testuser,cn=users," + self.base_dn)
        m["clearTextPassword"] = MessageElement([], FLAG_MOD_ADD, "clearTextPassword")
        try:
            self.ldb.modify(m)
            self.fail()
        except LdbError as e39:
            (num, _) = e39.args
            self.assertTrue(num == ERR_CONSTRAINT_VIOLATION or
                            num == ERR_NO_SUCH_ATTRIBUTE)  # for Windows

        m = Message()
        m.dn = Dn(self.ldb, "cn=testuser,cn=users," + self.base_dn)
        m["unicodePwd"] = MessageElement([], FLAG_MOD_REPLACE, "unicodePwd")
        try:
            self.ldb.modify(m)
            self.fail()
        except LdbError as e40:
            (num, _) = e40.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        m = Message()
        m.dn = Dn(self.ldb, "cn=testuser,cn=users," + self.base_dn)
        m["dBCSPwd"] = MessageElement([], FLAG_MOD_REPLACE, "dBCSPwd")
        try:
            self.ldb.modify(m)
            self.fail()
        except LdbError as e41:
            (num, _) = e41.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        m = Message()
        m.dn = Dn(self.ldb, "cn=testuser,cn=users," + self.base_dn)
        m["userPassword"] = MessageElement([], FLAG_MOD_REPLACE, "userPassword")
        try:
            self.ldb.modify(m)
            self.fail()
        except LdbError as e42:
            (num, _) = e42.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        m = Message()
        m.dn = Dn(self.ldb, "cn=testuser,cn=users," + self.base_dn)
        m["clearTextPassword"] = MessageElement([], FLAG_MOD_REPLACE, "clearTextPassword")
        try:
            self.ldb.modify(m)
            self.fail()
        except LdbError as e43:
            (num, _) = e43.args
            self.assertTrue(num == ERR_UNWILLING_TO_PERFORM or
                            num == ERR_NO_SUCH_ATTRIBUTE)  # for Windows

        m = Message()
        m.dn = Dn(self.ldb, "cn=testuser,cn=users," + self.base_dn)
        m["unicodePwd"] = MessageElement([], FLAG_MOD_DELETE, "unicodePwd")
        try:
            self.ldb.modify(m)
            self.fail()
        except LdbError as e44:
            (num, _) = e44.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        m = Message()
        m.dn = Dn(self.ldb, "cn=testuser,cn=users," + self.base_dn)
        m["dBCSPwd"] = MessageElement([], FLAG_MOD_DELETE, "dBCSPwd")
        try:
            self.ldb.modify(m)
            self.fail()
        except LdbError as e45:
            (num, _) = e45.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        m = Message()
        m.dn = Dn(self.ldb, "cn=testuser,cn=users," + self.base_dn)
        m["userPassword"] = MessageElement([], FLAG_MOD_DELETE, "userPassword")
        try:
            self.ldb.modify(m)
            self.fail()
        except LdbError as e46:
            (num, _) = e46.args
            self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)

        m = Message()
        m.dn = Dn(self.ldb, "cn=testuser,cn=users," + self.base_dn)
        m["clearTextPassword"] = MessageElement([], FLAG_MOD_DELETE, "clearTextPassword")
        try:
            self.ldb.modify(m)
            self.fail()
        except LdbError as e47:
            (num, _) = e47.args
            self.assertTrue(num == ERR_CONSTRAINT_VIOLATION or
                            num == ERR_NO_SUCH_ATTRIBUTE)  # for Windows

    def test_plain_userPassword(self):
        print("Performs testing about the standard 'userPassword' behaviour")

        # Delete the "dSHeuristics"
        self.ldb.set_dsheuristics(None)

        time.sleep(1)  # This switching time is strictly needed!

        m = Message()
        m.dn = Dn(self.ldb, "cn=testuser,cn=users," + self.base_dn)
        m["userPassword"] = MessageElement("myPassword", FLAG_MOD_ADD,
                                           "userPassword")
        self.ldb.modify(m)

        res = self.ldb.search("cn=testuser,cn=users," + self.base_dn,
                              scope=SCOPE_BASE, attrs=["userPassword"])
        self.assertTrue(len(res) == 1)
        self.assertTrue("userPassword" in res[0])
        self.assertEqual(str(res[0]["userPassword"][0]), "myPassword")

        m = Message()
        m.dn = Dn(self.ldb, "cn=testuser,cn=users," + self.base_dn)
        m["userPassword"] = MessageElement("myPassword2", FLAG_MOD_REPLACE,
                                           "userPassword")
        self.ldb.modify(m)

        res = self.ldb.search("cn=testuser,cn=users," + self.base_dn,
                              scope=SCOPE_BASE, attrs=["userPassword"])
        self.assertTrue(len(res) == 1)
        self.assertTrue("userPassword" in res[0])
        self.assertEqual(str(res[0]["userPassword"][0]), "myPassword2")

        m = Message()
        m.dn = Dn(self.ldb, "cn=testuser,cn=users," + self.base_dn)
        m["userPassword"] = MessageElement([], FLAG_MOD_DELETE,
                                           "userPassword")
        self.ldb.modify(m)

        res = self.ldb.search("cn=testuser,cn=users," + self.base_dn,
                              scope=SCOPE_BASE, attrs=["userPassword"])
        self.assertTrue(len(res) == 1)
        self.assertFalse("userPassword" in res[0])

        # Set the test "dSHeuristics" to deactivate "userPassword" pwd changes
        self.ldb.set_dsheuristics("000000000")

        m = Message()
        m.dn = Dn(self.ldb, "cn=testuser,cn=users," + self.base_dn)
        m["userPassword"] = MessageElement("myPassword3", FLAG_MOD_REPLACE,
                                           "userPassword")
        self.ldb.modify(m)

        res = self.ldb.search("cn=testuser,cn=users," + self.base_dn,
                              scope=SCOPE_BASE, attrs=["userPassword"])
        self.assertTrue(len(res) == 1)
        self.assertTrue("userPassword" in res[0])
        self.assertEqual(str(res[0]["userPassword"][0]), "myPassword3")

        # Set the test "dSHeuristics" to deactivate "userPassword" pwd changes
        self.ldb.set_dsheuristics("000000002")

        m = Message()
        m.dn = Dn(self.ldb, "cn=testuser,cn=users," + self.base_dn)
        m["userPassword"] = MessageElement("myPassword4", FLAG_MOD_REPLACE,
                                           "userPassword")
        self.ldb.modify(m)

        res = self.ldb.search("cn=testuser,cn=users," + self.base_dn,
                              scope=SCOPE_BASE, attrs=["userPassword"])
        self.assertTrue(len(res) == 1)
        self.assertTrue("userPassword" in res[0])
        self.assertEqual(str(res[0]["userPassword"][0]), "myPassword4")

        # Reset the test "dSHeuristics" (reactivate "userPassword" pwd changes)
        self.ldb.set_dsheuristics("000000001")

    def test_modify_dsheuristics_userPassword(self):
        print("Performs testing about reading userPassword between dsHeuristic modifies")

        # Make sure userPassword cannot be read
        self.ldb.set_dsheuristics("000000000")

        # Open a new connection (with dsHeuristic=000000000)
        ldb1 = SamDB(url=host, session_info=system_session(lp),
                     credentials=creds, lp=lp)

        # Set userPassword to be read
        # This setting only affects newer connections (ldb2)
        ldb1.set_dsheuristics("000000001")
        time.sleep(1)

        m = Message()
        m.dn = Dn(ldb1, "cn=testuser,cn=users," + self.base_dn)
        m["userPassword"] = MessageElement("thatsAcomplPASS1", FLAG_MOD_REPLACE,
                                           "userPassword")
        ldb1.modify(m)

        res = ldb1.search("cn=testuser,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["userPassword"])

        # userPassword cannot be read, it wasn't set, instead the
        # password was
        self.assertTrue(len(res) == 1)
        self.assertFalse("userPassword" in res[0])

        # Open another new connection (with dsHeuristic=000000001)
        ldb2 = SamDB(url=host, session_info=system_session(lp),
                     credentials=creds, lp=lp)

        res = ldb2.search("cn=testuser,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["userPassword"])

        # Check on the new connection that userPassword was not stored
        # from ldb1 or is not readable
        self.assertTrue(len(res) == 1)
        self.assertFalse("userPassword" in res[0])

        # Set userPassword to be readable
        # This setting does not affect this connection
        ldb2.set_dsheuristics("000000000")
        time.sleep(1)

        res = ldb2.search("cn=testuser,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["userPassword"])

        # Check that userPassword was not stored from ldb1
        self.assertTrue(len(res) == 1)
        self.assertFalse("userPassword" in res[0])

        m = Message()
        m.dn = Dn(ldb2, "cn=testuser,cn=users," + self.base_dn)
        m["userPassword"] = MessageElement("thatsAcomplPASS2", FLAG_MOD_REPLACE,
                                           "userPassword")
        ldb2.modify(m)

        res = ldb2.search("cn=testuser,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["userPassword"])

        # Check despite setting it with userPassword support disabled
        # on this connection it should still not be readable
        self.assertTrue(len(res) == 1)
        self.assertFalse("userPassword" in res[0])

        # Only password from ldb1 is the user's password
        creds2 = Credentials()
        creds2.set_username("testuser")
        creds2.set_password("thatsAcomplPASS1")
        creds2.set_domain(creds.get_domain())
        creds2.set_realm(creds.get_realm())
        creds2.set_workstation(creds.get_workstation())
        creds2.set_gensec_features(creds2.get_gensec_features()
                                   | gensec.FEATURE_SEAL)

        try:
            SamDB(url=host, credentials=creds2, lp=lp)
        except:
            self.fail("testuser used the wrong password")

        ldb3 = SamDB(url=host, session_info=system_session(lp),
                     credentials=creds, lp=lp)

        # Check that userPassword was stored from ldb2
        res = ldb3.search("cn=testuser,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["userPassword"])

        # userPassword can be read
        self.assertTrue(len(res) == 1)
        self.assertTrue("userPassword" in res[0])
        self.assertEqual(str(res[0]["userPassword"][0]), "thatsAcomplPASS2")

        # Reset the test "dSHeuristics" (reactivate "userPassword" pwd changes)
        self.ldb.set_dsheuristics("000000001")

        ldb4 = SamDB(url=host, session_info=system_session(lp),
                     credentials=creds, lp=lp)

        # Check that userPassword that was stored from ldb2
        res = ldb4.search("cn=testuser,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["userPassword"])

        # userPassword can be not be read
        self.assertTrue(len(res) == 1)
        self.assertFalse("userPassword" in res[0])

    def test_zero_length(self):
        # Get the old "minPwdLength"
        minPwdLength = self.ldb.get_minPwdLength()
        # Set it temporarely to "0"
        self.ldb.set_minPwdLength("0")

        # Get the old "pwdProperties"
        pwdProperties = self.ldb.get_pwdProperties()
        # Set them temporarely to "0" (to deactivate eventually the complexity)
        self.ldb.set_pwdProperties("0")

        self.ldb.setpassword("(sAMAccountName=testuser)", "")

        # Reset the "pwdProperties" as they were before
        self.ldb.set_pwdProperties(pwdProperties)

        # Reset the "minPwdLength" as it was before
        self.ldb.set_minPwdLength(minPwdLength)

    def test_pw_change_delete_no_value_userPassword(self):
        """Test password change with userPassword where the delete attribute doesn't have a value"""

        try:
            self.ldb2.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
delete: userPassword
add: userPassword
userPassword: thatsAcomplPASS1
""")
        except LdbError as e:
            (num, msg) = e.args
            self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)
        else:
            self.fail()

    def test_pw_change_delete_no_value_clearTextPassword(self):
        """Test password change with clearTextPassword where the delete attribute doesn't have a value"""

        try:
            self.ldb2.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
delete: clearTextPassword
add: clearTextPassword
clearTextPassword: thatsAcomplPASS2
""")
        except LdbError as e:
            (num, msg) = e.args
            self.assertTrue(num == ERR_CONSTRAINT_VIOLATION or
                            num == ERR_NO_SUCH_ATTRIBUTE)  # for Windows
        else:
            self.fail()

    def test_pw_change_delete_no_value_unicodePwd(self):
        """Test password change with unicodePwd where the delete attribute doesn't have a value"""

        try:
            self.ldb2.modify_ldif("""
dn: cn=testuser,cn=users,""" + self.base_dn + """
changetype: modify
delete: unicodePwd
add: unicodePwd
unicodePwd:: """ + base64.b64encode("\"thatsAcomplPASS3\"".encode('utf-16-le')).decode('utf8') + """
""")
        except LdbError as e:
            (num, msg) = e.args
            self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)
        else:
            self.fail()

    def tearDown(self):
        super(PasswordTests, self).tearDown()
        delete_force(self.ldb, "cn=testuser,cn=users," + self.base_dn)
        delete_force(self.ldb, "cn=testuser2,cn=users," + self.base_dn)
        # Close the second LDB connection (with the user credentials)
        self.ldb2 = None


if "://" not in host:
    if os.path.isfile(host):
        host = "tdb://%s" % host
    else:
        host = "ldap://%s" % host

TestProgram(module=__name__, opts=subunitopts)
