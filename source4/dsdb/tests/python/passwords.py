#!/usr/bin/env python3
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
import time
import os

sys.path.insert(0, "bin/python")

from samba.tests.subunitrun import SubunitOptions, TestProgram
from samba.tests.password_test import PasswordTestCase

import samba.getopt as options

from samba.auth import system_session
from samba.credentials import Credentials
from samba.dcerpc import security
from samba.dcerpc.samr import DOMAIN_PASSWORD_COMPLEX
from samba.hresult import HRES_SEC_E_INVALID_TOKEN
from ldb import SCOPE_BASE, LdbError
from ldb import ERR_ATTRIBUTE_OR_VALUE_EXISTS
from ldb import ERR_UNWILLING_TO_PERFORM, ERR_INSUFFICIENT_ACCESS_RIGHTS
from ldb import ERR_NO_SUCH_ATTRIBUTE
from ldb import ERR_CONSTRAINT_VIOLATION
from ldb import ERR_INVALID_CREDENTIALS
from ldb import Message, MessageElement, Dn
from ldb import FLAG_MOD_ADD, FLAG_MOD_REPLACE, FLAG_MOD_DELETE
from samba import gensec, werror
from samba.samdb import SamDB
from samba.tests import delete_force

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
        self.creds = creds2

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

    def test_old_password_simple_bind(self):
        """Shows that we can log in with the immediate previous password, but not any earlier passwords."""

        user_dn_str = f'CN=testuser,CN=Users,{self.base_dn}'
        user_dn = Dn(self.ldb, user_dn_str)

        # Change the account password.
        m = Message(user_dn)
        m['0'] = MessageElement(self.creds.get_password(),
                                FLAG_MOD_DELETE, 'userPassword')
        m['1'] = MessageElement('Password#2',
                                FLAG_MOD_ADD, 'userPassword')
        self.ldb.modify(m)

        # Show we can still log in using the previous password.
        self.creds.set_bind_dn(user_dn_str)
        try:
            SamDB(url=host_ldaps,
                  credentials=self.creds, lp=lp)
        except LdbError:
            self.fail('failed to login with previous password!')

        # Change the account password a second time.
        m = Message(user_dn)
        m['0'] = MessageElement('Password#2',
                                FLAG_MOD_DELETE, 'userPassword')
        m['1'] = MessageElement('Password#3',
                                FLAG_MOD_ADD, 'userPassword')
        self.ldb.modify(m)

        # Show we can no longer log in using the original password.
        try:
            SamDB(url=host_ldaps,
                  credentials=self.creds, lp=lp)
        except LdbError as err:
            num, estr = err.args
            self.assertEqual(ERR_INVALID_CREDENTIALS, num)
            self.assertIn(f"{HRES_SEC_E_INVALID_TOKEN:08X}", estr)
        else:
            self.fail('should have failed to login with previous password!')

    def test_old_password_attempt_reuse(self):
        """Shows that we cannot reuse the original password after changing the password twice."""
        res = self.ldb.search(self.ldb.domain_dn(), scope=SCOPE_BASE,
                              attrs=['pwdHistoryLength'])

        history_len = int(res[0].get('pwdHistoryLength', idx=0))
        self.assertGreaterEqual(history_len, 3)

        user_dn_str = f'CN=testuser,CN=Users,{self.base_dn}'
        user_dn = Dn(self.ldb, user_dn_str)

        first_pwd = self.creds.get_password()
        previous_pwd = first_pwd

        for new_pwd in ['Password#0', 'Password#1']:
            # Change the account password.
            m = Message(user_dn)
            m['0'] = MessageElement(previous_pwd,
                                    FLAG_MOD_DELETE, 'userPassword')
            m['1'] = MessageElement(new_pwd,
                                    FLAG_MOD_ADD, 'userPassword')
            self.ldb.modify(m)

            # Show that the original password is in the history by trying to
            # set it as our new password.
            m = Message(user_dn)
            m['0'] = MessageElement(new_pwd,
                                    FLAG_MOD_DELETE, 'userPassword')
            m['1'] = MessageElement(first_pwd,
                                    FLAG_MOD_ADD, 'userPassword')
            try:
                self.ldb.modify(m)
            except LdbError as err:
                num, estr = err.args
                self.assertEqual(ERR_CONSTRAINT_VIOLATION, num)
                self.assertIn(f'{werror.WERR_PASSWORD_RESTRICTION:08X}', estr)
            else:
                self.fail('should not have been able to reuse password!')

            previous_pwd = new_pwd

    def test_old_password_rename_simple_bind(self):
        """Shows that we can log in with the previous password after renaming the account."""
        user_dn_str = f'CN=testuser,CN=Users,{self.base_dn}'
        user_dn = Dn(self.ldb, user_dn_str)

        # Change the account password.
        m = Message(user_dn)
        m['0'] = MessageElement(self.creds.get_password(),
                                FLAG_MOD_DELETE, 'userPassword')
        m['1'] = MessageElement('Password#2',
                                FLAG_MOD_ADD, 'userPassword')
        self.ldb.modify(m)

        # Show we can still log in using the previous password.
        self.creds.set_bind_dn(user_dn_str)
        try:
            SamDB(url=host_ldaps,
                  credentials=self.creds, lp=lp)
        except LdbError:
            self.fail('failed to login with previous password!')

        # Rename the account, causing the salt to change.
        m = Message(user_dn)
        m['1'] = MessageElement('testuser_2',
                                FLAG_MOD_REPLACE, 'sAMAccountName')
        self.ldb.modify(m)

        # Show that a simple bind can still be performed using the previous
        # password.
        self.creds.set_username('testuser_2')
        try:
            SamDB(url=host_ldaps,
                  credentials=self.creds, lp=lp)
        except LdbError:
            self.fail('failed to login with previous password!')

    def test_old_password_rename_simple_bind_2(self):
        """Shows that we can rename the account, change the password and log in with the previous password."""
        user_dn_str = f'CN=testuser,CN=Users,{self.base_dn}'
        user_dn = Dn(self.ldb, user_dn_str)

        # Rename the account, causing the salt to change.
        m = Message(user_dn)
        m['1'] = MessageElement('testuser_2',
                                FLAG_MOD_REPLACE, 'sAMAccountName')
        self.ldb.modify(m)

        # Change the account password, causing the new salt to be stored.
        m = Message(user_dn)
        m['0'] = MessageElement(self.creds.get_password(),
                                FLAG_MOD_DELETE, 'userPassword')
        m['1'] = MessageElement('Password#2',
                                FLAG_MOD_ADD, 'userPassword')
        self.ldb.modify(m)

        # Show that a simple bind can still be performed using the previous
        # password.
        self.creds.set_bind_dn(user_dn_str)
        self.creds.set_username('testuser_2')
        try:
            SamDB(url=host_ldaps,
                  credentials=self.creds, lp=lp)
        except LdbError:
            self.fail('failed to login with previous password!')

    def test_old_password_rename_attempt_reuse(self):
        """Shows that we cannot reuse the original password after renaming the account."""
        user_dn_str = f'CN=testuser,CN=Users,{self.base_dn}'
        user_dn = Dn(self.ldb, user_dn_str)

        # Change the account password.
        m = Message(user_dn)
        m['0'] = MessageElement(self.creds.get_password(),
                                FLAG_MOD_DELETE, 'userPassword')
        m['1'] = MessageElement('Password#2',
                                FLAG_MOD_ADD, 'userPassword')
        self.ldb.modify(m)

        # Show that the previous password is in the history by trying to set it
        # as our new password.
        m = Message(user_dn)
        m['0'] = MessageElement('Password#2',
                                FLAG_MOD_DELETE, 'userPassword')
        m['1'] = MessageElement(self.creds.get_password(),
                                FLAG_MOD_ADD, 'userPassword')
        try:
            self.ldb.modify(m)
        except LdbError as err:
            num, estr = err.args
            self.assertEqual(ERR_CONSTRAINT_VIOLATION, num)
            self.assertIn(f'{werror.WERR_PASSWORD_RESTRICTION:08X}', estr)
        else:
            self.fail('should not have been able to reuse password!')

        # Rename the account, causing the salt to change.
        m = Message(user_dn)
        m['1'] = MessageElement('testuser_2',
                                FLAG_MOD_REPLACE, 'sAMAccountName')
        self.ldb.modify(m)

        # Show that the previous password is still in the history by trying to
        # set it as our new password.
        m = Message(user_dn)
        m['0'] = MessageElement('Password#2',
                                FLAG_MOD_DELETE, 'userPassword')
        m['1'] = MessageElement(self.creds.get_password(),
                                FLAG_MOD_ADD, 'userPassword')
        try:
            self.ldb.modify(m)
        except LdbError as err:
            num, estr = err.args
            self.assertEqual(ERR_CONSTRAINT_VIOLATION, num)
            self.assertIn(f'{werror.WERR_PASSWORD_RESTRICTION:08X}', estr)
        else:
            self.fail('should not have been able to reuse password!')

    def test_old_password_rename_attempt_reuse_2(self):
        """Shows that we cannot reuse the original password after renaming the account and changing the password."""
        user_dn_str = f'CN=testuser,CN=Users,{self.base_dn}'
        user_dn = Dn(self.ldb, user_dn_str)

        # Rename the account, causing the salt to change.
        m = Message(user_dn)
        m['1'] = MessageElement('testuser_2',
                                FLAG_MOD_REPLACE, 'sAMAccountName')
        self.ldb.modify(m)

        # Change the account password, causing the new salt to be stored.
        m = Message(user_dn)
        m['0'] = MessageElement(self.creds.get_password(),
                                FLAG_MOD_DELETE, 'userPassword')
        m['1'] = MessageElement('Password#2',
                                FLAG_MOD_ADD, 'userPassword')
        self.ldb.modify(m)

        # Show that the previous password is in the history by trying to set it
        # as our new password.
        m = Message(user_dn)
        m['0'] = MessageElement('Password#2',
                                FLAG_MOD_DELETE, 'userPassword')
        m['1'] = MessageElement(self.creds.get_password(),
                                FLAG_MOD_ADD, 'userPassword')
        try:
            self.ldb.modify(m)
        except LdbError as err:
            num, estr = err.args
            self.assertEqual(ERR_CONSTRAINT_VIOLATION, num)
            self.assertIn(f'{werror.WERR_PASSWORD_RESTRICTION:08X}', estr)
        else:
            self.fail('should not have been able to reuse password!')

    def test_protected_unicodePwd_clear_set(self):
        """Performs a password cleartext set operation on 'unicodePwd' with the user in
the Protected Users group"""

        user_dn = f'cn=testuser,cn=users,{self.base_dn}'

        # Add the user to the Protected Users group.

        # Search for the Protected Users group.
        group_dn = Dn(self.ldb,
                      f'<SID={self.ldb.get_domain_sid()}-'
                      f'{security.DOMAIN_RID_PROTECTED_USERS}>')
        try:
            group_res = self.ldb.search(base=group_dn,
                                        scope=SCOPE_BASE,
                                        attrs=['member'])
        except LdbError as err:
            self.fail(err)

        # Add the user to the list of members.
        members = list(group_res[0].get('member', ()))
        members.append(user_dn)

        m = Message(group_dn)
        m['member'] = MessageElement(members,
                                     FLAG_MOD_REPLACE,
                                     'member')
        self.ldb.modify(m)

        m = Message()
        m.dn = Dn(self.ldb, user_dn)
        m['unicodePwd'] = MessageElement(
            '"thatsAcomplPASS2"'.encode('utf-16-le'),
            FLAG_MOD_REPLACE, 'unicodePwd')
        self.ldb.modify(m)

    def test_protected_unicodePwd_clear_change(self):
        """Performs a password cleartext change operation on 'unicodePwd' with the user
in the Protected Users group"""

        user_dn = f'cn=testuser,cn=users,{self.base_dn}'

        # Add the user to the Protected Users group.

        # Search for the Protected Users group.
        group_dn = Dn(self.ldb,
                      f'<SID={self.ldb.get_domain_sid()}-'
                      f'{security.DOMAIN_RID_PROTECTED_USERS}>')
        try:
            group_res = self.ldb.search(base=group_dn,
                                        scope=SCOPE_BASE,
                                        attrs=['member'])
        except LdbError as err:
            self.fail(err)

        # Add the user to the list of members.
        members = list(group_res[0].get('member', ()))
        members.append(user_dn)

        m = Message(group_dn)
        m['member'] = MessageElement(members,
                                     FLAG_MOD_REPLACE,
                                     'member')
        self.ldb.modify(m)

        self.ldb2.modify_ldif(f"""
dn: cn=testuser,cn=users,{self.base_dn}
changetype: modify
delete: unicodePwd
unicodePwd:: {base64.b64encode('"thatsAcomplPASS1"'.encode('utf-16-le'))
        .decode('utf8')}
add: unicodePwd
unicodePwd:: {base64.b64encode('"thatsAcomplPASS2"'.encode('utf-16-le'))
        .decode('utf8')}
""")

    @staticmethod
    def _upwd_encode(password):
        return base64.b64encode(f'"{password}"'.encode('utf-16-le')).decode('utf8')

    def _replace_unicode_pwd(self, ldb, old=None, new=None, controls=None):
        ldif = (f"dn: cn=testuser,cn=users,{self.base_dn}\n"
                "changetype: modify\n")
        if old is not None:
            # change
            ldif += ("delete: unicodePwd\n"
                     f"unicodePwd:: {self._upwd_encode(old)}\n"
                     "add: unicodePwd\n"
                     f"unicodePwd:: {self._upwd_encode(new)}\n")
        else:
            # reset
            ldif += ("replace: unicodePwd\n"
                     f"unicodePwd:: {self._upwd_encode(new)}\n")

        #print(ldif)
        ldb.modify_ldif(ldif, controls)

    def _set_pwd_properties(self, new_pwd_properties):
        """There is a race, noticeable on Windows, where pwdProperties
        will not change instantly. This function changes and polls
        until the change is noticed.
        """
        s = str(new_pwd_properties)
        for i in range(10):
            self.ldb.set_pwdProperties(s)
            pwd_properties = int(self.ldb.get_pwdProperties())
            if pwd_properties == new_pwd_properties:
                return pwd_properties
            time.sleep(0.1)

        print("pwdProperties failed to change")

    def _set_pwd_property_bits(self, bits_on=0, bits_off=0):
        old_pwd_properties = int(self.ldb.get_pwdProperties())
        new_pwd_properties = old_pwd_properties | bits_on
        new_pwd_properties &= ~bits_off
        return self._set_pwd_properties(new_pwd_properties)

    def _test_unicodePwd_policy_hints_history(self, control):
        """Performs a password cleartext reset operation on
        'unicodePwd', but expect failure due to history, because the
        policy_hints control is set.

        We run this twice, once with "policy_hints", and once with
        "policy_hints_deprecated" -- both should work exactly the
        same.
        """
        self._replace_unicode_pwd(self.ldb2,
                                  "thatsAcomplPASS1",
                                  "thatsAcomplPASS2")

        # can't replace with same password, even with no nthash history (ad_dc_no_ntlm)
        with self.assertRaises(LdbError) as e:
            self._replace_unicode_pwd(self.ldb2,
                                      "thatsAcomplPASS2",
                                      "thatsAcomplPASS2")
        num, msg = e.exception.args
        self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)

        # An ADMIN reset to the old password will work, ignoring history.
        self._replace_unicode_pwd(self.ldb,
                                  None,
                                  "thatsAcomplPASS1")
        self._replace_unicode_pwd(self.ldb2,
                                  "thatsAcomplPASS1",
                                  "thatsAcomplPASS3")

        #self._replace_unicode_pwd(self.ldb,
        #                          None,
        #                          "thatsAcomplPASS2")
        # An Admin reset with policy hints works if password is new
        self._replace_unicode_pwd(self.ldb,
                                  None,
                                  "thatsAcomplPASS7",
                                  [f"{control}:1:1"])
        self._replace_unicode_pwd(self.ldb,
                                  None,
                                  "thatsAcomplPASS2")

        # User change with wrong old password will fail
        with self.assertRaises(LdbError) as e:
            self._replace_unicode_pwd(self.ldb2,
                                      "thatsAcomplPASS3",
                                      "thatsAcomplPASS4")

        num, msg = e.exception.args
        self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)

        # A reset to the old password again will not work, using ldb2,
        # which has the users credentials, because ordinary users
        # can't reset their own passwords.
        with self.assertRaises(LdbError) as e:
            self._replace_unicode_pwd(self.ldb2,
                                      None,
                                      "thatsAcomplPASS1",
                                      [f"{control}:1:1"])
        num, msg = e.exception.args
        self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)

        res = self.ldb.search(self.ldb.domain_dn(), scope=SCOPE_BASE,
                              attrs=['pwdHistoryLength'])

        history_len = int(res[0].get('pwdHistoryLength', idx=0))

        if history_len < 2:
            # We CAN switch to the old password if we have no history
            # (as found on fl2003dc)
            self._replace_unicode_pwd(self.ldb,
                                      None,
                                      "thatsAcomplPASS1",
                                      [f"{control}:1:1"])
            return

        # An ADMIN reset to the *current* password will not work, if
        # we give it the policy hints oid.
        with self.assertRaises(LdbError) as e:
            self._replace_unicode_pwd(self.ldb,
                                      None,
                                      "thatsAcomplPASS3",
                                      [f"{control}:1:1"])
        num, msg = e.exception.args
        self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        # An ADMIN reset to the old password again will not work, if
        # we give it the policy hints oid.
        #
        # This is a knownfail on ad_dc_no_ntlm, because password_hash
        # module needs the ntlm hash to compare.
        with self.assertRaises(LdbError) as e:
            self._replace_unicode_pwd(self.ldb,
                                      None,
                                      "thatsAcomplPASS1",
                                      [f"{control}:1:1"])
        num, msg = e.exception.args
        self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        # An ADMIN reset to the old password will work, if
        # we give it the policy hints oid with a BAD VALUE.
        self._replace_unicode_pwd(self.ldb,
                                  None,
                                  "thatsAcomplPASS1",
                                  [f"{control}:1:2"])

    def _test_unicodePwd_policy_hints_complexity(self, control):
        """Performs a password cleartext reset operation on
        'unicodePwd', but expect failure due to history, because the
        policy_hints control is set.

        We run this twice, once with "policy_hints", and once with
        "policy_hints_deprecated" -- both should work exactly the
        same.
        """
        # Now we are testing complexity constraints
        # the policy hints control should allow them to be ignored.
        # NOTE there is a race here.
        old_pwd_properties = self._set_pwd_property_bits(DOMAIN_PASSWORD_COMPLEX)
        self.addCleanup(self._set_pwd_properties, old_pwd_properties)

        # ensure complexity constraints work
        with self.assertRaises(LdbError) as e:
            self._replace_unicode_pwd(self.ldb2,
                                      "thatsAcomplPASS1",
                                      "ooooooooooooooo")

        num, msg = e.exception.args
        self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)

        # reset with control should not work
        with self.assertRaises(LdbError) as e:
            self._replace_unicode_pwd(self.ldb,
                                      None,
                                      "ooooooooooooooo",
                                      [f"{control}:1:1"])
        num, msg = e.exception.args
        self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        # reset with no control will not work either!
        with self.assertRaises(LdbError) as e:
            self._replace_unicode_pwd(self.ldb,
                                      None,
                                      "ooooooooooooooo")
        num, msg = e.exception.args
        self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        # Now we try with no complexity checks
        tmp_pwd_properties = old_pwd_properties & ~DOMAIN_PASSWORD_COMPLEX
        self._set_pwd_properties(tmp_pwd_properties)

        self._replace_unicode_pwd(self.ldb2,
                                  "thatsAcomplPASS1",
                                  "eeeeeeeeeeeeeee")

        # reset with control should work
        self._replace_unicode_pwd(self.ldb,
                                  None,
                                  "aaaaaaaaaaaaaaaa",
                                  [f"{control}:1:1"])

        # reset to complex password still works of course.
        self._replace_unicode_pwd(self.ldb,
                                  None,
                                  "thatsAnotherPass1")

    def _test_unicodePwd_policy_hints_length(self, control):
        """Test password cleartext reset operations on 'unicodePwd',
        mixing under-legth passwords and the policy hints control.
        """
        # try with a too short password
        old_min_length = self.ldb.get_minPwdLength()
        print(old_min_length)
        self.ldb.set_minPwdLength(8)
        with self.assertRaises(LdbError) as e:
            self._replace_unicode_pwd(self.ldb,
                                      None,
                                      "Short1*",
                                      [f"{control}:1:1"])
        num, msg = e.exception.args
        self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        # try it as a user change, which should fail the same way.
        with self.assertRaises(LdbError) as e:
            self._replace_unicode_pwd(self.ldb2,
                                      "thatsAcomplPASS1",
                                      "Short1*",
                                      [f"{control}:1:1"])
        num, msg = e.exception.args
        self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)

        with self.assertRaises(LdbError) as e:
            # reset without control should not work.
            self._replace_unicode_pwd(self.ldb,
                                      None,
                                      "Short1*")

        num, msg = e.exception.args
        self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        self.ldb.set_minPwdLength(old_min_length)
        self._replace_unicode_pwd(self.ldb,
                                  None,
                                  "LongLong1*2*3")

    def _test_unicodePwd_policy_hints_password_age(self, control):
        """We narrow password age limits to a narrow band and see if
        we can get a policy_hints control to make a difference.
        """
        # NOTE: we just ignore maxPwdAge in the password_hash module.

        old_min = self.ldb.get_minPwdAge()
        old_max = self.ldb.get_maxPwdAge()
        print(f"{old_min=}, {old_max=}")
        self.addCleanup(self.ldb.set_minPwdAge, old_min)
        self.addCleanup(self.ldb.set_maxPwdAge, old_max)

        self.ldb.set_minPwdAge(-2000000000)
        self.ldb.set_maxPwdAge(-2000000001)

        # as usual, constraint violation for user change,
        # unwillingness for admin reset with policy hints
        with self.assertRaises(LdbError) as e:
            self._replace_unicode_pwd(self.ldb,
                                      "thatsAcomplPASS1",
                                      "thatsAcomplPASS2")
        num, msg = e.exception.args
        self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)

        with self.assertRaises(LdbError) as e:
            self._replace_unicode_pwd(self.ldb,
                                      None,
                                      "thatsAcomplPASS2",
                                      [f"{control}:1:1"])
        num, msg = e.exception.args
        self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        # reset works with bad control value
        self._replace_unicode_pwd(self.ldb,
                                  None,
                                  "thatsAcomplPASS2",
                                  [f"{control}:1:0"])

    def test_unicodePwd_policy_hints_history(self):
        self._test_unicodePwd_policy_hints_history("policy_hints")

    def test_unicodePwd_policy_hints_deprecated_history(self):
        self._test_unicodePwd_policy_hints_history("policy_hints_deprecated")

    def test_unicodePwd_policy_hints_complexity(self):
        self._test_unicodePwd_policy_hints_complexity("policy_hints")

    # We don't need to run all of these twice, since we have shown
    # already that policy_hints and policy_hints_deprecated work the
    # same. Let's skip these ones:
    #
    # def test_unicodePwd_policy_hints_deprecated_complexity(self):
    # def test_unicodePwd_policy_hints_length(self):
    # def test_unicodePwd_policy_hints_password_age(self):

    def test_unicodePwd_policy_hints_deprecated_length(self):
        self._test_unicodePwd_policy_hints_length("policy_hints_deprecated")

    def test_unicodePwd_policy_hints_deprecated_password_age(self):
        self._test_unicodePwd_policy_hints_password_age("policy_hints_deprecated")

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
        # Set it temporarily to "0"
        self.ldb.set_minPwdLength("0")

        # Get the old "pwdProperties"
        pwdProperties = self.ldb.get_pwdProperties()
        # Set them temporarily to "0" (to deactivate eventually the complexity)
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
        host_ldaps = None
        host = "tdb://%s" % host
    else:
        host_ldaps = "ldaps://%s" % host
        host = "ldap://%s" % host
elif host.startswith('ldap://'):
    host_ldaps = f"ldaps://{host[7:]}"
elif host.startswith('ldaps://'):
    host_ldaps = host
    host = f"ldap://{host[8:]}"
else:
    host_ldaps = None


TestProgram(module=__name__, opts=subunitopts)
