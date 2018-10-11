# Unix SMB/CIFS implementation.
# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007
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

"""Tests for the Credentials Python bindings.

Note that this just tests the bindings work. It does not intend to test
the functionality, that's already done in other tests.
"""

from samba import credentials
import samba.tests
import os
import binascii
from samba.compat import PY3
from samba.dcerpc import misc


class CredentialsTests(samba.tests.TestCaseInTempDir):

    def setUp(self):
        super(CredentialsTests, self).setUp()
        self.creds = credentials.Credentials()
        if PY3:
            # Because Python 2 does not support 'x' mode and Python 3
            # does not support 'wx' mode in open() function
            # for exclusive creation
            self.open_mode = 'x'
        else:
            self.open_mode = 'wx'

    def test_set_username(self):
        self.creds.set_username("somebody")
        self.assertEqual("somebody", self.creds.get_username())

    def test_set_password(self):
        self.creds.set_password("S3CreT")
        self.assertEqual("S3CreT", self.creds.get_password())

    def test_set_utf16_password(self):
        password = 'S3cRet'
        passbytes = password.encode('utf-16-le')
        self.assertTrue(self.creds.set_utf16_password(passbytes))
        self.assertEqual(password, self.creds.get_password())

    def test_set_old_password(self):
        self.assertEqual(None, self.creds.get_old_password())
        self.assertTrue(self.creds.set_old_password("S3c0ndS3CreT"))
        self.assertEqual("S3c0ndS3CreT", self.creds.get_old_password())

    def test_set_old_utf16_password(self):
        password = '0ldS3cRet'
        passbytes = password.encode('utf-16-le')
        self.assertTrue(self.creds.set_old_utf16_password(passbytes))
        self.assertEqual(password, self.creds.get_old_password())

    def test_set_domain(self):
        self.creds.set_domain("ABMAS")
        self.assertEqual("ABMAS", self.creds.get_domain())
        self.assertEqual(self.creds.get_principal(), None)

    def test_set_realm(self):
        self.creds.set_realm("myrealm")
        self.assertEqual("MYREALM", self.creds.get_realm())
        self.assertEqual(self.creds.get_principal(), None)

    def test_parse_string_anon(self):
        self.creds.parse_string("%")
        self.assertEqual("", self.creds.get_username())
        self.assertEqual(None, self.creds.get_password())

    def test_parse_string_empty_pw(self):
        self.creds.parse_string("someone%")
        self.assertEqual("someone", self.creds.get_username())
        self.assertEqual("", self.creds.get_password())

    def test_parse_string_none_pw(self):
        self.creds.parse_string("someone")
        self.assertEqual("someone", self.creds.get_username())
        self.assertEqual(None, self.creds.get_password())

    def test_parse_string_user_pw_domain(self):
        self.creds.parse_string("dom\\someone%secr")
        self.assertEqual("someone", self.creds.get_username())
        self.assertEqual("secr", self.creds.get_password())
        self.assertEqual("DOM", self.creds.get_domain())

    def test_bind_dn(self):
        self.assertEqual(None, self.creds.get_bind_dn())
        self.creds.set_bind_dn("dc=foo,cn=bar")
        self.assertEqual("dc=foo,cn=bar", self.creds.get_bind_dn())

    def test_is_anon(self):
        self.creds.set_username("")
        self.assertTrue(self.creds.is_anonymous())
        self.creds.set_username("somebody")
        self.assertFalse(self.creds.is_anonymous())
        self.creds.set_anonymous()
        self.assertTrue(self.creds.is_anonymous())

    def test_workstation(self):
        # FIXME: This is uninitialised, it should be None
        #self.assertEqual(None, self.creds.get_workstation())
        self.creds.set_workstation("myworksta")
        self.assertEqual("myworksta", self.creds.get_workstation())

    def test_secure_channel_type(self):
        self.assertEqual(misc.SEC_CHAN_NULL,
                         self.creds.get_secure_channel_type())
        self.creds.set_secure_channel_type(misc.SEC_CHAN_BDC)
        self.assertEqual(misc.SEC_CHAN_BDC,
                         self.creds.get_secure_channel_type())

    def test_get_nt_hash(self):
        password = "geheim"
        hex_nthash = "c2ae1fe6e648846352453e816f2aeb93"
        self.creds.set_password(password)
        self.assertEqual(password, self.creds.get_password())
        self.assertEqual(binascii.a2b_hex(hex_nthash),
                         self.creds.get_nt_hash())

    def test_get_ntlm_response(self):
        password = "SecREt01"
        hex_challenge = "0123456789abcdef"
        hex_nthash = "cd06ca7c7e10c99b1d33b7485a2ed808"
        hex_session_key = "3f373ea8e4af954f14faa506f8eebdc4"
        hex_ntlm_response = "25a98c1c31e81847466b29b2df4680f39958fb8c213a9cc6"
        self.creds.set_username("fred")
        self.creds.set_domain("nurk")
        self.creds.set_password(password)
        self.assertEqual(password, self.creds.get_password())
        self.assertEqual(binascii.a2b_hex(hex_nthash),
                         self.creds.get_nt_hash())
        response = self.creds.get_ntlm_response(flags=credentials.CLI_CRED_NTLM_AUTH,
                                                challenge=binascii.a2b_hex(hex_challenge))

        self.assertEqual(response["nt_response"], binascii.a2b_hex(hex_ntlm_response))
        self.assertEqual(response["nt_session_key"], binascii.a2b_hex(hex_session_key))
        self.assertEqual(response["flags"], credentials.CLI_CRED_NTLM_AUTH)

    def test_get_nt_hash_string(self):
        self.creds.set_password_will_be_nt_hash(True)
        hex_nthash = "c2ae1fe6e648846352453e816f2aeb93"
        self.creds.set_password(hex_nthash)
        self.assertEqual(None, self.creds.get_password())
        self.assertEqual(binascii.a2b_hex(hex_nthash),
                         self.creds.get_nt_hash())

    def test_set_cmdline_callbacks(self):
        self.creds.set_cmdline_callbacks()

    def test_authentication_requested(self):
        self.creds.set_username("")
        self.assertFalse(self.creds.authentication_requested())
        self.creds.set_username("somebody")
        self.assertTrue(self.creds.authentication_requested())

    def test_wrong_password(self):
        self.assertFalse(self.creds.wrong_password())

    def test_guess(self):
        creds = credentials.Credentials()
        lp = samba.tests.env_loadparm()
        os.environ["USER"] = "env_user"
        creds.guess(lp)
        self.assertEqual(creds.get_username(), "env_user")
        self.assertEqual(creds.get_domain(), lp.get("workgroup").upper())
        self.assertEqual(creds.get_realm(), None)
        self.assertEqual(creds.get_principal(), "env_user@%s" % creds.get_domain())
        self.assertEqual(creds.is_anonymous(), False)
        self.assertEqual(creds.authentication_requested(), False)

    def test_set_anonymous(self):
        creds = credentials.Credentials()
        lp = samba.tests.env_loadparm()
        os.environ["USER"] = "env_user"
        creds.guess(lp)
        creds.set_anonymous()
        self.assertEqual(creds.get_username(), "")
        self.assertEqual(creds.get_domain(), "")
        self.assertEqual(creds.get_realm(), None)
        self.assertEqual(creds.get_principal(), None)
        self.assertEqual(creds.is_anonymous(), True)
        self.assertEqual(creds.authentication_requested(), False)

    def test_parse_file_1(self):
        realm = "realm.example.com"
        domain = "dom"
        password = "pass"
        username = "user"

        passwd_file_name = os.path.join(self.tempdir, "parse_file")
        passwd_file_fd = open(passwd_file_name, self.open_mode)
        passwd_file_fd.write("realm=%s\n" % realm)
        passwd_file_fd.write("domain=%s\n" % domain)
        passwd_file_fd.write("username=%s\n" % username)
        passwd_file_fd.write("password=%s\n" % password)
        passwd_file_fd.close()
        self.creds.parse_file(passwd_file_name)
        self.assertEqual(self.creds.get_username(), username)
        self.assertEqual(self.creds.get_password(), password)
        self.assertEqual(self.creds.get_domain(), domain.upper())
        self.assertEqual(self.creds.get_realm(), realm.upper())
        self.assertEqual(self.creds.get_principal(), "%s@%s" % (username, realm.upper()))
        self.assertEqual(self.creds.is_anonymous(), False)
        self.assertEqual(self.creds.authentication_requested(), True)
        os.unlink(passwd_file_name)

    def test_parse_file_2(self):
        realm = "realm.example.com"
        domain = "dom"
        password = "pass"
        username = "user"

        passwd_file_name = os.path.join(self.tempdir, "parse_file")
        passwd_file_fd = open(passwd_file_name, self.open_mode)
        passwd_file_fd.write("realm=%s\n" % realm)
        passwd_file_fd.write("domain=%s\n" % domain)
        passwd_file_fd.write("username=%s\\%s\n" % (domain, username))
        passwd_file_fd.write("password=%s\n" % password)
        passwd_file_fd.close()
        self.creds.parse_file(passwd_file_name)
        self.assertEqual(self.creds.get_username(), username)
        self.assertEqual(self.creds.get_password(), password)
        self.assertEqual(self.creds.get_domain(), domain.upper())
        self.assertEqual(self.creds.get_realm(), realm.upper())
        self.assertEqual(self.creds.get_principal(), "%s@%s" % (username, realm.upper()))
        self.assertEqual(self.creds.is_anonymous(), False)
        self.assertEqual(self.creds.authentication_requested(), True)
        os.unlink(passwd_file_name)

    def test_parse_file_3(self):
        realm = "realm.example.com"
        domain = "domain"
        password = "password"
        username = "username"

        userdom = "userdom"

        passwd_file_name = os.path.join(self.tempdir, "parse_file")
        passwd_file_fd = open(passwd_file_name, self.open_mode)
        passwd_file_fd.write("realm=%s\n" % realm)
        passwd_file_fd.write("domain=%s\n" % domain)
        passwd_file_fd.write("username=%s/%s\n" % (userdom, username))
        passwd_file_fd.write("password=%s\n" % password)
        passwd_file_fd.close()
        self.creds.parse_file(passwd_file_name)
        self.assertEqual(self.creds.get_username(), username)
        self.assertEqual(self.creds.get_password(), password)
        self.assertEqual(self.creds.get_domain(), userdom.upper())
        self.assertEqual(self.creds.get_realm(), userdom.upper())
        self.assertEqual(self.creds.get_principal(), "%s@%s" % (username, userdom.upper()))
        self.assertEqual(self.creds.is_anonymous(), False)
        self.assertEqual(self.creds.authentication_requested(), True)
        os.unlink(passwd_file_name)

    def test_parse_file_4(self):
        password = "password"
        username = "username"

        userdom = "userdom"

        passwd_file_name = os.path.join(self.tempdir, "parse_file")
        passwd_file_fd = open(passwd_file_name, self.open_mode)
        passwd_file_fd.write("username=%s\\%s%%%s\n" % (userdom, username, password))
        passwd_file_fd.write("realm=ignorerealm\n")
        passwd_file_fd.write("domain=ignoredomain\n")
        passwd_file_fd.write("password=ignorepassword\n")
        passwd_file_fd.close()
        self.creds.parse_file(passwd_file_name)
        self.assertEqual(self.creds.get_username(), username)
        self.assertEqual(self.creds.get_password(), password)
        self.assertEqual(self.creds.get_domain(), userdom.upper())
        self.assertEqual(self.creds.get_realm(), userdom.upper())
        self.assertEqual(self.creds.get_principal(), "%s@%s" % (username, userdom.upper()))
        self.assertEqual(self.creds.is_anonymous(), False)
        self.assertEqual(self.creds.authentication_requested(), True)
        os.unlink(passwd_file_name)

    def test_parse_file_5(self):
        password = "password"
        username = "username"

        userdom = "userdom"

        passwd_file_name = os.path.join(self.tempdir, "parse_file")
        passwd_file_fd = open(passwd_file_name, self.open_mode)
        passwd_file_fd.write("realm=ignorerealm\n")
        passwd_file_fd.write("username=%s\\%s%%%s\n" % (userdom, username, password))
        passwd_file_fd.write("domain=ignoredomain\n")
        passwd_file_fd.write("password=ignorepassword\n")
        passwd_file_fd.close()
        self.creds.parse_file(passwd_file_name)
        self.assertEqual(self.creds.get_username(), username)
        self.assertEqual(self.creds.get_password(), password)
        self.assertEqual(self.creds.get_domain(), userdom.upper())
        self.assertEqual(self.creds.get_realm(), userdom.upper())
        self.assertEqual(self.creds.get_principal(), "%s@%s" % (username, userdom.upper()))
        self.assertEqual(self.creds.is_anonymous(), False)
        self.assertEqual(self.creds.authentication_requested(), True)
        os.unlink(passwd_file_name)

    def test_parse_username_0(self):
        creds = credentials.Credentials()
        lp = samba.tests.env_loadparm()
        os.environ["USER"] = "env_user"
        creds.guess(lp)
        creds.parse_string("user")
        self.assertEqual(creds.get_username(), "user")
        self.assertEqual(creds.get_domain(), lp.get("workgroup").upper())
        self.assertEqual(creds.get_realm(), None)
        self.assertEqual(creds.get_principal(), "user@%s" % lp.get("workgroup").upper())
        self.assertEqual(creds.is_anonymous(), False)
        self.assertEqual(creds.authentication_requested(), True)

    def test_parse_username_1(self):
        creds = credentials.Credentials()
        lp = samba.tests.env_loadparm()
        os.environ["USER"] = "env_user"
        creds.guess(lp)
        realm = "realm.example.com"
        creds.set_realm(realm, credentials.UNINITIALISED)
        creds.parse_string("user")
        self.assertEqual(creds.get_username(), "user")
        self.assertEqual(creds.get_domain(), lp.get("workgroup").upper())
        self.assertEqual(creds.get_realm(), realm.upper())
        self.assertEqual(creds.get_principal(), "user@%s" % realm.upper())
        self.assertEqual(creds.is_anonymous(), False)
        self.assertEqual(creds.authentication_requested(), True)

    def test_parse_username_with_domain_0(self):
        creds = credentials.Credentials()
        lp = samba.tests.env_loadparm()
        os.environ["USER"] = "env_user"
        creds.guess(lp)
        creds.parse_string("domain\\user")
        self.assertEqual(creds.get_username(), "user")
        self.assertEqual(creds.get_domain(), "DOMAIN")
        self.assertEqual(creds.get_realm(), None)
        self.assertEqual(creds.get_principal(), "user@DOMAIN")
        self.assertEqual(creds.is_anonymous(), False)
        self.assertEqual(creds.authentication_requested(), True)

    def test_parse_username_with_domain_1(self):
        creds = credentials.Credentials()
        lp = samba.tests.env_loadparm()
        os.environ["USER"] = "env_user"
        creds.guess(lp)
        realm = "realm.example.com"
        creds.set_realm(realm, credentials.UNINITIALISED)
        self.assertEqual(creds.get_username(), "env_user")
        self.assertEqual(creds.get_domain(), lp.get("workgroup").upper())
        self.assertEqual(creds.get_realm(), realm.upper())
        self.assertEqual(creds.get_principal(), "env_user@%s" % realm.upper())
        creds.set_principal("unknown@realm.example.com")
        self.assertEqual(creds.get_username(), "env_user")
        self.assertEqual(creds.get_domain(), lp.get("workgroup").upper())
        self.assertEqual(creds.get_realm(), realm.upper())
        self.assertEqual(creds.get_principal(), "unknown@realm.example.com")
        creds.parse_string("domain\\user")
        self.assertEqual(creds.get_username(), "user")
        self.assertEqual(creds.get_domain(), "DOMAIN")
        self.assertEqual(creds.get_realm(), realm.upper())
        self.assertEqual(creds.get_principal(), "user@DOMAIN")
        self.assertEqual(creds.is_anonymous(), False)
        self.assertEqual(creds.authentication_requested(), True)

    def test_parse_username_with_domain_2(self):
        creds = credentials.Credentials()
        lp = samba.tests.env_loadparm()
        os.environ["USER"] = "env_user"
        creds.guess(lp)
        realm = "realm.example.com"
        creds.set_realm(realm, credentials.SPECIFIED)
        self.assertEqual(creds.get_username(), "env_user")
        self.assertEqual(creds.get_domain(), lp.get("workgroup").upper())
        self.assertEqual(creds.get_realm(), realm.upper())
        self.assertEqual(creds.get_principal(), "env_user@%s" % realm.upper())
        creds.set_principal("unknown@realm.example.com")
        self.assertEqual(creds.get_username(), "env_user")
        self.assertEqual(creds.get_domain(), lp.get("workgroup").upper())
        self.assertEqual(creds.get_realm(), realm.upper())
        self.assertEqual(creds.get_principal(), "unknown@realm.example.com")
        creds.parse_string("domain\\user")
        self.assertEqual(creds.get_username(), "user")
        self.assertEqual(creds.get_domain(), "DOMAIN")
        self.assertEqual(creds.get_realm(), "DOMAIN")
        self.assertEqual(creds.get_principal(), "user@DOMAIN")
        self.assertEqual(creds.is_anonymous(), False)
        self.assertEqual(creds.authentication_requested(), True)

    def test_parse_username_with_realm(self):
        creds = credentials.Credentials()
        lp = samba.tests.env_loadparm()
        os.environ["USER"] = "env_user"
        creds.guess(lp)
        creds.parse_string("user@samba.org")
        self.assertEqual(creds.get_username(), "user@samba.org")
        self.assertEqual(creds.get_domain(), "")
        self.assertEqual(creds.get_realm(), "SAMBA.ORG")
        self.assertEqual(creds.get_principal(), "user@samba.org")
        self.assertEqual(creds.is_anonymous(), False)
        self.assertEqual(creds.authentication_requested(), True)

    def test_parse_username_pw(self):
        creds = credentials.Credentials()
        lp = samba.tests.env_loadparm()
        os.environ["USER"] = "env_user"
        creds.guess(lp)
        creds.parse_string("user%pass")
        self.assertEqual(creds.get_username(), "user")
        self.assertEqual(creds.get_password(), "pass")
        self.assertEqual(creds.get_domain(), lp.get("workgroup"))
        self.assertEqual(creds.get_realm(), None)
        self.assertEqual(creds.get_principal(), "user@%s" % lp.get("workgroup"))
        self.assertEqual(creds.is_anonymous(), False)
        self.assertEqual(creds.authentication_requested(), True)

    def test_parse_username_with_domain_pw(self):
        creds = credentials.Credentials()
        lp = samba.tests.env_loadparm()
        os.environ["USER"] = "env_user"
        creds.guess(lp)
        creds.parse_string("domain\\user%pass")
        self.assertEqual(creds.get_username(), "user")
        self.assertEqual(creds.get_domain(), "DOMAIN")
        self.assertEqual(creds.get_password(), "pass")
        self.assertEqual(creds.get_realm(), None)
        self.assertEqual(creds.get_principal(), "user@DOMAIN")
        self.assertEqual(creds.is_anonymous(), False)
        self.assertEqual(creds.authentication_requested(), True)

    def test_parse_username_with_realm_pw(self):
        creds = credentials.Credentials()
        lp = samba.tests.env_loadparm()
        os.environ["USER"] = "env_user"
        creds.guess(lp)
        creds.parse_string("user@samba.org%pass")
        self.assertEqual(creds.get_username(), "user@samba.org")
        self.assertEqual(creds.get_domain(), "")
        self.assertEqual(creds.get_password(), "pass")
        self.assertEqual(creds.get_realm(), "SAMBA.ORG")
        self.assertEqual(creds.get_principal(), "user@samba.org")
        self.assertEqual(creds.is_anonymous(), False)
        self.assertEqual(creds.authentication_requested(), True)
