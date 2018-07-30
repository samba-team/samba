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

"""Tests for the Auth Python bindings.

Note that this just tests the bindings work. It does not intend to test
the functionality, that's already done in other tests.
"""

from samba import auth
import samba.tests


class AuthSystemSessionTests(samba.tests.TestCase):

    def setUp(self):
        super(AuthSystemSessionTests, self).setUp()
        self.system_session = auth.system_session()
        self.lp = samba.tests.env_loadparm()

    def test_system_session_attrs(self):
        self.assertTrue(hasattr(self.system_session, 'credentials'))
        self.assertTrue(hasattr(self.system_session, 'info'))
        self.assertTrue(hasattr(self.system_session, 'security_token'))
        self.assertTrue(hasattr(self.system_session, 'session_key'))
        self.assertTrue(hasattr(self.system_session, 'torture'))

    def test_system_session_credentials(self):
        self.assertIsNone(self.system_session.credentials.get_bind_dn())
        self.assertIsNotNone(self.system_session.credentials.get_password())
        self.assertEqual(self.system_session.credentials.get_username(),
                         self.lp.get('netbios name').upper() + "$")

    def test_system_session_info(self):
        self.assertEqual(self.system_session.info.full_name, 'System')
        self.assertEqual(self.system_session.info.domain_name, 'NT AUTHORITY')
        self.assertEqual(self.system_session.info.account_name, 'SYSTEM')

    def test_system_session_session_key(self):
        expected = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        self.assertEqual(self.system_session.session_key, expected)

    def test_system_session_security_token(self):
        self.assertTrue(self.system_session.security_token.is_system())
        self.assertFalse(self.system_session.security_token.is_anonymous())


class AuthAdminSessionTests(samba.tests.TestCase):

    def setUp(self):
        super(AuthAdminSessionTests, self).setUp()
        self.lp = samba.tests.env_loadparm()
        self.admin_session = auth.admin_session(self.lp,
                                                "S-1-5-21-2212615479-2695158682-2101375467")

    def test_admin_session_attrs(self):
        self.assertTrue(hasattr(self.admin_session, 'credentials'))
        self.assertTrue(hasattr(self.admin_session, 'info'))
        self.assertTrue(hasattr(self.admin_session, 'security_token'))
        self.assertTrue(hasattr(self.admin_session, 'session_key'))
        self.assertTrue(hasattr(self.admin_session, 'torture'))

    def test_admin_session_credentials(self):
        self.assertIsNone(self.admin_session.credentials)

    def test_session_info_details(self):
        self.assertEqual(self.admin_session.info.full_name,
                         'Administrator')
        self.assertEqual(self.admin_session.info.domain_name,
                         self.lp.get('workgroup'))
        self.assertEqual(self.admin_session.info.account_name,
                         'Administrator')

    def test_security_token(self):
        self.assertFalse(self.admin_session.security_token.is_system())
        self.assertFalse(self.admin_session.security_token.is_anonymous())
        self.assertTrue(self.admin_session.security_token.has_builtin_administrators())

    def test_session_info_unix_details(self):
        samba.auth.session_info_fill_unix(session_info=self.admin_session,
                                          lp_ctx=self.lp,
                                          user_name="Administrator")
        self.assertEqual(self.admin_session.unix_info.sanitized_username,
                         'Administrator')
        self.assertEqual(self.admin_session.unix_info.unix_name,
                         self.lp.get('workgroup').upper() +
                         self.lp.get('winbind separator') + 'Administrator')
        self.assertIsNotNone(self.admin_session.unix_token)
