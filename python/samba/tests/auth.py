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

class AuthTests(samba.tests.TestCase):

    def setUp(self):
        super(AuthTests, self).setUp()
        self.system_session = auth.system_session()

    def test_system_session_attrs(self):
        self.assertTrue(hasattr(self.system_session, 'credentials'))
        self.assertTrue(hasattr(self.system_session, 'info'))
        self.assertTrue(hasattr(self.system_session, 'security_token'))
        self.assertTrue(hasattr(self.system_session, 'session_key'))
        self.assertTrue(hasattr(self.system_session, 'torture'))

    def test_system_session_credentials(self):
        self.assertIsNone(self.system_session.credentials.get_bind_dn())
        self.assertIsNone(self.system_session.credentials.get_password())
        self.assertEqual(self.system_session.credentials.get_username(), '')

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
