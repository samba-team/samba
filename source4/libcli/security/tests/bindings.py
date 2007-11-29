#!/usr/bin/python

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

import unittest
import security

class SecurityTokenTests(unittest.TestCase):
    def setUp(self):
        self.token = security.SecurityToken()

    def test_is_system(self):
        self.assertFalse(self.token.is_system())

    def test_is_anonymous(self):
        self.assertFalse(self.token.is_anonymous())

    def test_has_builtin_administrators(self):
        self.assertFalse(self.token.has_builtin_administrators())

    def test_has_nt_authenticated_users(self):
        self.assertFalse(self.token.has_nt_authenticated_users())

    def test_has_priv(self):
        self.assertFalse(self.token.has_privilege(security.SEC_PRIV_SHUTDOWN))

    def test_set_priv(self):
        self.assertFalse(self.token.has_privilege(security.SEC_PRIV_SHUTDOWN))
        self.assertFalse(self.token.set_privilege(security.SEC_PRIV_SHUTDOWN))
        self.assertTrue(self.token.has_privilege(security.SEC_PRIV_SHUTDOWN))


class SecurityDescriptorTests(unittest.TestCase):
    def setUp(self):
        self.descriptor = security.SecurityDescriptor()


class RandomSidTests(unittest.TestCase):
    def test_random(self):
        sid = security.random_sid()
        self.assertTrue(str(sid).startswith("S-1-5-21-"))


class PrivilegeTests(unittest.TestCase):
    def test_privilege_name(self):
        self.assertEquals("SeShutdownPrivilege", security.privilege_name(security.SEC_PRIV_SHUTDOWN))

    def test_privilege_id(self):
        self.assertEquals(security.SEC_PRIV_SHUTDOWN, security.privilege_id("SeShutdownPrivilege"))

