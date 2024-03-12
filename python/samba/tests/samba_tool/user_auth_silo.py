# Unix SMB/CIFS implementation.
#
# Tests for samba-tool user auth silo command
#
# Copyright (C) Catalyst.Net Ltd. 2023
#
# Written by Rob van der Linde <rob@catalyst.net.nz>
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

from samba.domain.models import AuthenticationSilo, User

from .silo_base import SiloTest


class AuthPolicyCmdTestCase(SiloTest):
    def test_assign(self):
        """Test assigning an authentication silo to a user."""
        self.addCleanup(self.runcmd, "user", "auth", "silo", "remove", "alice")
        result, out, err = self.runcmd("user", "auth", "silo", "assign",
                                       "alice", "--silo", "Developers")
        self.assertIsNone(result, msg=err)

        # Assigned silo should be 'Developers'
        user = User.get(self.samdb, account_name="alice")
        silo = AuthenticationSilo.get(self.samdb, dn=user.assigned_silo)
        self.assertEqual(silo.name, "Developers")

    def test_assign__invalid_silo(self):
        """Test assigning a non-existing authentication silo to a user."""
        result, out, err = self.runcmd("user", "auth", "silo", "assign",
                                       "alice", "--silo", "doesNotExist")
        self.assertEqual(result, -1)
        self.assertIn("Authentication silo doesNotExist not found.", err)

    def test_remove(self):
        """Test removing the assigned authentication silo from a user."""
        # First assign a silo, so we can test removing it.
        self.runcmd("user", "auth", "silo", "assign", "bob", "--silo", "QA")

        # Assigned silo should be set
        user = User.get(self.samdb, account_name="bob")
        self.assertIsNotNone(user.assigned_silo)

        # Now try removing it
        result, out, err = self.runcmd("user", "auth", "silo", "remove",
                                       "bob")
        self.assertIsNone(result, msg=err)

        # Assigned silo should be None
        user = User.get(self.samdb, account_name="bob")
        self.assertIsNone(user.assigned_silo)

    def test_view(self):
        """Test viewing the current assigned authentication silo on a user."""
        # Assign a silo on one of the users.
        self.addCleanup(self.runcmd, "user", "auth", "silo", "remove", "bob")
        self.runcmd("user", "auth", "silo", "assign", "bob", "--silo", "QA")

        # Test user with a silo assigned.
        result, out, err = self.runcmd("user", "auth", "silo", "view",
                                       "bob")
        self.assertIsNone(result, msg=err)
        self.assertEqual(
            out, "User bob assigned to authentication silo QA (revoked)\n")

        # Test user without a silo assigned.
        result, out, err = self.runcmd("user", "auth", "silo", "view",
                                       "joe")
        self.assertIsNone(result, msg=err)
        self.assertEqual(
            out, "User joe has no assigned authentication silo.\n")
