# Unix SMB/CIFS implementation.
#
# Tests for samba-tool user auth policy command
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

from samba.domain.models import AuthenticationPolicy, User

from .silo_base import SiloTest


class AuthPolicyCmdTestCase(SiloTest):
    def test_assign(self):
        """Test assigning an authentication policy to a user."""
        self.addCleanup(self.runcmd, "user", "auth", "policy", "remove", "alice")
        result, out, err = self.runcmd("user", "auth", "policy", "assign",
                                       "alice", "--policy", "User Policy")
        self.assertIsNone(result, msg=err)

        # Assigned policy should be 'Developers'
        user = User.get(self.samdb, account_name="alice")
        policy = AuthenticationPolicy.get(self.samdb, dn=user.assigned_policy)
        self.assertEqual(policy.name, "User Policy")

    def test_assign__invalid_policy(self):
        """Test assigning a non-existing authentication policy to a user."""
        result, out, err = self.runcmd("user", "auth", "policy", "assign",
                                       "alice", "--policy", "doesNotExist")
        self.assertEqual(result, -1)
        self.assertIn("Authentication policy doesNotExist not found.", err)

    def test_remove(self):
        """Test removing the assigned authentication policy from a user."""
        # First assign a policy, so we can test removing it.
        self.runcmd("user", "auth", "policy", "assign", "bob", "--policy",
                    "User Policy")

        # Assigned policy should be set
        user = User.get(self.samdb, account_name="bob")
        self.assertIsNotNone(user.assigned_policy)

        # Now try removing it
        result, out, err = self.runcmd("user", "auth", "policy", "remove",
                                       "bob")
        self.assertIsNone(result, msg=err)

        # Assigned policy should be None
        user = User.get(self.samdb, account_name="bob")
        self.assertIsNone(user.assigned_policy)

    def test_view(self):
        """Test viewing the current assigned authentication policy on a user."""
        # Assign a policy on one of the users.
        self.addCleanup(self.runcmd, "user", "auth", "policy", "remove", "bob")
        self.runcmd("user", "auth", "policy", "assign", "bob", "--policy",
                    "User Policy")

        # Test user with a policy assigned.
        result, out, err = self.runcmd("user", "auth", "policy", "view",
                                       "bob")
        self.assertIsNone(result, msg=err)
        self.assertEqual(
            out, "User bob assigned to authentication policy User Policy\n")

        # Test user without a policy assigned.
        result, out, err = self.runcmd("user", "auth", "policy", "view",
                                       "joe")
        self.assertIsNone(result, msg=err)
        self.assertEqual(
            out, "User joe has no assigned authentication policy.\n")
