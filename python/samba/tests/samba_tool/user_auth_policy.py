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

    def setUp(self):
        super().setUp()
        # Create random test users
        self.user1 = self.randomName()
        self.user2 = self.randomName()
        self.user3 = self.randomName()

        # Create the users with random passwords
        password = self.random_password()
        self.runcmd("user", "add", self.user1, password)
        self.runcmd("user", "add", self.user2, password)
        self.runcmd("user", "add", self.user3, password)

    def tearDown(self):
        # Remove policy assignments before deleting users
        # (ignore errors if no assignment exists)
        self.runcmd("user", "auth", "policy", "remove", self.user1)
        self.runcmd("user", "auth", "policy", "remove", self.user2)

        # Delete the random test users
        self.runcmd("user", "delete", self.user1)
        self.runcmd("user", "delete", self.user2)
        self.runcmd("user", "delete", self.user3)
        super().tearDown()

    def test_assign(self):
        """Test assigning an authentication policy to a user."""
        self.addCleanup(
            self.runcmd, "user", "auth", "policy", "remove", self.user1
        )
        result, out, err = self.runcmd(
            "user",
            "auth",
            "policy",
            "assign",
            self.user1,
            "--policy",
            "User Policy",
        )
        self.assertIsNone(result, msg=err)

        # Assigned policy should be 'User Policy'
        user = User.get(self.samdb, account_name=self.user1)
        policy = AuthenticationPolicy.get(self.samdb, dn=user.assigned_policy)
        self.assertEqual(policy.name, "User Policy")

    def test_assign__invalid_policy(self):
        """Test assigning a non-existing authentication policy."""
        result, out, err = self.runcmd(
            "user",
            "auth",
            "policy",
            "assign",
            self.user1,
            "--policy",
            "doesNotExist",
        )
        self.assertEqual(result, -1)
        self.assertIn("Authentication policy doesNotExist not found.", err)

    def test_remove(self):
        """Test removing the assigned authentication policy."""
        # First assign a policy, so we can test removing it.
        self.runcmd(
            "user",
            "auth",
            "policy",
            "assign",
            self.user2,
            "--policy",
            "User Policy",
        )

        # Assigned policy should be set
        user = User.get(self.samdb, account_name=self.user2)
        self.assertIsNotNone(user.assigned_policy)

        # Now try removing it
        result, out, err = self.runcmd(
            "user", "auth", "policy", "remove", self.user2
        )
        self.assertIsNone(result, msg=err)

        # Assigned policy should be None
        user = User.get(self.samdb, account_name=self.user2)
        self.assertIsNone(user.assigned_policy)

    def test_view(self):
        """Test viewing the assigned authentication policy."""
        # Assign a policy on one of the users.
        self.addCleanup(
            self.runcmd, "user", "auth", "policy", "remove", self.user2
        )
        self.runcmd(
            "user",
            "auth",
            "policy",
            "assign",
            self.user2,
            "--policy",
            "User Policy",
        )

        # Test user with a policy assigned.
        result, out, err = self.runcmd(
            "user", "auth", "policy", "view", self.user2
        )
        self.assertIsNone(result, msg=err)
        self.assertEqual(
            out,
            f"User {self.user2} assigned to authentication policy "
            f"User Policy\n",
        )

        # Test user without a policy assigned.
        result, out, err = self.runcmd(
            "user", "auth", "policy", "view", self.user3
        )
        self.assertIsNone(result, msg=err)
        self.assertEqual(
            out, f"User {self.user3} has no assigned authentication policy.\n"
        )
