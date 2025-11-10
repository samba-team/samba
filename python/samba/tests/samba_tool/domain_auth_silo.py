# Unix SMB/CIFS implementation.
#
# Tests for samba-tool domain auth silo command
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

import json
from unittest.mock import patch

from samba.domain.models.exceptions import ModelError
from samba.samdb import SamDB
from samba.sd_utils import SDUtils

from .silo_base import SiloTest


class AuthSiloCmdTestCase(SiloTest):

    def test_list(self):
        """Test listing authentication silos in list format."""
        result, out, err = self.runcmd("domain", "auth", "silo", "list")
        self.assertIsNone(result, msg=err)

        expected_silos = ["Developers", "Managers", "QA"]

        for silo in expected_silos:
            self.assertIn(silo, out)

    def test_list___json(self):
        """Test listing authentication silos in JSON format."""
        result, out, err = self.runcmd("domain", "auth", "silo",
                                       "list", "--json")
        self.assertIsNone(result, msg=err)

        # we should get valid json
        silos = json.loads(out)

        expected_silos = ["Developers", "Managers", "QA"]

        for name in expected_silos:
            silo = silos[name]
            self.assertIn("msDS-AuthNPolicySilo", list(silo["objectClass"]))
            self.assertIn("description", silo)
            self.assertIn("msDS-UserAuthNPolicy", silo)
            self.assertIn("objectGUID", silo)

    def test_view(self):
        """Test viewing a single authentication silo."""
        result, out, err = self.runcmd("domain", "auth", "silo", "view",
                                       "--name", "Developers")
        self.assertIsNone(result, msg=err)

        # we should get valid json
        silo = json.loads(out)

        # check a few fields only
        self.assertEqual(silo["cn"], "Developers")
        self.assertEqual(silo["description"],
                         "Developers, Developers, Developers!")

    def test_view__notfound(self):
        """Test viewing an authentication silo that doesn't exist."""
        result, out, err = self.runcmd("domain", "auth", "silo", "view",
                                       "--name", "doesNotExist")
        self.assertEqual(result, -1)
        self.assertIn("Authentication silo doesNotExist not found.", err)

    def test_view__name_required(self):
        """Test view authentication silo without --name argument."""
        result, out, err = self.runcmd("domain", "auth", "silo", "view")
        self.assertEqual(result, -1)
        self.assertIn("Argument --name is required.", err)

    def test_create__single_policy(self):
        """Test creating a new authentication silo with a single policy."""
        name = self.unique_name()

        self.addCleanup(self.delete_authentication_silo, name=name, force=True)
        result, out, err = self.runcmd("domain", "auth", "silo", "create",
                                       "--name", name,
                                       "--user-authentication-policy", "User Policy")
        self.assertIsNone(result, msg=err)

        # Check silo that was created
        silo = self.get_authentication_silo(name)
        self.assertEqual(str(silo["cn"]), name)
        self.assertIn("User Policy", str(silo["msDS-UserAuthNPolicy"]))
        self.assertEqual(str(silo["msDS-AuthNPolicySiloEnforced"]), "TRUE")

    def test_create__multiple_policies(self):
        """Test creating a new authentication silo with multiple policies."""
        name = self.unique_name()

        self.addCleanup(self.delete_authentication_silo, name=name, force=True)
        result, out, err = self.runcmd("domain", "auth", "silo", "create",
                                       "--name", name,
                                       "--user-authentication-policy",
                                       "User Policy",
                                       "--service-authentication-policy",
                                       "Service Policy",
                                       "--computer-authentication-policy",
                                       "Computer Policy")
        self.assertIsNone(result, msg=err)

        # Check silo that was created.
        silo = self.get_authentication_silo(name)
        self.assertEqual(str(silo["cn"]), name)
        self.assertIn("User Policy", str(silo["msDS-UserAuthNPolicy"]))
        self.assertIn("Service Policy", str(silo["msDS-ServiceAuthNPolicy"]))
        self.assertIn("Computer Policy", str(silo["msDS-ComputerAuthNPolicy"]))
        self.assertEqual(str(silo["msDS-AuthNPolicySiloEnforced"]), "TRUE")

    def test_create__policy_dn(self):
        """Test creating a new authentication silo when policy is a dn."""
        name = self.unique_name()
        policy = self.get_authentication_policy("User Policy")

        self.addCleanup(self.delete_authentication_silo, name=name, force=True)
        result, out, err = self.runcmd("domain", "auth", "silo", "create",
                                       "--name", name,
                                       "--user-authentication-policy", policy["dn"])
        self.assertIsNone(result, msg=err)

        # Check silo that was created
        silo = self.get_authentication_silo(name)
        self.assertEqual(str(silo["cn"]), name)
        self.assertIn(str(policy["name"]), str(silo["msDS-UserAuthNPolicy"]))
        self.assertEqual(str(silo["msDS-AuthNPolicySiloEnforced"]), "TRUE")

    def test_create__already_exists(self):
        """Test creating a new authentication silo that already exists."""
        result, out, err = self.runcmd("domain", "auth", "silo", "create",
                                       "--name", "Developers",
                                       "--user-authentication-policy", "User Policy")
        self.assertEqual(result, -1)
        self.assertIn("Authentication silo Developers already exists.", err)

    def test_create__name_missing(self):
        """Test create authentication silo without --name argument."""
        result, out, err = self.runcmd("domain", "auth", "silo", "create",
                                       "--user-authentication-policy", "User Policy")
        self.assertEqual(result, -1)
        self.assertIn("Argument --name is required.", err)

    def test_create__audit(self):
        """Test create authentication silo with --audit flag."""
        name = self.unique_name()

        self.addCleanup(self.delete_authentication_silo, name=name, force=True)
        result, out, err = self.runcmd("domain", "auth", "silo", "create",
                                       "--name", "auditPolicies",
                                       "--user-authentication-policy", "User Policy",
                                       "--name", name,
                                       "--user-authentication-policy", "User Policy",
                                       "--audit")
        self.assertIsNone(result, msg=err)

        # fetch and check silo
        silo = self.get_authentication_silo(name)
        self.assertEqual(str(silo["msDS-AuthNPolicySiloEnforced"]), "FALSE")

    def test_create__enforce(self):
        """Test create authentication silo with --enforce flag."""
        name = self.unique_name()

        self.addCleanup(self.delete_authentication_silo, name=name, force=True)
        result, out, err = self.runcmd("domain", "auth", "silo", "create",
                                       "--name", name,
                                       "--user-authentication-policy", "User Policy",
                                       "--enforce")
        self.assertIsNone(result, msg=err)

        # fetch and check silo
        silo = self.get_authentication_silo(name)
        self.assertEqual(str(silo["msDS-AuthNPolicySiloEnforced"]), "TRUE")

    def test_create__audit_enforce_together(self):
        """Test create authentication silo using both --audit and --enforce."""
        name = self.unique_name()

        result, out, err = self.runcmd("domain", "auth", "silo", "create",
                                       "--name", name,
                                       "--user-authentication-policy", "User Policy",
                                       "--audit", "--enforce")

        self.assertEqual(result, -1)
        self.assertIn("--audit and --enforce cannot be used together.", err)

    def test_create__protect_unprotect_together(self):
        """Test create authentication silo using --protect and --unprotect."""
        name = self.unique_name()

        result, out, err = self.runcmd("domain", "auth", "silo", "create",
                                       "--name", name,
                                       "--user-authentication-policy", "User Policy",
                                       "--protect", "--unprotect")

        self.assertEqual(result, -1)
        self.assertIn("--protect and --unprotect cannot be used together.", err)

    def test_create__policy_notfound(self):
        """Test create authentication silo with a policy that doesn't exist."""
        name = self.unique_name()

        result, out, err = self.runcmd("domain", "auth", "silo", "create",
                                       "--name", name,
                                       "--user-authentication-policy", "Invalid Policy")

        self.assertEqual(result, -1)
        self.assertIn("Authentication policy Invalid Policy not found.", err)

    def test_create__fails(self):
        """Test creating an authentication silo, but it fails."""
        name = self.unique_name()

        # Raise ModelError when ldb.add() is called.
        with patch.object(SamDB, "add") as add_mock:
            add_mock.side_effect = ModelError("Custom error message")
            result, out, err = self.runcmd("domain", "auth", "silo", "create",
                                           "--name", name,
                                           "--user-authentication-policy", "User Policy")
            self.assertEqual(result, -1)
            self.assertIn("Custom error message", err)

    def test_modify__description(self):
        """Test modify authentication silo changing the description field."""
        name = self.unique_name()

        # Create a silo to modify for this test.
        self.addCleanup(self.delete_authentication_silo, name=name, force=True)
        self.runcmd("domain", "auth", "silo", "create", "--name", name)

        result, out, err = self.runcmd("domain", "auth", "silo", "modify",
                                       "--name", name,
                                       "--description", "New Description")
        self.assertIsNone(result, msg=err)

        # check new value
        silo = self.get_authentication_silo(name)
        self.assertEqual(str(silo["description"]), "New Description")

    def test_modify__audit_enforce(self):
        """Test modify authentication silo setting --audit and --enforce."""
        name = self.unique_name()

        # Create a silo to modify for this test.
        self.addCleanup(self.delete_authentication_silo, name=name, force=True)
        self.runcmd("domain", "auth", "silo", "create", "--name", name)

        result, out, err = self.runcmd("domain", "auth", "silo", "modify",
                                       "--name", name,
                                       "--audit")
        self.assertIsNone(result, msg=err)

        # Check silo is set to audit.
        silo = self.get_authentication_silo(name)
        self.assertEqual(str(silo["msDS-AuthNPolicySiloEnforced"]), "FALSE")

        result, out, err = self.runcmd("domain", "auth", "silo", "modify",
                                       "--name", name,
                                       "--enforce")
        self.assertIsNone(result, msg=err)

        # Check is set to enforce.
        silo = self.get_authentication_silo(name)
        self.assertEqual(str(silo["msDS-AuthNPolicySiloEnforced"]), "TRUE")

    def test_modify__protect_unprotect(self):
        """Test modify un-protecting and protecting an authentication silo."""
        name = self.unique_name()

        # Create a silo to modify for this test.
        self.addCleanup(self.delete_authentication_silo, name=name, force=True)
        self.runcmd("domain", "auth", "silo", "create", "--name", name)

        utils = SDUtils(self.samdb)
        result, out, err = self.runcmd("domain", "auth", "silo", "modify",
                                       "--name", name,
                                       "--protect")
        self.assertIsNone(result, msg=err)

        # Check that silo was protected.
        silo = self.get_authentication_silo(name)
        desc = utils.get_sd_as_sddl(silo["dn"])
        self.assertIn("(D;;DTSD;;;WD)", desc)

        result, out, err = self.runcmd("domain", "auth", "silo", "modify",
                                       "--name", name,
                                       "--unprotect")
        self.assertIsNone(result, msg=err)

        # Check that silo was unprotected.
        silo = self.get_authentication_silo(name)
        desc = utils.get_sd_as_sddl(silo["dn"])
        self.assertNotIn("(D;;DTSD;;;WD)", desc)

    def test_modify__audit_enforce_together(self):
        """Test modify silo doesn't allow both --audit and --enforce."""
        result, out, err = self.runcmd("domain", "auth", "silo", "modify",
                                       "--name", "QA",
                                       "--audit", "--enforce")

        self.assertEqual(result, -1)
        self.assertIn("--audit and --enforce cannot be used together.", err)

    def test_modify__protect_unprotect_together(self):
        """Test modify silo using both --protect and --unprotect."""
        result, out, err = self.runcmd("domain", "auth", "silo", "modify",
                                       "--name", "Developers",
                                       "--protect", "--unprotect")
        self.assertEqual(result, -1)
        self.assertIn("--protect and --unprotect cannot be used together.", err)

    def test_modify__notfound(self):
        """Test modify an authentication silo that doesn't exist."""
        result, out, err = self.runcmd("domain", "auth", "silo", "modify",
                                       "--name", "doesNotExist",
                                       "--description=NewDescription")
        self.assertEqual(result, -1)
        self.assertIn("Authentication silo doesNotExist not found.", err)

    def test_modify__name_missing(self):
        """Test modify authentication silo without --name argument."""
        result, out, err = self.runcmd("domain", "auth", "silo", "modify")
        self.assertEqual(result, -1)
        self.assertIn("Argument --name is required.", err)

    def test_modify__fails(self):
        """Test modify authentication silo, but it fails."""
        # Raise ModelError when ldb.modify() is called.
        with patch.object(SamDB, "modify") as add_mock:
            add_mock.side_effect = ModelError("Custom error message")
            result, out, err = self.runcmd("domain", "auth", "silo", "modify",
                                           "--name", "Developers",
                                           "--description", "Devs")
            self.assertEqual(result, -1)
            self.assertIn("Custom error message", err)

    def test_authentication_silo_delete(self):
        """Test deleting an authentication silo that is not protected."""
        name = self.unique_name()

        # Create non-protected authentication silo.
        result, out, err = self.runcmd("domain", "auth", "silo", "create",
                                       "--name", name,
                                       "--user-authentication-policy", "User Policy")
        self.assertIsNone(result, msg=err)
        silo = self.get_authentication_silo(name)
        self.assertIsNotNone(silo)

        # Do the deletion.
        result, out, err = self.runcmd("domain", "auth", "silo", "delete",
                                       "--name", name)
        self.assertIsNone(result, msg=err)

        # Authentication silo shouldn't exist anymore.
        silo = self.get_authentication_silo(name)
        self.assertIsNone(silo)

    def test_delete__protected(self):
        """Test deleting a protected auth silo, with and without --force."""
        name = self.unique_name()

        # Create protected authentication silo.
        result, out, err = self.runcmd("domain", "auth", "silo", "create",
                                       "--name", name,
                                       "--user-authentication-policy", "User Policy",
                                       "--protect")
        self.assertIsNone(result, msg=err)
        silo = self.get_authentication_silo(name)
        self.assertIsNotNone(silo)

        # Do the deletion.
        result, out, err = self.runcmd("domain", "auth", "silo", "delete",
                                       "--name", name)
        self.assertEqual(result, -1)

        # Authentication silo should still exist.
        silo = self.get_authentication_silo(name)
        self.assertIsNotNone(silo)

        # Try a force delete instead.
        result, out, err = self.runcmd("domain", "auth", "silo", "delete",
                                       "--name", name, "--force")
        self.assertIsNone(result, msg=err)

        # Authentication silo shouldn't exist anymore.
        silo = self.get_authentication_silo(name)
        self.assertIsNone(silo)

    def test_delete__notfound(self):
        """Test deleting an authentication silo that doesn't exist."""
        result, out, err = self.runcmd("domain", "auth", "silo", "delete",
                                       "--name", "doesNotExist")
        self.assertEqual(result, -1)
        self.assertIn("Authentication silo doesNotExist not found.", err)

    def test_delete__name_required(self):
        """Test deleting an authentication silo without --name argument."""
        result, out, err = self.runcmd("domain", "auth", "silo", "delete")
        self.assertEqual(result, -1)
        self.assertIn("Argument --name is required.", err)

    def test_delete__force_fails(self):
        """Test deleting an authentication silo with --force, but it fails."""
        name = self.unique_name()

        # Create protected authentication silo.
        self.addCleanup(self.delete_authentication_silo, name=name, force=True)
        result, out, err = self.runcmd("domain", "auth", "silo", "create",
                                       "--name", name,
                                       "--user-authentication-policy", "User Policy",
                                       "--protect")
        self.assertIsNone(result, msg=err)

        # Silo exists
        silo = self.get_authentication_silo(name)
        self.assertIsNotNone(silo)

        # Try doing delete with --force.
        # Patch SDUtils.dacl_delete_aces with a Mock that raises ModelError.
        with patch.object(SDUtils, "dacl_delete_aces") as delete_mock:
            delete_mock.side_effect = ModelError("Custom error message")
            result, out, err = self.runcmd("domain", "auth", "silo", "delete",
                                           "--name", name,
                                           "--force")
            self.assertEqual(result, -1)
            self.assertIn("Custom error message", err)

    def test_delete__fails(self):
        """Test deleting an authentication silo, but it fails."""
        name = self.unique_name()

        # Create regular authentication silo.
        self.addCleanup(self.delete_authentication_silo, name=name, force=True)
        result, out, err = self.runcmd("domain", "auth", "silo", "create",
                                       "--name", name,
                                       "--user-authentication-policy", "User Policy")
        self.assertIsNone(result, msg=err)

        # Silo exists
        silo = self.get_authentication_silo(name)
        self.assertIsNotNone(silo)

        # Raise ModelError when ldb.delete() is called.
        with patch.object(SamDB, "delete") as delete_mock:
            delete_mock.side_effect = ModelError("Custom error message")
            result, out, err = self.runcmd("domain", "auth", "silo", "delete",
                                           "--name", name)
            self.assertEqual(result, -1)
            self.assertIn("Custom error message", err)

            # When not using --force we get a hint.
            self.assertIn("Try --force", err)

    def test_delete__protected_fails(self):
        """Test deleting an authentication silo, but it fails."""
        name = self.unique_name()

        # Create protected authentication silo.
        self.addCleanup(self.delete_authentication_silo, name=name, force=True)
        result, out, err = self.runcmd("domain", "auth", "silo", "create",
                                       "--name", name,
                                       "--user-authentication-policy", "User Policy",
                                       "--protect")
        self.assertIsNone(result, msg=err)

        # Silo exists
        silo = self.get_authentication_silo(name)
        self.assertIsNotNone(silo)

        # Raise ModelError when ldb.delete() is called.
        with patch.object(SamDB, "delete") as delete_mock:
            delete_mock.side_effect = ModelError("Custom error message")
            result, out, err = self.runcmd("domain", "auth", "silo", "delete",
                                           "--name", name,
                                           "--force")
            self.assertEqual(result, -1)
            self.assertIn("Custom error message", err)

            # When using --force we don't get the hint.
            self.assertNotIn("Try --force", err)


class AuthSiloMemberCmdTestCase(SiloTest):

    def setUp(self):
        super().setUp()

        # Create random test users
        self.user1 = self.randomName()  # alice
        self.user2 = self.randomName()  # bob
        self.user3 = self.randomName()  # jane
        self.user4 = self.randomName()  # joe

        # Create the users with random passwords
        password = self.random_password()
        self.runcmd("user", "add", self.user1, password)
        self.runcmd("user", "add", self.user2, password)
        self.runcmd("user", "add", self.user3, password)
        self.runcmd("user", "add", self.user4, password)

        # Create an organisational unit to test in.
        self.ou = self.samdb.get_default_basedn()
        self.ou.add_child("OU=Domain Auth Tests")
        self.samdb.create_ou(self.ou)
        self.addCleanup(self.samdb.delete, self.ou, ["tree_delete:1"])

        # Grant member access to silos
        self.grant_silo_access("Developers", self.user2)
        self.grant_silo_access("Developers", self.user3)
        self.grant_silo_access("Managers", self.user1)

    def tearDown(self):
        # Revoke silo access granted in setUp() before deleting users
        self.revoke_silo_access("Developers", self.user2)
        self.revoke_silo_access("Developers", self.user3)
        self.revoke_silo_access("Managers", self.user1)

        # Delete the random test users
        self.runcmd("user", "delete", self.user1)
        self.runcmd("user", "delete", self.user2)
        self.runcmd("user", "delete", self.user3)
        self.runcmd("user", "delete", self.user4)
        super().tearDown()

    def create_computer(self, name):
        """Create a Computer and return the dn."""
        dn = f"CN={name},{self.ou}"
        self.samdb.newcomputer(name, self.ou)
        return dn

    def grant_silo_access(self, silo, member):
        """Grant a member access to an authentication silo."""
        result, out, err = self.runcmd("domain", "auth", "silo",
                                       "member", "grant",
                                       "--name", silo, "--member", member)

        self.assertIsNone(result, msg=err)
        self.assertIn(
            f"User {member} granted access to the authentication silo {silo}",
            out)

    def revoke_silo_access(self, silo, member):
        """Revoke a member from an authentication silo."""
        result, out, err = self.runcmd("domain", "auth", "silo",
                                       "member", "revoke",
                                       "--name", silo, "--member", member)

        self.assertIsNone(result, msg=err)

    def test_member_list(self):
        """Test listing authentication policy members in list format."""
        user1 = self.get_user(self.user1)
        user3 = self.get_user(self.user3)
        user2 = self.get_user(self.user2)

        result, out, err = self.runcmd("domain", "auth", "silo",
                                       "member", "list",
                                       "--name", "Developers")

        self.assertIsNone(result, msg=err)
        self.assertIn(str(user2.dn), out)
        self.assertIn(str(user3.dn), out)
        self.assertNotIn(str(user1.dn), out)

    def test_member_list___json(self):
        """Test listing authentication policy members list in json format."""
        user1 = self.get_user(self.user1)
        user3 = self.get_user(self.user3)
        user2 = self.get_user(self.user2)

        result, out, err = self.runcmd("domain", "auth", "silo",
                                       "member", "list",
                                       "--name", "Developers", "--json")

        self.assertIsNone(result, msg=err)
        members = json.loads(out)
        members_dn = [member["dn"] for member in members]
        self.assertIn(str(user2.dn), members_dn)
        self.assertIn(str(user3.dn), members_dn)
        self.assertNotIn(str(user1.dn), members_dn)

    def test_member_list__name_missing(self):
        """Test list authentication policy members without the name argument."""
        result, out, err = self.runcmd("domain", "auth", "silo",
                                       "member", "list")

        self.assertIsNotNone(result)
        self.assertIn("Argument --name is required.", err)

    def test_member_grant__user(self):
        """Test adding a user to an authentication silo."""
        self.grant_silo_access("Developers", self.user4)

        # Check if member is in silo
        user = self.get_user(self.user4)
        silo = self.get_authentication_silo("Developers")
        members = [str(member) for member in silo["msDS-AuthNPolicySiloMembers"]]
        self.assertIn(str(user.dn), members)

        # Clean up: revoke access before tearDown deletes the user
        self.revoke_silo_access("Developers", self.user4)

    def test_member_grant__computer(self):
        """Test adding a computer to an authentication silo"""
        name = self.unique_name()
        computer = self.create_computer(name)
        silo = "Developers"

        # Don't use self.grant_silo_member as it will try to clean up the user.
        result, out, err = self.runcmd("domain", "auth", "silo",
                                       "member", "grant",
                                       "--name", silo,
                                       "--member", computer)

        self.assertIsNone(result, msg=err)
        self.assertIn(
            f"User {name}$ granted access to the authentication silo {silo} (unassigned).",
            out)

    def test_member_grant__unknown_user(self):
        """Test adding an unknown user to an authentication silo."""
        result, out, err = self.runcmd("domain", "auth", "silo",
                                       "member", "grant",
                                       "--name", "Developers",
                                       "--member", "does_not_exist")

        self.assertIsNotNone(result)
        self.assertIn("User does_not_exist not found.", err)
