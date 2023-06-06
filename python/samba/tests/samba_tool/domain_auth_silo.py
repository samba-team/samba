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

from ldb import LdbError
from samba.samdb import SamDB
from samba.sd_utils import SDUtils

from .domain_auth_base import BaseAuthCmdTest


class AuthSiloCmdTestCase(BaseAuthCmdTest):

    def test_authentication_silo_list(self):
        """Test listing authentication silos in list format."""
        result, out, err = self.runcmd("domain", "auth", "silo", "list")
        self.assertIsNone(result, msg=err)

        # Check each silo we created is there.
        for silo in self.silos:
            self.assertIn(silo, out)

    def test_authentication_silo_list_json(self):
        """Test listing authentication silos in JSON format."""
        result, out, err = self.runcmd("domain", "auth", "silo",
                                       "list", "--json")
        self.assertIsNone(result, msg=err)

        # we should get valid json
        silos = json.loads(out)

        # each silo in self.silos must be present
        for name in self.silos:
            silo = silos[name]
            self.assertIn("msDS-AuthNPolicySilo", list(silo["objectClass"]))
            self.assertIn("description", silo)
            self.assertIn("msDS-ComputerAuthNPolicy", silo)
            self.assertIn("msDS-ServiceAuthNPolicy", silo)
            self.assertIn("msDS-UserAuthNPolicy", silo)
            self.assertIn("objectGUID", silo)

    def test_authentication_silo_view(self):
        """Test viewing a single authentication silo."""
        result, out, err = self.runcmd("domain", "auth", "silo", "view",
                                       "--name", "Developers")
        self.assertIsNone(result, msg=err)

        # we should get valid json
        silo = json.loads(out)

        # check a few fields only
        self.assertEqual(silo["cn"], "Developers")
        self.assertEqual(silo["description"], "Developers, Developers")

    def test_authentication_silo_view_notfound(self):
        """Test viewing an authentication silo that doesn't exist."""
        result, out, err = self.runcmd("domain", "auth", "silo", "view",
                                       "--name", "doesNotExist")
        self.assertEqual(result, -1)
        self.assertIn("ERROR: Authentication silo doesNotExist not found.", err)

    def test_authentication_silo_view_name_required(self):
        """Test view authentication silo without --name argument."""
        result, out, err = self.runcmd("domain", "auth", "silo", "view")
        self.assertEqual(result, -1)
        self.assertIn("Argument --name is required.", err)

    def test_authentication_silo_create_single_policy(self):
        """Test creating a new authentication silo with a single policy."""
        result, out, err = self.runcmd("domain", "auth", "silo", "create",
                                       "--name", "singlePolicy",
                                       "--policy", "Single Policy")
        self.assertIsNone(result, msg=err)

        # Check silo that was created
        silo = self.get_authentication_silo("singlePolicy")
        self.assertEqual(str(silo["cn"]), "singlePolicy")
        self.assertIn("Single Policy", str(silo["msDS-UserAuthNPolicy"]))
        self.assertIn("Single Policy", str(silo["msDS-ServiceAuthNPolicy"]))
        self.assertIn("Single Policy", str(silo["msDS-ComputerAuthNPolicy"]))
        self.assertEqual(str(silo["msDS-AuthNPolicySiloEnforced"]), "TRUE")

    def test_authentication_silo_create_multiple_policies(self):
        """Test creating a new authentication silo with multiple policies."""
        result, out, err = self.runcmd("domain", "auth", "silo", "create",
                                       "--name", "multiplePolicies",
                                       "--user-policy", "User Policy",
                                       "--service-policy", "Service Policy",
                                       "--computer-policy", "Computer Policy")
        self.assertIsNone(result, msg=err)

        # Check silo that was created.
        silo = self.get_authentication_silo("multiplePolicies")
        self.assertEqual(str(silo["cn"]), "multiplePolicies")
        self.assertIn("User Policy", str(silo["msDS-UserAuthNPolicy"]))
        self.assertIn("Service Policy", str(silo["msDS-ServiceAuthNPolicy"]))
        self.assertIn("Computer Policy", str(silo["msDS-ComputerAuthNPolicy"]))
        self.assertEqual(str(silo["msDS-AuthNPolicySiloEnforced"]), "TRUE")

    def test_authentication_silo_create_policy_dn(self):
        """Test creating a new authentication silo when policy is a dn."""
        policy = self.get_authentication_policy("Single Policy")

        result, out, err = self.runcmd("domain", "auth", "silo", "create",
                                       "--name", "singlePolicyDN",
                                       "--policy", policy["dn"])
        self.assertIsNone(result, msg=err)

        # Check silo that was created
        silo = self.get_authentication_silo("singlePolicyDN")
        self.assertEqual(str(silo["cn"]), "singlePolicyDN")
        self.assertIn(str(policy["name"]), str(silo["msDS-UserAuthNPolicy"]))
        self.assertIn(str(policy["name"]), str(silo["msDS-ServiceAuthNPolicy"]))
        self.assertIn(str(policy["name"]), str(silo["msDS-ComputerAuthNPolicy"]))
        self.assertEqual(str(silo["msDS-AuthNPolicySiloEnforced"]), "TRUE")

    def test_authentication_silo_create_already_exists(self):
        """Test creating a new authentication silo that already exists."""
        result, out, err = self.runcmd("domain", "auth", "silo", "create",
                                       "--name", "Developers",
                                       "--policy", "Single Policy")
        self.assertEqual(result, -1)
        self.assertIn("Authentication silo Developers already exists.", err)

    def test_authentication_silo_create_name_missing(self):
        """Test create authentication silo without --name argument."""
        result, out, err = self.runcmd("domain", "auth", "silo", "create",
                                       "--policy", "Single Policy")
        self.assertEqual(result, -1)
        self.assertIn("Argument --name is required.", err)

    def test_authentication_silo_create_audit(self):
        """Test create authentication silo with --audit flag."""
        result, out, err = self.runcmd("domain", "auth", "silo", "create",
                                       "--name", "auditPolicies",
                                       "--policy", "Single Policy",
                                       "--audit")
        self.assertIsNone(result, msg=err)

        # fetch and check silo
        silo = self.get_authentication_silo("auditPolicies")
        self.assertEqual(str(silo["msDS-AuthNPolicySiloEnforced"]), "FALSE")

    def test_authentication_silo_create_enforce(self):
        """Test create authentication silo with --enforce flag."""
        result, out, err = self.runcmd("domain", "auth", "silo", "create",
                                       "--name", "enforcePolicies",
                                       "--policy", "Single Policy",
                                       "--enforce")
        self.assertIsNone(result, msg=err)

        # fetch and check silo
        silo = self.get_authentication_silo("enforcePolicies")
        self.assertEqual(str(silo["msDS-AuthNPolicySiloEnforced"]), "TRUE")

    def test_authentication_silo_create_audit_enforce_together(self):
        """Test create authentication silo using both --audit and --enforce."""
        result, out, err = self.runcmd("domain", "auth", "silo", "create",
                                       "--name", "enforceTogether",
                                       "--policy", "Single Policy",
                                       "--audit", "--enforce")
        self.assertEqual(result, -1)
        self.assertIn("--audit and --enforce cannot be used together.", err)

    def test_authentication_silo_create_protect_unprotect_together(self):
        """Test create authentication silo using --protect and --unprotect."""
        result, out, err = self.runcmd("domain", "auth", "silo",
                                       "create", "--name", "protectTogether",
                                       "--policy", "Single Policy",
                                       "--protect", "--unprotect")
        self.assertEqual(result, -1)
        self.assertIn("--protect and --unprotect cannot be used together.", err)

    def test_authentication_silo_create_policy_notfound(self):
        """Test create authentication silo with a policy that doesn't exist."""
        result, out, err = self.runcmd("domain", "auth", "silo", "create",
                                       "--name", "policyNotFound",
                                       "--policy", "Invalid Policy")
        self.assertEqual(result, -1)
        self.assertIn(f"Authentication policy Invalid Policy not found.", err)

    def test_authentication_silo_create_fails(self):
        """Test creating an authentication silo, but it fails."""
        # Raise LdbError when ldb.add() is called.
        with patch.object(SamDB, "add") as add_mock:
            add_mock.side_effect = LdbError("Custom error message")
            result, out, err = self.runcmd("domain", "auth", "silo", "create",
                                           "--name", "createFails",
                                           "--policy", "Single Policy")
            self.assertEqual(result, -1)
            self.assertIn("ERROR: Custom error message", err)

    def test_authentication_silo_modify_description(self):
        """Test modify authentication silo changing the description field."""
        # check original value
        silo = self.get_authentication_silo("qa")
        self.assertNotEqual(str(silo["description"]), "Testing Team")

        result, out, err = self.runcmd("domain", "auth", "silo", "modify",
                                       "--name", "qa",
                                       "--description", "Testing Team")
        self.assertIsNone(result, msg=err)

        # check new value
        silo = self.get_authentication_silo("qa")
        self.assertEqual(str(silo["description"]), "Testing Team")

    def test_authentication_silo_modify_audit_enforce(self):
        """Test modify authentication silo setting --audit and --enforce."""
        result, out, err = self.runcmd("domain", "auth", "silo", "modify",
                                       "--name", "Developers",
                                       "--audit")
        self.assertIsNone(result, msg=err)

        # Check silo is set to audit.
        silo = self.get_authentication_silo("developers")
        self.assertEqual(str(silo["msDS-AuthNPolicySiloEnforced"]), "FALSE")

        result, out, err = self.runcmd("domain", "auth", "silo", "modify",
                                       "--name", "Developers",
                                       "--enforce")
        self.assertIsNone(result, msg=err)

        # Check is set to enforce.
        silo = self.get_authentication_silo("developers")
        self.assertEqual(str(silo["msDS-AuthNPolicySiloEnforced"]), "TRUE")

    def test_authentication_silo_modify_protect_unprotect(self):
        """Test modify un-protecting and protecting an authentication silo."""
        utils = SDUtils(self.samdb)
        result, out, err = self.runcmd("domain", "auth", "silo", "modify",
                                       "--name", "managers",
                                       "--protect")
        self.assertIsNone(result, msg=err)

        # Check that silo was protected.
        silo = self.get_authentication_silo("managers")
        desc = utils.get_sd_as_sddl(silo["dn"])
        self.assertIn("(D;;DTSD;;;WD)", desc)

        result, out, err = self.runcmd("domain", "auth", "silo", "modify",
                                       "--name", "managers",
                                       "--unprotect")
        self.assertIsNone(result, msg=err)

        # Check that silo was unprotected.
        silo = self.get_authentication_silo("managers")
        desc = utils.get_sd_as_sddl(silo["dn"])
        self.assertNotIn("(D;;DTSD;;;WD)", desc)

    def test_authentication_silo_modify_audit_enforce_together(self):
        """Test modify silo doesn't allow both --audit and --enforce."""
        result, out, err = self.runcmd("domain", "auth", "silo", "modify",
                                       "--name", "qa",
                                       "--audit", "--enforce")
        self.assertEqual(result, -1)
        self.assertIn("--audit and --enforce cannot be used together.", err)

    def test_authentication_silo_modify_protect_unprotect_together(self):
        """Test modify silo using both --protect and --unprotect."""
        result, out, err = self.runcmd("domain", "auth", "silo", "modify",
                                       "--name", "developers",
                                       "--protect", "--unprotect")
        self.assertEqual(result, -1)
        self.assertIn("--protect and --unprotect cannot be used together.", err)

    def test_authentication_silo_modify_notfound(self):
        """Test modify an authentication silo that doesn't exist."""
        result, out, err = self.runcmd("domain", "auth", "silo", "modify",
                                       "--name", "doesNotExist",
                                       "--description=NewDescription")
        self.assertEqual(result, -1)
        self.assertIn("ERROR: Authentication silo doesNotExist not found.", err)

    def test_authentication_silo_modify_name_missing(self):
        """Test modify authentication silo without --name argument."""
        result, out, err = self.runcmd("domain", "auth", "silo", "modify")
        self.assertEqual(result, -1)
        self.assertIn("Argument --name is required.", err)

    def test_authentication_silo_modify_fails(self):
        """Test modify authentication silo, but it fails."""
        # Raise LdbError when ldb.modify() is called.
        with patch.object(SamDB, "modify") as add_mock:
            add_mock.side_effect = LdbError("Custom error message")
            result, out, err = self.runcmd("domain", "auth", "silo", "modify",
                                           "--name", "developers",
                                           "--description", "Devs")
            self.assertEqual(result, -1)
            self.assertIn("ERROR: Custom error message", err)

    def test_authentication_silo_delete(self):
        """Test deleting an authentication silo that is not protected."""
        # Create non-protected authentication silo.
        result, out, err = self.runcmd("domain", "auth", "silo", "create",
                                       "--name=deleteTest",
                                       "--policy", "User Policy")
        self.assertIsNone(result, msg=err)
        silo = self.get_authentication_silo("deleteTest")
        self.assertIsNotNone(silo)

        # Do the deletion.
        result, out, err = self.runcmd("domain", "auth", "silo", "delete",
                                       "--name", "deleteTest")
        self.assertIsNone(result, msg=err)

        # Authentication silo shouldn't exist anymore.
        silo = self.get_authentication_silo("deleteTest")
        self.assertIsNone(silo)

    def test_authentication_silo_delete_protected(self):
        """Test deleting a protected auth silo, with and without --force."""
        # Create protected authentication silo.
        result, out, err = self.runcmd("domain", "auth", "silo", "create",
                                       "--name=deleteProtected",
                                       "--policy", "User Policy",
                                       "--protect")
        self.assertIsNone(result, msg=err)
        silo = self.get_authentication_silo("deleteProtected")
        self.assertIsNotNone(silo)

        # Do the deletion.
        result, out, err = self.runcmd("domain", "auth", "silo", "delete",
                                       "--name=deleteProtected")
        self.assertEqual(result, -1)

        # Authentication silo should still exist.
        silo = self.get_authentication_silo("deleteProtected")
        self.assertIsNotNone(silo)

        # Try a force delete instead.
        result, out, err = self.runcmd("domain", "auth", "silo", "delete",
                                       "--name=deleteProtected", "--force")
        self.assertIsNone(result, msg=err)

        # Authentication silo shouldn't exist anymore.
        silo = self.get_authentication_silo("deleteProtected")
        self.assertIsNone(silo)

    def test_authentication_silo_delete_notfound(self):
        """Test deleting an authentication silo that doesn't exist."""
        result, out, err = self.runcmd("domain", "auth", "silo", "delete",
                                       "--name", "doesNotExist")
        self.assertEqual(result, -1)
        self.assertIn("Authentication silo doesNotExist not found.", err)

    def test_authentication_silo_delete_name_required(self):
        """Test deleting an authentication silo without --name argument."""
        result, out, err = self.runcmd("domain", "auth", "silo", "delete")
        self.assertEqual(result, -1)
        self.assertIn("Argument --name is required.", err)

    def test_authentication_silo_delete_force_fails(self):
        """Test deleting an authentication silo with --force, but it fails."""
        # Create protected authentication silo.
        result, out, err = self.runcmd("domain", "auth", "silo", "create",
                                       "--name=deleteForceFail",
                                       "--policy", "User Policy",
                                       "--protect")
        self.assertIsNone(result, msg=err)
        silo = self.get_authentication_silo("deleteForceFail")
        self.assertIsNotNone(silo)

        # Try delete with --force.
        # Patch SDUtils.dacl_delete_aces with a Mock that raises LdbError.
        with patch.object(SDUtils, "dacl_delete_aces") as delete_mock:
            delete_mock.side_effect = LdbError("Custom error message")
            result, out, err = self.runcmd("domain", "auth", "silo", "delete",
                                           "--name", "deleteForceFail",
                                           "--force")
            self.assertEqual(result, -1)
            self.assertIn("ERROR: Custom error message", err)

    def test_authentication_silo_delete_fails(self):
        """Test deleting an authentication silo, but it fails."""
        # Create regular authentication silo.
        result, out, err = self.runcmd("domain", "auth", "silo", "create",
                                       "--name=regularSilo",
                                       "--policy", "User Policy")
        self.assertIsNone(result, msg=err)
        silo = self.get_authentication_silo("regularSilo")
        self.assertIsNotNone(silo)

        # Raise LdbError when ldb.delete() is called.
        with patch.object(SamDB, "delete") as delete_mock:
            delete_mock.side_effect = LdbError("Custom error message")
            result, out, err = self.runcmd("domain", "auth", "silo", "delete",
                                           "--name", "regularSilo")
            self.assertEqual(result, -1)
            self.assertIn("ERROR: Custom error message", err)

            # When not using --force we get a hint.
            self.assertIn("Try --force", err)

    def test_authentication_silo_delete_protected_fails(self):
        """Test deleting an authentication silo, but it fails."""
        # Create protected authentication silo.
        result, out, err = self.runcmd("domain", "auth", "silo", "create",
                                       "--name=protectedSilo",
                                       "--policy", "User Policy",
                                       "--protect")
        self.assertIsNone(result, msg=err)
        silo = self.get_authentication_silo("protectedSilo")
        self.assertIsNotNone(silo)

        # Raise LdbError when ldb.delete() is called.
        with patch.object(SamDB, "delete") as delete_mock:
            delete_mock.side_effect = LdbError("Custom error message")
            result, out, err = self.runcmd("domain", "auth", "silo", "delete",
                                           "--name", "protectedSilo",
                                           "--force")
            self.assertEqual(result, -1)
            self.assertIn("ERROR: Custom error message", err)

            # When using --force we don't get the hint.
            self.assertNotIn("Try --force", err)
