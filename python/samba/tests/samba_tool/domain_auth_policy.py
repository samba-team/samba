# Unix SMB/CIFS implementation.
#
# Tests for samba-tool domain auth policy command
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
from optparse import OptionValueError
from unittest.mock import patch

from samba.dcerpc import security
from samba.ndr import ndr_unpack
from samba.netcmd.domain.models.exceptions import ModelError
from samba.samdb import SamDB
from samba.sd_utils import SDUtils

from .domain_auth_base import BaseAuthCmdTest


class AuthPolicyCmdTestCase(BaseAuthCmdTest):

    def test_list(self):
        """Test listing authentication policies in list format."""
        result, out, err = self.runcmd("domain", "auth", "policy", "list")
        self.assertIsNone(result, msg=err)

        expected_policies = ["User Policy", "Service Policy", "Computer Policy"]

        for policy in expected_policies:
            self.assertIn(policy, out)

    def test_list__json(self):
        """Test listing authentication policies in JSON format."""
        result, out, err = self.runcmd("domain", "auth", "policy",
                                       "list", "--json")
        self.assertIsNone(result, msg=err)

        # we should get valid json
        policies = json.loads(out)

        expected_policies = ["User Policy", "Service Policy", "Computer Policy"]

        for name in expected_policies:
            policy = policies[name]
            self.assertIn("name", policy)
            self.assertIn("msDS-AuthNPolicy", list(policy["objectClass"]))
            self.assertIn("msDS-AuthNPolicyEnforced", policy)
            self.assertIn("msDS-StrongNTLMPolicy", policy)
            self.assertIn("objectGUID", policy)

    def test_view(self):
        """Test viewing a single authentication policy."""
        result, out, err = self.runcmd("domain", "auth", "policy", "view",
                                       "--name", "User Policy")
        self.assertIsNone(result, msg=err)

        # we should get valid json
        policy = json.loads(out)

        # check a few fields only
        self.assertEqual(policy["cn"], "User Policy")
        self.assertEqual(policy["msDS-AuthNPolicyEnforced"], True)

    def test_view__notfound(self):
        """Test viewing an authentication policy that doesn't exist."""
        result, out, err = self.runcmd("domain", "auth", "policy", "view",
                                       "--name", "doesNotExist")
        self.assertEqual(result, -1)
        self.assertIn("Authentication policy doesNotExist not found.", err)

    def test_view__name_required(self):
        """Test view authentication policy without --name argument."""
        result, out, err = self.runcmd("domain", "auth", "policy", "view")
        self.assertEqual(result, -1)
        self.assertIn("Argument --name is required.", err)

    def test_create__success(self):
        """Test creating a new authentication policy."""
        self.addCleanup(self.delete_authentication_policy,
                        name="createTest", force=True)
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", "createTest")
        self.assertIsNone(result, msg=err)

        # Check policy that was created
        policy = self.get_authentication_policy("createTest")
        self.assertEqual(str(policy["cn"]), "createTest")
        self.assertEqual(str(policy["msDS-AuthNPolicyEnforced"]), "TRUE")

    def test_create__description(self):
        """Test creating a new authentication policy with description set."""
        self.addCleanup(self.delete_authentication_policy,
                        name="descriptionTest", force=True)
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", "descriptionTest",
                                       "--description", "Custom Description")
        self.assertIsNone(result, msg=err)

        # Check policy description
        policy = self.get_authentication_policy("descriptionTest")
        self.assertEqual(str(policy["cn"]), "descriptionTest")
        self.assertEqual(str(policy["description"]), "Custom Description")

    def test_create__user_tgt_lifetime_mins(self):
        """Test create a new authentication policy with --user-tgt-lifetime-mins.

        Also checks the upper and lower bounds are handled.
        """
        self.addCleanup(self.delete_authentication_policy,
                        name="userTGTLifetime", force=True)
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", "userTGTLifetime",
                                       "--user-tgt-lifetime-mins", "60")
        self.assertIsNone(result, msg=err)

        # Check policy fields.
        policy = self.get_authentication_policy("userTGTLifetime")
        self.assertEqual(str(policy["cn"]), "userTGTLifetime")
        self.assertEqual(str(policy["msDS-UserTGTLifetime"]), "60")

        # check lower bounds (45)
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", "userTGTLifetimeLower",
                                       "--user-tgt-lifetime-mins", "44")
        self.assertEqual(result, -1)
        self.assertIn("--user-tgt-lifetime-mins must be between 45 and 2147483647",
                      err)

        # check upper bounds (2147483647)
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", "userTGTLifetimeUpper",
                                       "--user-tgt-lifetime-mins", "2147483648")
        self.assertEqual(result, -1)
        self.assertIn("--user-tgt-lifetime-mins must be between 45 and 2147483647",
                      err)

    def test_create__service_tgt_lifetime_mins(self):
        """Test create a new authentication policy with --service-tgt-lifetime-mins.

        Also checks the upper and lower bounds are handled.
        """
        self.addCleanup(self.delete_authentication_policy,
                        name="serviceTGTLifetime", force=True)
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", "serviceTGTLifetime",
                                       "--service-tgt-lifetime-mins", "60")
        self.assertIsNone(result, msg=err)

        # Check policy fields.
        policy = self.get_authentication_policy("serviceTGTLifetime")
        self.assertEqual(str(policy["cn"]), "serviceTGTLifetime")
        self.assertEqual(str(policy["msDS-ServiceTGTLifetime"]), "60")

        # check lower bounds (45)
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", "serviceTGTLifetimeLower",
                                       "--service-tgt-lifetime-mins", "44")
        self.assertEqual(result, -1)
        self.assertIn("--service-tgt-lifetime-mins must be between 45 and 2147483647",
                      err)

        # check upper bounds (2147483647)
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", "serviceTGTLifetimeUpper",
                                       "--service-tgt-lifetime-mins", "2147483648")
        self.assertEqual(result, -1)
        self.assertIn("--service-tgt-lifetime-mins must be between 45 and 2147483647",
                      err)

    def test_create__computer_tgt_lifetime_mins(self):
        """Test create a new authentication policy with --computer-tgt-lifetime-mins.

        Also checks the upper and lower bounds are handled.
        """
        self.addCleanup(self.delete_authentication_policy,
                        name="computerTGTLifetime", force=True)
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", "computerTGTLifetime",
                                       "--computer-tgt-lifetime-mins", "60")
        self.assertIsNone(result, msg=err)

        # Check policy fields.
        policy = self.get_authentication_policy("computerTGTLifetime")
        self.assertEqual(str(policy["cn"]), "computerTGTLifetime")
        self.assertEqual(str(policy["msDS-ComputerTGTLifetime"]), "60")

        # check lower bounds (45)
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", "computerTGTLifetimeLower",
                                       "--computer-tgt-lifetime-mins", "44")
        self.assertEqual(result, -1)
        self.assertIn("--computer-tgt-lifetime-mins must be between 45 and 2147483647",
                      err)

        # check upper bounds (2147483647)
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", "computerTGTLifetimeUpper",
                                       "--computer-tgt-lifetime-mins", "2147483648")
        self.assertEqual(result, -1)
        self.assertIn("--computer-tgt-lifetime-mins must be between 45 and 2147483647",
                      err)

    def test_create__valid_sddl(self):
        """Test creating a new authentication policy with valid SDDL in a field."""
        expected = "O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of {SID(AO)}))"

        self.addCleanup(self.delete_authentication_policy,
                        name="validSDDLPolicy", force=True)
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", "validSDDLPolicy",
                                       "--user-allowed-to-authenticate-from",
                                       expected)
        self.assertIsNone(result, msg=err)

        # Check policy fields.
        policy = self.get_authentication_policy("validSDDLPolicy")
        self.assertEqual(str(policy["cn"]), "validSDDLPolicy")
        desc = policy["msDS-UserAllowedToAuthenticateFrom"][0]
        sddl = ndr_unpack(security.descriptor, desc).as_sddl()
        self.assertEqual(sddl, expected)

    def test_create__invalid_sddl(self):
        """Test creating a new authentication policy with invalid SDDL in a field."""
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", "invalidSDDLPolicy",
                                       "--user-allowed-to-authenticate-from",
                                       "*INVALID SDDL*")
        self.assertEqual(result, -1)
        self.assertIn(
            "msDS-UserAllowedToAuthenticateFrom: Unable to parse SDDL", err)

    def test_create__already_exists(self):
        """Test creating a new authentication policy that already exists."""
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", "User Policy")
        self.assertEqual(result, -1)
        self.assertIn("Authentication policy User Policy already exists", err)

    def test_create__name_missing(self):
        """Test create authentication policy without --name argument."""
        result, out, err = self.runcmd("domain", "auth", "policy", "create")
        self.assertEqual(result, -1)
        self.assertIn("Argument --name is required.", err)

    def test_create__audit(self):
        """Test create authentication policy with --audit flag."""
        self.addCleanup(self.delete_authentication_policy,
                        name="auditPolicy", force=True)
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", "auditPolicy",
                                       "--audit")
        self.assertIsNone(result, msg=err)

        # fetch and check policy
        policy = self.get_authentication_policy("auditPolicy")
        self.assertEqual(str(policy["msDS-AuthNPolicyEnforced"]), "FALSE")

    def test_create__enforce(self):
        """Test create authentication policy with --enforce flag."""
        self.addCleanup(self.delete_authentication_policy,
                        name="enforcePolicy", force=True)
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", "enforcePolicy",
                                       "--enforce")
        self.assertIsNone(result, msg=err)

        # fetch and check policy
        policy = self.get_authentication_policy("enforcePolicy")
        self.assertEqual(str(policy["msDS-AuthNPolicyEnforced"]), "TRUE")

    def test_create__audit_enforce_together(self):
        """Test create auth policy using both --audit and --enforce."""
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", "enforceTogether",
                                       "--audit", "--enforce")
        self.assertEqual(result, -1)
        self.assertIn("--audit and --enforce cannot be used together.", err)

    def test_create__protect_unprotect_together(self):
        """Test create authentication policy using --protect and --unprotect."""
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", "protectTogether",
                                       "--protect", "--unprotect")
        self.assertEqual(result, -1)
        self.assertIn("--protect and --unprotect cannot be used together.", err)

    def test_create__fails(self):
        """Test creating an authentication policy, but it fails."""
        # Raise ModelError when ldb.add() is called.
        with patch.object(SamDB, "add") as add_mock:
            add_mock.side_effect = ModelError("Custom error message")
            result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                           "--name", "createFails")
            self.assertEqual(result, -1)
            self.assertIn("Custom error message", err)

    def test_modify__description(self):
        """Test modifying an authentication policy description."""
        name = "modifyDescription"

        # Create a policy to modify for this test.
        self.addCleanup(self.delete_authentication_policy,
                        name=name, force=True)
        self.runcmd("domain", "auth", "policy", "create", "--name", name)

        # Change the policy description.
        result, out, err = self.runcmd("domain", "auth", "policy", "modify",
                                       "--name", name,
                                       "--description", "NewDescription")
        self.assertIsNone(result, msg=err)

        # Verify fields were changed.
        policy = self.get_authentication_policy(name)
        self.assertEqual(str(policy["description"]), "NewDescription")

    def test_modify__strong_ntlm_policy(self):
        """Test modify strong ntlm policy on the authentication policy."""
        name = "modifyStrongNTLMPolicy"

        # Create a policy to modify for this test.
        self.addCleanup(self.delete_authentication_policy,
                        name=name, force=True)
        self.runcmd("domain", "auth", "policy", "create", "--name", name)

        result, out, err = self.runcmd("domain", "auth", "policy", "modify",
                                       "--name", name,
                                       "--strong-ntlm-policy", "Required")
        self.assertIsNone(result, msg=err)

        # Verify fields were changed.
        policy = self.get_authentication_policy(name)
        self.assertEqual(str(policy["msDS-StrongNTLMPolicy"]), "2")

        # Check an invalid choice.
        with self.assertRaises((OptionValueError, SystemExit)):
            self.runcmd("domain", "auth", "policy", "modify",
                        "--name", name,
                        "--strong-ntlm-policy", "Invalid")

        # It is difficult to test the error message text for invalid
        # choices because inside optparse it will raise OptionValueError
        # followed by raising SystemExit(2).

    def test_modify__user_tgt_lifetime_mins(self):
        """Test modifying an authentication policy --user-tgt-lifetime-mins.

        This includes checking the upper and lower bounds.
        """
        name = "modifyUserTGTLifetime"

        # Create a policy to modify for this test.
        self.addCleanup(self.delete_authentication_policy,
                        name=name, force=True)
        self.runcmd("domain", "auth", "policy", "create", "--name", name)

        result, out, err = self.runcmd("domain", "auth", "policy", "modify",
                                       "--name", name,
                                       "--user-tgt-lifetime-mins", "120")
        self.assertIsNone(result, msg=err)

        # Verify field was changed.
        policy = self.get_authentication_policy(name)
        self.assertEqual(str(policy["msDS-UserTGTLifetime"]), "120")

        # check lower bounds (45)
        result, out, err = self.runcmd("domain", "auth", "policy", "modify",
                                       "--name", name,
                                       "--user-tgt-lifetime-mins", "44")
        self.assertEqual(result, -1)
        self.assertIn("--user-tgt-lifetime-mins must be between 45 and 2147483647",
                      err)

        # check upper bounds (2147483647)
        result, out, err = self.runcmd("domain", "auth", "policy", "modify",
                                       "--name", name,
                                       "--user-tgt-lifetime-mins", "2147483648")
        self.assertEqual(result, -1)
        self.assertIn("--user-tgt-lifetime-mins must be between 45 and 2147483647",
                      err)

    def test_modify__service_tgt_lifetime_mins(self):
        """Test modifying an authentication policy --service-tgt-lifetime-mins.

        This includes checking the upper and lower bounds.
        """
        name = "modifyServiceTGTLifetime"

        # Create a policy to modify for this test.
        self.addCleanup(self.delete_authentication_policy,
                        name=name, force=True)
        self.runcmd("domain", "auth", "policy", "create", "--name", name)

        result, out, err = self.runcmd("domain", "auth", "policy", "modify",
                                       "--name", name,
                                       "--service-tgt-lifetime-mins", "120")
        self.assertIsNone(result, msg=err)

        # Verify field was changed.
        policy = self.get_authentication_policy(name)
        self.assertEqual(str(policy["msDS-ServiceTGTLifetime"]), "120")

        # check lower bounds (45)
        result, out, err = self.runcmd("domain", "auth", "policy", "modify",
                                       "--name", name,
                                       "--service-tgt-lifetime-mins", "44")
        self.assertEqual(result, -1)
        self.assertIn("--service-tgt-lifetime-mins must be between 45 and 2147483647",
                      err)

        # check upper bounds (2147483647)
        result, out, err = self.runcmd("domain", "auth", "policy", "modify",
                                       "--name", name,
                                       "--service-tgt-lifetime-mins", "2147483648")
        self.assertEqual(result, -1)
        self.assertIn("--service-tgt-lifetime-mins must be between 45 and 2147483647",
                      err)

    def test_modify__computer_tgt_lifetime_mins(self):
        """Test modifying an authentication policy --computer-tgt-lifetime-mins.

        This includes checking the upper and lower bounds.
        """
        name = "modifyComputerTGTLifetime"

        # Create a policy to modify for this test.
        self.addCleanup(self.delete_authentication_policy,
                        name=name, force=True)
        self.runcmd("domain", "auth", "policy", "create", "--name", name)

        result, out, err = self.runcmd("domain", "auth", "policy", "modify",
                                       "--name", name,
                                       "--computer-tgt-lifetime-mins", "120")
        self.assertIsNone(result, msg=err)

        # Verify field was changed.
        policy = self.get_authentication_policy(name)
        self.assertEqual(str(policy["msDS-ComputerTGTLifetime"]), "120")

        # check lower bounds (45)
        result, out, err = self.runcmd("domain", "auth", "policy", "modify",
                                       "--name", name,
                                       "--computer-tgt-lifetime-mins", "44")
        self.assertEqual(result, -1)
        self.assertIn("--computer-tgt-lifetime-mins must be between 45 and 2147483647",
                      err)

        # check upper bounds (2147483647)
        result, out, err = self.runcmd("domain", "auth", "policy", "modify",
                                       "--name", name,
                                       "--computer-tgt-lifetime-mins", "2147483648")
        self.assertEqual(result, -1)
        self.assertIn("--computer-tgt-lifetime-mins must be between 45 and 2147483647",
                      err)

    def test_modify__name_missing(self):
        """Test modify authentication but the --name argument is missing."""
        result, out, err = self.runcmd("domain", "auth", "policy", "modify",
                                       "--description", "NewDescription")
        self.assertEqual(result, -1)
        self.assertIn("Argument --name is required.", err)

    def test_modify__notfound(self):
        """Test modify an authentication silo that doesn't exist."""
        result, out, err = self.runcmd("domain", "auth", "policy", "modify",
                                       "--name", "doesNotExist",
                                       "--description", "NewDescription")
        self.assertEqual(result, -1)
        self.assertIn("Authentication policy doesNotExist not found.", err)

    def test_modify__audit_enforce(self):
        """Test modify authentication policy using --audit and --enforce."""
        name = "modifyEnforce"

        # Create a policy to modify for this test.
        self.addCleanup(self.delete_authentication_policy,
                        name=name, force=True)
        self.runcmd("domain", "auth", "policy", "create", "--name", name)

        # Change to audit, the default is --enforce.
        result, out, err = self.runcmd("domain", "auth", "policy", "modify",
                                       "--name", name,
                                       "--audit")
        self.assertIsNone(result, msg=err)

        # Check that the policy was changed to --audit.
        policy = self.get_authentication_policy(name)
        self.assertEqual(str(policy["msDS-AuthNPolicyEnforced"]), "FALSE")

        result, out, err = self.runcmd("domain", "auth", "policy", "modify",
                                       "--name", name,
                                       "--enforce")
        self.assertIsNone(result, msg=err)

        # Check if the policy was changed back to --enforce.
        policy = self.get_authentication_policy(name)
        self.assertEqual(str(policy["msDS-AuthNPolicyEnforced"]), "TRUE")

    def test_modify__protect_unprotect(self):
        """Test modify authentication policy using --protect and --unprotect."""
        name = "modifyProtect"

        # Create a policy to modify for this test.
        self.addCleanup(self.delete_authentication_policy,
                        name=name, force=True)
        self.runcmd("domain", "auth", "policy", "create", "--name", name)

        utils = SDUtils(self.samdb)
        result, out, err = self.runcmd("domain", "auth", "policy", "modify",
                                       "--name", name,
                                       "--protect")
        self.assertIsNone(result, msg=err)

        # Check that claim type was protected.
        policy = self.get_authentication_policy(name)
        desc = utils.get_sd_as_sddl(policy["dn"])
        self.assertIn("(D;;DTSD;;;WD)", desc)

        result, out, err = self.runcmd("domain", "auth", "policy", "modify",
                                       "--name", name,
                                       "--unprotect")
        self.assertIsNone(result, msg=err)

        # Check that claim type was unprotected.
        policy = self.get_authentication_policy(name)
        desc = utils.get_sd_as_sddl(policy["dn"])
        self.assertNotIn("(D;;DTSD;;;WD)", desc)

    def test_modify__audit_enforce_together(self):
        """Test modify auth policy using both --audit and --enforce."""
        result, out, err = self.runcmd("domain", "auth", "policy", "modify",
                                       "--name", "User Policy",
                                       "--audit", "--enforce")
        self.assertEqual(result, -1)
        self.assertIn("--audit and --enforce cannot be used together.", err)

    def test_modify__protect_unprotect_together(self):
        """Test modify authentication policy using --protect and --unprotect."""
        result, out, err = self.runcmd("domain", "auth", "policy", "modify",
                                       "--name", "User Policy",
                                       "--protect", "--unprotect")
        self.assertEqual(result, -1)
        self.assertIn("--protect and --unprotect cannot be used together.", err)

    def test_modify__fails(self):
        """Test modifying an authentication policy, but it fails."""
        # Raise ModelError when ldb.add() is called.
        with patch.object(SamDB, "modify") as modify_mock:
            modify_mock.side_effect = ModelError("Custom error message")
            result, out, err = self.runcmd("domain", "auth", "policy", "modify",
                                           "--name", "User Policy",
                                           "--description", "New description")
            self.assertEqual(result, -1)
            self.assertIn("Custom error message", err)

    def test_delete__success(self):
        """Test deleting an authentication policy that is not protected."""
        # Create non-protected authentication policy.
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name=deleteTest")
        self.assertIsNone(result, msg=err)
        policy = self.get_authentication_policy("deleteTest")
        self.assertIsNotNone(policy)

        # Do the deletion.
        result, out, err = self.runcmd("domain", "auth", "policy", "delete",
                                       "--name", "deleteTest")
        self.assertIsNone(result, msg=err)

        # Authentication policy shouldn't exist anymore.
        policy = self.get_authentication_policy("deleteTest")
        self.assertIsNone(policy)

    def test_delete__protected(self):
        """Test deleting a protected auth policy, with and without --force."""
        # Create protected authentication policy.
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name=deleteProtected",
                                       "--protect")
        self.assertIsNone(result, msg=err)
        policy = self.get_authentication_policy("deleteProtected")
        self.assertIsNotNone(policy)

        # Do the deletion.
        result, out, err = self.runcmd("domain", "auth", "policy", "delete",
                                       "--name=deleteProtected")
        self.assertEqual(result, -1)

        # Authentication silo should still exist.
        policy = self.get_authentication_policy("deleteProtected")
        self.assertIsNotNone(policy)

        # Try a force delete instead.
        result, out, err = self.runcmd("domain", "auth", "policy", "delete",
                                       "--name=deleteProtected", "--force")
        self.assertIsNone(result, msg=err)

        # Authentication silo shouldn't exist anymore.
        policy = self.get_authentication_policy("deleteProtected")
        self.assertIsNone(policy)

    def test_delete__notfound(self):
        """Test deleting an authentication policy that doesn't exist."""
        result, out, err = self.runcmd("domain", "auth", "policy", "delete",
                                       "--name", "doesNotExist")
        self.assertEqual(result, -1)
        self.assertIn("Authentication policy doesNotExist not found.", err)

    def test_delete__name_required(self):
        """Test deleting an authentication policy without --name argument."""
        result, out, err = self.runcmd("domain", "auth", "policy", "delete")
        self.assertEqual(result, -1)
        self.assertIn("Argument --name is required.", err)

    def test_delete__force_fails(self):
        """Test deleting an authentication policy with --force, but it fails."""
        # Create protected authentication policy.
        self.addCleanup(self.delete_authentication_policy,
                        name="deleteForceFail", force=True)
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name=deleteForceFail",
                                       "--protect")
        self.assertIsNone(result, msg=err)
        policy = self.get_authentication_policy("deleteForceFail")
        self.assertIsNotNone(policy)

        # Try delete with --force.
        # Patch SDUtils.dacl_delete_aces with a Mock that raises ModelError.
        with patch.object(SDUtils, "dacl_delete_aces") as delete_mock:
            delete_mock.side_effect = ModelError("Custom error message")
            result, out, err = self.runcmd("domain", "auth", "policy", "delete",
                                           "--name", "deleteForceFail",
                                           "--force")
            self.assertEqual(result, -1)
            self.assertIn("Custom error message", err)

    def test_delete__fails(self):
        """Test deleting an authentication policy, but it fails."""
        # Create regular authentication policy.
        self.addCleanup(self.delete_authentication_policy,
                        name="regularPolicy", force=True)
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name=regularPolicy")
        self.assertIsNone(result, msg=err)
        policy = self.get_authentication_policy("regularPolicy")
        self.assertIsNotNone(policy)

        # Raise ModelError when ldb.delete() is called.
        with patch.object(SamDB, "delete") as delete_mock:
            delete_mock.side_effect = ModelError("Custom error message")
            result, out, err = self.runcmd("domain", "auth", "policy", "delete",
                                           "--name", "regularPolicy")
            self.assertEqual(result, -1)
            self.assertIn("Custom error message", err)

            # When not using --force we get a hint.
            self.assertIn("Try --force", err)

    def test_delete__protected_fails(self):
        """Test deleting an authentication policy, but it fails."""
        # Create protected authentication policy.
        self.addCleanup(self.delete_authentication_policy,
                        name="protectedPolicy", force=True)
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name=protectedPolicy",
                                       "--protect")
        self.assertIsNone(result, msg=err)
        policy = self.get_authentication_policy("protectedPolicy")
        self.assertIsNotNone(policy)

        # Raise ModelError when ldb.delete() is called.
        with patch.object(SamDB, "delete") as delete_mock:
            delete_mock.side_effect = ModelError("Custom error message")
            result, out, err = self.runcmd("domain", "auth", "policy", "delete",
                                           "--name", "protectedPolicy",
                                           "--force")
            self.assertEqual(result, -1)
            self.assertIn("Custom error message", err)

            # When using --force we don't get the hint.
            self.assertNotIn("Try --force", err)
