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
from samba.ndr import ndr_pack, ndr_unpack
from samba.netcmd.domain.models.exceptions import ModelError
from samba.nt_time import NT_TICKS_PER_SEC
from samba.samdb import SamDB
from samba.sd_utils import SDUtils

from .silo_base import SiloTest


def mins_to_tgt_lifetime(minutes):
    """Convert minutes to the tgt_lifetime attributes unit which is 10^-7 seconds"""
    if minutes is not None:
        return minutes * 60 * NT_TICKS_PER_SEC
    return minutes

class AuthPolicyCmdTestCase(SiloTest):

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
        name = self.unique_name()

        self.addCleanup(self.delete_authentication_policy, name=name, force=True)
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", name)
        self.assertIsNone(result, msg=err)

        # Check policy that was created
        policy = self.get_authentication_policy(name)
        self.assertEqual(str(policy["cn"]), name)
        self.assertEqual(str(policy["msDS-AuthNPolicyEnforced"]), "TRUE")

    def test_create__description(self):
        """Test creating a new authentication policy with description set."""
        name = self.unique_name()

        self.addCleanup(self.delete_authentication_policy, name=name, force=True)
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", name,
                                       "--description", "Custom Description")
        self.assertIsNone(result, msg=err)

        # Check policy description
        policy = self.get_authentication_policy(name)
        self.assertEqual(str(policy["cn"]), name)
        self.assertEqual(str(policy["description"]), "Custom Description")

    def test_create__user_tgt_lifetime_mins(self):
        """Test create a new authentication policy with --user-tgt-lifetime-mins.

        Also checks the upper and lower bounds are handled.
        """
        name = self.unique_name()

        self.addCleanup(self.delete_authentication_policy, name=name, force=True)
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", name,
                                       "--user-tgt-lifetime-mins", "60")
        self.assertIsNone(result, msg=err)

        # Check policy fields.
        policy = self.get_authentication_policy(name)
        self.assertEqual(str(policy["cn"]), name)
        self.assertEqual(str(policy["msDS-UserTGTLifetime"]), str(mins_to_tgt_lifetime(60)))

        # check lower bounds (45)
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", name + "Lower",
                                       "--user-tgt-lifetime-mins", "44")
        self.assertEqual(result, -1)
        self.assertIn("--user-tgt-lifetime-mins must be between 45 and 2147483647",
                      err)

        # check upper bounds (2147483647)
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", name + "Upper",
                                       "--user-tgt-lifetime-mins", "2147483648")
        self.assertEqual(result, -1)
        self.assertIn("--user-tgt-lifetime-mins must be between 45 and 2147483647",
                      err)

    def test_create__user_allowed_to_authenticate_from_device_group(self):
        """Tests the --user-allowed-to-authenticate-from-device-group shortcut."""
        name = self.unique_name()
        expected = "O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of_any {SID(%s)}))" % (
            self.device_group.object_sid)

        self.addCleanup(self.delete_authentication_policy, name=name, force=True)
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", name,
                                       "--user-allowed-to-authenticate-from-device-group",
                                       self.device_group.name)
        self.assertIsNone(result, msg=err)

        # Check policy fields.
        policy = self.get_authentication_policy(name)
        self.assertEqual(str(policy["cn"]), name)

        # Check generated SDDL.
        desc = policy["msDS-UserAllowedToAuthenticateFrom"][0]
        sddl = ndr_unpack(security.descriptor, desc).as_sddl()
        self.assertEqual(sddl, expected)

    def test_create__user_allowed_to_authenticate_from_device_silo(self):
        """Tests the --user-allowed-to-authenticate-from-device-silo shortcut."""
        name = self.unique_name()

        self.addCleanup(self.delete_authentication_policy, name=name, force=True)
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", name,
                                       "--user-allowed-to-authenticate-from-device-silo",
                                       "Developers")
        self.assertIsNone(result, msg=err)

        # Check policy fields.
        policy = self.get_authentication_policy(name)
        self.assertEqual(str(policy["cn"]), name)

        # Check generated SDDL.
        desc = policy["msDS-UserAllowedToAuthenticateFrom"][0]
        sddl = ndr_unpack(security.descriptor, desc).as_sddl()
        self.assertEqual(
            sddl,
            'O:SYG:SYD:(XA;OICI;CR;;;WD;(@USER.ad://ext/AuthenticationSilo == "Developers"))')

    def test_create__user_allowed_to_authenticate_to_by_group(self):
        """Tests the --user-allowed-to-authenticate-to-by-group shortcut."""
        name = self.unique_name()
        expected = "O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of_any {SID(%s)}))" % (
            self.device_group.object_sid)

        # Create a user with authenticate to by group attribute.
        self.addCleanup(self.delete_authentication_policy, name=name, force=True)
        result, out, err = self.runcmd(
            "domain", "auth", "policy", "create", "--name", name,
            "--user-allowed-to-authenticate-to-by-group",
            self.device_group.name)
        self.assertIsNone(result, msg=err)

        # Check user allowed to authenticate to field was modified.
        policy = self.get_authentication_policy(name)
        self.assertEqual(str(policy["cn"]), name)
        desc = policy["msDS-UserAllowedToAuthenticateTo"][0]
        sddl = ndr_unpack(security.descriptor, desc).as_sddl()
        self.assertEqual(sddl, expected)

    def test_create__user_allowed_to_authenticate_to_by_silo(self):
        """Tests the --user-allowed-to-authenticate-to-by-silo shortcut."""
        name = self.unique_name()
        expected = ('O:SYG:SYD:(XA;OICI;CR;;;WD;(@USER.ad://ext/'
                    'AuthenticationSilo == "QA"))')

        # Create a user with authenticate to by silo attribute.
        self.addCleanup(self.delete_authentication_policy, name=name, force=True)
        result, out, err = self.runcmd(
            "domain", "auth", "policy", "create", "--name", name,
            "--user-allowed-to-authenticate-to-by-silo", "QA")
        self.assertIsNone(result, msg=err)

        # Check user allowed to authenticate to field was modified.
        policy = self.get_authentication_policy(name)
        self.assertEqual(str(policy["cn"]), name)
        desc = policy["msDS-UserAllowedToAuthenticateTo"][0]
        sddl = ndr_unpack(security.descriptor, desc).as_sddl()
        self.assertEqual(sddl, expected)

    def test_create__service_tgt_lifetime_mins(self):
        """Test create a new authentication policy with --service-tgt-lifetime-mins.

        Also checks the upper and lower bounds are handled.
        """
        name = self.unique_name()

        self.addCleanup(self.delete_authentication_policy, name=name, force=True)
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", name,
                                       "--service-tgt-lifetime-mins", "60")
        self.assertIsNone(result, msg=err)

        # Check policy fields.
        policy = self.get_authentication_policy(name)
        self.assertEqual(str(policy["cn"]), name)
        self.assertEqual(str(policy["msDS-ServiceTGTLifetime"]), str(mins_to_tgt_lifetime(60)))

        # check lower bounds (45)
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", name,
                                       "--service-tgt-lifetime-mins", "44")
        self.assertEqual(result, -1)
        self.assertIn("--service-tgt-lifetime-mins must be between 45 and 2147483647",
                      err)

        # check upper bounds (2147483647)
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", name,
                                       "--service-tgt-lifetime-mins", "2147483648")
        self.assertEqual(result, -1)
        self.assertIn("--service-tgt-lifetime-mins must be between 45 and 2147483647",
                      err)

    def test_create__service_allowed_to_authenticate_from_device_group(self):
        """Tests the --service-allowed-to-authenticate-from-device-group shortcut."""
        name = self.unique_name()
        expected = "O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of_any {SID(%s)}))" % (
            self.device_group.object_sid)

        self.addCleanup(self.delete_authentication_policy, name=name, force=True)
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", name,
                                       "--service-allowed-to-authenticate-from-device-group",
                                       self.device_group.name)
        self.assertIsNone(result, msg=err)

        # Check policy fields.
        policy = self.get_authentication_policy(name)
        self.assertEqual(str(policy["cn"]), name)

        # Check generated SDDL.
        desc = policy["msDS-ServiceAllowedToAuthenticateFrom"][0]
        sddl = ndr_unpack(security.descriptor, desc).as_sddl()
        self.assertEqual(sddl, expected)

    def test_create__service_allowed_to_authenticate_from_device_silo(self):
        """Tests the --service-allowed-to-authenticate-from-device-silo shortcut."""
        name = self.unique_name()

        self.addCleanup(self.delete_authentication_policy, name=name, force=True)
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", name,
                                       "--service-allowed-to-authenticate-from-device-silo",
                                       "Managers")
        self.assertIsNone(result, msg=err)

        # Check policy fields.
        policy = self.get_authentication_policy(name)
        self.assertEqual(str(policy["cn"]), name)
        desc = policy["msDS-ServiceAllowedToAuthenticateFrom"][0]

        # Check generated SDDL.
        sddl = ndr_unpack(security.descriptor, desc).as_sddl()
        self.assertEqual(
            sddl,
            'O:SYG:SYD:(XA;OICI;CR;;;WD;(@USER.ad://ext/AuthenticationSilo == "Managers"))')

    def test_create__service_allowed_to_authenticate_to_by_group(self):
        """Tests the --service-allowed-to-authenticate-to-by-group shortcut."""
        name = self.unique_name()
        expected = "O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of_any {SID(%s)}))" % (
            self.device_group.object_sid)

        # Create a user with authenticate to by group attribute.
        self.addCleanup(self.delete_authentication_policy, name=name, force=True)
        result, out, err = self.runcmd(
            "domain", "auth", "policy", "create", "--name", name,
            "--service-allowed-to-authenticate-to-by-group",
            self.device_group.name)
        self.assertIsNone(result, msg=err)

        # Check user allowed to authenticate to field was modified.
        policy = self.get_authentication_policy(name)
        self.assertEqual(str(policy["cn"]), name)
        desc = policy["msDS-ServiceAllowedToAuthenticateTo"][0]
        sddl = ndr_unpack(security.descriptor, desc).as_sddl()
        self.assertEqual(sddl, expected)

    def test_create__service_allowed_to_authenticate_to_by_silo(self):
        """Tests the --service-allowed-to-authenticate-to-by-silo shortcut."""
        name = self.unique_name()
        expected = ('O:SYG:SYD:(XA;OICI;CR;;;WD;(@USER.ad://ext/'
                    'AuthenticationSilo == "Managers"))')

        # Create a user with authenticate to by silo attribute.
        self.addCleanup(self.delete_authentication_policy, name=name, force=True)
        result, out, err = self.runcmd(
            "domain", "auth", "policy", "create", "--name", name,
            "--service-allowed-to-authenticate-to-by-silo", "Managers")
        self.assertIsNone(result, msg=err)

        # Check user allowed to authenticate to field was modified.
        policy = self.get_authentication_policy(name)
        self.assertEqual(str(policy["cn"]), name)
        desc = policy["msDS-ServiceAllowedToAuthenticateTo"][0]
        sddl = ndr_unpack(security.descriptor, desc).as_sddl()
        self.assertEqual(sddl, expected)

    def test_create__computer_tgt_lifetime_mins(self):
        """Test create a new authentication policy with --computer-tgt-lifetime-mins.

        Also checks the upper and lower bounds are handled.
        """
        name = self.unique_name()

        self.addCleanup(self.delete_authentication_policy, name=name, force=True)
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", name,
                                       "--computer-tgt-lifetime-mins", "60")
        self.assertIsNone(result, msg=err)

        # Check policy fields.
        policy = self.get_authentication_policy(name)
        self.assertEqual(str(policy["cn"]), name)
        self.assertEqual(str(policy["msDS-ComputerTGTLifetime"]), str(mins_to_tgt_lifetime(60)))

        # check lower bounds (45)
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", name + "Lower",
                                       "--computer-tgt-lifetime-mins", "44")
        self.assertEqual(result, -1)
        self.assertIn("--computer-tgt-lifetime-mins must be between 45 and 2147483647",
                      err)

        # check upper bounds (2147483647)
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", name + "Upper",
                                       "--computer-tgt-lifetime-mins", "2147483648")
        self.assertEqual(result, -1)
        self.assertIn("--computer-tgt-lifetime-mins must be between 45 and 2147483647",
                      err)

    def test_create__computer_allowed_to_authenticate_to_by_group(self):
        """Tests the --computer-allowed-to-authenticate-to-by-group shortcut."""
        name = self.unique_name()
        expected = "O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of_any {SID(%s)}))" % (
            self.device_group.object_sid)

        # Create a user with authenticate to by group attribute.
        self.addCleanup(self.delete_authentication_policy, name=name, force=True)
        result, out, err = self.runcmd(
            "domain", "auth", "policy", "create", "--name", name,
            "--computer-allowed-to-authenticate-to-by-group",
            self.device_group.name)
        self.assertIsNone(result, msg=err)

        # Check user allowed to authenticate to field was modified.
        policy = self.get_authentication_policy(name)
        self.assertEqual(str(policy["cn"]), name)
        desc = policy["msDS-ComputerAllowedToAuthenticateTo"][0]
        sddl = ndr_unpack(security.descriptor, desc).as_sddl()
        self.assertEqual(sddl, expected)

    def test_create__computer_allowed_to_authenticate_to_by_silo(self):
        """Tests the --computer-allowed-to-authenticate-to-by-silo shortcut."""
        name = self.unique_name()
        expected = ('O:SYG:SYD:(XA;OICI;CR;;;WD;(@USER.ad://ext/'
                    'AuthenticationSilo == "QA"))')

        # Create a user with authenticate to by silo attribute.
        self.addCleanup(self.delete_authentication_policy, name=name, force=True)
        result, out, err = self.runcmd(
            "domain", "auth", "policy", "create", "--name", name,
            "--computer-allowed-to-authenticate-to-by-silo", "QA")
        self.assertIsNone(result, msg=err)

        # Check user allowed to authenticate to field was modified.
        policy = self.get_authentication_policy(name)
        self.assertEqual(str(policy["cn"]), name)
        desc = policy["msDS-ComputerAllowedToAuthenticateTo"][0]
        sddl = ndr_unpack(security.descriptor, desc).as_sddl()
        self.assertEqual(sddl, expected)

    def test_create__valid_sddl(self):
        """Test creating a new authentication policy with valid SDDL in a field."""
        name = self.unique_name()
        expected = "O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of {SID(AO)}))"

        self.addCleanup(self.delete_authentication_policy, name=name, force=True)
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", name,
                                       "--user-allowed-to-authenticate-from",
                                       expected)
        self.assertIsNone(result, msg=err)

        # Check policy fields.
        policy = self.get_authentication_policy(name)
        self.assertEqual(str(policy["cn"]), name)
        desc = policy["msDS-UserAllowedToAuthenticateFrom"][0]
        sddl = ndr_unpack(security.descriptor, desc).as_sddl()
        self.assertEqual(sddl, expected)

    def test_create__invalid_sddl(self):
        """Test creating a new authentication policy with invalid SDDL in a field."""
        name = self.unique_name()

        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", name,
                                       "--user-allowed-to-authenticate-from",
                                       "*INVALID SDDL*")

        self.assertEqual(result, -1)
        self.assertIn("Unable to parse SDDL", err)
        self.assertIn(" *INVALID SDDL*\n ^\n expected '[OGDS]:' section start ", err)

    def test_create__invalid_sddl_conditional_ace(self):
        """Test creating a new authentication policy with invalid SDDL in a field."""
        sddl = "O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of {secret club}))"
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", "invalidSDDLPolicy2",
                                       "--user-allowed-to-authenticate-from",
                                       sddl)
        self.assertEqual(result, -1)
        self.assertIn("Unable to parse SDDL", err)
        self.assertIn(sddl, err)
        self.assertIn(f"\n{'^':>41}", err)
        self.assertIn("unexpected byte 0x73 's' parsing literal", err)
        self.assertNotIn("  File ", err)

    def test_create__invalid_sddl_conditional_ace_non_ascii(self):
        """Test creating a new authentication policy with invalid SDDL in a field."""
        sddl = 'O:SYG:SYD:(XA;OICI;CR;;;WD;(@User.āāēē == "łē¶ŧ¹⅓þōīŋ“đ¢ð»" && Member_of {secret club}))'
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", "invalidSDDLPolicy2",
                                       "--user-allowed-to-authenticate-from",
                                       sddl)
        self.assertEqual(result, -1)
        self.assertIn("Unable to parse SDDL", err)
        self.assertIn(sddl, err)
        self.assertIn(f"\n{'^':>76}\n", err)
        self.assertIn(" unexpected byte 0x73 's' parsing literal", err)
        self.assertNotIn("  File ", err)

    def test_create__invalid_sddl_normal_ace(self):
        """Test creating a new authentication policy with invalid SDDL in a field."""
        sddl = "O:SYG:SYD:(A;;;;ZZ)(XA;OICI;CR;;;WD;(Member_of {WD}))"
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", "invalidSDDLPolicy3",
                                       "--user-allowed-to-authenticate-from",
                                       sddl)
        self.assertEqual(result, -1)
        self.assertIn("Unable to parse SDDL", err)
        self.assertIn(sddl, err)
        self.assertIn(f"\n{'^':>13}", err)
        self.assertIn("\n malformed ACE with only 4 ';'\n", err)
        self.assertNotIn("  File ", err)  # traceback marker

    def test_create__device_attribute_in_sddl_allowed_to(self):
        """Test creating a new authentication policy that uses
        user-allowed-to-authenticate-to with a device attribute."""

        sddl = 'O:SYG:SYD:(XA;OICI;CR;;;WD;(@Device.claim == "foo"))'

        name = self.unique_name()
        self.addCleanup(self.delete_authentication_policy, name=name)
        result, _, err = self.runcmd("domain", "auth", "policy", "create",
                                     "--name", name,
                                     "--user-allowed-to-authenticate-to",
                                     sddl)
        self.assertIsNone(result, msg=err)

    def test_create__device_operator_in_sddl_allowed_to(self):
        """Test creating a new authentication policy that uses
        user-allowed-to-authenticate-to with a device operator."""

        sddl = 'O:SYG:SYD:(XA;OICI;CR;;;WD;(Not_Device_Member_of {SID(WD)}))'

        name = self.unique_name()
        self.addCleanup(self.delete_authentication_policy, name=name)
        result, _, err = self.runcmd("domain", "auth", "policy", "create",
                                     "--name", name,
                                     "--user-allowed-to-authenticate-to",
                                     sddl)
        self.assertIsNone(result, msg=err)

    def test_create__device_attribute_in_sddl_allowed_from(self):
        """Test creating a new authentication policy that uses
        user-allowed-to-authenticate-from with a device attribute."""

        sddl = 'O:SYG:SYD:(XA;OICI;CR;;;WD;(@Device.claim == "foo"))'

        name = self.unique_name()
        result, _, err = self.runcmd("domain", "auth", "policy", "create",
                                     "--name", name,
                                     "--user-allowed-to-authenticate-from",
                                     sddl)
        self.assertEqual(result, -1)
        self.assertIn("Unable to parse SDDL", err)
        self.assertIn(sddl, err)
        self.assertIn(f"\n{'^':>31}\n", err)
        self.assertIn(" a device attribute is not applicable in this context "
                      "(did you intend a user attribute?)",
                      err)
        self.assertNotIn("  File ", err)

    def test_create__device_operator_in_sddl_allowed_from(self):
        """Test creating a new authentication policy that uses
        user-allowed-to-authenticate-from with a device operator."""

        sddl = 'O:SYG:SYD:(XA;OICI;CR;;;WD;(Not_Device_Member_of {SID(WD)}))'

        name = self.unique_name()
        result, _, err = self.runcmd("domain", "auth", "policy", "create",
                                     "--name", name,
                                     "--user-allowed-to-authenticate-from",
                                     sddl)
        self.assertEqual(result, -1)
        self.assertIn("Unable to parse SDDL", err)
        self.assertIn(sddl, err)
        self.assertIn(f"\n{'^':>30}\n", err)
        self.assertIn(" a device‐relative expression will never evaluate to "
                      "true in this context (did you intend a user‐relative "
                      "expression?)",
                      err)
        self.assertNotIn("  File ", err)

    def test_create__device_attribute_in_sddl_already_exists(self):
        """Test modifying an existing authentication policy that uses
        user-allowed-to-authenticate-from with a device attribute."""

        # The SDDL refers to ‘Device.claim’.
        sddl = 'O:SYG:SYD:(XA;OICI;CR;;;WD;(@Device.claim == "foo"))'
        domain_sid = security.dom_sid(self.samdb.get_domain_sid())
        descriptor = security.descriptor.from_sddl(sddl, domain_sid)

        # Manually create an authentication policy that refers to a device
        # attribute.

        name = self.unique_name()
        dn = self.get_authn_policies_dn()
        dn.add_child(f"CN={name}")
        message = {
            'dn': dn,
            'msDS-AuthNPolicyEnforced': b'TRUE',
            'objectClass': b'msDS-AuthNPolicy',
            'msDS-UserAllowedToAuthenticateFrom': ndr_pack(descriptor),
        }

        self.addCleanup(self.delete_authentication_policy, name=name)
        self.samdb.add(message)

        # Change the policy description. This should succeed, in spite of the
        # policy’s referring to a device attribute when it shouldn’t.
        result, _, err = self.runcmd("domain", "auth", "policy", "modify",
                                     "--name", name,
                                     "--description", "NewDescription")
        self.assertIsNone(result, msg=err)

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
        name = self.unique_name()

        self.addCleanup(self.delete_authentication_policy, name=name, force=True)
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", name,
                                       "--audit")
        self.assertIsNone(result, msg=err)

        # fetch and check policy
        policy = self.get_authentication_policy(name)
        self.assertEqual(str(policy["msDS-AuthNPolicyEnforced"]), "FALSE")

    def test_create__enforce(self):
        """Test create authentication policy with --enforce flag."""
        name = self.unique_name()

        self.addCleanup(self.delete_authentication_policy, name=name, force=True)
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", name,
                                       "--enforce")
        self.assertIsNone(result, msg=err)

        # fetch and check policy
        policy = self.get_authentication_policy(name)
        self.assertEqual(str(policy["msDS-AuthNPolicyEnforced"]), "TRUE")

    def test_create__audit_enforce_together(self):
        """Test create auth policy using both --audit and --enforce."""
        name = self.unique_name()

        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", name,
                                       "--audit", "--enforce")

        self.assertEqual(result, -1)
        self.assertIn("--audit and --enforce cannot be used together.", err)

    def test_create__protect_unprotect_together(self):
        """Test create authentication policy using --protect and --unprotect."""
        name = self.unique_name()

        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", name,
                                       "--protect", "--unprotect")

        self.assertEqual(result, -1)
        self.assertIn("--protect and --unprotect cannot be used together.", err)

    def test_create__user_allowed_to_authenticate_from_repeated(self):
        """Test repeating similar arguments doesn't make sense to use together.

        --user-allowed-to-authenticate-from
        --user-allowed-to-authenticate-from-device-silo
        """
        sddl = 'O:SYG:SYD:(XA;OICI;CR;;;WD;(@USER.ad://ext/AuthenticationSilo == "Developers"))'
        name = self.unique_name()

        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", name,
                                       "--user-allowed-to-authenticate-from",
                                       sddl,
                                       "--user-allowed-to-authenticate-from-device-silo",
                                       "Managers")

        self.assertEqual(result, -1)
        self.assertIn("--user-allowed-to-authenticate-from argument repeated 2 times.", err)

    def test_create__user_allowed_to_authenticate_to_repeated(self):
        """Test repeating similar arguments doesn't make sense to use together.

        --user-allowed-to-authenticate-to
        --user-allowed-to-authenticate-to-by-silo
        """
        sddl = 'O:SYG:SYD:(XA;OICI;CR;;;WD;(@USER.ad://ext/AuthenticationSilo == "Developers"))'
        name = self.unique_name()

        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", name,
                                       "--user-allowed-to-authenticate-to",
                                       sddl,
                                       "--user-allowed-to-authenticate-to-by-silo",
                                       "Managers")

        self.assertEqual(result, -1)
        self.assertIn("--user-allowed-to-authenticate-to argument repeated 2 times.", err)

    def test_create__service_allowed_to_authenticate_from_repeated(self):
        """Test repeating similar arguments doesn't make sense to use together.

        --service-allowed-to-authenticate-from
        --service-allowed-to-authenticate-from-device-silo
        """
        sddl = 'O:SYG:SYD:(XA;OICI;CR;;;WD;(@USER.ad://ext/AuthenticationSilo == "Managers"))'
        name = self.unique_name()

        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", name,
                                       "--service-allowed-to-authenticate-from",
                                       sddl,
                                       "--service-allowed-to-authenticate-from-device-silo",
                                       "QA")

        self.assertEqual(result, -1)
        self.assertIn("--service-allowed-to-authenticate-from argument repeated 2 times.", err)

    def test_create__service_allowed_to_authenticate_to_repeated(self):
        """Test repeating similar arguments doesn't make sense to use together.

        --service-allowed-to-authenticate-to
        --service-allowed-to-authenticate-to-by-silo
        """
        sddl = 'O:SYG:SYD:(XA;OICI;CR;;;WD;(@USER.ad://ext/AuthenticationSilo == "Managers"))'
        name = self.unique_name()

        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", name,
                                       "--service-allowed-to-authenticate-to",
                                       sddl,
                                       "--service-allowed-to-authenticate-to-by-silo",
                                       "QA")

        self.assertEqual(result, -1)
        self.assertIn("--service-allowed-to-authenticate-to argument repeated 2 times.", err)

    def test_create__computer_allowed_to_authenticate_to_repeated(self):
        """Test repeating similar arguments doesn't make sense to use together.

        --computer-allowed-to-authenticate-to
        --computer-allowed-to-authenticate-to-by-silo
        """
        sddl = 'O:SYG:SYD:(XA;OICI;CR;;;WD;(@USER.ad://ext/AuthenticationSilo == "Managers"))'
        name = self.unique_name()

        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", name,
                                       "--computer-allowed-to-authenticate-to",
                                       sddl,
                                       "--computer-allowed-to-authenticate-to-by-silo",
                                       "QA")

        self.assertEqual(result, -1)
        self.assertIn("--computer-allowed-to-authenticate-to argument repeated 2 times.", err)

    def test_create__fails(self):
        """Test creating an authentication policy, but it fails."""
        name = self.unique_name()

        # Raise ModelError when ldb.add() is called.
        with patch.object(SamDB, "add") as add_mock:
            add_mock.side_effect = ModelError("Custom error message")
            result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                           "--name", name)
            self.assertEqual(result, -1)
            self.assertIn("Custom error message", err)

    def test_modify__description(self):
        """Test modifying an authentication policy description."""
        name = self.unique_name()

        # Create a policy to modify for this test.
        self.addCleanup(self.delete_authentication_policy, name=name, force=True)
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
        name = self.unique_name()

        # Create a policy to modify for this test.
        self.addCleanup(self.delete_authentication_policy, name=name, force=True)
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
        name = self.unique_name()

        # Create a policy to modify for this test.
        self.addCleanup(self.delete_authentication_policy, name=name, force=True)
        self.runcmd("domain", "auth", "policy", "create", "--name", name)

        result, out, err = self.runcmd("domain", "auth", "policy", "modify",
                                       "--name", name,
                                       "--user-tgt-lifetime-mins", "120")
        self.assertIsNone(result, msg=err)

        # Verify field was changed.
        policy = self.get_authentication_policy(name)
        self.assertEqual(str(policy["msDS-UserTGTLifetime"]), str(mins_to_tgt_lifetime(120)))

        # check lower bounds (45)
        result, out, err = self.runcmd("domain", "auth", "policy", "modify",
                                       "--name", name + "Lower",
                                       "--user-tgt-lifetime-mins", "44")
        self.assertEqual(result, -1)
        self.assertIn("--user-tgt-lifetime-mins must be between 45 and 2147483647",
                      err)

        # check upper bounds (2147483647)
        result, out, err = self.runcmd("domain", "auth", "policy", "modify",
                                       "--name", name + "Upper",
                                       "--user-tgt-lifetime-mins", "2147483648")
        self.assertEqual(result, -1)
        self.assertIn("--user-tgt-lifetime-mins must be between 45 and 2147483647",
                      err)

    def test_modify__service_tgt_lifetime_mins(self):
        """Test modifying an authentication policy --service-tgt-lifetime-mins.

        This includes checking the upper and lower bounds.
        """
        name = self.unique_name()

        # Create a policy to modify for this test.
        self.addCleanup(self.delete_authentication_policy, name=name, force=True)
        self.runcmd("domain", "auth", "policy", "create", "--name", name)

        result, out, err = self.runcmd("domain", "auth", "policy", "modify",
                                       "--name", name,
                                       "--service-tgt-lifetime-mins", "120")
        self.assertIsNone(result, msg=err)

        # Verify field was changed.
        policy = self.get_authentication_policy(name)
        self.assertEqual(str(policy["msDS-ServiceTGTLifetime"]), str(mins_to_tgt_lifetime(120)))

        # check lower bounds (45)
        result, out, err = self.runcmd("domain", "auth", "policy", "modify",
                                       "--name", name + "Lower",
                                       "--service-tgt-lifetime-mins", "44")
        self.assertEqual(result, -1)
        self.assertIn("--service-tgt-lifetime-mins must be between 45 and 2147483647",
                      err)

        # check upper bounds (2147483647)
        result, out, err = self.runcmd("domain", "auth", "policy", "modify",
                                       "--name", name + "Upper",
                                       "--service-tgt-lifetime-mins", "2147483648")
        self.assertEqual(result, -1)
        self.assertIn("--service-tgt-lifetime-mins must be between 45 and 2147483647",
                      err)

    def test_modify__computer_tgt_lifetime_mins(self):
        """Test modifying an authentication policy --computer-tgt-lifetime-mins.

        This includes checking the upper and lower bounds.
        """
        name = self.unique_name()

        # Create a policy to modify for this test.
        self.addCleanup(self.delete_authentication_policy, name=name, force=True)
        self.runcmd("domain", "auth", "policy", "create", "--name", name)

        result, out, err = self.runcmd("domain", "auth", "policy", "modify",
                                       "--name", name,
                                       "--computer-tgt-lifetime-mins", "120")
        self.assertIsNone(result, msg=err)

        # Verify field was changed.
        policy = self.get_authentication_policy(name)
        self.assertEqual(str(policy["msDS-ComputerTGTLifetime"]), str(mins_to_tgt_lifetime(120)))

        # check lower bounds (45)
        result, out, err = self.runcmd("domain", "auth", "policy", "modify",
                                       "--name", name + "Lower",
                                       "--computer-tgt-lifetime-mins", "44")
        self.assertEqual(result, -1)
        self.assertIn("--computer-tgt-lifetime-mins must be between 45 and 2147483647",
                      err)

        # check upper bounds (2147483647)
        result, out, err = self.runcmd("domain", "auth", "policy", "modify",
                                       "--name", name + "Upper",
                                       "--computer-tgt-lifetime-mins", "2147483648")
        self.assertEqual(result, -1)
        self.assertIn("--computer-tgt-lifetime-mins must be between 45 and 2147483647",
                      err)

    def test_modify__user_allowed_to_authenticate_from(self):
        """Modify authentication policy user allowed to authenticate from."""
        name = self.unique_name()
        expected = "O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of {SID(AO)}))"

        # Create a policy to modify for this test.
        self.addCleanup(self.delete_authentication_policy, name=name, force=True)
        self.runcmd("domain", "auth", "policy", "create", "--name", name)

        # Modify user allowed to authenticate from field
        result, out, err = self.runcmd("domain", "auth", "policy", "modify",
                                       "--name", name,
                                       "--user-allowed-to-authenticate-from",
                                       expected)
        self.assertIsNone(result, msg=err)

        # Check user allowed to authenticate from field was modified.
        policy = self.get_authentication_policy(name)
        self.assertEqual(str(policy["cn"]), name)
        desc = policy["msDS-UserAllowedToAuthenticateFrom"][0]
        sddl = ndr_unpack(security.descriptor, desc).as_sddl()
        self.assertEqual(sddl, expected)

    def test_modify__user_allowed_to_authenticate_from_device_group(self):
        """Test the --user-allowed-to-authenticate-from-device-group shortcut."""
        name = self.unique_name()
        expected = "O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of_any {SID(%s)}))" % (
            self.device_group.object_sid)

        # Create a policy to modify for this test.
        self.addCleanup(self.delete_authentication_policy, name=name, force=True)
        self.runcmd("domain", "auth", "policy", "create", "--name", name)

        # Modify user allowed to authenticate from silo field
        result, out, err = self.runcmd("domain", "auth", "policy", "modify",
                                       "--name", name,
                                       "--user-allowed-to-authenticate-from-device-group",
                                       self.device_group.name)
        self.assertIsNone(result, msg=err)

        # Check generated SDDL.
        policy = self.get_authentication_policy(name)
        desc = policy["msDS-UserAllowedToAuthenticateFrom"][0]
        sddl = ndr_unpack(security.descriptor, desc).as_sddl()
        self.assertEqual(sddl, expected)

    def test_modify__user_allowed_to_authenticate_from_device_silo(self):
        """Test the --user-allowed-to-authenticate-from-device-silo shortcut."""
        name = self.unique_name()

        # Create a policy to modify for this test.
        self.addCleanup(self.delete_authentication_policy, name=name, force=True)
        self.runcmd("domain", "auth", "policy", "create", "--name", name)

        # Modify user allowed to authenticate from silo field
        result, out, err = self.runcmd("domain", "auth", "policy", "modify",
                                       "--name", name,
                                       "--user-allowed-to-authenticate-from-device-silo",
                                       "QA")
        self.assertIsNone(result, msg=err)

        # Check generated SDDL.
        policy = self.get_authentication_policy(name)
        desc = policy["msDS-UserAllowedToAuthenticateFrom"][0]
        sddl = ndr_unpack(security.descriptor, desc).as_sddl()
        self.assertEqual(
            sddl,
            'O:SYG:SYD:(XA;OICI;CR;;;WD;(@USER.ad://ext/AuthenticationSilo == "QA"))')

    def test_modify__user_allowed_to_authenticate_to(self):
        """Modify authentication policy user allowed to authenticate to."""
        name = self.unique_name()
        expected = "O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of {SID(AO)}))"

        # Create a policy to modify for this test.
        self.addCleanup(self.delete_authentication_policy, name=name, force=True)
        self.runcmd("domain", "auth", "policy", "create", "--name", name)

        # Modify user allowed to authenticate to field
        result, out, err = self.runcmd("domain", "auth", "policy", "modify",
                                       "--name", name,
                                       "--user-allowed-to-authenticate-to",
                                       expected)
        self.assertIsNone(result, msg=err)

        # Check user allowed to authenticate to field was modified.
        policy = self.get_authentication_policy(name)
        self.assertEqual(str(policy["cn"]), name)
        desc = policy["msDS-UserAllowedToAuthenticateTo"][0]
        sddl = ndr_unpack(security.descriptor, desc).as_sddl()
        self.assertEqual(sddl, expected)

    def test_modify__user_allowed_to_authenticate_to_by_group(self):
        """Tests the --user-allowed-to-authenticate-to-by-group shortcut."""
        name = self.unique_name()
        expected = "O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of_any {SID(%s)}))" % (
            self.device_group.object_sid)

        # Create a policy to modify for this test.
        self.addCleanup(self.delete_authentication_policy, name=name, force=True)
        self.runcmd("domain", "auth", "policy", "create", "--name", name)

        # Modify user allowed to authenticate to field
        result, out, err = self.runcmd("domain", "auth", "policy", "modify",
                                       "--name", name,
                                       "--user-allowed-to-authenticate-to-by-group",
                                       self.device_group.name)
        self.assertIsNone(result, msg=err)

        # Check user allowed to authenticate to field was modified.
        policy = self.get_authentication_policy(name)
        self.assertEqual(str(policy["cn"]), name)
        desc = policy["msDS-UserAllowedToAuthenticateTo"][0]
        sddl = ndr_unpack(security.descriptor, desc).as_sddl()
        self.assertEqual(sddl, expected)

    def test_modify__user_allowed_to_authenticate_to_by_silo(self):
        """Tests the --user-allowed-to-authenticate-to-by-silo shortcut."""
        name = self.unique_name()
        expected = ('O:SYG:SYD:(XA;OICI;CR;;;WD;(@USER.ad://ext/'
                    'AuthenticationSilo == "Developers"))')

        # Create a policy to modify for this test.
        self.addCleanup(self.delete_authentication_policy, name=name, force=True)
        self.runcmd("domain", "auth", "policy", "create", "--name", name)

        # Modify user allowed to authenticate to field
        result, out, err = self.runcmd("domain", "auth", "policy", "modify",
                                       "--name", name,
                                       "--user-allowed-to-authenticate-to-by-silo",
                                       "Developers")
        self.assertIsNone(result, msg=err)

        # Check user allowed to authenticate to field was modified.
        policy = self.get_authentication_policy(name)
        self.assertEqual(str(policy["cn"]), name)
        desc = policy["msDS-UserAllowedToAuthenticateTo"][0]
        sddl = ndr_unpack(security.descriptor, desc).as_sddl()
        self.assertEqual(sddl, expected)

    def test_modify__service_allowed_to_authenticate_from(self):
        """Modify authentication policy service allowed to authenticate from."""
        name = self.unique_name()
        expected = "O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of {SID(AO)}))"

        # Create a policy to modify for this test.
        self.addCleanup(self.delete_authentication_policy, name=name, force=True)
        self.runcmd("domain", "auth", "policy", "create", "--name", name)

        # Modify service allowed to authenticate from field
        result, out, err = self.runcmd("domain", "auth", "policy", "modify",
                                       "--name", name,
                                       "--service-allowed-to-authenticate-from",
                                       expected)
        self.assertIsNone(result, msg=err)

        # Check service allowed to authenticate from field was modified.
        policy = self.get_authentication_policy(name)
        self.assertEqual(str(policy["cn"]), name)
        desc = policy["msDS-ServiceAllowedToAuthenticateFrom"][0]
        sddl = ndr_unpack(security.descriptor, desc).as_sddl()
        self.assertEqual(sddl, expected)

    def test_modify__service_allowed_to_authenticate_from_device_group(self):
        """Test the --service-allowed-to-authenticate-from-device-group shortcut."""
        name = self.unique_name()
        expected = "O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of_any {SID(%s)}))" % (
            self.device_group.object_sid)

        # Create a policy to modify for this test.
        self.addCleanup(self.delete_authentication_policy, name=name, force=True)
        self.runcmd("domain", "auth", "policy", "create", "--name", name)

        # Modify user allowed to authenticate from silo field
        result, out, err = self.runcmd("domain", "auth", "policy", "modify",
                                       "--name", name,
                                       "--service-allowed-to-authenticate-from-device-group",
                                       self.device_group.name)
        self.assertIsNone(result, msg=err)

        # Check generated SDDL.
        policy = self.get_authentication_policy(name)
        desc = policy["msDS-ServiceAllowedToAuthenticateFrom"][0]
        sddl = ndr_unpack(security.descriptor, desc).as_sddl()
        self.assertEqual(sddl, expected)

    def test_modify__service_allowed_to_authenticate_from_device_silo(self):
        """Test the --service-allowed-to-authenticate-from-device-silo shortcut."""
        name = self.unique_name()

        # Create a policy to modify for this test.
        self.addCleanup(self.delete_authentication_policy, name=name, force=True)
        self.runcmd("domain", "auth", "policy", "create", "--name", name)

        # Modify user allowed to authenticate from silo field
        result, out, err = self.runcmd("domain", "auth", "policy", "modify",
                                       "--name", name,
                                       "--service-allowed-to-authenticate-from-device-silo",
                                       "Developers")
        self.assertIsNone(result, msg=err)

        # Check generated SDDL.
        policy = self.get_authentication_policy(name)
        desc = policy["msDS-ServiceAllowedToAuthenticateFrom"][0]
        sddl = ndr_unpack(security.descriptor, desc).as_sddl()
        self.assertEqual(
            sddl,
            'O:SYG:SYD:(XA;OICI;CR;;;WD;(@USER.ad://ext/AuthenticationSilo == "Developers"))')

    def test_modify__service_allowed_to_authenticate_to(self):
        """Modify authentication policy service allowed to authenticate to."""
        name = self.unique_name()
        expected = "O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of {SID(AO)}))"

        # Create a policy to modify for this test.
        self.addCleanup(self.delete_authentication_policy, name=name, force=True)
        self.runcmd("domain", "auth", "policy", "create", "--name", name)

        # Modify service allowed to authenticate to field
        result, out, err = self.runcmd("domain", "auth", "policy", "modify",
                                       "--name", name,
                                       "--service-allowed-to-authenticate-to",
                                       expected)
        self.assertIsNone(result, msg=err)

        # Check service allowed to authenticate to field was modified.
        policy = self.get_authentication_policy(name)
        self.assertEqual(str(policy["cn"]), name)
        desc = policy["msDS-ServiceAllowedToAuthenticateTo"][0]
        sddl = ndr_unpack(security.descriptor, desc).as_sddl()
        self.assertEqual(sddl, expected)

    def test_modify__service_allowed_to_authenticate_to_by_group(self):
        """Tests the --service-allowed-to-authenticate-to-by-group shortcut."""
        name = self.unique_name()
        expected = "O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of_any {SID(%s)}))" % (
            self.device_group.object_sid)

        # Create a policy to modify for this test.
        self.addCleanup(self.delete_authentication_policy, name=name, force=True)
        self.runcmd("domain", "auth", "policy", "create", "--name", name)

        # Modify user allowed to authenticate to field
        result, out, err = self.runcmd("domain", "auth", "policy", "modify",
                                       "--name", name,
                                       "--service-allowed-to-authenticate-to-by-group",
                                       self.device_group.name)
        self.assertIsNone(result, msg=err)

        # Check user allowed to authenticate to field was modified.
        policy = self.get_authentication_policy(name)
        self.assertEqual(str(policy["cn"]), name)
        desc = policy["msDS-ServiceAllowedToAuthenticateTo"][0]
        sddl = ndr_unpack(security.descriptor, desc).as_sddl()
        self.assertEqual(sddl, expected)

    def test_modify__service_allowed_to_authenticate_to_by_silo(self):
        """Tests the --service-allowed-to-authenticate-to-by-silo shortcut."""
        name = self.unique_name()
        expected = ('O:SYG:SYD:(XA;OICI;CR;;;WD;(@USER.ad://ext/'
                    'AuthenticationSilo == "QA"))')

        # Create a policy to modify for this test.
        self.addCleanup(self.delete_authentication_policy, name=name, force=True)
        self.runcmd("domain", "auth", "policy", "create", "--name", name)

        # Modify user allowed to authenticate to field
        result, out, err = self.runcmd("domain", "auth", "policy", "modify",
                                       "--name", name,
                                       "--service-allowed-to-authenticate-to-by-silo",
                                       "QA")
        self.assertIsNone(result, msg=err)

        # Check user allowed to authenticate to field was modified.
        policy = self.get_authentication_policy(name)
        self.assertEqual(str(policy["cn"]), name)
        desc = policy["msDS-ServiceAllowedToAuthenticateTo"][0]
        sddl = ndr_unpack(security.descriptor, desc).as_sddl()
        self.assertEqual(sddl, expected)

    def test_modify__computer_allowed_to_authenticate_to(self):
        """Modify authentication policy computer allowed to authenticate to."""
        name = self.unique_name()
        expected = "O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of {SID(AO)}))"

        # Create a policy to modify for this test.
        self.addCleanup(self.delete_authentication_policy, name=name, force=True)
        self.runcmd("domain", "auth", "policy", "create", "--name", name)

        # Modify computer allowed to authenticate to field
        result, out, err = self.runcmd("domain", "auth", "policy", "modify",
                                       "--name", name,
                                       "--computer-allowed-to-authenticate-to",
                                       expected)
        self.assertIsNone(result, msg=err)

        # Check computer allowed to authenticate to field was modified.
        policy = self.get_authentication_policy(name)
        self.assertEqual(str(policy["cn"]), name)
        desc = policy["msDS-ComputerAllowedToAuthenticateTo"][0]
        sddl = ndr_unpack(security.descriptor, desc).as_sddl()
        self.assertEqual(sddl, expected)

    def test_modify__computer_allowed_to_authenticate_to_by_group(self):
        """Tests the --computer-allowed-to-authenticate-to-by-group shortcut."""
        name = self.unique_name()
        expected = "O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of_any {SID(%s)}))" % (
            self.device_group.object_sid)

        # Create a policy to modify for this test.
        self.addCleanup(self.delete_authentication_policy, name=name, force=True)
        self.runcmd("domain", "auth", "policy", "create", "--name", name)

        # Modify user allowed to authenticate to field
        result, out, err = self.runcmd("domain", "auth", "policy", "modify",
                                       "--name", name,
                                       "--computer-allowed-to-authenticate-to-by-group",
                                       self.device_group.name)
        self.assertIsNone(result, msg=err)

        # Check user allowed to authenticate to field was modified.
        policy = self.get_authentication_policy(name)
        self.assertEqual(str(policy["cn"]), name)
        desc = policy["msDS-ComputerAllowedToAuthenticateTo"][0]
        sddl = ndr_unpack(security.descriptor, desc).as_sddl()
        self.assertEqual(sddl, expected)

    def test_modify__computer_allowed_to_authenticate_to_by_silo(self):
        """Tests the --computer-allowed-to-authenticate-to-by-silo shortcut."""
        name = self.unique_name()
        expected = ('O:SYG:SYD:(XA;OICI;CR;;;WD;(@USER.ad://ext/'
                    'AuthenticationSilo == "QA"))')

        # Create a policy to modify for this test.
        self.addCleanup(self.delete_authentication_policy, name=name, force=True)
        self.runcmd("domain", "auth", "policy", "create", "--name", name)

        # Modify user allowed to authenticate to field
        result, out, err = self.runcmd("domain", "auth", "policy", "modify",
                                       "--name", name,
                                       "--computer-allowed-to-authenticate-to-by-silo",
                                       "QA")
        self.assertIsNone(result, msg=err)

        # Check user allowed to authenticate to field was modified.
        policy = self.get_authentication_policy(name)
        self.assertEqual(str(policy["cn"]), name)
        desc = policy["msDS-ComputerAllowedToAuthenticateTo"][0]
        sddl = ndr_unpack(security.descriptor, desc).as_sddl()
        self.assertEqual(sddl, expected)

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
        name = self.unique_name()

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
        name = self.unique_name()

        # Create a policy to modify for this test.
        self.addCleanup(self.delete_authentication_policy, name=name, force=True)
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
        name = self.unique_name()

        # Create protected authentication policy.
        self.addCleanup(self.delete_authentication_policy, name=name, force=True)
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", name,
                                       "--protect")
        self.assertIsNone(result, msg=err)

        # Policy exists
        policy = self.get_authentication_policy(name)
        self.assertIsNotNone(policy)

        # Try doing delete with --force.
        # Patch SDUtils.dacl_delete_aces with a Mock that raises ModelError.
        with patch.object(SDUtils, "dacl_delete_aces") as delete_mock:
            delete_mock.side_effect = ModelError("Custom error message")
            result, out, err = self.runcmd("domain", "auth", "policy", "delete",
                                           "--name", name,
                                           "--force")
            self.assertEqual(result, -1)
            self.assertIn("Custom error message", err)

    def test_delete__fails(self):
        """Test deleting an authentication policy, but it fails."""
        name = self.unique_name()

        # Create regular authentication policy.
        self.addCleanup(self.delete_authentication_policy, name=name, force=True)
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", name)
        self.assertIsNone(result, msg=err)

        # Policy exists
        policy = self.get_authentication_policy(name)
        self.assertIsNotNone(policy)

        # Raise ModelError when ldb.delete() is called.
        with patch.object(SamDB, "delete") as delete_mock:
            delete_mock.side_effect = ModelError("Custom error message")
            result, out, err = self.runcmd("domain", "auth", "policy", "delete",
                                           "--name", name)
            self.assertEqual(result, -1)
            self.assertIn("Custom error message", err)

            # When not using --force we get a hint.
            self.assertIn("Try --force", err)

    def test_delete__protected_fails(self):
        """Test deleting an authentication policy, but it fails."""
        name = self.unique_name()

        # Create protected authentication policy.
        self.addCleanup(self.delete_authentication_policy, name=name, force=True)
        result, out, err = self.runcmd("domain", "auth", "policy", "create",
                                       "--name", name,
                                       "--protect")
        self.assertIsNone(result, msg=err)

        # Policy exists
        policy = self.get_authentication_policy(name)
        self.assertIsNotNone(policy)

        # Raise ModelError when ldb.delete() is called.
        with patch.object(SamDB, "delete") as delete_mock:
            delete_mock.side_effect = ModelError("Custom error message")
            result, out, err = self.runcmd("domain", "auth", "policy", "delete",
                                           "--name", name,
                                           "--force")
            self.assertEqual(result, -1)
            self.assertIn("Custom error message", err)

            # When using --force we don't get the hint.
            self.assertNotIn("Try --force", err)
