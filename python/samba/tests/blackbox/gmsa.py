# Unix SMB/CIFS implementation.
#
# Blackbox tests for GMSA workflow.
#
# Copyright (C) Catalyst.Net Ltd. 2024
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
import os
import sys
from shlex import quote

sys.path.insert(0, "bin/python")
os.environ["PYTHONUNBUFFERED"] = "1"

from samba.domain.models import Computer
from samba.tests import BlackboxProcessError, BlackboxTestCase, connect_samdb

DC_SERVER = os.environ["SERVER"]
SERVER = os.environ["SERVER"]
SERVER_USERNAME = os.environ["USERNAME"]
SERVER_PASSWORD = os.environ["PASSWORD"]

HOST = f"ldap://{SERVER}"
ADMIN_CREDS = f"-U{SERVER_USERNAME}%{SERVER_PASSWORD}"


class GMSABlackboxTest(BlackboxTestCase):
    """Blackbox tests for GMSA management."""

    @classmethod
    def setUpClass(cls):
        cls.lp = cls.get_loadparm()
        cls.env_creds = cls.get_env_credentials(lp=cls.lp,
                                                env_username="USERNAME",
                                                env_password="PASSWORD",
                                                env_domain="DOMAIN",
                                                env_realm="REALM")
        cls.samdb = connect_samdb(HOST, lp=cls.lp, credentials=cls.env_creds)
        super().setUpClass()

    def getpassword(self, account_name, attrs, creds=ADMIN_CREDS):
        cmd = f"samba-tool user getpassword --attributes={quote(attrs)} {account_name} -H {HOST} {creds}"
        ldif = self.check_output(cmd).decode()
        res = self.samdb.parse_ldif(ldif)
        _, user_message = next(res)

        # check each attr is returned
        for attr in attrs.split(","):
            if attr not in user_message:
                raise KeyError

        return user_message

    def test_gmsa_password_access(self):
        """Test machine account read password access."""
        machine_account = "Machine_Account$"
        machine_password = "T3stPassword0nly"
        machine_creds = f"-U{machine_account}%{machine_password}"
        gmsa_account = "GMSA_Test_User$"

        # Create a machine account and set the password.
        self.check_run(f"samba-tool computer create {machine_account} -H {HOST} {ADMIN_CREDS}")
        self.addCleanup(self.run_command, f"samba-tool computer delete {machine_account} -H {HOST} {ADMIN_CREDS}")
        self.check_run(f"samba-tool user setpassword {machine_account} --newpassword={machine_password} -H {HOST} {ADMIN_CREDS}")

        # Create a Group Managed Service Account with default SDDL.
        self.check_run(f"samba-tool service-account create --name={gmsa_account} --dns-host-name=example.com --managed-password-interval=1 -H {HOST} {ADMIN_CREDS}")
        self.addCleanup(self.run_command, f"samba-tool service-account delete --name={gmsa_account} -H {HOST} {ADMIN_CREDS}")

        # Grant password read access to the machine account.
        self.check_run(f"samba-tool service-account group-msa-membership add --name={gmsa_account} --principal={machine_account} -H {HOST} {ADMIN_CREDS}")

        try:
            self.getpassword(gmsa_account, "unicodePwd", creds=machine_creds)
        except KeyError:
            self.fail("Failed to get unicodePwd despite being in the gMSA membership")

        # Remove password read access from the machine account and verify.
        self.check_run(f"samba-tool service-account group-msa-membership remove --name={gmsa_account} --principal={machine_account} -H {HOST} {ADMIN_CREDS}")

        try:
            self.assertRaises(KeyError, self.getpassword, gmsa_account, "unicodePwd", creds=machine_creds)
        except BlackboxProcessError:
            self.fail("Unexpected subcommand failure retrieving unicodePwd")

    def test_gmsa_add_sid_only_viewer(self):
        """Add unknown SID to password viewers and check group-msa-membership show output."""
        gmsa_account = "GMSA_Test_User$"
        unknown_sid = f"{self.samdb.domain_sid}-9999"

        self.check_run(f"samba-tool service-account create --name={gmsa_account} --dns-host-name=example.com --managed-password-interval=1 -H {HOST} {ADMIN_CREDS}")
        self.addCleanup(self.run_command, f"samba-tool service-account delete --name={gmsa_account} -H {HOST} {ADMIN_CREDS}")

        self.check_run(f"samba-tool service-account group-msa-membership add --name={gmsa_account} --principal={unknown_sid} -H {HOST} {ADMIN_CREDS}")

        out = self.check_output(f"samba-tool service-account group-msa-membership show --name={gmsa_account} -H {HOST} {ADMIN_CREDS}")
        self.assertIn(f"<SID={unknown_sid}>", out.decode())

    def test_custom_sddl_as_list(self):
        """Test custom SDDL that can be represented by a simple list."""
        machine_account = "Machine_Account$"
        machine_password = "T3stPassword0nly"
        gmsa_account = "GMSA_Test_User$"
        unknown_sid = f"{self.samdb.domain_sid}-9999"

        # Create a machine account and set the password.
        self.check_run(f"samba-tool computer create {machine_account} -H {HOST} {ADMIN_CREDS}")
        self.addCleanup(self.run_command, f"samba-tool computer delete {machine_account} -H {HOST} {ADMIN_CREDS}")
        self.check_run(f"samba-tool user setpassword {machine_account} --newpassword={machine_password} -H {HOST} {ADMIN_CREDS}")

        # Create GMSA with custom SDDL this time rather than the command default.
        initial_sddl = f"O:SYD:(A;;RP;;;{self.samdb.connecting_user_sid})"
        self.check_run(f'samba-tool service-account create --name={gmsa_account} --dns-host-name=example.com --group-msa-membership="{initial_sddl}" --managed-password-interval=1 -H {HOST} {ADMIN_CREDS}')
        self.addCleanup(self.run_command, f"samba-tool service-account delete --name={gmsa_account} -H {HOST} {ADMIN_CREDS}")

        # Read the SDDL using service-account view JSON, it should be the same.
        out = self.check_output(f"samba-tool service-account view --name={gmsa_account} -H {HOST} {ADMIN_CREDS}")
        gmsa = json.loads(out.decode())
        self.assertEqual(gmsa["msDS-GroupMSAMembership"], initial_sddl)

        # Add the machine account as a password viewer.
        self.check_run(f"samba-tool service-account group-msa-membership add --name={gmsa_account} --principal={machine_account} -H {HOST} {ADMIN_CREDS}")

        # Add the unknown SID as a viewer as well.
        self.check_run(f"samba-tool service-account group-msa-membership add --name={gmsa_account} --principal={unknown_sid} -H {HOST} {ADMIN_CREDS}")

        # Read the SDDL again and check if the machine account and unknown SID were added.
        out = self.check_output(f"samba-tool service-account view --name={gmsa_account} -H {HOST} {ADMIN_CREDS}")
        gmsa = json.loads(out.decode())
        machine_user = Computer.get(self.samdb, account_name=machine_account)
        expected_sddl = (initial_sddl +
                         f"(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;{machine_user.object_sid})" +
                         f"(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;{unknown_sid})")
        self.assertEqual(gmsa["msDS-GroupMSAMembership"], expected_sddl)

        # Get the list as --json which is easier to parse in the test.
        out = self.check_output(f"samba-tool service-account group-msa-membership show --name={gmsa_account} --json -H {HOST} {ADMIN_CREDS}")
        response = json.loads(out.decode())
        self.assertListEqual(response["trustees"], [
            "CN=Administrator,CN=Users,DC=addom,DC=samba,DC=example,DC=com",
            "CN=Machine_Account,CN=Computers,DC=addom,DC=samba,DC=example,DC=com",
            f"<SID={unknown_sid}>",
        ])

    def test_custom_sddl_complex(self):
        """Test custom SDDL that cannot be display as a simple list.

        In this case the "samba-tool service-account view" command
        can be used to retrieve the SDDL.
        """
        machine_account = "Machine_Account$"
        machine_password = "T3stPassword0nly"
        gmsa_account = "GMSA_Test_User$"

        # Create a machine account and set the password.
        self.check_run(f"samba-tool computer create {machine_account} -H {HOST} {ADMIN_CREDS}")
        self.addCleanup(self.run_command, f"samba-tool computer delete {machine_account} -H {HOST} {ADMIN_CREDS}")
        self.check_run(f"samba-tool user setpassword {machine_account} --newpassword={machine_password} -H {HOST} {ADMIN_CREDS}")

        # Create GMSA with custom SDDL this time rather than the command default.
        initial_sddl = f"O:SYD:(A;;RP;;;{self.samdb.connecting_user_sid})"
        self.check_run(f'samba-tool service-account create --name={gmsa_account} --dns-host-name=example.com --group-msa-membership="{initial_sddl}" --managed-password-interval=1 -H {HOST} {ADMIN_CREDS}')
        self.addCleanup(self.run_command, f"samba-tool service-account delete --name={gmsa_account} -H {HOST} {ADMIN_CREDS}")

        # At first retrieving as a list will work fine.
        out = self.check_output(f"samba-tool service-account group-msa-membership show --name={gmsa_account} --json -H {HOST} {ADMIN_CREDS}")
        response = json.loads(out.decode())
        self.assertListEqual(
            response["trustees"],
            ["CN=Administrator,CN=Users,DC=addom,DC=samba,DC=example,DC=com"])

        # Set custom SDDL this time using the service-account modify command.
        machine_user = Computer.get(self.samdb, account_name=machine_account)
        deny_ace = f"(D;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;{machine_user.object_sid})"
        sddl = initial_sddl + deny_ace
        self.check_run(f'samba-tool service-account modify --name={gmsa_account} --group-msa-membership="{sddl}" -H {HOST} {ADMIN_CREDS}')

        # Group MSA membership can no longer be represented as a simple list.
        with self.assertRaisesRegex(BlackboxProcessError, "Cannot be represented as a simple list"):
            self.check_run(f"samba-tool service-account group-msa-membership show --name={gmsa_account} -H {HOST} {ADMIN_CREDS}")

        # Retrieving the SDDL still works fine.
        out = self.check_output(f"samba-tool service-account view --name={gmsa_account} -H {HOST} {ADMIN_CREDS}")
        gmsa = json.loads(out.decode())
        self.assertEqual(gmsa["msDS-GroupMSAMembership"], sddl)


if __name__ == "__main__":
    import unittest
    unittest.main()
