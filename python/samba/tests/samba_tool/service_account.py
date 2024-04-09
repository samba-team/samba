# Unix SMB/CIFS implementation.
#
# Tests for samba-tool service-account commands.
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

from samba.domain.models import Group, GroupManagedServiceAccount, User
from samba.domain.models.constants import GROUP_MSA_MEMBERSHIP_DEFAULT

from .base import SambaToolCmdTest

HOST = "ldap://{DC_SERVER}".format(**os.environ)
CREDS = "-U{DC_USERNAME}%{DC_PASSWORD}".format(**os.environ)


class ServiceAccountTests(SambaToolCmdTest):

    @classmethod
    def setUpClass(cls):
        cls.samdb = cls.getSamDB("-H", HOST, CREDS)
        super().setUpClass()

    @classmethod
    def setUpTestData(cls):
        """Setup initial data without the samba-tool command."""
        cls.accounts = [
            GroupManagedServiceAccount.create(cls.samdb, name="foo",
                                              dns_host_name="example.com"),
            GroupManagedServiceAccount.create(cls.samdb, name="bar",
                                              dns_host_name="example.com"),
            GroupManagedServiceAccount.create(cls.samdb, name="baz",
                                              dns_host_name="example.com"),
        ]

        for account in cls.accounts:
            cls.addClassCleanup(account.delete, cls.samdb)

    @classmethod
    def _run(cls, *argv):
        """Override _run, so we don't always have to pass HOST and CREDS."""
        args = list(argv)
        args.extend(["-H", HOST, CREDS])
        return super()._run(*args)

    runcmd = _run
    runsubcmd = _run

    @classmethod
    def delete_service_account(cls, name):
        """Delete a service account using samba-tool."""
        result, out, err = cls.runcmd("service-account", "delete",
                                      "--name", name)
        assert result is None
        assert out.startswith("Deleted group managed service account")

    @classmethod
    def create_service_account(cls, name, dns_host_name="example.com",
                               managed_password_interval=None):
        """Create a service account using samba-tool.

        Adds a class cleanup to automatically delete the gmsa at the end
        of the test case.
        """
        # required arguments
        cmd = ["service-account", "create",
               "--name", name,
               "--dns-host-name", dns_host_name]

        # defaults to 30 if left None
        if managed_password_interval is not None:
            cmd += ["--managed-password-interval", str(managed_password_interval)]

        # create gmsa and setup cleanup
        result, out, err = cls.runcmd(*cmd)
        assert result is None
        assert out.startswith("Created group managed service account")
        cls.addClassCleanup(cls.delete_service_account, name=name)

    def test_list(self):
        """List group managed service accounts with samba-tool."""
        result, out, err = self.runcmd("service-account", "list")
        self.assertIsNone(result, msg=err)

        self.assertIn("foo$", out)
        self.assertIn("bar$", out)
        self.assertIn("baz$", out)

    def test_list__json(self):
        """List group managed service accounts in json format."""
        result, out, err = self.runcmd("service-account", "list", "--json")
        self.assertIsNone(result, msg=err)
        accounts = json.loads(out)

        self.assertIn("foo$", accounts)
        self.assertIn("bar$", accounts)
        self.assertIn("baz$", accounts)

    def test_create(self):
        """Create a group managed service account using samba-tool."""
        # Create a Group Managed Service account using samba-tool.
        name = self.unique_name()
        self.create_service_account(name,
                                    dns_host_name="test.com",
                                    managed_password_interval=60)

        # Group Managed Service count exists.
        # Since GroupManagedServiceAccount is also a Computer it ends in '$'
        gmsa = GroupManagedServiceAccount.get(self.samdb, account_name=name + "$")
        self.assertIsNotNone(gmsa)
        self.assertEqual(gmsa.account_name, name + "$")
        self.assertEqual(gmsa.dns_host_name, "test.com")
        self.assertEqual(gmsa.managed_password_interval, 60)

    def test_view(self):
        """View a group managed service account using samba-tool."""
        result, out, err = self.runcmd("service-account", "view",
                                       "--name", "foo")
        self.assertIsNone(result, msg=err)

        # Service account view always returns JSON.
        response = json.loads(out)
        self.assertEqual(response["cn"], "foo")
        self.assertEqual(response["dNSHostName"], "example.com")
        self.assertEqual(response["msDS-ManagedPasswordInterval"], 30)

    def test_delete(self):
        """Delete a group managed service account using samba-tool."""
        # Create the gmsa without samba-tool.
        name = self.unique_name()
        GroupManagedServiceAccount.create(self.samdb, name=name,
                                          dns_host_name="example.com"),

        # The group managed service account exists.
        gmsa = GroupManagedServiceAccount.get(self.samdb, account_name=name + "$")
        self.assertIsNotNone(gmsa)

        # Now delete the gmsa.
        result, out, err = self.runcmd("service-account", "delete",
                                       "--name", name)
        self.assertIsNone(result, msg=err)

        # Service account is gone.
        gmsa = GroupManagedServiceAccount.get(self.samdb, account_name=name + "$")
        self.assertIsNone(gmsa, msg="Group Managed Service Account not deleted.")

    def test_modify(self):
        """Modify a group managed service account and manually set SDDL."""
        name = self.unique_name()
        gmsa = GroupManagedServiceAccount.create(self.samdb, name=name,
                                                 dns_host_name="example.com")
        self.addCleanup(gmsa.delete, self.samdb)

        # Build some SDDL for adding a user manually.
        bob = User.get(self.samdb, account_name="bob")
        sddl = gmsa.group_msa_membership.as_sddl()
        sddl += f"(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;{bob.object_sid})"

        result, out, err = self.runcmd("service-account", "modify",
                                       "--name", name,
                                       "--dns-host-name", "new.example.com",
                                       "--group-msa-membership", sddl)
        self.assertIsNone(result, msg=err)

        # Check field changes and see if the new user is in there.
        gmsa = GroupManagedServiceAccount.get(self.samdb, account_name=name + "$")
        self.assertEqual(gmsa.dns_host_name, "new.example.com")
        self.assertIn(bob.object_sid, gmsa.trustees)


class ServiceAccountGroupMSAMembershipTests(SambaToolCmdTest):

    @classmethod
    def setUpClass(cls):
        cls.samdb = cls.getSamDB("-H", HOST, CREDS)
        super().setUpClass()

    @classmethod
    def setUpTestData(cls):
        """Setup initial data without the samba-tool command."""
        # Add a user other than the Administrator to the default SDDL.
        jane = User.get(cls.samdb, account_name="jane")
        sddl = f"{GROUP_MSA_MEMBERSHIP_DEFAULT}(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;{jane.object_sid})"
        cls.gmsa = GroupManagedServiceAccount.create(cls.samdb, name="gmsa",
                                                     dns_host_name="example.com",
                                                     group_msa_membership=sddl)

        cls.addClassCleanup(cls.gmsa.delete, cls.samdb)

    @classmethod
    def _run(cls, *argv):
        """Override _run, so we don't always have to pass HOST and CREDS."""
        args = list(argv)
        args.extend(["-H", HOST, CREDS])
        return super()._run(*args)

    runcmd = _run
    runsubcmd = _run

    def test_show(self):
        """Show password viewers on a Group Managed Service Account."""
        result, out, err = self.runcmd("service-account",
                                       "group-msa-membership", "show",
                                       "--name", self.gmsa.account_name)
        self.assertIsNone(result, msg=err)

        # Plain text output.
        self.assertIn(
            "Account-DN: CN=gmsa,CN=Managed Service Accounts,DC=addom,DC=samba,DC=example,DC=com", out)
        self.assertIn(
            "CN=Administrator,CN=Users,DC=addom,DC=samba,DC=example,DC=com", out)
        self.assertIn(
            "CN=jane,CN=Users,DC=addom,DC=samba,DC=example,DC=com", out)

    def test_show__json(self):
        """Show password viewers on a Group Managed Service Account as JSON."""
        result, out, err = self.runcmd("service-account",
                                       "group-msa-membership", "show",
                                       "--name", self.gmsa.account_name,
                                       "--json")
        self.assertIsNone(result, msg=err)

        # JSON output.
        response = json.loads(out)
        self.assertEqual(response["dn"], str(self.gmsa.dn))
        self.assertListEqual(response["trustees"], [
            "CN=Administrator,CN=Users,DC=addom,DC=samba,DC=example,DC=com",
            "CN=jane,CN=Users,DC=addom,DC=samba,DC=example,DC=com"
        ])

    def test_add__username(self):
        """Add principal to a Group Managed Service Account by username."""
        alice = User.get(self.samdb, account_name="alice")
        name = self.unique_name()
        gmsa = GroupManagedServiceAccount.create(self.samdb, name=name,
                                                 dns_host_name="example.com")
        self.addCleanup(gmsa.delete, self.samdb)

        # Add user 'alice' by username.
        result, out, err = self.runcmd("service-account",
                                       "group-msa-membership", "add",
                                       "--name", gmsa.account_name,
                                       "--principal", alice.account_name)
        self.assertIsNone(result, msg=err)

        # See if user was added.
        gmsa.refresh(self.samdb)
        self.assertIn(alice.object_sid, gmsa.trustees)

    def test_add__dn(self):
        """Add principal to a Group Managed Service Account by dn."""
        admins = Group.get(self.samdb, name="DnsAdmins")
        name = self.unique_name()
        gmsa = GroupManagedServiceAccount.create(self.samdb, name=name,
                                                 dns_host_name="example.com")
        self.addCleanup(gmsa.delete, self.samdb)

        # Add group 'DnsAdmins' by dn.
        result, out, err = self.runcmd("service-account",
                                       "group-msa-membership", "add",
                                       "--name", gmsa.account_name,
                                       "--principal", str(admins.dn))
        self.assertIsNone(result, msg=err)

        # See if group was added.
        gmsa.refresh(self.samdb)
        self.assertIn(admins.object_sid, gmsa.trustees)

    def test_remove__username(self):
        """Remove principal from a Group Managed Service Account by username."""
        # Create a GMSA with custom SDDL and add extra user.
        bob = User.get(self.samdb, account_name="bob")
        sddl = f"{GROUP_MSA_MEMBERSHIP_DEFAULT}(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;{bob.object_sid})"
        name = self.unique_name()
        gmsa = GroupManagedServiceAccount.create(self.samdb, name=name,
                                                 dns_host_name="example.com",
                                                 group_msa_membership=sddl)

        # The user is in list to start with.
        self.assertIn(bob.object_sid, gmsa.trustees)

        # Remove user 'bob' by username.
        result, out, err = self.runcmd("service-account",
                                       "group-msa-membership", "remove",
                                       "--name", gmsa.account_name,
                                       "--principal", bob.account_name)
        self.assertIsNone(result, msg=err)

        # See if user was removed.
        gmsa.refresh(self.samdb)
        self.assertNotIn(bob.object_sid, gmsa.trustees)

    def test_remove__dn(self):
        """Remove principal from a Group Managed Service Account by dn."""
        # Create a GMSA with custom SDDL and add extra group.
        admins = Group.get(self.samdb, name="DnsAdmins")
        sddl = f"{GROUP_MSA_MEMBERSHIP_DEFAULT}(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;{admins.object_sid})"
        name = self.unique_name()
        gmsa = GroupManagedServiceAccount.create(self.samdb, name=name,
                                                 dns_host_name="example.com",
                                                 group_msa_membership=sddl)

        # The group is in list to start with.
        self.assertIn(admins.object_sid, gmsa.trustees)

        # Remove group 'DnsAdmins' by dn.
        result, out, err = self.runcmd("service-account",
                                       "group-msa-membership", "remove",
                                       "--name", gmsa.account_name,
                                       "--principal", str(admins.dn))
        self.assertIsNone(result, msg=err)

        # See if group was removed.
        gmsa.refresh(self.samdb)
        self.assertNotIn(admins.object_sid, gmsa.trustees)
