# Unix SMB/CIFS implementation.
#
# Base test class for samba-tool domain auth policy and silo commands.
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

import os

from ldb import SCOPE_ONELEVEL

from samba.domain.models import Group

from .base import SambaToolCmdTest

HOST = "ldap://{DC_SERVER}".format(**os.environ)
CREDS = "-U{DC_USERNAME}%{DC_PASSWORD}".format(**os.environ)


class SiloTest(SambaToolCmdTest):
    """Base test class for silo and policy related commands."""

    @classmethod
    def setUpClass(cls):
        cls.samdb = cls.getSamDB("-H", HOST, CREDS)
        super().setUpClass()

    @classmethod
    def setUpTestData(cls):
        cls.create_authentication_policy(name="User Policy")
        cls.create_authentication_policy(name="Service Policy")
        cls.create_authentication_policy(name="Computer Policy")

        cls.create_authentication_silo(
            name="Developers",
            description="Developers, Developers, Developers!",
            user_authentication_policy="User Policy")
        cls.create_authentication_silo(
            name="Managers",
            description="Managers",
            user_authentication_policy="User Policy")
        cls.create_authentication_silo(
            name="QA",
            description="Quality Assurance",
            user_authentication_policy="User Policy",
            service_authentication_policy="Service Policy",
            computer_authentication_policy="Computer Policy")

        cls.device_group = Group(name="device-group")
        cls.device_group.save(cls.samdb)
        cls.addClassCleanup(cls.device_group.delete, cls.samdb)

    def get_services_dn(self):
        """Returns Services DN."""
        services_dn = self.samdb.get_config_basedn()
        services_dn.add_child("CN=Services")
        return services_dn

    def get_authn_configuration_dn(self):
        """Returns AuthN Configuration DN."""
        authn_policy_configuration = self.get_services_dn()
        authn_policy_configuration.add_child("CN=AuthN Policy Configuration")
        return authn_policy_configuration

    def get_authn_silos_dn(self):
        """Returns AuthN Silos DN."""
        authn_silos_dn = self.get_authn_configuration_dn()
        authn_silos_dn.add_child("CN=AuthN Silos")
        return authn_silos_dn

    def get_authn_policies_dn(self):
        """Returns AuthN Policies DN."""
        authn_policies_dn = self.get_authn_configuration_dn()
        authn_policies_dn.add_child("CN=AuthN Policies")
        return authn_policies_dn

    def get_users_dn(self):
        """Returns Users DN."""
        users_dn = self.samdb.get_root_basedn()
        users_dn.add_child("CN=Users")
        return users_dn

    def get_user(self, username):
        """Get a user by username."""
        users_dn = self.get_users_dn()

        result = self.samdb.search(base=users_dn,
                                   scope=SCOPE_ONELEVEL,
                                   expression=f"(sAMAccountName={username})")

        if len(result) == 1:
            return result[0]

    @classmethod
    def _run(cls, *argv):
        """Override _run, so we don't always have to pass host and creds."""
        args = list(argv)
        args.extend(["-H", HOST, CREDS])
        return super()._run(*args)

    runcmd = _run
    runsubcmd = _run

    @classmethod
    def create_authentication_policy(cls, name, description=None, audit=False,
                                     protect=False):
        """Create an authentication policy."""

        # base command for create authentication policy
        cmd = ["domain", "auth", "policy", "create", "--name", name]

        # optional attributes
        if description is not None:
            cmd.append(f"--description={description}")
        if audit:
            cmd.append("--audit")
        if protect:
            cmd.append("--protect")

        # Run command and store name in self.silos for tearDownClass to clean
        # up.
        result, out, err = cls.runcmd(*cmd)
        assert result is None
        assert out.startswith("Created authentication policy")
        cls.addClassCleanup(cls.delete_authentication_policy,
                            name=name, force=True)
        return name

    @classmethod
    def delete_authentication_policy(cls, name, force=False):
        """Delete authentication policy by name."""
        cmd = ["domain", "auth", "policy", "delete", "--name", name]

        # Force-delete protected authentication policy.
        if force:
            cmd.append("--force")

        result, out, err = cls.runcmd(*cmd)
        assert result is None
        assert "Deleted authentication policy" in out

    @classmethod
    def create_authentication_silo(cls, name, description=None,
                                   user_authentication_policy=None,
                                   service_authentication_policy=None,
                                   computer_authentication_policy=None,
                                   audit=False, protect=False):
        """Create an authentication silo using the samba-tool command."""

        # Base command for create authentication policy.
        cmd = ["domain", "auth", "silo", "create", "--name", name]

        # Authentication policies.
        if user_authentication_policy:
            cmd += ["--user-authentication-policy",
                    user_authentication_policy]
        if service_authentication_policy:
            cmd += ["--service-authentication-policy",
                    service_authentication_policy]
        if computer_authentication_policy:
            cmd += ["--computer-authentication-policy",
                    computer_authentication_policy]

        # Other optional attributes.
        if description is not None:
            cmd.append(f"--description={description}")
        if protect:
            cmd.append("--protect")
        if audit:
            cmd.append("--audit")

        # Run command and store name in self.silos for tearDownClass to clean
        # up.
        result, out, err = cls.runcmd(*cmd)
        assert result is None
        assert out.startswith("Created authentication silo")
        cls.addClassCleanup(cls.delete_authentication_silo,
                            name=name, force=True)
        return name

    @classmethod
    def delete_authentication_silo(cls, name, force=False):
        """Delete authentication silo by name."""
        cmd = ["domain", "auth", "silo", "delete", "--name", name]

        # Force-delete protected authentication silo.
        if force:
            cmd.append("--force")

        result, out, err = cls.runcmd(*cmd)
        assert result is None
        assert "Deleted authentication silo" in out

    def get_authentication_silo(self, name):
        """Get authentication silo by name."""
        authn_silos_dn = self.get_authn_silos_dn()

        result = self.samdb.search(base=authn_silos_dn,
                                   scope=SCOPE_ONELEVEL,
                                   expression=f"(CN={name})")

        if len(result) == 1:
            return result[0]

    def get_authentication_policy(self, name):
        """Get authentication policy by name."""
        authn_policies_dn = self.get_authn_policies_dn()

        result = self.samdb.search(base=authn_policies_dn,
                                   scope=SCOPE_ONELEVEL,
                                   expression=f"(CN={name})")

        if len(result) == 1:
            return result[0]
