# Unix SMB/CIFS implementation.
#
# Base class for samba-tool domain auth policy and silo commands
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

from .base import SambaToolCmdTest


class BaseAuthCmdTest(SambaToolCmdTest):
    def setUp(self):
        super().setUp()
        self.host = "ldap://{DC_SERVER}".format(**os.environ)
        self.creds = "-U{DC_USERNAME}%{DC_PASSWORD}".format(**os.environ)
        self.samdb = self.getSamDB("-H", self.host, self.creds)

        # Generate some test data.
        self.policies = []
        self.create_authentication_policy(name="Single Policy")
        self.create_authentication_policy(name="User Policy")
        self.create_authentication_policy(name="Service Policy")
        self.create_authentication_policy(name="Computer Policy")

        self.silos = []
        self.create_authentication_silo(name="Developers",
                                        description="Developers, Developers",
                                        policy="Single Policy")
        self.create_authentication_silo(name="Managers",
                                        description="Managers",
                                        policy="Single Policy")
        self.create_authentication_silo(name="QA",
                                        description="Quality Assurance",
                                        user_policy="User Policy",
                                        service_policy="Service Policy",
                                        computer_policy="Computer Policy")

    def tearDown(self):
        """Remove data created by setUp."""
        for policy in self.policies:
            self.delete_authentication_policy(policy, force=True)

        for silo in self.silos:
            self.delete_authentication_silo(silo, force=True)

        super().tearDown()

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

    def _run(self, *argv):
        """Override _run, so we don't always have to pass host and creds."""
        args = list(argv)
        args.extend(["-H", self.host, self.creds])
        return super()._run(*args)

    runcmd = _run
    runsubcmd = _run

    def create_authentication_policy(self, name, description=None, audit=False,
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

        # Run command and store name in self.silos for tearDown to clean up.
        result, out, err = self.runcmd(*cmd)
        self.assertIsNone(result, msg=err)
        self.assertTrue(out.startswith("Created authentication policy"))
        self.policies.append(name)
        return name

    def delete_authentication_policy(self, name, force=False):
        """Delete authentication policy by name."""
        cmd = ["domain", "auth", "policy", "delete", "--name", name]

        # Force-delete protected authentication policy.
        if force:
            cmd.append("--force")

        result, out, err = self.runcmd(*cmd)
        self.assertIsNone(result, msg=err)
        self.assertIn("Deleted authentication policy", out)

    def create_authentication_silo(self, name, description=None, policy=None,
                                   user_policy=None, service_policy=None,
                                   computer_policy=None, audit=False,
                                   protect=False):
        """Create an authentication silo using the samba-tool command."""

        # Base command for create authentication policy.
        cmd = ["domain", "auth", "silo", "create", "--name", name]

        # If --policy is present, use a singular authentication policy.
        # otherwise use --user-policy, --service-policy, --computer-policy
        if policy is not None:
            cmd += ["--policy", policy]
        else:
            cmd += ["--user-policy", user_policy,
                    "--service-policy", service_policy,
                    "--computer-policy", computer_policy]

        # Other optional attributes.
        if description is not None:
            cmd.append(f"--description={description}")
        if protect:
            cmd.append("--protect")
        if audit:
            cmd.append("--audit")

        # Run command and store name in self.silos for tearDown to clean up.
        result, out, err = self.runcmd(*cmd)
        self.assertIsNone(result, msg=err)
        self.assertTrue(out.startswith("Created authentication silo"))
        self.silos.append(name)
        return name

    def delete_authentication_silo(self, name, force=False):
        """Delete authentication silo by name."""
        cmd = ["domain", "auth", "silo", "delete", "--name", name]

        # Force-delete protected authentication silo.
        if force:
            cmd.append("--force")

        result, out, err = self.runcmd(*cmd)
        self.assertIsNone(result, msg=err)
        self.assertIn("Deleted authentication silo", out)

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
