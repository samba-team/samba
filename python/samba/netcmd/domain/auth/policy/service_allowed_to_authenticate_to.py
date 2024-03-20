# Unix SMB/CIFS implementation.
#
# authentication policy - manage service-allowed-to-authenticate-to property
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

from samba.domain.models import AuthenticationPolicy, AuthenticationSilo, Group
from samba.domain.models.exceptions import ModelError
from samba.getopt import CredentialsOptions, HostOptions, Option, SambaOptions
from samba.netcmd import Command, CommandError, SuperCommand


class cmd_domain_auth_policy_service_allowed_to_authenticate_to_set(Command):
    """Set the service-allowed-to-authenticate-to property based on scenario.

    --by-group:

        The target service requires the connecting user to be in GROUP.

    --by-silo:

        The target service requires the connecting user to be in SILO.

    The options above are mutually exclusive, only one can be set at a time.
    """

    synopsis = "%prog -H <URL> [options]"

    takes_optiongroups = {
        "sambaopts": SambaOptions,
        "credopts": CredentialsOptions,
        "hostopts": HostOptions,
    }

    takes_options = [
        Option("--name",
               help="Name of authentication policy to view (required).",
               dest="name", action="store", type=str, required=True),
        Option("--by-group",
               help="The target service requires the connecting "
                    "user to be in GROUP.",
               dest="groupname", action="store", type=str),
        Option("--by-silo",
               help="The target service requires the connecting "
                    "user to be in SILO.",
               dest="siloname", action="store", type=str),
    ]

    def run(self, hostopts=None, sambaopts=None, credopts=None, name=None,
            groupname=None, siloname=None):

        if groupname and siloname:
            raise CommandError("Cannot have both --by-group and --by-silo options.")

        ldb = self.ldb_connect(hostopts, sambaopts, credopts)

        try:
            policy = AuthenticationPolicy.get(ldb, cn=name)
        except ModelError as e:
            raise CommandError(e)

        if policy is None:
            raise CommandError(f"Authentication policy {name} not found.")

        if groupname:
            try:
                group = Group.get(ldb, cn=groupname)
            except ModelError as e:
                raise CommandError(e)

            if group is None:
                raise CommandError(f"Group {groupname} not found.")

            sddl = group.get_authentication_sddl()

        elif siloname:
            try:
                silo = AuthenticationSilo.get(ldb, cn=siloname)
            except ModelError as e:
                raise CommandError(e)

            if silo is None:
                raise CommandError(f"Authentication silo {siloname} not found.")

            sddl = silo.get_authentication_sddl()

        else:
            raise CommandError("Either --by-group or --by-silo expected.")

        policy.service_allowed_to_authenticate_to = sddl

        try:
            policy.save(ldb)
        except ModelError as e:
            raise CommandError(e)

        # Authentication policy updated successfully.
        print(f"Updated authentication policy: {name}", file=self.outf)
        print(f"Updated SDDL: {sddl}", file=self.outf)


class cmd_domain_auth_policy_service_allowed_to_authenticate_to(SuperCommand):
    """Manage the service-allowed-to-authenticate-to property."""

    subcommands = {
        "set": cmd_domain_auth_policy_service_allowed_to_authenticate_to_set(),
    }
