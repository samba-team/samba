# Unix SMB/CIFS implementation.
#
# claim value type management
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

import samba.getopt as options
from samba.auth import system_session
from samba.netcmd import CommandError, Option, SuperCommand
from samba.samdb import SamDB

from .base import ClaimCommand


class cmd_domain_claim_value_type_list(ClaimCommand):
    """List claim values types on the domain."""

    synopsis = "%prog -H <URL> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server.",
               type=str, metavar="URL", dest="ldap_url"),
        Option("--json", help="Output results in JSON format.",
               dest="output_format", action="store_const", const="json"),
    ]

    def run(self, ldap_url=None, sambaopts=None, credopts=None,
            output_format=None):

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)
        self.ldb = SamDB(ldap_url, credentials=creds,
                         session_info=system_session(lp), lp=lp)

        # Claim value types grouped by displayName.
        value_types = {v["displayName"]: v for v in self.get_value_types()}

        # Using json output format gives more detail.
        if output_format == "json":
            json_data = json.dumps(value_types, indent=2, sort_keys=True)
            self.outf.write(f"{json_data}\n")
        else:
            for claim_type in value_types.keys():
                self.outf.write(f"{claim_type}\n")


class cmd_domain_claim_value_type_view(ClaimCommand):
    """View a single claim value type on the domain."""

    synopsis = "%prog -H <URL> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server.",
               type=str, metavar="URL", dest="ldap_url"),
        Option("--name",
               help="Display name of claim value type to view (required).",
               dest="display_name", action="store", type=str),
    ]

    def run(self, ldap_url=None, sambaopts=None, credopts=None,
            display_name=None):

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)
        self.ldb = SamDB(ldap_url, credentials=creds,
                         session_info=system_session(lp), lp=lp)

        if not display_name:
            raise CommandError("Argument --name is required.")

        value_type = self.get_value_type(display_name)
        if value_type is None:
            raise CommandError(f"Value type {display_name} not found.")

        # Display one value type as JSON.
        serialized = self.serialize_message(value_type)
        json_data = json.dumps(serialized, indent=2, sort_keys=True)
        self.outf.write(f"{json_data}\n")


class cmd_domain_claim_value_type(SuperCommand):
    """Manage claim value types on the domain."""

    subcommands = {
        "list": cmd_domain_claim_value_type_list(),
        "view": cmd_domain_claim_value_type_view(),
    }
