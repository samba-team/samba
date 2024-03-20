# Unix SMB/CIFS implementation.
#
# authentication silos - silo member management
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

import samba.getopt as options
from samba.domain.models import AuthenticationSilo, User
from samba.domain.models.exceptions import ModelError
from samba.netcmd import Command, CommandError, Option, SuperCommand


class cmd_domain_auth_silo_member_grant(Command):
    """Grant a member access to an authentication silo."""

    synopsis = "%prog -H <URL> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    takes_options = [
        Option("--name",
               help="Name of authentication silo (required).",
               dest="name", action="store", type=str, required=True),
        Option("--member",
               help="Member to grant access to the silo (DN or account name).",
               dest="member", action="store", type=str, required=True),
    ]

    def run(self, hostopts=None, sambaopts=None, credopts=None,
            name=None, member=None):

        ldb = self.ldb_connect(hostopts, sambaopts, credopts)

        try:
            silo = AuthenticationSilo.get(ldb, cn=name)
        except ModelError as e:
            raise CommandError(e)

        # Check if authentication silo exists first.
        if silo is None:
            raise CommandError(f"Authentication silo {name} not found.")

        try:
            user = User.find(ldb, member)
        except ModelError as e:
            raise CommandError(e)

        # Ensure the user actually exists first.
        if user is None:
            raise CommandError(f"User {member} not found.")

        # Grant access to member.
        try:
            silo.grant(ldb, user)
        except ModelError as e:
            raise CommandError(e)

        # Display silo assigned status.
        if user.assigned_silo and user.assigned_silo == silo.dn:
            status = "assigned"
        else:
            status = "unassigned"

        print(f"User {user} granted access to the authentication silo {name} ({status}).",
              file=self.outf)


class cmd_domain_auth_silo_member_list(Command):
    """List all members in the authentication silo."""

    synopsis = "%prog -H <URL> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    takes_options = [
        Option("--name",
               help="Name of authentication silo (required).",
               dest="name", action="store", type=str, required=True),
        Option("--json", help="Output results in JSON format.",
               dest="output_format", action="store_const", const="json"),
    ]

    def run(self, hostopts=None, sambaopts=None, credopts=None,
            name=None, output_format=None):

        ldb = self.ldb_connect(hostopts, sambaopts, credopts)

        try:
            silo = AuthenticationSilo.get(ldb, cn=name)
        except ModelError as e:
            raise CommandError(e)

        # Check if authentication silo exists first.
        if silo is None:
            raise CommandError(f"Authentication silo {name} not found.")

        # Fetch all members.
        try:
            members = [User.get(ldb, dn=dn) for dn in silo.members]
        except ModelError as e:
            raise CommandError(e)

        # Using json output format gives more detail.
        if output_format == "json":
            self.print_json([member.as_dict() for member in members])
        else:
            for member in members:
                print(member.dn, file=self.outf)


class cmd_domain_auth_silo_member_revoke(Command):
    """Revoke a member from an authentication silo."""

    synopsis = "%prog -H <URL> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    takes_options = [
        Option("--name",
               help="Name of authentication silo (required).",
               dest="name", action="store", type=str, required=True),
        Option("--member",
               help="Member to revoke from the silo (DN or account name).",
               dest="member", action="store", type=str, required=True),
    ]

    def run(self, hostopts=None, sambaopts=None, credopts=None,
            name=None, member=None):

        ldb = self.ldb_connect(hostopts, sambaopts, credopts)

        try:
            silo = AuthenticationSilo.get(ldb, cn=name)
        except ModelError as e:
            raise CommandError(e)

        # Check if authentication silo exists first.
        if silo is None:
            raise CommandError(f"Authentication silo {name} not found.")

        try:
            user = User.find(ldb, member)
        except ModelError as e:
            raise CommandError(e)

        # Ensure the user actually exists first.
        if user is None:
            raise CommandError(f"User {member} not found.")

        # Revoke member access.
        try:
            silo.revoke(ldb, user)
        except ModelError as e:
            raise CommandError(e)

        # Display silo assigned status.
        if user.assigned_silo and user.assigned_silo == silo.dn:
            status = "assigned"
        else:
            status = "unassigned"

        print(f"User {user} revoked from the authentication silo {name} ({status}).",
              file=self.outf)


class cmd_domain_auth_silo_member(SuperCommand):
    """Manage members in an authentication silo."""

    subcommands = {
        "grant": cmd_domain_auth_silo_member_grant(),
        "list": cmd_domain_auth_silo_member_list(),
        "revoke": cmd_domain_auth_silo_member_revoke(),
    }
