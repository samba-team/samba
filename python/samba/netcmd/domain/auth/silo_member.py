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
from ldb import Dn
from samba.netcmd import Command, CommandError, Option, SuperCommand
from samba.netcmd.domain.models import AuthenticationSilo, User
from samba.netcmd.domain.models.exceptions import ModelError


class cmd_domain_auth_silo_member_add(Command):
    """Add a member to an authentication silo."""

    synopsis = "%prog -H <URL> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server.",
               type=str, metavar="URL", dest="ldap_url"),
        Option("--name",
               help="Name of authentication silo (required).",
               dest="name", action="store", type=str),
        Option("--member",
               help="Member to add to the silo (DN or account name).",
               dest="member", action="store", type=str),
    ]

    def run(self, ldap_url=None, sambaopts=None, credopts=None,
            name=None, member=None):

        if not name:
            raise CommandError("Argument --name is required.")
        if not member:
            raise CommandError("Argument --member is required.")

        ldb = self.ldb_connect(ldap_url, sambaopts, credopts)

        try:
            silo = AuthenticationSilo.get(ldb, cn=name)
        except ModelError as e:
            raise CommandError(e)

        # Check if authentication silo exists first.
        if silo is None:
            raise CommandError(f"Authentication silo {name} not found.")

        # Try a Dn first, then sAMAccountName.
        try:
            user_query = {"dn": Dn(ldb, member)}
        except ValueError:
            user_query = {"username": member}

        try:
            user = User.get(ldb, **user_query)
        except ModelError as e:
            raise CommandError(e)

        # Ensure the user actually exists first.
        if user is None:
            raise CommandError(f"User '{member}' not found.")

        # Set the assigned silo.
        user.assigned_silo = silo.dn

        # Add member and save user.
        try:
            silo.add_member(ldb, user)
            user.save(ldb)
        except ModelError as e:
            raise CommandError(e)

        self.outf.write(f"User '{user.name}' added to the {name} silo.\n")


class cmd_domain_auth_silo_member_list(Command):
    """List all members in the authentication silo."""

    synopsis = "%prog -H <URL> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server.",
               type=str, metavar="URL", dest="ldap_url"),
        Option("--name",
               help="Name of authentication silo (required).",
               dest="name", action="store", type=str),
        Option("--json", help="Output results in JSON format.",
               dest="output_format", action="store_const", const="json"),
    ]

    def run(self, ldap_url=None, sambaopts=None, credopts=None,
            name=None, output_format=None):

        if not name:
            raise CommandError("Argument --name is required.")

        ldb = self.ldb_connect(ldap_url, sambaopts, credopts)

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
                self.outf.write(f"{member.dn}\n")


class cmd_domain_auth_silo_member_remove(Command):
    """Remove a member from an authentication silo."""

    synopsis = "%prog -H <URL> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server.",
               type=str, metavar="URL", dest="ldap_url"),
        Option("--name",
               help="Name of authentication silo (required).",
               dest="name", action="store", type=str),
        Option("--member",
               help="Member to remove from the silo (DN or account name).",
               dest="member", action="store", type=str),
    ]

    def run(self, ldap_url=None, sambaopts=None, credopts=None,
            name=None, member=None):

        if not name:
            raise CommandError("Argument --name is required.")
        if not member:
            raise CommandError("Argument --member is required.")

        ldb = self.ldb_connect(ldap_url, sambaopts, credopts)

        try:
            silo = AuthenticationSilo.get(ldb, cn=name)
        except ModelError as e:
            raise CommandError(e)

        # Check if authentication silo exists first.
        if silo is None:
            raise CommandError(f"Authentication silo {name} not found.")

        # Try a Dn first, then sAMAccountName.
        try:
            user_query = {"dn": Dn(ldb, member)}
        except ValueError:
            user_query = {"username": member}

        try:
            user = User.get(ldb, **user_query)
        except ModelError as e:
            raise CommandError(e)

        # Ensure the user actually exists first.
        if user is None:
            raise CommandError(f"User '{member}' not found.")

        # Unset the assigned silo.
        user.assigned_silo = None

        # Remove member and save user.
        try:
            silo.remove_member(ldb, user)
            user.save(ldb)
        except ModelError as e:
            raise CommandError(e)

        self.outf.write(f"User '{user.name}' removed from the {name} silo.\n")


class cmd_domain_auth_silo_member(SuperCommand):
    """Manage members in an authentication silo."""

    subcommands = {
        "add": cmd_domain_auth_silo_member_add(),
        "list": cmd_domain_auth_silo_member_list(),
        "remove": cmd_domain_auth_silo_member_remove(),
    }
