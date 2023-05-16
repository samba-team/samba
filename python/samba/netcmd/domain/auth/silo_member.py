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
from ldb import Dn, LdbError
from samba.netcmd import CommandError, Option, SuperCommand
from samba.netcmd.domain.models import AuthenticationSilo, User

from .base import SiloCommand


class cmd_domain_auth_silo_member_add(SiloCommand):
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

        self.ldb = self.ldb_connect(ldap_url, sambaopts, credopts)

        # Check if authentication silo exists first.
        silo = AuthenticationSilo.get(self.ldb, cn=name)
        if silo is None:
            raise CommandError(f"Authentication silo {name} not found.")

        # Try a Dn first, then sAMAccountName.
        try:
            user = User.get(self.ldb, dn=Dn(self.ldb, member))
        except ValueError:
            user = User.get(self.ldb, username=member)

        # Ensure the user actually exists first.
        if user is None:
            raise CommandError(f"User '{member}' not found.")

        # Check if user isn't already assigned to another silo.
        if user.assigned_silo:
            assigned_silo = AuthenticationSilo.get(self.ldb,
                                                   dn=user.assigned_silo)
            raise CommandError(
                f"Member '{member}' is already in the {assigned_silo} silo.")

        # Check if the user isn't already in this silo.
        if user.dn in silo.members:
            raise CommandError(
                f"Member '{member}' is already in the {name} silo.")

        # Add user dn to silo members and set the assigned silo.
        silo.members.append(user.dn)
        user.assigned_silo = silo.dn

        try:
            silo.save(self.ldb)
            user.save(self.ldb)
        except LdbError as e:
            raise CommandError(e)

        self.outf.write(f"User '{user.name}' added to the {name} silo.\n")


class cmd_domain_auth_silo_member_list(SiloCommand):
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

        self.ldb = self.ldb_connect(ldap_url, sambaopts, credopts)

        # Check if authentication silo exists first.
        silo = AuthenticationSilo.get(self.ldb, cn=name)
        if silo is None:
            raise CommandError(f"Authentication silo {name} not found.")

        # Fetch all members.
        members = [User.get(self.ldb, dn=dn) for dn in silo.members]

        # Using json output format gives more detail.
        if output_format == "json":
            self.print_json([member.as_dict() for member in members])
        else:
            for member in members:
                self.outf.write(f"{member.dn}\n")


class cmd_domain_auth_silo_member_remove(SiloCommand):
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

        self.ldb = self.ldb_connect(ldap_url, sambaopts, credopts)

        # Check if authentication silo exists first.
        silo = AuthenticationSilo.get(self.ldb, cn=name)
        if silo is None:
            raise CommandError(f"Authentication silo {name} not found.")

        # Try a Dn first, then sAMAccountName.
        try:
            user = User.get(self.ldb, dn=Dn(self.ldb, member))
        except ValueError:
            user = User.get(self.ldb, username=member)

        # Ensure the user actually exists first.
        if user is None:
            raise CommandError(f"User '{member}' not found.")

        # Make sure member is in the silo before removing them.
        # Also unset the assigned silo on the User object.
        if user.dn in silo.members:
            silo.members.remove(user.dn)
            user.assigned_silo = None
        else:
            raise CommandError(f"User '{member}' is not in the {name} silo.")

        try:
            silo.save(self.ldb)
            user.save(self.ldb)
        except LdbError as e:
            raise CommandError(e)

        self.outf.write(f"User '{user.name}' removed from the {name} silo.\n")


class cmd_domain_auth_silo_member(SuperCommand):
    """Manage members in an authentication silo."""

    subcommands = {
        "add": cmd_domain_auth_silo_member_add(),
        "list": cmd_domain_auth_silo_member_list(),
        "remove": cmd_domain_auth_silo_member_remove(),
    }
