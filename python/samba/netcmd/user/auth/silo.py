# Unix SMB/CIFS implementation.
#
# manage assigned authentication silos on a user
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


class cmd_user_auth_silo_assign(Command):
    """Set the assigned authentication silo on a user."""

    synopsis = "%prog <username> [options]"

    takes_args = ["username"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    takes_options = [
        Option("--silo", help="Authentication silo name.",
               action="store", dest="silo_name", type=str, required=True),
    ]

    def run(self, username, hostopts=None, sambaopts=None, credopts=None,
            silo_name=None):

        ldb = self.ldb_connect(hostopts, sambaopts, credopts)

        try:
            user = User.find(ldb, username)
            silo = AuthenticationSilo.get(ldb, name=silo_name)
        except ModelError as e:
            raise CommandError(e)

        # User and silo exist.
        if user is None:
            raise CommandError(f"User {username} not found.")
        if silo is None:
            raise CommandError(f"Authentication silo {silo_name} not found.")

        # Set assigned silo.
        user.assigned_silo = silo.dn

        try:
            user.save(ldb)
        except ModelError as e:
            raise CommandError(f"Set assigned authentication silo failed: {e}")

        # Display silo member status.
        if user.dn in silo.members:
            status = "granted"
        else:
            status = "revoked"

        print(f"User {username} assigned to authentication silo {silo} ({status})",
              file=self.outf)


class cmd_user_auth_silo_remove(Command):
    """Remove the assigned authentication silo on a user."""

    synopsis = "%prog <username> [options]"

    takes_args = ["username"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    def run(self, username, hostopts=None, sambaopts=None, credopts=None):

        ldb = self.ldb_connect(hostopts, sambaopts, credopts)

        try:
            user = User.find(ldb, username)
        except ModelError as e:
            raise CommandError(e)

        # User exists
        if user is None:
            raise CommandError(f"User {username} not found.")

        # Get previous silo for display.
        if user.assigned_silo:
            try:
                silo = AuthenticationSilo.get(ldb, dn=user.assigned_silo)
            except ModelError as e:
                raise CommandError(e)
        else:
            silo = None

        # Unset assigned authentication silo
        user.assigned_silo = None

        try:
            user.save(ldb)
        except ModelError as e:
            raise CommandError(f"Remove assigned authentication silo failed: {e}")

        # Display silo member status.
        if silo and user.dn in silo.members:
            status = "granted"
        else:
            status = "revoked"

        print(f"User {username} removed from authentication silo {silo} ({status})",
              file=self.outf)


class cmd_user_auth_silo_view(Command):
    """View the current assigned authentication silo on a user."""

    synopsis = "%prog <username> [options]"

    takes_args = ["username"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    def run(self, username, hostopts=None, sambaopts=None, credopts=None):

        ldb = self.ldb_connect(hostopts, sambaopts, credopts)

        try:
            user = User.find(ldb, username)

            # Check user exists before fetching silo.
            if user is None:
                raise CommandError(f"User {username} not found.")

            # Only fetch silo is one is assigned.
            if user.assigned_silo:
                silo = AuthenticationSilo.get(ldb, dn=user.assigned_silo)
            else:
                silo = None

        except ModelError as e:
            raise CommandError(e)

        # Display silo member status.
        if silo and user.dn in silo.members:
            status = "granted"
        else:
            status = "revoked"

        if silo:
            print(f"User {username} assigned to authentication silo {silo} ({status})",
                  file=self.outf)
        else:
            print(f"User {username} has no assigned authentication silo.",
                  file=self.outf)


class cmd_user_auth_silo(SuperCommand):
    """Manage authentication silos on a user."""

    subcommands = {
        "assign": cmd_user_auth_silo_assign(),
        "remove": cmd_user_auth_silo_remove(),
        "view": cmd_user_auth_silo_view(),
    }
