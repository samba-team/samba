# Unix SMB/CIFS implementation.
#
# manage assigned authentication policies on a user
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
from samba.domain.models import AuthenticationPolicy, User
from samba.domain.models.exceptions import ModelError
from samba.netcmd import Command, CommandError, Option, SuperCommand


class cmd_user_auth_policy_assign(Command):
    """Set the assigned authentication policy on a user."""

    synopsis = "%prog <username> [options]"

    takes_args = ["username"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    takes_options = [
        Option("--policy", help="Authentication policy name.",
               action="store", dest="policy_name", type=str, required=True),
    ]

    def run(self, username, hostopts=None, sambaopts=None, credopts=None,
            policy_name=None):

        ldb = self.ldb_connect(hostopts, sambaopts, credopts)

        try:
            user = User.find(ldb, username)
            policy = AuthenticationPolicy.get(ldb, name=policy_name)
        except ModelError as e:
            raise CommandError(e)

        # User and policy exist.
        if user is None:
            raise CommandError(f"User {username} not found.")
        if policy is None:
            raise CommandError(f"Authentication policy {policy_name} not found.")

        # Set assigned policy.
        user.assigned_policy = policy.dn

        try:
            user.save(ldb)
        except ModelError as e:
            raise CommandError(f"Set assigned authentication policy failed: {e}")

        print(f"User {username} assigned to authentication policy {policy}",
              file=self.outf)


class cmd_user_auth_policy_remove(Command):
    """Remove the assigned authentication policy on a user."""

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

        # Get previous policy for display.
        if user.assigned_policy:
            try:
                policy = AuthenticationPolicy.get(ldb, dn=user.assigned_policy)
            except ModelError as e:
                raise CommandError(e)
        else:
            policy = None

        # Unset assigned authentication policy
        user.assigned_policy = None

        try:
            user.save(ldb)
        except ModelError as e:
            raise CommandError(f"Remove assigned authentication policy failed: {e}")

        print(f"User {username} removed from authentication policy {policy}",
              file=self.outf)


class cmd_user_auth_policy_view(Command):
    """View the current assigned authentication policy on a user."""

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

            # Check user exists before fetching policy.
            if user is None:
                raise CommandError(f"User {username} not found.")

            if user.assigned_policy:
                policy = AuthenticationPolicy.get(ldb, dn=user.assigned_policy)
            else:
                policy = None

        except ModelError as e:
            raise CommandError(e)

        if policy:
            print(f"User {username} assigned to authentication policy {policy}",
                  file=self.outf)
        else:
            print(f"User {username} has no assigned authentication policy.",
                  file=self.outf)


class cmd_user_auth_policy(SuperCommand):
    """Manage authentication policies on a user."""

    subcommands = {
        "assign": cmd_user_auth_policy_assign(),
        "remove": cmd_user_auth_policy_remove(),
        "view": cmd_user_auth_policy_view(),
    }
