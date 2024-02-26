# Unix SMB/CIFS implementation.
#
# Manage who can view service account passwords.
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

from samba.getopt import CredentialsOptions, HostOptions, Option, SambaOptions
from samba.netcmd import Command, CommandError, SuperCommand
from samba.netcmd.domain.models import (Group, GroupManagedServiceAccount,
                                        Model, User)
from samba.netcmd.domain.models.exceptions import ModelError


class cmd_service_account_group_msa_membership_show(Command):
    """Display who is able to view the service account password."""

    synopsis = "%prog -H <URL> [options]"

    takes_optiongroups = {
        "sambaopts": SambaOptions,
        "credopts": CredentialsOptions,
        "hostopts": HostOptions,
    }

    takes_options = [
        Option("--name",
               help="Name of managed service account (required).",
               dest="name", action="store", type=str, required=True),
        Option("--json", help="Output results in JSON format.",
               dest="output_format", action="store_const", const="json"),
    ]

    def run(self, hostopts=None, sambaopts=None, credopts=None, name=None,
            output_format=None):

        ldb = self.ldb_connect(hostopts, sambaopts, credopts)

        try:
            gmsa = GroupManagedServiceAccount.find(ldb, name)
        except ModelError as e:
            raise CommandError(e)

        if gmsa is None:
            raise CommandError(f"Group managed service account {name} not found.")

        try:
            trustees = [Model.get(ldb, object_sid=sid, polymorphic=True) for sid in gmsa.trustees]
        except ModelError as e:
            raise CommandError(e)

        if output_format == "json":
            self.print_json({
                "dn": gmsa.dn,
                "trustees": [trustee.dn for trustee in trustees]
            })
        else:
            print(f"Account-DN: {gmsa.dn}", file=self.outf)

            print("Accounts or groups that are able to retrieve this group managed service account password:",
                  file=self.outf)

            for trustee in trustees:
                print(f"  {trustee.dn}", file=self.outf)


class cmd_service_account_group_msa_membership_add(Command):
    """Add a password viewer."""

    synopsis = "%prog -H <URL> [options]"

    takes_optiongroups = {
        "sambaopts": SambaOptions,
        "credopts": CredentialsOptions,
        "hostopts": HostOptions,
    }

    takes_options = [
        Option("--name",
               help="Name of managed service account (required).",
               dest="name", action="store", type=str, required=True),
        Option("--principal",
               help="Principal sAMAccountName or Dn to add (required).",
               dest="principal", action="store", type=str, required=True),
    ]

    def run(self, hostopts=None, sambaopts=None, credopts=None, name=None,
            principal=None):

        ldb = self.ldb_connect(hostopts, sambaopts, credopts)

        try:
            gmsa = GroupManagedServiceAccount.find(ldb, name)
        except ModelError as e:
            raise CommandError(e)

        if gmsa is None:
            raise CommandError(f"Group managed service account {name} not found.")

        # Note that principal can be a user or group (by passing in a Dn).
        # If the Dn is a group it will see it as a User but this doesn't matter.
        try:
            trustee = User.find(ldb, principal)
        except ModelError as e:
            raise CommandError(e)

        if trustee is None:
            raise CommandError(f"Trust {principal} not found.")

        try:
            trustees = gmsa.trustees
        except ModelError as e:
            raise CommandError(e)

        if trustee.object_sid in trustees:
            print(f"Trustee '{trustee}' is already allowed to show managed passwords for: {gmsa}",
                  file=self.outf)
        else:
            gmsa.add_trustee(trustee)

            try:
                gmsa.save(ldb)
            except ModelError as e:
                raise CommandError(e)

            print(f"Trustee '{trustee}' is now allowed to show managed passwords for: {gmsa}",
                  file=self.outf)


class cmd_service_account_group_msa_membership_remove(Command):
    """Remove a password viewer."""

    synopsis = "%prog -H <URL> [options]"

    takes_optiongroups = {
        "sambaopts": SambaOptions,
        "credopts": CredentialsOptions,
        "hostopts": HostOptions,
    }

    takes_options = [
        Option("--name",
               help="Name of managed service account (required).",
               dest="name", action="store", type=str, required=True),
        Option("--principal",
               help="Principal sAMAccountName or Dn to remove (required).",
               dest="principal", action="store", type=str, required=True),
    ]

    def run(self, hostopts=None, sambaopts=None, credopts=None, name=None,
            principal=None):

        ldb = self.ldb_connect(hostopts, sambaopts, credopts)

        try:
            gmsa = GroupManagedServiceAccount.find(ldb, name)
        except ModelError as e:
            raise CommandError(e)

        if gmsa is None:
            raise CommandError(f"Group managed service account {name} not found.")

        # Note that principal can be a user or group (by passing in a Dn).
        # If the Dn is a group it will see it as a User but this doesn't matter.
        try:
            trustee = User.find(ldb, principal)
        except ModelError as e:
            raise CommandError(e)

        if trustee is None:
            raise CommandError(f"User {principal} not found.")

        try:
            trustees = gmsa.trustees
        except ModelError as e:
            raise CommandError(e)

        if trustee.object_sid not in trustees:
            print(f"Trustee '{trustee}' cannot currently show managed passwords for: {gmsa}",
                  file=self.outf)
        else:
            gmsa.remove_trustee(trustee)

            try:
                gmsa.save(ldb)
            except ModelError as e:
                raise CommandError(e)

            print(f"Trustee '{trustee}' removed access to show managed passwords for: {gmsa}",
                  file=self.outf)


class cmd_service_account_group_msa_membership(SuperCommand):
    """View and manage password retrieval for service account."""

    # set sddl
    subcommands = {
        "show": cmd_service_account_group_msa_membership_show(),
        "add": cmd_service_account_group_msa_membership_add(),
        "remove": cmd_service_account_group_msa_membership_remove(),
    }
