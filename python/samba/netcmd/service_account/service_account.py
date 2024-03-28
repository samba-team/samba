# Unix SMB/CIFS implementation.
#
# Manage service accounts and group managed service accounts.
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

from samba.domain.models import GroupManagedServiceAccount
from samba.domain.models.exceptions import ModelError
from samba.getopt import CredentialsOptions, HostOptions, Option, SambaOptions
from samba.netcmd import Command, CommandError


class cmd_service_account_list(Command):
    """List service accounts."""

    synopsis = "%prog -H <URL> [options]"

    takes_optiongroups = {
        "sambaopts": SambaOptions,
        "credopts": CredentialsOptions,
        "hostopts": HostOptions,
    }

    takes_options = [
        Option("--json", help="Output results in JSON format.",
               dest="output_format", action="store_const", const="json"),
    ]

    def run(self, hostopts=None, sambaopts=None, credopts=None,
            output_format=None):

        ldb = self.ldb_connect(hostopts, sambaopts, credopts)

        try:
            accounts = GroupManagedServiceAccount.query(ldb)
        except ModelError as e:
            raise CommandError(e)

        if output_format == "json":
            self.print_json({account.account_name: account for account in accounts})
        else:
            for account in accounts:
                print(account.account_name, file=self.outf)


class cmd_service_account_view(Command):
    """View a service account on the domain."""

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
    ]

    def run(self, hostopts=None, sambaopts=None, credopts=None, name=None):

        ldb = self.ldb_connect(hostopts, sambaopts, credopts)

        try:
            account = GroupManagedServiceAccount.find(ldb, name)
        except ModelError as e:
            raise CommandError(e)

        if account is None:
            raise CommandError(f"Group managed service account {name} not found.")

        self.print_json(account.as_dict())


class cmd_service_account_create(Command):
    """Create a new service account."""

    synopsis = "%prog -H <URL> [options]"

    takes_optiongroups = {
        "sambaopts": SambaOptions,
        "credopts": CredentialsOptions,
        "hostopts": HostOptions,
    }

    takes_options = [
        Option("--name", help="Name of managed service account (required).",
               dest="name", action="store", type=str, required=True),
        Option("--dns-host-name", help="DNS hostname of this service account (required).",
               dest="dns_host_name", action="store", type=str, required=True),
        Option("--group-msa-membership",
               help="Provide optional Group MSA Membership SDDL.",
               dest="group_msa_membership", action="store", type=str),
        Option("--managed-password-interval",
               help="Managed password refresh interval in days.",
               dest="managed_password_interval", action="store", type=int),
    ]

    def run(self, hostopts=None, sambaopts=None, credopts=None, name=None,
            dns_host_name=None, group_msa_membership=None,
            managed_password_interval=None):

        ldb = self.ldb_connect(hostopts, sambaopts, credopts)

        gmsa = GroupManagedServiceAccount(
            name=name,
            managed_password_interval=managed_password_interval,
            dns_host_name=dns_host_name,
            group_msa_membership=group_msa_membership,
        )

        # Create group managed service account.
        try:
            gmsa.save(ldb)
        except ModelError as e:
            raise CommandError(e)

        print(f"Created group managed service account: {name}", file=self.outf)


class cmd_service_account_modify(Command):
    """Modify a managed service account."""

    synopsis = "%prog -H <URL> [options]"

    takes_optiongroups = {
        "sambaopts": SambaOptions,
        "credopts": CredentialsOptions,
        "hostopts": HostOptions,
    }

    takes_options = [
        Option("--name", help="Name of managed service account (required).",
               dest="name", action="store", type=str, required=True),
        Option("--dns-host-name", help="Update DNS hostname of this service account.",
               dest="dns_host_name", action="store", type=str),
        Option("--group-msa-membership",
               help="Update Group MSA Membership field directly (SDDL).",
               dest="group_msa_membership", action="store", type=str),
    ]

    def run(self, hostopts=None, sambaopts=None, credopts=None, name=None,
            dns_host_name=None, group_msa_membership=None):

        ldb = self.ldb_connect(hostopts, sambaopts, credopts)

        try:
            gmsa = GroupManagedServiceAccount.find(ldb, name)
        except ModelError as e:
            raise CommandError(e)

        if gmsa is None:
            raise CommandError(f"Group managed service account {name} not found.")

        if dns_host_name is not None:
            gmsa.dns_host_name = dns_host_name

        if group_msa_membership is not None:
            gmsa.group_msa_membership = group_msa_membership

        # Update group managed service account.
        try:
            gmsa.save(ldb)
        except ModelError as e:
            raise CommandError(e)

        print(f"Modified group managed service account: {name}", file=self.outf)


class cmd_service_account_delete(Command):
    """Delete a managed service account."""

    synopsis = "%prog -H <URL> [options]"

    takes_optiongroups = {
        "sambaopts": SambaOptions,
        "credopts": CredentialsOptions,
        "hostopts": HostOptions,
    }

    takes_options = [
        Option("--name", help="Name of managed service account (required).",
               dest="name", action="store", type=str, required=True),
    ]

    def run(self, hostopts=None, sambaopts=None, credopts=None, name=None):

        ldb = self.ldb_connect(hostopts, sambaopts, credopts)

        try:
            account = GroupManagedServiceAccount.find(ldb, name)
        except ModelError as e:
            raise CommandError(e)

        if account is None:
            raise CommandError(f"Group managed service account {name} not found.")

        try:
            account.delete(ldb)
        except ModelError as e:
            raise CommandError(e)

        print(f"Deleted group managed service account: {name}", file=self.outf)
