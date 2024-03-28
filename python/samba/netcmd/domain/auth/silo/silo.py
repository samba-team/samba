# Unix SMB/CIFS implementation.
#
# authentication silos - authentication silo management
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
from samba.domain.models import AuthenticationPolicy, AuthenticationSilo
from samba.domain.models.exceptions import ModelError
from samba.netcmd import Command, CommandError, Option


class cmd_domain_auth_silo_list(Command):
    """List authentication silos on the domain."""

    synopsis = "%prog -H <URL> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    takes_options = [
        Option("--json", help="Output results in JSON format.",
               dest="output_format", action="store_const", const="json"),
    ]

    def run(self, hostopts=None, sambaopts=None, credopts=None,
            output_format=None):

        ldb = self.ldb_connect(hostopts, sambaopts, credopts)

        try:
            silos = AuthenticationSilo.query(ldb)
        except ModelError as e:
            raise CommandError(e)

        # Using json output format gives more detail.
        if output_format == "json":
            self.print_json({silo.name: silo for silo in silos})
        else:
            for silo in silos:
                print(silo.name, file=self.outf)


class cmd_domain_auth_silo_view(Command):
    """View an authentication silo on the domain."""

    synopsis = "%prog -H <URL> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    takes_options = [
        Option("--name",
               help="Name of authentication silo to view (required).",
               dest="name", action="store", type=str, required=True),
    ]

    def run(self, hostopts=None, sambaopts=None, credopts=None, name=None):

        ldb = self.ldb_connect(hostopts, sambaopts, credopts)

        try:
            silo = AuthenticationSilo.get(ldb, cn=name)
        except ModelError as e:
            raise CommandError(e)

        # Check if silo exists first.
        if silo is None:
            raise CommandError(f"Authentication silo {name} not found.")

        # Display silo as JSON.
        self.print_json(silo.as_dict())


class cmd_domain_auth_silo_create(Command):
    """Create a new authentication silo on the domain."""

    synopsis = "%prog -H <URL> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    takes_options = [
        Option("--name", help="Name of authentication silo (required).",
               dest="name", action="store", type=str, required=True),
        Option("--description",
               help="Optional description for authentication silo.",
               dest="description", action="store", type=str),
        Option("--user-authentication-policy",
               help="User account authentication policy.",
               dest="user_authentication_policy", action="store", type=str,
               metavar="USER_POLICY"),
        Option("--service-authentication-policy",
               help="Managed service account authentication policy.",
               dest="service_authentication_policy", action="store", type=str,
               metavar="SERVICE_POLICY"),
        Option("--computer-authentication-policy",
               help="Computer authentication policy.",
               dest="computer_authentication_policy", action="store", type=str,
               metavar="COMPUTER_POLICY"),
        Option("--protect",
               help="Protect authentication silo from accidental deletion.",
               dest="protect", action="store_true"),
        Option("--unprotect",
               help="Unprotect authentication silo from accidental deletion.",
               dest="unprotect", action="store_true"),
        Option("--audit",
               help="Only audit silo policies.",
               dest="audit", action="store_true"),
        Option("--enforce",
               help="Enforce silo policies.",
               dest="enforce", action="store_true")
    ]

    @staticmethod
    def get_policy(ldb, name):
        """Helper function to fetch auth policy or raise CommandError.

        :param ldb: Ldb connection
        :param name: Either the DN or name of authentication policy
        """
        try:
            return AuthenticationPolicy.find(ldb, name)
        except (ModelError, ValueError) as e:
            raise CommandError(e)

    def run(self, hostopts=None, sambaopts=None, credopts=None,
            name=None, description=None,
            user_authentication_policy=None,
            service_authentication_policy=None,
            computer_authentication_policy=None,
            protect=None, unprotect=None,
            audit=None, enforce=None):

        if protect and unprotect:
            raise CommandError("--protect and --unprotect cannot be used together.")
        if audit and enforce:
            raise CommandError("--audit and --enforce cannot be used together.")

        ldb = self.ldb_connect(hostopts, sambaopts, credopts)

        try:
            silo = AuthenticationSilo.get(ldb, cn=name)
        except ModelError as e:
            raise CommandError(e)

        # Make sure silo doesn't already exist.
        if silo is not None:
            raise CommandError(f"Authentication silo {name} already exists.")

        # New silo object.
        silo = AuthenticationSilo(cn=name, description=description)

        # Set user policy
        if user_authentication_policy:
            silo.user_authentication_policy = \
                self.get_policy(ldb, user_authentication_policy).dn

        # Set service policy
        if service_authentication_policy:
            silo.service_authentication_policy = \
                self.get_policy(ldb, service_authentication_policy).dn

        # Set computer policy
        if computer_authentication_policy:
            silo.computer_authentication_policy = \
                self.get_policy(ldb, computer_authentication_policy).dn

        # Either --enforce will be set or --audit but never both.
        # The default if both are missing is enforce=True.
        if enforce is not None:
            silo.enforced = enforce
        else:
            silo.enforced = not audit

        # Create silo
        try:
            silo.save(ldb)

            if protect:
                silo.protect(ldb)
        except ModelError as e:
            raise CommandError(e)

        # Authentication silo created successfully.
        print(f"Created authentication silo: {name}", file=self.outf)


class cmd_domain_auth_silo_modify(Command):
    """Modify an authentication silo on the domain."""

    synopsis = "%prog -H <URL> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    takes_options = [
        Option("--name", help="Name of authentication silo (required).",
               dest="name", action="store", type=str, required=True),
        Option("--description",
               help="Optional description for authentication silo.",
               dest="description", action="store", type=str),
        Option("--user-authentication-policy",
               help="User account authentication policy.",
               dest="user_authentication_policy", action="store", type=str,
               metavar="USER_POLICY"),
        Option("--service-authentication-policy",
               help="Managed service account authentication policy.",
               dest="service_authentication_policy", action="store", type=str,
               metavar="SERVICE_POLICY"),
        Option("--computer-authentication-policy",
               help="Computer authentication policy.",
               dest="computer_authentication_policy", action="store", type=str,
               metavar="COMPUTER_POLICY"),
        Option("--protect",
               help="Protect authentication silo from accidental deletion.",
               dest="protect", action="store_true"),
        Option("--unprotect",
               help="Unprotect authentication silo from accidental deletion.",
               dest="unprotect", action="store_true"),
        Option("--audit",
               help="Only audit silo policies.",
               dest="audit", action="store_true"),
        Option("--enforce",
               help="Enforce silo policies.",
               dest="enforce", action="store_true")
    ]

    @staticmethod
    def get_policy(ldb, name):
        """Helper function to fetch auth policy or raise CommandError.

        :param ldb: Ldb connection
        :param name: Either the DN or name of authentication policy
        """
        try:
            return AuthenticationPolicy.find(ldb, name)
        except (ModelError, ValueError) as e:
            raise CommandError(e)

    def run(self, hostopts=None, sambaopts=None, credopts=None,
            name=None, description=None,
            user_authentication_policy=None,
            service_authentication_policy=None,
            computer_authentication_policy=None,
            protect=None, unprotect=None,
            audit=None, enforce=None):

        if audit and enforce:
            raise CommandError("--audit and --enforce cannot be used together.")
        if protect and unprotect:
            raise CommandError("--protect and --unprotect cannot be used together.")

        ldb = self.ldb_connect(hostopts, sambaopts, credopts)

        try:
            silo = AuthenticationSilo.get(ldb, cn=name)
        except ModelError as e:
            raise CommandError(e)

        # Check if silo exists first.
        if silo is None:
            raise CommandError(f"Authentication silo {name} not found.")

        # Either --enforce will be set or --audit but never both.
        if enforce:
            silo.enforced = True
        elif audit:
            silo.enforced = False

        # Update the description.
        if description is not None:
            silo.description = description

        # Set or unset user policy.
        if user_authentication_policy == "":
            silo.user_authentication_policy = None
        elif user_authentication_policy:
            silo.user_authentication_policy = \
                self.get_policy(ldb, user_authentication_policy).dn

        # Set or unset service policy.
        if service_authentication_policy == "":
            silo.service_authentication_policy = None
        elif service_authentication_policy:
            silo.service_authentication_policy = \
                self.get_policy(ldb, service_authentication_policy).dn

        # Set or unset computer policy.
        if computer_authentication_policy == "":
            silo.computer_authentication_policy = None
        elif computer_authentication_policy:
            silo.computer_authentication_policy = \
                self.get_policy(ldb, computer_authentication_policy).dn

        # Update silo
        try:
            silo.save(ldb)

            if protect:
                silo.protect(ldb)
            elif unprotect:
                silo.unprotect(ldb)
        except ModelError as e:
            raise CommandError(e)

        # Silo updated successfully.
        print(f"Updated authentication silo: {name}", file=self.outf)


class cmd_domain_auth_silo_delete(Command):
    """Delete an authentication silo on the domain."""

    synopsis = "%prog -H <URL> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    takes_options = [
        Option("--name", help="Name of authentication silo (required).",
               dest="name", action="store", type=str, required=True),
        Option("--force", help="Force delete protected authentication silo.",
               dest="force", action="store_true")
    ]

    def run(self, hostopts=None, sambaopts=None, credopts=None, name=None,
            force=None):

        ldb = self.ldb_connect(hostopts, sambaopts, credopts)

        try:
            silo = AuthenticationSilo.get(ldb, cn=name)
        except ModelError as e:
            raise CommandError(e)

        # Check if silo exists first.
        if silo is None:
            raise CommandError(f"Authentication silo {name} not found.")

        # Delete silo
        try:
            if force:
                silo.unprotect(ldb)

            silo.delete(ldb)
        except ModelError as e:
            if not force:
                raise CommandError(
                    f"{e}\nTry --force to delete protected authentication silos.")

            raise CommandError(e)

        # Authentication silo deleted successfully.
        print(f"Deleted authentication silo: {name}", file=self.outf)
