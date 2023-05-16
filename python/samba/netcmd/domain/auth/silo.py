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
from ldb import LdbError
from samba.netcmd import CommandError, Option, SuperCommand
from samba.netcmd.domain.models import AuthenticationPolicy, AuthenticationSilo

from .base import SiloCommand
from .silo_member import cmd_domain_auth_silo_member


class cmd_domain_auth_silo_list(SiloCommand):
    """List authentication silos on the domain."""

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

        self.ldb = self.ldb_connect(ldap_url, sambaopts, credopts)

        # Authentication silos grouped by cn.
        silos = {silo.cn: silo.as_dict()
                 for silo in AuthenticationSilo.query(self.ldb)}

        # Using json output format gives more detail.
        if output_format == "json":
            self.print_json(silos)
        else:
            for silo in silos.keys():
                self.outf.write(f"{silo}\n")


class cmd_domain_auth_silo_view(SiloCommand):
    """View an authentication silo on the domain."""

    synopsis = "%prog -H <URL> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server.",
               type=str, metavar="URL", dest="ldap_url"),
        Option("--name",
               help="Name of authentication silo to view (required).",
               dest="name", action="store", type=str),
    ]

    def run(self, ldap_url=None, sambaopts=None, credopts=None, name=None):

        if not name:
            raise CommandError("Argument --name is required.")

        self.ldb = self.ldb_connect(ldap_url, sambaopts, credopts)

        # Check if silo exists first.
        silo = AuthenticationSilo.get(self.ldb, cn=name)
        if silo is None:
            raise CommandError(f"Authentication silo {name} not found.")

        # Display silo as JSON.
        self.print_json(silo.as_dict())


class cmd_domain_auth_silo_create(SiloCommand):
    """Create a new authentication silo on the domain."""

    synopsis = "%prog -H <URL> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server.",
               type=str, metavar="URL", dest="ldap_url"),
        Option("--name", help="Name of authentication silo (required).",
               dest="name", action="store", type=str),
        Option("--description",
               help="Optional description for authentication silo.",
               dest="description", action="store", type=str),
        Option("--policy",
               help="Use single policy for all principals in this silo.",
               dest="policy", action="store", type=str),
        Option("--user-policy",
               help="User account policy.",
               dest="user_policy", action="store", type=str),
        Option("--service-policy",
               help="Managed Service Account policy.",
               dest="service_policy", action="store", type=str),
        Option("--computer-policy",
               help="Computer account policy.",
               dest="computer_policy", action="store", type=str),
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
            return AuthenticationPolicy.lookup(ldb, name)
        except (LookupError, ValueError) as e:
            raise CommandError(e)

    def run(self, ldap_url=None, sambaopts=None, credopts=None, name=None,
            description=None, policy=None, user_policy=None,
            service_policy=None, computer_policy=None, protect=None,
            unprotect=None, audit=None, enforce=None):

        if not name:
            raise CommandError("Argument --name is required.")
        if protect and unprotect:
            raise CommandError("--protect and --unprotect cannot be used together.")
        if audit and enforce:
            raise CommandError("--audit and --enforce cannot be used together.")

        # If --policy is present start with that as the base. Then optionally
        # --user-policy, --service-policy, --computer-policy can override this.
        if policy is not None:
            user_policy = user_policy or policy
            service_policy = service_policy or policy
            computer_policy = computer_policy or policy

        self.ldb = self.ldb_connect(ldap_url, sambaopts, credopts)

        # Make sure silo doesn't already exist.
        silo = AuthenticationSilo.get(self.ldb, cn=name)
        if silo is not None:
            raise CommandError(f"Authentication silo {name} already exists.")

        # New silo object.
        silo = AuthenticationSilo(cn=name, description=description)

        # Set user policy
        if user_policy:
            silo.user_policy = self.get_policy(self.ldb, user_policy).dn

        # Set service policy
        if service_policy:
            silo.service_policy = self.get_policy(self.ldb, service_policy).dn

        # Set computer policy
        if computer_policy:
            silo.computer_policy = self.get_policy(self.ldb, computer_policy).dn

        # Either --enforce will be set or --audit but never both.
        # The default if both are missing is enforce=True.
        if enforce is not None:
            silo.enforced = enforce
        else:
            silo.enforced = not audit

        # Create silo
        try:
            silo.save(self.ldb)

            if protect:
                silo.protect(self.ldb)
        except LdbError as e:
            raise CommandError(e)

        # Authentication silo created successfully.
        self.outf.write(f"Created authentication silo: {name}\n")


class cmd_domain_auth_silo_modify(SiloCommand):
    """Modify an authentication silo on the domain."""

    synopsis = "%prog -H <URL> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server.",
               type=str, metavar="URL", dest="ldap_url"),
        Option("--name", help="Name of authentication silo (required).",
               dest="name", action="store", type=str),
        Option("--description",
               help="Optional description for authentication silo.",
               dest="description", action="store", type=str),
        Option("--policy",
               help="Set single policy for all principals in this silo.",
               dest="policy", action="store", type=str),
        Option("--user-policy",
               help="Set User account policy.",
               dest="user_policy", action="store", type=str),
        Option("--service-policy",
               help="Set Managed Service Account policy.",
               dest="service_policy", action="store", type=str),
        Option("--computer-policy",
               help="Set Computer Account policy.",
               dest="computer_policy", action="store", type=str),
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
            return AuthenticationPolicy.lookup(ldb, name)
        except (LookupError, ValueError) as e:
            raise CommandError(e)

    def run(self, ldap_url=None, sambaopts=None, credopts=None, name=None,
            description=None, policy=None, user_policy=None,
            service_policy=None, computer_policy=None, protect=None,
            unprotect=None, audit=None, enforce=None):

        if not name:
            raise CommandError("Argument --name is required.")
        if audit and enforce:
            raise CommandError("--audit and --enforce cannot be used together.")
        if protect and unprotect:
            raise CommandError("--protect and --unprotect cannot be used together.")

        # If --policy is set then start with that for all policies.
        # They can be individually overridden as well after that.
        if policy is not None:
            user_policy = user_policy or policy
            service_policy = service_policy or policy
            computer_policy = computer_policy or policy

        self.ldb = self.ldb_connect(ldap_url, sambaopts, credopts)

        # Check if silo exists first.
        silo = AuthenticationSilo.get(self.ldb, cn=name)
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
        if user_policy == "":
            silo.user_policy = None
        elif user_policy:
            silo.user_policy = self.get_policy(self.ldb, user_policy).dn

        # Set or unset service policy.
        if service_policy == "":
            silo.service_policy = None
        elif service_policy:
            silo.service_policy = self.get_policy(self.ldb, service_policy).dn

        # Set or unset computer policy.
        if computer_policy == "":
            silo.computer_policy = None
        elif computer_policy:
            silo.computer_policy = self.get_policy(self.ldb, computer_policy).dn

        # Update silo
        try:
            silo.save(self.ldb)

            if protect:
                silo.protect(self.ldb)
            elif unprotect:
                silo.unprotect(self.ldb)
        except LdbError as e:
            raise CommandError(e)

        # Silo updated successfully.
        self.outf.write(f"Updated authentication silo: {name}\n")


class cmd_domain_auth_silo_delete(SiloCommand):
    """Delete an authentication silo on the domain."""

    synopsis = "%prog -H <URL> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server.",
               type=str, metavar="URL", dest="ldap_url"),
        Option("--name", help="Name of authentication silo (required).",
               dest="name", action="store", type=str),
        Option("--force", help="Force delete protected authentication silo.",
               dest="force", action="store_true")
    ]

    def run(self, ldap_url=None, sambaopts=None, credopts=None, name=None,
            force=None):

        if not name:
            raise CommandError("Argument --name is required.")

        self.ldb = self.ldb_connect(ldap_url, sambaopts, credopts)

        # Check if silo exists first.
        silo = AuthenticationSilo.get(self.ldb, cn=name)
        if silo is None:
            raise CommandError(f"Authentication silo {name} not found.")

        # Delete silo
        try:
            if force:
                silo.unprotect(self.ldb)

            silo.delete(self.ldb)
        except LdbError as e:
            if not force:
                raise CommandError(
                    f"{e}\nTry --force to delete protected authentication silos.")
            else:
                raise CommandError(e)

        # Authentication silo deleted successfully.
        self.outf.write(f"Deleted authentication silo: {name}\n")


class cmd_domain_auth_silo(SuperCommand):
    """Manage authentication silos on the domain."""

    subcommands = {
        "list": cmd_domain_auth_silo_list(),
        "view": cmd_domain_auth_silo_view(),
        "create": cmd_domain_auth_silo_create(),
        "modify": cmd_domain_auth_silo_modify(),
        "delete": cmd_domain_auth_silo_delete(),
        "member": cmd_domain_auth_silo_member(),
    }
