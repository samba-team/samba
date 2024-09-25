# Unix SMB/CIFS implementation.
#
# authentication silos - authentication policy management
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
from samba.domain.models import (MAX_TGT_LIFETIME, MIN_TGT_LIFETIME,
                                 AuthenticationPolicy, StrongNTLMPolicy)
from samba.domain.models.exceptions import ModelError
from samba.netcmd import Command, CommandError, Option
from samba.netcmd.validators import Range
from samba.nt_time import NT_TICKS_PER_SEC

def mins_to_tgt_lifetime(minutes):
    """Convert minutes to the tgt_lifetime attributes unit which is 10^-7 seconds"""
    if minutes is not None:
        return minutes * 60 * NT_TICKS_PER_SEC
    return minutes

class UserOptions(options.OptionGroup):
    """User options used by policy create and policy modify commands."""

    def __init__(self, parser):
        super().__init__(parser, "User Options")

        self.add_option("--user-tgt-lifetime-mins",
                        help="Ticket-Granting-Ticket lifetime for user accounts.",
                        dest="tgt_lifetime", type=int, action="callback",
                        callback=self.set_option,
                        validators=[Range(min=MIN_TGT_LIFETIME, max=MAX_TGT_LIFETIME)])
        self.add_option("--user-allow-ntlm-auth",
                        help="Allow NTLM network authentication despite the fact that the user "
                             "is restricted to selected devices.",
                        dest="allow_ntlm_auth", default=False,
                        action="callback", callback=self.set_option)
        self.add_option("--user-allowed-to-authenticate-from",
                        help="SDDL Rules setting which device the user is allowed to authenticate from.",
                        type=str, dest="allowed_to_authenticate_from",
                        action="callback", callback=self.set_option,
                        metavar="SDDL")
        self.add_option("--user-allowed-to-authenticate-to",
                        help="A target service, on a user account, requires the connecting user to match SDDL",
                        type=str, dest="allowed_to_authenticate_to",
                        action="callback", callback=self.set_option,
                        metavar="SDDL")


class ServiceOptions(options.OptionGroup):
    """Service options used by policy create and policy modify commands."""

    def __init__(self, parser):
        super().__init__(parser, "Service Options")

        self.add_option("--service-tgt-lifetime-mins",
                        help="Ticket-Granting-Ticket lifetime for service accounts.",
                        dest="tgt_lifetime", type=int, action="callback",
                        callback=self.set_option,
                        validators=[Range(min=MIN_TGT_LIFETIME, max=MAX_TGT_LIFETIME)])
        self.add_option("--service-allow-ntlm-auth",
                        help="Allow NTLM network authentication despite "
                             "the fact that the service account "
                             "is restricted to selected devices.",
                        dest="allow_ntlm_auth", default=False,
                        action="callback", callback=self.set_option)
        self.add_option("--service-allowed-to-authenticate-from",
                        help="SDDL Rules setting which device the "
                        "service account is allowed to authenticate from.",
                        type=str, dest="allowed_to_authenticate_from",
                        action="callback", callback=self.set_option,
                        metavar="SDDL")
        self.add_option("--service-allowed-to-authenticate-to",
                        help="The target service requires the connecting user to match SDDL",
                        type=str, dest="allowed_to_authenticate_to",
                        action="callback", callback=self.set_option,
                        metavar="SDDL")


class ComputerOptions(options.OptionGroup):
    """Computer options used by policy create and policy modify commands."""

    def __init__(self, parser):
        super().__init__(parser, "Computer Options")

        self.add_option("--computer-tgt-lifetime-mins",
                        help="Ticket-Granting-Ticket lifetime for computer accounts.",
                        dest="tgt_lifetime", type=int, action="callback",
                        callback=self.set_option,
                        validators=[Range(min=MIN_TGT_LIFETIME, max=MAX_TGT_LIFETIME)])
        self.add_option("--computer-allowed-to-authenticate-to",
                        help="The computer account (server, workstation) service requires the connecting user to match SDDL",
                        type=str, dest="allowed_to_authenticate_to",
                        action="callback", callback=self.set_option,
                        metavar="SDDL")


class cmd_domain_auth_policy_list(Command):
    """List authentication policies on the domain."""

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
            policies = AuthenticationPolicy.query(ldb)
        except ModelError as e:
            raise CommandError(e)

        # Using json output format gives more detail.
        if output_format == "json":
            self.print_json({policy.name: policy for policy in policies})
        else:
            for policy in policies:
                print(policy.name, file=self.outf)


class cmd_domain_auth_policy_view(Command):
    """View an authentication policy on the domain."""

    synopsis = "%prog -H <URL> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    takes_options = [
        Option("--name",
               help="Name of authentication policy to view (required).",
               dest="name", action="store", type=str, required=True),
    ]

    def run(self, hostopts=None, sambaopts=None, credopts=None, name=None):

        ldb = self.ldb_connect(hostopts, sambaopts, credopts)

        try:
            policy = AuthenticationPolicy.get(ldb, cn=name)
        except ModelError as e:
            raise CommandError(e)

        # Check if authentication policy exists first.
        if policy is None:
            raise CommandError(f"Authentication policy {name} not found.")

        # Display policy as JSON.
        self.print_json(policy.as_dict())


class cmd_domain_auth_policy_create(Command):
    """Create an authentication policy on the domain."""

    synopsis = "%prog -H <URL> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
        "useropts": UserOptions,
        "serviceopts": ServiceOptions,
        "computeropts": ComputerOptions,
    }

    takes_options = [
        Option("--name", help="Name of authentication policy (required).",
               dest="name", action="store", type=str, required=True),
        Option("--description",
               help="Optional description for authentication policy.",
               dest="description", action="store", type=str),
        Option("--protect",
               help="Protect authentication silo from accidental deletion.",
               dest="protect", action="store_true"),
        Option("--unprotect",
               help="Unprotect authentication silo from accidental deletion.",
               dest="unprotect", action="store_true"),
        Option("--audit",
               help="Only audit authentication policy.",
               dest="audit", action="store_true"),
        Option("--enforce",
               help="Enforce authentication policy.",
               dest="enforce", action="store_true"),
        Option("--strong-ntlm-policy",
               help=f"Strong NTLM Policy ({StrongNTLMPolicy.choices_str()}).",
               dest="strong_ntlm_policy", type="choice", action="store",
               choices=StrongNTLMPolicy.get_choices(),
               default="Disabled"),
    ]

    def run(self, hostopts=None, sambaopts=None, credopts=None, useropts=None,
            serviceopts=None, computeropts=None, name=None, description=None,
            protect=None, unprotect=None, audit=None, enforce=None,
            strong_ntlm_policy=None):

        if protect and unprotect:
            raise CommandError("--protect and --unprotect cannot be used together.")
        if audit and enforce:
            raise CommandError("--audit and --enforce cannot be used together.")

        ldb = self.ldb_connect(hostopts, sambaopts, credopts)

        try:
            policy = AuthenticationPolicy.get(ldb, cn=name)
        except ModelError as e:
            raise CommandError(e)

        # Make sure authentication policy doesn't already exist.
        if policy is not None:
            raise CommandError(f"Authentication policy {name} already exists.")

        # New policy object.
        policy = AuthenticationPolicy(
            cn=name,
            description=description,
            strong_ntlm_policy=StrongNTLMPolicy[strong_ntlm_policy.upper()],
            user_allow_ntlm_auth=useropts.allow_ntlm_auth,
            user_tgt_lifetime=mins_to_tgt_lifetime(useropts.tgt_lifetime),
            user_allowed_to_authenticate_from=useropts.allowed_to_authenticate_from,
            user_allowed_to_authenticate_to=useropts.allowed_to_authenticate_to,
            service_allow_ntlm_auth=serviceopts.allow_ntlm_auth,
            service_tgt_lifetime=mins_to_tgt_lifetime(serviceopts.tgt_lifetime),
            service_allowed_to_authenticate_from=serviceopts.allowed_to_authenticate_from,
            service_allowed_to_authenticate_to=serviceopts.allowed_to_authenticate_to,
            computer_tgt_lifetime=mins_to_tgt_lifetime(computeropts.tgt_lifetime),
            computer_allowed_to_authenticate_to=computeropts.allowed_to_authenticate_to,
        )

        # Either --enforce will be set or --audit but never both.
        # The default if both are missing is enforce=True.
        if enforce is not None:
            policy.enforced = enforce
        else:
            policy.enforced = not audit

        # Create policy.
        try:
            policy.save(ldb)

            if protect:
                policy.protect(ldb)
        except ModelError as e:
            raise CommandError(e)

        # Authentication policy created successfully.
        print(f"Created authentication policy: {name}", file=self.outf)


class cmd_domain_auth_policy_modify(Command):
    """Modify authentication policies on the domain."""

    synopsis = "%prog -H <URL> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
        "useropts": UserOptions,
        "serviceopts": ServiceOptions,
        "computeropts": ComputerOptions,
    }

    takes_options = [
        Option("--name", help="Name of authentication policy (required).",
               dest="name", action="store", type=str, required=True),
        Option("--description",
               help="Optional description for authentication policy.",
               dest="description", action="store", type=str),
        Option("--protect",
               help="Protect authentication silo from accidental deletion.",
               dest="protect", action="store_true"),
        Option("--unprotect",
               help="Unprotect authentication silo from accidental deletion.",
               dest="unprotect", action="store_true"),
        Option("--audit",
               help="Only audit authentication policy.",
               dest="audit", action="store_true"),
        Option("--enforce",
               help="Enforce authentication policy.",
               dest="enforce", action="store_true"),
        Option("--strong-ntlm-policy",
               help=f"Strong NTLM Policy ({StrongNTLMPolicy.choices_str()}).",
               dest="strong_ntlm_policy", type="choice", action="store",
               choices=StrongNTLMPolicy.get_choices()),
    ]

    def run(self, hostopts=None, sambaopts=None, credopts=None, useropts=None,
            serviceopts=None, computeropts=None, name=None, description=None,
            protect=None, unprotect=None, audit=None, enforce=None,
            strong_ntlm_policy=None):

        if protect and unprotect:
            raise CommandError("--protect and --unprotect cannot be used together.")
        if audit and enforce:
            raise CommandError("--audit and --enforce cannot be used together.")

        ldb = self.ldb_connect(hostopts, sambaopts, credopts)

        try:
            policy = AuthenticationPolicy.get(ldb, cn=name)
        except ModelError as e:
            raise CommandError(e)

        # Check if authentication policy exists.
        if policy is None:
            raise CommandError(f"Authentication policy {name} not found.")

        # Either --enforce will be set or --audit but never both.
        if enforce:
            policy.enforced = True
        elif audit:
            policy.enforced = False

        # Update the description.
        if description is not None:
            policy.description = description

        # User sign on
        ###############

        if strong_ntlm_policy is not None:
            policy.strong_ntlm_policy = \
                StrongNTLMPolicy[strong_ntlm_policy.upper()]

        if useropts.tgt_lifetime is not None:
            policy.user_tgt_lifetime = mins_to_tgt_lifetime(useropts.tgt_lifetime)

        if useropts.allowed_to_authenticate_from is not None:
            policy.user_allowed_to_authenticate_from = \
                useropts.allowed_to_authenticate_from

        if useropts.allowed_to_authenticate_to is not None:
            policy.user_allowed_to_authenticate_to = \
                useropts.allowed_to_authenticate_to

        # Service sign on
        ##################

        if serviceopts.tgt_lifetime is not None:
            policy.service_tgt_lifetime = mins_to_tgt_lifetime(serviceopts.tgt_lifetime)

        if serviceopts.allowed_to_authenticate_from is not None:
            policy.service_allowed_to_authenticate_from = \
                serviceopts.allowed_to_authenticate_from

        if serviceopts.allowed_to_authenticate_to is not None:
            policy.service_allowed_to_authenticate_to = \
                serviceopts.allowed_to_authenticate_to

        # Computer
        ###########

        if computeropts.tgt_lifetime is not None:
            policy.computer_tgt_lifetime = mins_to_tgt_lifetime(computeropts.tgt_lifetime)

        if computeropts.allowed_to_authenticate_to is not None:
            policy.computer_allowed_to_authenticate_to = \
                computeropts.allowed_to_authenticate_to

        # Update policy.
        try:
            policy.save(ldb)

            if protect:
                policy.protect(ldb)
            elif unprotect:
                policy.unprotect(ldb)
        except ModelError as e:
            raise CommandError(e)

        # Authentication policy updated successfully.
        print(f"Updated authentication policy: {name}", file=self.outf)


class cmd_domain_auth_policy_delete(Command):
    """Delete authentication policies on the domain."""

    synopsis = "%prog -H <URL> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    takes_options = [
        Option("--name", help="Name of authentication policy (required).",
               dest="name", action="store", type=str, required=True),
        Option("--force", help="Force delete protected authentication policy.",
               dest="force", action="store_true")
    ]

    def run(self, hostopts=None, sambaopts=None, credopts=None, name=None,
            force=None):

        ldb = self.ldb_connect(hostopts, sambaopts, credopts)

        try:
            policy = AuthenticationPolicy.get(ldb, cn=name)
        except ModelError as e:
            raise CommandError(e)

        # Check if authentication policy exists first.
        if policy is None:
            raise CommandError(f"Authentication policy {name} not found.")

        # Delete item, --force removes delete protection first.
        try:
            if force:
                policy.unprotect(ldb)

            policy.delete(ldb)
        except ModelError as e:
            if not force:
                raise CommandError(
                    f"{e}\nTry --force to delete protected authentication policies.")

            raise CommandError(e)

        # Authentication policy deleted successfully.
        print(f"Deleted authentication policy: {name}", file=self.outf)
