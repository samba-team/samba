# Unix SMB/CIFS implementation.
#
# claim type management
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
from samba.domain.models import AttributeSchema, ClaimType, ClassSchema
from samba.domain.models.exceptions import ModelError
from samba.netcmd import Command, CommandError, Option, SuperCommand


class cmd_domain_claim_claim_type_create(Command):
    """Create claim types on the domain."""

    synopsis = "%prog -H <URL> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    takes_options = [
        Option("--attribute", help="Attribute of claim type to create (required).",
               dest="attribute_name", action="store", type=str, required=True),
        Option("--class", help="Object classes to set claim type to.",
               dest="class_names", action="append", type=str, required=True),
        Option("--name", help="Optional display name or use attribute name.",
               dest="name", action="store", type=str),
        Option("--description",
               help="Optional description or use from attribute.",
               dest="description", action="store", type=str),
        Option("--disable", help="Disable claim type.",
               dest="disable", action="store_true"),
        Option("--enable", help="Enable claim type.",
               dest="enable", action="store_true"),
        Option("--protect",
               help="Protect claim type from accidental deletion.",
               dest="protect", action="store_true"),
        Option("--unprotect",
               help="Unprotect claim type from accidental deletion.",
               dest="unprotect", action="store_true")
    ]

    def run(self, hostopts=None, sambaopts=None, credopts=None, name=None,
            attribute_name=None, class_names=None, description=None,
            disable=None, enable=None, protect=None, unprotect=None):

        # mutually exclusive attributes
        if enable and disable:
            raise CommandError("--enable and --disable cannot be used together.")
        if protect and unprotect:
            raise CommandError("--protect and --unprotect cannot be used together.")

        ldb = self.ldb_connect(hostopts, sambaopts, credopts)

        display_name = name or attribute_name
        try:
            claim_type = ClaimType.get(ldb, display_name=display_name)
        except ModelError as e:
            raise CommandError(e)

        # Check if a claim type with this display name already exists.
        # Note: you can register the same claim type under another display name.
        if claim_type:
            raise CommandError(f"Claim type {display_name} already exists, "
                               "but you can use --name to use another name.")

        # Either --enable will be set or --disable but never both.
        # The default if both are missing is enabled=True.
        if enable is not None:
            enabled = enable
        else:
            enabled = not disable

        # Lookup attribute and class names in schema.
        try:
            applies_to = [ClassSchema.find(ldb, name) for name in class_names]
            attribute = AttributeSchema.find(ldb, attribute_name)
            claim_type = ClaimType.new_claim_type(
                ldb, attribute, applies_to, display_name,
                description, enabled)
        except (ModelError, ValueError) as e:
            raise CommandError(e)

        # Create claim type
        try:
            claim_type.save(ldb)

            if protect:
                claim_type.protect(ldb)
        except ModelError as e:
            raise CommandError(e)

        # Claim type created successfully.
        message = f"Created claim type: {display_name}"
        if attribute_name != display_name:
            message += f" ({attribute_name})"
        print(message, file=self.outf)


class cmd_domain_claim_claim_type_modify(Command):
    """Modify claim types on the domain."""

    synopsis = "%prog -H <URL> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    takes_options = [
        Option("--name", help="Display name of claim type to modify (required).",
               dest="name", action="store", type=str, required=True),
        Option("--class", help="Object classes to set claim type to.",
               dest="class_names", action="append", type=str),
        Option("--description", help="Set the claim type description.",
               dest="description", action="store", type=str),
        Option("--enable",
               help="Enable claim type.",
               dest="enable", action="store_true"),
        Option("--disable",
               help="Disable claim type.",
               dest="disable", action="store_true"),
        Option("--protect",
               help="Protect claim type from accidental deletion.",
               dest="protect", action="store_true"),
        Option("--unprotect",
               help="Unprotect claim type from accidental deletion.",
               dest="unprotect", action="store_true")
    ]

    def run(self, hostopts=None, sambaopts=None, credopts=None, name=None,
            class_names=None, description=None, enable=None, disable=None,
            protect=None, unprotect=None):

        if enable and disable:
            raise CommandError("--enable and --disable cannot be used together.")
        if protect and unprotect:
            raise CommandError("--protect and --unprotect cannot be used together.")

        ldb = self.ldb_connect(hostopts, sambaopts, credopts)

        try:
            claim_type = ClaimType.get(ldb, display_name=name)
        except ModelError as e:
            raise CommandError(e)

        # Check if claim type exists.
        if not claim_type:
            raise CommandError(f"Claim type {name} not found.")

        # Either --enable will be set or --disable but never both.
        if enable:
            claim_type.enabled = True
        elif disable:
            claim_type.enabled = False

        # Update the description.
        if description is not None:
            claim_type.description = description

        # Change class names for claim type.
        if class_names is not None:
            try:
                applies_to = [ClassSchema.find(ldb, name) for name in class_names]
            except (ModelError, ValueError) as e:
                raise CommandError(e)

            claim_type.claim_type_applies_to_class = [obj.dn for obj in applies_to]

        # Update claim type.
        try:
            claim_type.save(ldb)

            if protect:
                claim_type.protect(ldb)
            elif unprotect:
                claim_type.unprotect(ldb)
        except ModelError as e:
            raise CommandError(e)

        # Claim type updated successfully.
        print(f"Updated claim type: {name}", file=self.outf)


class cmd_domain_claim_claim_type_delete(Command):
    """Delete claim types on the domain."""

    synopsis = "%prog -H <URL> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    takes_options = [
        Option("--name", help="Display name of claim type to delete (required).",
               dest="name", action="store", type=str, required=True),
        Option("--force", help="Force claim type delete even if it is protected.",
               dest="force", action="store_true")
    ]

    def run(self, hostopts=None, sambaopts=None, credopts=None,
            name=None, force=None):

        ldb = self.ldb_connect(hostopts, sambaopts, credopts)

        try:
            claim_type = ClaimType.get(ldb, display_name=name)
        except ModelError as e:
            raise CommandError(e)

        # Check if claim type exists first.
        if claim_type is None:
            raise CommandError(f"Claim type {name} not found.")

        # Delete claim type.
        try:
            if force:
                claim_type.unprotect(ldb)

            claim_type.delete(ldb)
        except ModelError as e:
            if not force:
                raise CommandError(
                    f"{e}\nTry --force to delete protected claim types.")

            raise CommandError(e)

        # Claim type deleted successfully.
        print(f"Deleted claim type: {name}", file=self.outf)


class cmd_domain_claim_claim_type_list(Command):
    """List claim types on the domain."""

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
            claim_types = ClaimType.query(ldb)
        except ModelError as e:
            raise CommandError(e)

        # Using json output format gives more detail.
        if output_format == "json":
            self.print_json({claim_type.display_name: claim_type
                             for claim_type in claim_types})
        else:
            for claim_type in claim_types:
                print(claim_type.display_name, file=self.outf)


class cmd_domain_claim_claim_type_view(Command):
    """View a single claim type on the domain."""

    synopsis = "%prog -H <URL> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    takes_options = [
        Option("--name", help="Display name of claim type to view (required).",
               dest="name", action="store", type=str, required=True),
    ]

    def run(self, hostopts=None, sambaopts=None, credopts=None, name=None):

        ldb = self.ldb_connect(hostopts, sambaopts, credopts)

        try:
            claim_type = ClaimType.get(ldb, display_name=name)
        except ModelError as e:
            raise CommandError(e)

        # Check if claim type exists first.
        if claim_type is None:
            raise CommandError(f"Claim type {name} not found.")

        # Display claim type as JSON.
        self.print_json(claim_type.as_dict())


class cmd_domain_claim_claim_type(SuperCommand):
    """Manage claim types on the domain."""

    subcommands = {
        "create": cmd_domain_claim_claim_type_create(),
        "delete": cmd_domain_claim_claim_type_delete(),
        "modify": cmd_domain_claim_claim_type_modify(),
        "list": cmd_domain_claim_claim_type_list(),
        "view": cmd_domain_claim_claim_type_view(),
    }
