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

import binascii
import os

import samba.getopt as options
from ldb import LdbError
from samba.netcmd import CommandError, Option, SuperCommand
from samba.netcmd.domain.models import ClaimType, ValueType

from .base import ClaimCommand

# LDAP Syntax to Claim Type CN lookup table.
# These are the ones actively used by AD claim type attributes.
SYNTAX_TO_CLAIM_TYPE_CN = {
    "2.5.5.1": "MS-DS-Text",     # Object(DS-DN)
    "2.5.5.2": "MS-DS-Text",     # String(Object-Identifier)
    "2.5.5.8": "MS-DS-YesNo",    # Boolean
    "2.5.5.9": "MS-DS-Number",   # Integer
    "2.5.5.12": "MS-DS-Text",    # String(Unicode)
    "2.5.5.15": "MS-DS-Text",    # String(NT-Sec-Desc)
    "2.5.5.16": "MS-DS-Number",  # LargeInteger
}


class cmd_domain_claim_claim_type_create(ClaimCommand):
    """Create claim types on the domain."""

    synopsis = "%prog -H <URL> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server.",
               type=str, metavar="URL", dest="ldap_url"),
        Option("--attribute", help="Attribute of claim type to create (required).",
               dest="attribute_name", action="store", type=str),
        Option("--class", help="Object classes to set claim type to.",
               dest="class_names", action="append", type=str),
        Option("--name", help="Optional display name or use attribute name.",
               dest="display_name", action="store", type=str),
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

    @property
    def claim_value_types(self):
        """Property that returns a dict of claim value types keyed by CN.

        NOTE: Can be replaced with @cached_property when the minimum Python
        version becomes 3.8
        """
        value_types = getattr(self, "_claim_value_types", None)
        if value_types is None:
            value_types = {v.cn: v for v in ValueType.query(self.ldb)}
            setattr(self, "_claim_value_types", value_types)
        return value_types

    def get_claim_value_type(self, attribute):
        """Returns the correct claim value type for the given attribute.

        Uses the LDAP attribute syntax to find the matching claim value type.
        """
        attribute_syntax = str(attribute["attributeSyntax"])
        claim_type_cn = SYNTAX_TO_CLAIM_TYPE_CN[attribute_syntax]
        return self.claim_value_types[claim_type_cn].claim_value_type

    def run(self, ldap_url=None, sambaopts=None, credopts=None,
            attribute_name=None, class_names=None, display_name=None,
            description=None, disable=None, enable=None, protect=None,
            unprotect=None):

        # required attributes
        if not attribute_name:
            raise CommandError("Argument --attribute is required.")
        if not class_names:
            raise CommandError("Argument --class is required.")

        # mutually exclusive attributes
        if enable and disable:
            raise CommandError("--enable and --disable cannot be used together.")
        if protect and unprotect:
            raise CommandError("--protect and --unprotect cannot be used together.")

        self.ldb = self.ldb_connect(ldap_url, sambaopts, credopts)

        # Check if a claim type with this display name already exists.
        # Note: you can register the same claim type under another display name.
        display_name = display_name or attribute_name
        claim_type = ClaimType.get(self.ldb, display_name=display_name)
        if claim_type:
            raise CommandError(f"Claim type {display_name} already exists, "
                               "but you can use --name to use another name.")

        # Lookup attribute and class names in schema.
        try:
            applies_to = [self.get_class_from_schema(name) for name in class_names]
            attribute = self.get_attribute_from_schema(attribute_name)
        except (LookupError, ValueError) as e:
            raise CommandError(e)

        # Generate the new Claim Type cn.
        # Windows creates a random number here containing 16 hex digits.
        # We can achieve something similar using urandom(8)
        instance = binascii.hexlify(os.urandom(8)).decode()
        cn = f"ad://ext/{display_name}:{instance}"

        # adminDescription should be present but still have a fallback.
        if description is None:
            description = str(attribute["adminDescription"] or attribute_name)

        # claim_is_value_space_restricted is always False because we don't
        # yet support creating claims with a restricted possible values list.
        claim_type = ClaimType(
            cn=cn,
            description=description,
            display_name=display_name,
            enabled=not disable,
            claim_attribute_source=attribute.dn,
            claim_is_single_valued=str(attribute["isSingleValued"]) == "TRUE",
            claim_is_value_space_restricted=False,
            claim_source_type="AD",
            claim_type_applies_to_class=[obj.dn for obj in applies_to],
            claim_value_type=self.get_claim_value_type(attribute),
        )

        # Either --enable will be set or --disable but never both.
        # The default if both are missing is enabled=True.
        if enable is not None:
            claim_type.enabled = enable
        else:
            claim_type.enabled = not disable

        # Create claim type
        try:
            claim_type.save(self.ldb)

            if protect:
                claim_type.protect(self.ldb)
        except LdbError as e:
            raise CommandError(e)

        # Claim type created successfully.
        self.outf.write(f"Created claim type: {display_name}")
        if attribute_name != display_name:
            self.outf.write(f" ({attribute_name})\n")
        else:
            self.outf.write("\n")


class cmd_domain_claim_claim_type_modify(ClaimCommand):
    """Modify claim types on the domain."""

    synopsis = "%prog -H <URL> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server.",
               type=str, metavar="URL", dest="ldap_url"),
        Option("--name", help="Display name of claim type to modify (required).",
               dest="display_name", action="store", type=str),
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

    def run(self, ldap_url=None, sambaopts=None, credopts=None,
            display_name=None, class_names=None, description=None,
            enable=None, disable=None, protect=None, unprotect=None):

        if not display_name:
            raise CommandError("Argument --name is required.")
        if enable and disable:
            raise CommandError("--enable and --disable cannot be used together.")
        if protect and unprotect:
            raise CommandError("--protect and --unprotect cannot be used together.")

        self.ldb = self.ldb_connect(ldap_url, sambaopts, credopts)

        # Check if claim type exists.
        claim_type = ClaimType.get(self.ldb, display_name=display_name)
        if not claim_type:
            raise CommandError(f"Claim type {display_name} not found.")

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
                applies_to = [self.get_class_from_schema(name) for name in class_names]
            except (LookupError, ValueError) as e:
                raise CommandError(e)

            claim_type.claim_type_applies_to_class = [obj.dn for obj in applies_to]

        # Update claim type.
        try:
            claim_type.save(self.ldb)

            if protect:
                claim_type.protect(self.ldb)
            elif unprotect:
                claim_type.unprotect(self.ldb)
        except LdbError as e:
            raise CommandError(e)

        # Claim type updated successfully.
        self.outf.write(f"Updated claim type: {display_name}\n")


class cmd_domain_claim_claim_type_delete(ClaimCommand):
    """Delete claim types on the domain."""

    synopsis = "%prog -H <URL> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server.",
               type=str, metavar="URL", dest="ldap_url"),
        Option("--name", help="Display name of claim type to delete (required).",
               dest="display_name", action="store", type=str),
        Option("--force", help="Force claim type delete even if it is protected.",
               dest="force", action="store_true")
    ]

    def run(self, ldap_url=None, sambaopts=None, credopts=None,
            display_name=None, force=None):

        if not display_name:
            raise CommandError("Argument --name is required.")

        self.ldb = self.ldb_connect(ldap_url, sambaopts, credopts)

        # Check if claim type exists first.
        claim_type = ClaimType.get(self.ldb, display_name=display_name)
        if claim_type is None:
            raise CommandError(f"Claim type {display_name} not found.")

        # Delete claim type.
        try:
            if force:
                claim_type.unprotect(self.ldb)

            claim_type.delete(self.ldb)
        except LdbError as e:
            if not force:
                raise CommandError(
                    f"{e}\nTry --force to delete protected claim types.")
            else:
                raise CommandError(e)

        # Claim type deleted successfully.
        self.outf.write(f"Deleted claim type: {display_name}\n")


class cmd_domain_claim_claim_type_list(ClaimCommand):
    """List claim types on the domain."""

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

        # Claim types grouped by displayName.
        claim_types = {claim_type.display_name: claim_type.as_dict()
                       for claim_type in ClaimType.query(self.ldb)}

        # Using json output format gives more detail.
        if output_format == "json":
            self.print_json(claim_types)
        else:
            for claim_type in claim_types.keys():
                self.outf.write(f"{claim_type}\n")


class cmd_domain_claim_claim_type_view(ClaimCommand):
    """View a single claim type on the domain."""

    synopsis = "%prog -H <URL> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server.",
               type=str, metavar="URL", dest="ldap_url"),
        Option("--name", help="Display name of claim type to view (required).",
               dest="display_name", action="store", type=str),
    ]

    def run(self, ldap_url=None, sambaopts=None, credopts=None,
            display_name=None):

        if not display_name:
            raise CommandError("Argument --name is required.")

        self.ldb = self.ldb_connect(ldap_url, sambaopts, credopts)

        # Check if claim type exists first.
        claim_type = ClaimType.get(self.ldb, display_name=display_name)
        if claim_type is None:
            raise CommandError(f"Claim type {display_name} not found.")

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
