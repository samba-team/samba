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
import json
import os

import samba.getopt as options
from ldb import FLAG_MOD_REPLACE, LdbError, Message, MessageElement
from samba.auth import system_session
from samba.netcmd import CommandError, Option, SuperCommand
from samba.samdb import SamDB
from samba.sd_utils import SDUtils

from .base import ClaimCommand

# LDAP Syntax to Claim Type DN lookup table.
# These are the ones actively used by AD claim type attributes.
SYNTAX_TO_CLAIM_TYPE_DN = {
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
            value_types = {v["cn"]: v for v in self.get_value_types()}
            setattr(self, "_claim_value_types", value_types)
        return value_types

    def get_claim_value_type(self, attribute):
        """Returns the correct claim value type for the given attribute.

        Uses the LDAP attribute syntax to find the matching claim value type.
        """
        attribute_syntax = str(attribute["attributeSyntax"])
        claim_type_dn = SYNTAX_TO_CLAIM_TYPE_DN[attribute_syntax]
        return self.claim_value_types[claim_type_dn]["msDS-ClaimValueType"]

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

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)
        self.ldb = SamDB(ldap_url, credentials=creds,
                         session_info=system_session(lp), lp=lp)

        # Check if a claim type with this display name already exists.
        # Note: you can register the same claim type under another display name.
        display_name = display_name or attribute_name
        claim_type = self.get_claim_type(display_name)
        if claim_type:
            raise CommandError(f"Claim type {display_name} already exists, "
                               "but you can use --name to use another name.")

        # Lookup attribute and class names in schema.
        try:
            applies_to = [self.get_class_from_schema(name) for name in class_names]
            attribute = self.get_attribute_from_schema(attribute_name)
        except (LookupError, ValueError) as e:
            raise CommandError(e)

        # Generate the new Claim Type dn.
        # Windows creates a random number here containing 16 hex digits.
        # We can achieve something similar using urandom(8)
        instance = binascii.hexlify(os.urandom(8)).decode()
        claim_type_dn = self.get_claim_types_dn()
        claim_type_dn.add_child(f"CN=ad://ext/{display_name}:{instance}")

        # adminDescription should be present but still have a fallback.
        if description is None:
            description = str(attribute["adminDescription"] or attribute_name)

        # msDS-ClaimIsValueSpaceRestricted is always FALSE because we don't
        # yet support creating claims with a restricted possible values list.
        value_space_restricted = "FALSE"

        message = {
            "dn": claim_type_dn,
            "description": description,
            "displayName": display_name,
            "Enabled": str(not disable).upper(),
            "objectClass": "msDS-ClaimType",
            "msDS-ClaimAttributeSource": str(attribute.dn),
            "msDS-ClaimIsSingleValued": str(attribute["isSingleValued"]),
            "msDS-ClaimIsValueSpaceRestricted": value_space_restricted,
            "msDS-ClaimSourceType": "AD",
            "msDS-ClaimTypeAppliesToClass": [str(obj.dn) for obj in applies_to],
            "msDS-ClaimValueType": str(self.get_claim_value_type(attribute)),
        }

        # Either --enable will be set or --disable but never both.
        if enable is not None:
            message["Enabled"] = str(enable).upper()
        else:
            message["Enabled"] = str(not disable).upper()

        # Do the add, treat LdbError as CommandError.
        try:
            self.ldb.add(message)

            # Protect claim types from accidental deletion.
            if protect:
                utils = SDUtils(self.ldb)
                utils.dacl_add_ace(claim_type_dn, "(D;;DTSD;;;WD)")
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

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)
        self.ldb = SamDB(ldap_url, credentials=creds,
                         session_info=system_session(lp), lp=lp)

        # Check if claim type exists.
        claim_type = self.get_claim_type(display_name)
        if not claim_type:
            raise CommandError(f"Claim type {display_name} not found.")

        # Update message.
        update_attrs = Message()
        update_attrs.dn = claim_type.dn

        # Change the description of the claim type.
        if description is not None:
            update_attrs.add(
                MessageElement(description, FLAG_MOD_REPLACE, "description"))

        # Enable or disable the claim type.
        # Check existing value to avoid LDAP error.
        if enable:
            update_attrs.add(
                MessageElement("TRUE", FLAG_MOD_REPLACE, "Enabled"))
        elif disable:
            update_attrs.add(
                MessageElement("FALSE", FLAG_MOD_REPLACE, "Enabled"))

        # Change class names for claim type.
        if class_names is not None:
            try:
                applies_to = [self.get_class_from_schema(name) for name in class_names]
            except (LookupError, ValueError) as e:
                raise CommandError(e)

            update_attrs.add(
                MessageElement([str(obj.dn) for obj in applies_to],
                               FLAG_MOD_REPLACE, "msDS-ClaimTypeAppliesToClass"))

        try:
            # Update claim type.
            if len(update_attrs) > 0:
                self.ldb.modify(update_attrs)

            # Protect or unprotect the claim type from accidental deletion.
            if protect:
                utils = SDUtils(self.ldb)
                utils.dacl_add_ace(claim_type.dn, "(D;;DTSD;;;WD)")
            elif unprotect:
                utils = SDUtils(self.ldb)
                utils.dacl_delete_aces(claim_type.dn, "(D;;DTSD;;;WD)")
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

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)
        self.ldb = SamDB(ldap_url, credentials=creds,
                         session_info=system_session(lp), lp=lp)

        # Check if attribute exists first to avoid raising LdbError.
        claim_type = self.get_claim_type(display_name)
        if not claim_type:
            raise CommandError(f"Claim type {display_name} not found.")

        # If force is set try to unlock the item first.
        if force:
            try:
                utils = SDUtils(self.ldb)
                utils.dacl_delete_aces(claim_type.dn, "(D;;DTSD;;;WD)")
            except LdbError as e:
                raise CommandError(e)

        # Delete the claim type.
        # Show hint about using --force if it fails.
        try:
            self.ldb.delete(claim_type.dn)
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
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)
        self.ldb = SamDB(ldap_url, credentials=creds,
                         session_info=system_session(lp), lp=lp)

        # Claim types grouped by displayName.
        claim_types = {c["displayName"]: c for c in self.get_claim_types()}

        # Using json output format gives more detail.
        if output_format == "json":
            json_data = json.dumps(claim_types, indent=2, sort_keys=True)
            self.outf.write(f"{json_data}\n")
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

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)
        self.ldb = SamDB(ldap_url, credentials=creds,
                         session_info=system_session(lp), lp=lp)

        if not display_name:
            raise CommandError("Argument --name is required.")

        claim_type = self.get_claim_type(display_name)
        if claim_type is None:
            raise CommandError(f"Claim type {display_name} not found.")

        # Display one claim type as JSON.
        serialized = self.serialize_message(claim_type)
        json_data = json.dumps(serialized, indent=2, sort_keys=True)
        self.outf.write(f"{json_data}\n")


class cmd_domain_claim_claim_type(SuperCommand):
    """Manage claim types on the domain."""

    subcommands = {
        "create": cmd_domain_claim_claim_type_create(),
        "delete": cmd_domain_claim_claim_type_delete(),
        "modify": cmd_domain_claim_claim_type_modify(),
        "list": cmd_domain_claim_claim_type_list(),
        "view": cmd_domain_claim_claim_type_view(),
    }
