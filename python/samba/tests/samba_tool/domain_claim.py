# Unix SMB/CIFS implementation.
#
# Tests for samba-tool domain claim management
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

import json
import os

from ldb import SCOPE_ONELEVEL
from samba.sd_utils import SDUtils

from .base import SambaToolCmdTest

# A small subset of known attributes with various data types to be expected.
# This isn't a full list of all the possible attributes but is enough to test.
ATTRIBUTES = [
    "adminCount",
    "businessCategory",
    "catalogs",
    "company",
    "extensionName",
    "givenName",
    "isDeleted",
    "isRecycled",
    "mobile",
    "msDS-PrimaryComputer",
    "msDS-SiteName",
    "msNPAllowDialin",
    "msTSHomeDrive",
    "pager",
    "postalCode",
    "seeAlso",
    "street",
    "wWWHomePage",
]

# List of claim value types we should expect to see.
VALUE_TYPES = [
    "Date Time",
    "Multi-valued Choice",
    "Multi-valued Text",
    "Number",
    "Ordered List",
    "Single-valued Choice",
    "Text",
    "Yes/No"
]


class ClaimCmdTestCase(SambaToolCmdTest):
    def setUp(self):
        super().setUp()
        self.host = "ldap://{DC_SERVER}".format(**os.environ)
        self.creds = "-U{DC_USERNAME}%{DC_PASSWORD}".format(**os.environ)
        self.samdb = self.getSamDB("-H", self.host, self.creds)

        # Generate some known claim types.
        # Use unique names that aren't in the ATTRIBUTES list.
        self.claim_types = []
        self.create_claim_type("accountExpires", name="expires",
                               classes=["user"])
        self.create_claim_type("department", name="dept", classes=["user"],
                               protect=True)
        self.create_claim_type("carLicense", name="plate", classes=["user"],
                               disable=True)

    def tearDown(self):
        # Remove claim types created by setUp.
        for claim_type in self.claim_types:
            self.delete_claim_type(claim_type, force=True)

        super().tearDown()

    def get_services_dn(self):
        """Returns Services DN."""
        services_dn = self.samdb.get_config_basedn()
        services_dn.add_child("CN=Services")
        return services_dn

    def get_claim_types_dn(self):
        """Returns the Claim Types DN."""
        claim_types_dn = self.get_services_dn()
        claim_types_dn.add_child("CN=Claim Types,CN=Claims Configuration")
        return claim_types_dn

    def _run(self, *argv):
        """Override _run, so we don't always have to pass host and creds."""
        args = list(argv)
        args.extend(["-H", self.host, self.creds])
        return super()._run(*args)

    runcmd = _run
    runsubcmd = _run

    def create_claim_type(self, attribute, name=None, description=None,
                          classes=None, disable=False, protect=False):
        """Create a claim type using the samba-tool command."""

        # if name is specified it will override the attribute name
        display_name = name or attribute

        # base command for create claim-type
        cmd = ["domain", "claim", "claim-type",
               "create", "--attribute", attribute]

        # list of classes (applies_to)
        if classes is not None:
            cmd.extend([f"--class={name}" for name in classes])

        # optional attributes
        if name is not None:
            cmd.append(f"--name={name}")
        if description is not None:
            cmd.append(f"--description={description}")
        if disable:
            cmd.append("--disable")
        if protect:
            cmd.append("--protect")

        result, out, err = self.runcmd(*cmd)
        self.assertIsNone(result, msg=err)
        self.assertTrue(out.startswith("Created claim type"))
        self.claim_types.append(display_name)
        return display_name

    def delete_claim_type(self, name, force=False):
        """Delete claim type by display name."""
        cmd = ["domain", "claim", "claim-type", "delete", "--name", name]

        # Force-delete protected claim type.
        if force:
            cmd.append("--force")

        result, out, err = self.runcmd(*cmd)
        self.assertIsNone(result)
        self.assertIn("Deleted claim type", out)

    def get_claim_type(self, name):
        """Get claim type by display name."""
        claim_types_dn = self.get_claim_types_dn()

        result = self.samdb.search(base=claim_types_dn,
                                   scope=SCOPE_ONELEVEL,
                                   expression=f"(displayName={name})")

        if len(result) == 1:
            return result[0]

    def test_claim_type_list(self):
        """Test listing claim types in list format."""
        result, out, err = self.runcmd("domain", "claim", "claim-type", "list")
        self.assertIsNone(result)

        # check each claim type we created is there
        for claim_type in self.claim_types:
            self.assertIn(claim_type, out)

    def test_claim_type_list_json(self):
        """Test listing claim types in JSON format."""
        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "list", "--json")
        self.assertIsNone(result)

        # we should get valid json
        json_result = json.loads(out)
        claim_types = list(json_result.keys())

        # check each claim type we created is there
        for claim_type in self.claim_types:
            self.assertIn(claim_type, claim_types)

    def test_claim_type_view(self):
        """Test viewing a single claim type."""
        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "view", "--name", "expires")
        self.assertIsNone(result)

        # we should get valid json
        claim_type = json.loads(out)

        # check a few fields only
        self.assertEqual(claim_type["displayName"], "expires")
        self.assertEqual(claim_type["description"], "Account-Expires")

    def test_claim_type_view_name_missing(self):
        """Test view claim type without --name is handled."""
        result, out, err = self.runcmd("domain", "claim", "claim-type", "view")
        self.assertEqual(result, -1)
        self.assertIn("ERROR: Argument --name is required.", err)

    def test_claim_type_view_notfound(self):
        """Test viewing claim type that doesn't exist is handled."""
        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "view", "--name", "doesNotExist")
        self.assertEqual(result, -1)
        self.assertIn("ERROR: Claim type doesNotExist not found.", err)

    def test_claim_type_create(self):
        """Test creating several known attributes as claim types.

        The point is to test it against the various datatypes that could
        be found, but not include every known attribute.
        """
        # Each known attribute must be in the schema.
        for attribute in ATTRIBUTES:
            result, out, err = self.runcmd("domain", "claim", "claim-type",
                                           "create", f"--attribute={attribute}",
                                           "--class=user")
            self.assertIsNone(result)

            # It should have used the attribute name as displayName.
            claim_type = self.get_claim_type(attribute)
            self.assertEqual(str(claim_type["displayName"]), attribute)
            self.assertEqual(str(claim_type["Enabled"]), "TRUE")
            self.assertEqual(str(claim_type["objectClass"][-1]), "msDS-ClaimType")
            self.assertEqual(str(claim_type["msDS-ClaimSourceType"]), "AD")

    def test_claim_type_create_boolean(self):
        """Test adding a known boolean attribute and check its type."""
        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "create", "--attribute=msNPAllowDialin",
                                       "--name=boolAttr", "--class=user")

        self.assertIsNone(result)
        claim_type = self.get_claim_type("boolAttr")
        self.assertEqual(str(claim_type["displayName"]), "boolAttr")
        self.assertEqual(str(claim_type["msDS-ClaimValueType"]), "6")

    def test_claim_type_create_number(self):
        """Test adding a known numeric attribute and check its type."""
        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "create", "--attribute=adminCount",
                                       "--name=intAttr", "--class=user")

        self.assertIsNone(result)
        claim_type = self.get_claim_type("intAttr")
        self.assertEqual(str(claim_type["displayName"]), "intAttr")
        self.assertEqual(str(claim_type["msDS-ClaimValueType"]), "1")

    def test_claim_type_create_text(self):
        """Test adding a known text attribute and check its type."""
        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "create", "--attribute=givenName",
                                       "--name=textAttr", "--class=user")

        self.assertIsNone(result)
        claim_type = self.get_claim_type("textAttr")
        self.assertEqual(str(claim_type["displayName"]), "textAttr")
        self.assertEqual(str(claim_type["msDS-ClaimValueType"]), "3")

    def test_claim_type_create_disabled(self):
        """Test adding a disabled attribute."""
        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "create", "--attribute=msTSHomeDrive",
                                       "--name=home", "--class=user",
                                       "--disable")

        self.assertIsNone(result)
        claim_type = self.get_claim_type("home")
        self.assertEqual(str(claim_type["displayName"]), "home")
        self.assertEqual(str(claim_type["Enabled"]), "FALSE")

    def test_claim_type_create_protected(self):
        """Test adding a protected attribute."""
        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "create", "--attribute=mobile",
                                       "--name=cellphone", "--class=user",
                                       "--protect")

        self.assertIsNone(result)
        claim_type = self.get_claim_type("cellphone")
        self.assertEqual(str(claim_type["displayName"]), "cellphone")

        # Check if the claim type is protected from accidental deletion.
        utils = SDUtils(self.samdb)
        desc = utils.get_sd_as_sddl(claim_type["dn"])
        self.assertIn("(D;;DTSD;;;WD)", desc)

    def test_claim_type_create_classes(self):
        """Test adding an attribute applied to different classes."""
        schema_dn = self.samdb.get_schema_basedn()
        user_dn = f"CN=User,{schema_dn}"
        computer_dn = f"CN=Computer,{schema_dn}"

        # --class=user
        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "create", "--attribute=street",
                                       "--name=streetName", "--class=user")
        self.assertIsNone(result)
        claim_type = self.get_claim_type("streetName")
        applies_to = [str(dn) for dn in claim_type["msDS-ClaimTypeAppliesToClass"]]
        self.assertEqual(str(claim_type["displayName"]), "streetName")
        self.assertEqual(len(applies_to), 1)
        self.assertIn(user_dn, applies_to)
        self.assertNotIn(computer_dn, applies_to)

        # --class=computer
        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "create", "--attribute=extensionName",
                                       "--name=ext", "--class=computer")
        self.assertIsNone(result)
        claim_type = self.get_claim_type("ext")
        applies_to = [str(dn) for dn in claim_type["msDS-ClaimTypeAppliesToClass"]]
        self.assertEqual(str(claim_type["displayName"]), "ext")
        self.assertEqual(len(applies_to), 1)
        self.assertNotIn(user_dn, applies_to)
        self.assertIn(computer_dn, applies_to)

        # --class=user --class=computer
        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "create", "--attribute=msDS-PrimaryComputer",
                                       "--name=primaryComputer", "--class=user",
                                       "--class=computer")
        self.assertIsNone(result)
        claim_type = self.get_claim_type("primaryComputer")
        applies_to = [str(dn) for dn in claim_type["msDS-ClaimTypeAppliesToClass"]]
        self.assertEqual(str(claim_type["displayName"]), "primaryComputer")
        self.assertEqual(len(applies_to), 2)
        self.assertIn(user_dn, applies_to)
        self.assertIn(computer_dn, applies_to)

        # No classes should raise CommandError.
        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "create", "--attribute=wWWHomePage",
                                       "--name=homepage")
        self.assertEqual(result, -1)
        self.assertIn("ERROR: Argument --class is required.", err)

    def test_claim_type_delete(self):
        """Test deleting a claim type that is not protected."""
        # Create non-protected claim type.
        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "create", "--attribute=msDS-SiteName",
                                       "--name=siteName", "--class=computer")
        self.assertIsNone(result)
        claim_type = self.get_claim_type("siteName")
        self.assertIsNotNone(claim_type)

        # Do the deletion.
        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "delete", "--name=siteName")
        self.assertIsNone(result)

        # Claim type shouldn't exist anymore.
        claim_type = self.get_claim_type("siteName")
        self.assertIsNone(claim_type)

    def test_claim_type_delete_protected(self):
        """Test deleting a protected claim type, with and without --force."""
        # Create protected claim type.
        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "create", "--attribute=postalCode",
                                       "--name=postcode", "--class=user",
                                       "--protect")
        self.assertIsNone(result)
        claim_type = self.get_claim_type("postcode")
        self.assertIsNotNone(claim_type)

        # Do the deletion.
        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "delete", "--name=postcode")
        self.assertEqual(result, -1)

        # Claim type should still exist.
        claim_type = self.get_claim_type("postcode")
        self.assertIsNotNone(claim_type)

        # Try a force delete instead.
        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "delete", "--name=postcode", "--force")
        self.assertIsNone(result)

        # Claim type shouldn't exist anymore.
        claim_type = self.get_claim_type("siteName")
        self.assertIsNone(claim_type)

    def test_claim_type_delete_notfound(self):
        """Test deleting a claim type that doesn't exist."""
        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "delete", "--name", "doesNotExist")
        self.assertEqual(result, -1)
        self.assertIn("ERROR: Claim type doesNotExist not found.", err)

    def test_claim_type_modify_description(self):
        """Test modifying a claim type description."""
        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "modify", "--name", "company",
                                       "--description=NewDescription")
        self.assertIsNone(result)

        # Verify fields were changed.
        claim_type = self.get_claim_type("company")
        self.assertEqual(str(claim_type["description"]), "NewDescription")

    def test_claim_type_modify_classes(self):
        """Test modify claim type classes."""
        schema_dn = self.samdb.get_schema_basedn()
        user_dn = f"CN=User,{schema_dn}"
        computer_dn = f"CN=Computer,{schema_dn}"

        # First try removing all classes which shouldn't be allowed.
        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "modify", "--name", "seeAlso",
                                       "--class=")
        self.assertEqual(result, -1)
        self.assertIn("ERROR: Class name is required.", err)

        # Try changing it to just --class=computer first.
        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "modify", "--name", "seeAlso",
                                       "--class=computer")
        self.assertIsNone(result)
        claim_type = self.get_claim_type("seeAlso")
        applies_to = [str(dn) for dn in claim_type["msDS-ClaimTypeAppliesToClass"]]
        self.assertNotIn(user_dn, applies_to)
        self.assertIn(computer_dn, applies_to)

        # Now try changing it to --class=user again.
        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "modify", "--name", "seeAlso",
                                       "--class=user")
        self.assertIsNone(result)
        claim_type = self.get_claim_type("seeAlso")
        applies_to = [str(dn) for dn in claim_type["msDS-ClaimTypeAppliesToClass"]]
        self.assertIn(user_dn, applies_to)
        self.assertNotIn(computer_dn, applies_to)

        # Why not both?
        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "modify", "--name", "seeAlso",
                                       "--class=user", "--class=computer")
        self.assertIsNone(result)
        claim_type = self.get_claim_type("seeAlso")
        applies_to = [str(dn) for dn in claim_type["msDS-ClaimTypeAppliesToClass"]]
        self.assertIn(user_dn, applies_to)
        self.assertIn(computer_dn, applies_to)

    def test_claim_type_modify_enable_disable(self):
        """Test modify disabling and enabling a claim type."""
        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "modify", "--name", "catalogs",
                                       "--disable")
        self.assertIsNone(result)

        # Check that claim type was disabled.
        claim_type = self.get_claim_type("catalogs")
        self.assertEqual(str(claim_type["Enabled"]), "FALSE")

        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "modify", "--name", "catalogs",
                                       "--enable")
        self.assertIsNone(result)

        # Check that claim type was enabled.
        claim_type = self.get_claim_type("catalogs")
        self.assertEqual(str(claim_type["Enabled"]), "TRUE")

    def test_claim_type_modify_protect_unprotect(self):
        """Test modify un-protecting and protecting a claim type."""
        utils = SDUtils(self.samdb)
        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "modify", "--name", "pager",
                                       "--protect")
        self.assertIsNone(result)

        # Check that claim type was protected.
        claim_type = self.get_claim_type("pager")
        desc = utils.get_sd_as_sddl(claim_type["dn"])
        self.assertIn("(D;;DTSD;;;WD)", desc)

        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "modify", "--name", "pager",
                                       "--unprotect")
        self.assertIsNone(result)

        # Check that claim type was unprotected.
        claim_type = self.get_claim_type("pager")
        desc = utils.get_sd_as_sddl(claim_type["dn"])
        self.assertNotIn("(D;;DTSD;;;WD)", desc)

    def test_claim_type_modify_enable_disable_together(self):
        """Test modify claim type doesn't allow both --enable and --disable."""
        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "modify", "--name", "businessCategory",
                                       "--enable", "--disable")
        self.assertEqual(result, -1)
        self.assertIn("--enable and --disable cannot be used together.", err)

    def test_claim_type_modify_protect_unprotect_together(self):
        """Test modify claim type using both --protect and --unprotect."""
        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "modify", "--name", "businessCategory",
                                       "--protect", "--unprotect")
        self.assertEqual(result, -1)
        self.assertIn("--protect and --unprotect cannot be used together.", err)

    def test_claim_type_modify_notfound(self):
        """Test modify a claim type that doesn't exist."""
        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "modify", "--name", "doesNotExist",
                                       "--description=NewDescription")
        self.assertEqual(result, -1)
        self.assertIn("ERROR: Claim type doesNotExist not found.", err)

    def test_value_type_list(self):
        """Test listing claim value types in list format."""
        result, out, err = self.runcmd("domain", "claim", "value-type", "list")
        self.assertIsNone(result)

        # base list of value types is there
        for value_type in VALUE_TYPES:
            self.assertIn(value_type, out)

    def test_value_type_list_json(self):
        """Test listing claim value types in JSON format."""
        result, out, err = self.runcmd("domain", "claim", "value-type",
                                       "list", "--json")
        self.assertIsNone(result)

        # we should get valid json
        json_result = json.loads(out)
        value_types = list(json_result.keys())

        # base list of value types is there
        for value_type in VALUE_TYPES:
            self.assertIn(value_type, value_types)

    def test_value_type_view(self):
        """Test viewing a single claim value type."""
        result, out, err = self.runcmd("domain", "claim", "value-type",
                                       "view", "--name", "Text")
        self.assertIsNone(result)

        # we should get valid json
        value_type = json.loads(out)

        # check a few fields only
        self.assertEqual(value_type["name"], "MS-DS-Text")
        self.assertEqual(value_type["displayName"], "Text")
        self.assertEqual(value_type["msDS-ClaimValueType"], "3")

    def test_value_type_view_name_missing(self):
        """Test viewing a claim value type with missing --name is handled."""
        result, out, err = self.runcmd("domain", "claim", "value-type", "view")
        self.assertEqual(result, -1)
        self.assertIn("ERROR: Argument --name is required.", err)

    def test_value_type_view_notfound(self):
        """Test viewing a claim value type that doesn't exist is handled."""
        result, out, err = self.runcmd("domain", "claim", "value-type",
                                       "view", "--name", "doesNotExist")
        self.assertEqual(result, -1)
        self.assertIn("ERROR: Value type doesNotExist not found.", err)
