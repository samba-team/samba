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

HOST = "ldap://{DC_SERVER}".format(**os.environ)
CREDS = "-U{DC_USERNAME}%{DC_PASSWORD}".format(**os.environ)


class BaseClaimCmdTest(SambaToolCmdTest):
    """Base class for claim types and claim value types tests."""

    @classmethod
    def setUpClass(cls):
        cls.samdb = cls.getSamDB("-H", HOST, CREDS)
        super().setUpClass()

    @classmethod
    def setUpTestData(cls):
        cls.create_claim_type("accountExpires", name="expires",
                              classes=["user"])
        cls.create_claim_type("department", name="dept", classes=["user"],
                              protect=True)
        cls.create_claim_type("carLicense", name="plate", classes=["user"],
                              disable=True)

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

    @classmethod
    def _run(cls, *argv):
        """Override _run, so we don't always have to pass host and creds."""
        args = list(argv)
        args.extend(["-H", HOST, CREDS])
        return super()._run(*args)

    runcmd = _run
    runsubcmd = _run

    @classmethod
    def create_claim_type(cls, attribute, name=None, description=None,
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

        result, out, err = cls.runcmd(*cmd)
        assert result is None
        assert out.startswith("Created claim type")
        cls.addClassCleanup(cls.delete_claim_type, name=display_name, force=True)
        return display_name

    @classmethod
    def delete_claim_type(cls, name, force=False):
        """Delete claim type by display name."""
        cmd = ["domain", "claim", "claim-type", "delete", "--name", name]

        # Force-delete protected claim type.
        if force:
            cmd.append("--force")

        result, out, err = cls.runcmd(*cmd)
        assert result is None
        assert "Deleted claim type" in out

    def get_claim_type(self, name):
        """Get claim type by display name."""
        claim_types_dn = self.get_claim_types_dn()

        result = self.samdb.search(base=claim_types_dn,
                                   scope=SCOPE_ONELEVEL,
                                   expression=f"(displayName={name})")

        if len(result) == 1:
            return result[0]


class ClaimTypeCmdTestCase(BaseClaimCmdTest):
    """Tests for the claim-type command."""

    def test_list(self):
        """Test listing claim types in list format."""
        result, out, err = self.runcmd("domain", "claim", "claim-type", "list")
        self.assertIsNone(result, msg=err)

        expected_claim_types = ["expires", "dept", "plate"]

        for claim_type in expected_claim_types:
            self.assertIn(claim_type, out)

    def test_list__json(self):
        """Test listing claim types in JSON format."""
        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "list", "--json")
        self.assertIsNone(result, msg=err)

        # we should get valid json
        json_result = json.loads(out)
        claim_types = list(json_result.keys())

        expected_claim_types = ["expires", "dept", "plate"]

        for claim_type in expected_claim_types:
            self.assertIn(claim_type, claim_types)

    def test_view(self):
        """Test viewing a single claim type."""
        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "view", "--name", "expires")
        self.assertIsNone(result, msg=err)

        # we should get valid json
        claim_type = json.loads(out)

        # check a few fields only
        self.assertEqual(claim_type["displayName"], "expires")
        self.assertEqual(claim_type["description"], "Account-Expires")

    def test_view__name_missing(self):
        """Test view claim type without --name is handled."""
        result, out, err = self.runcmd("domain", "claim", "claim-type", "view")
        self.assertEqual(result, -1)
        self.assertIn("Argument --name is required.", err)

    def test_view__notfound(self):
        """Test viewing claim type that doesn't exist is handled."""
        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "view", "--name", "doesNotExist")
        self.assertEqual(result, -1)
        self.assertIn("Claim type doesNotExist not found.", err)

    def test_create(self):
        """Test creating several known attributes as claim types.

        The point is to test it against the various datatypes that could
        be found, but not include every known attribute.
        """
        # We just need to test a few different data types for attributes,
        # there is no need to test every known attribute.
        claim_types = [
            "adminCount",
            "accountExpires",
            "department",
            "carLicense",
            "msDS-PrimaryComputer",
            "isDeleted",
        ]

        # Each known attribute must be in the schema.
        for attribute in claim_types:
            # Use a different name, so we don't clash with existing attributes.
            name = "test_create_" + attribute

            self.addCleanup(self.delete_claim_type, name=name, force=True)

            result, out, err = self.runcmd("domain", "claim", "claim-type",
                                           "create",
                                           "--attribute", attribute,
                                           "--name", name,
                                           "--class=user")
            self.assertIsNone(result, msg=err)

            # It should have used the attribute name as displayName.
            claim_type = self.get_claim_type(name)
            self.assertEqual(str(claim_type["displayName"]), name)
            self.assertEqual(str(claim_type["Enabled"]), "TRUE")
            self.assertEqual(str(claim_type["objectClass"][-1]), "msDS-ClaimType")
            self.assertEqual(str(claim_type["msDS-ClaimSourceType"]), "AD")

    def test_create__boolean(self):
        """Test adding a known boolean attribute and check its type."""
        self.addCleanup(self.delete_claim_type, name="boolAttr", force=True)

        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "create", "--attribute=msNPAllowDialin",
                                       "--name=boolAttr", "--class=user")

        self.assertIsNone(result, msg=err)
        claim_type = self.get_claim_type("boolAttr")
        self.assertEqual(str(claim_type["displayName"]), "boolAttr")
        self.assertEqual(str(claim_type["msDS-ClaimValueType"]), "6")

    def test_create__number(self):
        """Test adding a known numeric attribute and check its type."""
        self.addCleanup(self.delete_claim_type, name="intAttr", force=True)

        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "create", "--attribute=adminCount",
                                       "--name=intAttr", "--class=user")

        self.assertIsNone(result, msg=err)
        claim_type = self.get_claim_type("intAttr")
        self.assertEqual(str(claim_type["displayName"]), "intAttr")
        self.assertEqual(str(claim_type["msDS-ClaimValueType"]), "1")

    def test_create__text(self):
        """Test adding a known text attribute and check its type."""
        self.addCleanup(self.delete_claim_type, name="textAttr", force=True)

        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "create", "--attribute=givenName",
                                       "--name=textAttr", "--class=user")

        self.assertIsNone(result, msg=err)
        claim_type = self.get_claim_type("textAttr")
        self.assertEqual(str(claim_type["displayName"]), "textAttr")
        self.assertEqual(str(claim_type["msDS-ClaimValueType"]), "3")

    def test_create__disabled(self):
        """Test adding a disabled attribute."""
        self.addCleanup(self.delete_claim_type, name="disabledAttr", force=True)

        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "create", "--attribute=msTSHomeDrive",
                                       "--name=disabledAttr", "--class=user",
                                       "--disable")

        self.assertIsNone(result, msg=err)
        claim_type = self.get_claim_type("disabledAttr")
        self.assertEqual(str(claim_type["displayName"]), "disabledAttr")
        self.assertEqual(str(claim_type["Enabled"]), "FALSE")

    def test_create__protected(self):
        """Test adding a protected attribute."""
        self.addCleanup(self.delete_claim_type, name="protectedAttr", force=True)

        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "create", "--attribute=mobile",
                                       "--name=protectedAttr", "--class=user",
                                       "--protect")

        self.assertIsNone(result, msg=err)
        claim_type = self.get_claim_type("protectedAttr")
        self.assertEqual(str(claim_type["displayName"]), "protectedAttr")

        # Check if the claim type is protected from accidental deletion.
        utils = SDUtils(self.samdb)
        desc = utils.get_sd_as_sddl(claim_type["dn"])
        self.assertIn("(D;;DTSD;;;WD)", desc)

    def test_create__classes(self):
        """Test adding an attribute applied to different classes."""
        schema_dn = self.samdb.get_schema_basedn()
        user_dn = f"CN=User,{schema_dn}"
        computer_dn = f"CN=Computer,{schema_dn}"

        # --class=user
        self.addCleanup(self.delete_claim_type, name="streetName", force=True)
        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "create", "--attribute=street",
                                       "--name=streetName", "--class=user")
        self.assertIsNone(result, msg=err)
        claim_type = self.get_claim_type("streetName")
        applies_to = [str(dn) for dn in claim_type["msDS-ClaimTypeAppliesToClass"]]
        self.assertEqual(str(claim_type["displayName"]), "streetName")
        self.assertEqual(len(applies_to), 1)
        self.assertIn(user_dn, applies_to)
        self.assertNotIn(computer_dn, applies_to)

        # --class=computer
        self.addCleanup(self.delete_claim_type, name="ext", force=True)
        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "create", "--attribute=extensionName",
                                       "--name=ext", "--class=computer")
        self.assertIsNone(result, msg=err)
        claim_type = self.get_claim_type("ext")
        applies_to = [str(dn) for dn in claim_type["msDS-ClaimTypeAppliesToClass"]]
        self.assertEqual(str(claim_type["displayName"]), "ext")
        self.assertEqual(len(applies_to), 1)
        self.assertNotIn(user_dn, applies_to)
        self.assertIn(computer_dn, applies_to)

        # --class=user --class=computer
        self.addCleanup(self.delete_claim_type,
                        name="primaryComputer", force=True)
        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "create", "--attribute=msDS-PrimaryComputer",
                                       "--name=primaryComputer", "--class=user",
                                       "--class=computer")
        self.assertIsNone(result, msg=err)
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
        self.assertIn("Argument --class is required.", err)

    def test__delete(self):
        """Test deleting a claim type that is not protected."""
        # Create non-protected claim type.
        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "create", "--attribute=msDS-SiteName",
                                       "--name=siteName", "--class=computer")
        self.assertIsNone(result, msg=err)
        claim_type = self.get_claim_type("siteName")
        self.assertIsNotNone(claim_type)

        # Do the deletion.
        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "delete", "--name=siteName")
        self.assertIsNone(result, msg=err)

        # Claim type shouldn't exist anymore.
        claim_type = self.get_claim_type("siteName")
        self.assertIsNone(claim_type)

    def test_delete__protected(self):
        """Test deleting a protected claim type, with and without --force."""
        # Create protected claim type.
        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "create", "--attribute=postalCode",
                                       "--name=postcode", "--class=user",
                                       "--protect")
        self.assertIsNone(result, msg=err)
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
        self.assertIsNone(result, msg=err)

        # Claim type shouldn't exist anymore.
        claim_type = self.get_claim_type("siteName")
        self.assertIsNone(claim_type)

    def test_delete__notfound(self):
        """Test deleting a claim type that doesn't exist."""
        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "delete", "--name", "doesNotExist")
        self.assertEqual(result, -1)
        self.assertIn("Claim type doesNotExist not found.", err)

    def test_modify__description(self):
        """Test modifying a claim type description."""
        self.addCleanup(self.delete_claim_type, name="company", force=True)
        self.create_claim_type("company", classes=["user"])

        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "modify", "--name", "company",
                                       "--description=NewDescription")
        self.assertIsNone(result, msg=err)

        # Verify fields were changed.
        claim_type = self.get_claim_type("company")
        self.assertEqual(str(claim_type["description"]), "NewDescription")

    def test_modify__classes(self):
        """Test modify claim type classes."""
        schema_dn = self.samdb.get_schema_basedn()
        user_dn = f"CN=User,{schema_dn}"
        computer_dn = f"CN=Computer,{schema_dn}"

        self.addCleanup(self.delete_claim_type, name="seeAlso", force=True)
        self.create_claim_type("seeAlso", classes=["user"])

        # First try removing all classes which shouldn't be allowed.
        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "modify", "--name", "seeAlso",
                                       "--class=")
        self.assertEqual(result, -1)
        self.assertIn("Class name is required.", err)

        # Try changing it to just --class=computer first.
        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "modify", "--name", "seeAlso",
                                       "--class=computer")
        self.assertIsNone(result, msg=err)
        claim_type = self.get_claim_type("seeAlso")
        applies_to = [str(dn) for dn in claim_type["msDS-ClaimTypeAppliesToClass"]]
        self.assertNotIn(user_dn, applies_to)
        self.assertIn(computer_dn, applies_to)

        # Now try changing it to --class=user again.
        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "modify", "--name", "seeAlso",
                                       "--class=user")
        self.assertIsNone(result, msg=err)
        claim_type = self.get_claim_type("seeAlso")
        applies_to = [str(dn) for dn in claim_type["msDS-ClaimTypeAppliesToClass"]]
        self.assertIn(user_dn, applies_to)
        self.assertNotIn(computer_dn, applies_to)

        # Why not both?
        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "modify", "--name", "seeAlso",
                                       "--class=user", "--class=computer")
        self.assertIsNone(result, msg=err)
        claim_type = self.get_claim_type("seeAlso")
        applies_to = [str(dn) for dn in claim_type["msDS-ClaimTypeAppliesToClass"]]
        self.assertIn(user_dn, applies_to)
        self.assertIn(computer_dn, applies_to)

    def test_modify__enable_disable(self):
        """Test modify disabling and enabling a claim type."""
        self.addCleanup(self.delete_claim_type, name="catalogs", force=True)
        self.create_claim_type("catalogs", classes=["user"])

        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "modify", "--name", "catalogs",
                                       "--disable")
        self.assertIsNone(result, msg=err)

        # Check that claim type was disabled.
        claim_type = self.get_claim_type("catalogs")
        self.assertEqual(str(claim_type["Enabled"]), "FALSE")

        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "modify", "--name", "catalogs",
                                       "--enable")
        self.assertIsNone(result, msg=err)

        # Check that claim type was enabled.
        claim_type = self.get_claim_type("catalogs")
        self.assertEqual(str(claim_type["Enabled"]), "TRUE")

    def test_modify__protect_unprotect(self):
        """Test modify un-protecting and protecting a claim type."""
        self.addCleanup(self.delete_claim_type, name="pager", force=True)
        self.create_claim_type("pager", classes=["user"])

        utils = SDUtils(self.samdb)
        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "modify", "--name", "pager",
                                       "--protect")
        self.assertIsNone(result, msg=err)

        # Check that claim type was protected.
        claim_type = self.get_claim_type("pager")
        desc = utils.get_sd_as_sddl(claim_type["dn"])
        self.assertIn("(D;;DTSD;;;WD)", desc)

        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "modify", "--name", "pager",
                                       "--unprotect")
        self.assertIsNone(result, msg=err)

        # Check that claim type was unprotected.
        claim_type = self.get_claim_type("pager")
        desc = utils.get_sd_as_sddl(claim_type["dn"])
        self.assertNotIn("(D;;DTSD;;;WD)", desc)

    def test_modify__enable_disable_together(self):
        """Test modify claim type doesn't allow both --enable and --disable."""
        self.addCleanup(self.delete_claim_type,
                        name="businessCategory", force=True)
        self.create_claim_type("businessCategory", classes=["user"])

        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "modify", "--name", "businessCategory",
                                       "--enable", "--disable")
        self.assertEqual(result, -1)
        self.assertIn("--enable and --disable cannot be used together.", err)

    def test_modify__protect_unprotect_together(self):
        """Test modify claim type using both --protect and --unprotect."""
        self.addCleanup(self.delete_claim_type,
                        name="businessCategory", force=True)
        self.create_claim_type("businessCategory", classes=["user"])

        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "modify", "--name", "businessCategory",
                                       "--protect", "--unprotect")
        self.assertEqual(result, -1)
        self.assertIn("--protect and --unprotect cannot be used together.", err)

    def test_modify__notfound(self):
        """Test modify a claim type that doesn't exist."""
        result, out, err = self.runcmd("domain", "claim", "claim-type",
                                       "modify", "--name", "doesNotExist",
                                       "--description=NewDescription")
        self.assertEqual(result, -1)
        self.assertIn("Claim type doesNotExist not found.", err)


class ValueTypeCmdTestCase(BaseClaimCmdTest):
    """Tests for the value-type command."""

    def test_list(self):
        """Test listing claim value types in list format."""
        result, out, err = self.runcmd("domain", "claim", "value-type", "list")
        self.assertIsNone(result, msg=err)

        # base list of value types is there
        for value_type in VALUE_TYPES:
            self.assertIn(value_type, out)

    def test_list__json(self):
        """Test listing claim value types in JSON format."""
        result, out, err = self.runcmd("domain", "claim", "value-type",
                                       "list", "--json")
        self.assertIsNone(result, msg=err)

        # we should get valid json
        json_result = json.loads(out)
        value_types = list(json_result.keys())

        # base list of value types is there
        for value_type in VALUE_TYPES:
            self.assertIn(value_type, value_types)

    def test_view(self):
        """Test viewing a single claim value type."""
        result, out, err = self.runcmd("domain", "claim", "value-type",
                                       "view", "--name", "Text")
        self.assertIsNone(result, msg=err)

        # we should get valid json
        value_type = json.loads(out)

        # check a few fields only
        self.assertEqual(value_type["name"], "MS-DS-Text")
        self.assertEqual(value_type["displayName"], "Text")
        self.assertEqual(value_type["msDS-ClaimValueType"], 3)

    def test_view__name_missing(self):
        """Test viewing a claim value type with missing --name is handled."""
        result, out, err = self.runcmd("domain", "claim", "value-type", "view")
        self.assertEqual(result, -1)
        self.assertIn("Argument --name is required.", err)

    def test_view__notfound(self):
        """Test viewing a claim value type that doesn't exist is handled."""
        result, out, err = self.runcmd("domain", "claim", "value-type",
                                       "view", "--name", "doesNotExist")
        self.assertEqual(result, -1)
        self.assertIn("Value type doesNotExist not found.", err)
