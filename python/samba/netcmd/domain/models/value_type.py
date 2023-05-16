# Unix SMB/CIFS implementation.
#
# Claim value type model.
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

from .fields import BooleanField, DnField, IntegerField, StringField
from .model import Model

# LDAP Syntax to Value Type CN lookup table.
# These are the lookups used by known AD attributes, add new ones as required.
SYNTAX_TO_VALUE_TYPE_CN = {
    "2.5.5.1": "MS-DS-Text",     # Object(DS-DN)
    "2.5.5.2": "MS-DS-Text",     # String(Object-Identifier)
    "2.5.5.8": "MS-DS-YesNo",    # Boolean
    "2.5.5.9": "MS-DS-Number",   # Integer
    "2.5.5.12": "MS-DS-Text",    # String(Unicode)
    "2.5.5.15": "MS-DS-Text",    # String(NT-Sec-Desc)
    "2.5.5.16": "MS-DS-Number",  # LargeInteger
}


class ValueType(Model):
    description = StringField("description")
    display_name = StringField("displayName")
    claim_is_single_valued = BooleanField("msDS-ClaimIsSingleValued")
    claim_is_value_space_restricted = BooleanField(
        "msDS-ClaimIsValueSpaceRestricted")
    claim_value_type = IntegerField("msDS-ClaimValueType")
    is_possible_values_present = BooleanField("msDS-IsPossibleValuesPresent")
    value_type_reference_bl = DnField("msDS-ValueTypeReferenceBL")
    show_in_advanced_view_only = BooleanField("showInAdvancedViewOnly")

    @staticmethod
    def get_base_dn(ldb):
        """Return the base DN for the ValueType model.

        :param ldb: Ldb connection
        :return: Dn object of container
        """
        base_dn = ldb.get_config_basedn()
        base_dn.add_child("CN=Value Types,CN=Claims Configuration,CN=Services")
        return base_dn

    @staticmethod
    def get_object_class():
        return "msDS-ValueType"

    @classmethod
    def lookup(cls, ldb, attribute):
        """Helper function to get ValueType by attribute or raise LookupError.

        :param ldb: Ldb connection
        :param attribute: AttributeSchema object
        :raises: LookupError if not found
        :raises: ValueError for unknown attribute syntax
        """
        # If attribute is None.
        if not attribute:
            raise ValueError("Attribute is required for value type lookup.")

        # Unknown attribute syntax as it isn't in the lookup table.
        syntax = attribute.attribute_syntax
        cn = SYNTAX_TO_VALUE_TYPE_CN.get(syntax)
        if not cn:
            raise ValueError(f"Unable to process attribute syntax {syntax}")

        # This should always return something but should still be handled.
        value_type = cls.get(ldb, cn=cn)
        if value_type is None:
            raise LookupError(
                f"Could not find claim value type for {attribute}.")

        return value_type

    def __str__(self):
        return str(self.display_name)
