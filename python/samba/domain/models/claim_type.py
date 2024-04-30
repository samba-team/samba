# Unix SMB/CIFS implementation.
#
# Claim type model.
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

from .fields import BooleanField, DnField, IntegerField,\
    PossibleClaimValuesField, StringField
from .model import Model
from .value_type import ValueType


class ClaimType(Model):
    enabled = BooleanField("Enabled")
    description = StringField("description")
    display_name = StringField("displayName")
    claim_attribute_source = DnField("msDS-ClaimAttributeSource")
    claim_is_single_valued = BooleanField("msDS-ClaimIsSingleValued")
    claim_is_value_space_restricted = BooleanField(
        "msDS-ClaimIsValueSpaceRestricted")
    claim_possible_values = PossibleClaimValuesField("msDS-ClaimPossibleValues")
    claim_source_type = StringField("msDS-ClaimSourceType")
    claim_type_applies_to_class = DnField(
        "msDS-ClaimTypeAppliesToClass", many=True)
    claim_value_type = IntegerField("msDS-ClaimValueType")

    def __str__(self):
        return str(self.display_name)

    @staticmethod
    def get_base_dn(samdb):
        """Return the base DN for the ClaimType model.

        :param samdb: SamDB connection
        :return: Dn object of container
        """
        base_dn = samdb.get_config_basedn()
        base_dn.add_child("CN=Claim Types,CN=Claims Configuration,CN=Services")
        return base_dn

    @staticmethod
    def get_object_class():
        return "msDS-ClaimType"

    @staticmethod
    def new_claim_type(samdb, attribute, applies_to, display_name=None,
                       description=None, enabled=True):
        """Creates a ClaimType but does not save the instance.

        :param samdb: SamDB database connection
        :param attribute: AttributeSchema object to use for creating ClaimType
        :param applies_to: List of ClassSchema objects ClaimType applies to
        :param display_name: Optional display name to use or use attribute name
        :param description: Optional description or fall back to display_name
        :param enabled: Create an enabled or disabled claim type (default True)
        :raises NotFound: if the ValueType for this attribute doesn't exist
        """
        value_type = ValueType.find(samdb, attribute)

        # Generate the new Claim Type cn.
        # Windows creates a random number here containing 16 hex digits.
        # We can achieve something similar using urandom(8)
        instance = binascii.hexlify(os.urandom(8)).decode()
        cn = f"ad://ext/{display_name}:{instance}"

        # if displayName is missing use attribute name.
        if display_name is None:
            display_name = attribute.name

        # adminDescription should be present but still have a fallback.
        if description is None:
            description = attribute.admin_description or display_name

        # claim_is_value_space_restricted is always False because we don't
        # yet support creating claims with a restricted possible values list.
        return ClaimType(
            cn=cn,
            description=description,
            display_name=display_name,
            enabled=enabled,
            claim_attribute_source=attribute.dn,
            claim_is_single_valued=attribute.is_single_valued,
            claim_is_value_space_restricted=False,
            claim_source_type="AD",
            claim_type_applies_to_class=[obj.dn for obj in applies_to],
            claim_value_type=value_type.claim_value_type,
        )
