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

from .fields import BooleanField, DnField, IntegerField,\
    PossibleClaimValuesField, StringField
from .model import Model


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

    @staticmethod
    def get_base_dn(ldb):
        """Return the base DN for the ClaimType model.

        :param ldb: Ldb connection
        :return: Dn object of container
        """
        base_dn = ldb.get_config_basedn()
        base_dn.add_child("CN=Claim Types,CN=Claims Configuration,CN=Services")
        return base_dn

    @staticmethod
    def get_object_class():
        return "msDS-ClaimType"

    def __str__(self):
        return str(self.display_name)
