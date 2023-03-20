# Unix SMB/CIFS implementation.
#
# claim management - base class and common code
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

from xml.etree import ElementTree

from ldb import Dn, SCOPE_ONELEVEL
from samba.netcmd import Command
from samba.netcmd.domain.common import parse_guid, parse_text


# Namespaces for PossibleValues xml parsing.
NS_POSSIBLE_VALUES = {
    "xsd": "http://www.w3.org/2001/XMLSchema",
    "xsi": "http://www.w3.org/2001/XMLSchema-instance",
    "": "http://schemas.microsoft.com/2010/08/ActiveDirectory/PossibleValues"
}


class ClaimCommand(Command):
    """Base class for all claim commands."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ldb = None

    def get_services_dn(self):
        """Returns Services DN."""
        services_dn = self.ldb.get_config_basedn()
        services_dn.add_child("CN=Services")
        return services_dn

    def get_claim_types_dn(self):
        """Returns the Claim Types DN."""
        claim_types_dn = self.get_services_dn()
        claim_types_dn.add_child("CN=Claim Types,CN=Claims Configuration")
        return claim_types_dn

    def get_value_types_dn(self):
        """Returns the Value Types DN."""
        value_types_dn = self.get_services_dn()
        value_types_dn.add_child("CN=Value Types,CN=Claims Configuration")
        return value_types_dn

    def parse_possible_values(self, value):
        """Parse PossibleValues XML and return as list of dicts."""
        if value is not None:
            root = ElementTree.fromstring(str(value))
            string_list = root.find("StringList", NS_POSSIBLE_VALUES)

            values = []
            for item in string_list.findall("Item", NS_POSSIBLE_VALUES):
                values.append({
                    "ValueGUID": item.find("ValueGUID", NS_POSSIBLE_VALUES).text,
                    "ValueDisplayName": item.find("ValueDisplayName",
                                                  NS_POSSIBLE_VALUES).text,
                    "ValueDescription": item.find("ValueDescription",
                                                  NS_POSSIBLE_VALUES).text,
                    "Value": item.find("Value", NS_POSSIBLE_VALUES).text,
                })

            return values

    def serialize_message(self, message):
        """General serialize method for claim type and value type."""
        serialized = dict(message)

        for field, value in serialized.items():
            if isinstance(value, Dn):
                serialized[field] = str(value)
            elif field == "objectGUID":
                serialized[field] = parse_guid(value)
            elif field == "msDS-ClaimPossibleValues":
                serialized[field] = self.parse_possible_values(value)
            elif len(value) > 1:
                serialized[field] = [parse_text(val) for val in value]
            elif serialized[field]:
                serialized[field] = parse_text(value)

        return serialized

    def get_claim_types(self, expression=None):
        """Returns claim types as a generator for producing JSON."""
        claim_types_dn = self.get_claim_types_dn()
        result = self.ldb.search(base=claim_types_dn, scope=SCOPE_ONELEVEL,
                                 expression=expression)

        for msg in result:
            yield self.serialize_message(msg)

    def get_value_types(self, expression=None):
        """Returns value types as a generator for producing JSON."""
        value_types_dn = self.get_value_types_dn()
        result = self.ldb.search(base=value_types_dn, scope=SCOPE_ONELEVEL,
                                 expression=expression)

        for msg in result:
            yield self.serialize_message(msg)

    def get_claim_type(self, name, attrs=None):
        """Get claim type by name.

        :returns: Claim type or None if not found.
        """
        claim_types_dn = self.get_claim_types_dn()

        res = self.ldb.search(base=claim_types_dn,
                              scope=SCOPE_ONELEVEL,
                              expression=f"(displayName={name})",
                              attrs=attrs)

        if len(res):
            return res[0]

    def get_value_type(self, name, attrs=None):
        """Get claim value type by cn.

        :returns: Claim  value type or None if not found.
        """
        value_types_dn = self.get_value_types_dn()

        res = self.ldb.search(base=value_types_dn,
                              scope=SCOPE_ONELEVEL,
                              expression=f"(displayName={name})",
                              attrs=attrs)

        if len(res):
            return res[0]

    def get_attribute_from_schema(self, name):
        """Find DN by name in attribute schema.

        :raises LookupError: if not found.
        """
        if not name:
            raise ValueError("Attribute name is required.")
        return self.get_object_from_schema(name, "attributeSchema")

    def get_class_from_schema(self, name):
        """Find DN by name in class schema.

        :raises LookupError: if not found.
        """
        if not name:
            raise ValueError("Class name is required.")
        return self.get_object_from_schema(name, "classSchema")

    def get_object_from_schema(self, name, object_class):
        """Gets a single item from the schema by name and object class.

        :raises LookupError: if not found.
        """
        schema_dn = self.ldb.get_schema_basedn()

        res = self.ldb.search(base=schema_dn,
                              scope=SCOPE_ONELEVEL,
                              expression=(f"(&(objectClass={object_class})"
                                          f"(lDAPDisplayName={name}))"))

        if len(res) != 1:
            raise LookupError(f"Could not locate {name} in {object_class}.")

        return res[0]
