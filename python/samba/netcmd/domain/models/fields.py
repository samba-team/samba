# Unix SMB/CIFS implementation.
#
# Model fields.
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

from enum import IntEnum

import io
from abc import ABCMeta, abstractmethod
from datetime import datetime
from xml.etree import ElementTree

from ldb import Dn, MessageElement, string_to_time, timestring
from samba.dcerpc.misc import GUID
from samba.ndr import ndr_pack, ndr_unpack


class Field(metaclass=ABCMeta):
    """Base class for all fields.

    Each field will need to implement from_db_value and to_db_value.

    A field must correctly support converting both single valued fields,
    and list type fields.

    The only thing many=True does is say the field "prefers" to be a list,
    but really any field can be a list or single value.
    """

    def __init__(self, name, many=False, default=None, hidden=False):
        """Creates a new field, should be subclassed.

        :param name: Ldb field name.
        :param many: If true always convert field to a list when loaded.
        :param default: Default value or callback method (obj is first argument)
        :param hidden: If this is True, exclude the field when calling as_dict()
        """
        self.name = name
        self.many = many
        self.hidden = hidden

        # This ensures that fields with many=True are always lists.
        # If this is inconsistent anywhere, it isn't so great to use.
        if self.many and default is None:
            self.default = []
        else:
            self.default = default

    @abstractmethod
    def from_db_value(self, ldb, value):
        """Converts value read from the database to Python value.

        :param ldb: Ldb connection
        :param value: MessageElement value from the database
        :returns: Parsed value as Python type
        """
        pass

    @abstractmethod
    def to_db_value(self, value, flags):
        """Converts value to database value.

        This should return a MessageElement or None, where None means
        the field will be unset on the next save.

        :param value: Input value from Python field
        :param flags: MessageElement flags
        :returns: MessageElement or None
        """
        pass


class IntegerField(Field):
    """A simple integer field, can be an int or list of int."""

    def from_db_value(self, ldb, value):
        """Convert MessageElement to int or list of int."""
        if value is None:
            return
        elif len(value) > 1 or self.many:
            return [int(item) for item in value]
        else:
            return int(value[0])

    def to_db_value(self, value, flags):
        """Convert int or list of int to MessageElement."""
        if value is None:
            return
        elif isinstance(value, list):
            return MessageElement(
                [str(item) for item in value], flags, self.name)
        else:
            return MessageElement(str(value), flags, self.name)


class BinaryField(Field):
    """Similar to StringField but using bytes instead of str.

    This tends to be quite easy because a MessageElement already uses bytes.
    """

    def from_db_value(self, ldb, value):
        """Convert MessageElement to bytes or list of bytes.

        The values on the MessageElement should already be bytes so the
        cast to bytes() is likely not needed in from_db_value.
        """
        if value is None:
            return
        elif len(value) > 1 or self.many:
            return [bytes(item) for item in value]
        else:
            return bytes(value[0])

    def to_db_value(self, value, flags):
        """Convert bytes or list of bytes to MessageElement."""
        if value is None:
            return
        elif isinstance(value, list):
            return MessageElement(
                [bytes(item) for item in value], flags, self.name)
        else:
            return MessageElement(bytes(value), flags, self.name)


class StringField(Field):
    """A simple string field, may contain str or list of str."""

    def from_db_value(self, ldb, value):
        """Convert MessageElement to str or list of str."""
        if value is None:
            return
        elif len(value) > 1 or self.many:
            return [str(item) for item in value]
        else:
            return str(value)

    def to_db_value(self, value, flags):
        """Convert str or list of str to MessageElement."""
        if value is None:
            return
        elif isinstance(value, list):
            return MessageElement(
                [str(item) for item in value], flags, self.name)
        else:
            return MessageElement(str(value), flags, self.name)


class EnumField(Field):
    """A field based around Python's Enum type."""

    def __init__(self, name, enum, many=False, default=None):
        """Create a new EnumField for the given enum class."""
        self.enum = enum
        super().__init__(name, many, default)

    def enum_from_value(self, value):
        """Return Enum instance from value.

        Has a special case for IntEnum as the constructor only accepts int.
        """
        if issubclass(self.enum, IntEnum):
            return self.enum(int(str(value)))
        else:
            return self.enum(str(value))

    def from_db_value(self, ldb, value):
        """Convert MessageElement to enum or list of enum."""
        if value is None:
            return
        elif len(value) > 1 or self.many:
            return [self.enum_from_value(item) for item in value]
        else:
            return self.enum_from_value(value)

    def to_db_value(self, value, flags):
        """Convert enum or list of enum to MessageElement."""
        if value is None:
            return
        elif isinstance(value, list):
            return MessageElement(
                [str(item.value) for item in value], flags, self.name)
        else:
            return MessageElement(str(value.value), flags, self.name)


class DateTimeField(Field):
    """A field for parsing ldb timestamps into Python datetime."""

    def from_db_value(self, ldb, value):
        """Convert MessageElement to datetime or list of datetime."""
        if value is None:
            return
        elif len(value) > 1 or self.many:
            return [datetime.fromtimestamp(string_to_time(str(item)))
                    for item in value]
        else:
            return datetime.fromtimestamp(string_to_time(str(value)))

    def to_db_value(self, value, flags):
        """Convert datetime or list of datetime to MessageElement."""
        if value is None:
            return
        elif isinstance(value, list):
            return MessageElement(
                [timestring(int(datetime.timestamp(item))) for item in value],
                flags, self.name)
        else:
            return MessageElement(timestring(int(datetime.timestamp(value))),
                                  flags, self.name)


class RelatedField(Field):
    """A field that automatically fetches the related objects.

    Use sparingly, can be a little slow. If in doubt just use DnField instead.
    """

    def __init__(self, name, model, many=False, default=None):
        """Create a new RelatedField for the given model."""
        self.model = model
        super().__init__(name, many, default)

    def from_db_value(self, ldb, value):
        """Convert Message element to related object or list of objects.

        Note that fetching related items is not using any sort of lazy
        loading so use this field sparingly.
        """
        if value is None:
            return
        elif len(value) > 1 or self.many:
            return [self.model.get(ldb, dn=Dn(ldb, str(item))) for item in value]
        else:
            return self.model.get(ldb, dn=Dn(ldb, str(value)))

    def to_db_value(self, value, flags):
        """Convert related object or list of objects to MessageElement."""
        if value is None:
            return
        elif isinstance(value, list):
            return MessageElement(
                [str(item.dn) for item in value], flags, self.name)
        else:
            return MessageElement(str(value.dn), flags, self.name)


class DnField(Field):
    """A Dn field parses the current field into a Dn object."""

    def from_db_value(self, ldb, value):
        """Convert MessageElement to a Dn object or list of Dn objects."""
        if value is None:
            return
        elif isinstance(value, Dn):
            return value
        elif len(value) > 1 or self.many:
            return [Dn(ldb, str(item)) for item in value]
        else:
            return Dn(ldb, str(value))

    def to_db_value(self, value, flags):
        """Convert Dn object or list of Dn objects into a MessageElement."""
        if value is None:
            return
        elif isinstance(value, list):
            return MessageElement(
                [str(item) for item in value], flags, self.name)
        else:
            return MessageElement(str(value), flags, self.name)


class GUIDField(Field):
    """A GUID field decodes fields containing binary GUIDs."""

    def from_db_value(self, ldb, value):
        """Convert MessageElement with a GUID into a str or list of str."""
        if value is None:
            return
        elif len(value) > 1 or self.many:
            return [str(ndr_unpack(GUID, item)) for item in value]
        else:
            return str(ndr_unpack(GUID, value[0]))

    def to_db_value(self, value, flags):
        """Convert str with GUID into MessageElement."""
        if value is None:
            return
        elif isinstance(value, list):
            return MessageElement(
                [ndr_pack(GUID(item)) for item in value], flags, self.name)
        else:
            return MessageElement(ndr_pack(GUID(value)), flags, self.name)


class BooleanField(Field):
    """A simple boolean field, can be a bool or list of bool."""

    def from_db_value(self, ldb, value):
        """Convert MessageElement into a bool or list of bool."""
        if value is None:
            return
        elif len(value) > 1 or self.many:
            return [str(item) == "TRUE" for item in value]
        else:
            return str(value) == "TRUE"

    def to_db_value(self, value, flags):
        """Convert bool or list of bool into a MessageElement."""
        if value is None:
            return
        elif isinstance(value, list):
            return MessageElement(
                [str(bool(item)).upper() for item in value], flags, self.name)
        else:
            return MessageElement(str(bool(value)).upper(), flags, self.name)


class PossibleClaimValuesField(Field):
    """Field for parsing possible values XML for claim types.

    This field will be represented by a list of dicts as follows:

    [
        {"ValueGUID": <GUID>},
        {"ValueDisplayName: "Display name"},
        {"ValueDescription: "Optional description or None for no description"},
        {"Value": <Value>},
    ]

    Note that the GUID needs to be created client-side when adding entries,
    leaving it as None then saving it doesn't generate the GUID.

    The field itself just converts the XML to list and vice versa, it doesn't
    automatically generate GUIDs for entries, this is entirely up to the caller.
    """

    # Namespaces for PossibleValues xml parsing.
    NAMESPACE = {
        "xsd": "http://www.w3.org/2001/XMLSchema",
        "xsi": "http://www.w3.org/2001/XMLSchema-instance",
        "": "http://schemas.microsoft.com/2010/08/ActiveDirectory/PossibleValues"
    }

    def from_db_value(self, ldb, value):
        """Parse MessageElement with XML to list of dicts."""
        if value is not None:
            root = ElementTree.fromstring(str(value))
            string_list = root.find("StringList", self.NAMESPACE)

            values = []
            for item in string_list.findall("Item", self.NAMESPACE):
                values.append({
                    "ValueGUID": item.find("ValueGUID", self.NAMESPACE).text,
                    "ValueDisplayName": item.find("ValueDisplayName",
                                                  self.NAMESPACE).text,
                    "ValueDescription": item.find("ValueDescription",
                                                  self.NAMESPACE).text,
                    "Value": item.find("Value", self.NAMESPACE).text,
                })

            return values

    def to_db_value(self, value, flags):
        """Convert list of dicts back fo XML as a MessageElement."""
        if value is None:
            return

        # Possible values should always be a list of dict, but for consistency
        # with other fields just wrap a single value into a list and continue.
        if isinstance(value, list):
            possible_values = value
        else:
            possible_values = [value]

        # No point storing XML of an empty list.
        # Return None, the field will be unset on the next save.
        if len(possible_values) == 0:
            return

        # root node
        root = ElementTree.Element("PossibleClaimValues")
        for name, url in self.NAMESPACE.items():
            if name == "":
                root.set("xmlns", url)
            else:
                root.set(f"xmlns:{name}", url)

        # StringList node
        string_list = ElementTree.SubElement(root, "StringList")

        # List of values
        for item_dict in possible_values:
            item = ElementTree.SubElement(string_list, "Item")
            item_guid = ElementTree.SubElement(item, "ValueGUID")
            item_guid.text = item_dict["ValueGUID"]
            item_name = ElementTree.SubElement(item, "ValueDisplayName")
            item_name.text = item_dict["ValueDisplayName"]
            item_desc = ElementTree.SubElement(item, "ValueDescription")
            item_desc.text = item_dict["ValueDescription"]
            item_value = ElementTree.SubElement(item, "Value")
            item_value.text = item_dict["Value"]

        # NOTE: indent was only added in Python 3.9 so can't be used yet.
        # ElementTree.indent(root, space="\t", level=0)

        out = io.BytesIO()
        ElementTree.ElementTree(root).write(out,
                                            encoding="utf-16",
                                            xml_declaration=True,
                                            short_empty_elements=False)

        # Back to str as that is what MessageElement needs.
        return MessageElement(out.getvalue().decode("utf-16"), flags, self.name)
