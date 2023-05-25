# Unix SMB/CIFS implementation.
#
# Tests for domain models and fields
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

import os
from datetime import datetime
from xml.etree import ElementTree

from ldb import FLAG_MOD_ADD, MessageElement, SCOPE_ONELEVEL
from samba.dcerpc.misc import GUID
from samba.netcmd.domain.models import User, fields
from samba.netcmd.domain.models.auth_policy import StrongNTLMPolicy
from samba.ndr import ndr_unpack

from .base import SambaToolCmdTest


class FieldTestMixin:
    """Tests a model field to ensure it behaves correctly in both directions.

    Use a mixin since TestCase can't be marked as abstract.
    """

    def setUp(self):
        super().setUp()
        self.host = "ldap://{DC_SERVER}".format(**os.environ)
        self.creds = "-U{DC_USERNAME}%{DC_PASSWORD}".format(**os.environ)
        self.samdb = self.getSamDB("-H", self.host, self.creds)

    def get_users_dn(self):
        """Returns Users DN."""
        users_dn = self.samdb.get_root_basedn()
        users_dn.add_child("CN=Users")
        return users_dn

    def test_to_db_value(self):
        # Loop through each value and expected value combination.
        # If the expected value is callable, treat it as a validation callback.
        # NOTE: perhaps we should be using subtests for this.
        for (value, expected) in self.to_db_value:
            db_value = self.field.to_db_value(value, FLAG_MOD_ADD)
            if callable(expected):
                self.assertTrue(expected(db_value))
            else:
                self.assertEqual(db_value, expected)

    def test_from_db_value(self):
        # Loop through each value and expected value combination.
        # NOTE: perhaps we should be using subtests for this.
        for (db_value, expected) in self.from_db_value:
            value = self.field.from_db_value(self.samdb, db_value)
            self.assertEqual(value, expected)


class IntegerFieldTest(FieldTestMixin, SambaToolCmdTest):
    field = fields.IntegerField("FieldName")

    to_db_value = [
        (10, MessageElement(b"10")),
        ([1, 5, 10], MessageElement([b"1", b"5", b"10"])),
        (None, None),
    ]

    from_db_value = [
        (MessageElement(b"10"), 10),
        (MessageElement([b"1", b"5", b"10"]), [1, 5, 10]),
        (None, None),
    ]


class BinaryFieldTest(FieldTestMixin, SambaToolCmdTest):
    field = fields.BinaryField("FieldName")

    to_db_value = [
        (b"SAMBA", MessageElement(b"SAMBA")),
        ([b"SAMBA", b"Developer"], MessageElement([b"SAMBA", b"Developer"])),
        (None, None),
    ]

    from_db_value = [
        (MessageElement(b"SAMBA"), b"SAMBA"),
        (MessageElement([b"SAMBA", b"Developer"]), [b"SAMBA", b"Developer"]),
        (None, None),
    ]


class StringFieldTest(FieldTestMixin, SambaToolCmdTest):
    field = fields.StringField("FieldName")

    to_db_value = [
        ("SAMBA", MessageElement(b"SAMBA")),
        (["SAMBA", "Developer"], MessageElement([b"SAMBA", b"Developer"])),
        (None, None),
    ]

    from_db_value = [
        (MessageElement(b"SAMBA"), "SAMBA"),
        (MessageElement([b"SAMBA", b"Developer"]), ["SAMBA", "Developer"]),
        (None, None),
    ]


class BooleanFieldTest(FieldTestMixin, SambaToolCmdTest):
    field = fields.BooleanField("FieldName")

    to_db_value = [
        (True, MessageElement(b"TRUE")),
        ([False, True], MessageElement([b"FALSE", b"TRUE"])),
        (None, None),
    ]

    from_db_value = [
        (MessageElement(b"TRUE"), True),
        (MessageElement([b"FALSE", b"TRUE"]), [False, True]),
        (None, None),
    ]


class EnumFieldTest(FieldTestMixin, SambaToolCmdTest):
    field = fields.EnumField("FieldName", StrongNTLMPolicy)

    to_db_value = [
        (StrongNTLMPolicy.OPTIONAL, MessageElement("1")),
        ([StrongNTLMPolicy.REQUIRED, StrongNTLMPolicy.OPTIONAL],
         MessageElement(["2", "1"])),
        (None, None),
    ]

    from_db_value = [
        (MessageElement("1"), StrongNTLMPolicy.OPTIONAL),
        (MessageElement(["2", "1"]),
         [StrongNTLMPolicy.REQUIRED, StrongNTLMPolicy.OPTIONAL]),
        (None, None),
    ]


class DateTimeFieldTest(FieldTestMixin, SambaToolCmdTest):
    field = fields.DateTimeField("FieldName")

    to_db_value = [
        (datetime(2023, 1, 27, 22, 36, 41), MessageElement("20230127223641.0Z")),
        ([datetime(2023, 1, 27, 22, 36, 41), datetime(2023, 1, 27, 22, 47, 50)],
         MessageElement(["20230127223641.0Z", "20230127224750.0Z"])),
        (None, None),
    ]

    from_db_value = [
        (MessageElement("20230127223641.0Z"), datetime(2023, 1, 27, 22, 36, 41)),
        (MessageElement(["20230127223641.0Z", "20230127224750.0Z"]),
         [datetime(2023, 1, 27, 22, 36, 41), datetime(2023, 1, 27, 22, 47, 50)]),
        (None, None),
    ]


class RelatedFieldTest(FieldTestMixin, SambaToolCmdTest):
    field = fields.RelatedField("FieldName", User)

    @property
    def to_db_value(self):
        alice = User.get(self.samdb, username="alice")
        joe = User.get(self.samdb, username="joe")
        return [
            (alice, MessageElement(str(alice.dn))),
            ([joe, alice], MessageElement([str(joe.dn), str(alice.dn)])),
            (None, None),
        ]

    @property
    def from_db_value(self):
        alice = User.get(self.samdb, username="alice")
        joe = User.get(self.samdb, username="joe")
        return [
            (MessageElement(str(alice.dn)), alice),
            (MessageElement([str(joe.dn), str(alice.dn)]), [joe, alice]),
            (None, None),
        ]


class DnFieldTest(FieldTestMixin, SambaToolCmdTest):
    field = fields.DnField("FieldName")

    @property
    def to_db_value(self):
        alice = User.get(self.samdb, username="alice")
        joe = User.get(self.samdb, username="joe")
        return [
            (alice.dn, MessageElement(str(alice.dn))),
            ([joe.dn, alice.dn], MessageElement([str(joe.dn), str(alice.dn)])),
            (None, None),
        ]

    @property
    def from_db_value(self):
        alice = User.get(self.samdb, username="alice")
        joe = User.get(self.samdb, username="joe")
        return [
            (MessageElement(str(alice.dn)), alice.dn),
            (MessageElement([str(joe.dn), str(alice.dn)]), [joe.dn, alice.dn]),
            (None, None),
        ]


class GUIDFieldTest(FieldTestMixin, SambaToolCmdTest):
    field = fields.GUIDField("FieldName")

    @property
    def to_db_value(self):
        users_dn = self.get_users_dn()

        alice = self.samdb.search(users_dn,
                                  scope=SCOPE_ONELEVEL,
                                  expression="(sAMAccountName=alice)",
                                  attrs=["objectGUID"])[0]

        joe = self.samdb.search(users_dn,
                                scope=SCOPE_ONELEVEL,
                                expression="(sAMAccountName=joe)",
                                attrs=["objectGUID"])[0]

        alice_guid = str(ndr_unpack(GUID, alice["objectGUID"][0]))
        joe_guid = str(ndr_unpack(GUID, joe["objectGUID"][0]))

        return [
            (alice_guid, alice["objectGUID"]),
            (
                [joe_guid, alice_guid],
                MessageElement([joe["objectGUID"][0], alice["objectGUID"][0]]),
            ),
            (None, None),
        ]

    @property
    def from_db_value(self):
        users_dn = self.get_users_dn()

        alice = self.samdb.search(users_dn,
                                  scope=SCOPE_ONELEVEL,
                                  expression="(sAMAccountName=alice)",
                                  attrs=["objectGUID"])[0]

        joe = self.samdb.search(users_dn,
                                scope=SCOPE_ONELEVEL,
                                expression="(sAMAccountName=joe)",
                                attrs=["objectGUID"])[0]

        alice_guid = str(ndr_unpack(GUID, alice["objectGUID"][0]))
        joe_guid = str(ndr_unpack(GUID, joe["objectGUID"][0]))

        return [
            (alice["objectGUID"], alice_guid),
            (
                MessageElement([joe["objectGUID"][0], alice["objectGUID"][0]]),
                [joe_guid, alice_guid],
            ),
            (None, None),
        ]


class PossibleClaimValuesFieldTest(FieldTestMixin, SambaToolCmdTest):
    field = fields.PossibleClaimValuesField("FieldName")

    json_data = [{
        "ValueGUID": "1c39ed4f-0b26-4536-b963-5959c8b1b676",
        "ValueDisplayName": "Alice",
        "ValueDescription": "Alice Description",
        "Value": "alice",
    }]

    xml_data = "<?xml version='1.0' encoding='utf-16'?>" \
               "<PossibleClaimValues xmlns:xsd='http://www.w3.org/2001/XMLSchema'" \
               " xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'" \
               " xmlns='http://schemas.microsoft.com/2010/08/ActiveDirectory/PossibleValues'>" \
               "<StringList>" \
               "<Item>" \
               "<ValueGUID>1c39ed4f-0b26-4536-b963-5959c8b1b676</ValueGUID>" \
               "<ValueDisplayName>Alice</ValueDisplayName>" \
               "<ValueDescription>Alice Description</ValueDescription>" \
               "<Value>alice</Value>" \
               "</Item>" \
               "</StringList>" \
               "</PossibleClaimValues>"

    def validate_xml(self, db_field):
        """Callback that compares XML strings.

        Tidying the HTMl output and adding consistent indentation was only
        added to ETree in Python 3.9+ so generate a single line XML string.

        This is just based on comparing the parsed XML, converted back
        to a string, then comparing those strings.

        So the expected xml_data string must have no spacing or indentation.

        :param db_field: MessageElement value returned by field.to_db_field()
        """
        expected = ElementTree.fromstring(self.xml_data)
        parsed = ElementTree.fromstring(str(db_field))
        return ElementTree.tostring(parsed) == ElementTree.tostring(expected)

    @property
    def to_db_value(self):
        return [
            (self.json_data, self.validate_xml),     # callback to validate XML
            (self.json_data[0], self.validate_xml),  # one item wrapped as list
            ([], None),                              # empty list clears field
            (None, None),
        ]

    @property
    def from_db_value(self):
        return [
            (MessageElement(self.xml_data), self.json_data),
            (None, None),
        ]
