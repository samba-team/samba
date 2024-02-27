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
from datetime import datetime, timezone
from xml.etree import ElementTree

from ldb import FLAG_MOD_ADD, MessageElement, SCOPE_ONELEVEL
from samba.dcerpc import security
from samba.dcerpc.misc import GUID
from samba.netcmd.domain.models import (AccountType, Computer, Group, Site,
                                        User, StrongNTLMPolicy, fields)
from samba.ndr import ndr_pack, ndr_unpack

from .base import SambaToolCmdTest

HOST = "ldap://{DC_SERVER}".format(**os.environ)
CREDS = "-U{DC_USERNAME}%{DC_PASSWORD}".format(**os.environ)


class ModelTests(SambaToolCmdTest):

    @classmethod
    def setUpClass(cls):
        cls.samdb = cls.getSamDB("-H", HOST, CREDS)
        super().setUpClass()

    def test_query_count(self):
        """Test count property on Query object without converting to a list."""
        groups = Group.query(self.samdb)
        self.assertEqual(groups.count, len(list(groups)))

    def test_query_filter_bool(self):
        """Tests filtering by a BooleanField."""
        total = Group.query(self.samdb).count
        system_groups = Group.query(self.samdb,
                                    is_critical_system_object=True).count
        user_groups = Group.query(self.samdb,
                                  is_critical_system_object=False).count
        self.assertNotEqual(system_groups, 0)
        self.assertNotEqual(user_groups, 0)
        self.assertEqual(system_groups + user_groups, total)

    def test_query_filter_enum(self):
        """Tests filtering by an EnumField."""
        robots_vs_humans = User.query(self.samdb).count
        robots = User.query(self.samdb,
                            account_type=AccountType.WORKSTATION_TRUST).count
        humans = User.query(self.samdb,
                            account_type=AccountType.NORMAL_ACCOUNT).count
        self.assertNotEqual(robots, 0)
        self.assertNotEqual(humans, 0)
        self.assertEqual(robots + humans, robots_vs_humans)


class ComputerModelTests(SambaToolCmdTest):

    @classmethod
    def setUpClass(cls):
        cls.samdb = cls.getSamDB("-H", HOST, CREDS)
        super().setUpClass()

    def test_computer_constructor(self):
        comp1 = Computer(name="comp1")
        self.assertEqual(comp1.account_name, "comp1$")

        comp2 = Computer(cn="comp2")
        self.assertEqual(comp2.account_name, "comp2$")

        # User accidentally left out '$' in username.
        comp3 = Computer(name="comp3", username="comp3")
        self.assertEqual(comp3.account_name, "comp3$")

        comp4 = Computer(cn="comp4", username="comp4$")
        self.assertEqual(comp4.account_name, "comp4$")


class FieldTestMixin:
    """Tests a model field to ensure it behaves correctly in both directions.

    Use a mixin since TestCase can't be marked as abstract.
    """

    @classmethod
    def setUpClass(cls):
        cls.samdb = cls.getSamDB("-H", HOST, CREDS)
        super().setUpClass()

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
            db_value = self.field.to_db_value(self.samdb, value, FLAG_MOD_ADD)
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
        (datetime(2023, 1, 27, 22, 36, 41, tzinfo=timezone.utc),
         MessageElement("20230127223641.0Z")),
        ([datetime(2023, 1, 27, 22, 36, 41, tzinfo=timezone.utc),
          datetime(2023, 1, 27, 22, 47, 50, tzinfo=timezone.utc)],
         MessageElement(["20230127223641.0Z", "20230127224750.0Z"])),
        (None, None),
    ]

    from_db_value = [
        (MessageElement("20230127223641.0Z"),
         datetime(2023, 1, 27, 22, 36, 41, tzinfo=timezone.utc)),
        (MessageElement(["20230127223641.0Z", "20230127224750.0Z"]),
         [datetime(2023, 1, 27, 22, 36, 41, tzinfo=timezone.utc),
          datetime(2023, 1, 27, 22, 47, 50, tzinfo=timezone.utc)]),
        (None, None),
    ]


class NtTimeFieldTest(FieldTestMixin, SambaToolCmdTest):
    field = fields.NtTimeField("FieldName")

    to_db_value = [
        (datetime(2023, 1, 27, 22, 36, 41, tzinfo=timezone.utc),
         MessageElement("133193326010000000")),
        ([datetime(2023, 1, 27, 22, 36, 41, tzinfo=timezone.utc),
          datetime(2023, 1, 27, 22, 47, 50, tzinfo=timezone.utc)],
         MessageElement(["133193326010000000", "133193332700000000"])),
        (None, None),
    ]

    from_db_value = [
        (MessageElement("133193326010000000"),
         datetime(2023, 1, 27, 22, 36, 41, tzinfo=timezone.utc)),
        (MessageElement(["133193326010000000", "133193332700000000"]),
         [datetime(2023, 1, 27, 22, 36, 41, tzinfo=timezone.utc),
          datetime(2023, 1, 27, 22, 47, 50, tzinfo=timezone.utc)]),
        (None, None),
    ]


class RelatedFieldTest(FieldTestMixin, SambaToolCmdTest):
    field = fields.RelatedField("FieldName", User)

    @property
    def to_db_value(self):
        alice = User.get(self.samdb, account_name="alice")
        joe = User.get(self.samdb, account_name="joe")
        return [
            (alice, MessageElement(str(alice.dn))),
            ([joe, alice], MessageElement([str(joe.dn), str(alice.dn)])),
            (None, None),
        ]

    @property
    def from_db_value(self):
        alice = User.get(self.samdb, account_name="alice")
        joe = User.get(self.samdb, account_name="joe")
        return [
            (MessageElement(str(alice.dn)), alice),
            (MessageElement([str(joe.dn), str(alice.dn)]), [joe, alice]),
            (None, None),
        ]


class DnFieldTest(FieldTestMixin, SambaToolCmdTest):
    field = fields.DnField("FieldName")

    @property
    def to_db_value(self):
        alice = User.get(self.samdb, account_name="alice")
        joe = User.get(self.samdb, account_name="joe")
        return [
            (alice.dn, MessageElement(str(alice.dn))),
            ([joe.dn, alice.dn], MessageElement([str(joe.dn), str(alice.dn)])),
            (None, None),
        ]

    @property
    def from_db_value(self):
        alice = User.get(self.samdb, account_name="alice")
        joe = User.get(self.samdb, account_name="joe")
        return [
            (MessageElement(str(alice.dn)), alice.dn),
            (MessageElement([str(joe.dn), str(alice.dn)]), [joe.dn, alice.dn]),
            (None, None),
        ]


class SIDFieldTest(FieldTestMixin, SambaToolCmdTest):
    field = fields.SIDField("FieldName")

    @property
    def to_db_value(self):
        # Create a group for testing
        group = Group(name="group1")
        group.save(self.samdb)
        self.addCleanup(group.delete, self.samdb)

        # Get raw value to compare against
        group_rec = self.samdb.search(Group.get_base_dn(self.samdb),
                                      scope=SCOPE_ONELEVEL,
                                      expression="(name=group1)",
                                      attrs=["objectSid"])[0]
        raw_sid = group_rec["objectSid"]

        return [
            (group.object_sid, raw_sid),
            (None, None),
        ]

    @property
    def from_db_value(self):
        # Create a group for testing
        group = Group(name="group1")
        group.save(self.samdb)
        self.addCleanup(group.delete, self.samdb)

        # Get raw value to compare against
        group_rec = self.samdb.search(Group.get_base_dn(self.samdb),
                                      scope=SCOPE_ONELEVEL,
                                      expression="(name=group1)",
                                      attrs=["objectSid"])[0]
        raw_sid = group_rec["objectSid"]

        return [
            (raw_sid, group.object_sid),
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


class SDDLFieldTest(FieldTestMixin, SambaToolCmdTest):
    field = fields.SDDLField("FieldName")

    def setUp(self):
        super().setUp()
        self.domain_sid = security.dom_sid(self.samdb.get_domain_sid())

    def security_descriptor(self, sddl):
        return security.descriptor.from_sddl(sddl, self.domain_sid)

    @property
    def to_db_value(self):
        values = [
            "O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of {SID(AU)}))",
            "O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of {SID(AO)}))",
            "O:SYG:SYD:(XA;OICI;CR;;;WD;((Member_of {SID(AO)}) || (Member_of {SID(BO)})))",
            "O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of {SID(%s)}))" % self.domain_sid,
        ]

        # Values coming in are SDDL strings
        expected = [
            (value, MessageElement(ndr_pack(self.security_descriptor(value))))
            for value in values
        ]

        # Values coming in are already security descriptors
        expected.extend([
            (self.security_descriptor(value),
             MessageElement(ndr_pack(self.security_descriptor(value))))
            for value in values
        ])

        expected.append((None, None))
        return expected

    @property
    def from_db_value(self):
        values = [
            "O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of {SID(AU)}))",
            "O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of {SID(AO)}))",
            "O:SYG:SYD:(XA;OICI;CR;;;WD;((Member_of {SID(AO)}) || (Member_of {SID(BO)})))",
            "O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of {SID(%s)}))" % self.domain_sid,
        ]
        expected = [
            (MessageElement(ndr_pack(self.security_descriptor(value))),
             self.security_descriptor(value))
            for value in values
        ]
        expected.append((None, None))
        return expected


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
