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

from ldb import FLAG_MOD_ADD, SCOPE_ONELEVEL, MessageElement

from samba.dcerpc import security
from samba.dcerpc.misc import GUID
from samba.domain.models import (AccountType, AuthenticationPolicy,
                                 AuthenticationSilo, Computer, Group, Site,
                                 StrongNTLMPolicy, User, fields)
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
        all_users = list(User.query(self.samdb))
        robots_vs_humans = len(all_users)

        robots_list = list(
            User.query(self.samdb, account_type=AccountType.WORKSTATION_TRUST)
        )
        robots = len(robots_list)

        humans_list = list(
            User.query(self.samdb, account_type=AccountType.NORMAL_ACCOUNT)
        )
        humans = len(humans_list)
        trusts_list = list(
            User.query(self.samdb, account_type=AccountType.INTERDOMAIN_TRUST)
        )
        trusts = len(trusts_list)

        # Debug output
        print("\n=== Debug Output for test_query_filter_enum ===")
        print(f"Total users: {robots_vs_humans}")
        print(f"Robots (WORKSTATION_TRUST): {robots}")
        print(f"Humans (NORMAL_ACCOUNT): {humans}")
        print(f"Trusts (INTERDOMAIN_TRUST): {trusts}")
        print(f"Sum (robots + humans + trusts): {robots + humans + trusts}")
        print(f"Difference: {robots_vs_humans - (robots + humans + trusts)}")

        # Find users that are neither robots nor humans
        robots_dns = {str(user.dn) for user in robots_list}
        humans_dns = {str(user.dn) for user in humans_list}
        trust_dns = {str(user.dn) for user in trusts_list}
        all_dns = {str(user.dn) for user in all_users}
        other_dns = all_dns - robots_dns - humans_dns - trust_dns

        if other_dns:
            print(f"\nUsers that are neither WORKSTATION_TRUST nor "
                  f"NORMAL_ACCOUNT nor INTERDOMAIN_TRUST ({len(other_dns)}):")
            for user in all_users:
                if str(user.dn) in other_dns:
                    account_type_value = user.account_type
                    print(f"  - {user.account_name}: "
                          f"account_type={account_type_value}")

        print("=== End Debug Output ===\n")

        self.assertNotEqual(robots, 0)
        self.assertNotEqual(humans, 0)
        # If we have domain trusts or not, depends if we have setup
        # environments with domain trusts before.
        self.assertEqual(robots + humans + trusts, robots_vs_humans)

    def test_as_dict(self):
        """Test the as_dict method for serializing to dict then JSON."""
        policy = AuthenticationPolicy.create(self.samdb, name="as_dict_pol")
        self.addCleanup(policy.delete, self.samdb)
        silo = AuthenticationSilo.create(self.samdb,
                                         name="test_as_dict_silo",
                                         description="test as_dict silo",
                                         enforced=True,
                                         user_authentication_policy=None,
                                         service_authentication_policy=policy.dn,
                                         computer_authentication_policy=None,
                                         members=[])
        self.addCleanup(silo.delete, self.samdb)
        silo_dict = silo.as_dict()

        # Test various fields with different datatypes.
        self.assertEqual(silo_dict["name"], "test_as_dict_silo")
        self.assertEqual(silo_dict["description"], "test as_dict silo")
        self.assertEqual(silo_dict["msDS-AuthNPolicySiloEnforced"], True)

        # Fields that are None are excluded as that means unsetting a field.
        self.assertNotIn("msDS-UserAuthNPolicy", silo_dict)
        self.assertIn("msDS-ServiceAuthNPolicy", silo_dict)

        # Fields with many=True are represented by an empty list,
        # but should still be excluded by as_dict().
        self.assertNotIn("msDS-AuthNPolicySiloMembers", silo_dict)

        # Now add a member and see if silo members appears as a key.
        jane = User.get(self.samdb, account_name="jane")
        silo.members.append(jane.dn)
        silo.save(self.samdb)
        silo_dict = silo.as_dict()
        self.assertIn("msDS-AuthNPolicySiloMembers", silo_dict)

        # Hidden fields are excluded by default.
        self.assertNotIn("whenCreated", silo_dict)

        # Unless include_hidden=True is used.
        silo_dict = silo.as_dict(include_hidden=True)
        self.assertIn("whenCreated", silo_dict)


class UserModelTests(SambaToolCmdTest):

    @classmethod
    def setUpClass(cls):
        cls.samdb = cls.getSamDB("-H", HOST, CREDS)
        super().setUpClass()

    def test_get_primary_group(self):
        jane = User.get(self.samdb, account_name="jane")
        domain_sid = self.samdb.domain_sid
        expected_group = Group.get(self.samdb,
                                   object_sid=f"{domain_sid}-{jane.primary_group_id}")
        self.assertEqual(jane.get_primary_group(self.samdb), expected_group)


class ComputerModelTests(SambaToolCmdTest):

    @classmethod
    def setUpClass(cls):
        cls.samdb = cls.getSamDB("-H", HOST, CREDS)
        super().setUpClass()

    def test_computer_constructor(self):
        # Use only name
        comp1 = Computer.create(self.samdb, name="comp1")
        self.addCleanup(comp1.delete, self.samdb)
        self.assertEqual(comp1.name, "comp1")
        self.assertEqual(comp1.account_name, "comp1$")

        # Use only cn
        comp2 = Computer.create(self.samdb, cn="comp2")
        self.addCleanup(comp2.delete, self.samdb)
        self.assertEqual(comp2.name, "comp2")
        self.assertEqual(comp2.account_name, "comp2$")

        # Use name and account_name but missing "$" in account_name.
        comp3 = Computer.create(self.samdb, name="comp3", account_name="comp3")
        self.addCleanup(comp3.delete, self.samdb)
        self.assertEqual(comp3.name, "comp3")
        self.assertEqual(comp3.account_name, "comp3$")

        # Use cn and account_name but missing "$" in account_name.
        comp4 = Computer.create(self.samdb, cn="comp4", account_name="comp4$")
        self.addCleanup(comp4.delete, self.samdb)
        self.assertEqual(comp4.name, "comp4")
        self.assertEqual(comp4.account_name, "comp4$")

        # Use only account_name, the name should get the "$" removed.
        comp5 = Computer.create(self.samdb, account_name="comp5$")
        self.addCleanup(comp5.delete, self.samdb)
        self.assertEqual(comp5.name, "comp5")
        self.assertEqual(comp5.account_name, "comp5$")

        # Use only account_name but accidentally forgot the "$" character.
        comp6 = Computer.create(self.samdb, account_name="comp6")
        self.addCleanup(comp6.delete, self.samdb)
        self.assertEqual(comp6.name, "comp6")
        self.assertEqual(comp6.account_name, "comp6$")


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
