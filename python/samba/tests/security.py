# Unix SMB/CIFS implementation.
# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007
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

"""Tests for samba.dcerpc.security."""

import samba.tests
from samba.dcerpc import security, claims
from samba.security import (
    access_check,
    claims_tf_policy_parse_rules,
    claims_tf_policy_wrap_xml,
)
from samba import ntstatus
from samba import NTSTATUSError
from binascii import a2b_base64


class SecurityTokenTests(samba.tests.TestCase):

    def setUp(self):
        super().setUp()
        self.token = security.token()

    def test_is_system(self):
        self.assertFalse(self.token.is_system())

    def test_is_anonymous(self):
        self.assertFalse(self.token.is_anonymous())

    def test_has_builtin_administrators(self):
        self.assertFalse(self.token.has_builtin_administrators())

    def test_has_nt_authenticated_users(self):
        self.assertFalse(self.token.has_nt_authenticated_users())

    def test_has_priv(self):
        self.assertFalse(self.token.has_privilege(security.SEC_PRIV_SHUTDOWN))

    def test_set_priv(self):
        self.assertFalse(self.token.has_privilege(security.SEC_PRIV_SHUTDOWN))
        self.assertFalse(self.token.set_privilege(security.SEC_PRIV_SHUTDOWN))
        self.assertTrue(self.token.has_privilege(security.SEC_PRIV_SHUTDOWN))


class SecurityDescriptorTests(samba.tests.TestCase):

    def setUp(self):
        super().setUp()
        self.descriptor = security.descriptor()

    def test_from_sddl(self):
        desc = security.descriptor.from_sddl("O:AOG:DAD:(A;;RPWPCCDCLCSWRCWDWOGA;;;S-1-0-0)",
                                             security.dom_sid("S-1-2-3"))
        self.assertEqual(desc.group_sid, security.dom_sid('S-1-2-3-512'))
        self.assertEqual(desc.owner_sid, security.dom_sid('S-1-5-32-548'))
        self.assertEqual(desc.revision, 1)
        self.assertEqual(desc.sacl, None)
        self.assertEqual(desc.type, 0x8004)

    def test_from_sddl_invalidsddl(self):
        self.assertRaises(security.SDDLValueError, security.descriptor.from_sddl, "foo",
                          security.dom_sid("S-1-2-3"))

    def test_from_sddl_invalidtype1(self):
        self.assertRaises(TypeError, security.descriptor.from_sddl, security.dom_sid('S-1-2-3-512'),
                          security.dom_sid("S-1-2-3"))

    def test_from_sddl_invalidtype2(self):
        sddl = "O:AOG:DAD:(A;;RPWPCCDCLCSWRCWDWOGA;;;S-1-0-0)"
        self.assertRaises(TypeError, security.descriptor.from_sddl, sddl,
                          "S-1-2-3")

    def test_as_sddl(self):
        text = "O:AOG:DAD:(A;;RPWPCCDCLCSWRCWDWOGA;;;S-1-0-0)"
        dom = security.dom_sid("S-1-2-3")
        desc1 = security.descriptor.from_sddl(text, dom)
        desc2 = security.descriptor.from_sddl(desc1.as_sddl(dom), dom)
        self.assertEqual(desc1.group_sid, desc2.group_sid)
        self.assertEqual(desc1.owner_sid, desc2.owner_sid)
        self.assertEqual(desc1.sacl, desc2.sacl)
        self.assertEqual(desc1.type, desc2.type)

    def test_as_sddl_invalid(self):
        text = "O:AOG:DAD:(A;;RPWPCCDCLCSWRCWDWOGA;;;S-1-0-0)"
        dom = security.dom_sid("S-1-2-3")
        desc1 = security.descriptor.from_sddl(text, dom)
        self.assertRaises(TypeError, desc1.as_sddl, text)

    def test_as_sddl_no_domainsid(self):
        dom = security.dom_sid("S-1-2-3")
        text = "O:AOG:DAD:(A;;RPWPCCDCLCSWRCWDWOGA;;;S-1-0-0)"
        desc1 = security.descriptor.from_sddl(text, dom)
        desc2 = security.descriptor.from_sddl(desc1.as_sddl(), dom)
        self.assertEqual(desc1.group_sid, desc2.group_sid)
        self.assertEqual(desc1.owner_sid, desc2.owner_sid)
        self.assertEqual(desc1.sacl, desc2.sacl)
        self.assertEqual(desc1.type, desc2.type)

    def test_domsid_nodomsid_as_sddl(self):
        dom = security.dom_sid("S-1-2-3")
        text = "O:AOG:DAD:(A;;RPWPCCDCLCSWRCWDWOGA;;;S-1-0-0)"
        desc1 = security.descriptor.from_sddl(text, dom)
        self.assertNotEqual(desc1.as_sddl(), desc1.as_sddl(dom))

    def test_split(self):
        dom = security.dom_sid("S-1-0-7")
        self.assertEqual((security.dom_sid("S-1-0"), 7), dom.split())


class DomSidTests(samba.tests.TestCase):

    def test_parse_sid(self):
        sid = security.dom_sid("S-1-5-21")
        self.assertEqual("S-1-5-21", str(sid))

    def test_sid_equal(self):
        sid1 = security.dom_sid("S-1-5-21")
        sid2 = security.dom_sid("S-1-5-21")
        self.assertEqual(sid1, sid1)
        self.assertEqual(sid1, sid2)

    def test_random(self):
        sid = security.random_sid()
        self.assertTrue(str(sid).startswith("S-1-5-21-"))

    def test_repr(self):
        sid = security.random_sid()
        self.assertTrue(repr(sid).startswith("dom_sid('S-1-5-21-"))


class PrivilegeTests(samba.tests.TestCase):

    def test_privilege_name(self):
        self.assertEqual("SeShutdownPrivilege",
                          security.privilege_name(security.SEC_PRIV_SHUTDOWN))

    def test_privilege_id(self):
        self.assertEqual(security.SEC_PRIV_SHUTDOWN,
                          security.privilege_id("SeShutdownPrivilege"))


class CheckAccessTests(samba.tests.TestCase):

    def test_check_access(self):
        desc = security.descriptor.from_sddl("O:AOG:DAD:(A;;RPWPCCDCLCSWRCWDWOGA;;;S-1-0-0)",
                                             security.dom_sid("S-1-2-3"))
        token = security.token()

        self.assertEqual(access_check(desc, token, 0), 0)

        params = (
            (security.SEC_FLAG_SYSTEM_SECURITY,
             ntstatus.NT_STATUS_PRIVILEGE_NOT_HELD),
            (security.SEC_STD_READ_CONTROL, ntstatus.NT_STATUS_ACCESS_DENIED)
        )

        for arg, num in params:
            try:
                result = access_check(desc, token, arg)
            except Exception as e:
                self.assertTrue(isinstance(e, NTSTATUSError))
                e_num, e_msg = e.args
                self.assertEqual(num, e_num)
            else:
                self.fail()


class SecurityAceTests(samba.tests.TestCase):
    sddl       = "(OA;CIIO;RPWP;aaaaaaaa-1111-bbbb-2222-dddddddddddd;33333333-eeee-4444-ffff-555555555555;PS)"
    sddl2      = "(OA;CIIO;RPWP;cccccccc-9999-ffff-8888-eeeeeeeeeeee;77777777-dddd-6666-bbbb-555555555555;PS)"
    sddl3      = "(OA;CIIO;RPWP;aaaaaaaa-1111-bbbb-2222-dddddddddddd;77777777-dddd-6666-bbbb-555555555555;PS)"
    sddl_uc    = "(OA;CIIO;RPWP;AAAAAAAA-1111-BBBB-2222-DDDDDDDDDDDD;33333333-EEEE-4444-FFFF-555555555555;PS)"
    sddl_mc    = "(OA;CIIO;RPWP;AaAaAAAa-1111-BbBb-2222-DDddDDdDDDDD;33333333-EeeE-4444-FffF-555555555555;PS)"
    sddl_sid   = "(OA;CIIO;RPWP;aaaaaaaa-1111-bbbb-2222-dddddddddddd;33333333-eeee-4444-ffff-555555555555;S-1-5-10)"

    def setUp(self):
        super().setUp()
        self.dom = security.dom_sid("S-1-2-3")

    def test_equality(self):
        ace = security.descriptor.from_sddl("D:" + self.sddl, self.dom).dacl.aces[0]
        ace2 = security.descriptor.from_sddl("D:" + self.sddl2, self.dom).dacl.aces[0]
        ace3 = security.descriptor.from_sddl("D:" + self.sddl3, self.dom).dacl.aces[0]
        ace_uc = security.descriptor.from_sddl("D:" + self.sddl_uc, self.dom).dacl.aces[0]
        ace_mc = security.descriptor.from_sddl("D:" + self.sddl_mc, self.dom).dacl.aces[0]
        ace_sid = security.descriptor.from_sddl("D:" + self.sddl_sid, self.dom).dacl.aces[0]
        self.assertTrue(ace == ace_uc, "Case should not matter.")
        self.assertTrue(ace == ace_mc, "Case should not matter.")
        self.assertTrue(ace != ace2, "Different ACEs should be unequal.")
        self.assertTrue(ace2 != ace3, "Different ACEs should be unequal.")
        self.assertTrue(ace == ace_sid, "Different ways of specifying SID should not matter.")

    def test_as_sddl(self):
        ace = security.descriptor.from_sddl("D:" + self.sddl, self.dom).dacl.aces[0]
        ace_sddl = ace.as_sddl(self.dom)
        # compare created SDDL with original one (we need to strip the parenthesis from the original
        # since as_sddl does not create them)
        self.assertEqual(ace_sddl, self.sddl[1:-1])
        ace_new = security.descriptor.from_sddl("D:(" + ace_sddl + ")", self.dom).dacl.aces[0]
        self.assertTrue(ace == ace_new, "Exporting ace as SDDl and reading back should result in same ACE.")


class ClaimsTransformationTests(samba.tests.TestCase):

    def test_deny_all_claims(self):
        rules = ''
        rs = claims_tf_policy_parse_rules(rules)
        self.assertEqual(rs.num_rules, 0)

    def test_allow_all_claims1(self):
        rules = 'C1:[] => ISSUE(Claim=C1);'
        rs = claims_tf_policy_parse_rules(rules)
        self.assertEqual(rs.num_rules, 1)
        self.assertEqual(rs.rules[0].num_condition_sets, 1)
        self.assertEqual(rs.rules[0].condition_sets[0].opt_identifier, 'C1')
        self.assertEqual(rs.rules[0].condition_sets[0].num_conditions, 0)
        self.assertEqual(rs.rules[0].action.type.ref.identifier, 'C1')
        self.assertEqual(rs.rules[0].action.type.ref.property,
                         claims.CLAIMS_TF_PROPERTY_TYPE)
        self.assertIsNone(rs.rules[0].action.type.string)
        self.assertEqual(rs.rules[0].action.value.ref.identifier, 'C1')
        self.assertEqual(rs.rules[0].action.value.ref.property,
                         claims.CLAIMS_TF_PROPERTY_VALUE)
        self.assertIsNone(rs.rules[0].action.value.string)
        self.assertEqual(rs.rules[0].action.value_type.ref.identifier, 'C1')
        self.assertEqual(rs.rules[0].action.value_type.ref.property,
                         claims.CLAIMS_TF_PROPERTY_VALUE_TYPE)
        self.assertIsNone(rs.rules[0].action.value_type.string)

    def test_allow_all_claims2(self):
        rules = 'C1:[] => ISSUE(ValueType=C1.ValueType,Value=C1.Value,Type=C1.Type);'
        rs = claims_tf_policy_parse_rules(rules)
        self.assertEqual(rs.num_rules, 1)
        self.assertEqual(rs.rules[0].num_condition_sets, 1)
        self.assertEqual(rs.rules[0].condition_sets[0].opt_identifier, 'C1')
        self.assertEqual(rs.rules[0].condition_sets[0].num_conditions, 0)
        self.assertEqual(rs.rules[0].action.type.ref.identifier, 'C1')
        self.assertEqual(rs.rules[0].action.type.ref.property,
                         claims.CLAIMS_TF_PROPERTY_TYPE)
        self.assertIsNone(rs.rules[0].action.type.string)
        self.assertEqual(rs.rules[0].action.value.ref.identifier, 'C1')
        self.assertEqual(rs.rules[0].action.value.ref.property,
                         claims.CLAIMS_TF_PROPERTY_VALUE)
        self.assertIsNone(rs.rules[0].action.value.string)
        self.assertEqual(rs.rules[0].action.value_type.ref.identifier, 'C1')
        self.assertEqual(rs.rules[0].action.value_type.ref.property,
                         claims.CLAIMS_TF_PROPERTY_VALUE_TYPE)
        self.assertIsNone(rs.rules[0].action.value_type.string)

    def test_allow_all_switch1(self):
        rules = 'C1:[] => ISSUE(ValueType=C1.ValueType,Value=C1.Type,Type=C1.Value);'
        rs = claims_tf_policy_parse_rules(rules)
        self.assertEqual(rs.num_rules, 1)
        self.assertEqual(rs.rules[0].num_condition_sets, 1)
        self.assertEqual(rs.rules[0].condition_sets[0].opt_identifier, 'C1')
        self.assertEqual(rs.rules[0].condition_sets[0].num_conditions, 0)
        self.assertEqual(rs.rules[0].action.type.ref.identifier, 'C1')
        self.assertEqual(rs.rules[0].action.type.ref.property,
                         claims.CLAIMS_TF_PROPERTY_VALUE)
        self.assertIsNone(rs.rules[0].action.type.string)
        self.assertEqual(rs.rules[0].action.value.ref.identifier, 'C1')
        self.assertEqual(rs.rules[0].action.value.ref.property,
                         claims.CLAIMS_TF_PROPERTY_TYPE)
        self.assertIsNone(rs.rules[0].action.value.string)
        self.assertEqual(rs.rules[0].action.value_type.ref.identifier, 'C1')
        self.assertEqual(rs.rules[0].action.value_type.ref.property,
                         claims.CLAIMS_TF_PROPERTY_VALUE_TYPE)
        self.assertIsNone(rs.rules[0].action.value_type.string)

    def test_deny_some_claims(self):
        rules = 'C1:[type != "Type1"] => ISSUE (Claim = C1);'
        rs = claims_tf_policy_parse_rules(rules)
        self.assertEqual(rs.num_rules, 1)
        self.assertEqual(rs.rules[0].num_condition_sets, 1)
        self.assertEqual(rs.rules[0].condition_sets[0].opt_identifier, 'C1')
        self.assertEqual(rs.rules[0].condition_sets[0].num_conditions, 1)
        self.assertEqual(rs.rules[0].condition_sets[0].conditions[0].property,
                         claims.CLAIMS_TF_PROPERTY_TYPE)
        self.assertEqual(rs.rules[0].condition_sets[0].conditions[0].operator,
                         claims.CLAIMS_TF_CONDITION_OPERATOR_NEQ)
        self.assertEqual(rs.rules[0].condition_sets[0].conditions[0].string,
                         'Type1')
        self.assertEqual(rs.rules[0].action.type.ref.identifier, 'C1')
        self.assertEqual(rs.rules[0].action.type.ref.property,
                         claims.CLAIMS_TF_PROPERTY_TYPE)
        self.assertIsNone(rs.rules[0].action.type.string)
        self.assertEqual(rs.rules[0].action.value.ref.identifier, 'C1')
        self.assertEqual(rs.rules[0].action.value.ref.property,
                         claims.CLAIMS_TF_PROPERTY_VALUE)
        self.assertIsNone(rs.rules[0].action.value.string)
        self.assertEqual(rs.rules[0].action.value_type.ref.identifier, 'C1')
        self.assertEqual(rs.rules[0].action.value_type.ref.property,
                         claims.CLAIMS_TF_PROPERTY_VALUE_TYPE)
        self.assertIsNone(rs.rules[0].action.value_type.string)

    def test_issue_always(self):
        rules = '=> ISSUE (type="type1", VALUE="false", VALUETYPE="boolean");'
        rs = claims_tf_policy_parse_rules(rules)
        self.assertEqual(rs.num_rules, 1)
        self.assertEqual(rs.rules[0].num_condition_sets, 0)
        self.assertIsNone(rs.rules[0].action.type.ref.identifier)
        self.assertEqual(rs.rules[0].action.type.ref.property,
                         claims.CLAIMS_TF_PROPERTY_INVALID)
        self.assertEqual(rs.rules[0].action.type.string, 'type1')
        self.assertIsNone(rs.rules[0].action.value.ref.identifier)
        self.assertEqual(rs.rules[0].action.value.ref.property,
                         claims.CLAIMS_TF_PROPERTY_INVALID)
        self.assertEqual(rs.rules[0].action.value.string, 'false')
        self.assertIsNone(rs.rules[0].action.value_type.ref.identifier)
        self.assertEqual(rs.rules[0].action.value_type.ref.property,
                         claims.CLAIMS_TF_PROPERTY_INVALID)
        self.assertEqual(rs.rules[0].action.value_type.string, 'boolean')

    def test_allow_some_claims1(self):
        rules = '_1:[value == "Bla",valuetype == "sTring"] => ISSUE (Claim = _1);'
        rs = claims_tf_policy_parse_rules(rules)
        self.assertEqual(rs.num_rules, 1)
        self.assertEqual(rs.rules[0].num_condition_sets, 1)
        self.assertEqual(rs.rules[0].condition_sets[0].opt_identifier, '_1')
        self.assertEqual(rs.rules[0].condition_sets[0].num_conditions, 2)
        self.assertEqual(rs.rules[0].condition_sets[0].conditions[0].property,
                         claims.CLAIMS_TF_PROPERTY_VALUE)
        self.assertEqual(rs.rules[0].condition_sets[0].conditions[0].operator,
                         claims.CLAIMS_TF_CONDITION_OPERATOR_EQ)
        self.assertEqual(rs.rules[0].condition_sets[0].conditions[0].string,
                         'Bla')
        self.assertEqual(rs.rules[0].condition_sets[0].conditions[1].property,
                         claims.CLAIMS_TF_PROPERTY_VALUE_TYPE)
        self.assertEqual(rs.rules[0].condition_sets[0].conditions[1].operator,
                         claims.CLAIMS_TF_CONDITION_OPERATOR_EQ)
        self.assertEqual(rs.rules[0].condition_sets[0].conditions[1].string,
                         'sTring')
        self.assertEqual(rs.rules[0].action.type.ref.identifier, '_1')
        self.assertEqual(rs.rules[0].action.type.ref.property,
                         claims.CLAIMS_TF_PROPERTY_TYPE)
        self.assertIsNone(rs.rules[0].action.type.string)
        self.assertEqual(rs.rules[0].action.value.ref.identifier, '_1')
        self.assertEqual(rs.rules[0].action.value.ref.property,
                         claims.CLAIMS_TF_PROPERTY_VALUE)
        self.assertIsNone(rs.rules[0].action.value.string)
        self.assertEqual(rs.rules[0].action.value_type.ref.identifier, '_1')
        self.assertEqual(rs.rules[0].action.value_type.ref.property,
                         claims.CLAIMS_TF_PROPERTY_VALUE_TYPE)
        self.assertIsNone(rs.rules[0].action.value_type.string)

    def test_allow_some_claims2(self):
        rules = '_1:[value == "Bla",valuetype == "string"] => ISSUE(Type=_1.Type, ValueType=_1.Valuetype, Value=_1.vAlUe);'
        rs = claims_tf_policy_parse_rules(rules)
        self.assertEqual(rs.num_rules, 1)
        self.assertEqual(rs.rules[0].num_condition_sets, 1)
        self.assertEqual(rs.rules[0].condition_sets[0].opt_identifier, '_1')
        self.assertEqual(rs.rules[0].condition_sets[0].num_conditions, 2)
        self.assertEqual(rs.rules[0].condition_sets[0].conditions[0].property,
                         claims.CLAIMS_TF_PROPERTY_VALUE)
        self.assertEqual(rs.rules[0].condition_sets[0].conditions[0].operator,
                         claims.CLAIMS_TF_CONDITION_OPERATOR_EQ)
        self.assertEqual(rs.rules[0].condition_sets[0].conditions[0].string,
                         'Bla')
        self.assertEqual(rs.rules[0].condition_sets[0].conditions[1].property,
                         claims.CLAIMS_TF_PROPERTY_VALUE_TYPE)
        self.assertEqual(rs.rules[0].condition_sets[0].conditions[1].operator,
                         claims.CLAIMS_TF_CONDITION_OPERATOR_EQ)
        self.assertEqual(rs.rules[0].condition_sets[0].conditions[1].string,
                         'string')
        self.assertEqual(rs.rules[0].action.type.ref.identifier, '_1')
        self.assertEqual(rs.rules[0].action.type.ref.property,
                         claims.CLAIMS_TF_PROPERTY_TYPE)
        self.assertIsNone(rs.rules[0].action.type.string)
        self.assertEqual(rs.rules[0].action.value.ref.identifier, '_1')
        self.assertEqual(rs.rules[0].action.value.ref.property,
                         claims.CLAIMS_TF_PROPERTY_VALUE)
        self.assertIsNone(rs.rules[0].action.value.string)
        self.assertEqual(rs.rules[0].action.value_type.ref.identifier, '_1')
        self.assertEqual(rs.rules[0].action.value_type.ref.property,
                         claims.CLAIMS_TF_PROPERTY_VALUE_TYPE)
        self.assertIsNone(rs.rules[0].action.value_type.string)

    def test_allow_some_claims3(self):
        rules = '[tYpE =~ "str*", value == "Bla",valuetype == "string"] => ISSUE(Type="Type", ValueType="string", Value="Val");'
        rs = claims_tf_policy_parse_rules(rules)
        self.assertEqual(rs.num_rules, 1)
        self.assertEqual(rs.rules[0].num_condition_sets, 1)
        self.assertIsNone(rs.rules[0].condition_sets[0].opt_identifier)
        self.assertEqual(rs.rules[0].condition_sets[0].num_conditions, 3)
        self.assertEqual(rs.rules[0].condition_sets[0].conditions[0].property,
                         claims.CLAIMS_TF_PROPERTY_TYPE)
        self.assertEqual(rs.rules[0].condition_sets[0].conditions[0].operator,
                         claims.CLAIMS_TF_CONDITION_OPERATOR_REGEXP_MATCH)
        self.assertEqual(rs.rules[0].condition_sets[0].conditions[0].string,
                         'str*')
        self.assertEqual(rs.rules[0].condition_sets[0].conditions[1].property,
                         claims.CLAIMS_TF_PROPERTY_VALUE)
        self.assertEqual(rs.rules[0].condition_sets[0].conditions[1].operator,
                         claims.CLAIMS_TF_CONDITION_OPERATOR_EQ)
        self.assertEqual(rs.rules[0].condition_sets[0].conditions[1].string,
                         'Bla')
        self.assertEqual(rs.rules[0].condition_sets[0].conditions[2].property,
                         claims.CLAIMS_TF_PROPERTY_VALUE_TYPE)
        self.assertEqual(rs.rules[0].condition_sets[0].conditions[2].operator,
                         claims.CLAIMS_TF_CONDITION_OPERATOR_EQ)
        self.assertEqual(rs.rules[0].condition_sets[0].conditions[2].string,
                         'string')
        self.assertIsNone(rs.rules[0].action.type.ref.identifier)
        self.assertEqual(rs.rules[0].action.type.ref.property,
                         claims.CLAIMS_TF_PROPERTY_INVALID)
        self.assertEqual(rs.rules[0].action.type.string, 'Type')
        self.assertIsNone(rs.rules[0].action.value.ref.identifier)
        self.assertEqual(rs.rules[0].action.value.ref.property,
                         claims.CLAIMS_TF_PROPERTY_INVALID)
        self.assertEqual(rs.rules[0].action.value.string, 'Val')
        self.assertIsNone(rs.rules[0].action.value_type.ref.identifier)
        self.assertEqual(rs.rules[0].action.value_type.ref.property,
                         claims.CLAIMS_TF_PROPERTY_INVALID)
        self.assertEqual(rs.rules[0].action.value_type.string, 'string')

    def test_two_condition_sets(self):
        rules = 'C1:[type != "Type1"] && _1:[valuetype == "string",value !~ "*v*", type == "t1"] => ISSUE(Type=C1.vAluE, ValueType=_1.Valuetype, Value="Val");'
        rs = claims_tf_policy_parse_rules(rules)
        self.assertEqual(rs.num_rules, 1)
        self.assertEqual(rs.rules[0].num_condition_sets, 2)
        self.assertEqual(rs.rules[0].condition_sets[0].opt_identifier, 'C1')
        self.assertEqual(rs.rules[0].condition_sets[0].num_conditions, 1)
        self.assertEqual(rs.rules[0].condition_sets[0].conditions[0].property,
                         claims.CLAIMS_TF_PROPERTY_TYPE)
        self.assertEqual(rs.rules[0].condition_sets[0].conditions[0].operator,
                         claims.CLAIMS_TF_CONDITION_OPERATOR_NEQ)
        self.assertEqual(rs.rules[0].condition_sets[0].conditions[0].string,
                         'Type1')
        self.assertEqual(rs.rules[0].condition_sets[1].opt_identifier, '_1')
        self.assertEqual(rs.rules[0].condition_sets[1].num_conditions, 3)
        self.assertEqual(rs.rules[0].condition_sets[1].conditions[0].property,
                         claims.CLAIMS_TF_PROPERTY_VALUE_TYPE)
        self.assertEqual(rs.rules[0].condition_sets[1].conditions[0].operator,
                         claims.CLAIMS_TF_CONDITION_OPERATOR_EQ)
        self.assertEqual(rs.rules[0].condition_sets[1].conditions[0].string,
                         'string')
        self.assertEqual(rs.rules[0].condition_sets[1].conditions[1].property,
                         claims.CLAIMS_TF_PROPERTY_VALUE)
        self.assertEqual(rs.rules[0].condition_sets[1].conditions[1].operator,
                         claims.CLAIMS_TF_CONDITION_OPERATOR_REGEXP_NOT_MATCH)
        self.assertEqual(rs.rules[0].condition_sets[1].conditions[1].string,
                         '*v*')
        self.assertEqual(rs.rules[0].condition_sets[1].conditions[2].property,
                         claims.CLAIMS_TF_PROPERTY_TYPE)
        self.assertEqual(rs.rules[0].condition_sets[1].conditions[2].operator,
                         claims.CLAIMS_TF_CONDITION_OPERATOR_EQ)
        self.assertEqual(rs.rules[0].condition_sets[1].conditions[2].string,
                         't1')
        self.assertEqual(rs.rules[0].action.type.ref.identifier, 'C1')
        self.assertEqual(rs.rules[0].action.type.ref.property,
                         claims.CLAIMS_TF_PROPERTY_VALUE)
        self.assertIsNone(rs.rules[0].action.type.string)
        self.assertIsNone(rs.rules[0].action.value.ref.identifier)
        self.assertEqual(rs.rules[0].action.value.ref.property,
                         claims.CLAIMS_TF_PROPERTY_INVALID)
        self.assertEqual(rs.rules[0].action.value.string, 'Val')
        self.assertEqual(rs.rules[0].action.value_type.ref.identifier, '_1')
        self.assertEqual(rs.rules[0].action.value_type.ref.property,
                         claims.CLAIMS_TF_PROPERTY_VALUE_TYPE)
        self.assertIsNone(rs.rules[0].action.value_type.string)

    def test_two_rules(self):
        rules = 'C1:[] => ISSUE(Claim=C1);C1:[] => ISSUE(Claim=C1);'
        rs = claims_tf_policy_parse_rules(rules)
        self.assertEqual(rs.num_rules, 2)
        self.assertEqual(rs.rules[0].num_condition_sets, 1)
        self.assertEqual(rs.rules[0].condition_sets[0].opt_identifier, 'C1')
        self.assertEqual(rs.rules[0].condition_sets[0].num_conditions, 0)
        self.assertEqual(rs.rules[0].action.type.ref.identifier, 'C1')
        self.assertEqual(rs.rules[0].action.type.ref.property,
                         claims.CLAIMS_TF_PROPERTY_TYPE)
        self.assertIsNone(rs.rules[0].action.type.string)
        self.assertEqual(rs.rules[0].action.value.ref.identifier, 'C1')
        self.assertEqual(rs.rules[0].action.value.ref.property,
                         claims.CLAIMS_TF_PROPERTY_VALUE)
        self.assertIsNone(rs.rules[0].action.value.string)
        self.assertEqual(rs.rules[0].action.value_type.ref.identifier, 'C1')
        self.assertEqual(rs.rules[0].action.value_type.ref.property,
                         claims.CLAIMS_TF_PROPERTY_VALUE_TYPE)
        self.assertIsNone(rs.rules[0].action.value_type.string)
        self.assertEqual(rs.rules[1].num_condition_sets, 1)
        self.assertEqual(rs.rules[1].condition_sets[0].opt_identifier, 'C1')
        self.assertEqual(rs.rules[1].condition_sets[0].num_conditions, 0)
        self.assertEqual(rs.rules[1].action.type.ref.identifier, 'C1')
        self.assertEqual(rs.rules[1].action.type.ref.property,
                         claims.CLAIMS_TF_PROPERTY_TYPE)
        self.assertIsNone(rs.rules[1].action.type.string)
        self.assertEqual(rs.rules[1].action.value.ref.identifier, 'C1')
        self.assertEqual(rs.rules[1].action.value.ref.property,
                         claims.CLAIMS_TF_PROPERTY_VALUE)
        self.assertIsNone(rs.rules[1].action.value.string)
        self.assertEqual(rs.rules[1].action.value_type.ref.identifier, 'C1')
        self.assertEqual(rs.rules[1].action.value_type.ref.property,
                         claims.CLAIMS_TF_PROPERTY_VALUE_TYPE)
        self.assertIsNone(rs.rules[1].action.value_type.string)

    def test_invalid_rule1(self):
        rules = 'C1:[type] => ISSUE (Claim = C1);'
        errmsg = 'syntax error, unexpected CLAIMS_TF_YY_C_SQ_BRACKET, expecting CLAIMS_TF_YY_EQ or CLAIMS_TF_YY_NEQ or CLAIMS_TF_YY_REGEXP_MATCH or CLAIMS_TF_YY_REGEXP_NOT_MATCH'
        try:
            claims_tf_policy_parse_rules(rules)
            self.fail()
        except RuntimeError as error:
            self.assertIn(errmsg, error.args[0])
        else:
            self.fail()

    def test_invalid_rule2(self):
        rules = 'C1:[valuetype== "none", value=="none"] => ISSUE (Claim = C1);'
        errmsg = 'Invalid ValueType string[none]'
        try:
            claims_tf_policy_parse_rules(rules)
            self.fail()
        except RuntimeError as error:
            self.assertIn(errmsg, error.args[0])
        else:
            self.fail()

    def test_invalid_rule3(self):
        rules = 'C1:[valuetype== "int64", value=="none"] => ISSUE (Claim = C3);'
        errmsg = 'Invalid Rules: rule[0] action.type invalid tidentifier C3'
        try:
            claims_tf_policy_parse_rules(rules)
            self.fail()
        except RuntimeError as error:
            self.assertIn(errmsg, error.args[0])
        else:
            self.fail()

    def test_invalid_rule4(self):
        rules = 'C1:[] => ISSUE(Type=C1.vAluE, ValueType=C1.type, Value=C1.Type);'
        errmsg = 'ValueType requires C1.ValueType'
        try:
            claims_tf_policy_parse_rules(rules)
            self.fail()
        except RuntimeError as error:
            self.assertIn(errmsg, error.args[0])
        else:
            self.fail()

    def test_invalid_rule5(self):
        rules = '[] && [] => ISSUE(Type=C1.vAluE, ValueType=C1.Valuetype, Value=C1.Type);'
        errmsg = 'Invalid Rules: rule[0] action.type invalid tidentifier C1'
        try:
            claims_tf_policy_parse_rules(rules)
            self.fail()
        except RuntimeError as error:
            self.assertIn(errmsg, error.args[0])
        else:
            self.fail()

    def test_xml_two_rules(self):
        rules = 'C1:[] => ISSUE(Claim=C1);C1:[] => ISSUE(Claim=C1);'
        xml_rules = claims_tf_policy_wrap_xml(rules)
        rs = claims_tf_policy_parse_rules(xml_rules, strip_xml=True)
        self.assertEqual(rs.num_rules, 2)
        self.assertEqual(rs.rules[0].num_condition_sets, 1)
        self.assertEqual(rs.rules[0].condition_sets[0].opt_identifier, 'C1')
        self.assertEqual(rs.rules[0].condition_sets[0].num_conditions, 0)
        self.assertEqual(rs.rules[0].action.type.ref.identifier, 'C1')
        self.assertEqual(rs.rules[0].action.type.ref.property,
                         claims.CLAIMS_TF_PROPERTY_TYPE)
        self.assertIsNone(rs.rules[0].action.type.string)
        self.assertEqual(rs.rules[0].action.value.ref.identifier, 'C1')
        self.assertEqual(rs.rules[0].action.value.ref.property,
                         claims.CLAIMS_TF_PROPERTY_VALUE)
        self.assertIsNone(rs.rules[0].action.value.string)
        self.assertEqual(rs.rules[0].action.value_type.ref.identifier, 'C1')
        self.assertEqual(rs.rules[0].action.value_type.ref.property,
                         claims.CLAIMS_TF_PROPERTY_VALUE_TYPE)
        self.assertIsNone(rs.rules[0].action.value_type.string)
        self.assertEqual(rs.rules[1].num_condition_sets, 1)
        self.assertEqual(rs.rules[1].condition_sets[0].opt_identifier, 'C1')
        self.assertEqual(rs.rules[1].condition_sets[0].num_conditions, 0)
        self.assertEqual(rs.rules[1].action.type.ref.identifier, 'C1')
        self.assertEqual(rs.rules[1].action.type.ref.property,
                         claims.CLAIMS_TF_PROPERTY_TYPE)
        self.assertIsNone(rs.rules[1].action.type.string)
        self.assertEqual(rs.rules[1].action.value.ref.identifier, 'C1')
        self.assertEqual(rs.rules[1].action.value.ref.property,
                         claims.CLAIMS_TF_PROPERTY_VALUE)
        self.assertIsNone(rs.rules[1].action.value.string)
        self.assertEqual(rs.rules[1].action.value_type.ref.identifier, 'C1')
        self.assertEqual(rs.rules[1].action.value_type.ref.property,
                         claims.CLAIMS_TF_PROPERTY_VALUE_TYPE)
        self.assertIsNone(rs.rules[1].action.value_type.string)

    def test_xml_from_windows1(self):
        # a msDS-TransformationRules value from Windows
        b64 =  'IDxDbGFpbXNUcmFuc2Zvcm1hdGlvblBvbGljeT4gICAgIDxSdWx'
        b64 += 'lcyB2ZXJzaW9uPSIxIj4gICAgICAgICA8IVtDREFUQVtNMTpbVH'
        b64 += 'lwZT09ImFkOi8vZXh0L3NBTUFjY291bnROYW1lOjg4ZGQzMTc2M'
        b64 += 'mQ3MzY1MmQiLCBUeXBlPX4iYmxhXS5dPiIsIFZhbHVlPT0ibWV0'
        b64 += 'emUiLCBWYWx1ZVR5cGUhfiJpbnQ2NCIsIHR5cGUhPSJub3QiXSA'
        b64 += 'mJiBNMjpbVHlwZT09Im5vbmUiXSA9PiBJU1NVRShWYWx1ZVR5cG'
        b64 += 'U9TTEuVmFsdWVUeXBlLFZhbHVlPU0yLlZhbHVlVHlwZSx0WXBFP'
        b64 += 'U0xLlR5cGUpO11dPiAgICA8L1J1bGVzPjwvQ2xhaW1zVHJhbnNm'
        b64 += 'b3JtYXRpb25Qb2xpY3k+'
        bval = a2b_base64(b64)
        sval = bval.decode('utf8')
        rs = claims_tf_policy_parse_rules(sval, strip_xml=True)
        self.assertEqual(rs.num_rules, 1)
        self.assertEqual(rs.rules[0].num_condition_sets, 2)
        self.assertEqual(rs.rules[0].condition_sets[0].opt_identifier, 'M1')
        self.assertEqual(rs.rules[0].condition_sets[0].num_conditions, 5)
        self.assertEqual(rs.rules[0].condition_sets[0].conditions[0].property,
                         claims.CLAIMS_TF_PROPERTY_TYPE)
        self.assertEqual(rs.rules[0].condition_sets[0].conditions[0].operator,
                         claims.CLAIMS_TF_CONDITION_OPERATOR_EQ)
        self.assertEqual(rs.rules[0].condition_sets[0].conditions[0].string,
                         'ad://ext/sAMAccountName:88dd31762d73652d')
        self.assertEqual(rs.rules[0].condition_sets[0].conditions[1].property,
                         claims.CLAIMS_TF_PROPERTY_TYPE)
        self.assertEqual(rs.rules[0].condition_sets[0].conditions[1].operator,
                         claims.CLAIMS_TF_CONDITION_OPERATOR_REGEXP_MATCH)
        self.assertEqual(rs.rules[0].condition_sets[0].conditions[1].string,
                         'bla].]>')
        self.assertEqual(rs.rules[0].condition_sets[0].conditions[2].property,
                         claims.CLAIMS_TF_PROPERTY_VALUE)
        self.assertEqual(rs.rules[0].condition_sets[0].conditions[2].operator,
                         claims.CLAIMS_TF_CONDITION_OPERATOR_EQ)
        self.assertEqual(rs.rules[0].condition_sets[0].conditions[2].string,
                         'metze')
        self.assertEqual(rs.rules[0].condition_sets[0].conditions[3].property,
                         claims.CLAIMS_TF_PROPERTY_VALUE_TYPE)
        self.assertEqual(rs.rules[0].condition_sets[0].conditions[3].operator,
                         claims.CLAIMS_TF_CONDITION_OPERATOR_REGEXP_NOT_MATCH)
        self.assertEqual(rs.rules[0].condition_sets[0].conditions[3].string,
                         'int64')
        self.assertEqual(rs.rules[0].condition_sets[0].conditions[4].property,
                         claims.CLAIMS_TF_PROPERTY_TYPE)
        self.assertEqual(rs.rules[0].condition_sets[0].conditions[4].operator,
                         claims.CLAIMS_TF_CONDITION_OPERATOR_NEQ)
        self.assertEqual(rs.rules[0].condition_sets[0].conditions[4].string,
                         'not')
        self.assertEqual(rs.rules[0].condition_sets[1].opt_identifier, 'M2')
        self.assertEqual(rs.rules[0].condition_sets[1].num_conditions, 1)
        self.assertEqual(rs.rules[0].condition_sets[1].conditions[0].property,
                         claims.CLAIMS_TF_PROPERTY_TYPE)
        self.assertEqual(rs.rules[0].condition_sets[1].conditions[0].operator,
                         claims.CLAIMS_TF_CONDITION_OPERATOR_EQ)
        self.assertEqual(rs.rules[0].condition_sets[1].conditions[0].string,
                         'none')
        self.assertEqual(rs.rules[0].action.type.ref.identifier, 'M1')
        self.assertEqual(rs.rules[0].action.type.ref.property,
                         claims.CLAIMS_TF_PROPERTY_TYPE)
        self.assertIsNone(rs.rules[0].action.type.string)
        self.assertEqual(rs.rules[0].action.value.ref.identifier, 'M2')
        self.assertEqual(rs.rules[0].action.value.ref.property,
                         claims.CLAIMS_TF_PROPERTY_VALUE_TYPE)
        self.assertIsNone(rs.rules[0].action.value.string)
        self.assertEqual(rs.rules[0].action.value_type.ref.identifier, 'M1')
        self.assertEqual(rs.rules[0].action.value_type.ref.property,
                         claims.CLAIMS_TF_PROPERTY_VALUE_TYPE)
        self.assertIsNone(rs.rules[0].action.value_type.string)
