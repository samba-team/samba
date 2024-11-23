#!/usr/bin/env python3
# Unix SMB/CIFS implementation.
# Copyright (C) Stefan Metzmacher 2020
# Copyright (C) Catalyst.Net Ltd 2023
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

import sys
import os

sys.path.insert(0, 'bin/python')
os.environ['PYTHONUNBUFFERED'] = '1'

from collections import OrderedDict
from functools import partial
import re
from string import Formatter

import ldb

from samba import dsdb, ntstatus
from samba.dcerpc import claims, krb5pac, netlogon, security
from samba.ndr import ndr_pack, ndr_unpack
from samba.sd_utils import escaped_claim_id

from samba.tests import DynamicTestCase, env_get_var_value
from samba.tests.krb5.authn_policy_tests import (
    AuditEvent,
    AuditReason,
    AuthnPolicyBaseTests,
)
from samba.tests.krb5.raw_testcase import RawKerberosTest
from samba.tests.krb5.rfc4120_constants import (
    KDC_ERR_BADOPTION,
    KDC_ERR_GENERIC,
    KDC_ERR_POLICY,
    NT_PRINCIPAL,
)
import samba.tests.krb5.rfc4120_pyasn1 as krb5_asn1

SidType = RawKerberosTest.SidType

global_asn1_print = False
global_hexdump = False


# When used as a test outcome, indicates that the test can cause a Windows
# server to crash, and is to be run with caution.
CRASHES_WINDOWS = object()


class ConditionalAceBaseTests(AuthnPolicyBaseTests):
    # Constants for group SID attributes.
    default_attrs = security.SE_GROUP_DEFAULT_FLAGS
    resource_attrs = default_attrs | security.SE_GROUP_RESOURCE

    aa_asserted_identity = (
        security.SID_AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY)
    service_asserted_identity = security.SID_SERVICE_ASSERTED_IDENTITY

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        cls._setup = False

    def setUp(self):
        super().setUp()
        self.do_asn1_print = global_asn1_print
        self.do_hexdump = global_hexdump

        if not self._setup:
            samdb = self.get_samdb()
            cls = type(self)

            # Create a machine account with which to perform FAST.
            cls._mach_creds = self.get_cached_creds(
                account_type=self.AccountType.COMPUTER)

            # Create an account with which to perform SamLogon.
            cls._mach_creds_ntlm = self._get_creds(
                account_type=self.AccountType.USER,
                ntlm=True)

            # Create some new groups.

            group0_name = self.get_new_username()
            group0_dn = self.create_group(samdb, group0_name)
            cls._group0_sid = self.get_objectSid(samdb, group0_dn)

            group1_name = self.get_new_username()
            group1_dn = self.create_group(samdb, group1_name)
            cls._group1_sid = self.get_objectSid(samdb, group1_dn)

            # Create machine accounts with which to perform FAST that belong to
            # various arrangements of the groups.

            cls._member_of_both_creds = self.get_cached_creds(
                account_type=self.AccountType.COMPUTER,
                opts={'member_of': (group0_dn, group1_dn)})

            cls._member_of_one_creds = self.get_cached_creds(
                account_type=self.AccountType.COMPUTER,
                opts={'member_of': (group1_dn,)})

            cls._member_of_both_creds_ntlm = self.get_cached_creds(
                account_type=self.AccountType.USER,
                opts={
                    'member_of': (group0_dn, group1_dn),
                    'kerberos_enabled': False,
                })

            # Create some authentication silos.
            cls._unenforced_silo = self.create_authn_silo(enforced=False)
            cls._enforced_silo = self.create_authn_silo(enforced=True)

            # Create machine accounts with which to perform FAST that belong to
            # the respective silos.

            cls._member_of_unenforced_silo = self._get_creds(
                account_type=self.AccountType.COMPUTER,
                assigned_silo=self._unenforced_silo,
                cached=True)
            self.add_to_group(str(self._member_of_unenforced_silo.get_dn()),
                              self._unenforced_silo.dn,
                              'msDS-AuthNPolicySiloMembers',
                              expect_attr=False)

            cls._member_of_enforced_silo = self._get_creds(
                account_type=self.AccountType.COMPUTER,
                assigned_silo=self._enforced_silo,
                cached=True)
            self.add_to_group(str(self._member_of_enforced_silo.get_dn()),
                              self._enforced_silo.dn,
                              'msDS-AuthNPolicySiloMembers',
                              expect_attr=False)

            cls._member_of_enforced_silo_ntlm = self._get_creds(
                account_type=self.AccountType.USER,
                assigned_silo=self._enforced_silo,
                ntlm=True,
                cached=True)
            self.add_to_group(str(self._member_of_enforced_silo_ntlm.get_dn()),
                              self._enforced_silo.dn,
                              'msDS-AuthNPolicySiloMembers',
                              expect_attr=False)

            # Create a couple of multi‐valued string claims for testing claim
            # value comparisons.

            cls.claim0_attr = 'carLicense'
            cls.claim0_id = self.get_new_username()
            self.create_claim(cls.claim0_id,
                              enabled=True,
                              attribute=cls.claim0_attr,
                              single_valued=False,
                              source_type='AD',
                              for_classes=['computer', 'user'],
                              value_type=claims.CLAIM_TYPE_STRING)

            cls.claim1_attr = 'departmentNumber'
            cls.claim1_id = self.get_new_username()
            self.create_claim(cls.claim1_id,
                              enabled=True,
                              attribute=cls.claim1_attr,
                              single_valued=False,
                              source_type='AD',
                              for_classes=['computer', 'user'],
                              value_type=claims.CLAIM_TYPE_STRING)

            cls._setup = True

    # For debugging purposes. Prints out the SDDL representation of
    # authentication policy conditions set by the Windows GUI.
    def _print_authn_policy_sddl(self, policy_id):
        policy_dn = self.get_authn_policies_dn()
        policy_dn.add_child(f'CN={policy_id}')

        attrs = [
            'msDS-ComputerAllowedToAuthenticateTo',
            'msDS-ServiceAllowedToAuthenticateFrom',
            'msDS-ServiceAllowedToAuthenticateTo',
            'msDS-UserAllowedToAuthenticateFrom',
            'msDS-UserAllowedToAuthenticateTo',
        ]

        samdb = self.get_samdb()
        res = samdb.search(policy_dn, scope=ldb.SCOPE_BASE, attrs=attrs)
        self.assertEqual(1, len(res),
                         f'Authentication policy {policy_id} not found')
        result = res[0]

        def print_sddl(attr):
            sd = result.get(attr, idx=0)
            if sd is None:
                return

            sec_desc = ndr_unpack(security.descriptor, sd)
            print(f'{attr}: {sec_desc.as_sddl()}')

        for attr in attrs:
            print_sddl(attr)

    def sddl_array_from_sids(self, sids):
        def sddl_from_sid_entry(sid_entry):
            sid, _, _ = sid_entry
            return f'SID({sid})'

        return f"{{{', '.join(map(sddl_from_sid_entry, sids))}}}"

    def allow_if(self, condition):
        return f'O:SYD:(XA;;CR;;;WD;({condition}))'


@DynamicTestCase
class ConditionalAceTests(ConditionalAceBaseTests):
    @classmethod
    def setUpDynamicTestCases(cls):
        FILTER = env_get_var_value('FILTER', allow_missing=True)

        # These operators are arranged so that each operator precedes its own
        # affixes.
        op_names = OrderedDict([
            ('!=', 'does not equal'),
            ('!', 'not'),
            ('&&', 'and'),
            ('<=', 'is less than or equals'),
            ('<', 'is less than'),
            ('==', 'equals'),
            ('>=', 'exceeds or equals'),
            ('>', 'exceeds'),
            ('Not_Any_of', 'matches none of'),
            ('Any_of', 'matches any of'),
            ('Not_Contains', 'does not contain'),
            ('Contains', 'contains'),
            ('Not_Member_of_Any', 'the user belongs to none of'),
            ('Not_Device_Member_of_Any', 'the device belongs to none of'),  # TODO: no test for this yet
            ('Device_Member_of_Any', 'the device belongs to any of'),  # TODO: no test for this yet
            ('Not_Device_Member_of', 'the device does not belong to'),  # TODO: no test for this yet
            ('Device_Member_of', 'the device belongs to'),
            ('Not_Exists', 'there does not exist'),
            ('Exists', 'there exists'),
            ('Member_of_Any', 'the user belongs to any of'),
            ('Not_Member_of', 'the user does not belong to'),
            ('Member_of', 'the user belongs to'),
            ('||', 'or'),
        ])

        # This is a safety measure to ensure correct ordering of op_names
        keys = list(op_names.keys())
        for i in range(len(keys)):
            for j in range(i + 1, len(keys)):
                if keys[i] in keys[j]:
                    raise AssertionError((keys[i], keys[j]))

        for case in cls.pac_claim_cases:
            if len(case) == 3:
                pac_claims, expression, outcome = case
                claim_map = None
            elif len(case) == 4:
                pac_claims, expression, claim_map, outcome = case
            else:
                raise AssertionError(
                    f'found {len(case)} items in case, expected 3–4')

            expression_name = expression
            for op, op_name in op_names.items():
                expression_name = expression_name.replace(op, op_name)

            name = f'{pac_claims}_{expression_name}'

            if claim_map is not None:
                name += f'_{claim_map}'

            name = re.sub(r'\W+', '_', name)
            if len(name) > 150:
                name = f'{name[:125]}+{len(name) - 125}‐more'

            if FILTER and not re.search(FILTER, name):
                continue

            cls.generate_dynamic_test('test_pac_claim_cmp', name,
                                      pac_claims, expression, claim_map,
                                      outcome)

        for case in cls.claim_against_claim_cases:
            lhs, op, rhs, outcome = case
            op_name = op_names[op]

            name = f'{lhs}_{op_name}_{rhs}'

            name = re.sub(r'\W+', '_', name)
            if FILTER and not re.search(FILTER, name):
                continue

            cls.generate_dynamic_test('test_cmp', name,
                                      lhs, op, rhs, outcome)

        for case in cls.claim_against_literal_cases:
            lhs, op, rhs, outcome = case
            op_name = op_names[op]

            name = f'{lhs}_{op_name}_literal_{rhs}'

            name = re.sub(r'\W+', '_', name)
            if FILTER and not re.search(FILTER, name):
                continue

            cls.generate_dynamic_test('test_cmp', name,
                                      lhs, op, rhs, outcome, True)

    def test_allowed_from_member_of_each(self):
        # Create an authentication policy that allows accounts belonging to
        # both groups.
        policy = self.create_authn_policy(
            enforced=True,
            user_allowed_from=(
                f'O:SYD:(XA;;CR;;;WD;(Member_of '
                f'{{SID({self._group0_sid}), SID({self._group1_sid})}}))'),
        )

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that we get a policy error if the machine account does not
        # belong to both groups.
        armor_tgt = self.get_tgt(self._member_of_one_creds)
        self._get_tgt(client_creds, armor_tgt=armor_tgt,
                      expected_error=KDC_ERR_POLICY)

        # Otherwise, authentication should succeed.
        armor_tgt = self.get_tgt(self._member_of_both_creds)
        self._get_tgt(client_creds, armor_tgt=armor_tgt,
                      expected_error=0)

    def test_allowed_from_member_of_any(self):
        # Create an authentication policy that allows accounts belonging to
        # either group.
        policy = self.create_authn_policy(
            enforced=True,
            user_allowed_from=(
                f'O:SYD:(XA;;CR;;;WD;(Member_of_Any '
                f'{{SID({self._group0_sid}), SID({self._group1_sid})}}))'),
        )

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that we get a policy error if the machine account belongs to
        # neither group.
        armor_tgt = self.get_tgt(self._mach_creds)
        self._get_tgt(client_creds, armor_tgt=armor_tgt,
                      expected_error=KDC_ERR_POLICY)

        # Otherwise, authentication should succeed.
        armor_tgt = self.get_tgt(self._member_of_one_creds)
        self._get_tgt(client_creds, armor_tgt=armor_tgt,
                      expected_error=0)

    def test_allowed_from_not_member_of_each(self):
        # Create an authentication policy that allows accounts not belonging to
        # both groups.
        policy = self.create_authn_policy(
            enforced=True,
            user_allowed_from=(
                f'O:SYD:(XA;;CR;;;WD;(Not_Member_of '
                f'{{SID({self._group0_sid}), SID({self._group1_sid})}}))'),
        )

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that we get a policy error if the machine account belongs to
        # both groups.
        armor_tgt = self.get_tgt(self._member_of_both_creds)
        self._get_tgt(client_creds, armor_tgt=armor_tgt,
                      expected_error=KDC_ERR_POLICY)

        # Otherwise, authentication should succeed.
        armor_tgt = self.get_tgt(self._member_of_one_creds)
        self._get_tgt(client_creds, armor_tgt=armor_tgt,
                      expected_error=0)

    def test_allowed_from_not_member_of_any(self):
        # Create an authentication policy that allows accounts belonging to
        # neither group.
        policy = self.create_authn_policy(
            enforced=True,
            user_allowed_from=(
                f'O:SYD:(XA;;CR;;;WD;(Not_Member_of_Any '
                f'{{SID({self._group0_sid}), SID({self._group1_sid})}}))'),
        )

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that we get a policy error if the machine account belongs to one
        # of the groups.
        armor_tgt = self.get_tgt(self._member_of_one_creds)
        self._get_tgt(client_creds, armor_tgt=armor_tgt,
                      expected_error=KDC_ERR_POLICY)

        # Otherwise, authentication should succeed.
        armor_tgt = self.get_tgt(self._mach_creds)
        self._get_tgt(client_creds, armor_tgt=armor_tgt,
                      expected_error=0)

    def test_allowed_from_member_of_each_deny(self):
        # Create an authentication policy that denies accounts belonging to
        # both groups, and allows other accounts.
        policy = self.create_authn_policy(
            enforced=True,
            user_allowed_from=(
                f'O:SYD:(XD;;CR;;;WD;(Member_of '
                f'{{SID({self._group0_sid}), SID({self._group1_sid})}}))'
                f'(A;;CR;;;WD)'),
        )

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that we get a policy error if the machine account belongs to
        # both groups.
        armor_tgt = self.get_tgt(self._member_of_both_creds)
        self._get_tgt(client_creds, armor_tgt=armor_tgt,
                      expected_error=KDC_ERR_POLICY)

        # Otherwise, authentication should succeed.
        armor_tgt = self.get_tgt(self._member_of_one_creds)
        self._get_tgt(client_creds, armor_tgt=armor_tgt,
                      expected_error=0)

    def test_allowed_from_member_of_any_deny(self):
        # Create an authentication policy that denies accounts belonging to
        # either group, and allows other accounts.
        policy = self.create_authn_policy(
            enforced=True,
            user_allowed_from=(
                f'O:SYD:(XD;;CR;;;WD;(Member_of_Any '
                f'{{SID({self._group0_sid}), SID({self._group1_sid})}}))'
                f'(A;;CR;;;WD)'),
        )

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that we get a policy error if the machine account belongs to
        # either group.
        armor_tgt = self.get_tgt(self._member_of_one_creds)
        self._get_tgt(client_creds, armor_tgt=armor_tgt,
                      expected_error=KDC_ERR_POLICY)

        # Otherwise, authentication should succeed.
        armor_tgt = self.get_tgt(self._mach_creds)
        self._get_tgt(client_creds, armor_tgt=armor_tgt,
                      expected_error=0)

    def test_allowed_from_not_member_of_each_deny(self):
        # Create an authentication policy that denies accounts not belonging to
        # both groups, and allows other accounts.
        policy = self.create_authn_policy(
            enforced=True,
            user_allowed_from=(
                f'O:SYD:(XD;;CR;;;WD;(Not_Member_of '
                f'{{SID({self._group0_sid}), SID({self._group1_sid})}}))'
                f'(A;;CR;;;WD)'),
        )

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that we get a policy error if the machine account doesn’t belong
        # to both groups.
        armor_tgt = self.get_tgt(self._member_of_one_creds)
        self._get_tgt(client_creds, armor_tgt=armor_tgt,
                      expected_error=KDC_ERR_POLICY)

        # Otherwise, authentication should succeed.
        armor_tgt = self.get_tgt(self._member_of_both_creds)
        self._get_tgt(client_creds, armor_tgt=armor_tgt,
                      expected_error=0)

    def test_allowed_from_not_member_of_any_deny(self):
        # Create an authentication policy that denies accounts belonging to
        # neither group, and allows other accounts.
        policy = self.create_authn_policy(
            enforced=True,
            user_allowed_from=(
                f'O:SYD:(XD;;CR;;;WD;(Not_Member_of_Any '
                f'{{SID({self._group0_sid}), SID({self._group1_sid})}}))'
                f'(A;;CR;;;WD)'),
        )

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that we get a policy error if the machine account belongs to
        # neither group.
        armor_tgt = self.get_tgt(self._mach_creds)
        self._get_tgt(client_creds, armor_tgt=armor_tgt,
                      expected_error=KDC_ERR_POLICY)

        # Otherwise, authentication should succeed.
        armor_tgt = self.get_tgt(self._member_of_one_creds)
        self._get_tgt(client_creds, armor_tgt=armor_tgt,
                      expected_error=0)

    def test_allowed_from_unenforced_silo_equals(self):
        # Create an authentication policy that allows accounts belonging to the
        # unenforced silo.
        policy = self.create_authn_policy(
            enforced=True,
            user_allowed_from=(
                f'O:SYD:(XA;;CR;;;WD;'
                f'(@User.ad://ext/AuthenticationSilo == '
                f'"{self._unenforced_silo}"))'),
        )

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # As the silo is unenforced, the ‘ad://ext/AuthenticationSilo’ claim
        # will not be present in the TGT, and the ACE will never allow access.

        armor_tgt = self.get_tgt(self._mach_creds)
        self._get_tgt(client_creds, armor_tgt=armor_tgt,
                      expected_error=KDC_ERR_POLICY)

        armor_tgt = self.get_tgt(self._member_of_unenforced_silo)
        self._get_tgt(client_creds, armor_tgt=armor_tgt,
                      expected_error=KDC_ERR_POLICY)

        armor_tgt = self.get_tgt(self._member_of_enforced_silo)
        self._get_tgt(client_creds, armor_tgt=armor_tgt,
                      expected_error=KDC_ERR_POLICY)

    def test_allowed_from_enforced_silo_equals(self):
        # Create an authentication policy that allows accounts belonging to the
        # enforced silo.
        policy = self.create_authn_policy(
            enforced=True,
            user_allowed_from=(
                f'O:SYD:(XA;;CR;;;WD;'
                f'(@User.ad://ext/AuthenticationSilo == '
                f'"{self._enforced_silo}"))'),
        )

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that we get a policy error if the machine account does not
        # belong to the silo.
        armor_tgt = self.get_tgt(self._mach_creds)
        self._get_tgt(client_creds, armor_tgt=armor_tgt,
                      expected_error=KDC_ERR_POLICY)

        armor_tgt = self.get_tgt(self._member_of_unenforced_silo)
        self._get_tgt(client_creds, armor_tgt=armor_tgt,
                      expected_error=KDC_ERR_POLICY)

        # Otherwise, authentication should succeed.
        armor_tgt = self.get_tgt(self._member_of_enforced_silo)
        self._get_tgt(client_creds, armor_tgt=armor_tgt,
                      expected_error=0)

    def test_allowed_from_unenforced_silo_not_equals(self):
        # Create an authentication policy that allows accounts not belonging to
        # the unenforced silo.
        policy = self.create_authn_policy(
            enforced=True,
            user_allowed_from=(
                f'O:SYD:(XA;;CR;;;WD;'
                f'(@User.ad://ext/AuthenticationSilo != '
                f'"{self._unenforced_silo}"))'),
        )

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that authentication fails unless the account belongs to a silo
        # other than the unenforced silo.

        armor_tgt = self.get_tgt(self._mach_creds)
        self._get_tgt(client_creds, armor_tgt=armor_tgt,
                      expected_error=KDC_ERR_POLICY)

        armor_tgt = self.get_tgt(self._member_of_unenforced_silo)
        self._get_tgt(client_creds, armor_tgt=armor_tgt,
                      expected_error=KDC_ERR_POLICY)

        armor_tgt = self.get_tgt(self._member_of_enforced_silo)
        self._get_tgt(client_creds, armor_tgt=armor_tgt,
                      expected_error=0)

    def test_allowed_from_enforced_silo_not_equals(self):
        # Create an authentication policy that allows accounts not belonging to
        # the enforced silo.
        policy = self.create_authn_policy(
            enforced=True,
            user_allowed_from=(
                f'O:SYD:(XA;;CR;;;WD;'
                f'(@User.ad://ext/AuthenticationSilo != '
                f'"{self._enforced_silo}"))'),
        )

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that authentication always fails, as none of the machine
        # accounts belong to a silo that is not the enforced one. (The
        # unenforced silo doesn’t count, as it will never appear in a claim.)

        armor_tgt = self.get_tgt(self._mach_creds)
        self._get_tgt(client_creds, armor_tgt=armor_tgt,
                      expected_error=KDC_ERR_POLICY)

        armor_tgt = self.get_tgt(self._member_of_unenforced_silo)
        self._get_tgt(client_creds, armor_tgt=armor_tgt,
                      expected_error=KDC_ERR_POLICY)

        armor_tgt = self.get_tgt(self._member_of_enforced_silo)
        self._get_tgt(client_creds, armor_tgt=armor_tgt,
                      expected_error=KDC_ERR_POLICY)

    def test_allowed_from_unenforced_silo_equals_deny(self):
        # Create an authentication policy that denies accounts belonging to the
        # unenforced silo, and allows other accounts.
        policy = self.create_authn_policy(
            enforced=True,
            user_allowed_from=(
                f'O:SYD:(XD;;CR;;;WD;'
                f'(@User.ad://ext/AuthenticationSilo == '
                f'"{self._unenforced_silo}"))'
                f'(A;;CR;;;WD)'),
        )

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that authentication fails unless the account belongs to a silo
        # other than the unenforced silo.

        armor_tgt = self.get_tgt(self._mach_creds)
        self._get_tgt(client_creds, armor_tgt=armor_tgt,
                      expected_error=KDC_ERR_POLICY)

        armor_tgt = self.get_tgt(self._member_of_unenforced_silo)
        self._get_tgt(client_creds, armor_tgt=armor_tgt,
                      expected_error=KDC_ERR_POLICY)

        armor_tgt = self.get_tgt(self._member_of_enforced_silo)
        self._get_tgt(client_creds, armor_tgt=armor_tgt,
                      expected_error=0)

    def test_allowed_from_enforced_silo_equals_deny(self):
        # Create an authentication policy that denies accounts belonging to the
        # enforced silo, and allows other accounts.
        policy = self.create_authn_policy(
            enforced=True,
            user_allowed_from=(
                f'O:SYD:(XD;;CR;;;WD;'
                f'(@User.ad://ext/AuthenticationSilo == '
                f'"{self._enforced_silo}"))'
                f'(A;;CR;;;WD)'),
        )

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that authentication always fails, as none of the machine
        # accounts belong to a silo that is not the enforced one. (The
        # unenforced silo doesn’t count, as it will never appear in a claim.)

        armor_tgt = self.get_tgt(self._mach_creds)
        self._get_tgt(client_creds, armor_tgt=armor_tgt,
                      expected_error=KDC_ERR_POLICY)

        armor_tgt = self.get_tgt(self._member_of_unenforced_silo)
        self._get_tgt(client_creds, armor_tgt=armor_tgt,
                      expected_error=KDC_ERR_POLICY)

        armor_tgt = self.get_tgt(self._member_of_enforced_silo)
        self._get_tgt(client_creds, armor_tgt=armor_tgt,
                      expected_error=KDC_ERR_POLICY)

    def test_allowed_from_unenforced_silo_not_equals_deny(self):
        # Create an authentication policy that denies accounts not belonging to
        # the unenforced silo, and allows other accounts.
        policy = self.create_authn_policy(
            enforced=True,
            user_allowed_from=(
                f'O:SYD:(XD;;CR;;;WD;'
                f'(@User.ad://ext/AuthenticationSilo != '
                f'"{self._unenforced_silo}"))'
                f'(A;;CR;;;WD)'),
        )

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that authentication always fails, as the unenforced silo will
        # never appear in a claim.

        armor_tgt = self.get_tgt(self._mach_creds)
        self._get_tgt(client_creds, armor_tgt=armor_tgt,
                      expected_error=KDC_ERR_POLICY)

        armor_tgt = self.get_tgt(self._member_of_unenforced_silo)
        self._get_tgt(client_creds, armor_tgt=armor_tgt,
                      expected_error=KDC_ERR_POLICY)

        armor_tgt = self.get_tgt(self._member_of_enforced_silo)
        self._get_tgt(client_creds, armor_tgt=armor_tgt,
                      expected_error=KDC_ERR_POLICY)

    def test_allowed_from_enforced_silo_not_equals_deny(self):
        # Create an authentication policy that denies accounts not belonging to
        # the enforced silo, and allows other accounts.
        policy = self.create_authn_policy(
            enforced=True,
            user_allowed_from=(
                f'O:SYD:(XD;;CR;;;WD;'
                f'(@User.ad://ext/AuthenticationSilo != '
                f'"{self._enforced_silo}"))'
                f'(A;;CR;;;WD)'),
        )

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that authentication fails unless the account belongs to the
        # enforced silo.

        armor_tgt = self.get_tgt(self._mach_creds)
        self._get_tgt(client_creds, armor_tgt=armor_tgt,
                      expected_error=KDC_ERR_POLICY)

        armor_tgt = self.get_tgt(self._member_of_unenforced_silo)
        self._get_tgt(client_creds, armor_tgt=armor_tgt,
                      expected_error=KDC_ERR_POLICY)

        armor_tgt = self.get_tgt(self._member_of_enforced_silo)
        self._get_tgt(client_creds, armor_tgt=armor_tgt,
                      expected_error=0)

    def test_allowed_from_claim_equals_claim(self):
        # Create a couple of claim types.

        claim0_id = self.get_new_username()
        self.create_claim(claim0_id,
                          enabled=True,
                          attribute='carLicense',
                          single_valued=True,
                          source_type='AD',
                          for_classes=['computer'],
                          value_type=claims.CLAIM_TYPE_STRING)

        claim1_id = self.get_new_username()
        self.create_claim(claim1_id,
                          enabled=True,
                          attribute='comment',
                          single_valued=True,
                          source_type='AD',
                          for_classes=['computer'],
                          value_type=claims.CLAIM_TYPE_STRING)

        # Create an authentication policy that allows accounts having the two
        # claims be equal.
        policy = self.create_authn_policy(
            enforced=True,
            user_allowed_from=(
                f'O:SYD:(XA;;CR;;;WD;'
                f'(@User.{claim0_id} == @User.{claim1_id}))'),
        )

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        armor_tgt = self.get_tgt(self._mach_creds)
        self._get_tgt(client_creds, armor_tgt=armor_tgt,
                      expected_error=KDC_ERR_POLICY)

        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={
                'additional_details': (
                    ('carLicense', 'foo'),
                    ('comment', 'foo'),
                ),
            })
        armor_tgt = self.get_tgt(
            mach_creds,
            expect_client_claims=True,
            expected_client_claims={
                claim0_id: {
                    'source_type': claims.CLAIMS_SOURCE_TYPE_AD,
                    'type': claims.CLAIM_TYPE_STRING,
                    'values': ('foo',),
                },
                claim1_id: {
                    'source_type': claims.CLAIMS_SOURCE_TYPE_AD,
                    'type': claims.CLAIM_TYPE_STRING,
                    'values': ('foo',),
                },
            })
        self._get_tgt(client_creds, armor_tgt=armor_tgt,
                      expected_error=0)

    def test_allowed_to_client_equals(self):
        client_claim_attr = 'carLicense'
        client_claim_value = 'foo bar'
        client_claim_values = client_claim_value,

        client_claim_id = self.get_new_username()
        self.create_claim(client_claim_id,
                          enabled=True,
                          attribute=client_claim_attr,
                          single_valued=True,
                          source_type='AD',
                          for_classes=['user'],
                          value_type=claims.CLAIM_TYPE_STRING)

        # Create an authentication policy that allows authorization if the
        # client has a particular claim value.
        policy = self.create_authn_policy(
            enforced=True,
            computer_allowed_to=(
                f'O:SYD:(XA;;CR;;;WD;'
                f'((@User.{client_claim_id} == "{client_claim_value}")))'),
        )

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        armor_tgt = self.get_tgt(self._mach_creds)

        # Create a user account without the claim value.
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        tgt = self.get_tgt(client_creds)
        # Show that obtaining a service ticket is denied.
        self._tgs_req(
            tgt, KDC_ERR_POLICY, client_creds, target_creds,
            armor_tgt=armor_tgt,
            expect_edata=self.expect_padata_outer,
            # We aren’t particular about whether or not we get an NTSTATUS.
            expect_status=None,
            expected_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            check_patypes=False)

        # Create a user account with the claim value.
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER,
            opts={
                'additional_details': (
                    (client_claim_attr, client_claim_values),
                ),
            })
        tgt = self.get_tgt(
            client_creds,
            expect_client_claims=True,
            expected_client_claims={
                client_claim_id: {
                    'source_type': claims.CLAIMS_SOURCE_TYPE_AD,
                    'type': claims.CLAIM_TYPE_STRING,
                    'values': client_claim_values,
                },
            })
        # Show that obtaining a service ticket is allowed.
        self._tgs_req(tgt, 0, client_creds, target_creds,
                      armor_tgt=armor_tgt)

    def test_allowed_to_device_equals(self):
        device_claim_attr = 'carLicense'
        device_claim_value = 'bar'
        device_claim_values = device_claim_value,

        device_claim_id = self.get_new_username()
        self.create_claim(device_claim_id,
                          enabled=True,
                          attribute=device_claim_attr,
                          single_valued=True,
                          source_type='AD',
                          for_classes=['computer'],
                          value_type=claims.CLAIM_TYPE_STRING)

        # Create a user account.
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        tgt = self.get_tgt(client_creds)

        # Create an authentication policy that allows authorization if the
        # device has a particular claim value.
        policy = self.create_authn_policy(
            enforced=True,
            computer_allowed_to=(
                f'O:SYD:(XA;;CR;;;WD;'
                f'(@Device.{device_claim_id} == "{device_claim_value}"))'),
        )

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        armor_tgt = self.get_tgt(self._mach_creds)
        # Show that obtaining a service ticket is denied when the claim value
        # is not present.
        self._tgs_req(
            tgt, KDC_ERR_POLICY, client_creds, target_creds,
            armor_tgt=armor_tgt,
            expect_edata=self.expect_padata_outer,
            # We aren’t particular about whether or not we get an NTSTATUS.
            expect_status=None,
            expected_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            check_patypes=False)

        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={
                'additional_details': (
                    (device_claim_attr, device_claim_values),
                ),
            })
        armor_tgt = self.get_tgt(
            mach_creds,
            expect_client_claims=True,
            expected_client_claims={
                device_claim_id: {
                    'source_type': claims.CLAIMS_SOURCE_TYPE_AD,
                    'type': claims.CLAIM_TYPE_STRING,
                    'values': device_claim_values,
                },
            })
        # Show that obtaining a service ticket is allowed when the claim value
        # is present.
        self._tgs_req(tgt, 0, client_creds, target_creds,
                      armor_tgt=armor_tgt)

    claim_against_claim_cases = [
        # If either side is missing, the result is unknown.
        ((), '==', (), None),
        ((), '!=', (), None),
        ('a', '==', (), None),
        ((), '==', 'b', None),
        # Straightforward equality and inequality checks work.
        ('foo', '==', 'foo', True),
        ('foo', '==', 'bar', False),
        ('foo', '!=', 'foo', False),
        ('foo', '!=', 'bar', True),
        # We can perform less‐than and greater‐than operations.
        ('cat', '<', 'dog', True),
        ('cat', '<=', 'dog', True),
        ('cat', '>', 'dog', False),
        ('cat', '>=', 'dog', False),
        ('foo', '<=', 'foo', True),
        ('foo', '>=', 'foo', True),
        ('foo', '<', 'foo bar', True),
        ('foo bar', '>', 'foo', True),
        # String comparison is case‐sensitive.
        ('foo bar', '==', 'Foo BAR', True),
        ('ｆｏｏ ｂａｒ', '==', 'ＦＯＯ ＢＡＲ', True),
        ('ćàț', '==', 'ĆÀȚ', True),
        ('ḽ', '==', 'Ḽ', True),
        ('ⅸ', '==', 'Ⅸ', True),
        ('ꙭ', '==', 'Ꙭ', True),
        ('ⱦ', '==', 'Ⱦ', True),  # Lowercased variant added in Unicode 5.0.
        ('ԛԣ', '==', 'ԚԢ', True),  # All added in Unicode 5.1.
        ('foo', '<', 'ｆｏｏ', True),
        ('ćàș', '<', 'ĆÀȚ', True),
        ('cat', '<', 'ćàț', True),
        # This is done by converting to UPPER CASE. Hence, both ‘A’ (U+41) and
        # ‘a’ (U+61) compare less than ‘_’ (U+5F).
        ('A', '<', '_', True),
        ('a', '<', '_', True),
        # But not all uppercased/lowercased pairs are considered to be equal in
        # this way.
        ('ß', '<', 'ẞ', True),
        ('ß', '>', 'SS', True),
        ('ⳬ', '>', 'Ⳬ', True),  # Added in Unicode 5.2.
        ('ʞ', '<', 'Ʞ', True),  # Uppercased variant added in Unicode 6.0.
        ('ʞ', '<', 'ʟ', True),  # U+029E < U+029F < U+A7B0 (upper variant, Ʞ)
        ('ꞧ', '>', 'Ꞧ', True),  # Added in Unicode 6.0.
        ('ɜ', '<', 'Ɜ', True),  # Uppercased variant added in Unicode 7.0.
        #
        # Strings are compared as UTF‐16 code units, rather than as Unicode
        # codepoints. So while you might expect ‘𐀀’ (U+10000) to compare
        # greater than ‘豈’ (U+F900), it is actually considered to be the
        # *smaller* of the pair. That is because it is encoded as a sequence of
        # two code units, 0xd800 and 0xdc00, which combination compares less
        # than the single code unit 0xf900.
        ('ퟻ', '<', '𐀀', True),
        ('𐀀', '<', '豈', True),
        ('ퟻ', '<', '豈', True),
        # Composites can be compared.
        (('foo', 'bar'), '==', ('foo', 'bar'), True),
        (('foo', 'bar'), '==', ('foo', 'baz'), False),
        # The individual components don’t have to match in case.
        (('foo', 'bar'), '==', ('FOO', 'BAR'), True),
        # Nor must they match in order.
        (('foo', 'bar'), '==', ('bar', 'foo'), True),
        # Composites of different lengths compare unequal.
        (('foo', 'bar'), '!=', 'foo', True),
        (('foo', 'bar'), '!=', ('foo', 'bar', 'baz'), True),
        # But composites don’t have a defined ordering, and aren’t considered
        # greater or lesser than one another.
        (('foo', 'bar'), '<', ('foo', 'bar'), None),
        (('foo', 'bar'), '<=', ('foo', 'bar'), None),
        (('foo', 'bar'), '>', ('foo', 'bar', 'baz'), None),
        (('foo', 'bar'), '>=', ('foo', 'bar', 'baz'), None),
        # We can test for containment.
        (('foo', 'bar'), 'Contains', ('FOO'), True),
        (('foo', 'bar'), 'Contains', ('foo', 'bar'), True),
        (('foo', 'bar'), 'Not_Contains', ('foo', 'bar'), False),
        (('foo', 'bar'), 'Contains', ('foo', 'bar', 'baz'), False),
        (('foo', 'bar'), 'Not_Contains', ('foo', 'bar', 'baz'), True),
        # We can test whether the operands have any elements in common.
        ('foo', 'Any_of', 'foo', True),
        (('foo', 'bar'), 'Any_of', 'BAR', True),
        (('foo', 'bar'), 'Any_of', 'baz', False),
        (('foo', 'bar'), 'Not_Any_of', 'baz', True),
        (('foo', 'bar'), 'Any_of', ('bar', 'baz'), True),
        (('foo', 'bar'), 'Not_Any_of', ('bar', 'baz'), False),
    ]

    claim_against_literal_cases = [
        # String comparisons also work against literals.
        ('foo bar', '==', '"foo bar"', True),
        # Composites can be compared with literals.
        ((), '==', '{{}}', None),
        ('foo', '!=', '{{}}', True),
        ('bar', '==', '{{"bar"}}', True),
        (('apple', 'banana'), '==', '{{"APPLE", "BANANA"}}', True),
        (('apple', 'banana'), '==', '{{"BANANA", "APPLE"}}', True),
        (('apple', 'banana'), '==', '{{"apple", "banana", "apple"}}', False),
        # We can test for containment.
        ((), 'Contains', '{{}}', False),
        ((), 'Not_Contains', '{{}}', True),
        ((), 'Contains', '{{"foo"}}', None),
        ((), 'Not_Contains', '{{"foo", "bar"}}', None),
        ('foo', 'Contains', '{{}}', False),
        ('bar', 'Contains', '{{"bar"}}', True),
        (('foo', 'bar'), 'Contains', '{{"foo", "bar"}}', True),
        (('foo', 'bar'), 'Contains', '{{"foo", "bar", "baz"}}', False),
        # The right‐hand side of Contains or Not_Contains does not have to be a
        # composite.
        ('foo', 'Contains', '"foo"', True),
        (('foo', 'bar'), 'Not_Contains', '"foo"', False),
        # It’s fine if the right‐hand side contains duplicate elements.
        (('foo', 'bar'), 'Contains', '{{"foo", "bar", "bar"}}', True),
        # We can test whether the operands have any elements in common.
        ((), 'Any_of', '{{}}', None),
        ((), 'Not_Any_of', '{{}}', None),
        ('foo', 'Any_of', '{{}}', False),
        ('foo', 'Not_Any_of', '{{}}', True),
        ('bar', 'Any_of', '{{"bar"}}', True),
        (('foo', 'bar'), 'Any_of', '{{"bar", "baz"}}', True),
        (('foo', 'bar'), 'Any_of', '{{"baz"}}', False),
        # The right‐hand side of Any_of or Not_Any_of must be a composite.
        ('foo', 'Any_of', '"foo"', None),
        (('foo', 'bar'), 'Not_Any_of', '"baz"', None),
        # A string won’t compare equal to a numeric literal.
        ('42', '==', '"42"', True),
        ('42', '==', '42', None),
        # Nor can composites that mismatch in type be compared.
        (('123', '456'), '==', '{{"123", "456"}}', True),
        (('654', '321'), '==', '{{654, 321}}', None),
        (('foo', 'bar'), 'Contains', '{{1, 2, 3}}', None),
    ]

    def _test_cmp_with_args(self, lhs, op, rhs, outcome, rhs_is_literal=False):
        # Construct a conditional ACE expression that evaluates to True if the
        # two claim values are equal.
        if rhs_is_literal:
            self.assertIsInstance(rhs, str)
            rhs = rhs.format(self=self)
            expression = f'(@User.{self.claim0_id} {op} {rhs})'
        else:
            expression = f'(@User.{self.claim0_id} {op} @User.{self.claim1_id})'

        # Create an authentication policy that will allow authentication when
        # the expression is true, and a second that will deny authentication in
        # the same circumstance. By observing the results of authenticating
        # against each of these policies in turn, we can determine whether the
        # expression evaluates to a True, False, or Unknown value.

        allowed_sddl = f'O:SYD:(XA;;CR;;;WD;{expression})'
        denied_sddl = f'O:SYD:(XD;;CR;;;WD;{expression})(A;;CR;;;WD)'

        allowed_policy = self.create_authn_policy(
            enforced=True,
            user_allowed_from=allowed_sddl)
        denied_policy = self.create_authn_policy(
            enforced=True,
            user_allowed_from=denied_sddl)

        # Create a user account assigned to each policy.
        allowed_creds = self._get_creds(account_type=self.AccountType.USER,
                                        assigned_policy=allowed_policy)
        denied_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=denied_policy)

        additional_details = ()
        if lhs:
            additional_details += ((self.claim0_attr, lhs),)
        if rhs and not rhs_is_literal:
            additional_details += ((self.claim1_attr, rhs),)

        # Create a computer account with the provided attribute values.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'additional_details': additional_details})

        def expected_values(val):
            if isinstance(val, (str, bytes)):
                return val,

            return val

        expected_client_claims = {}
        if lhs:
            expected_client_claims[self.claim0_id] = {
                'source_type': claims.CLAIMS_SOURCE_TYPE_AD,
                'type': claims.CLAIM_TYPE_STRING,
                'values': expected_values(lhs),
            }
        if rhs and not rhs_is_literal:
            expected_client_claims[self.claim1_id] = {
                'source_type': claims.CLAIMS_SOURCE_TYPE_AD,
                'type': claims.CLAIM_TYPE_STRING,
                'values': expected_values(rhs),
            }

        # Fetch the computer account’s TGT, and ensure it contains the claims.
        armor_tgt = self.get_tgt(
            mach_creds,
            expect_client_claims=bool(expected_client_claims) or None,
            expected_client_claims=expected_client_claims)

        # The first or the second authentication request is expected to succeed
        # if the outcome is True or False, respectively. An Unknown outcome,
        # represented by None, will result in a policy error in either case.
        allowed_error = 0 if outcome is True else KDC_ERR_POLICY
        denied_error = 0 if outcome is False else KDC_ERR_POLICY

        # Attempt to authenticate and ensure that we observe the expected
        # results.
        self._get_tgt(allowed_creds, armor_tgt=armor_tgt,
                      expected_error=allowed_error)
        self._get_tgt(denied_creds, armor_tgt=armor_tgt,
                      expected_error=denied_error)

    pac_claim_cases = [
        # Test a very simple expression with various claims.
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{non_empty_string}', claims.CLAIM_TYPE_STRING, ['foo bar']),
            ]),
        ], '{non_empty_string}', True),
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{zero_uint}', claims.CLAIM_TYPE_UINT64, [0]),
            ]),
        ], '{zero_uint}', False),
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{nonzero_uint}', claims.CLAIM_TYPE_UINT64, [1]),
            ]),
        ], '{nonzero_uint}', True),
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{zero_uints}', claims.CLAIM_TYPE_UINT64, [0, 0]),
            ]),
        ], '{zero_uints}', KDC_ERR_GENERIC),
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{zero_and_one_uint}', claims.CLAIM_TYPE_UINT64, [0, 1]),
            ]),
        ], '{zero_and_one_uint}', True),
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{one_and_zero_uint}', claims.CLAIM_TYPE_UINT64, [1, 0]),
            ]),
        ], '{one_and_zero_uint}', True),
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{zero_int}', claims.CLAIM_TYPE_INT64, [0]),
            ]),
        ], '{zero_int}', False),
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{nonzero_int}', claims.CLAIM_TYPE_INT64, [1]),
            ]),
        ], '{nonzero_int}', True),
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{zero_ints}', claims.CLAIM_TYPE_INT64, [0, 0]),
            ]),
        ], '{zero_ints}', KDC_ERR_GENERIC),
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{zero_and_one_int}', claims.CLAIM_TYPE_INT64, [0, 1]),
            ]),
        ], '{zero_and_one_int}', True),
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{one_and_zero_int}', claims.CLAIM_TYPE_INT64, [1, 0]),
            ]),
        ], '{one_and_zero_int}', True),
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{false_boolean}', claims.CLAIM_TYPE_BOOLEAN, [0]),
            ]),
        ], '{false_boolean}', False),
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{true_boolean}', claims.CLAIM_TYPE_BOOLEAN, [1]),
            ]),
        ], '{true_boolean}', True),
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{false_booleans}', claims.CLAIM_TYPE_BOOLEAN, [0, 0]),
            ]),
        ], '{false_booleans}', KDC_ERR_GENERIC),
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{false_and_true_boolean}', claims.CLAIM_TYPE_BOOLEAN, [0, 1]),
            ]),
        ], '{false_and_true_boolean}', True),
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{true_and_false_boolean}', claims.CLAIM_TYPE_BOOLEAN, [1, 0]),
            ]),
        ], '{true_and_false_boolean}', True),
        # Test a basic comparison against a literal.
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{a}', claims.CLAIM_TYPE_STRING, ['foo bar']),
            ]),
        ], '{a} == "foo bar"', True),
        # Claims can be compared against one another.
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{a}', claims.CLAIM_TYPE_STRING, ['foo bar']),
                ('{b}', claims.CLAIM_TYPE_STRING, ['FOO BAR']),
            ]),
        ], '{a} == {b}', True),
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{b}', claims.CLAIM_TYPE_STRING, ['FOO', 'BAR', 'BAZ']),
                ('{a}', claims.CLAIM_TYPE_STRING, ['foo', 'bar', 'baz']),
            ]),
        ], '{a} != {b}', False),
        # Certificate claims are also valid.
        ([
            (claims.CLAIMS_SOURCE_TYPE_CERTIFICATE, [
                ('{a}', claims.CLAIM_TYPE_STRING, ['foo']),
            ]),
        ], '{a} == "foo"', True),
        # Other claim source types are ignored.
        ([
            (0, [
                ('{a}', claims.CLAIM_TYPE_STRING, ['foo']),
            ]),
        ], '{a} == "foo"', None),
        ([
            (3, [
                ('{a}', claims.CLAIM_TYPE_STRING, ['foo']),
            ]),
        ], '{a} == "foo"', None),
        # If multiple claims have the same ID, the *last* one takes precedence.
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{a}', claims.CLAIM_TYPE_STRING, ['this is not the value…']),
                ('{a}', claims.CLAIM_TYPE_STRING, ['…nor is this…']),
            ]),
            (claims.CLAIMS_SOURCE_TYPE_CERTIFICATE, [
                ('{a}', claims.CLAIM_TYPE_STRING, ['…and this isn’t either.']),
            ]),
            (claims.CLAIMS_SOURCE_TYPE_CERTIFICATE, [
                ('{a}', claims.CLAIM_TYPE_STRING, ['here’s the actual value!']),
            ]),
            (3, [
                ('{a}', claims.CLAIM_TYPE_STRING, ['this is a red herring.']),
            ]),
        ], '{a} == "here’s the actual value!"', True),
        # Claim values can be empty.
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{empty_claim_string}', claims.CLAIM_TYPE_STRING, []),
            ]),
        ], '{empty_claim_string} != "foo bar"', None),
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{empty_claim_boolean}', claims.CLAIM_TYPE_BOOLEAN, []),
            ]),
        ], 'Exists {empty_claim_boolean}', None),
        # Test unsigned integer equality.
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{a}', claims.CLAIM_TYPE_UINT64, [42]),
            ]),
        ], '{a} == 42', True),
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{a}', claims.CLAIM_TYPE_UINT64, [0]),
            ]),
        ], '{a} == 3', False),
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{a}', claims.CLAIM_TYPE_UINT64, [1, 2, 3]),
            ]),
        ], '{a} == {{1, 2, 3}}', True),
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{a}', claims.CLAIM_TYPE_UINT64, [4, 5, 6]),
            ]),
        ], '{a} != {{1, 2, 3}}', True),
        # Test unsigned integer comparison. Ensure we don’t run into any
        # integer overflow issues.
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{a}', claims.CLAIM_TYPE_UINT64, [1 << 32]),
            ]),
        ], '{a} > 0', True),
        # Test signed integer comparisons.
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{a}', claims.CLAIM_TYPE_INT64, [42]),
            ]),
        ], '{a} == 42', True),
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{a}', claims.CLAIM_TYPE_INT64, [42 << 32]),
            ]),
        ], f'{{a}} == {42 << 32}', True),
        # Test boolean claims. Be careful! Windows will *crash* if you send it
        # claims that aren’t real booleans (not 0 or 1). I doubt Microsoft will
        # consider this a security issue though.
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{a}', claims.CLAIM_TYPE_BOOLEAN, [2]),
                ('{b}', claims.CLAIM_TYPE_BOOLEAN, [3]),
            ]),
        ], '{a} == {b}', (None, CRASHES_WINDOWS)),
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{a}', claims.CLAIM_TYPE_BOOLEAN, [1]),
                ('{b}', claims.CLAIM_TYPE_BOOLEAN, [1]),
            ]),
        ], '{a} == {b}', True),
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{a}', claims.CLAIM_TYPE_BOOLEAN, [1]),
            ]),
        ], '{a} == 42', None),
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{a}', claims.CLAIM_TYPE_BOOLEAN, [1]),
                ('{b}', claims.CLAIM_TYPE_BOOLEAN, [1]),
            ]),
        ], '{a} && {b}', True),
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{a}', claims.CLAIM_TYPE_BOOLEAN, [0]),
                ('{b}', claims.CLAIM_TYPE_BOOLEAN, [1]),
            ]),
        ], '{a} && {b}', False),
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{a}', claims.CLAIM_TYPE_BOOLEAN, [0]),
                ('{b}', claims.CLAIM_TYPE_BOOLEAN, [0]),
            ]),
        ], '{a} && {b}', False),
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{a}', claims.CLAIM_TYPE_BOOLEAN, [1]),
                ('{b}', claims.CLAIM_TYPE_BOOLEAN, [1]),
            ]),
        ], '{a} || {b}', True),
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{a}', claims.CLAIM_TYPE_BOOLEAN, [1]),
                ('{b}', claims.CLAIM_TYPE_BOOLEAN, [0]),
            ]),
        ], '{a} || {b}', True),
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{a}', claims.CLAIM_TYPE_BOOLEAN, [0]),
                ('{b}', claims.CLAIM_TYPE_BOOLEAN, [0]),
            ]),
        ], '{a} || {b}', False),
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{a}', claims.CLAIM_TYPE_BOOLEAN, [0]),
            ]),
        ], '!({a})', True),
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{a}', claims.CLAIM_TYPE_BOOLEAN, [0]),
            ]),
        ], '!(!(!(!({a}))))', False),
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{a}', claims.CLAIM_TYPE_BOOLEAN, [0]),
            ]),
        ], '!({a} && {a})', True),
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{a}', claims.CLAIM_TYPE_BOOLEAN, [1]),
                ('{b}', claims.CLAIM_TYPE_BOOLEAN, [0]),
            ]),
        ], '{a} && !({b} || {b})', True),
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{a}', claims.CLAIM_TYPE_BOOLEAN, [0]),
            ]),
        ], '!({a}) || !({a})', True),
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{a}', claims.CLAIM_TYPE_BOOLEAN, [1]),
                ('{b}', claims.CLAIM_TYPE_BOOLEAN, [0]),
            ]),
        ], '{a} && !({b})', None),
        # Expressions containing the ‘not’ operator are occasionally evaluated
        # inconsistently, as evidenced here. ‘a || !a’ evaluates to ‘unknown’…
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{a}', claims.CLAIM_TYPE_BOOLEAN, [1]),
            ]),
        ], '{a} || !({a})', None),
        # …but ‘!a || a’ — the same expression, just with the operands switched
        # round — evaluates to ‘true’.
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{a}', claims.CLAIM_TYPE_BOOLEAN, [1]),
            ]),
        ], '!({a}) || {a}', True),
        # This inconsistency is not observed with other boolean expressions,
        # such as ‘a || a’.
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{a}', claims.CLAIM_TYPE_BOOLEAN, [1]),
            ]),
        ], '{a} || ({a} || {a})', True),
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{b}', claims.CLAIM_TYPE_BOOLEAN, [1]),
            ]),
        ], '({b} || {b}) || {b}', True),
        # Test a very large claim. Much larger than this, and
        # conditional_ace_encode_binary() will refuse to encode the conditions.
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{large_claim}', claims.CLAIM_TYPE_STRING, ['z' * 4900]),
            ]),
        ], f'{{large_claim}} == "{"z" * 4900}"', True),
        # Test an even larger claim. Windows does not appear to like receiving
        # a claim this large.
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{larger_claim}', claims.CLAIM_TYPE_STRING, ['z' * 100000]),
            ]),
        ], '{larger_claim} > "z"', (True, CRASHES_WINDOWS)),
        # Test a great number of claims. Windows does not appear to like
        # receiving this many claims.
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{many_claims}', claims.CLAIM_TYPE_UINT64,
                 list(range(0, 100000))),
            ]),
        ], '{many_claims} Any_of "99999"', (True, CRASHES_WINDOWS)),
        # Test a claim with a very long name. Much larger than this, and
        # conditional_ace_encode_binary() will refuse to encode the conditions.
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{long_name}', claims.CLAIM_TYPE_STRING, ['a']),
            ]),
        ], '{long_name} == "a"', {'long_name': 'z' * 4900}, True),
        # Test attribute name escaping.
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{escaped_claim}', claims.CLAIM_TYPE_STRING, ['claim value']),
            ]),
        ], '{escaped_claim} == "claim value"',
           {'escaped_claim': '(:foo:! /&/ :bar:!)'}, True),
        # Test a claim whose name consists entirely of dots.
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{dotty_claim}', claims.CLAIM_TYPE_STRING, ['a']),
            ]),
        ], '{dotty_claim} == "a"', {'dotty_claim': '...'}, True),
        # Test a claim whose name consists of the first thousand non‐zero
        # Unicode codepoints.
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{1000_unicode}', claims.CLAIM_TYPE_STRING, ['a']),
            ]),
        ], '{1000_unicode} == "a"',
           {'1000_unicode': ''.join(map(chr, range(1, 1001)))}, True),
        # Test a claim whose name consists of some higher Unicode codepoints,
        # including non‐BMP ones.
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{higher_unicode}', claims.CLAIM_TYPE_STRING, ['a']),
            ]),
        ], '{higher_unicode} == "a"',
           {'higher_unicode': ''.join(map(chr, range(0xfe00, 0x10800)))}, True),
        # Duplicate claim values are not allowed…
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{a}', claims.CLAIM_TYPE_INT64, [42, 42, 42]),
            ]),
        ], '{a} == {a}', KDC_ERR_GENERIC),
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{a}', claims.CLAIM_TYPE_UINT64, [42, 42]),
            ]),
        ], '{a} == {a}', KDC_ERR_GENERIC),
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{a}', claims.CLAIM_TYPE_STRING, ['foo', 'foo']),
            ]),
        ], '{a} == {a}', KDC_ERR_GENERIC),
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{a}', claims.CLAIM_TYPE_STRING, ['FOO', 'foo']),
            ]),
        ], '{a} == {a}', KDC_ERR_GENERIC),
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{a}', claims.CLAIM_TYPE_BOOLEAN, [0, 0]),
            ]),
        ], '{a} == {a}', KDC_ERR_GENERIC),
        # …but it’s OK if duplicate values are spread across multiple claim
        # entries.
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{dup}', claims.CLAIM_TYPE_STRING, ['foo']),
                ('{dup}', claims.CLAIM_TYPE_STRING, ['foo']),
            ]),
            (claims.CLAIMS_SOURCE_TYPE_CERTIFICATE, [
                ('{dup}', claims.CLAIM_TYPE_UINT64, [42]),
                ('{dup}', claims.CLAIM_TYPE_UINT64, [42]),
            ]),
            (claims.CLAIMS_SOURCE_TYPE_CERTIFICATE, [
                ('{dup}', claims.CLAIM_TYPE_STRING, ['foo']),
                ('{dup}', claims.CLAIM_TYPE_STRING, ['foo']),
                ('{dup}', claims.CLAIM_TYPE_STRING, ['foo', 'bar']),
                ('{dup}', claims.CLAIM_TYPE_STRING, ['foo', 'bar']),
            ]),
        ], '{dup} == {dup}', True),
        # Test invalid claim types. Be careful! Windows will *crash* if you
        # send it invalid claim types. I doubt Microsoft will consider this a
        # security issue though.
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{invalid_sid}', 5, []),
            ]),
        ], '{invalid_sid} == {invalid_sid}', (None, CRASHES_WINDOWS)),
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{invalid_octet_string}', 16, []),
            ]),
        ], '{invalid_octet_string} == {invalid_octet_string}', (None, CRASHES_WINDOWS)),
        # Sending an empty string will crash Windows.
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{empty_string}', claims.CLAIM_TYPE_STRING, ['']),
            ]),
        ], '{empty_string}', (None, CRASHES_WINDOWS)),
        # But sending empty arrays is OK.
        ([
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                ('{empty_array}', claims.CLAIM_TYPE_INT64, []),
                ('{empty_array}', claims.CLAIM_TYPE_UINT64, []),
                ('{empty_array}', claims.CLAIM_TYPE_BOOLEAN, []),
                ('{empty_array}', claims.CLAIM_TYPE_STRING, []),
            ]),
        ], '{empty_array}', None),
    ]

    def _test_pac_claim_cmp_with_args(self,
                                      pac_claims,
                                      expression,
                                      claim_map,
                                      outcome):
        self.assertIsInstance(expression, str)

        try:
            outcome, crashes_windows = outcome
            self.assertIs(crashes_windows, CRASHES_WINDOWS)
            if not self.crash_windows:
                self.skipTest('test crashes Windows servers')
        except TypeError:
            self.assertIsNot(outcome, CRASHES_WINDOWS)

        if claim_map is None:
            claim_map = {}

        claim_ids = {}

        def get_claim_id(claim_name):
            claim = claim_ids.get(claim_name)
            if claim is None:
                claim = claim_map.pop(claim_name, None)
                if claim is None:
                    claim = self.get_new_username()

                claim_ids[claim_name] = claim

            return claim

        def formatted_claim_expression(expr):
            formatter = Formatter()
            result = []

            for literal_text, field_name, format_spec, conversion in (
                    formatter.parse(expr)):
                self.assertFalse(format_spec,
                                 f'format specifier ({format_spec}) should '
                                 f'not be specified')
                self.assertFalse(conversion,
                                 f'conversion ({conversion}) should not be '
                                 'specified')

                result.append(literal_text)

                if field_name is not None:
                    self.assertTrue(field_name,
                                    'a field name should be specified')

                    claim_id = get_claim_id(field_name)
                    claim_id = escaped_claim_id(claim_id)
                    result.append(f'@User.{claim_id}')

            return ''.join(result)

        # Construct the conditional ACE expression.
        expression = formatted_claim_expression(expression)

        self.assertFalse(claim_map, 'unused claim mapping(s) remain')

        # Create an authentication policy that will allow authentication when
        # the expression is true, and a second that will deny authentication in
        # the same circumstance. By observing the results of authenticating
        # against each of these policies in turn, we can determine whether the
        # expression evaluates to a True, False, or Unknown value.

        allowed_sddl = f'O:SYD:(XA;;CR;;;WD;({expression}))'
        denied_sddl = f'O:SYD:(XD;;CR;;;WD;({expression}))(A;;CR;;;WD)'

        allowed_policy = self.create_authn_policy(
            enforced=True,
            user_allowed_from=allowed_sddl)
        denied_policy = self.create_authn_policy(
            enforced=True,
            user_allowed_from=denied_sddl)

        # Create a user account assigned to each policy.
        allowed_creds = self._get_creds(account_type=self.AccountType.USER,
                                        assigned_policy=allowed_policy)
        denied_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=denied_policy)

        # Create a computer account.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)

        def expected_values(val):
            if isinstance(val, (str, bytes)):
                return val,

            return val

        # Fetch the computer account’s TGT.
        armor_tgt = self.get_tgt(mach_creds)

        if pac_claims:
            # Replace the claims in the PAC with our own.
            armor_tgt = self.modified_ticket(
                armor_tgt,
                modify_pac_fn=partial(self.set_pac_claims,
                                      client_claims=pac_claims,
                                      claim_ids=claim_ids),
                checksum_keys=self.get_krbtgt_checksum_key())

        # The first or the second authentication request is expected to succeed
        # if the outcome is True or False, respectively. An Unknown outcome,
        # represented by None, will result in a policy error in either case.
        if outcome is True:
            allowed_error, denied_error = 0, KDC_ERR_POLICY
        elif outcome is False:
            allowed_error, denied_error = KDC_ERR_POLICY, 0
        elif outcome is None:
            allowed_error, denied_error = KDC_ERR_POLICY, KDC_ERR_POLICY
        else:
            allowed_error, denied_error = outcome, outcome

        # Attempt to authenticate and ensure that we observe the expected
        # results.
        self._get_tgt(allowed_creds, armor_tgt=armor_tgt,
                      expected_error=allowed_error)
        self._get_tgt(denied_creds, armor_tgt=armor_tgt,
                      expected_error=denied_error)

    def test_rbcd_without_aa_asserted_identity(self):
        service_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
        }

        self._rbcd(f'Member_of SID({self.aa_asserted_identity})',
                   service_sids=service_sids,
                   code=KDC_ERR_BADOPTION,
                   status=ntstatus.NT_STATUS_UNSUCCESSFUL,
                   edata=self.expect_padata_outer)

        self._rbcd(target_policy=f'Member_of SID({self.aa_asserted_identity})',
                   service_sids=service_sids,
                   code=KDC_ERR_POLICY,
                   status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
                   event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
                   reason=AuditReason.ACCESS_DENIED,
                   edata=self.expect_padata_outer)

    def test_rbcd_with_aa_asserted_identity(self):
        service_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            (self.aa_asserted_identity, SidType.EXTRA_SID, self.default_attrs),
        }

        expected_groups = service_sids | {
            (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, self.default_attrs),
        }

        self._rbcd(f'Member_of SID({self.aa_asserted_identity})',
                   service_sids=service_sids,
                   expected_groups=expected_groups)

        self._rbcd(target_policy=f'Member_of SID({self.aa_asserted_identity})',
                   service_sids=service_sids,
                   expected_groups=expected_groups)

    def test_rbcd_without_service_asserted_identity(self):
        service_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
        }

        self._rbcd(f'Member_of SID({self.service_asserted_identity})',
                   service_sids=service_sids,
                   code=KDC_ERR_BADOPTION,
                   status=ntstatus.NT_STATUS_UNSUCCESSFUL,
                   edata=self.expect_padata_outer)

        self._rbcd(target_policy=f'Member_of SID({self.service_asserted_identity})',
                   service_sids=service_sids,
                   code=KDC_ERR_POLICY,
                   status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
                   event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
                   reason=AuditReason.ACCESS_DENIED,
                   edata=self.expect_padata_outer)

    def test_rbcd_with_service_asserted_identity(self):
        service_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            (self.service_asserted_identity, SidType.EXTRA_SID, self.default_attrs),
        }

        expected_groups = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            # The Application Authority Asserted Identity SID has replaced the
            # Service Asserted Identity SID.
            (self.aa_asserted_identity, SidType.EXTRA_SID, self.default_attrs),
            (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, self.default_attrs),
        }

        self._rbcd(f'Member_of SID({self.service_asserted_identity})',
                   service_sids=service_sids,
                   expected_groups=expected_groups)

        self._rbcd(target_policy=f'Member_of SID({self.service_asserted_identity})',
                   service_sids=service_sids,
                   expected_groups=expected_groups)

    def test_rbcd_without_claims_valid(self):
        service_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
        }

        self._rbcd(f'Member_of SID({security.SID_CLAIMS_VALID})',
                   service_sids=service_sids,
                   code=KDC_ERR_BADOPTION,
                   status=ntstatus.NT_STATUS_UNSUCCESSFUL,
                   edata=self.expect_padata_outer)

        self._rbcd(target_policy=f'Member_of SID({security.SID_CLAIMS_VALID})',
                   service_sids=service_sids,
                   code=KDC_ERR_POLICY,
                   status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
                   event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
                   reason=AuditReason.ACCESS_DENIED,
                   edata=self.expect_padata_outer)

    def test_rbcd_with_claims_valid(self):
        service_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, self.default_attrs),
        }

        expected_groups = service_sids | {
            (self.aa_asserted_identity, SidType.EXTRA_SID, self.default_attrs),
        }

        self._rbcd(f'Member_of SID({security.SID_CLAIMS_VALID})',
                   service_sids=service_sids,
                   expected_groups=expected_groups)

        self._rbcd(target_policy=f'Member_of SID({security.SID_CLAIMS_VALID})',
                   service_sids=service_sids,
                   expected_groups=expected_groups)

    def test_rbcd_without_compounded_authentication(self):
        service_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
        }

        self._rbcd(f'Member_of SID({security.SID_COMPOUNDED_AUTHENTICATION})',
                   service_sids=service_sids,
                   code=KDC_ERR_BADOPTION,
                   status=ntstatus.NT_STATUS_UNSUCCESSFUL,
                   edata=self.expect_padata_outer)

        self._rbcd(target_policy=f'Member_of SID({security.SID_COMPOUNDED_AUTHENTICATION})',
                   service_sids=service_sids,
                   code=KDC_ERR_POLICY,
                   status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
                   event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
                   reason=AuditReason.ACCESS_DENIED,
                   edata=self.expect_padata_outer)

    def test_rbcd_with_compounded_authentication(self):
        service_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            (security.SID_COMPOUNDED_AUTHENTICATION, SidType.EXTRA_SID, self.default_attrs),
        }

        expected_groups = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            (self.aa_asserted_identity, SidType.EXTRA_SID, self.default_attrs),
            (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, self.default_attrs),
        }

        self._rbcd(f'Member_of SID({security.SID_COMPOUNDED_AUTHENTICATION})',
                   service_sids=service_sids,
                   expected_groups=expected_groups)

        self._rbcd(target_policy=f'Member_of SID({security.SID_COMPOUNDED_AUTHENTICATION})',
                   service_sids=service_sids,
                   expected_groups=expected_groups)

    def test_rbcd_client_without_aa_asserted_identity(self):
        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
        }

        self._rbcd(f'Member_of SID({self.aa_asserted_identity})',
                   client_sids=client_sids)

        self._rbcd(target_policy=f'Member_of SID({self.aa_asserted_identity})',
                   client_sids=client_sids)

    def test_rbcd_client_with_aa_asserted_identity(self):
        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            (self.aa_asserted_identity, SidType.EXTRA_SID, self.default_attrs),
        }

        self._rbcd(f'Member_of SID({self.aa_asserted_identity})',
                   client_sids=client_sids,
                   expected_groups=client_sids)

        self._rbcd(target_policy=f'Member_of SID({self.aa_asserted_identity})',
                   client_sids=client_sids,
                   expected_groups=client_sids)

    def test_rbcd_client_without_service_asserted_identity(self):
        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
        }

        self._rbcd(f'Member_of SID({self.service_asserted_identity})',
                   client_sids=client_sids,
                   code=KDC_ERR_BADOPTION,
                   status=ntstatus.NT_STATUS_UNSUCCESSFUL,
                   edata=self.expect_padata_outer)

        self._rbcd(target_policy=f'Member_of SID({self.service_asserted_identity})',
                   client_sids=client_sids,
                   code=KDC_ERR_POLICY,
                   status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
                   event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
                   reason=AuditReason.ACCESS_DENIED,
                   edata=self.expect_padata_outer)

    def test_rbcd_client_with_service_asserted_identity(self):
        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            (self.service_asserted_identity, SidType.EXTRA_SID, self.default_attrs),
        }

        self._rbcd(f'Not_Member_of SID({self.service_asserted_identity})',
                   client_sids=client_sids,
                   expected_groups=client_sids)

        self._rbcd(target_policy=f'Not_Member_of SID({self.service_asserted_identity})',
                   client_sids=client_sids,
                   expected_groups=client_sids)

    def test_rbcd_client_without_claims_valid(self):
        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
        }

        self._rbcd(f'Member_of SID({security.SID_CLAIMS_VALID})',
                   client_sids=client_sids)

        self._rbcd(target_policy=f'Member_of SID({security.SID_CLAIMS_VALID})',
                   client_sids=client_sids)

    def test_rbcd_client_with_claims_valid(self):
        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, self.default_attrs),
        }

        self._rbcd(f'Member_of SID({security.SID_CLAIMS_VALID})',
                   client_sids=client_sids,
                   expected_groups=client_sids)

        self._rbcd(target_policy=f'Member_of SID({security.SID_CLAIMS_VALID})',
                   client_sids=client_sids,
                   expected_groups=client_sids)

    def test_rbcd_client_without_compounded_authentication(self):
        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
        }

        self._rbcd(f'Member_of SID({security.SID_COMPOUNDED_AUTHENTICATION})',
                   client_sids=client_sids,
                   code=KDC_ERR_BADOPTION,
                   status=ntstatus.NT_STATUS_UNSUCCESSFUL,
                   edata=self.expect_padata_outer)

        self._rbcd(target_policy=f'Member_of SID({security.SID_COMPOUNDED_AUTHENTICATION})',
                   client_sids=client_sids,
                   code=KDC_ERR_POLICY,
                   status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
                   event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
                   reason=AuditReason.ACCESS_DENIED,
                   edata=self.expect_padata_outer)

    def test_rbcd_client_with_compounded_authentication(self):
        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            (security.SID_COMPOUNDED_AUTHENTICATION, SidType.EXTRA_SID, self.default_attrs),
        }

        self._rbcd(f'Not_Member_of SID({security.SID_COMPOUNDED_AUTHENTICATION})',
                   client_sids=client_sids,
                   expected_groups=client_sids)

        self._rbcd(target_policy=f'Not_Member_of SID({security.SID_COMPOUNDED_AUTHENTICATION})',
                   client_sids=client_sids,
                   expected_groups=client_sids)

    def test_rbcd_device_without_aa_asserted_identity(self):
        device_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
        }

        self._rbcd(f'Device_Member_of SID({self.aa_asserted_identity})',
                   device_sids=device_sids,
                   code=KDC_ERR_BADOPTION,
                   status=ntstatus.NT_STATUS_UNSUCCESSFUL,
                   edata=self.expect_padata_outer)

        self._rbcd(target_policy=f'Device_Member_of SID({self.aa_asserted_identity})',
                   device_sids=device_sids,
                   code=KDC_ERR_POLICY,
                   status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
                   event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
                   reason=AuditReason.ACCESS_DENIED,
                   edata=self.expect_padata_outer)

    def test_rbcd_device_without_aa_asserted_identity_not_memberof(self):
        device_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
        }

        self._rbcd(f'Not_Device_Member_of SID({self.aa_asserted_identity})',
                   device_sids=device_sids)

        self._rbcd(target_policy=f'Not_Device_Member_of SID({self.aa_asserted_identity})',
                   device_sids=device_sids)

    def test_rbcd_device_with_aa_asserted_identity(self):
        device_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            (self.aa_asserted_identity, SidType.EXTRA_SID, self.default_attrs),
        }

        self._rbcd(f'Device_Member_of SID({self.aa_asserted_identity})',
                   device_sids=device_sids)

        self._rbcd(target_policy=f'Device_Member_of SID({self.aa_asserted_identity})',
                   device_sids=device_sids)

    def test_rbcd_device_without_service_asserted_identity(self):
        device_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
        }

        self._rbcd(f'Device_Member_of SID({self.service_asserted_identity})',
                   device_sids=device_sids,
                   code=KDC_ERR_BADOPTION,
                   status=ntstatus.NT_STATUS_UNSUCCESSFUL,
                   edata=self.expect_padata_outer)

        self._rbcd(target_policy=f'Device_Member_of SID({self.service_asserted_identity})',
                   device_sids=device_sids,
                   code=KDC_ERR_POLICY,
                   status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
                   event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
                   reason=AuditReason.ACCESS_DENIED,
                   edata=self.expect_padata_outer)

    def test_rbcd_device_with_service_asserted_identity(self):
        device_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            (self.service_asserted_identity, SidType.EXTRA_SID, self.default_attrs),
        }

        self._rbcd(f'Device_Member_of SID({self.service_asserted_identity})',
                   device_sids=device_sids)

        self._rbcd(target_policy=f'Device_Member_of SID({self.service_asserted_identity})',
                   device_sids=device_sids)

    def test_rbcd_device_without_claims_valid(self):
        device_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
        }

        self._rbcd(f'Device_Member_of SID({security.SID_CLAIMS_VALID})',
                   device_sids=device_sids,
                   code=KDC_ERR_BADOPTION,
                   status=ntstatus.NT_STATUS_UNSUCCESSFUL,
                   edata=self.expect_padata_outer)

        self._rbcd(target_policy=f'Device_Member_of SID({security.SID_CLAIMS_VALID})',
                   device_sids=device_sids,
                   code=KDC_ERR_POLICY,
                   status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
                   event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
                   reason=AuditReason.ACCESS_DENIED,
                   edata=self.expect_padata_outer)

    def test_rbcd_device_with_claims_valid(self):
        device_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, self.default_attrs),
        }

        self._rbcd(f'Device_Member_of SID({security.SID_CLAIMS_VALID})',
                   device_sids=device_sids)

        self._rbcd(target_policy=f'Device_Member_of SID({security.SID_CLAIMS_VALID})',
                   device_sids=device_sids)

    def test_rbcd_device_without_compounded_authentication(self):
        device_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
        }

        self._rbcd(f'Device_Member_of SID({security.SID_COMPOUNDED_AUTHENTICATION})',
                   device_sids=device_sids,
                   code=KDC_ERR_BADOPTION,
                   status=ntstatus.NT_STATUS_UNSUCCESSFUL,
                   edata=self.expect_padata_outer)

        self._rbcd(target_policy=f'Device_Member_of SID({security.SID_COMPOUNDED_AUTHENTICATION})',
                   device_sids=device_sids,
                   code=KDC_ERR_POLICY,
                   status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
                   event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
                   reason=AuditReason.ACCESS_DENIED,
                   edata=self.expect_padata_outer)

    def test_rbcd_device_with_compounded_authentication(self):
        device_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            (security.SID_COMPOUNDED_AUTHENTICATION, SidType.EXTRA_SID, self.default_attrs),
        }

        self._rbcd(f'Device_Member_of SID({security.SID_COMPOUNDED_AUTHENTICATION})',
                   device_sids=device_sids)

        self._rbcd(target_policy=f'Device_Member_of SID({security.SID_COMPOUNDED_AUTHENTICATION})',
                   device_sids=device_sids)

    def test_rbcd(self):
        self._rbcd('Member_of SID({service_sid})')

    def test_rbcd_device_from_rodc(self):
        self._rbcd('Member_of SID({service_sid})',
                   device_from_rodc=True,
                   code=(0, CRASHES_WINDOWS))

    def test_rbcd_service_from_rodc(self):
        self._rbcd('Member_of SID({service_sid})',
                   service_from_rodc=True)

    def test_rbcd_device_and_service_from_rodc(self):
        self._rbcd('Member_of SID({service_sid})',
                   service_from_rodc=True,
                   device_from_rodc=True,
                   code=(0, CRASHES_WINDOWS))

    def test_rbcd_client_from_rodc(self):
        self._rbcd('Member_of SID({service_sid})',
                   client_from_rodc=True)

    def test_rbcd_client_and_device_from_rodc(self):
        self._rbcd('Member_of SID({service_sid})',
                   client_from_rodc=True,
                   device_from_rodc=True,
                   code=(0, CRASHES_WINDOWS))

    def test_rbcd_client_and_service_from_rodc(self):
        self._rbcd('Member_of SID({service_sid})',
                   client_from_rodc=True,
                   service_from_rodc=True)

    def test_rbcd_all_from_rodc(self):
        self._rbcd('Member_of SID({service_sid})',
                   client_from_rodc=True,
                   service_from_rodc=True,
                   device_from_rodc=True,
                   code=(0, CRASHES_WINDOWS))

    def test_delegating_proxy_in_world_group_rbcd(self):
        self._check_delegating_proxy_in_group_rbcd(security.SID_WORLD)

    def test_delegating_proxy_in_network_group_rbcd(self):
        self._check_delegating_proxy_not_in_group_rbcd(security.SID_NT_NETWORK)

    def test_delegating_proxy_in_authenticated_users_rbcd(self):
        self._check_delegating_proxy_in_group_rbcd(
            security.SID_NT_AUTHENTICATED_USERS)

    def test_delegating_proxy_in_aa_asserted_identity_rbcd(self):
        self._check_delegating_proxy_in_group_rbcd(
            security.SID_AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY)

    def test_delegating_proxy_in_service_asserted_identity_rbcd(self):
        self._check_delegating_proxy_not_in_group_rbcd(
            security.SID_SERVICE_ASSERTED_IDENTITY)

    def test_delegating_proxy_in_compounded_authentication_rbcd(self):
        self._check_delegating_proxy_not_in_group_rbcd(
            security.SID_COMPOUNDED_AUTHENTICATION)

    def test_delegating_proxy_in_claims_valid_rbcd(self):
        self._check_delegating_proxy_in_group_rbcd(security.SID_CLAIMS_VALID)

    def test_device_in_world_group_rbcd(self):
        self._check_device_in_group_rbcd(security.SID_WORLD)

    def test_device_in_network_group_rbcd(self):
        self._check_device_not_in_group_rbcd(security.SID_NT_NETWORK)

    def test_device_in_authenticated_users_rbcd(self):
        self._check_device_in_group_rbcd(security.SID_NT_AUTHENTICATED_USERS)

    def test_device_in_aa_asserted_identity_rbcd(self):
        self._check_device_in_group_rbcd(
            security.SID_AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY)

    def test_device_in_service_asserted_identity_rbcd(self):
        self._check_device_not_in_group_rbcd(
            security.SID_SERVICE_ASSERTED_IDENTITY)

    def test_device_in_compounded_authentication_rbcd(self):
        self._check_device_not_in_group_rbcd(
            security.SID_COMPOUNDED_AUTHENTICATION)

    def test_device_in_claims_valid_rbcd(self):
        self._check_device_in_group_rbcd(security.SID_CLAIMS_VALID)

    def _check_delegating_proxy_in_group_rbcd(self, group):
        self._check_membership_rbcd(group, expect_in_group=True)

    def _check_delegating_proxy_not_in_group_rbcd(self, group):
        self._check_membership_rbcd(group, expect_in_group=False)

    def _check_device_in_group_rbcd(self, group):
        self._check_membership_rbcd(group, expect_in_group=True, device=True)

    def _check_device_not_in_group_rbcd(self, group):
        self._check_membership_rbcd(group, expect_in_group=False, device=True)

    def _check_membership_rbcd(self,
                               group,
                               *,
                               expect_in_group,
                               device=False):
        """Test that authentication succeeds or fails when the delegating proxy
        is required to belong to a certain group.
        """

        sddl_op = 'Device_Member_of' if device else 'Member_of'

        samdb = self.get_samdb()
        functional_level = self.get_domain_functional_level(samdb)

        if functional_level < dsdb.DS_DOMAIN_FUNCTION_2008:
            self.skipTest('RBCD requires FL2008')

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'id': 'device'})
        mach_tgt = self.get_tgt(mach_creds)

        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER)

        client_tkt_options = 'forwardable'
        expected_flags = krb5_asn1.TicketFlags(client_tkt_options)
        client_tgt = self.get_tgt(client_creds,
                                  kdc_options=client_tkt_options,
                                  expected_flags=expected_flags)

        client_sid = client_creds.get_sid()

        client_username = client_creds.get_username()
        client_cname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                                 names=[client_username])

        service_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'id': 'service'})
        service_tgt = self.get_tgt(service_creds)

        client_service_tkt = self.get_service_ticket(
            client_tgt,
            service_creds,
            kdc_options=client_tkt_options,
            expected_flags=expected_flags)

        domain_sid_str = samdb.get_domain_sid()
        domain_sid = security.dom_sid(domain_sid_str)

        # Require the principal to belong to a certain group.
        in_group_sddl = self.allow_if(f'{sddl_op} {{SID({group})}}')
        in_group_descriptor = security.descriptor.from_sddl(in_group_sddl,
                                                            domain_sid)

        # Create a target account that allows RBCD if the principal belongs to
        # the group.
        in_group_target_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={
                'additional_details': (
                    ('msDS-AllowedToActOnBehalfOfOtherIdentity',
                     ndr_pack(in_group_descriptor)),
                ),
            })

        kdc_options = str(krb5_asn1.KDCOptions('cname-in-addl-tkt'))

        in_group_target_key = self.TicketDecryptionKey_from_creds(
            in_group_target_creds)
        in_group_target_etypes = in_group_target_creds.tgs_supported_enctypes

        service_name = service_creds.get_username()
        if service_name[-1] == '$':
            service_name = service_name[:-1]
        expected_transited_services = [
            f'host/{service_name}@{service_creds.get_realm()}'
        ]

        pac_options = '1001'  # supports claims, RBCD

        success_result = 0, None, None
        failure_result = (
            KDC_ERR_BADOPTION,
            ntstatus.NT_STATUS_UNSUCCESSFUL,
            self.expect_padata_outer,
        )

        code, status, expect_edata = (success_result if expect_in_group
                                      else failure_result)

        # Test whether obtaining a service ticket with RBCD is allowed.
        self._tgs_req(service_tgt,
                      code,
                      service_creds,
                      in_group_target_creds,
                      armor_tgt=mach_tgt,
                      kdc_options=kdc_options,
                      pac_options=pac_options,
                      expected_cname=client_cname,
                      expected_account_name=client_username,
                      additional_ticket=client_service_tkt,
                      decryption_key=in_group_target_key,
                      expected_sid=client_sid,
                      expected_supported_etypes=in_group_target_etypes,
                      expected_proxy_target=in_group_target_creds.get_spn(),
                      expected_transited_services=expected_transited_services,
                      expected_status=status,
                      expect_edata=expect_edata)

        effective_client_creds = service_creds if code else client_creds
        self.check_tgs_log(effective_client_creds, in_group_target_creds,
                           checked_creds=service_creds,
                           status=status)

        # Require the principal not to belong to a certain group.
        not_in_group_sddl = self.allow_if(f'Not_{sddl_op} {{SID({group})}}')
        not_in_group_descriptor = security.descriptor.from_sddl(
            not_in_group_sddl, domain_sid)

        # Create a target account that allows RBCD if the principal does not
        # belong to the group.
        not_in_group_target_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={
                'additional_details': (
                    ('msDS-AllowedToActOnBehalfOfOtherIdentity',
                     ndr_pack(not_in_group_descriptor)),
                ),
            })

        not_in_group_target_key = self.TicketDecryptionKey_from_creds(
            not_in_group_target_creds)
        not_in_group_target_etypes = (
            not_in_group_target_creds.tgs_supported_enctypes)

        code, status, expect_edata = (failure_result if expect_in_group
                                      else success_result)

        # Test whether obtaining a service ticket with RBCD is allowed.
        self._tgs_req(service_tgt,
                      code,
                      service_creds,
                      not_in_group_target_creds,
                      armor_tgt=mach_tgt,
                      kdc_options=kdc_options,
                      pac_options=pac_options,
                      expected_cname=client_cname,
                      expected_account_name=client_username,
                      additional_ticket=client_service_tkt,
                      decryption_key=not_in_group_target_key,
                      expected_sid=client_sid,
                      expected_supported_etypes=not_in_group_target_etypes,
                      expected_proxy_target=not_in_group_target_creds.get_spn(),
                      expected_transited_services=expected_transited_services,
                      expected_status=status,
                      expect_edata=expect_edata)

        effective_client_creds = service_creds if code else client_creds
        self.check_tgs_log(effective_client_creds, not_in_group_target_creds,
                           checked_creds=service_creds,
                           status=status)

    def _rbcd(self,
              rbcd_expression=None,
              *,
              code=0,
              status=None,
              event=AuditEvent.OK,
              reason=AuditReason.NONE,
              edata=False,
              target_policy=None,
              client_from_rodc=False,
              service_from_rodc=False,
              device_from_rodc=False,
              client_sids=None,
              client_claims=None,
              service_sids=None,
              service_claims=None,
              device_sids=None,
              device_claims=None,
              expected_groups=None,
              expected_claims=None):
        try:
            code, crashes_windows = code
            self.assertIs(crashes_windows, CRASHES_WINDOWS)
            if not self.crash_windows:
                self.skipTest('test crashes Windows servers')
        except TypeError:
            self.assertIsNot(code, CRASHES_WINDOWS)

        samdb = self.get_samdb()
        functional_level = self.get_domain_functional_level(samdb)

        if functional_level < dsdb.DS_DOMAIN_FUNCTION_2008:
            self.skipTest('RBCD requires FL2008')

        domain_sid_str = samdb.get_domain_sid()
        domain_sid = security.dom_sid(domain_sid_str)

        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER,
            opts={
                'allowed_replication_mock': client_from_rodc,
                'revealed_to_mock_rodc': client_from_rodc,
            })
        client_sid = client_creds.get_sid()

        client_username = client_creds.get_username()
        client_cname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                                 names=[client_username])

        client_tkt_options = 'forwardable'
        expected_flags = krb5_asn1.TicketFlags(client_tkt_options)

        checksum_key = self.get_krbtgt_checksum_key()

        if client_from_rodc or service_from_rodc or device_from_rodc:
            rodc_krbtgt_creds = self.get_mock_rodc_krbtgt_creds()
            rodc_krbtgt_key = self.TicketDecryptionKey_from_creds(rodc_krbtgt_creds)
            rodc_checksum_key = {
                krb5pac.PAC_TYPE_KDC_CHECKSUM: rodc_krbtgt_key,
            }

        client_tgt = self.get_tgt(client_creds,
                                  kdc_options=client_tkt_options,
                                  expected_flags=expected_flags)

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={
                'allowed_replication_mock': device_from_rodc,
                'revealed_to_mock_rodc': device_from_rodc,
            })
        mach_tgt = self.get_tgt(mach_creds)
        device_modify_pac_fn = []
        if device_sids is not None:
            device_modify_pac_fn.append(partial(self.set_pac_sids,
                                                new_sids=device_sids))
        if device_claims is not None:
            device_modify_pac_fn.append(partial(self.set_pac_claims,
                                                client_claims=device_claims))
        mach_tgt = self.modified_ticket(
            mach_tgt,
            modify_pac_fn=device_modify_pac_fn,
            new_ticket_key=rodc_krbtgt_key if device_from_rodc else None,
            checksum_keys=rodc_checksum_key if device_from_rodc else checksum_key)

        service_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={
                'id': 1,
                'allowed_replication_mock': service_from_rodc,
                'revealed_to_mock_rodc': service_from_rodc,
            })
        service_tgt = self.get_tgt(service_creds)

        service_modify_pac_fn = []
        if service_sids is not None:
            service_modify_pac_fn.append(partial(self.set_pac_sids,
                                                 new_sids=service_sids))
        if service_claims is not None:
            service_modify_pac_fn.append(partial(self.set_pac_claims,
                                                 client_claims=service_claims))
        service_tgt = self.modified_ticket(
            service_tgt,
            modify_pac_fn=service_modify_pac_fn,
            new_ticket_key=rodc_krbtgt_key if service_from_rodc else None,
            checksum_keys=rodc_checksum_key if service_from_rodc else checksum_key)

        if target_policy is None:
            policy = None
            assigned_policy = None
        else:
            sddl = f'O:SYD:(XA;;CR;;;WD;({target_policy.format(service_sid=service_creds.get_sid())}))'
            policy = self.create_authn_policy(enforced=True,
                                              computer_allowed_to=sddl)
            assigned_policy = str(policy.dn)

        if rbcd_expression is not None:
            sddl = f'O:SYD:(XA;;CR;;;WD;({rbcd_expression.format(service_sid=service_creds.get_sid())}))'
        else:
            sddl = 'O:SYD:(A;;CR;;;WD)'
        descriptor = security.descriptor.from_sddl(sddl, domain_sid)
        descriptor = ndr_pack(descriptor)

        # Create a target account with the assigned policy.
        target_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={
                'assigned_policy': assigned_policy,
                'additional_details': (
                    ('msDS-AllowedToActOnBehalfOfOtherIdentity', descriptor),
                ),
            })

        client_service_tkt = self.get_service_ticket(
            client_tgt,
            service_creds,
            kdc_options=client_tkt_options,
            expected_flags=expected_flags)
        client_modify_pac_fn = []
        if client_sids is not None:
            client_modify_pac_fn.append(partial(self.set_pac_sids,
                                                new_sids=client_sids))
        if client_claims is not None:
            client_modify_pac_fn.append(partial(self.set_pac_claims,
                                                client_claims=client_claims))
        client_service_tkt = self.modified_ticket(client_service_tkt,
                                                  modify_pac_fn=client_modify_pac_fn,
                                                  checksum_keys=rodc_checksum_key if client_from_rodc else checksum_key)

        kdc_options = str(krb5_asn1.KDCOptions('cname-in-addl-tkt'))

        target_decryption_key = self.TicketDecryptionKey_from_creds(
            target_creds)
        target_etypes = target_creds.tgs_supported_enctypes

        service_name = service_creds.get_username()
        if service_name[-1] == '$':
            service_name = service_name[:-1]
        expected_transited_services = [
            f'host/{service_name}@{service_creds.get_realm()}'
        ]

        expected_groups = self.map_sids(expected_groups, None, domain_sid_str)

        # Show that obtaining a service ticket with RBCD is allowed.
        self._tgs_req(service_tgt, code, service_creds, target_creds,
                      armor_tgt=mach_tgt,
                      kdc_options=kdc_options,
                      pac_options='1001',  # supports claims, RBCD
                      expected_cname=client_cname,
                      expected_account_name=client_username,
                      additional_ticket=client_service_tkt,
                      decryption_key=target_decryption_key,
                      expected_sid=client_sid,
                      expected_groups=expected_groups,
                      expect_client_claims=bool(expected_claims) or None,
                      expected_client_claims=expected_claims,
                      expected_supported_etypes=target_etypes,
                      expected_proxy_target=target_creds.get_spn(),
                      expected_transited_services=expected_transited_services,
                      expected_status=status,
                      expect_edata=edata)

        if code:
            effective_client_creds = service_creds
        else:
            effective_client_creds = client_creds

        self.check_tgs_log(effective_client_creds, target_creds,
                           policy=policy,
                           checked_creds=service_creds,
                           status=status,
                           event=event,
                           reason=reason)

    def test_tgs_claims_valid_missing(self):
        """Test that the Claims Valid SID is not added to the PAC when
        performing a TGS‐REQ."""
        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            (self.aa_asserted_identity, SidType.EXTRA_SID, self.default_attrs),
        }

        self._tgs(use_fast=False,
                  client_sids=client_sids,
                  expected_groups=client_sids)

    def test_tgs_claims_valid_missing_from_rodc(self):
        """Test that the Claims Valid SID *is* added to the PAC when
        performing a TGS‐REQ with an RODC‐issued TGT."""
        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            (self.aa_asserted_identity, SidType.EXTRA_SID, self.default_attrs),
        }

        expected_groups = client_sids | {
            (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, self.default_attrs),
        }

        self._tgs(use_fast=False,
                  client_from_rodc=True,
                  client_sids=client_sids,
                  expected_groups=expected_groups)

    def test_tgs_aa_asserted_identity(self):
        """Test performing a TGS‐REQ with the Authentication Identity Asserted
        Identity SID present."""
        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            (self.aa_asserted_identity, SidType.EXTRA_SID, self.default_attrs),
            (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, self.default_attrs),
        }

        self._tgs(use_fast=False,
                  client_sids=client_sids,
                  expected_groups=client_sids)

    def test_tgs_aa_asserted_identity_no_attrs(self):
        """Test performing a TGS‐REQ with the Authentication Identity Asserted
        Identity SID present, albeit without any attributes."""
        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            # Put the Asserted Identity SID in the PAC without any flags set.
            (self.aa_asserted_identity, SidType.EXTRA_SID, 0),
            (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, self.default_attrs),
        }

        self._tgs(use_fast=False,
                  client_sids=client_sids,
                  expected_groups=client_sids)

    def test_tgs_aa_asserted_identity_from_rodc(self):
        """Test that the Authentication Identity Asserted Identity SID in an
        RODC‐issued PAC is preserved when performing a TGS‐REQ."""
        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            (self.aa_asserted_identity, SidType.EXTRA_SID, self.default_attrs),
            (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, self.default_attrs),
        }

        self._tgs(use_fast=False,
                  client_from_rodc=True,
                  client_sids=client_sids,
                  expected_groups=client_sids)

    def test_tgs_aa_asserted_identity_from_rodc_no_attrs_from_rodc(self):
        """Test that the Authentication Identity Asserted Identity SID without
        attributes in an RODC‐issued PAC is preserved when performing a
        TGS‐REQ."""
        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            # Put the Asserted Identity SID in the PAC without any flags set.
            (self.aa_asserted_identity, SidType.EXTRA_SID, 0),
            (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, self.default_attrs),
        }

        expected_groups = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            # The SID in the resulting PAC has the default attributes.
            (self.aa_asserted_identity, SidType.EXTRA_SID, self.default_attrs),
            (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, self.default_attrs),
        }

        self._tgs(use_fast=False,
                  client_from_rodc=True,
                  client_sids=client_sids,
                  expected_groups=expected_groups)

    def test_tgs_compound_authentication(self):
        """Test performing a TGS‐REQ with the Compounded Authentication SID
        present."""
        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, self.default_attrs),
            (security.SID_COMPOUNDED_AUTHENTICATION, SidType.EXTRA_SID, self.default_attrs),
        }

        self._tgs(use_fast=False,
                  client_sids=client_sids,
                  expected_groups=client_sids)

    def test_tgs_compound_authentication_from_rodc(self):
        """Test that the Compounded Authentication SID in an
        RODC‐issued PAC is not preserved when performing a TGS‐REQ."""
        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, self.default_attrs),
            (security.SID_COMPOUNDED_AUTHENTICATION, SidType.EXTRA_SID, self.default_attrs),
        }

        expected_groups = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, self.default_attrs),
        }

        self._tgs(use_fast=False,
                  client_from_rodc=True,
                  client_sids=client_sids,
                  expected_groups=expected_groups)

    def test_tgs_asserted_identity_missing(self):
        """Test that the Authentication Identity Asserted Identity SID is not
        added to the PAC when performing a TGS‐REQ."""
        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, self.default_attrs),
        }

        self._tgs(use_fast=False,
                  client_sids=client_sids,
                  expected_groups=client_sids)

    def test_tgs_asserted_identity_missing_from_rodc(self):
        """Test that the Authentication Identity Asserted Identity SID is not
        added to an RODC‐issued PAC when performing a TGS‐REQ."""
        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, self.default_attrs),
        }

        self._tgs(use_fast=False,
                  client_from_rodc=True,
                  client_sids=client_sids,
                  expected_groups=client_sids)

    def test_tgs_service_asserted_identity(self):
        """Test performing a TGS‐REQ with the Service Asserted Identity SID
        present."""
        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            (self.service_asserted_identity, SidType.EXTRA_SID, self.default_attrs),
            (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, self.default_attrs),
        }

        self._tgs(use_fast=False,
                  client_sids=client_sids,
                  expected_groups=client_sids)

    def test_tgs_service_asserted_identity_from_rodc(self):
        """Test that the Service Asserted Identity SID in an
        RODC‐issued PAC is not preserved when performing a TGS‐REQ."""
        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            (self.service_asserted_identity, SidType.EXTRA_SID, self.default_attrs),
            (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, self.default_attrs),
        }

        expected_groups = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            # Don’t expect the Service Asserted Identity SID.
            (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, self.default_attrs),
        }

        self._tgs(use_fast=False,
                  client_from_rodc=True,
                  client_sids=client_sids,
                  expected_groups=expected_groups)

    def test_tgs_without_aa_asserted_identity(self):
        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
        }

        self._tgs(f'Member_of SID({self.aa_asserted_identity})',
                  client_sids=client_sids,
                  code=KDC_ERR_POLICY,
                  status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
                  event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
                  reason=AuditReason.ACCESS_DENIED,
                  edata=self.expect_padata_outer)

    def test_tgs_without_aa_asserted_identity_client_from_rodc(self):
        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
        }

        self._tgs(f'Member_of SID({self.aa_asserted_identity})',
                  client_from_rodc=True,
                  client_sids=client_sids,
                  code=KDC_ERR_POLICY,
                  status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
                  event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
                  reason=AuditReason.ACCESS_DENIED,
                  edata=self.expect_padata_outer)

    def test_tgs_without_aa_asserted_identity_device_from_rodc(self):
        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
        }

        self._tgs(f'Member_of SID({self.aa_asserted_identity})',
                  device_from_rodc=True,
                  client_sids=client_sids,
                  code=(KDC_ERR_POLICY, CRASHES_WINDOWS),
                  status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
                  event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
                  reason=AuditReason.ACCESS_DENIED,
                  edata=self.expect_padata_outer)

    def test_tgs_without_aa_asserted_identity_both_from_rodc(self):
        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
        }

        self._tgs(f'Member_of SID({self.aa_asserted_identity})',
                  client_from_rodc=True,
                  device_from_rodc=True,
                  client_sids=client_sids,
                  code=(KDC_ERR_POLICY, CRASHES_WINDOWS),
                  status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
                  event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
                  reason=AuditReason.ACCESS_DENIED,
                  edata=self.expect_padata_outer)

    def test_tgs_with_aa_asserted_identity(self):
        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            (self.aa_asserted_identity, SidType.EXTRA_SID, self.default_attrs),
        }

        self._tgs(f'Member_of SID({self.aa_asserted_identity})',
                  client_sids=client_sids,
                  expected_groups=client_sids)

    def test_tgs_with_aa_asserted_identity_client_from_rodc(self):
        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            (self.aa_asserted_identity, SidType.EXTRA_SID, self.default_attrs),
        }

        expected_groups = client_sids | {
            (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, self.default_attrs),
        }

        self._tgs(f'Member_of SID({self.aa_asserted_identity})',
                  client_from_rodc=True,
                  client_sids=client_sids,
                  expected_groups=expected_groups)

    def test_tgs_with_aa_asserted_identity_device_from_rodc(self):
        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            (self.aa_asserted_identity, SidType.EXTRA_SID, self.default_attrs),
        }

        self._tgs(f'Member_of SID({self.aa_asserted_identity})',
                  device_from_rodc=True,
                  client_sids=client_sids,
                  expected_groups=client_sids,
                  code=(0, CRASHES_WINDOWS))

    def test_tgs_with_aa_asserted_identity_both_from_rodc(self):
        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            (self.aa_asserted_identity, SidType.EXTRA_SID, self.default_attrs),
        }

        expected_groups = client_sids | {
            (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, self.default_attrs),
        }

        self._tgs(f'Member_of SID({self.aa_asserted_identity})',
                  client_from_rodc=True,
                  device_from_rodc=True,
                  client_sids=client_sids,
                  expected_groups=expected_groups,
                  code=(0, CRASHES_WINDOWS))

    def test_tgs_without_service_asserted_identity(self):
        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
        }

        self._tgs(f'Member_of SID({self.service_asserted_identity})',
                  client_sids=client_sids,
                  code=KDC_ERR_POLICY,
                  status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
                  event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
                  reason=AuditReason.ACCESS_DENIED,
                  edata=self.expect_padata_outer)

    def test_tgs_without_service_asserted_identity_client_from_rodc(self):
        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
        }

        self._tgs(f'Member_of SID({self.service_asserted_identity})',
                  client_from_rodc=True,
                  client_sids=client_sids,
                  code=KDC_ERR_POLICY,
                  status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
                  event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
                  reason=AuditReason.ACCESS_DENIED,
                  edata=self.expect_padata_outer)

    def test_tgs_without_service_asserted_identity_device_from_rodc(self):
        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
        }

        self._tgs(f'Member_of SID({self.service_asserted_identity})',
                  device_from_rodc=True,
                  client_sids=client_sids,
                  code=(KDC_ERR_POLICY, CRASHES_WINDOWS),
                  status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
                  event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
                  reason=AuditReason.ACCESS_DENIED,
                  edata=self.expect_padata_outer)

    def test_tgs_without_service_asserted_identity_both_from_rodc(self):
        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
        }

        self._tgs(f'Member_of SID({self.service_asserted_identity})',
                  client_from_rodc=True,
                  device_from_rodc=True,
                  client_sids=client_sids,
                  code=(KDC_ERR_POLICY, CRASHES_WINDOWS),
                  status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
                  event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
                  reason=AuditReason.ACCESS_DENIED,
                  edata=self.expect_padata_outer)

    def test_tgs_with_service_asserted_identity(self):
        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            (self.service_asserted_identity, SidType.EXTRA_SID, self.default_attrs),
        }

        self._tgs(f'Member_of SID({self.service_asserted_identity})',
                  client_sids=client_sids,
                  expected_groups=client_sids)

    def test_tgs_with_service_asserted_identity_client_from_rodc(self):
        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            (self.service_asserted_identity, SidType.EXTRA_SID, self.default_attrs),
        }

        self._tgs(f'Member_of SID({self.service_asserted_identity})',
                  client_from_rodc=True,
                  client_sids=client_sids,
                  code=KDC_ERR_POLICY,
                  status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
                  event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
                  reason=AuditReason.ACCESS_DENIED,
                  edata=self.expect_padata_outer)

    def test_tgs_with_service_asserted_identity_device_from_rodc(self):
        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            (self.service_asserted_identity, SidType.EXTRA_SID, self.default_attrs),
        }

        self._tgs(f'Member_of SID({self.service_asserted_identity})',
                  device_from_rodc=True,
                  client_sids=client_sids,
                  expected_groups=client_sids,
                  code=(0, CRASHES_WINDOWS))

    def test_tgs_with_service_asserted_identity_both_from_rodc(self):
        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            (self.service_asserted_identity, SidType.EXTRA_SID, self.default_attrs),
        }

        self._tgs(f'Member_of SID({self.service_asserted_identity})',
                  client_from_rodc=True,
                  device_from_rodc=True,
                  client_sids=client_sids,
                  code=(KDC_ERR_POLICY, CRASHES_WINDOWS),
                  status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
                  event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
                  reason=AuditReason.ACCESS_DENIED,
                  edata=self.expect_padata_outer)

    def test_tgs_without_claims_valid(self):
        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
        }

        self._tgs(f'Member_of SID({security.SID_CLAIMS_VALID})',
                  client_sids=client_sids,
                  code=KDC_ERR_POLICY,
                  status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
                  event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
                  reason=AuditReason.ACCESS_DENIED,
                  edata=self.expect_padata_outer)

    def test_tgs_without_claims_valid_client_from_rodc(self):
        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
        }

        expected_groups = client_sids | {
            (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, self.default_attrs),
        }

        self._tgs(f'Member_of SID({security.SID_CLAIMS_VALID})',
                  client_from_rodc=True,
                  client_sids=client_sids,
                  expected_groups=expected_groups)

    def test_tgs_without_claims_valid_device_from_rodc(self):
        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
        }

        self._tgs(f'Member_of SID({security.SID_CLAIMS_VALID})',
                  device_from_rodc=True,
                  client_sids=client_sids,
                  code=(KDC_ERR_POLICY, CRASHES_WINDOWS),
                  status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
                  event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
                  reason=AuditReason.ACCESS_DENIED,
                  edata=self.expect_padata_outer)

    def test_tgs_without_claims_valid_both_from_rodc(self):
        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
        }

        expected_groups = client_sids | {
            (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, self.default_attrs),
        }

        self._tgs(f'Member_of SID({security.SID_CLAIMS_VALID})',
                  client_from_rodc=True,
                  device_from_rodc=True,
                  client_sids=client_sids,
                  expected_groups=expected_groups,
                  code=(0, CRASHES_WINDOWS))

    def test_tgs_with_claims_valid(self):
        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, self.default_attrs),
        }

        self._tgs(f'Member_of SID({security.SID_CLAIMS_VALID})',
                  client_sids=client_sids,
                  expected_groups=client_sids)

    def test_tgs_with_claims_valid_client_from_rodc(self):
        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, self.default_attrs),
        }

        self._tgs(f'Member_of SID({security.SID_CLAIMS_VALID})',
                  client_from_rodc=True,
                  client_sids=client_sids,
                  expected_groups=client_sids)

    def test_tgs_with_claims_valid_device_from_rodc(self):
        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, self.default_attrs),
        }

        self._tgs(f'Member_of SID({security.SID_CLAIMS_VALID})',
                  device_from_rodc=True,
                  client_sids=client_sids,
                  expected_groups=client_sids,
                  code=(0, CRASHES_WINDOWS))

    def test_tgs_with_claims_valid_both_from_rodc(self):
        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, self.default_attrs),
        }

        self._tgs(f'Member_of SID({security.SID_CLAIMS_VALID})',
                  client_from_rodc=True,
                  device_from_rodc=True,
                  client_sids=client_sids,
                  expected_groups=client_sids,
                  code=(0, CRASHES_WINDOWS))

    def _tgs(self,
             target_policy=None,
             *,
             code=0,
             event=AuditEvent.OK,
             reason=AuditReason.NONE,
             status=None,
             edata=False,
             use_fast=True,
             client_from_rodc=None,
             device_from_rodc=None,
             client_sids=None,
             client_claims=None,
             device_sids=None,
             device_claims=None,
             expected_groups=None,
             expected_claims=None):
        try:
            code, crashes_windows = code
            self.assertIs(crashes_windows, CRASHES_WINDOWS)
            if not self.crash_windows:
                self.skipTest('test crashes Windows servers')
        except TypeError:
            self.assertIsNot(code, CRASHES_WINDOWS)

        if not use_fast:
            self.assertIsNone(device_from_rodc)
            self.assertIsNone(device_sids)
            self.assertIsNone(device_claims)

        if client_from_rodc is None:
            client_from_rodc = False

        if device_from_rodc is None:
            device_from_rodc = False

        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER,
            opts={
                'allowed_replication_mock': client_from_rodc,
                'revealed_to_mock_rodc': client_from_rodc,
            })
        client_sid = client_creds.get_sid()

        client_username = client_creds.get_username()
        client_cname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                                 names=[client_username])

        client_tkt_options = 'forwardable'
        expected_flags = krb5_asn1.TicketFlags(client_tkt_options)

        checksum_key = self.get_krbtgt_checksum_key()

        if client_from_rodc or device_from_rodc:
            rodc_krbtgt_creds = self.get_mock_rodc_krbtgt_creds()
            rodc_krbtgt_key = self.TicketDecryptionKey_from_creds(rodc_krbtgt_creds)
            rodc_checksum_key = {
                krb5pac.PAC_TYPE_KDC_CHECKSUM: rodc_krbtgt_key,
            }

        client_tgt = self.get_tgt(client_creds,
                                  kdc_options=client_tkt_options,
                                  expected_flags=expected_flags)

        client_modify_pac_fn = []
        if client_sids is not None:
            client_modify_pac_fn.append(partial(self.set_pac_sids,
                                                new_sids=client_sids))
        if client_claims is not None:
            client_modify_pac_fn.append(partial(self.set_pac_claims,
                                                client_claims=client_claims))
        client_tgt = self.modified_ticket(
            client_tgt,
            modify_pac_fn=client_modify_pac_fn,
            new_ticket_key=rodc_krbtgt_key if client_from_rodc else None,
            checksum_keys=rodc_checksum_key if client_from_rodc else checksum_key)

        if use_fast:
            # Create a machine account with which to perform FAST.
            mach_creds = self.get_cached_creds(
                account_type=self.AccountType.COMPUTER,
                opts={
                    'allowed_replication_mock': device_from_rodc,
                    'revealed_to_mock_rodc': device_from_rodc,
                })
            mach_tgt = self.get_tgt(mach_creds)
            device_modify_pac_fn = []
            if device_sids is not None:
                device_modify_pac_fn.append(partial(self.set_pac_sids,
                                                    new_sids=device_sids))
            if device_claims is not None:
                device_modify_pac_fn.append(partial(self.set_pac_claims,
                                                    client_claims=device_claims))
            mach_tgt = self.modified_ticket(
                mach_tgt,
                modify_pac_fn=device_modify_pac_fn,
                new_ticket_key=rodc_krbtgt_key if device_from_rodc else None,
                checksum_keys=rodc_checksum_key if device_from_rodc else checksum_key)
        else:
            mach_tgt = None

        if target_policy is None:
            policy = None
            assigned_policy = None
        else:
            sddl = f'O:SYD:(XA;;CR;;;WD;({target_policy.format(client_sid=client_creds.get_sid())}))'
            policy = self.create_authn_policy(enforced=True,
                                              computer_allowed_to=sddl)
            assigned_policy = str(policy.dn)

        # Create a target account with the assigned policy.
        target_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'assigned_policy': assigned_policy})

        target_decryption_key = self.TicketDecryptionKey_from_creds(
            target_creds)
        target_etypes = target_creds.tgs_supported_enctypes

        samdb = self.get_samdb()
        domain_sid_str = samdb.get_domain_sid()

        expected_groups = self.map_sids(expected_groups, None, domain_sid_str)

        # Show that obtaining a service ticket is allowed.
        self._tgs_req(client_tgt, code, client_creds, target_creds,
                      armor_tgt=mach_tgt,
                      expected_cname=client_cname,
                      expected_account_name=client_username,
                      decryption_key=target_decryption_key,
                      expected_sid=client_sid,
                      expected_groups=expected_groups,
                      expect_client_claims=bool(expected_claims) or None,
                      expected_client_claims=expected_claims,
                      expected_supported_etypes=target_etypes,
                      expected_status=status,
                      expect_edata=edata)

        self.check_tgs_log(client_creds, target_creds,
                           policy=policy,
                           checked_creds=client_creds,
                           status=status,
                           event=event,
                           reason=reason)

    def test_conditional_ace_allowed_from_user_allow(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create an authentication policy that explicitly allows the machine
        # account for a user.
        allowed = (f'O:SYD:(XA;;CR;;;{mach_creds.get_sid()};'
                   f'(Member_of SID({mach_creds.get_sid()})))')
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_from=allowed,
                                          service_allowed_from=denied)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that authentication succeeds.
        self._get_tgt(client_creds, armor_tgt=mach_tgt,
                      expected_error=0)

        self.check_as_log(
            client_creds,
            armor_creds=mach_creds,
            client_policy=policy)

    def test_conditional_ace_allowed_from_user_deny(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create an authentication policy that explicitly denies the machine
        # account for a user.
        allowed = 'O:SYD:(A;;CR;;;WD)'
        denied = (f'O:SYD:(XD;;CR;;;{mach_creds.get_sid()};'
                  f'(Member_of SID({mach_creds.get_sid()})))'
                  f'(A;;CR;;;WD)')
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_from=denied,
                                          service_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that we get a policy error when trying to authenticate.
        self._get_tgt(client_creds, armor_tgt=mach_tgt,
                      expected_error=KDC_ERR_POLICY)

        self.check_as_log(
            client_creds,
            armor_creds=mach_creds,
            client_policy=policy,
            client_policy_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.KERBEROS_DEVICE_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED,
            status=ntstatus.NT_STATUS_INVALID_WORKSTATION)


class DeviceRestrictionTests(ConditionalAceBaseTests):
    def test_pac_groups_not_present(self):
        """Test that authentication fails if the device does not belong to some
        required groups.
        """

        required_sids = {
            ('S-1-2-3-4', SidType.EXTRA_SID, self.default_attrs),
            ('S-1-9-8-7', SidType.EXTRA_SID, self.default_attrs),
        }

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'id': 'device'})
        mach_tgt = self.get_tgt(mach_creds)

        # Create an authentication policy that requires the device to belong to
        # certain groups.
        client_policy_sddl = self.allow_if(
            f'Member_of {self.sddl_array_from_sids(required_sids)}')
        client_policy = self.create_authn_policy(
            enforced=True, user_allowed_from=client_policy_sddl)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=client_policy)

        # Show that authentication fails.
        self._armored_as_req(client_creds,
                             self.get_krbtgt_creds(),
                             mach_tgt,
                             expected_error=KDC_ERR_POLICY)

        self.check_as_log(
            client_creds,
            armor_creds=mach_creds,
            client_policy=client_policy,
            client_policy_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.KERBEROS_DEVICE_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED,
            status=ntstatus.NT_STATUS_INVALID_WORKSTATION)

    def test_pac_groups_present(self):
        """Test that authentication succeeds if the device belongs to some
        required groups.
        """

        required_sids = {
            ('S-1-2-3-4', SidType.EXTRA_SID, self.default_attrs),
            ('S-1-9-8-7', SidType.EXTRA_SID, self.default_attrs),
        }

        device_sids = required_sids | {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
        }

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'id': 'device'})
        mach_tgt = self.get_tgt(mach_creds)

        # Add the required groups to the machine account’s TGT.
        mach_tgt = self.modified_ticket(
            mach_tgt,
            modify_pac_fn=partial(self.set_pac_sids,
                                  new_sids=device_sids),
            checksum_keys=self.get_krbtgt_checksum_key())

        # Create an authentication policy that requires the device to belong to
        # certain groups.
        client_policy_sddl = self.allow_if(
            f'Member_of {self.sddl_array_from_sids(required_sids)}')
        client_policy = self.create_authn_policy(
            enforced=True, user_allowed_from=client_policy_sddl)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=client_policy)

        # Show that authentication succeeds.
        self._armored_as_req(client_creds,
                             self.get_krbtgt_creds(),
                             mach_tgt)

        self.check_as_log(client_creds,
                          armor_creds=mach_creds,
                          client_policy=client_policy)

    def test_pac_resource_groups_present(self):
        """Test that authentication succeeds if the device belongs to some
        required resource groups.
        """

        required_sids = {
            ('S-1-2-3-4', SidType.RESOURCE_SID, self.resource_attrs),
            ('S-1-2-3-5', SidType.RESOURCE_SID, self.resource_attrs),
            ('S-1-2-3-6', SidType.RESOURCE_SID, self.resource_attrs),
        }

        device_sids = required_sids | {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
        }

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'id': 'device'})
        mach_tgt = self.get_tgt(mach_creds)

        # Add the required groups to the machine account’s TGT.
        mach_tgt = self.modified_ticket(
            mach_tgt,
            modify_pac_fn=partial(self.set_pac_sids,
                                  new_sids=device_sids),
            checksum_keys=self.get_krbtgt_checksum_key())

        # Create an authentication policy that requires the device to belong to
        # certain groups.
        client_policy_sddl = self.allow_if(
            f'Member_of {self.sddl_array_from_sids(required_sids)}')
        client_policy = self.create_authn_policy(
            enforced=True, user_allowed_from=client_policy_sddl)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=client_policy)

        # Show that authentication fails.
        self._armored_as_req(client_creds,
                             self.get_krbtgt_creds(),
                             mach_tgt,
                             expected_error=KDC_ERR_POLICY)

        self.check_as_log(
            client_creds,
            armor_creds=mach_creds,
            client_policy=client_policy,
            client_policy_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.KERBEROS_DEVICE_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED,
            status=ntstatus.NT_STATUS_INVALID_WORKSTATION)

    def test_pac_resource_groups_present_to_service_sid_compression(self):
        """Test that authentication succeeds if the device belongs to some
        required resource groups, and the request is to a service that supports
        SID compression.
        """

        required_sids = {
            ('S-1-2-3-4', SidType.RESOURCE_SID, self.resource_attrs),
            ('S-1-2-3-5', SidType.RESOURCE_SID, self.resource_attrs),
            ('S-1-2-3-6', SidType.RESOURCE_SID, self.resource_attrs),
        }

        device_sids = required_sids | {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
        }

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'id': 'device'})
        mach_tgt = self.get_tgt(mach_creds)

        # Add the required groups to the machine account’s TGT.
        mach_tgt = self.modified_ticket(
            mach_tgt,
            modify_pac_fn=partial(self.set_pac_sids,
                                  new_sids=device_sids),
            checksum_keys=self.get_krbtgt_checksum_key())

        # Create an authentication policy that requires the device to belong to
        # certain groups.
        client_policy_sddl = self.allow_if(
            f'Member_of {self.sddl_array_from_sids(required_sids)}')
        client_policy = self.create_authn_policy(
            enforced=True, user_allowed_from=client_policy_sddl)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=client_policy)

        target_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'id': 'target'})

        # Show that authentication fails.
        self._armored_as_req(client_creds,
                             target_creds,
                             mach_tgt,
                             expected_error=KDC_ERR_POLICY)

        self.check_as_log(
            client_creds,
            armor_creds=mach_creds,
            client_policy=client_policy,
            client_policy_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.KERBEROS_DEVICE_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED,
            status=ntstatus.NT_STATUS_INVALID_WORKSTATION)

    def test_pac_resource_groups_present_to_service_no_sid_compression(self):
        """Test that authentication succeeds if the device belongs to some
        required resource groups, and the request is to a service that does not
        support SID compression.
        """

        required_sids = {
            ('S-1-2-3-4', SidType.RESOURCE_SID, self.resource_attrs),
            ('S-1-2-3-5', SidType.RESOURCE_SID, self.resource_attrs),
            ('S-1-2-3-6', SidType.RESOURCE_SID, self.resource_attrs),
        }

        device_sids = required_sids | {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
        }

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'id': 'device'})
        mach_tgt = self.get_tgt(mach_creds)

        # Add the required groups to the machine account’s TGT.
        mach_tgt = self.modified_ticket(
            mach_tgt,
            modify_pac_fn=partial(self.set_pac_sids,
                                  new_sids=device_sids),
            checksum_keys=self.get_krbtgt_checksum_key())

        # Create an authentication policy that requires the device to belong to
        # certain groups.
        client_policy_sddl = self.allow_if(
            f'Member_of {self.sddl_array_from_sids(required_sids)}')
        client_policy = self.create_authn_policy(
            enforced=True, user_allowed_from=client_policy_sddl)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=client_policy)

        target_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={
                'id': 'target',
                'supported_enctypes': (
                    security.KERB_ENCTYPE_RC4_HMAC_MD5) | (
                        security.KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96_SK),
                'sid_compression_support': False,
            })

        # Show that authentication fails.
        self._armored_as_req(client_creds,
                             target_creds,
                             mach_tgt,
                             expected_error=KDC_ERR_POLICY)

        self.check_as_log(
            client_creds,
            armor_creds=mach_creds,
            client_policy=client_policy,
            client_policy_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.KERBEROS_DEVICE_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED,
            status=ntstatus.NT_STATUS_INVALID_WORKSTATION)

    def test_pac_well_known_groups_not_present(self):
        """Test that authentication fails if the device does not belong to one
        or more required well‐known groups.
        """

        required_sids = {
            (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, self.default_attrs),
            (security.SID_COMPOUNDED_AUTHENTICATION, SidType.EXTRA_SID, self.default_attrs),
            (self.aa_asserted_identity, SidType.EXTRA_SID, self.default_attrs),
            (self.service_asserted_identity, SidType.EXTRA_SID, self.default_attrs),
        }

        device_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
        }

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'id': 'device'})
        mach_tgt = self.get_tgt(mach_creds)

        # Modify the machine account’s TGT to contain only the SID of the
        # machine account’s primary group.
        mach_tgt = self.modified_ticket(
            mach_tgt,
            modify_pac_fn=partial(self.set_pac_sids,
                                  new_sids=device_sids),
            checksum_keys=self.get_krbtgt_checksum_key())

        # Create an authentication policy that requires the device to belong to
        # certain groups.
        client_policy_sddl = self.allow_if(
            f'Member_of_any {self.sddl_array_from_sids(required_sids)}')
        client_policy = self.create_authn_policy(
            enforced=True, user_allowed_from=client_policy_sddl)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=client_policy)

        # Show that authentication fails.
        self._armored_as_req(client_creds,
                             self.get_krbtgt_creds(),
                             mach_tgt,
                             expected_error=KDC_ERR_POLICY)

        self.check_as_log(
            client_creds,
            armor_creds=mach_creds,
            client_policy=client_policy,
            client_policy_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.KERBEROS_DEVICE_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED,
            status=ntstatus.NT_STATUS_INVALID_WORKSTATION)

    def test_pac_device_info(self):
        """Test the groups of the client and the device after performing a
        FAST‐armored AS‐REQ.
        """

        device_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
        }

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'id': 'device'})
        mach_tgt = self.get_tgt(mach_creds)

        # Add the required groups to the machine account’s TGT.
        mach_tgt = self.modified_ticket(
            mach_tgt,
            modify_pac_fn=partial(self.set_pac_sids,
                                  new_sids=device_sids),
            checksum_keys=self.get_krbtgt_checksum_key())

        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER)

        target_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'id': 'target'})

        expected_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            # The client’s groups are to include the Asserted Identity and
            # Claims Valid SIDs.
            (self.aa_asserted_identity, SidType.EXTRA_SID, self.default_attrs),
            (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, self.default_attrs),
        }

        samdb = self.get_samdb()
        domain_sid_str = samdb.get_domain_sid()

        expected_sids = self.map_sids(expected_sids, None, domain_sid_str)

        # Show that authentication succeeds. Check that the groups in the PAC
        # are as expected.
        self._armored_as_req(client_creds,
                             target_creds,
                             mach_tgt,
                             expected_groups=expected_sids,
                             expect_device_info=False,
                             expected_device_groups=None)

        self.check_as_log(
            client_creds,
            armor_creds=mach_creds)

    def test_pac_claims_not_present(self):
        """Test that authentication fails if the device does not have a
        required claim.
        """

        claim_id = 'the name of the claim'
        claim_value = 'the value of the claim'

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'id': 'device'})
        mach_tgt = self.get_tgt(mach_creds)

        # Create an authentication policy that requires the device to have a
        # certain claim.
        client_policy_sddl = self.allow_if(
            f'@User.{escaped_claim_id(claim_id)} == "{claim_value}"')
        client_policy = self.create_authn_policy(
            enforced=True, user_allowed_from=client_policy_sddl)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=client_policy)

        # Show that authentication fails.
        self._armored_as_req(client_creds,
                             self.get_krbtgt_creds(),
                             mach_tgt,
                             expected_error=KDC_ERR_POLICY)

        self.check_as_log(
            client_creds,
            armor_creds=mach_creds,
            client_policy=client_policy,
            client_policy_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.KERBEROS_DEVICE_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED,
            status=ntstatus.NT_STATUS_INVALID_WORKSTATION)

    def test_pac_claims_present(self):
        """Test that authentication succeeds if the device has a required
        claim.
        """

        claim_id = 'the name of the claim'
        claim_value = 'the value of the claim'

        pac_claims = [
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                (claim_id, claims.CLAIM_TYPE_STRING, [claim_value]),
            ]),
        ]

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'id': 'device'})
        mach_tgt = self.get_tgt(mach_creds)

        # Add the required claim to the machine account’s TGT.
        mach_tgt = self.modified_ticket(
            mach_tgt,
            modify_pac_fn=partial(self.set_pac_claims,
                                  client_claims=pac_claims),
            checksum_keys=self.get_krbtgt_checksum_key())

        # Create an authentication policy that requires the device to have a
        # certain claim.
        client_policy_sddl = self.allow_if(
            f'@User.{escaped_claim_id(claim_id)} == "{claim_value}"')
        client_policy = self.create_authn_policy(
            enforced=True, user_allowed_from=client_policy_sddl)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=client_policy)

        # Show that authentication succeeds.
        self._armored_as_req(client_creds,
                             self.get_krbtgt_creds(),
                             mach_tgt)

        self.check_as_log(client_creds,
                          armor_creds=mach_creds,
                          client_policy=client_policy)

    def test_pac_claims_invalid(self):
        """Test that authentication fails if the device’s required claim is not
        valid.
        """

        claim_id = 'the name of the claim'
        claim_value = 'the value of the claim'

        pac_claims = [
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                (claim_id, claims.CLAIM_TYPE_STRING, [claim_value]),
            ]),
        ]

        # The device’s SIDs do not include the Claims Valid SID.
        device_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
        }

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'id': 'device'})
        mach_tgt = self.get_tgt(mach_creds)

        # Add the SIDs and the required claim to the machine account’s TGT.
        mach_tgt = self.modified_ticket(
            mach_tgt,
            modify_pac_fn=[
                partial(self.set_pac_claims, client_claims=pac_claims),
                partial(self.set_pac_sids, new_sids=device_sids)],
            checksum_keys=self.get_krbtgt_checksum_key())

        # Create an authentication policy that requires the device to have a
        # certain claim.
        client_policy_sddl = self.allow_if(
            f'@User.{escaped_claim_id(claim_id)} == "{claim_value}"')
        client_policy = self.create_authn_policy(
            enforced=True, user_allowed_from=client_policy_sddl)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=client_policy)

        # Show that authentication fails.
        self._armored_as_req(client_creds,
                             self.get_krbtgt_creds(),
                             mach_tgt,
                             expected_error=KDC_ERR_POLICY)

        self.check_as_log(
            client_creds,
            armor_creds=mach_creds,
            client_policy=client_policy,
            client_policy_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.KERBEROS_DEVICE_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED,
            status=ntstatus.NT_STATUS_INVALID_WORKSTATION)

    def test_device_in_world_group(self):
        self._check_device_in_group(security.SID_WORLD)

    def test_device_in_network_group(self):
        self._check_device_not_in_group(security.SID_NT_NETWORK)

    def test_device_in_authenticated_users(self):
        self._check_device_in_group(security.SID_NT_AUTHENTICATED_USERS)

    def test_device_in_aa_asserted_identity(self):
        self._check_device_in_group(
            security.SID_AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY)

    def test_device_in_service_asserted_identity(self):
        self._check_device_not_in_group(security.SID_SERVICE_ASSERTED_IDENTITY)

    def test_device_in_compounded_authentication(self):
        self._check_device_not_in_group(security.SID_COMPOUNDED_AUTHENTICATION)

    def test_device_in_claims_valid(self):
        self._check_device_in_group(security.SID_CLAIMS_VALID)

    def _check_device_in_group(self, group):
        self._check_device_membership(group, expect_in_group=True)

    def _check_device_not_in_group(self, group):
        self._check_device_membership(group, expect_in_group=False)

    def _check_device_membership(self, group, *, expect_in_group):
        """Test that authentication succeeds or fails when the device is
        required to belong to a certain group.
        """

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'id': 'device'})
        mach_tgt = self.get_tgt(mach_creds)

        # Create an authentication policy that requires the device to belong to
        # a certain group.
        in_group_sddl = self.allow_if(f'Member_of {{SID({group})}}')
        in_group_policy = self.create_authn_policy(
            enforced=True, user_allowed_from=in_group_sddl)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=in_group_policy)

        krbtgt_creds = self.get_krbtgt_creds()

        # Test whether authentication succeeds or fails.
        self._armored_as_req(
            client_creds,
            krbtgt_creds,
            mach_tgt,
            expected_error=0 if expect_in_group else KDC_ERR_POLICY)

        policy_success_args = {}
        policy_failure_args = {
            'client_policy_status': ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            'event': AuditEvent.KERBEROS_DEVICE_RESTRICTION,
            'reason': AuditReason.ACCESS_DENIED,
            'status': ntstatus.NT_STATUS_INVALID_WORKSTATION,
        }

        self.check_as_log(client_creds,
                          armor_creds=mach_creds,
                          client_policy=in_group_policy,
                          **(policy_success_args if expect_in_group
                             else policy_failure_args))

        # Create an authentication policy that requires the device not to belong
        # to the group.
        not_in_group_sddl = self.allow_if(f'Not_Member_of {{SID({group})}}')
        not_in_group_policy = self.create_authn_policy(
            enforced=True, user_allowed_from=not_in_group_sddl)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=not_in_group_policy)

        # Test whether authentication succeeds or fails.
        self._armored_as_req(
            client_creds,
            krbtgt_creds,
            mach_tgt,
            expected_error=KDC_ERR_POLICY if expect_in_group else 0)

        self.check_as_log(client_creds,
                          armor_creds=mach_creds,
                          client_policy=not_in_group_policy,
                          **(policy_failure_args if expect_in_group
                             else policy_success_args))


class TgsReqServicePolicyTests(ConditionalAceBaseTests):
    def test_pac_groups_not_present(self):
        """Test that authorization succeeds if the client does not belong to
        some required groups.
        """

        required_sids = {
            ('S-1-2-3-4', SidType.EXTRA_SID, self.default_attrs),
            ('S-1-9-8-7', SidType.EXTRA_SID, self.default_attrs),
        }

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'id': 'device'})
        mach_tgt = self.get_tgt(mach_creds)

        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER)
        client_tgt = self.get_tgt(client_creds)

        # Create an authentication policy that requires the client to belong to
        # certain groups.
        target_policy_sddl = self.allow_if(
            f'Member_of {self.sddl_array_from_sids(required_sids)}')
        target_policy = self.create_authn_policy(
            enforced=True, computer_allowed_to=target_policy_sddl)

        # Create a target account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=target_policy)

        # Show that authorization fails.
        self._tgs_req(
            client_tgt, KDC_ERR_POLICY, client_creds, target_creds,
            armor_tgt=mach_tgt,
            expect_edata=self.expect_padata_outer,
            # We aren’t particular about whether or not we get an NTSTATUS.
            expect_status=None,
            expected_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

        self.check_tgs_log(
            client_creds, target_creds,
            policy=target_policy,
            status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

    def test_pac_groups_present(self):
        """Test that authorization succeeds if the client belongs to some
        required groups.
        """

        required_sids = {
            ('S-1-2-3-4', SidType.EXTRA_SID, self.default_attrs),
            ('S-1-9-8-7', SidType.EXTRA_SID, self.default_attrs),
        }

        client_sids = required_sids | {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
        }

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'id': 'device'})
        mach_tgt = self.get_tgt(mach_creds)

        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER)
        client_tgt = self.get_tgt(client_creds)

        # Add the required groups to the client’s TGT.
        client_tgt = self.modified_ticket(
            client_tgt,
            modify_pac_fn=partial(self.set_pac_sids,
                                  new_sids=client_sids),
            checksum_keys=self.get_krbtgt_checksum_key())

        # Create an authentication policy that requires the client to belong to
        # certain groups.
        target_policy_sddl = self.allow_if(
            f'Member_of {self.sddl_array_from_sids(required_sids)}')
        target_policy = self.create_authn_policy(
            enforced=True, computer_allowed_to=target_policy_sddl)

        # Create a target account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=target_policy)

        # Show that authorization succeeds.
        self._tgs_req(client_tgt, 0, client_creds, target_creds, armor_tgt=mach_tgt)

        self.check_tgs_log(client_creds, target_creds,
                           policy=target_policy)

    def test_pac_resource_groups_present_to_service_sid_compression(self):
        """Test that authorization succeeds if the client belongs to some
        required resource groups, and the request is to a service that supports
        SID compression.
        """

        required_sids = {
            ('S-1-2-3-4', SidType.RESOURCE_SID, self.resource_attrs),
            ('S-1-2-3-5', SidType.RESOURCE_SID, self.resource_attrs),
            ('S-1-2-3-6', SidType.RESOURCE_SID, self.resource_attrs),
        }

        client_sids = required_sids | {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
        }

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'id': 'device'})
        mach_tgt = self.get_tgt(mach_creds)

        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER)
        client_tgt = self.get_tgt(client_creds)

        # Add the required groups to the client’s TGT.
        client_tgt = self.modified_ticket(
            client_tgt,
            modify_pac_fn=partial(self.set_pac_sids,
                                  new_sids=client_sids),
            checksum_keys=self.get_krbtgt_checksum_key())

        # Create an authentication policy that requires the client to belong to
        # certain groups.
        target_policy_sddl = self.allow_if(
            f'Member_of {self.sddl_array_from_sids(required_sids)}')
        target_policy = self.create_authn_policy(
            enforced=True, computer_allowed_to=target_policy_sddl)

        # Create a target account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=target_policy)

        # Show that authorization fails.
        self._tgs_req(
            client_tgt, KDC_ERR_POLICY, client_creds, target_creds,
            armor_tgt=mach_tgt,
            expect_edata=self.expect_padata_outer,
            # We aren’t particular about whether or not we get an NTSTATUS.
            expect_status=None,
            expected_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

        self.check_tgs_log(
            client_creds, target_creds,
            policy=target_policy,
            status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

    def test_pac_resource_groups_present_to_service_no_sid_compression(self):
        """Test that authorization succeeds if the client belongs to some
        required resource groups, and the request is to a service that does not
        support SID compression.
        """

        required_sids = {
            ('S-1-2-3-4', SidType.RESOURCE_SID, self.resource_attrs),
            ('S-1-2-3-5', SidType.RESOURCE_SID, self.resource_attrs),
            ('S-1-2-3-6', SidType.RESOURCE_SID, self.resource_attrs),
        }

        client_sids = required_sids | {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
        }

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'id': 'device'})
        mach_tgt = self.get_tgt(mach_creds)

        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER)
        client_tgt = self.get_tgt(client_creds)

        # Add the required groups to the client’s TGT.
        client_tgt = self.modified_ticket(
            client_tgt,
            modify_pac_fn=partial(self.set_pac_sids,
                                  new_sids=client_sids),
            checksum_keys=self.get_krbtgt_checksum_key())

        # Create an authentication policy that requires the client to belong to
        # certain groups.
        target_policy_sddl = self.allow_if(
            f'Member_of {self.sddl_array_from_sids(required_sids)}')
        target_policy = self.create_authn_policy(
            enforced=True, computer_allowed_to=target_policy_sddl)

        # Create a target account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=target_policy,
                                       additional_details={
                                           'msDS-SupportedEncryptionTypes': str((
                                               security.KERB_ENCTYPE_RC4_HMAC_MD5) | (
                                                   security.KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96_SK) | (
                                                       security.KERB_ENCTYPE_RESOURCE_SID_COMPRESSION_DISABLED))})

        # Show that authorization fails.
        self._tgs_req(
            client_tgt, KDC_ERR_POLICY, client_creds, target_creds,
            armor_tgt=mach_tgt,
            expect_edata=self.expect_padata_outer,
            # We aren’t particular about whether or not we get an NTSTATUS.
            expect_status=None,
            expected_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

        self.check_tgs_log(
            client_creds, target_creds,
            policy=target_policy,
            status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

    def test_pac_well_known_groups_not_present(self):
        """Test that authorization fails if the client does not belong to one
        or more required well‐known groups.
        """

        required_sids = {
            (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, self.default_attrs),
            (security.SID_COMPOUNDED_AUTHENTICATION, SidType.EXTRA_SID, self.default_attrs),
            (self.aa_asserted_identity, SidType.EXTRA_SID, self.default_attrs),
            (self.service_asserted_identity, SidType.EXTRA_SID, self.default_attrs),
        }

        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
        }

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'id': 'device'})
        mach_tgt = self.get_tgt(mach_creds)

        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER)
        client_tgt = self.get_tgt(client_creds)

        # Modify the client’s TGT to contain only the SID of the client’s
        # primary group.
        client_tgt = self.modified_ticket(
            client_tgt,
            modify_pac_fn=partial(self.set_pac_sids,
                                  new_sids=client_sids),
            checksum_keys=self.get_krbtgt_checksum_key())

        # Create an authentication policy that requires the client to belong to
        # certain groups.
        target_policy_sddl = self.allow_if(
            f'Member_of_any {self.sddl_array_from_sids(required_sids)}')
        target_policy = self.create_authn_policy(
            enforced=True, computer_allowed_to=target_policy_sddl)

        # Create a target account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=target_policy)

        # Show that authorization fails.
        self._tgs_req(
            client_tgt, KDC_ERR_POLICY, client_creds, target_creds,
            armor_tgt=mach_tgt,
            expect_edata=self.expect_padata_outer,
            # We aren’t particular about whether or not we get an NTSTATUS.
            expect_status=None,
            expected_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

        self.check_tgs_log(
            client_creds, target_creds,
            policy=target_policy,
            status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

    def test_pac_device_info(self):
        self._run_pac_device_info_test()

    def test_pac_device_info_target_policy(self):
        target_policy = self.allow_if('Device_Member_of {{SID({device_0})}}')
        self._run_pac_device_info_test(target_policy=target_policy)

    def test_pac_device_info_rodc_issued(self):
        self._run_pac_device_info_test(rodc_issued=True)

    def test_pac_device_info_existing_device_info(self):
        self._run_pac_device_info_test(existing_device_info=True)

    def test_pac_device_info_existing_device_info_target_policy(self):
        target_policy = self.allow_if('Device_Member_of {{SID({device_0})}}')
        self._run_pac_device_info_test(target_policy=target_policy,
                                       existing_device_info=True)

    def test_pac_device_info_existing_device_info_rodc_issued(self):
        self._run_pac_device_info_test(rodc_issued=True,
                                       existing_device_info=True)

    def test_pac_device_info_existing_device_claims(self):
        self._run_pac_device_info_test(existing_device_claims=True)

    def test_pac_device_info_existing_device_claims_target_policy(self):
        target_policy = self.allow_if('Device_Member_of {{SID({device_0})}}')
        self._run_pac_device_info_test(target_policy=target_policy,
                                       existing_device_claims=True)

    def test_pac_device_info_existing_device_claims_rodc_issued(self):
        self._run_pac_device_info_test(rodc_issued=True,
                                       existing_device_claims=True)

    def test_pac_device_info_existing_device_info_and_claims(self):
        self._run_pac_device_info_test(existing_device_claims=True,
                                       existing_device_info=True)

    def test_pac_device_info_existing_device_info_and_claims_target_policy(self):
        target_policy = self.allow_if('Device_Member_of {{SID({device_0})}}')
        self._run_pac_device_info_test(target_policy=target_policy,
                                       existing_device_claims=True,
                                       existing_device_info=True)

    def test_pac_device_info_existing_device_info_and_claims_rodc_issued(self):
        self._run_pac_device_info_test(rodc_issued=True,
                                       existing_device_claims=True,
                                       existing_device_info=True)

    def test_pac_device_info_no_compound_id_support(self):
        self._run_pac_device_info_test(compound_id_support=False)

    def test_pac_device_info_no_compound_id_support_target_policy(self):
        target_policy = self.allow_if('Device_Member_of {{SID({device_0})}}')
        self._run_pac_device_info_test(target_policy=target_policy,
                                       compound_id_support=False)

    def test_pac_device_info_no_compound_id_support_rodc_issued(self):
        self._run_pac_device_info_test(rodc_issued=True,
                                       compound_id_support=False)

    def test_pac_device_info_no_compound_id_support_existing_device_info(self):
        self._run_pac_device_info_test(compound_id_support=False,
                                       existing_device_info=True)

    def test_pac_device_info_no_compound_id_support_existing_device_info_target_policy(self):
        target_policy = self.allow_if('Device_Member_of {{SID({device_0})}}')
        self._run_pac_device_info_test(target_policy=target_policy,
                                       compound_id_support=False,
                                       existing_device_info=True)

    def test_pac_device_info_no_compound_id_support_existing_device_info_rodc_issued(self):
        self._run_pac_device_info_test(rodc_issued=True,
                                       compound_id_support=False,
                                       existing_device_info=True)

    def test_pac_device_info_no_compound_id_support_existing_device_claims(self):
        self._run_pac_device_info_test(compound_id_support=False,
                                       existing_device_claims=True)

    def test_pac_device_info_no_compound_id_support_existing_device_claims_target_policy(self):
        target_policy = self.allow_if('Device_Member_of {{SID({device_0})}}')
        self._run_pac_device_info_test(target_policy=target_policy,
                                       compound_id_support=False,
                                       existing_device_claims=True)

    def test_pac_device_info_no_compound_id_support_existing_device_claims_rodc_issued(self):
        self._run_pac_device_info_test(rodc_issued=True,
                                       compound_id_support=False,
                                       existing_device_claims=True)

    def test_pac_device_info_no_compound_id_support_existing_device_info_and_claims(self):
        self._run_pac_device_info_test(compound_id_support=False,
                                       existing_device_claims=True,
                                       existing_device_info=True)

    def test_pac_device_info_no_compound_id_support_existing_device_info_and_claims_target_policy(self):
        target_policy = self.allow_if('Device_Member_of {{SID({device_0})}}')
        self._run_pac_device_info_test(target_policy=target_policy,
                                       compound_id_support=False,
                                       existing_device_claims=True,
                                       existing_device_info=True)

    def test_pac_device_info_no_compound_id_support_existing_device_info_and_claims_rodc_issued(self):
        self._run_pac_device_info_test(rodc_issued=True,
                                       compound_id_support=False,
                                       existing_device_claims=True,
                                       existing_device_info=True)

    def test_pac_device_info_no_compound_id_support_no_claims_valid_existing_device_info(self):
        self._run_pac_device_info_test(device_claims_valid=False,
                                       compound_id_support=False,
                                       existing_device_info=True)

    def test_pac_device_info_no_compound_id_support_no_claims_valid_existing_device_info_target_policy(self):
        target_policy = self.allow_if('Device_Member_of {{SID({device_0})}}')
        self._run_pac_device_info_test(target_policy=target_policy,
                                       device_claims_valid=False,
                                       compound_id_support=False,
                                       existing_device_info=True)

    def test_pac_device_info_no_compound_id_support_no_claims_valid_existing_device_info_rodc_issued(self):
        self._run_pac_device_info_test(rodc_issued=True,
                                       device_claims_valid=False,
                                       compound_id_support=False,
                                       existing_device_info=True)

    def test_pac_device_info_no_compound_id_support_no_claims_valid_existing_device_claims(self):
        self._run_pac_device_info_test(device_claims_valid=False,
                                       compound_id_support=False,
                                       existing_device_claims=True)

    def test_pac_device_info_no_compound_id_support_no_claims_valid_existing_device_claims_target_policy(self):
        target_policy = self.allow_if('Device_Member_of {{SID({device_0})}}')
        self._run_pac_device_info_test(target_policy=target_policy,
                                       device_claims_valid=False,
                                       compound_id_support=False,
                                       existing_device_claims=True)

    def test_pac_device_info_no_compound_id_support_no_claims_valid_existing_device_claims_rodc_issued(self):
        self._run_pac_device_info_test(rodc_issued=True,
                                       device_claims_valid=False,
                                       compound_id_support=False,
                                       existing_device_claims=True)

    def test_pac_device_info_no_compound_id_support_no_claims_valid_existing_device_info_and_claims(self):
        self._run_pac_device_info_test(device_claims_valid=False,
                                       compound_id_support=False,
                                       existing_device_claims=True,
                                       existing_device_info=True)

    def test_pac_device_info_no_compound_id_support_no_claims_valid_existing_device_info_and_claims_target_policy(self):
        target_policy = self.allow_if('Device_Member_of {{SID({device_0})}}')
        self._run_pac_device_info_test(target_policy=target_policy,
                                       device_claims_valid=False,
                                       compound_id_support=False,
                                       existing_device_claims=True,
                                       existing_device_info=True)

    def test_pac_device_info_no_compound_id_support_no_claims_valid_existing_device_info_and_claims_rodc_issued(self):
        self._run_pac_device_info_test(rodc_issued=True,
                                       device_claims_valid=False,
                                       compound_id_support=False,
                                       existing_device_claims=True,
                                       existing_device_info=True)

    def test_pac_device_info_no_claims_valid(self):
        self._run_pac_device_info_test(device_claims_valid=False)

    def test_pac_device_info_no_claims_valid_target_policy(self):
        target_policy = self.allow_if('Device_Member_of {{SID({device_0})}}')
        self._run_pac_device_info_test(target_policy=target_policy,
                                       device_claims_valid=False)

    def test_pac_device_info_no_claims_valid_rodc_issued(self):
        self._run_pac_device_info_test(rodc_issued=True,
                                       device_claims_valid=False)

    def test_pac_device_info_no_claims_valid_existing_device_info(self):
        self._run_pac_device_info_test(device_claims_valid=False,
                                       existing_device_info=True)

    def test_pac_device_info_no_claims_valid_existing_device_info_target_policy(self):
        target_policy = self.allow_if('Device_Member_of {{SID({device_0})}}')
        self._run_pac_device_info_test(target_policy=target_policy,
                                       device_claims_valid=False,
                                       existing_device_info=True)

    def test_pac_device_info_no_claims_valid_existing_device_info_rodc_issued(self):
        self._run_pac_device_info_test(rodc_issued=True,
                                       device_claims_valid=False,
                                       existing_device_info=True)

    def test_pac_device_info_no_claims_valid_existing_device_claims(self):
        self._run_pac_device_info_test(device_claims_valid=False,
                                       existing_device_claims=True)

    def test_pac_device_info_no_claims_valid_existing_device_claims_target_policy(self):
        target_policy = self.allow_if('Device_Member_of {{SID({device_0})}}')
        self._run_pac_device_info_test(target_policy=target_policy,
                                       device_claims_valid=False,
                                       existing_device_claims=True)

    def test_pac_device_info_no_claims_valid_existing_device_claims_rodc_issued(self):
        self._run_pac_device_info_test(rodc_issued=True,
                                       device_claims_valid=False,
                                       existing_device_claims=True)

    def test_pac_device_info_no_claims_valid_existing_device_info_and_claims(self):
        self._run_pac_device_info_test(device_claims_valid=False,
                                       existing_device_claims=True,
                                       existing_device_info=True)

    def test_pac_device_info_no_claims_valid_existing_device_info_and_claims_target_policy(self):
        target_policy = self.allow_if('Device_Member_of {{SID({device_0})}}')
        self._run_pac_device_info_test(target_policy=target_policy,
                                       device_claims_valid=False,
                                       existing_device_claims=True,
                                       existing_device_info=True)

    def test_pac_device_info_no_claims_valid_existing_device_info_and_claims_rodc_issued(self):
        self._run_pac_device_info_test(rodc_issued=True,
                                       device_claims_valid=False,
                                       existing_device_claims=True,
                                       existing_device_info=True)

    def _run_pac_device_info_test(self, *,
                                  target_policy=None,
                                  rodc_issued=False,
                                  compound_id_support=True,
                                  device_claims_valid=True,
                                  existing_device_claims=False,
                                  existing_device_info=False):
        """Test the groups of the client and the device after performing a
        FAST‐armored TGS‐REQ.
        """

        client_claim_id = 'the name of the client’s client claim'
        client_claim_value = 'the value of the client’s client claim'

        client_claims = [
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                (client_claim_id, claims.CLAIM_TYPE_STRING, [client_claim_value]),
            ]),
        ]

        if not rodc_issued:
            expected_client_claims = {
                client_claim_id: {
                    'source_type': claims.CLAIMS_SOURCE_TYPE_AD,
                    'type': claims.CLAIM_TYPE_STRING,
                    'values': (client_claim_value,),
                },
            }
        else:
            expected_client_claims = None

        device_claim_id = 'the name of the device’s client claim'
        device_claim_value = 'the value of the device’s client claim'

        device_claims = [
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                (device_claim_id, claims.CLAIM_TYPE_STRING, [device_claim_value]),
            ]),
        ]

        existing_claim_id = 'the name of an existing device claim'
        existing_claim_value = 'the value of an existing device claim'

        existing_claims = [
            (claims.CLAIMS_SOURCE_TYPE_CERTIFICATE, [
                (existing_claim_id, claims.CLAIM_TYPE_STRING, [existing_claim_value]),
            ]),
        ]

        if rodc_issued:
            expected_device_claims = None
        elif existing_device_info and existing_device_claims:
            expected_device_claims = {
                existing_claim_id: {
                    'source_type': claims.CLAIMS_SOURCE_TYPE_CERTIFICATE,
                    'type': claims.CLAIM_TYPE_STRING,
                    'values': (existing_claim_value,),
                },
            }
        elif compound_id_support and not existing_device_info and not existing_device_claims:
            expected_device_claims = {
                device_claim_id: {
                    'source_type': claims.CLAIMS_SOURCE_TYPE_AD,
                    'type': claims.CLAIM_TYPE_STRING,
                    'values': (device_claim_value,),
                },
            }
        else:
            expected_device_claims = None

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'id': 'device'})
        mach_tgt = self.get_tgt(mach_creds)

        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            # This to ensure we have EXTRA_SIDS set already, as
            # windows won't set that flag otherwise when adding one
            # more
            ('S-1-2-3-4', SidType.EXTRA_SID, self.default_attrs),
        }

        device_sid_0 = 'S-1-3-4-5'
        device_sid_1 = 'S-1-4-5-6'

        policy_sids = {
            'device_0': device_sid_0,
            'device_1': device_sid_1,
        }

        device_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            (device_sid_0, SidType.EXTRA_SID, self.resource_attrs),
            (device_sid_1, SidType.EXTRA_SID, self.resource_attrs),
        }

        if device_claims_valid:
            device_sids.add((security.SID_CLAIMS_VALID, SidType.EXTRA_SID, self.default_attrs))

        checksum_key = self.get_krbtgt_checksum_key()

        # Modify the machine account’s TGT to contain only the SID of the
        # machine account’s primary group.
        mach_tgt = self.modified_ticket(
            mach_tgt,
            modify_pac_fn=[
                partial(self.set_pac_sids,
                        new_sids=device_sids),
                partial(self.set_pac_claims, client_claims=device_claims),
            ],
            checksum_keys=checksum_key)

        # Create a user account.
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER,
            opts={
                'allowed_replication_mock': rodc_issued,
                'revealed_to_mock_rodc': rodc_issued,
            })
        client_tgt = self.get_tgt(client_creds)

        client_modify_pac_fns = [
            partial(self.set_pac_sids,
                    new_sids=client_sids),
            partial(self.set_pac_claims, client_claims=client_claims),
        ]

        if existing_device_claims:
            client_modify_pac_fns.append(
                partial(self.set_pac_claims, device_claims=existing_claims))
        if existing_device_info:
            # These are different from the SIDs in the device’s TGT.
            existing_sid_0 = 'S-1-7-8-9'
            existing_sid_1 = 'S-1-9-8-7'

            policy_sids.update({
                'existing_0': existing_sid_0,
                'existing_1': existing_sid_1,
            })

            existing_sids = {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (existing_sid_0, SidType.EXTRA_SID, self.resource_attrs),
                (existing_sid_1, SidType.EXTRA_SID, self.resource_attrs),
            }

            client_modify_pac_fns.append(partial(
                self.set_pac_device_sids, new_sids=existing_sids, user_rid=mach_creds.get_rid()))

        if rodc_issued:
            rodc_krbtgt_creds = self.get_mock_rodc_krbtgt_creds()
            rodc_krbtgt_key = self.TicketDecryptionKey_from_creds(rodc_krbtgt_creds)
            rodc_checksum_key = {
                krb5pac.PAC_TYPE_KDC_CHECKSUM: rodc_krbtgt_key,
            }

        # Modify the client’s TGT to contain only the SID of the client’s
        # primary group.
        client_tgt = self.modified_ticket(
            client_tgt,
            modify_pac_fn=client_modify_pac_fns,
            new_ticket_key=rodc_krbtgt_key if rodc_issued else None,
            checksum_keys=rodc_checksum_key if rodc_issued else checksum_key)

        if target_policy is None:
            policy = None
            assigned_policy = None
        else:
            policy = self.create_authn_policy(
                enforced=True,
                computer_allowed_to=target_policy.format_map(policy_sids))
            assigned_policy = str(policy.dn)

        target_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={
                'supported_enctypes':
                    security.KERB_ENCTYPE_RC4_HMAC_MD5
                    | security.KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96,
                # Indicate that Compound Identity is supported.
                'compound_id_support': compound_id_support,
                'assigned_policy': assigned_policy,
            })

        expected_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            # The client’s groups are not to include the Asserted Identity and
            # Claims Valid SIDs.
        }
        if rodc_issued:
            expected_sids.add((security.SID_CLAIMS_VALID, SidType.EXTRA_SID, self.default_attrs))
        else:
            expected_sids.add(('S-1-2-3-4', SidType.EXTRA_SID, self.default_attrs))

        if rodc_issued:
            expected_device_sids = None
        elif existing_device_info:
            expected_device_sids = {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                ('S-1-7-8-9', SidType.EXTRA_SID, self.resource_attrs),
                ('S-1-9-8-7', SidType.EXTRA_SID, self.resource_attrs),
            }
        elif compound_id_support and not existing_device_claims:
            expected_sids.add((security.SID_COMPOUNDED_AUTHENTICATION, SidType.EXTRA_SID, self.default_attrs))

            expected_device_sids = {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                ('S-1-3-4-5', SidType.EXTRA_SID, self.resource_attrs),
                ('S-1-4-5-6', SidType.EXTRA_SID, self.resource_attrs),
            }

            if device_claims_valid:
                expected_device_sids.add(frozenset([(security.SID_CLAIMS_VALID, SidType.RESOURCE_SID, self.default_attrs)]))
        else:
            expected_device_sids = None

        samdb = self.get_samdb()
        domain_sid_str = samdb.get_domain_sid()

        expected_sids = self.map_sids(expected_sids, None, domain_sid_str)
        # The device SIDs will be put into the PAC unmodified.
        expected_device_sids = self.map_sids(expected_device_sids, None, domain_sid_str)

        # Show that authorization succeeds.
        self._tgs_req(client_tgt, 0, client_creds, target_creds, armor_tgt=mach_tgt,
                      expected_groups=expected_sids,
                      expect_device_info=bool(expected_device_sids),
                      expected_device_domain_sid=domain_sid_str,
                      expected_device_groups=expected_device_sids,
                      expect_client_claims=True,
                      expected_client_claims=expected_client_claims,
                      expect_device_claims=bool(expected_device_claims),
                      expected_device_claims=expected_device_claims)

        self.check_tgs_log(client_creds, target_creds, policy=policy)

    def test_pac_extra_sids_behaviour(self):
        """Test the groups of the client and the device after performing a
        FAST‐armored TGS‐REQ.
        """

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'id': 'device'})
        mach_tgt = self.get_tgt(mach_creds)

        client_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
        }

        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER)
        client_tgt = self.get_tgt(client_creds)

        # Modify the client’s TGT to contain only the SID of the client’s
        # primary group.
        client_tgt = self.modified_ticket(
            client_tgt,
            modify_pac_fn=partial(self.set_pac_sids,
                                  new_sids=client_sids),
            checksum_keys=self.get_krbtgt_checksum_key())

        # Indicate that Compound Identity is supported.
        target_creds, _ = self.get_target(to_krbtgt=False, compound_id=True)

        expected_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            (security.SID_COMPOUNDED_AUTHENTICATION, SidType.EXTRA_SID, self.default_attrs)
            # The client’s groups are not to include the Asserted Identity and
            # Claims Valid SIDs.
        }

        samdb = self.get_samdb()
        domain_sid_str = samdb.get_domain_sid()

        expected_sids = self.map_sids(expected_sids, None, domain_sid_str)

        # Show that authorization succeeds.
        self._tgs_req(client_tgt, 0, client_creds, target_creds, armor_tgt=mach_tgt,
                      expected_groups=expected_sids)

        self.check_tgs_log(client_creds, target_creds)

    def test_pac_claims_not_present(self):
        """Test that authentication fails if the device does not have a
        required claim.
        """

        claim_id = 'the name of the claim'
        claim_value = 'the value of the claim'

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'id': 'device'})
        mach_tgt = self.get_tgt(mach_creds)

        # Create an authentication policy that requires the device to have a
        # certain claim.
        target_policy_sddl = self.allow_if(
            f'@User.{escaped_claim_id(claim_id)} == "{claim_value}"')
        target_policy = self.create_authn_policy(
            enforced=True, computer_allowed_to=target_policy_sddl)

        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER)
        client_tgt = self.get_tgt(client_creds)

        # Create a target account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=target_policy)

        # Show that authorization fails.
        self._tgs_req(
            client_tgt, KDC_ERR_POLICY, client_creds, target_creds,
            armor_tgt=mach_tgt,
            expect_edata=self.expect_padata_outer,
            # We aren’t particular about whether or not we get an NTSTATUS.
            expect_status=None,
            expected_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

        self.check_tgs_log(
            client_creds,
            target_creds,
            policy=target_policy,
            status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

    def test_pac_claims_present(self):
        """Test that authentication succeeds if the user has a required
        claim.
        """

        claim_id = 'the name of the claim'
        claim_value = 'the value of the claim'

        pac_claims = [
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                (claim_id, claims.CLAIM_TYPE_STRING, [claim_value]),
            ]),
        ]

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'id': 'device'})
        mach_tgt = self.get_tgt(mach_creds)

        # Create an authentication policy that requires the user to have a
        # certain claim.
        target_policy_sddl = self.allow_if(
            f'@User.{escaped_claim_id(claim_id)} == "{claim_value}"')
        target_policy = self.create_authn_policy(
            enforced=True, computer_allowed_to=target_policy_sddl)

        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER)
        client_tgt = self.get_tgt(client_creds)

        # Add the required claim to the client’s TGT.
        client_tgt = self.modified_ticket(
            client_tgt,
            modify_pac_fn=partial(self.set_pac_claims,
                                  client_claims=pac_claims),
            checksum_keys=self.get_krbtgt_checksum_key())

        # Create a target account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=target_policy)

        # Show that authorization succeeds.
        self._tgs_req(client_tgt, 0, client_creds, target_creds, armor_tgt=mach_tgt)

        self.check_tgs_log(client_creds, target_creds,
                           policy=target_policy)

    def test_pac_claims_invalid(self):
        """Test that authentication fails if the device’s required claim is not
        valid.
        """

        claim_id = 'the name of the claim'
        claim_value = 'the value of the claim'

        pac_claims = [
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                (claim_id, claims.CLAIM_TYPE_STRING, [claim_value]),
            ]),
        ]

        # The device’s SIDs do not include the Claims Valid SID.
        device_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
        }

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'id': 'device'})
        mach_tgt = self.get_tgt(mach_creds)

        # Create an authentication policy that requires the device to have a
        # certain claim.
        target_policy_sddl = self.allow_if(
            f'@User.{escaped_claim_id(claim_id)} == "{claim_value}"')
        target_policy = self.create_authn_policy(
            enforced=True, computer_allowed_to=target_policy_sddl)

        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER)
        client_tgt = self.get_tgt(client_creds)

        # Add the SIDs and the required claim to the client’s TGT.
        client_tgt = self.modified_ticket(
            client_tgt,
            modify_pac_fn=[
                partial(self.set_pac_claims, client_claims=pac_claims),
                partial(self.set_pac_sids, new_sids=device_sids)],
            checksum_keys=self.get_krbtgt_checksum_key())

        # Create a target account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=target_policy)

        # Show that authorization fails.
        self._tgs_req(
            client_tgt, KDC_ERR_POLICY, client_creds, target_creds,
            armor_tgt=mach_tgt,
            expect_edata=self.expect_padata_outer,
            # We aren’t particular about whether or not we get an NTSTATUS.
            expect_status=None,
            expected_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

        self.check_tgs_log(
            client_creds,
            target_creds,
            policy=target_policy,
            status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

    def test_pac_device_claims_not_present(self):
        """Test that authorization fails if the device does not have a
        required claim.
        """

        claim_id = 'the name of the claim'
        claim_value = 'the value of the claim'

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'id': 'device'})
        mach_tgt = self.get_tgt(mach_creds)

        # Create an authentication policy that requires the device to have a
        # certain device claim.
        target_policy_sddl = self.allow_if(
            f'@Device.{escaped_claim_id(claim_id)} == "{claim_value}"')
        target_policy = self.create_authn_policy(
            enforced=True, computer_allowed_to=target_policy_sddl)

        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER)
        client_tgt = self.get_tgt(client_creds)

        # Create a target account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=target_policy)

        # Show that authorization fails.
        self._tgs_req(
            client_tgt, KDC_ERR_POLICY, client_creds, target_creds,
            armor_tgt=mach_tgt,
            expect_edata=self.expect_padata_outer,
            # We aren’t particular about whether or not we get an NTSTATUS.
            expect_status=None,
            expected_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

        self.check_tgs_log(
            client_creds,
            target_creds,
            policy=target_policy,
            status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

    def test_pac_device_claims_present(self):
        """Test that authorization succeeds if the device has a required claim.
        """

        claim_id = 'the name of the claim'
        claim_value = 'the value of the claim'

        pac_claims = [
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                (claim_id, claims.CLAIM_TYPE_STRING, [claim_value]),
            ]),
        ]

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'id': 'device'})
        mach_tgt = self.get_tgt(mach_creds)

        # Add the required claim to the machine account’s TGT.
        mach_tgt = self.modified_ticket(
            mach_tgt,
            modify_pac_fn=partial(self.set_pac_claims,
                                  client_claims=pac_claims),
            checksum_keys=self.get_krbtgt_checksum_key())

        # Create an authentication policy that requires the device to have a
        # certain device claim.
        target_policy_sddl = self.allow_if(
            f'@Device.{escaped_claim_id(claim_id)} == "{claim_value}"')
        target_policy = self.create_authn_policy(
            enforced=True, computer_allowed_to=target_policy_sddl)

        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER)
        client_tgt = self.get_tgt(client_creds)

        # Create a target account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=target_policy)

        # Show that authorization succeeds.
        self._tgs_req(client_tgt, 0, client_creds, target_creds, armor_tgt=mach_tgt)

        self.check_tgs_log(client_creds, target_creds,
                           policy=target_policy)

    def test_pac_device_claims_invalid(self):
        """Test that authorization fails if the device’s required claim is not
        valid.
        """

        claim_id = 'the name of the claim'
        claim_value = 'the value of the claim'

        pac_claims = [
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                (claim_id, claims.CLAIM_TYPE_STRING, [claim_value]),
            ]),
        ]

        # The device’s SIDs do not include the Claims Valid SID.
        device_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
        }

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'id': 'device'})
        mach_tgt = self.get_tgt(mach_creds)

        # Add the SIDs and the required claim to the machine account’s TGT.
        mach_tgt = self.modified_ticket(
            mach_tgt,
            modify_pac_fn=[
                partial(self.set_pac_claims, client_claims=pac_claims),
                partial(self.set_pac_sids, new_sids=device_sids)],
            checksum_keys=self.get_krbtgt_checksum_key())

        # Create an authentication policy that requires the device to have a
        # certain claim.
        target_policy_sddl = self.allow_if(
            f'@Device.{escaped_claim_id(claim_id)} == "{claim_value}"')
        target_policy = self.create_authn_policy(
            enforced=True, computer_allowed_to=target_policy_sddl)

        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER)
        client_tgt = self.get_tgt(client_creds)

        # Create a target account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=target_policy)

        # Show that authorization fails.
        self._tgs_req(
            client_tgt, KDC_ERR_POLICY, client_creds, target_creds,
            armor_tgt=mach_tgt,
            expect_edata=self.expect_padata_outer,
            # We aren’t particular about whether or not we get an NTSTATUS.
            expect_status=None,
            expected_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

        self.check_tgs_log(
            client_creds,
            target_creds,
            policy=target_policy,
            status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

    def test_pac_device_claims_invalid_no_attrs(self):
        """Test that authorization fails if the device’s required claim is not
        valid.
        """

        claim_id = 'the name of the claim'
        claim_value = 'the value of the claim'

        pac_claims = [
            (claims.CLAIMS_SOURCE_TYPE_AD, [
                (claim_id, claims.CLAIM_TYPE_STRING, [claim_value]),
            ]),
        ]

        device_sids = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            # The device’s SIDs include the Claims Valid SID, but it has no
            # attributes.
            (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, 0),
        }

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'id': 'device'})
        mach_tgt = self.get_tgt(mach_creds)

        # Add the SIDs and the required claim to the machine account’s TGT.
        mach_tgt = self.modified_ticket(
            mach_tgt,
            modify_pac_fn=[
                partial(self.set_pac_claims, client_claims=pac_claims),
                partial(self.set_pac_sids, new_sids=device_sids)],
            checksum_keys=self.get_krbtgt_checksum_key())

        # Create an authentication policy that requires the device to have a
        # certain claim.
        target_policy_sddl = self.allow_if(
            f'@Device.{escaped_claim_id(claim_id)} == "{claim_value}"')
        target_policy = self.create_authn_policy(
            enforced=True, computer_allowed_to=target_policy_sddl)

        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER)
        client_tgt = self.get_tgt(client_creds)

        # Create a target account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=target_policy)

        # Show that authorization succeeds.
        self._tgs_req(client_tgt, 0, client_creds, target_creds, armor_tgt=mach_tgt)

        self.check_tgs_log(client_creds, target_creds,
                           policy=target_policy)

    def test_simple_as_req_client_and_target_policy(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create an authentication policy that explicitly allows the machine
        # account for a user.
        client_policy_sddl = f'O:SYD:(XA;;CR;;;{mach_creds.get_sid()};(Member_of {{SID({mach_creds.get_sid()}), SID({mach_creds.get_sid()})}}))'
        client_policy = self.create_authn_policy(enforced=True,
                                                 user_allowed_from=client_policy_sddl)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=client_policy)

        # Create an authentication policy that applies to a computer and
        # explicitly allows the user account to obtain a service ticket.
        target_policy_sddl = f'O:SYD:(XA;;CR;;;{client_creds.get_sid()};(Member_of SID({client_creds.get_sid()})))'
        target_policy = self.create_authn_policy(enforced=True,
                                                 computer_allowed_to=target_policy_sddl)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=target_policy)

        expected_groups = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            (security.SID_AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY, SidType.EXTRA_SID, self.default_attrs),
            (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, self.default_attrs),
        }

        # Show that obtaining a service ticket with an AS‐REQ is allowed.
        self._armored_as_req(client_creds,
                             target_creds,
                             mach_tgt,
                             expected_groups=expected_groups)

        self.check_as_log(client_creds,
                          armor_creds=mach_creds,
                          client_policy=client_policy,
                          server_policy=target_policy)

    def test_device_in_world_group(self):
        self._check_device_in_group(security.SID_WORLD)

    def test_device_in_network_group(self):
        self._check_device_not_in_group(security.SID_NT_NETWORK)

    def test_device_in_authenticated_users(self):
        self._check_device_in_group(security.SID_NT_AUTHENTICATED_USERS)

    def test_device_in_aa_asserted_identity(self):
        self._check_device_in_group(
            security.SID_AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY)

    def test_device_in_service_asserted_identity(self):
        self._check_device_not_in_group(security.SID_SERVICE_ASSERTED_IDENTITY)

    def test_device_in_compounded_authentication(self):
        self._check_device_not_in_group(security.SID_COMPOUNDED_AUTHENTICATION)

    def test_device_in_claims_valid(self):
        self._check_device_in_group(security.SID_CLAIMS_VALID)

    def _check_device_in_group(self, group):
        self._check_device_membership(group, expect_in_group=True)

    def _check_device_not_in_group(self, group):
        self._check_device_membership(group, expect_in_group=False)

    def _check_device_membership(self, group, *, expect_in_group):
        """Test that authentication succeeds or fails when the device is
        required to belong to a certain group.
        """

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'id': 'device'})
        mach_tgt = self.get_tgt(mach_creds)

        # Create an authentication policy that requires the device to belong to
        # a certain group.
        in_group_sddl = self.allow_if(f'Device_Member_of {{SID({group})}}')
        in_group_policy = self.create_authn_policy(
            enforced=True, computer_allowed_to=in_group_sddl)

        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER)
        client_tgt = self.get_tgt(client_creds)

        # Create a target account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=in_group_policy)

        tgs_success_args = {}
        tgs_failure_args = {
            'expect_edata': self.expect_padata_outer,
            # We aren’t particular about whether or not we get an NTSTATUS.
            'expect_status': None,
            'expected_status': ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
        }

        # Test whether authorization succeeds or fails.
        self._tgs_req(client_tgt,
                      0 if expect_in_group else KDC_ERR_POLICY,
                      client_creds,
                      target_creds,
                      armor_tgt=mach_tgt,
                      **(tgs_success_args if expect_in_group
                      else tgs_failure_args))

        policy_success_args = {}
        policy_failure_args = {
            'status': ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            'event': AuditEvent.KERBEROS_SERVER_RESTRICTION,
            'reason': AuditReason.ACCESS_DENIED,
        }

        self.check_tgs_log(client_creds, target_creds,
                           policy=in_group_policy,
                           **(policy_success_args if expect_in_group
                           else policy_failure_args))

        # Create an authentication policy that requires the device not to belong
        # to the group.
        not_in_group_sddl = self.allow_if(
            f'Not_Device_Member_of {{SID({group})}}')
        not_in_group_policy = self.create_authn_policy(
            enforced=True, computer_allowed_to=not_in_group_sddl)

        # Create a target account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=not_in_group_policy)

        # Test whether authorization succeeds or fails.
        self._tgs_req(client_tgt,
                      KDC_ERR_POLICY if expect_in_group else 0,
                      client_creds,
                      target_creds,
                      armor_tgt=mach_tgt,
                      **(tgs_failure_args if expect_in_group
                      else tgs_success_args))

        self.check_tgs_log(client_creds, target_creds,
                           policy=not_in_group_policy,
                           **(policy_failure_args if expect_in_group
                              else policy_success_args))

    def test_simple_as_req_client_policy_only(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create an authentication policy that explicitly allows the machine
        # account for a user.
        client_policy_sddl = f'O:SYD:(XA;;CR;;;{mach_creds.get_sid()};(Member_of SID({mach_creds.get_sid()})))'
        client_policy = self.create_authn_policy(enforced=True,
                                                 user_allowed_from=client_policy_sddl)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=client_policy)

        expected_groups = {
            (security.DOMAIN_RID_USERS, SidType.BASE_SID, self.default_attrs),
            (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            (security.SID_AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY, SidType.EXTRA_SID, self.default_attrs),
            (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, self.default_attrs),
        }

        # Show that obtaining a service ticket with an AS‐REQ is allowed.
        self._armored_as_req(client_creds,
                             self.get_krbtgt_creds(),
                             mach_tgt,
                             expected_groups=expected_groups)

        self.check_as_log(client_creds,
                          armor_creds=mach_creds,
                          client_policy=client_policy)


class SamLogonTests(ConditionalAceBaseTests):
    # These tests show that although conditional ACEs work with SamLogon,
    # claims do not appear to be used at all.

    def test_samlogon_allowed_to_computer_member_of(self):
        # Create an authentication policy that applies to a computer and
        # requires that the account should belong to both groups.
        allowed = (f'O:SYD:(XA;;CR;;;WD;(Member_of '
                   f'{{SID({self._group0_sid}), SID({self._group1_sid})}}))')
        policy = self.create_authn_policy(enforced=True,
                                          computer_allowed_to=allowed)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # When the account is a member of both groups, network SamLogon
        # succeeds.
        self._test_samlogon(creds=self._member_of_both_creds_ntlm,
                            domain_joined_mach_creds=target_creds,
                            logon_type=netlogon.NetlogonNetworkInformation)

        self.check_samlogon_network_log(self._member_of_both_creds_ntlm,
                                        server_policy=policy)

        # Interactive SamLogon also succeeds.
        self._test_samlogon(creds=self._member_of_both_creds_ntlm,
                            domain_joined_mach_creds=target_creds,
                            logon_type=netlogon.NetlogonInteractiveInformation)

        self.check_samlogon_interactive_log(self._member_of_both_creds_ntlm,
                                            server_policy=policy)

        # When the account is a member of neither group, network SamLogon
        # fails.
        self._test_samlogon(
            creds=self._mach_creds_ntlm,
            domain_joined_mach_creds=target_creds,
            logon_type=netlogon.NetlogonNetworkInformation,
            expect_error=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

        self.check_samlogon_network_log(
            self._mach_creds_ntlm,
            server_policy=policy,
            server_policy_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.NTLM_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

        # Interactive SamLogon also fails.
        self._test_samlogon(
            creds=self._mach_creds_ntlm,
            domain_joined_mach_creds=target_creds,
            logon_type=netlogon.NetlogonInteractiveInformation,
            expect_error=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

        self.check_samlogon_interactive_log(
            self._mach_creds_ntlm,
            server_policy=policy,
            server_policy_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.NTLM_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

    def test_samlogon_allowed_to_service_member_of(self):
        # Create an authentication policy that applies to a managed service and
        # requires that the account should belong to both groups.
        allowed = (f'O:SYD:(XA;;CR;;;WD;(Member_of '
                   f'{{SID({self._group0_sid}), SID({self._group1_sid})}}))')
        policy = self.create_authn_policy(enforced=True,
                                          service_allowed_to=allowed)

        # Create a managed service account with the assigned policy.
        target_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
            assigned_policy=policy)

        # When the account is a member of both groups, network SamLogon
        # succeeds.
        self._test_samlogon(creds=self._member_of_both_creds_ntlm,
                            domain_joined_mach_creds=target_creds,
                            logon_type=netlogon.NetlogonNetworkInformation)

        self.check_samlogon_network_log(self._member_of_both_creds_ntlm,
                                        server_policy=policy)

        # Interactive SamLogon also succeeds.
        self._test_samlogon(creds=self._member_of_both_creds_ntlm,
                            domain_joined_mach_creds=target_creds,
                            logon_type=netlogon.NetlogonInteractiveInformation)

        self.check_samlogon_interactive_log(self._member_of_both_creds_ntlm,
                                            server_policy=policy)

        # When the account is a member of neither group, network SamLogon
        # fails.
        self._test_samlogon(
            creds=self._mach_creds_ntlm,
            domain_joined_mach_creds=target_creds,
            logon_type=netlogon.NetlogonNetworkInformation,
            expect_error=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

        self.check_samlogon_network_log(
            self._mach_creds_ntlm,
            server_policy=policy,
            server_policy_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.NTLM_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

        # Interactive SamLogon also fails.
        self._test_samlogon(
            creds=self._mach_creds_ntlm,
            domain_joined_mach_creds=target_creds,
            logon_type=netlogon.NetlogonInteractiveInformation,
            expect_error=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

        self.check_samlogon_interactive_log(
            self._mach_creds_ntlm,
            server_policy=policy,
            server_policy_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.NTLM_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

    def test_samlogon_allowed_to_computer_silo(self):
        # Create an authentication policy that applies to a computer and
        # requires that the account belong to the enforced silo.
        allowed = (f'O:SYD:(XA;;CR;;;WD;'
                   f'(@User.ad://ext/AuthenticationSilo == '
                   f'"{self._enforced_silo}"))')
        policy = self.create_authn_policy(enforced=True,
                                          computer_allowed_to=allowed)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Even though the account is a member of the silo, its claims are
        # ignored, and network SamLogon fails.
        self._test_samlogon(
            creds=self._member_of_enforced_silo_ntlm,
            domain_joined_mach_creds=target_creds,
            logon_type=netlogon.NetlogonNetworkInformation,
            expect_error=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

        self.check_samlogon_network_log(
            self._member_of_enforced_silo_ntlm,
            server_policy=policy,
            server_policy_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.NTLM_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

        # Interactive SamLogon also fails.
        self._test_samlogon(
            creds=self._member_of_enforced_silo_ntlm,
            domain_joined_mach_creds=target_creds,
            logon_type=netlogon.NetlogonInteractiveInformation,
            expect_error=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

        self.check_samlogon_interactive_log(
            self._member_of_enforced_silo_ntlm,
            server_policy=policy,
            server_policy_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.NTLM_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

    def test_samlogon_allowed_to_service_silo(self):
        # Create an authentication policy that applies to a managed service and
        # requires that the account belong to the enforced silo.
        allowed = (f'O:SYD:(XA;;CR;;;WD;'
                   f'(@User.ad://ext/AuthenticationSilo == '
                   f'"{self._enforced_silo}"))')
        policy = self.create_authn_policy(enforced=True,
                                          service_allowed_to=allowed)

        # Create a managed service account with the assigned policy.
        target_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
            assigned_policy=policy)

        # Even though the account is a member of the silo, its claims are
        # ignored, and network SamLogon fails.
        self._test_samlogon(
            creds=self._member_of_enforced_silo_ntlm,
            domain_joined_mach_creds=target_creds,
            logon_type=netlogon.NetlogonNetworkInformation,
            expect_error=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

        self.check_samlogon_network_log(
            self._member_of_enforced_silo_ntlm,
            server_policy=policy,
            server_policy_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.NTLM_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

        # Interactive SamLogon also fails.
        self._test_samlogon(
            creds=self._member_of_enforced_silo_ntlm,
            domain_joined_mach_creds=target_creds,
            logon_type=netlogon.NetlogonInteractiveInformation,
            expect_error=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

        self.check_samlogon_interactive_log(
            self._member_of_enforced_silo_ntlm,
            server_policy=policy,
            server_policy_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.NTLM_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)


if __name__ == '__main__':
    global_asn1_print = False
    global_hexdump = False
    import unittest
    unittest.main()
