#!/usr/bin/env python3
# Unix SMB/CIFS implementation.
# Copyright (C) Stefan Metzmacher 2020
# Copyright (C) Catalyst.Net Ltd 2022
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

import random
import re

from enum import Enum
from functools import partial

import ldb

from samba import common, werror
from samba.dcerpc import krb5pac, netlogon, samr, security
from samba.dsdb import (
    GTYPE_SECURITY_DOMAIN_LOCAL_GROUP,
    GTYPE_SECURITY_GLOBAL_GROUP,
    GTYPE_SECURITY_UNIVERSAL_GROUP,
)
from samba.tests import DynamicTestCase, env_get_var_value
from samba.tests.krb5 import kcrypto
from samba.tests.krb5.kdc_base_test import KDCBaseTest
from samba.tests.krb5.raw_testcase import RawKerberosTest
from samba.tests.krb5.rfc4120_constants import (
    KRB_TGS_REP,
    NT_PRINCIPAL,
)

SidType = RawKerberosTest.SidType

global_asn1_print = False
global_hexdump = False


class GroupType(Enum):
    GLOBAL = GTYPE_SECURITY_GLOBAL_GROUP
    DOMAIN_LOCAL = GTYPE_SECURITY_DOMAIN_LOCAL_GROUP
    UNIVERSAL = GTYPE_SECURITY_UNIVERSAL_GROUP


# This simple class encapsulates the DN and SID of a Principal.
class Principal:
    def __init__(self, dn, sid):
        if dn is not None and not isinstance(dn, ldb.Dn):
            raise AssertionError(f'expected {dn} to be an ldb.Dn')

        self.dn = dn
        self.sid = sid


@DynamicTestCase
class GroupTests(KDCBaseTest):
    # Placeholder objects that represent the user account undergoing testing.
    user = object()
    trust_user = object()

    # Constants for group SID attributes.
    default_attrs = security.SE_GROUP_DEFAULT_FLAGS
    resource_attrs = default_attrs | security.SE_GROUP_RESOURCE

    asserted_identity = security.SID_AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY

    trust_domain = 'S-1-5-21-123-456-789'

    def setUp(self):
        super().setUp()
        self.do_asn1_print = global_asn1_print
        self.do_hexdump = global_hexdump

    @classmethod
    def setUpDynamicTestCases(cls):
        FILTER = env_get_var_value('FILTER', allow_missing=True)
        SKIP_INVALID = env_get_var_value('SKIP_INVALID', allow_missing=True)

        for case in cls.cases:
            invalid = case.pop('configuration_invalid', False)
            if SKIP_INVALID and invalid:
                # Some group setups are invalid on Windows, so we allow them to
                # be skipped.
                continue
            name = case.pop('test')
            if FILTER and not re.search(FILTER, name):
                continue
            name = re.sub(r'\W+', '_', name)

            cls.generate_dynamic_test('test_group', name,
                                      dict(case))

    def test_set_universal_primary_group(self):
        samdb = self.get_samdb()

        # Create a universal group.
        universal_dn = self.create_group(samdb,
                                         self.get_new_username(),
                                         gtype=GroupType.UNIVERSAL.value)

        # Get the SID of the universal group.
        universal_sid = self.get_objectSid(samdb, universal_dn)

        # Create a user account belonging to the group.
        creds = self.get_cached_creds(
            account_type=self.AccountType.USER,
            opts={
                'member_of': (
                    universal_dn,
                ),
                'kerberos_enabled': False,
            },
            use_cache=False)

        # Set the user's primary group.
        self.set_primary_group(samdb, creds.get_dn(), universal_sid)

    def test_set_domain_local_primary_group(self):
        samdb = self.get_samdb()

        # Create a domain-local group.
        domain_local_dn = self.create_group(samdb,
                                            self.get_new_username(),
                                            gtype=GroupType.DOMAIN_LOCAL.value)

        # Get the SID of the domain-local group.
        domain_local_sid = self.get_objectSid(samdb, domain_local_dn)

        # Create a user account belonging to the group.
        creds = self.get_cached_creds(
            account_type=self.AccountType.USER,
            opts={
                'member_of': (
                    domain_local_dn,
                ),
                'kerberos_enabled': False,
            },
            use_cache=False)

        # Setting the user's primary group fails.
        self.set_primary_group(
            samdb, creds.get_dn(), domain_local_sid,
            expected_error=ldb.ERR_UNWILLING_TO_PERFORM,
            expected_werror=werror.WERR_MEMBER_NOT_IN_GROUP)

    def test_change_universal_primary_group_to_global(self):
        samdb = self.get_samdb()

        # Create a universal group.
        universal_dn = self.create_group(samdb,
                                         self.get_new_username(),
                                         gtype=GroupType.UNIVERSAL.value)

        # Get the SID of the universal group.
        universal_sid = self.get_objectSid(samdb, universal_dn)

        # Create a user account belonging to the group.
        creds = self.get_cached_creds(
            account_type=self.AccountType.USER,
            opts={
                'member_of': (
                    universal_dn,
                ),
                'kerberos_enabled': False,
            },
            use_cache=False)

        # Set the user's primary group.
        self.set_primary_group(samdb, creds.get_dn(), universal_sid)

        # Change the group to a global group.
        self.set_group_type(samdb,
                            ldb.Dn(samdb, universal_dn),
                            GroupType.GLOBAL)

    def test_change_universal_primary_group_to_domain_local(self):
        samdb = self.get_samdb()

        # Create a universal group.
        universal_dn = self.create_group(samdb,
                                         self.get_new_username(),
                                         gtype=GroupType.UNIVERSAL.value)

        # Get the SID of the universal group.
        universal_sid = self.get_objectSid(samdb, universal_dn)

        # Create a user account belonging to the group.
        creds = self.get_cached_creds(
            account_type=self.AccountType.USER,
            opts={
                'member_of': (
                    universal_dn,
                ),
                'kerberos_enabled': False,
            },
            use_cache=False)

        # Set the user's primary group.
        self.set_primary_group(samdb, creds.get_dn(), universal_sid)

        # Change the group to a domain-local group. This works, even though the
        # group is still the user's primary group.
        self.set_group_type(samdb,
                            ldb.Dn(samdb, universal_dn),
                            GroupType.DOMAIN_LOCAL)

    # Check the groups in a SamInfo structure returned by SamLogon.
    def test_samlogon_SamInfo(self):
        samdb = self.get_samdb()

        # Create a universal and a domain-local group.
        universal_dn = self.create_group(samdb,
                                         self.get_new_username(),
                                         gtype=GroupType.UNIVERSAL.value)
        domain_local_dn = self.create_group(samdb,
                                            self.get_new_username(),
                                            gtype=GroupType.DOMAIN_LOCAL.value)

        # Create a user account belonging to both groups.
        creds = self.get_cached_creds(
            account_type=self.AccountType.USER,
            opts={
                'member_of': (
                    universal_dn,
                    domain_local_dn,
                ),
                'kerberos_enabled': False,
            })

        # Get the SID and RID of the user account.
        user_sid = self.get_objectSid(samdb, creds.get_dn())
        user_rid = int(user_sid.rsplit('-', 1)[1])

        # Get the SID and RID of the universal group.
        universal_sid = self.get_objectSid(samdb, universal_dn)
        universal_rid = int(universal_sid.rsplit('-', 1)[1])

        # We don't expect the EXTRA_SIDS flag to be set.
        unexpected_flags = netlogon.NETLOGON_EXTRA_SIDS

        # Do a SamLogon call and check we get back the right structure.
        interactive = netlogon.NetlogonInteractiveInformation
        level = netlogon.NetlogonValidationSamInfo
        validation = self._test_samlogon(creds=creds,
                                         logon_type=interactive,
                                         protected=False,
                                         validation_level=level)
        self.assertIsInstance(validation, netlogon.netr_SamInfo2)

        base = validation.base

        # Check some properties of the base structure.
        self.assertEqual(user_rid, base.rid)
        self.assertEqual(security.DOMAIN_RID_USERS, base.primary_gid)
        self.assertEqual(samdb.get_domain_sid(), str(base.domain_sid))
        self.assertFalse(unexpected_flags & base.user_flags,
                         f'0x{unexpected_flags:x} unexpectedly set in '
                         f'user_flags (0x{base.user_flags:x})')

        # Check we have two groups in the base.
        self.assertEqual(2, base.groups.count)

        rids = base.groups.rids

        # The first group should be Domain Users.
        self.assertEqual(security.DOMAIN_RID_USERS, rids[0].rid)
        self.assertEqual(self.default_attrs, rids[0].attributes)

        # The second should be our universal group.
        self.assertEqual(universal_rid, rids[1].rid)
        self.assertEqual(self.default_attrs, rids[1].attributes)

        # The domain-local group is nowhere to be found.

    # Check the groups in a SamInfo2 structure returned by SamLogon.
    def test_samlogon_SamInfo2(self):
        samdb = self.get_samdb()

        # Create a universal and a domain-local group.
        universal_dn = self.create_group(samdb,
                                         self.get_new_username(),
                                         gtype=GroupType.UNIVERSAL.value)
        domain_local_dn = self.create_group(samdb,
                                            self.get_new_username(),
                                            gtype=GroupType.DOMAIN_LOCAL.value)

        # Create a user account belonging to both groups.
        creds = self.get_cached_creds(
            account_type=self.AccountType.USER,
            opts={
                'member_of': (
                    universal_dn,
                    domain_local_dn,
                ),
                'kerberos_enabled': False,
            })

        # Get the SID and RID of the user account.
        user_sid = self.get_objectSid(samdb, creds.get_dn())
        user_rid = int(user_sid.rsplit('-', 1)[1])

        # Get the SID and RID of the universal group.
        universal_sid = self.get_objectSid(samdb, universal_dn)
        universal_rid = int(universal_sid.rsplit('-', 1)[1])

        # Get the SID of the domain-local group.
        domain_local_sid = self.get_objectSid(samdb, domain_local_dn)

        # We expect the EXTRA_SIDS flag to be set.
        expected_flags = netlogon.NETLOGON_EXTRA_SIDS

        # Do a SamLogon call and check we get back the right structure.
        interactive = netlogon.NetlogonInteractiveInformation
        level = netlogon.NetlogonValidationSamInfo2
        validation = self._test_samlogon(creds=creds,
                                         logon_type=interactive,
                                         protected=False,
                                         validation_level=level)
        self.assertIsInstance(validation, netlogon.netr_SamInfo3)

        base = validation.base

        # Check some properties of the base structure.
        self.assertEqual(user_rid, base.rid)
        self.assertEqual(security.DOMAIN_RID_USERS, base.primary_gid)
        self.assertEqual(samdb.get_domain_sid(), str(base.domain_sid))
        self.assertTrue(expected_flags & base.user_flags,
                        f'0x{expected_flags:x} unexpectedly reset in '
                        f'user_flags (0x{base.user_flags:x})')

        # Check we have two groups in the base.
        self.assertEqual(2, base.groups.count)

        rids = base.groups.rids

        # The first group should be Domain Users.
        self.assertEqual(security.DOMAIN_RID_USERS, rids[0].rid)
        self.assertEqual(self.default_attrs, rids[0].attributes)

        # The second should be our universal group.
        self.assertEqual(universal_rid, rids[1].rid)
        self.assertEqual(self.default_attrs, rids[1].attributes)

        # Check that we have one group in the SIDs array.
        self.assertEqual(1, validation.sidcount)

        sids = validation.sids

        # That group should be our domain-local group.
        self.assertEqual(domain_local_sid, str(sids[0].sid))
        self.assertEqual(self.resource_attrs, sids[0].attributes)

    # Check the groups in a SamInfo4 structure returned by SamLogon.
    def test_samlogon_SamInfo4(self):
        samdb = self.get_samdb()

        # Create a universal and a domain-local group.
        universal_dn = self.create_group(samdb,
                                         self.get_new_username(),
                                         gtype=GroupType.UNIVERSAL.value)
        domain_local_dn = self.create_group(samdb,
                                            self.get_new_username(),
                                            gtype=GroupType.DOMAIN_LOCAL.value)

        # Create a user account belonging to both groups.
        creds = self.get_cached_creds(
            account_type=self.AccountType.USER,
            opts={
                'member_of': (
                    universal_dn,
                    domain_local_dn,
                ),
                'kerberos_enabled': False,
            })

        # Get the SID and RID of the user account.
        user_sid = self.get_objectSid(samdb, creds.get_dn())
        user_rid = int(user_sid.rsplit('-', 1)[1])

        # Get the SID and RID of the universal group.
        universal_sid = self.get_objectSid(samdb, universal_dn)
        universal_rid = int(universal_sid.rsplit('-', 1)[1])

        # Get the SID of the domain-local group.
        domain_local_sid = self.get_objectSid(samdb, domain_local_dn)

        # We expect the EXTRA_SIDS flag to be set.
        expected_flags = netlogon.NETLOGON_EXTRA_SIDS

        # Do a SamLogon call and check we get back the right structure.
        interactive = netlogon.NetlogonInteractiveInformation
        level = netlogon.NetlogonValidationSamInfo4
        validation = self._test_samlogon(creds=creds,
                                         logon_type=interactive,
                                         protected=False,
                                         validation_level=level)
        self.assertIsInstance(validation, netlogon.netr_SamInfo6)

        base = validation.base

        # Check some properties of the base structure.
        self.assertEqual(user_rid, base.rid)
        self.assertEqual(security.DOMAIN_RID_USERS, base.primary_gid)
        self.assertEqual(samdb.get_domain_sid(), str(base.domain_sid))
        self.assertTrue(expected_flags & base.user_flags,
                        f'0x{expected_flags:x} unexpectedly reset in '
                        f'user_flags (0x{base.user_flags:x})')

        # Check we have two groups in the base.
        self.assertEqual(2, base.groups.count)

        rids = base.groups.rids

        # The first group should be Domain Users.
        self.assertEqual(security.DOMAIN_RID_USERS, rids[0].rid)
        self.assertEqual(self.default_attrs, rids[0].attributes)

        # The second should be our universal group.
        self.assertEqual(universal_rid, rids[1].rid)
        self.assertEqual(self.default_attrs, rids[1].attributes)

        # Check that we have one group in the SIDs array.
        self.assertEqual(1, validation.sidcount)

        sids = validation.sids

        # That group should be our domain-local group.
        self.assertEqual(domain_local_sid, str(sids[0].sid))
        self.assertEqual(self.resource_attrs, sids[0].attributes)

    # Get a ticket with the SIDs in the PAC replaced with ones we specify. This
    # is useful for creating arbitrary tickets that can be used to perform a
    # TGS-REQ.
    def ticket_with_sids(self,
                         ticket,
                         new_sids,
                         domain_sid,
                         user_rid,
                         set_user_flags=0,
                         reset_user_flags=0):
        krbtgt_creds = self.get_krbtgt_creds()
        krbtgt_key = self.TicketDecryptionKey_from_creds(krbtgt_creds)

        checksum_keys = {
            krb5pac.PAC_TYPE_KDC_CHECKSUM: krbtgt_key
        }

        modify_pac_fn = partial(self.set_pac_sids,
                                new_sids=new_sids,
                                domain_sid=domain_sid,
                                user_rid=user_rid,
                                set_user_flags=set_user_flags,
                                reset_user_flags=reset_user_flags)

        return self.modified_ticket(ticket,
                                    modify_pac_fn=modify_pac_fn,
                                    checksum_keys=checksum_keys)

    # Replace the SIDs in a PAC with 'new_sids'.
    def set_pac_sids(self,
                     pac,
                     new_sids,
                     domain_sid,
                     user_rid,
                     set_user_flags=0,
                     reset_user_flags=0):
        base_sids = []
        extra_sids = []
        resource_sids = []

        resource_domain = None

        primary_gid = None

        # Filter our SIDs into three arrays depending on their ultimate
        # location in the PAC.
        for sid, sid_type, attrs in new_sids:
            if sid_type is self.SidType.BASE_SID:
                domain, rid = sid.rsplit('-', 1)
                self.assertEqual(domain_sid, domain,
                                 f'base SID {sid} must be in our domain')

                base_sid = samr.RidWithAttribute()
                base_sid.rid = int(rid)
                base_sid.attributes = attrs

                base_sids.append(base_sid)
            elif sid_type is self.SidType.EXTRA_SID:
                extra_sid = netlogon.netr_SidAttr()
                extra_sid.sid = security.dom_sid(sid)
                extra_sid.attributes = attrs

                extra_sids.append(extra_sid)
            elif sid_type is self.SidType.RESOURCE_SID:
                domain, rid = sid.rsplit('-', 1)
                if resource_domain is None:
                    resource_domain = domain
                else:
                    self.assertEqual(resource_domain, domain,
                                     'resource SIDs must share the same '
                                     'domain')

                resource_sid = samr.RidWithAttribute()
                resource_sid.rid = int(rid)
                resource_sid.attributes = attrs

                resource_sids.append(resource_sid)
            elif sid_type is self.SidType.PRIMARY_GID:
                self.assertIsNone(primary_gid,
                                  f'must not specify a second primary GID '
                                  f'{sid}')
                self.assertIsNone(attrs, 'cannot specify primary GID attrs')

                domain, primary_gid = sid.rsplit('-', 1)
                self.assertEqual(domain_sid, domain,
                                 f'primary GID {sid} must be in our domain')
            else:
                self.fail(f'invalid SID type {sid_type}')

        found_logon_info = True

        user_sid = security.dom_sid(f'{domain_sid}-{user_rid}')

        pac_buffers = pac.buffers
        for pac_buffer in pac_buffers:
            # Find the LOGON_INFO PAC buffer.
            if pac_buffer.type == krb5pac.PAC_TYPE_LOGON_INFO:
                logon_info = pac_buffer.info.info

                # Add Extra SIDs and set the EXTRA_SIDS flag as needed.
                logon_info.info3.sidcount = len(extra_sids)
                if extra_sids:
                    logon_info.info3.sids = extra_sids
                    logon_info.info3.base.user_flags |= (
                        netlogon.NETLOGON_EXTRA_SIDS)
                else:
                    logon_info.info3.sids = None
                    logon_info.info3.base.user_flags &= ~(
                        netlogon.NETLOGON_EXTRA_SIDS)

                # Add Base SIDs.
                logon_info.info3.base.groups.count = len(base_sids)
                if base_sids:
                    logon_info.info3.base.groups.rids = base_sids
                else:
                    logon_info.info3.base.groups.rids = None

                logon_info.info3.base.domain_sid = security.dom_sid(domain_sid)
                logon_info.info3.base.rid = int(user_rid)

                if primary_gid is not None:
                    logon_info.info3.base.primary_gid = int(primary_gid)

                # Add Resource SIDs and set the RESOURCE_GROUPS flag as needed.
                logon_info.resource_groups.groups.count = len(resource_sids)
                if resource_sids:
                    resource_domain = security.dom_sid(resource_domain)
                    logon_info.resource_groups.domain_sid = resource_domain
                    logon_info.resource_groups.groups.rids = resource_sids
                    logon_info.info3.base.user_flags |= (
                        netlogon.NETLOGON_RESOURCE_GROUPS)
                else:
                    logon_info.resource_groups.domain_sid = None
                    logon_info.resource_groups.groups.rids = None
                    logon_info.info3.base.user_flags &= ~(
                        netlogon.NETLOGON_RESOURCE_GROUPS)

                logon_info.info3.base.user_flags |= set_user_flags
                logon_info.info3.base.user_flags &= ~reset_user_flags

                found_logon_info = True

            # Also replace the user's SID in the UPN DNS buffer.
            elif pac_buffer.type == krb5pac.PAC_TYPE_UPN_DNS_INFO:
                upn_dns_info_ex = pac_buffer.info.ex

                upn_dns_info_ex.objectsid = user_sid

            # But don't replace the user's SID in the Requester SID buffer, or
            # we'll get a SID mismatch.

        self.assertTrue(found_logon_info, 'no LOGON_INFO PAC buffer')

        pac.buffers = pac_buffers

        return pac

    # A list of test cases.
    cases = [
        # AS-REQ tests.
        {
            'test': 'universal; as-req to krbtgt',
            'groups': {
                # A Universal group containing the user.
                'foo': (GroupType.UNIVERSAL, {user}),
            },
            # Make an AS-REQ to the krbtgt with the user's account.
            'as:to_krbtgt': True,
            'as:expected': {
                # Ignoring the user ID, or base RID, expect the PAC to contain
                # precisely the following SIDS in any order:
                ('foo', SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'universal; as-req to service',
            'groups': {
                'foo': (GroupType.UNIVERSAL, {user}),
            },
            # The same again, but this time perform the AS-REQ to a service.
            'as:to_krbtgt': False,
            'as:expected': {
                ('foo', SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'global; as-req to krbtgt',
            'groups': {
                # The behaviour should be the same with a Global group.
                'foo': (GroupType.GLOBAL, {user}),
            },
            'as:to_krbtgt': True,
            'as:expected': {
                ('foo', SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'global; as-req to service',
            'groups': {
                'foo': (GroupType.GLOBAL, {user}),
            },
            'as:to_krbtgt': False,
            'as:expected': {
                ('foo', SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'domain-local; as-req to krbtgt',
            'groups': {
                # A Domain-local group containing the user.
                'foo': (GroupType.DOMAIN_LOCAL, {user}),
            },
            'as:to_krbtgt': True,
            'as:expected': {
                # A TGT will not contain domain-local groups the user belongs
                # to.
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'domain-local; compression; as-req to service',
            'groups': {
                'foo': (GroupType.DOMAIN_LOCAL, {user}),
            },
            'as:to_krbtgt': False,
            'as:expected': {
                # However, a service ticket will include domain-local
                # groups. The account supports SID compression, so they are
                # added as resource SIDs.
                ('foo', SidType.RESOURCE_SID, resource_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'domain-local; no compression; as-req to service',
            'groups': {
                'foo': (GroupType.DOMAIN_LOCAL, {user}),
            },
            'as:to_krbtgt': False,
            # This time, the target account disclaims support for SID
            # compression.
            'as:compression': False,
            'as:expected': {
                # The SIDs in the PAC are the same, except the group SID is
                # placed in Extra SIDs, not Resource SIDs.
                ('foo', SidType.EXTRA_SID, resource_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'nested domain-local; as-req to krbtgt',
            'groups': {
                # A Universal group containing a Domain-local group containing
                # the user.
                'universal': (GroupType.UNIVERSAL, {'dom-local'}),
                'dom-local': (GroupType.DOMAIN_LOCAL, {user}),
            },
            # It is not possible in Windows for a Universal group to contain a
            # Domain-local group without exploiting bugs. This flag provides a
            # convenient means by which these tests can be skipped.
            'configuration_invalid': True,
            'as:to_krbtgt': True,
            'as:expected': {
                # While Windows would exclude the universal group from the PAC,
                # expecting its inclusion is more sensible on the whole.
                ('universal', SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'nested domain-local; compression; as-req to service',
            'groups': {
                'universal': (GroupType.UNIVERSAL, {'dom-local'}),
                'dom-local': (GroupType.DOMAIN_LOCAL, {user}),
            },
            'configuration_invalid': True,
            'as:to_krbtgt': False,
            'as:expected': {
                # A service ticket is expected to include both SIDs.
                ('universal', SidType.BASE_SID, default_attrs),
                ('dom-local', SidType.RESOURCE_SID, resource_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'nested domain-local; no compression; as-req to service',
            'groups': {
                'universal': (GroupType.UNIVERSAL, {'dom-local'}),
                'dom-local': (GroupType.DOMAIN_LOCAL, {user}),
            },
            'configuration_invalid': True,
            'as:to_krbtgt': False,
            'as:compression': False,
            'as:expected': {
                # As before, but disclaiming SID compression support, so the
                # domain-local SID goes in Extra SIDs.
                ('universal', SidType.BASE_SID, default_attrs),
                ('dom-local', SidType.EXTRA_SID, resource_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'nested universal; as-req to krbtgt',
            'groups': {
                # A similar scenario, except flipped around: a Domain-local
                # group containing a Universal group containing the user.
                'dom-local': (GroupType.DOMAIN_LOCAL, {'universal'}),
                'universal': (GroupType.UNIVERSAL, {user}),
            },
            'as:to_krbtgt': True,
            'as:expected': {
                # Expect the Universal group's inclusion in the PAC.
                ('universal', SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'nested universal; compression; as-req to service',
            'groups': {
                'dom-local': (GroupType.DOMAIN_LOCAL, {'universal'}),
                'universal': (GroupType.UNIVERSAL, {user}),
            },
            'as:to_krbtgt': False,
            'as:expected': {
                # Expect a service ticket to contain both SIDs.
                ('universal', SidType.BASE_SID, default_attrs),
                ('dom-local', SidType.RESOURCE_SID, resource_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'nested universal; no compression; as-req to service',
            'groups': {
                'dom-local': (GroupType.DOMAIN_LOCAL, {'universal'}),
                'universal': (GroupType.UNIVERSAL, {user}),
            },
            'as:to_krbtgt': False,
            'as:compression': False,
            'as:expected': {
                # As before, but disclaiming SID compression support, so the
                # domain-local SID goes in Extra SIDs.
                ('universal', SidType.BASE_SID, default_attrs),
                ('dom-local', SidType.EXTRA_SID, resource_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        # TGS-REQ tests.
        {
            'test': 'tgs-req to krbtgt',
            'groups': {
                # A Universal group containing the user.
                'foo': (GroupType.UNIVERSAL, {user}),
            },
            'as:to_krbtgt': True,
            'as:expected': {
                ('foo', SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            # Make a TGS-REQ to the krbtgt with the user's account.
            'tgs:to_krbtgt': True,
            'tgs:expected': {
                # Expect the same results as with an AS-REQ.
                ('foo', SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'tgs-req to service',
            'groups': {
                # A Universal group containing the user.
                'foo': (GroupType.UNIVERSAL, {user}),
            },
            'as:to_krbtgt': True,
            'as:expected': {
                ('foo', SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            # Make a TGS-REQ to a service with the user's account.
            'tgs:to_krbtgt': False,
            'tgs:expected': {
                ('foo', SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'domain-local; tgs-req to krbtgt',
            'groups': {
                # A Domain-local group containing the user.
                'foo': (GroupType.UNIVERSAL, {user}),
            },
            'as:to_krbtgt': True,
            'as:expected': {
                ('foo', SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:to_krbtgt': True,
            'tgs:expected': {
                # Expect the same results as with an AS-REQ.
                ('foo', SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'domain-local; compression; tgs-req to service',
            'groups': {
                # A Domain-local group containing the user.
                'foo': (GroupType.DOMAIN_LOCAL, {user}),
            },
            'as:to_krbtgt': True,
            'as:expected': {
                # The Domain-local group is not present in the PAC after an
                # AS-REQ.
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:to_krbtgt': False,
            'tgs:expected': {
                # Now it's added as a resource SID after the TGS-REQ.
                ('foo', SidType.RESOURCE_SID, resource_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'domain-local; no compression; tgs-req to service',
            'groups': {
                # A Domain-local group containing the user.
                'foo': (GroupType.DOMAIN_LOCAL, {user}),
            },
            'as:to_krbtgt': True,
            # This time, the target account disclaims support for SID
            # compression.
            'as:expected': {
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:to_krbtgt': False,
            'tgs:compression': False,
            'tgs:expected': {
                # The SIDs in the PAC are the same, except the group SID is
                # placed in Extra SIDs, not Resource SIDs.
                ('foo', SidType.EXTRA_SID, resource_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'exclude asserted identity; tgs-req to krbtgt',
            'groups': {
                'foo': (GroupType.UNIVERSAL, {user}),
            },
            'as:to_krbtgt': True,
            'tgs:to_krbtgt': True,
            'tgs:sids': {
                # Remove the Asserted Identity SID from the PAC.
                ('foo', SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:expected': {
                # It should not be re-added in the TGS-REQ.
                ('foo', SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'exclude asserted identity; tgs-req to service',
            'groups': {
                'foo': (GroupType.UNIVERSAL, {user}),
            },
            'as:to_krbtgt': True,
            # Nor should it be re-added if the TGS-REQ is directed to a
            # service.
            'tgs:to_krbtgt': False,
            'tgs:sids': {
                ('foo', SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:expected': {
                ('foo', SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'exclude claims valid; tgs-req to krbtgt',
            'groups': {
                'foo': (GroupType.UNIVERSAL, {user}),
            },
            'as:to_krbtgt': True,
            'tgs:to_krbtgt': True,
            'tgs:sids': {
                # Remove the Claims Valid SID from the PAC.
                ('foo', SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
            },
            'tgs:expected': {
                # It should not be re-added in the TGS-REQ.
                ('foo', SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            },
        },
        {
            'test': 'exclude claims valid; tgs-req to service',
            'groups': {
                'foo': (GroupType.UNIVERSAL, {user}),
            },
            'as:to_krbtgt': True,
            # Nor should it be re-added if the TGS-REQ is directed to a
            # service.
            'tgs:to_krbtgt': False,
            'tgs:sids': {
                ('foo', SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
            },
            'tgs:expected': {
                ('foo', SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            },
        },
        {
            'test': 'user group removal; tgs-req to krbtgt',
            'groups': {
                # The user has been removed from the group...
                'foo': (GroupType.UNIVERSAL, {}),
            },
            'as:to_krbtgt': True,
            'tgs:to_krbtgt': True,
            'tgs:sids': {
                # ...but the user's PAC still contains the group SID.
                ('foo', SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:expected': {
                # The group SID should not be removed when a TGS-REQ is
                # performed.
                ('foo', SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'user group removal; tgs-req to service',
            'groups': {
                'foo': (GroupType.UNIVERSAL, {}),
            },
            'as:to_krbtgt': True,
            # Likewise, but to a service.
            'tgs:to_krbtgt': False,
            'tgs:sids': {
                ('foo', SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:expected': {
                ('foo', SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'nested group removal; tgs-req to krbtgt',
            'groups': {
                # A Domain-local group contains a Universal group, of which the
                # user is no longer a member...
                'dom-local': (GroupType.DOMAIN_LOCAL, {'universal'}),
                'universal': (GroupType.UNIVERSAL, {}),
            },
            'as:to_krbtgt': True,
            'tgs:to_krbtgt': True,
            'tgs:sids': {
                # ...but the user's PAC still contains the group SID.
                ('universal', SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:expected': {
                # The group SID should not be removed when a TGS-REQ is
                # performed.
                ('universal', SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'nested group removal; compression; tgs-req to service',
            'groups': {
                # A Domain-local group contains a Universal group, of which the
                # user is no longer a member...
                'dom-local': (GroupType.DOMAIN_LOCAL, {'universal'}),
                'universal': (GroupType.UNIVERSAL, {}),
            },
            'as:to_krbtgt': True,
            'tgs:to_krbtgt': False,
            'tgs:sids': {
                # ...but the user's PAC still contains the group SID.
                ('universal', SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:expected': {
                # Both SIDs should be present in the PAC when a TGS-REQ is
                # performed.
                ('universal', SidType.BASE_SID, default_attrs),
                ('dom-local', SidType.RESOURCE_SID, resource_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'nested group removal; no compression; tgs-req to service',
            'groups': {
                'dom-local': (GroupType.DOMAIN_LOCAL, {'universal'}),
                'universal': (GroupType.UNIVERSAL, {}),
            },
            'as:to_krbtgt': True,
            'tgs:to_krbtgt': False,
            # The same again, but with the server not supporting compression.
            'tgs:compression': False,
            'tgs:sids': {
                ('universal', SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:expected': {
                # The domain-local SID will go into Extra SIDs.
                ('universal', SidType.BASE_SID, default_attrs),
                ('dom-local', SidType.EXTRA_SID, resource_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'resource sids given; tgs-req to krbtgt',
            'groups': {
                # A couple of independent domain-local groups.
                'dom-local-0': (GroupType.DOMAIN_LOCAL, {}),
                'dom-local-1': (GroupType.DOMAIN_LOCAL, {}),
            },
            'as:to_krbtgt': True,
            'tgs:to_krbtgt': True,
            'tgs:sids': {
                # The TGT contains two resource SIDs for the domain-local
                # groups.
                ('dom-local-0', SidType.RESOURCE_SID, resource_attrs),
                ('dom-local-1', SidType.RESOURCE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:expected': {
                # The resource SIDs remain after performing a TGS-REQ to the
                # krbtgt.
                ('dom-local-0', SidType.RESOURCE_SID, resource_attrs),
                ('dom-local-1', SidType.RESOURCE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'resource sids wrongly given; tgs-req to krbtgt',
            'groups': {
                'dom-local-0': (GroupType.DOMAIN_LOCAL, {}),
                'dom-local-1': (GroupType.DOMAIN_LOCAL, {}),
            },
            'as:to_krbtgt': True,
            'tgs:to_krbtgt': True,
            # Though we have provided resource SIDs, we have reset the flag
            # indicating that they are present.
            'tgs:reset_user_flags': netlogon.NETLOGON_RESOURCE_GROUPS,
            'tgs:sids': {
                ('dom-local-0', SidType.RESOURCE_SID, resource_attrs),
                ('dom-local-1', SidType.RESOURCE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:expected': {
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
                # The resource SIDs remain in the PAC.
                ('dom-local-0', SidType.RESOURCE_SID, resource_attrs),
                ('dom-local-1', SidType.RESOURCE_SID, default_attrs),
            },
        },
        {
            'test': 'resource sids claimed given; tgs-req to krbtgt',
            'groups': {
            },
            'as:to_krbtgt': True,
            'tgs:to_krbtgt': True,
            # Though we claim to have provided resource SIDs, we have not
            # actually done so.
            'tgs:set_user_flags': netlogon.NETLOGON_RESOURCE_GROUPS,
            'tgs:sids': {
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:expected': {
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'resource sids given; compression; tgs-req to service',
            'groups': {
                'dom-local-0': (GroupType.DOMAIN_LOCAL, {}),
                'dom-local-1': (GroupType.DOMAIN_LOCAL, {}),
            },
            'as:to_krbtgt': True,
            'tgs:to_krbtgt': False,
            'tgs:sids': {
                ('dom-local-0', SidType.RESOURCE_SID, resource_attrs),
                ('dom-local-1', SidType.RESOURCE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:expected': {
                # The resource SIDs are removed upon issuing a service ticket.
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'resource sids given; no compression; tgs-req to service',
            'groups': {
                'dom-local-0': (GroupType.DOMAIN_LOCAL, {}),
                'dom-local-1': (GroupType.DOMAIN_LOCAL, {}),
            },
            'as:to_krbtgt': True,
            'tgs:to_krbtgt': False,
            # Compression is disabled on the service account.
            'tgs:compression': False,
            'tgs:sids': {
                ('dom-local-0', SidType.RESOURCE_SID, resource_attrs),
                ('dom-local-1', SidType.RESOURCE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:expected': {
                # The resource SIDs are again removed.
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        # Testing operability with older Samba versions.
        {
            'test': 'domain-local; Samba 4.17; tgs-req to krbtgt',
            'groups': {
                'foo': (GroupType.DOMAIN_LOCAL, {user}),
            },
            'as:to_krbtgt': True,
            'tgs:to_krbtgt': True,
            'tgs:sids': {
                # In Samba 4.17, domain-local groups are contained within the
                # TGT, and do not have the SE_GROUP_RESOURCE bit set.
                ('foo', SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
            },
            'tgs:expected': {
                # After the TGS-REQ, the domain-local group remains in the PAC
                # with its original attributes.
                ('foo', SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            },
        },
        {
            'test': 'domain-local; Samba 4.17; compression; tgs-req to service',
            'groups': {
                'foo': (GroupType.DOMAIN_LOCAL, {user}),
            },
            'as:to_krbtgt': True,
            # The same scenario, but requesting a service ticket.
            'tgs:to_krbtgt': False,
            'tgs:compression': True,
            'tgs:sids': {
                ('foo', SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
            },
            'tgs:expected': {
                # The domain-local group remains in the PAC...
                ('foo', SidType.BASE_SID, default_attrs),
                # and another copy is added in Resource SIDs. This one has the
                # SE_GROUP_RESOURCE bit set.
                ('foo', SidType.RESOURCE_SID, resource_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            },
        },
        {
            'test': 'domain-local; Samba 4.17; no compression; tgs-req to service',
            'groups': {
                'foo': (GroupType.DOMAIN_LOCAL, {user}),
            },
            'as:to_krbtgt': True,
            'tgs:to_krbtgt': False,
            # In this case compression is disabled on the service.
            'tgs:compression': False,
            'tgs:sids': {
                ('foo', SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
            },
            'tgs:expected': {
                ('foo', SidType.BASE_SID, default_attrs),
                # Without compression, the extra SID appears in Extra SIDs.
                ('foo', SidType.EXTRA_SID, resource_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            },
        },
        # Simulate a ticket coming in over a trust.
        {
            'test': 'from trust; to krbtgt',
            'groups': {
                # The user belongs to a couple of domain-local groups in our
                # domain.
                'foo': (GroupType.DOMAIN_LOCAL, {trust_user}),
                'bar': (GroupType.DOMAIN_LOCAL, {'foo'}),
            },
            'as:to_krbtgt': True,
            'tgs:to_krbtgt': True,
            # The user SID is from a different domain.
            'tgs:user_sid': trust_user,
            'tgs:sids': {
                (trust_user, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                # This dummy resource SID comes from the trusted domain.
                (f'{trust_domain}-333', SidType.RESOURCE_SID, resource_attrs),
            },
            'tgs:expected': {
                # After performing a TGS-REQ to the krbtgt, the PAC remains
                # unchanged.
                (trust_user, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (f'{trust_domain}-333', SidType.RESOURCE_SID, resource_attrs),
            },
        },
        {
            'test': 'from trust; compression; to service',
            'groups': {
                'foo': (GroupType.DOMAIN_LOCAL, {trust_user}),
                'bar': (GroupType.DOMAIN_LOCAL, {'foo'}),
            },
            'as:to_krbtgt': True,
            # The same thing, but to a service.
            'tgs:to_krbtgt': False,
            'tgs:compression': True,
            'tgs:user_sid': trust_user,
            'tgs:sids': {
                (trust_user, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (f'{trust_domain}-333', SidType.RESOURCE_SID, resource_attrs),
            },
            'tgs:expected': {
                (trust_user, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                # The resource SIDs are added to the PAC.
                ('foo', SidType.RESOURCE_SID, resource_attrs),
                ('bar', SidType.RESOURCE_SID, resource_attrs),
            },
        },
        # Simulate a ticket coming in over a trust
        {
            'test': 'from trust; no compression; to service',
            'groups': {
                'foo': (GroupType.DOMAIN_LOCAL, {trust_user}),
                'bar': (GroupType.DOMAIN_LOCAL, {'foo'}),
            },
            'as:to_krbtgt': True,
            'tgs:to_krbtgt': False,
            # And again, but this time compression is disabled.
            'tgs:compression': False,
            'tgs:user_sid': trust_user,
            'tgs:sids': {
                (trust_user, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (f'{trust_domain}-333', SidType.RESOURCE_SID, resource_attrs),
            },
            'tgs:expected': {
                (trust_user, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                # The resource SIDs are added again, but this time to Extra
                # SIDs.
                ('foo', SidType.EXTRA_SID, resource_attrs),
                ('bar', SidType.EXTRA_SID, resource_attrs),
            },
        },
        # Test a group being the primary one for the user.
        {
            'test': 'primary universal; as-req to krbtgt',
            'groups': {
                'foo': (GroupType.UNIVERSAL, {user}),
            },
            # Set this group as our primary group.
            'primary_group': 'foo',
            'as:to_krbtgt': True,
            'as:expected': {
                # It appears in the PAC as normal.
                ('foo', SidType.BASE_SID, default_attrs),
                ('foo', SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'primary universal; as-req to service',
            'groups': {
                'foo': (GroupType.UNIVERSAL, {user}),
            },
            # Set this group as our primary group.
            'primary_group': 'foo',
            # The request is made to a service.
            'as:to_krbtgt': False,
            'as:expected': {
                # The group appears in the PAC as normal.
                ('foo', SidType.BASE_SID, default_attrs),
                ('foo', SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        # Test domain-local primary groups.
        {
            'test': 'primary domain-local; as-req to krbtgt',
            'groups': {
                'foo': (GroupType.DOMAIN_LOCAL, {user}),
            },
            # Though Windows normally disallows setting a domain-local group as
            # a primary group, Samba does not.
            'primary_group': 'foo',
            'as:to_krbtgt': True,
            'as:expected': {
                # The domain-local group appears as our primary GID, but does
                # not appear in the base SIDs.
                ('foo', SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'primary domain-local; compression; as-req to service',
            'groups': {
                'foo': (GroupType.DOMAIN_LOCAL, {user}),
            },
            'primary_group': 'foo',
            # The same test, but the request is made to a service.
            'as:to_krbtgt': False,
            'as:expected': {
                # The domain-local still only appears as our primary GID.
                ('foo', SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'primary domain-local; no compression; as-req to service',
            'groups': {
                'foo': (GroupType.DOMAIN_LOCAL, {user}),
            },
            'primary_group': 'foo',
            'as:to_krbtgt': False,
            # This time, the target account disclaims support for SID
            # compression.
            'as:compression': False,
            'as:expected': {
                ('foo', SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'primary domain-local; tgs-req to krbtgt',
            'groups': {
                'foo': (GroupType.DOMAIN_LOCAL, {user}),
            },
            # Though Windows normally disallows setting a domain-local group as
            # a primary group, Samba does not.
            'primary_group': 'foo',
            'as:to_krbtgt': True,
            'as:expected': {
                # The domain-local group appears as our primary GID, but does
                # not appear in the base SIDs.
                ('foo', SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:to_krbtgt': True,
            'tgs:expected': {
                # The domain-local group does not appear in the base SIDs.
                ('foo', SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'primary domain-local; compression; tgs-req to service',
            'groups': {
                'foo': (GroupType.DOMAIN_LOCAL, {user}),
            },
            # Though Windows normally disallows setting a domain-local group as
            # a primary group, Samba does not.
            'primary_group': 'foo',
            'as:to_krbtgt': True,
            'as:expected': {
                # The domain-local group appears as our primary GID, but does
                # not appear in the base SIDs.
                ('foo', SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            # The service is made to a service.
            'tgs:to_krbtgt': False,
            'tgs:expected': {
                # The domain-local still only appears as our primary GID.
                ('foo', SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'primary domain-local; no compression; tgs-req to service',
            'groups': {
                'foo': (GroupType.DOMAIN_LOCAL, {user}),
            },
            # Though Windows normally disallows setting a domain-local group as
            # a primary group, Samba does not.
            'primary_group': 'foo',
            'as:to_krbtgt': True,
            'as:expected': {
                # The domain-local group appears as our primary GID, but does
                # not appear in the base SIDs.
                ('foo', SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:to_krbtgt': False,
            # The service does not support compression.
            'tgs:compression': False,
            'tgs:expected': {
                ('foo', SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        # Test the scenario where we belong to a now-domain-local group, and
        # possess an old TGT issued when the group was still our primary one.
        {
            'test': 'old primary domain-local; tgs-req to krbtgt',
            'groups': {
                # A domain-local group to which we belong.
                'foo': (GroupType.DOMAIN_LOCAL, {user}),
            },
            'as:to_krbtgt': True,
            'tgs:to_krbtgt': True,
            'tgs:sids': {
                # In the PAC, the group has the attributes of an ordinary
                # group...
                ('foo', SidType.BASE_SID, default_attrs),
                # ...and remains our primary one.
                ('foo', SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:expected': {
                # The groups don't change.
                ('foo', SidType.BASE_SID, default_attrs),
                ('foo', SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'old primary domain-local; compression; tgs-req to service',
            'groups': {
                'foo': (GroupType.DOMAIN_LOCAL, {user}),
            },
            'as:to_krbtgt': True,
            # The TGS request is made to a service.
            'tgs:to_krbtgt': False,
            'tgs:sids': {
                ('foo', SidType.BASE_SID, default_attrs),
                ('foo', SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:expected': {
                ('foo', SidType.BASE_SID, default_attrs),
                ('foo', SidType.PRIMARY_GID, None),
                # The group is added a second time to the PAC, now as a
                # resource group.
                ('foo', SidType.RESOURCE_SID, resource_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'old primary domain-local; no compression; tgs-req to service',
            'groups': {
                'foo': (GroupType.DOMAIN_LOCAL, {user}),
            },
            'as:to_krbtgt': True,
            'tgs:to_krbtgt': False,
            # The target service doesn't support SID compression.
            'tgs:compression': False,
            'tgs:sids': {
                ('foo', SidType.BASE_SID, default_attrs),
                ('foo', SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:expected': {
                ('foo', SidType.BASE_SID, default_attrs),
                ('foo', SidType.PRIMARY_GID, None),
                # This time, the group is added to Extra SIDs.
                ('foo', SidType.EXTRA_SID, resource_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        # Test the scenario where we possess an old TGT issued when a
        # now-domain-local group was still our primary one. We no longer belong
        # to that group, which itself belongs to another domain-local group.
        {
            'test': 'old primary domain-local; transitive; tgs-req to krbtgt',
            'groups': {
                'bar': (GroupType.DOMAIN_LOCAL, {'foo'}),
                'foo': (GroupType.DOMAIN_LOCAL, {}),
            },
            'as:to_krbtgt': True,
            'tgs:to_krbtgt': True,
            'tgs:sids': {
                # In the PAC, the group has the attributes of an ordinary
                # group...
                ('foo', SidType.BASE_SID, default_attrs),
                # ...and remains our primary one.
                ('foo', SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:expected': {
                # The groups don't change.
                ('foo', SidType.BASE_SID, default_attrs),
                ('foo', SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'old primary domain-local; transitive; compression; tgs-req to service',
            'groups': {
                'bar': (GroupType.DOMAIN_LOCAL, {'foo'}),
                'foo': (GroupType.DOMAIN_LOCAL, {}),
            },
            'as:to_krbtgt': True,
            # The TGS request is made to a service.
            'tgs:to_krbtgt': False,
            'tgs:sids': {
                ('foo', SidType.BASE_SID, default_attrs),
                ('foo', SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:expected': {
                ('foo', SidType.BASE_SID, default_attrs),
                ('foo', SidType.PRIMARY_GID, None),
                # The second resource group is added to the PAC as a resource
                # group.
                ('bar', SidType.RESOURCE_SID, resource_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'old primary domain-local; transitive; no compression; tgs-req to service',
            'groups': {
                'bar': (GroupType.DOMAIN_LOCAL, {'foo'}),
                'foo': (GroupType.DOMAIN_LOCAL, {}),
            },
            'as:to_krbtgt': True,
            'tgs:to_krbtgt': False,
            # The target service doesn't support SID compression.
            'tgs:compression': False,
            'tgs:sids': {
                ('foo', SidType.BASE_SID, default_attrs),
                ('foo', SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:expected': {
                ('foo', SidType.BASE_SID, default_attrs),
                ('foo', SidType.PRIMARY_GID, None),
                # This time, the group is added to Extra SIDs.
                ('bar', SidType.EXTRA_SID, resource_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
    ]

    # Create a new group and return a Principal object representing it.
    def create_group_principal(self, samdb, group_type):
        name = self.get_new_username()
        dn = self.create_group(samdb, name, gtype=group_type.value)
        sid = self.get_objectSid(samdb, dn)

        return Principal(ldb.Dn(samdb, dn), sid)

    claims_valid_sid = (security.SID_CLAIMS_VALID,
                        SidType.EXTRA_SID,
                        default_attrs)

    # Return SIDs from principal placeholders based on a supplied mapping.
    def map_sids(self, sids, mapping, domain_sid):
        if sids is None:
            return None

        mapped_sids = set()
        for sid, sid_type, attrs in sids:
            if isinstance(sid, int):
                # If it's an integer, we assume it's a RID, and prefix the
                # domain SID.
                sid = f'{domain_sid}-{sid}'
            elif sid in mapping:
                # Or if we have a mapping for it, apply that. Otherwise leave
                # it unmodified.
                sid = mapping[sid].sid

            # There's no point expecting the 'Claims Valid' SID to be present
            # if we don't support claims. Filter it out to give the tests a
            # chance of passing.
            if not self.kdc_claims_support and (
                    sid == security.SID_CLAIMS_VALID):
                continue

            mapped_sids.add((sid, sid_type, attrs))

        return mapped_sids

    def set_primary_group(self, samdb, dn, primary_sid,
                          expected_error=None,
                          expected_werror=None):
        # Get the RID to be set as our primary group.
        primary_rid = primary_sid.rsplit('-', 1)[1]

        # Find out our current primary group.
        res = samdb.search(dn,
                           scope=ldb.SCOPE_BASE,
                           attrs=['primaryGroupId'])
        orig_msg = res[0]

        # Prepare to modify the attribute.
        msg = ldb.Message(dn)
        msg['primaryGroupId'] = ldb.MessageElement(str(primary_rid),
                                                   ldb.FLAG_MOD_REPLACE,
                                                   'primaryGroupId')

        # We'll remove the primaryGroupId attribute after the test, to avoid
        # problems in the teardown if the user outlives the group.
        remove_msg = samdb.msg_diff(msg, orig_msg)
        self.addCleanup(samdb.modify, remove_msg)

        # Set primaryGroupId.
        if expected_error is None:
            self.assertIsNone(expected_werror)

            samdb.modify(msg)
        else:
            self.assertIsNotNone(expected_werror)

            with self.assertRaises(
                    ldb.LdbError,
                    msg='expected setting primary group to fail'
            ) as err:
                samdb.modify(msg)

            error, estr = err.exception.args
            self.assertEqual(expected_error, error)
            self.assertIn(f'{expected_werror:08X}', estr)

    def set_group_type(self, samdb, dn, gtype):
        group_type = common.normalise_int32(gtype.value)
        msg = ldb.Message(dn)
        msg['groupType'] = ldb.MessageElement(group_type,
                                              ldb.FLAG_MOD_REPLACE,
                                              'groupType')
        samdb.modify(msg)

    # Create an arrangement of groups based on a configuration specified in a
    # test case. 'user_principal' is a principal representing the user account;
    # 'trust_principal', a principal representing the account of a user from
    # another domain.
    def setup_groups(self,
                     samdb,
                     preexisting_groups,
                     group_setup,
                     primary_groups):
        groups = dict(preexisting_groups)

        primary_group_types = {}

        # Create each group and add it to the group mapping.
        for group_id, (group_type, _) in group_setup.items():
            self.assertNotIn(group_id, preexisting_groups,
                             "don't specify placeholders")
            self.assertNotIn(group_id, groups,
                             'group ID specified more than once')

            if primary_groups is not None and (
                    group_id in primary_groups.values()):
                # Windows disallows setting a domain-local group as a primary
                # group, unless we create it as Universal first and change it
                # back to Domain-Local later.
                primary_group_types[group_id] = group_type
                group_type = GroupType.UNIVERSAL

            groups[group_id] = self.create_group_principal(samdb, group_type)

        # Map a group ID to that group's DN, and generate an
        # understandable error message if the mapping fails.
        def group_id_to_dn(group_id):
            try:
                group = groups[group_id]
            except KeyError:
                self.fail(f"included group member '{group_id}', but it is not "
                          f"specified in {groups.keys()}")
            else:
                if group.dn is not None:
                    return str(group.dn)

                return f'<SID={group.sid}>'

        # Populate each group's members.
        for group_id, (_, members) in group_setup.items():
            # Get the group's DN and the mapped DNs of its members.
            dn = groups[group_id].dn
            principal_members = map(group_id_to_dn, members)

            # Add the members to the group.
            self.add_to_group(principal_members, dn, 'member',
                              expect_attr=False)

        # Set primary groups.
        if primary_groups is not None:
            for user, primary_group in primary_groups.items():
                primary_sid = groups[primary_group].sid
                self.set_primary_group(samdb, user.dn, primary_sid)

        # Change the primary groups to their actual group types.
        for primary_group, primary_group_type in primary_group_types.items():
            self.set_group_type(samdb,
                                groups[primary_group].dn,
                                primary_group_type)

        # Return the mapping from group IDs to principals.
        return groups

    # This is the main function to handle a single testcase.
    def _test_group_with_args(self, case):
        # The group arrangement for the test.
        group_setup = case.pop('groups')

        # A group that should be the primary group for the user.
        primary_group = case.pop('primary_group', None)

        # Whether the AS-REQ or TGS-REQ should be directed to the krbtgt.
        as_to_krbtgt = case.pop('as:to_krbtgt')
        tgs_to_krbtgt = case.pop('tgs:to_krbtgt', None)

        # Whether the target server of the AS-REQ or TGS-REQ should support
        # resource SID compression.
        as_compression = case.pop('as:compression', None)
        tgs_compression = case.pop('tgs:compression', None)

        # Optional SIDs to replace those in the PAC prior to a TGS-REQ.
        tgs_sids = case.pop('tgs:sids', None)

        # Optional user SID to replace that in the PAC prior to a TGS-REQ.
        tgs_user_sid = case.pop('tgs:user_sid', None)

        # User flags that may be set or reset in the PAC prior to a TGS-REQ.
        tgs_set_user_flags = case.pop('tgs:set_user_flags', None)
        tgs_reset_user_flags = case.pop('tgs:reset_user_flags', None)

        # The SIDs we expect to see in the PAC after a AS-REQ or a TGS-REQ.
        as_expected = case.pop('as:expected', None)
        tgs_expected = case.pop('tgs:expected', None)

        # There should be no parameters remaining in the testcase.
        self.assertFalse(case, 'unexpected parameters in testcase')

        if as_expected is None:
            self.assertIsNotNone(tgs_expected,
                                 'no set of expected SIDs is provided')

        if as_to_krbtgt is None:
            as_to_krbtgt = False

        if not as_to_krbtgt:
            self.assertIsNone(tgs_expected,
                              "if we're performing a TGS-REQ, then AS-REQ "
                              "should be directed to the krbtgt")

        if tgs_to_krbtgt is None:
            tgs_to_krbtgt = False
        else:
            self.assertIsNotNone(tgs_expected,
                                 'specified TGS request to krbtgt, but no '
                                 'expected SIDs provided')

        if tgs_compression is not None:
            self.assertIsNotNone(tgs_expected,
                                 'specified compression for TGS request, but '
                                 'no expected SIDs provided')

        if tgs_user_sid is not None:
            self.assertIsNotNone(tgs_sids,
                                 'specified TGS-REQ user SID, but no '
                                 'accompanying SIDs provided')

        if tgs_set_user_flags is None:
            tgs_set_user_flags = 0
        else:
            self.assertIsNotNone(tgs_sids,
                                 'specified TGS-REQ set user flags, but no '
                                 'accompanying SIDs provided')

        if tgs_reset_user_flags is None:
            tgs_reset_user_flags = 0
        else:
            self.assertIsNotNone(tgs_sids,
                                 'specified TGS-REQ reset user flags, but no '
                                 'accompanying SIDs provided')

        samdb = self.get_samdb()

        domain_sid = samdb.get_domain_sid()

        # Create the user account. It needs to be freshly created rather than
        # cached because we will probably add it to one or more groups.
        user_creds = self.get_cached_creds(
            account_type=self.AccountType.USER,
            use_cache=False)
        user_dn = user_creds.get_dn()
        user_sid = self.get_objectSid(samdb, user_dn)
        user_name = user_creds.get_username()
        salt = user_creds.get_salt()

        trust_user_rid = random.randint(2000, 0xfffffffe)
        trust_user_sid = f'{self.trust_domain}-{trust_user_rid}'

        cname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                          names=user_name.split('/'))

        preauth_key = self.PasswordKey_from_creds(user_creds,
                                                  kcrypto.Enctype.AES256)

        ts_enc_padata = self.get_enc_timestamp_pa_data_from_key(preauth_key)
        padata = [ts_enc_padata]

        target_creds, sname = self.get_target(as_to_krbtgt, as_compression)
        decryption_key = self.TicketDecryptionKey_from_creds(target_creds)

        target_supported_etypes = target_creds.tgs_supported_enctypes
        realm = target_creds.get_realm()

        # Initialise the group mapping with the user and trust principals.
        user_principal = Principal(user_dn, user_sid)
        trust_principal = Principal(None, trust_user_sid)
        preexisting_groups = {
            self.user: user_principal,
            self.trust_user: trust_principal,
        }
        if primary_group is not None:
            primary_groups = {
                user_principal: primary_group,
            }
        else:
            primary_groups = None
        groups = self.setup_groups(samdb,
                                   preexisting_groups,
                                   group_setup,
                                   primary_groups)
        del group_setup

        if tgs_user_sid is None:
            tgs_user_sid = user_sid
        elif tgs_user_sid in groups:
            tgs_user_sid = groups[tgs_user_sid].sid

        tgs_domain_sid, tgs_user_rid = tgs_user_sid.rsplit('-', 1)

        expected_groups = self.map_sids(as_expected, groups,
                                        domain_sid)
        tgs_sids_mapped = self.map_sids(tgs_sids, groups,
                                        tgs_domain_sid)
        tgs_expected_mapped = self.map_sids(tgs_expected, groups,
                                            tgs_domain_sid)

        till = self.get_KerberosTime(offset=36000)
        kdc_options = '0'

        etypes = self.get_default_enctypes()

        # Perform an AS-REQ with the user account.
        as_rep, kdc_exchange_dict = self._test_as_exchange(
            cname=cname,
            realm=realm,
            sname=sname,
            till=till,
            expected_error_mode=0,
            expected_crealm=realm,
            expected_cname=cname,
            expected_srealm=realm,
            expected_sname=sname,
            expected_salt=salt,
            etypes=etypes,
            padata=padata,
            kdc_options=kdc_options,
            expected_account_name=user_name,
            expected_groups=expected_groups,
            expected_sid=user_sid,
            expected_domain_sid=domain_sid,
            expected_supported_etypes=target_supported_etypes,
            preauth_key=preauth_key,
            ticket_decryption_key=decryption_key)
        self.check_as_reply(as_rep)

        ticket = kdc_exchange_dict['rep_ticket_creds']

        if tgs_expected is None:
            # We're not performing a TGS-REQ, so we're done.
            self.assertIsNone(tgs_sids,
                              'provided SIDs to populate PAC for TGS-REQ, but '
                              'failed to specify expected SIDs')
            return

        if tgs_sids is not None:
            # Replace the SIDs in the PAC with the ones provided by the test.
            ticket = self.ticket_with_sids(ticket,
                                           tgs_sids_mapped,
                                           tgs_domain_sid,
                                           tgs_user_rid,
                                           set_user_flags=tgs_set_user_flags,
                                           reset_user_flags=tgs_reset_user_flags)

        target_creds, sname = self.get_target(tgs_to_krbtgt, tgs_compression)
        decryption_key = self.TicketDecryptionKey_from_creds(target_creds)

        subkey = self.RandomKey(ticket.session_key.etype)

        requester_sid = None
        if tgs_to_krbtgt:
            requester_sid = user_sid

        expect_resource_groups_flag = None
        if tgs_reset_user_flags & netlogon.NETLOGON_RESOURCE_GROUPS:
            expect_resource_groups_flag = False
        elif tgs_set_user_flags & netlogon.NETLOGON_RESOURCE_GROUPS:
            expect_resource_groups_flag = True

        # Perform a TGS-REQ with the user account.

        kdc_exchange_dict = self.tgs_exchange_dict(
            expected_crealm=ticket.crealm,
            expected_cname=cname,
            expected_srealm=realm,
            expected_sname=sname,
            expected_account_name=user_name,
            expected_groups=tgs_expected_mapped,
            expected_sid=tgs_user_sid,
            expected_requester_sid=requester_sid,
            expected_domain_sid=tgs_domain_sid,
            expected_supported_etypes=target_supported_etypes,
            expect_resource_groups_flag=expect_resource_groups_flag,
            ticket_decryption_key=decryption_key,
            check_rep_fn=self.generic_check_kdc_rep,
            check_kdc_private_fn=self.generic_check_kdc_private,
            tgt=ticket,
            authenticator_subkey=subkey,
            kdc_options=kdc_options)

        rep = self._generic_kdc_exchange(kdc_exchange_dict,
                                         cname=None,
                                         realm=realm,
                                         sname=sname,
                                         till_time=till,
                                         etypes=etypes)
        self.check_reply(rep, KRB_TGS_REP)


if __name__ == '__main__':
    global_asn1_print = False
    global_hexdump = False
    import unittest
    unittest.main()
