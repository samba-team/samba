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

from samba.dcerpc import netlogon, security
from samba.tests import DynamicTestCase, env_get_var_value
from samba.tests.krb5 import kcrypto
from samba.tests.krb5.kdc_base_test import GroupType, KDCBaseTest, Principal
from samba.tests.krb5.raw_testcase import Krb5EncryptionKey, RawKerberosTest
from samba.tests.krb5.rfc4120_constants import (
    AES256_CTS_HMAC_SHA1_96,
    ARCFOUR_HMAC_MD5,
    KRB_TGS_REP,
)

SidType = RawKerberosTest.SidType

global_asn1_print = False
global_hexdump = False


@DynamicTestCase
class DeviceTests(KDCBaseTest):
    # Placeholder objects that represent accounts undergoing testing.
    user = object()
    mach = object()
    trust_user = object()
    trust_mach = object()

    # Constants for group SID attributes.
    default_attrs = security.SE_GROUP_DEFAULT_FLAGS
    resource_attrs = default_attrs | security.SE_GROUP_RESOURCE

    asserted_identity = security.SID_AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY
    compounded_auth = security.SID_COMPOUNDED_AUTHENTICATION

    user_trust_domain = 'S-1-5-21-123-456-111'
    mach_trust_domain = 'S-1-5-21-123-456-222'

    def setUp(self):
        super().setUp()
        self.do_asn1_print = global_asn1_print
        self.do_hexdump = global_hexdump

    # Some general information on how Windows handles device info:

    # All the SIDs in the computer's info3.sids end up in device.domain_groups
    # (if they are in any domain), or in device.sids (if they are not). Even if
    # netlogon.NETLOGON_EXTRA_SIDS is not set.

    # The remainder of the SIDs in device.domain_groups come from an LDAP
    # search of the computer's domain-local groups.

    # None of the SIDs in the computer's logon_info.resource_groups.groups go
    # anywhere. Even if netlogon.NETLOGON_RESOURCE_GROUPS is set.

    # In summary:
    # info3.base.groups => device.groups
    # info3.sids => device.sids (if not in a domain)
    # info3.sids => device.domain_groups (if in a domain)
    # searched-for domain-local groups => device.domain_groups

    # These searched-for domain-local groups are based on _all_ the groups in
    # info3.base.groups and info3.sids. So if the account is no longer a member
    # of a (universal or global) group that belongs to a domain-local group,
    # but has that universal or global group in info3.base.groups or
    # info3.sids, then the domain-local group will still get added to the
    # PAC. But the resource groups don't affect this (presumably, they are
    # being filtered out). Also, those groups the search is based on do not go
    # in themselves, even if they are domain-local groups.

    cases = [
        {
            # Make a TGS request to the krbtgt.
            'test': 'basic to krbtgt',
            'as:expected': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'as:mach:expected': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            # Indicate this request is to the krbtgt.
            'tgs:to_krbtgt': True,
            'tgs:expected': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            # Make a TGS request to a service that supports SID compression.
            'test': 'device to service compressed',
            'as:expected': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'as:mach:expected': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:to_krbtgt': False,
            'tgs:compression': True,
            'tgs:expected': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                # The compounded authentication SID indicates that we used FAST
                # with a device's TGT.
                (compounded_auth, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:device:expected': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                frozenset([(security.SID_CLAIMS_VALID, SidType.RESOURCE_SID, default_attrs)]),
            },
        },
        {
            # Make a TGS request to a service that lacks support for SID
            # compression.
            'test': 'device to service uncompressed',
            'as:expected': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'as:mach:expected': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:to_krbtgt': False,
            # SID compression is unsupported.
            'tgs:compression': False,
            # There is no change in the reply PAC.
            'tgs:expected': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (compounded_auth, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:device:expected': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                frozenset([(security.SID_CLAIMS_VALID, SidType.RESOURCE_SID, default_attrs)]),
            },
        },
        {
            # Make a TGS request to a service that lacks support for compound
            # identity.
            'test': 'device to service no compound id',
            'as:expected': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'as:mach:expected': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:to_krbtgt': False,
            # Compound identity is unsupported.
            'tgs:compound_id': False,
            'tgs:expected': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (compounded_auth, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            # The device info is still generated.
            'tgs:device:expected': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                frozenset([(security.SID_CLAIMS_VALID, SidType.RESOURCE_SID, default_attrs)]),
            },
        },
        {
            'test': 'universal groups to krbtgt',
            'groups': {
                # The user and computer each belong to a couple of universal
                # groups.
                'group0': (GroupType.UNIVERSAL, {'group1'}),
                'group1': (GroupType.UNIVERSAL, {user}),
                'group2': (GroupType.UNIVERSAL, {'group3'}),
                'group3': (GroupType.UNIVERSAL, {mach}),
            },
            'as:expected': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                # The user's groups appear in the PAC of the TGT.
                ('group0', SidType.BASE_SID, default_attrs),
                ('group1', SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'as:mach:expected': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                # So too for the computer's groups.
                ('group2', SidType.BASE_SID, default_attrs),
                ('group3', SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:to_krbtgt': True,
            'tgs:expected': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                # The user's groups appear in the TGS reply PAC.
                ('group0', SidType.BASE_SID, default_attrs),
                ('group1', SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'universal groups to service',
            'groups': {
                'group0': (GroupType.UNIVERSAL, {'group1'}),
                'group1': (GroupType.UNIVERSAL, {user}),
                'group2': (GroupType.UNIVERSAL, {'group3'}),
                'group3': (GroupType.UNIVERSAL, {mach}),
            },
            'as:expected': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                ('group0', SidType.BASE_SID, default_attrs),
                ('group1', SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'as:mach:expected': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                ('group2', SidType.BASE_SID, default_attrs),
                ('group3', SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:to_krbtgt': False,
            'tgs:expected': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                ('group0', SidType.BASE_SID, default_attrs),
                ('group1', SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (compounded_auth, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:device:expected': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                # The computer's groups appear in the device info structure of
                # the TGS reply PAC.
                ('group2', SidType.BASE_SID, default_attrs),
                ('group3', SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                frozenset([(security.SID_CLAIMS_VALID, SidType.RESOURCE_SID, default_attrs)]),
            },
        },
        {
            'test': 'domain-local groups to krbtgt',
            'groups': {
                # The user and computer each belong to a couple of domain-local
                # groups.
                'group0': (GroupType.DOMAIN_LOCAL, {'group1'}),
                'group1': (GroupType.DOMAIN_LOCAL, {user}),
                'group2': (GroupType.DOMAIN_LOCAL, {'group3'}),
                'group3': (GroupType.DOMAIN_LOCAL, {mach}),
            },
            'as:expected': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                # The user's domain-local group memberships do not appear.
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'as:mach:expected': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                # Nor do the computer's.
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:to_krbtgt': True,
            'tgs:expected': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                # The user's groups do not appear in the TGS reply PAC.
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'domain-local groups to service compressed',
            'groups': {
                'group0': (GroupType.DOMAIN_LOCAL, {'group1'}),
                'group1': (GroupType.DOMAIN_LOCAL, {user}),
                'group2': (GroupType.DOMAIN_LOCAL, {'group3'}),
                'group3': (GroupType.DOMAIN_LOCAL, {mach}),
            },
            'as:expected': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'as:mach:expected': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:to_krbtgt': False,
            'tgs:compression': True,
            'tgs:expected': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                # These groups appear as resource SIDs.
                ('group0', SidType.RESOURCE_SID, resource_attrs),
                ('group1', SidType.RESOURCE_SID, resource_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (compounded_auth, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:device:expected': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                # The computer's groups appear together as resource SIDs.
                frozenset([
                    ('group2', SidType.RESOURCE_SID, resource_attrs),
                    ('group3', SidType.RESOURCE_SID, resource_attrs),
                ]),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                frozenset([(security.SID_CLAIMS_VALID, SidType.RESOURCE_SID, default_attrs)]),
            },
        },
        {
            'test': 'domain-local groups to service uncompressed',
            'groups': {
                'group0': (GroupType.DOMAIN_LOCAL, {'group1'}),
                'group1': (GroupType.DOMAIN_LOCAL, {user}),
                'group2': (GroupType.DOMAIN_LOCAL, {'group3'}),
                'group3': (GroupType.DOMAIN_LOCAL, {mach}),
            },
            'as:expected': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'as:mach:expected': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:to_krbtgt': False,
            'tgs:compression': False,
            'tgs:expected': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                # The user's groups now appear as extra SIDs.
                ('group0', SidType.EXTRA_SID, resource_attrs),
                ('group1', SidType.EXTRA_SID, resource_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (compounded_auth, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:device:expected': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                # The computer's groups are still resource SIDs.
                frozenset([
                    ('group2', SidType.RESOURCE_SID, resource_attrs),
                    ('group3', SidType.RESOURCE_SID, resource_attrs),
                ]),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                frozenset([(security.SID_CLAIMS_VALID, SidType.RESOURCE_SID, default_attrs)]),
            },
        },
        # Test what happens if the computer is removed from a group prior to
        # the TGS request.
        {
            'test': 'remove transitive domain-local groups to krbtgt',
            'groups': {
                # The computer is transitively a member of a couple of
                # domain-local groups...
                'dom-local-outer-0': (GroupType.DOMAIN_LOCAL, {'dom-local-inner'}),
                'dom-local-outer-1': (GroupType.DOMAIN_LOCAL, {'universal-inner'}),
                # ...via another domain-local group and a universal group.
                'dom-local-inner': (GroupType.DOMAIN_LOCAL, {mach}),
                'universal-inner': (GroupType.UNIVERSAL, {mach}),
            },
            # Just prior to the TGS request, the computer is removed from both
            # inner groups. Domain-local groups will have not been added to the
            # PAC at this point.
            'tgs:mach:removed': {
                'dom-local-inner',
                'universal-inner',
            },
            'as:mach:expected': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                # Only the universal group appears in the PAC.
                ('universal-inner', SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:to_krbtgt': True,
            'tgs:expected': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'remove transitive domain-local groups to service compressed',
            'groups': {
                'dom-local-outer-0': (GroupType.DOMAIN_LOCAL, {'dom-local-inner'}),
                'dom-local-outer-1': (GroupType.DOMAIN_LOCAL, {'universal-inner'}),
                'dom-local-inner': (GroupType.DOMAIN_LOCAL, {mach}),
                'universal-inner': (GroupType.UNIVERSAL, {mach}),
            },
            'tgs:mach:removed': {
                'dom-local-inner',
                'universal-inner',
            },
            'as:mach:expected': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                ('universal-inner', SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:to_krbtgt': False,
            'tgs:compression': True,
            'tgs:expected': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (compounded_auth, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:device:expected': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                # The universal group appears in the device info...
                ('universal-inner', SidType.BASE_SID, default_attrs),
                # ...along with the second domain-local group, even though the
                # computer no longer belongs to it.
                frozenset([
                    ('dom-local-outer-1', SidType.RESOURCE_SID, resource_attrs),
                ]),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                frozenset([(security.SID_CLAIMS_VALID, SidType.RESOURCE_SID, default_attrs)]),
            },
        },
        {
            'test': 'remove transitive domain-local groups to service uncompressed',
            'groups': {
                'dom-local-outer-0': (GroupType.DOMAIN_LOCAL, {'dom-local-inner'}),
                'dom-local-outer-1': (GroupType.DOMAIN_LOCAL, {'universal-inner'}),
                'dom-local-inner': (GroupType.DOMAIN_LOCAL, {mach}),
                'universal-inner': (GroupType.UNIVERSAL, {mach}),
            },
            'tgs:mach:removed': {
                'dom-local-inner',
                'universal-inner',
            },
            'as:mach:expected': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                ('universal-inner', SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:to_krbtgt': False,
            'tgs:compression': False,
            'tgs:expected': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (compounded_auth, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:device:expected': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                ('universal-inner', SidType.BASE_SID, default_attrs),
                frozenset([
                    ('dom-local-outer-1', SidType.RESOURCE_SID, resource_attrs),
                ]),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                frozenset([(security.SID_CLAIMS_VALID, SidType.RESOURCE_SID, default_attrs)]),
            },
        },
        # Test what happens if the computer is added to a group prior to the
        # TGS request.
        {
            'test': 'add transitive domain-local groups to krbtgt',
            'groups': {
                # We create a pair of groups, to be used presently.
                'dom-local-outer': (GroupType.DOMAIN_LOCAL, {'universal-inner'}),
                'universal-inner': (GroupType.UNIVERSAL, {}),
            },
            # Just prior to the TGS request, the computer is added to the inner
            # group.
            'tgs:mach:added': {
                'universal-inner',
            },
            'as:mach:expected': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:to_krbtgt': True,
            'tgs:expected': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'add transitive domain-local groups to service compressed',
            'groups': {
                'dom-local-outer': (GroupType.DOMAIN_LOCAL, {'universal-inner'}),
                'universal-inner': (GroupType.UNIVERSAL, {}),
            },
            'tgs:mach:added': {
                'universal-inner',
            },
            'as:mach:expected': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:to_krbtgt': False,
            'tgs:compression': True,
            'tgs:expected': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (compounded_auth, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:device:expected': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                # The computer was not a member of the universal group at the
                # time of obtaining a TGT, and said group did not make it into
                # the PAC. Group expansion is only concerned with domain-local
                # groups, none of which the machine currently belongs
                # to. Therefore, neither group is present in the device info
                # structure.
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                frozenset([(security.SID_CLAIMS_VALID, SidType.RESOURCE_SID, default_attrs)]),
            },
        },
        {
            'test': 'add transitive domain-local groups to service uncompressed',
            'groups': {
                'dom-local-outer': (GroupType.DOMAIN_LOCAL, {'universal-inner'}),
                'universal-inner': (GroupType.UNIVERSAL, {}),
            },
            'tgs:mach:added': {
                'universal-inner',
            },
            'as:mach:expected': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:to_krbtgt': False,
            'tgs:compression': False,
            'tgs:expected': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (compounded_auth, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:device:expected': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                frozenset([(security.SID_CLAIMS_VALID, SidType.RESOURCE_SID, default_attrs)]),
            },
        },
        # Simulate a machine ticket coming in over a trust.
        {
            'test': 'from trust domain-local groups to service compressed',
            'groups': {
                # The machine belongs to a couple of domain-local groups in our
                # domain.
                'foo': (GroupType.DOMAIN_LOCAL, {trust_mach}),
                'bar': (GroupType.DOMAIN_LOCAL, {'foo'}),
            },
            'tgs:to_krbtgt': False,
            'tgs:compression': True,
            # The machine SID is from a different domain.
            'tgs:mach_sid': trust_mach,
            'tgs:mach:sids': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
                # This dummy resource SID comes from the trusted domain.
                (f'{mach_trust_domain}-333', SidType.RESOURCE_SID, resource_attrs),
            },
            'tgs:expected': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (compounded_auth, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:device:expected': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                # The domain-local groups end up in the device info.
                frozenset([
                    ('foo', SidType.RESOURCE_SID, resource_attrs),
                    ('bar', SidType.RESOURCE_SID, resource_attrs),
                ]),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                frozenset([(security.SID_CLAIMS_VALID, SidType.RESOURCE_SID, default_attrs)]),
            },
        },
        {
            'test': 'from trust domain-local groups to service uncompressed',
            'groups': {
                'foo': (GroupType.DOMAIN_LOCAL, {trust_mach}),
                'bar': (GroupType.DOMAIN_LOCAL, {'foo'}),
            },
            'tgs:to_krbtgt': False,
            'tgs:compression': False,
            'tgs:mach_sid': trust_mach,
            'tgs:mach:sids': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
                (f'{mach_trust_domain}-333', SidType.RESOURCE_SID, resource_attrs),
            },
            'tgs:expected': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (compounded_auth, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:device:expected': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                frozenset([
                    ('foo', SidType.RESOURCE_SID, resource_attrs),
                    ('bar', SidType.RESOURCE_SID, resource_attrs),
                ]),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                frozenset([(security.SID_CLAIMS_VALID, SidType.RESOURCE_SID, default_attrs)]),
            },
        },
        # Simulate the user ticket coming in over a trust.
        {
            'test': 'user from trust domain-local groups to krbtgt',
            'groups': {
                # The user belongs to a couple of domain-local groups in our
                # domain.
                'group0': (GroupType.DOMAIN_LOCAL, {trust_user}),
                'group1': (GroupType.DOMAIN_LOCAL, {'group0'}),
            },
            'tgs:to_krbtgt': True,
            # Both SIDs are from a different domain.
            'tgs:user_sid': trust_user,
            'tgs:user:sids': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
                # This dummy resource SID comes from the trusted domain.
                (f'{mach_trust_domain}-333', SidType.RESOURCE_SID, resource_attrs),
            },
            'tgs:expected': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
                # The dummy resource SID remains in the PAC.
                (f'{mach_trust_domain}-333', SidType.RESOURCE_SID, resource_attrs),
            },
        },
        {
            'test': 'user from trust domain-local groups to service compressed',
            'groups': {
                'group0': (GroupType.DOMAIN_LOCAL, {trust_user}),
                'group1': (GroupType.DOMAIN_LOCAL, {'group0'}),
            },
            'tgs:to_krbtgt': False,
            'tgs:compression': True,
            'tgs:user_sid': trust_user,
            'tgs:user:sids': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
                # This dummy resource SID comes from the trusted domain.
                (f'{mach_trust_domain}-333', SidType.RESOURCE_SID, resource_attrs),
            },
            'tgs:expected': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (compounded_auth, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
                ('group0', SidType.RESOURCE_SID, resource_attrs),
                ('group1', SidType.RESOURCE_SID, resource_attrs),
            },
            'tgs:device:expected': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                frozenset([(security.SID_CLAIMS_VALID, SidType.RESOURCE_SID, default_attrs)]),
            },
        },
        {
            'test': 'user from trust domain-local groups to service uncompressed',
            'groups': {
                'group0': (GroupType.DOMAIN_LOCAL, {trust_user}),
                'group1': (GroupType.DOMAIN_LOCAL, {'group0'}),
            },
            'tgs:to_krbtgt': False,
            'tgs:compression': False,
            'tgs:user_sid': trust_user,
            'tgs:user:sids': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
                # This dummy resource SID comes from the trusted domain.
                (f'{mach_trust_domain}-333', SidType.RESOURCE_SID, resource_attrs),
            },
            'tgs:expected': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (compounded_auth, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
                ('group0', SidType.EXTRA_SID, resource_attrs),
                ('group1', SidType.EXTRA_SID, resource_attrs),
            },
            'tgs:device:expected': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                frozenset([(security.SID_CLAIMS_VALID, SidType.RESOURCE_SID, default_attrs)]),
            },
        },
        # Simulate both tickets coming in over a trust.
        {
            'test': 'both from trust domain-local groups to krbtgt',
            'groups': {
                # The user and machine each belong to a couple of domain-local
                # groups in our domain.
                'group0': (GroupType.DOMAIN_LOCAL, {trust_user}),
                'group1': (GroupType.DOMAIN_LOCAL, {'group0'}),
                'group2': (GroupType.DOMAIN_LOCAL, {trust_mach}),
                'group3': (GroupType.DOMAIN_LOCAL, {'group2'}),
            },
            'tgs:to_krbtgt': True,
            # Both SIDs are from a different domain.
            'tgs:user_sid': trust_user,
            'tgs:mach_sid': trust_mach,
            'tgs:user:sids': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
                # This dummy resource SID comes from the trusted domain.
                (f'{mach_trust_domain}-333', SidType.RESOURCE_SID, resource_attrs),
            },
            'tgs:mach:sids': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
                # This dummy resource SID comes from the trusted domain.
                (f'{mach_trust_domain}-444', SidType.RESOURCE_SID, resource_attrs),
            },
            'tgs:expected': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
                # The dummy resource SID remains in the PAC.
                (f'{mach_trust_domain}-333', SidType.RESOURCE_SID, resource_attrs),
            },
        },
        {
            'test': 'both from trust domain-local groups to service compressed',
            'groups': {
                # The machine belongs to a couple of domain-local groups in our
                # domain.
                'group0': (GroupType.DOMAIN_LOCAL, {trust_user}),
                'group1': (GroupType.DOMAIN_LOCAL, {'group0'}),
                'group2': (GroupType.DOMAIN_LOCAL, {trust_mach}),
                'group3': (GroupType.DOMAIN_LOCAL, {'group2'}),
            },
            'tgs:to_krbtgt': False,
            'tgs:compression': True,
            'tgs:user_sid': trust_user,
            'tgs:mach_sid': trust_mach,
            'tgs:user:sids': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
                # This dummy resource SID comes from the trusted domain.
                (f'{mach_trust_domain}-333', SidType.RESOURCE_SID, resource_attrs),
            },
            'tgs:mach:sids': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
                # This dummy resource SID comes from the trusted domain.
                (f'{mach_trust_domain}-444', SidType.RESOURCE_SID, resource_attrs),
            },
            'tgs:expected': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (compounded_auth, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
                ('group0', SidType.RESOURCE_SID, resource_attrs),
                ('group1', SidType.RESOURCE_SID, resource_attrs),
            },
            'tgs:device:expected': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                # The domain-local groups end up in the device info.
                frozenset([
                    ('group2', SidType.RESOURCE_SID, resource_attrs),
                    ('group3', SidType.RESOURCE_SID, resource_attrs),
                ]),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                frozenset([(security.SID_CLAIMS_VALID, SidType.RESOURCE_SID, default_attrs)]),
            },
        },
        {
            'test': 'both from trust domain-local groups to service uncompressed',
            'groups': {
                'group0': (GroupType.DOMAIN_LOCAL, {trust_user}),
                'group1': (GroupType.DOMAIN_LOCAL, {'group0'}),
                'group2': (GroupType.DOMAIN_LOCAL, {trust_mach}),
                'group3': (GroupType.DOMAIN_LOCAL, {'group2'}),
            },
            'tgs:to_krbtgt': False,
            'tgs:compression': False,
            'tgs:user_sid': trust_user,
            'tgs:mach_sid': trust_mach,
            'tgs:user:sids': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
                # This dummy resource SID comes from the trusted domain.
                (f'{mach_trust_domain}-333', SidType.RESOURCE_SID, resource_attrs),
            },
            'tgs:mach:sids': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
                # This dummy resource SID comes from the trusted domain.
                (f'{mach_trust_domain}-444', SidType.RESOURCE_SID, resource_attrs),
            },
            'tgs:expected': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (compounded_auth, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
                ('group0', SidType.EXTRA_SID, resource_attrs),
                ('group1', SidType.EXTRA_SID, resource_attrs),
            },
            'tgs:device:expected': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                frozenset([
                    ('group2', SidType.RESOURCE_SID, resource_attrs),
                    ('group3', SidType.RESOURCE_SID, resource_attrs),
                ]),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                frozenset([(security.SID_CLAIMS_VALID, SidType.RESOURCE_SID, default_attrs)]),
            },
        },
        # Test how resource SIDs are propagated into the device info structure.
        {
            'test': 'mach resource sids',
            'tgs:mach:sids': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                # Of these SIDs, the Base SIDs and Extra SIDs are all
                # propagated into the device info structure, regardless of
                # their attrs, while the Resource SIDs are all dropped.
                (123, SidType.BASE_SID, default_attrs),
                (333, SidType.BASE_SID, default_attrs),
                (333, SidType.BASE_SID, resource_attrs),
                (1000, SidType.BASE_SID, resource_attrs),
                (497, SidType.EXTRA_SID, resource_attrs),  # the Claims Valid RID.
                (333, SidType.RESOURCE_SID, default_attrs),
                (498, SidType.RESOURCE_SID, resource_attrs),
                (99999, SidType.RESOURCE_SID, default_attrs),
                (12345678, SidType.RESOURCE_SID, resource_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:to_krbtgt': False,
            'tgs:expected': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (compounded_auth, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:device:expected': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                (123, SidType.BASE_SID, default_attrs),
                (333, SidType.BASE_SID, default_attrs),
                (333, SidType.BASE_SID, resource_attrs),
                (1000, SidType.BASE_SID, resource_attrs),
                frozenset({
                    (497, SidType.RESOURCE_SID, resource_attrs),
                }),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                frozenset([(security.SID_CLAIMS_VALID, SidType.RESOURCE_SID, default_attrs)]),
            },
        },
        # Add a Base SID to the user's PAC, and confirm it is propagated into
        # the PAC of the service ticket.
        {
            'test': 'base sid to krbtgt',
            'tgs:user:sids': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (123, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:to_krbtgt': True,
            'tgs:expected': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (123, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'base sid to service',
            'tgs:user:sids': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (123, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:to_krbtgt': False,
            'tgs:expected': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (123, SidType.BASE_SID, default_attrs),
                (compounded_auth, SidType.EXTRA_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:device:expected': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                frozenset([(security.SID_CLAIMS_VALID, SidType.RESOURCE_SID, default_attrs)]),
            },
        },
        # Add a Base SID with resource attrs to the user's PAC, and confirm it
        # is propagated into the PAC of the service ticket.
        {
            'test': 'base sid resource attrs to krbtgt',
            'tgs:user:sids': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (123, SidType.BASE_SID, resource_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:to_krbtgt': True,
            'tgs:expected': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (123, SidType.BASE_SID, resource_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'base sid resource attrs to service',
            'tgs:user:sids': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (123, SidType.BASE_SID, resource_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:to_krbtgt': False,
            'tgs:expected': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (123, SidType.BASE_SID, resource_attrs),
                (compounded_auth, SidType.EXTRA_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:device:expected': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                frozenset([(security.SID_CLAIMS_VALID, SidType.RESOURCE_SID, default_attrs)]),
            },
        },
        # Add a couple of Extra SIDs to the user's PAC, and confirm they are
        # propagated into the PAC of the service ticket.
        {
            'test': 'extra sids to krbtgt',
            'tgs:user:sids': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                ('S-1-5-2-3-4', SidType.EXTRA_SID, default_attrs),
                ('S-1-5-2-3-5', SidType.EXTRA_SID, resource_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:to_krbtgt': True,
            'tgs:expected': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                ('S-1-5-2-3-4', SidType.EXTRA_SID, default_attrs),
                ('S-1-5-2-3-5', SidType.EXTRA_SID, resource_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'extra sids to service',
            'tgs:user:sids': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                ('S-1-5-2-3-4', SidType.EXTRA_SID, default_attrs),
                ('S-1-5-2-3-5', SidType.EXTRA_SID, resource_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:to_krbtgt': False,
            'tgs:expected': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                ('S-1-5-2-3-4', SidType.EXTRA_SID, default_attrs),
                ('S-1-5-2-3-5', SidType.EXTRA_SID, resource_attrs),
                (compounded_auth, SidType.EXTRA_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:device:expected': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                frozenset([(security.SID_CLAIMS_VALID, SidType.RESOURCE_SID, default_attrs)]),
            },
        },
        # Test what happens if we remove the CLAIMS_VALID and ASSERTED_IDENTITY
        # SIDs from either of the PACs, so we can see at what point these SIDs
        # are added.
        {
            'test': 'removed special sids to krbtgt',
            'tgs:user:sids': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                ('S-1-5-2-3-4', SidType.EXTRA_SID, default_attrs),
                # We don't specify asserted identity or claims valid SIDs for
                # the user...
            },
            'tgs:mach:sids': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                # ...nor for the computer.
            },
            'tgs:to_krbtgt': True,
            'tgs:expected': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                ('S-1-5-2-3-4', SidType.EXTRA_SID, default_attrs),
                # They don't show up in the service ticket.
            },
        },
        {
            'test': 'removed special sids to service',
            'tgs:user:sids': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                ('S-1-5-2-3-4', SidType.EXTRA_SID, default_attrs),
            },
            'tgs:mach:sids': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
            },
            'tgs:to_krbtgt': False,
            'tgs:expected': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                ('S-1-5-2-3-4', SidType.EXTRA_SID, default_attrs),
                (compounded_auth, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:device:expected': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                # These special SIDs don't show up in the device info either.
            },
        },
        # Test a group being the primary one for the user and machine.
        {
            'test': 'primary universal to krbtgt',
            'groups': {
                'primary-user': (GroupType.UNIVERSAL, {user}),
                'primary-mach': (GroupType.UNIVERSAL, {mach}),
            },
            # Set these groups as the account's primary groups.
            'primary_group': 'primary-user',
            'mach:primary_group': 'primary-mach',
            'as:expected': {
                # They appear in the PAC as normal.
                ('primary-user', SidType.BASE_SID, default_attrs),
                ('primary-user', SidType.PRIMARY_GID, None),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'as:mach:expected': {
                ('primary-mach', SidType.BASE_SID, default_attrs),
                ('primary-mach', SidType.PRIMARY_GID, None),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:to_krbtgt': True,
            'tgs:expected': {
                ('primary-user', SidType.BASE_SID, default_attrs),
                ('primary-user', SidType.PRIMARY_GID, None),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'primary universal to service compressed',
            'groups': {
                'primary-user': (GroupType.UNIVERSAL, {user}),
                'primary-mach': (GroupType.UNIVERSAL, {mach}),
            },
            'primary_group': 'primary-user',
            'mach:primary_group': 'primary-mach',
            'as:expected': {
                ('primary-user', SidType.BASE_SID, default_attrs),
                ('primary-user', SidType.PRIMARY_GID, None),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'as:mach:expected': {
                ('primary-mach', SidType.BASE_SID, default_attrs),
                ('primary-mach', SidType.PRIMARY_GID, None),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:to_krbtgt': False,
            'tgs:compression': True,
            'tgs:expected': {
                ('primary-user', SidType.BASE_SID, default_attrs),
                ('primary-user', SidType.PRIMARY_GID, None),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (compounded_auth, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:device:expected': {
                ('primary-mach', SidType.BASE_SID, default_attrs),
                ('primary-mach', SidType.PRIMARY_GID, None),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                frozenset([(security.SID_CLAIMS_VALID, SidType.RESOURCE_SID, default_attrs)]),
            },
        },
        {
            'test': 'primary universal to service uncompressed',
            'groups': {
                'primary-user': (GroupType.UNIVERSAL, {user}),
                'primary-mach': (GroupType.UNIVERSAL, {mach}),
            },
            'primary_group': 'primary-user',
            'mach:primary_group': 'primary-mach',
            'as:expected': {
                ('primary-user', SidType.BASE_SID, default_attrs),
                ('primary-user', SidType.PRIMARY_GID, None),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'as:mach:expected': {
                ('primary-mach', SidType.BASE_SID, default_attrs),
                ('primary-mach', SidType.PRIMARY_GID, None),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:to_krbtgt': False,
            # SID compression is unsupported.
            'tgs:compression': False,
            'tgs:expected': {
                ('primary-user', SidType.BASE_SID, default_attrs),
                ('primary-user', SidType.PRIMARY_GID, None),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (compounded_auth, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:device:expected': {
                ('primary-mach', SidType.BASE_SID, default_attrs),
                ('primary-mach', SidType.PRIMARY_GID, None),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                frozenset([(security.SID_CLAIMS_VALID, SidType.RESOURCE_SID, default_attrs)]),
            },
        },
        # Test domain-local primary groups.
        {
            'test': 'primary domain-local to krbtgt',
            'groups': {
                'primary-user': (GroupType.DOMAIN_LOCAL, {user}),
                'primary-mach': (GroupType.DOMAIN_LOCAL, {mach}),
            },
            # Though Windows normally disallows setting domain-locals group as
            # primary groups, Samba does not.
            'primary_group': 'primary-user',
            'mach:primary_group': 'primary-mach',
            'as:expected': {
                # The domain-local groups appear as our primary GIDs, but do
                # not appear in the base SIDs.
                ('primary-user', SidType.PRIMARY_GID, None),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'as:mach:expected': {
                ('primary-mach', SidType.PRIMARY_GID, None),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:to_krbtgt': True,
            'tgs:expected': {
                ('primary-user', SidType.PRIMARY_GID, None),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'primary domain-local to service compressed',
            'groups': {
                'primary-user': (GroupType.DOMAIN_LOCAL, {user}),
                'primary-mach': (GroupType.DOMAIN_LOCAL, {mach}),
            },
            'primary_group': 'primary-user',
            'mach:primary_group': 'primary-mach',
            'as:expected': {
                ('primary-user', SidType.PRIMARY_GID, None),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'as:mach:expected': {
                ('primary-mach', SidType.PRIMARY_GID, None),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:to_krbtgt': False,
            'tgs:compression': True,
            'tgs:expected': {
                ('primary-user', SidType.PRIMARY_GID, None),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (compounded_auth, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:device:expected': {
                ('primary-mach', SidType.PRIMARY_GID, None),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                frozenset([(security.SID_CLAIMS_VALID, SidType.RESOURCE_SID, default_attrs)]),
            },
        },
        {
            'test': 'primary domain-local to service uncompressed',
            'groups': {
                'primary-user': (GroupType.DOMAIN_LOCAL, {user}),
                'primary-mach': (GroupType.DOMAIN_LOCAL, {mach}),
            },
            'primary_group': 'primary-user',
            'mach:primary_group': 'primary-mach',
            'as:expected': {
                ('primary-user', SidType.PRIMARY_GID, None),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'as:mach:expected': {
                ('primary-mach', SidType.PRIMARY_GID, None),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:to_krbtgt': False,
            # SID compression is unsupported.
            'tgs:compression': False,
            'tgs:expected': {
                ('primary-user', SidType.PRIMARY_GID, None),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (compounded_auth, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:device:expected': {
                ('primary-mach', SidType.PRIMARY_GID, None),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                frozenset([(security.SID_CLAIMS_VALID, SidType.RESOURCE_SID, default_attrs)]),
            },
        },
        # Test the scenario where we belong to a now-domain-local group, and
        # possess an old TGT issued when the group was still our primary one.
        {
            'test': 'old primary domain-local to krbtgt',
            'groups': {
                # Domain-local groups to which the accounts belong.
                'primary-user': (GroupType.DOMAIN_LOCAL, {user}),
                'primary-mach': (GroupType.DOMAIN_LOCAL, {mach}),
            },
            'tgs:user:sids': {
                # In the PACs, the groups have the attributes of an ordinary
                # group...
                ('primary-user', SidType.BASE_SID, default_attrs),
                # ...and remain our primary ones.
                ('primary-user', SidType.PRIMARY_GID, None),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:mach:sids': {
                ('primary-mach', SidType.BASE_SID, default_attrs),
                ('primary-mach', SidType.PRIMARY_GID, None),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:to_krbtgt': True,
            'tgs:expected': {
                # The groups don't change.
                ('primary-user', SidType.BASE_SID, default_attrs),
                ('primary-user', SidType.PRIMARY_GID, None),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'old primary domain-local to service compressed',
            'groups': {
                'primary-user': (GroupType.DOMAIN_LOCAL, {user}),
                'primary-mach': (GroupType.DOMAIN_LOCAL, {mach}),
            },
            'tgs:user:sids': {
                ('primary-user', SidType.BASE_SID, default_attrs),
                ('primary-user', SidType.PRIMARY_GID, None),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:mach:sids': {
                ('primary-mach', SidType.BASE_SID, default_attrs),
                ('primary-mach', SidType.PRIMARY_GID, None),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:to_krbtgt': False,
            'tgs:compression': True,
            'tgs:expected': {
                ('primary-user', SidType.BASE_SID, default_attrs),
                ('primary-user', SidType.PRIMARY_GID, None),
                # The groups are added a second time to the PAC, now as
                # resource groups.
                ('primary-user', SidType.RESOURCE_SID, resource_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (compounded_auth, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:device:expected': {
                ('primary-mach', SidType.BASE_SID, default_attrs),
                ('primary-mach', SidType.PRIMARY_GID, None),
                frozenset([('primary-mach', SidType.RESOURCE_SID, resource_attrs)]),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                frozenset([(security.SID_CLAIMS_VALID, SidType.RESOURCE_SID, default_attrs)]),
            },
        },
        {
            'test': 'old primary domain-local to service uncompressed',
            'groups': {
                'primary-user': (GroupType.DOMAIN_LOCAL, {user}),
                'primary-mach': (GroupType.DOMAIN_LOCAL, {mach}),
            },
            'tgs:user:sids': {
                ('primary-user', SidType.BASE_SID, default_attrs),
                ('primary-user', SidType.PRIMARY_GID, None),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:mach:sids': {
                ('primary-mach', SidType.BASE_SID, default_attrs),
                ('primary-mach', SidType.PRIMARY_GID, None),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:to_krbtgt': False,
            # SID compression is unsupported.
            'tgs:compression': False,
            'tgs:expected': {
                ('primary-user', SidType.BASE_SID, default_attrs),
                ('primary-user', SidType.PRIMARY_GID, None),
                # This time, the group is added to Extra SIDs.
                ('primary-user', SidType.EXTRA_SID, resource_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (compounded_auth, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:device:expected': {
                ('primary-mach', SidType.BASE_SID, default_attrs),
                ('primary-mach', SidType.PRIMARY_GID, None),
                frozenset([('primary-mach', SidType.RESOURCE_SID, resource_attrs)]),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                frozenset([(security.SID_CLAIMS_VALID, SidType.RESOURCE_SID, default_attrs)]),
            },
        },
        # Test the scenario where each account possesses an old TGT issued when
        # a now-domain-local group was still its primary one. The accounts no
        # longer belong to those groups, which themselves belong to other
        # domain-local groups.
        {
            'test': 'old primary domain-local transitive to krbtgt',
            'groups': {
                'user-outer': (GroupType.DOMAIN_LOCAL, {'user-inner'}),
                'user-inner': (GroupType.DOMAIN_LOCAL, {}),
                'mach-outer': (GroupType.DOMAIN_LOCAL, {'mach-inner'}),
                'mach-inner': (GroupType.DOMAIN_LOCAL, {}),
            },
            'tgs:user:sids': {
                # In the PACs, the groups have the attributes of an ordinary
                # group...
                ('user-inner', SidType.BASE_SID, default_attrs),
                # ...and remain our primary ones.
                ('user-inner', SidType.PRIMARY_GID, None),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:mach:sids': {
                ('mach-inner', SidType.BASE_SID, default_attrs),
                ('mach-inner', SidType.PRIMARY_GID, None),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:to_krbtgt': True,
            'tgs:expected': {
                # The groups don't change.
                ('user-inner', SidType.BASE_SID, default_attrs),
                ('user-inner', SidType.PRIMARY_GID, None),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            'test': 'old primary domain-local transitive to service compressed',
            'groups': {
                'user-outer': (GroupType.DOMAIN_LOCAL, {'user-inner'}),
                'user-inner': (GroupType.DOMAIN_LOCAL, {}),
                'mach-outer': (GroupType.DOMAIN_LOCAL, {'mach-inner'}),
                'mach-inner': (GroupType.DOMAIN_LOCAL, {}),
            },
            'tgs:user:sids': {
                ('user-inner', SidType.BASE_SID, default_attrs),
                ('user-inner', SidType.PRIMARY_GID, None),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:mach:sids': {
                ('mach-inner', SidType.BASE_SID, default_attrs),
                ('mach-inner', SidType.PRIMARY_GID, None),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:to_krbtgt': False,
            'tgs:compression': True,
            'tgs:expected': {
                ('user-inner', SidType.BASE_SID, default_attrs),
                ('user-inner', SidType.PRIMARY_GID, None),
                # The second resource groups are added a second time to the PAC
                # as resource groups.
                ('user-outer', SidType.RESOURCE_SID, resource_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (compounded_auth, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:device:expected': {
                ('mach-inner', SidType.BASE_SID, default_attrs),
                ('mach-inner', SidType.PRIMARY_GID, None),
                frozenset([('mach-outer', SidType.RESOURCE_SID, resource_attrs)]),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                frozenset([(security.SID_CLAIMS_VALID, SidType.RESOURCE_SID, default_attrs)]),
            },
        },
        {
            'test': 'old primary domain-local transitive to service uncompressed',
            'groups': {
                'user-outer': (GroupType.DOMAIN_LOCAL, {'user-inner'}),
                'user-inner': (GroupType.DOMAIN_LOCAL, {}),
                'mach-outer': (GroupType.DOMAIN_LOCAL, {'mach-inner'}),
                'mach-inner': (GroupType.DOMAIN_LOCAL, {}),
            },
            'tgs:user:sids': {
                ('user-inner', SidType.BASE_SID, default_attrs),
                ('user-inner', SidType.PRIMARY_GID, None),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:mach:sids': {
                ('mach-inner', SidType.BASE_SID, default_attrs),
                ('mach-inner', SidType.PRIMARY_GID, None),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:to_krbtgt': False,
            # SID compression is unsupported.
            'tgs:compression': False,
            'tgs:expected': {
                ('user-inner', SidType.BASE_SID, default_attrs),
                ('user-inner', SidType.PRIMARY_GID, None),
                # This time, the group is added to Extra SIDs.
                ('user-outer', SidType.EXTRA_SID, resource_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (compounded_auth, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:device:expected': {
                ('mach-inner', SidType.BASE_SID, default_attrs),
                ('mach-inner', SidType.PRIMARY_GID, None),
                frozenset([('mach-outer', SidType.RESOURCE_SID, resource_attrs)]),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                frozenset([(security.SID_CLAIMS_VALID, SidType.RESOURCE_SID, default_attrs)]),
            },
        },
        # Test how the various categories of SIDs are propagated into the
        # device info structure.
        {
            'test': 'device info sid grouping',
            'tgs:mach:sids': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                # These base SIDs are simply propagated into the device info,
                # irrespective of whatever attributes they have.
                (1, SidType.BASE_SID, default_attrs),
                (2, SidType.BASE_SID, 12345),
                # Extra SIDs not from a domain are also propagated.
                ('S-1-5-2-3-4', SidType.EXTRA_SID, 789),
                ('S-1-5-20', SidType.EXTRA_SID, 999),
                ('S-1-5-21', SidType.EXTRA_SID, 999),
                ('S-1-6-0', SidType.EXTRA_SID, 999),
                ('S-1-6-2-3-4', SidType.EXTRA_SID, 789),
                # Extra SIDs from our own domain are collated into a group.
                (3, SidType.EXTRA_SID, default_attrs),
                (4, SidType.EXTRA_SID, 12345),
                # Extra SIDs from other domains are collated into separate groups.
                ('S-1-5-21-0-0-0-490', SidType.EXTRA_SID, 5),
                ('S-1-5-21-0-0-0-491', SidType.EXTRA_SID, 6),
                ('S-1-5-21-0-0-1-492', SidType.EXTRA_SID, 7),
                ('S-1-5-21-0-0-1-493', SidType.EXTRA_SID, 8),
                ('S-1-5-21-0-0-1-494', SidType.EXTRA_SID, 9),
                # A non-domain SID (too few subauths), ...
                ('S-1-5-21-242424-12345-2', SidType.EXTRA_SID, 1111111111),
                # ... a domain SID, ...
                ('S-1-5-21-242424-12345-321321-2', SidType.EXTRA_SID, 1111111111),
                # ... and a non-domain SID (too many subauths).
                ('S-1-5-21-242424-12345-321321-654321-2', SidType.EXTRA_SID, default_attrs),
                # Special SIDs.
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:to_krbtgt': False,
            'tgs:expected': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (compounded_auth, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:device:expected': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                # Base SIDs.
                (1, SidType.BASE_SID, default_attrs),
                (2, SidType.BASE_SID, 12345),
                # Extra SIDs from other domains.
                ('S-1-5-2-3-4', SidType.EXTRA_SID, 789),
                ('S-1-5-20', SidType.EXTRA_SID, 999),
                ('S-1-5-21', SidType.EXTRA_SID, 999),
                ('S-1-6-0', SidType.EXTRA_SID, 999),
                ('S-1-6-2-3-4', SidType.EXTRA_SID, 789),
                # Extra SIDs from our own domain.
                frozenset({
                    (3, SidType.RESOURCE_SID, default_attrs),
                    (4, SidType.RESOURCE_SID, 12345),
                }),
                # Extra SIDs from other domains.
                frozenset({
                    ('S-1-5-21-0-0-0-490', SidType.RESOURCE_SID, 5),
                    ('S-1-5-21-0-0-0-491', SidType.RESOURCE_SID, 6),
                    # These SIDs end up placed with the CLAIMS_VALID SID.
                    (security.SID_CLAIMS_VALID, SidType.RESOURCE_SID, default_attrs),
                }),
                frozenset({
                    ('S-1-5-21-0-0-1-492', SidType.RESOURCE_SID, 7),
                    ('S-1-5-21-0-0-1-493', SidType.RESOURCE_SID, 8),
                    ('S-1-5-21-0-0-1-494', SidType.RESOURCE_SID, 9),
                }),
                # Non-domain SID.
                ('S-1-5-21-242424-12345-2', SidType.EXTRA_SID, 1111111111),
                # Domain SID.
                frozenset({
                    ('S-1-5-21-242424-12345-321321-2', SidType.RESOURCE_SID, 1111111111),
                }),
                # Non-domain SID.
                ('S-1-5-21-242424-12345-321321-654321-2', SidType.EXTRA_SID, default_attrs),
                # Special SIDs.
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
            },
        },
        {
            # Test RODC-issued device claims.
            'test': 'rodc-issued device claims attack',
            'groups': {
                # A couple of groups to which the machine belongs.
                'dom-local': (GroupType.DOMAIN_LOCAL, {mach}),
                'universal': (GroupType.UNIVERSAL, {mach}),
            },
            'as:expected': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:mach:sids': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
                # Try to sneak a few extra SIDs into the machine's RODC-issued
                # PAC.
                (security.BUILTIN_RID_ADMINISTRATORS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_ENTERPRISE_READONLY_DCS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_KRBTGT, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_CERT_ADMINS, SidType.RESOURCE_SID, resource_attrs),
                (security.SID_NT_SYSTEM, SidType.EXTRA_SID, default_attrs),
                # Don't include the groups of which the machine is a member.
            },
            # The armor ticket was issued by an RODC.
            'tgs:mach:from_rodc': True,
            'tgs:to_krbtgt': False,
            'tgs:compression': True,
            'tgs:expected': {
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (compounded_auth, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:device:expected': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                # The machine's groups are now included.
                ('universal', SidType.BASE_SID, default_attrs),
                frozenset([
                    ('dom-local', SidType.RESOURCE_SID, resource_attrs),
                    # Note that we're not considered a "member" of 'Allowed
                    # RODC Password Replication Group'.
                ]),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                frozenset([(security.SID_CLAIMS_VALID, SidType.RESOURCE_SID, default_attrs)]),
                # The device groups should have been regenerated, our extra
                # SIDs removed, and our elevation of privilege attack foiled.
            },
        },
    ]

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

            cls.generate_dynamic_test('test_device_info', name,
                                      dict(case))

    def _test_device_info_with_args(self, case):
        # The group arrangement for the test.
        group_setup = case.pop('groups', None)

        # Groups that should be the primary group for the user and machine
        # respectively.
        primary_group = case.pop('primary_group', None)
        mach_primary_group = case.pop('mach:primary_group', None)

        # Whether the TGS-REQ should be directed to the krbtgt.
        tgs_to_krbtgt = case.pop('tgs:to_krbtgt', None)

        # Whether the target server of the TGS-REQ should support compound
        # identity or resource SID compression.
        tgs_compound_id = case.pop('tgs:compound_id', None)
        tgs_compression = case.pop('tgs:compression', None)

        # Optional SIDs to replace those in the PACs prior to a TGS-REQ.
        tgs_user_sids = case.pop('tgs:user:sids', None)
        tgs_mach_sids = case.pop('tgs:mach:sids', None)

        # Whether the machine's TGT should be issued by an RODC.
        tgs_mach_from_rodc = case.pop('tgs:mach:from_rodc', None)

        # Optional groups which the machine is added to or removed from prior
        # to a TGS-REQ , to test how the groups in the device PAC are expanded.
        tgs_mach_added = case.pop('tgs:mach:added', None)
        tgs_mach_removed = case.pop('tgs:mach:removed', None)

        # Optional account SIDs to replace those in the PACs prior to a
        # TGS-REQ.
        tgs_user_sid = case.pop('tgs:user_sid', None)
        tgs_mach_sid = case.pop('tgs:mach_sid', None)

        # User flags that may be set or reset in the PAC prior to a TGS-REQ.
        tgs_mach_set_user_flags = case.pop('tgs:mach:set_user_flags', None)
        tgs_mach_reset_user_flags = case.pop('tgs:mach:reset_user_flags', None)

        # The SIDs we expect to see in the PAC after a AS-REQ or a TGS-REQ.
        as_expected = case.pop('as:expected', None)
        as_mach_expected = case.pop('as:mach:expected', None)
        tgs_expected = case.pop('tgs:expected', None)
        tgs_device_expected = case.pop('tgs:device:expected', None)

        # There should be no parameters remaining in the testcase.
        self.assertFalse(case, 'unexpected parameters in testcase')

        if as_expected is None:
            self.assertIsNotNone(tgs_expected,
                                 'no set of expected SIDs is provided')

        if as_mach_expected is None:
            self.assertIsNotNone(tgs_expected,
                                 'no set of expected machine SIDs is provided')

        if tgs_to_krbtgt is None:
            tgs_to_krbtgt = False

        if tgs_compound_id is None and not tgs_to_krbtgt:
            # Assume the service supports compound identity by default.
            tgs_compound_id = True

        if tgs_to_krbtgt:
            self.assertIsNone(tgs_device_expected,
                              'device SIDs are not added for a krbtgt request')

        self.assertIsNotNone(tgs_expected,
                             'no set of expected TGS SIDs is provided')

        if tgs_user_sid is not None:
            self.assertIsNotNone(tgs_user_sids,
                                 'specified TGS-REQ user SID, but no '
                                 'accompanying user SIDs provided')

        if tgs_mach_sid is not None:
            self.assertIsNotNone(tgs_mach_sids,
                                 'specified TGS-REQ mach SID, but no '
                                 'accompanying machine SIDs provided')

        if tgs_mach_set_user_flags is None:
            tgs_mach_set_user_flags = 0
        else:
            self.assertIsNotNone(tgs_mach_sids,
                                 'specified TGS-REQ set user flags, but no '
                                 'accompanying machine SIDs provided')

        if tgs_mach_reset_user_flags is None:
            tgs_mach_reset_user_flags = 0
        else:
            self.assertIsNotNone(tgs_mach_sids,
                                 'specified TGS-REQ reset user flags, but no '
                                 'accompanying machine SIDs provided')

        if tgs_mach_from_rodc is None:
            tgs_mach_from_rodc = False

        user_use_cache = not group_setup and (
            not primary_group)
        mach_use_cache = not group_setup and (
            not mach_primary_group) and (
            not tgs_mach_added) and (
                not tgs_mach_removed)

        samdb = self.get_samdb()

        domain_sid = samdb.get_domain_sid()

        # Create the user account. It needs to be freshly created rather than
        # cached if there is a possibility of adding it to one or more groups.
        user_creds = self.get_cached_creds(
            account_type=self.AccountType.USER,
            use_cache=user_use_cache)
        user_dn = user_creds.get_dn()
        user_sid = user_creds.get_sid()
        user_name = user_creds.get_username()

        trust_user_rid = random.randint(2000, 0xfffffffe)
        trust_user_sid = f'{self.user_trust_domain}-{trust_user_rid}'

        trust_mach_rid = random.randint(2000, 0xfffffffe)
        trust_mach_sid = f'{self.mach_trust_domain}-{trust_mach_rid}'

        # Create the machine account. It needs to be freshly created rather
        # than cached if there is a possibility of adding it to one or more
        # groups.
        if tgs_mach_from_rodc:
            # If the machine's TGT is to be issued by an RODC, ensure the
            # machine account is allowed to replicate to an RODC.
            mach_opts = {
                'allowed_replication_mock': True,
                'revealed_to_mock_rodc': True,
            }
        else:
            mach_opts = None
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts=mach_opts,
            use_cache=mach_use_cache)
        mach_dn = mach_creds.get_dn()
        mach_dn_str = str(mach_dn)
        mach_sid = mach_creds.get_sid()

        user_principal = Principal(user_dn, user_sid)
        mach_principal = Principal(mach_dn, mach_sid)
        trust_user_principal = Principal(None, trust_user_sid)
        trust_mach_principal = Principal(None, trust_mach_sid)
        preexisting_groups = {
            self.user: user_principal,
            self.mach: mach_principal,
            self.trust_user: trust_user_principal,
            self.trust_mach: trust_mach_principal,
        }
        primary_groups = {}
        if primary_group is not None:
            primary_groups[user_principal] = primary_group
        if mach_primary_group is not None:
            primary_groups[mach_principal] = mach_primary_group
        groups = self.setup_groups(samdb,
                                   preexisting_groups,
                                   group_setup,
                                   primary_groups)
        del group_setup

        if tgs_user_sid is None:
            tgs_user_sid = user_sid
        elif tgs_user_sid in groups:
            tgs_user_sid = groups[tgs_user_sid].sid

        tgs_user_domain_sid, tgs_user_rid = tgs_user_sid.rsplit('-', 1)

        if tgs_mach_sid is None:
            tgs_mach_sid = mach_sid
        elif tgs_mach_sid in groups:
            tgs_mach_sid = groups[tgs_mach_sid].sid

        tgs_mach_domain_sid, tgs_mach_rid = tgs_mach_sid.rsplit('-', 1)

        expected_groups = self.map_sids(as_expected, groups,
                                        domain_sid)
        mach_expected_groups = self.map_sids(as_mach_expected, groups,
                                             domain_sid)
        tgs_user_sids_mapped = self.map_sids(tgs_user_sids, groups,
                                             tgs_user_domain_sid)
        tgs_mach_sids_mapped = self.map_sids(tgs_mach_sids, groups,
                                             tgs_mach_domain_sid)
        tgs_expected_mapped = self.map_sids(tgs_expected, groups,
                                            tgs_user_domain_sid)
        tgs_device_expected_mapped = self.map_sids(tgs_device_expected, groups,
                                                   tgs_mach_domain_sid)

        user_tgt = self.get_tgt(user_creds,
                                expected_groups=expected_groups,
                                unexpected_groups=None)

        mach_tgt = self.get_tgt(mach_creds,
                                expected_groups=mach_expected_groups,
                                unexpected_groups=None)

        if tgs_user_sids is not None:
            # Replace the SIDs in the user's PAC with the ones provided by the
            # test.
            user_tgt = self.ticket_with_sids(user_tgt,
                                             tgs_user_sids_mapped,
                                             tgs_user_domain_sid,
                                             tgs_user_rid)

        if tgs_mach_sids is not None:
            # Replace the SIDs in the machine's PAC with the ones provided by
            # the test.
            mach_tgt = self.ticket_with_sids(mach_tgt,
                                             tgs_mach_sids_mapped,
                                             tgs_mach_domain_sid,
                                             tgs_mach_rid,
                                             set_user_flags=tgs_mach_set_user_flags,
                                             reset_user_flags=tgs_mach_reset_user_flags,
                                             from_rodc=tgs_mach_from_rodc)
        elif tgs_mach_from_rodc:
            mach_tgt = self.issued_by_rodc(mach_tgt)

        if tgs_mach_removed is not None:
            for removed in tgs_mach_removed:
                group_dn = self.map_to_dn(removed, groups, domain_sid=None)
                self.remove_from_group(mach_dn, group_dn)

        if tgs_mach_added is not None:
            for added in tgs_mach_added:
                group_dn = self.map_to_dn(added, groups, domain_sid=None)
                self.add_to_group(mach_dn_str, group_dn, 'member',
                                  expect_attr=False)

        subkey = self.RandomKey(user_tgt.session_key.etype)

        armor_subkey = self.RandomKey(subkey.etype)
        explicit_armor_key = self.generate_armor_key(armor_subkey,
                                                     mach_tgt.session_key)
        armor_key = kcrypto.cf2(explicit_armor_key.key,
                                subkey.key,
                                b'explicitarmor',
                                b'tgsarmor')
        armor_key = Krb5EncryptionKey(armor_key, None)

        target_creds, sname = self.get_target(
            to_krbtgt=tgs_to_krbtgt,
            compound_id=tgs_compound_id,
            compression=tgs_compression)
        srealm = target_creds.get_realm()

        decryption_key = self.TicketDecryptionKey_from_creds(
            target_creds)

        target_supported_etypes = target_creds.tgs_supported_enctypes

        etypes = (AES256_CTS_HMAC_SHA1_96, ARCFOUR_HMAC_MD5)

        kdc_options = '0'
        pac_options = '1'  # claims support

        requester_sid = None
        if tgs_to_krbtgt:
            requester_sid = user_sid

        expect_resource_groups_flag = None
        if tgs_mach_reset_user_flags & netlogon.NETLOGON_RESOURCE_GROUPS:
            expect_resource_groups_flag = False
        elif tgs_mach_set_user_flags & netlogon.NETLOGON_RESOURCE_GROUPS:
            expect_resource_groups_flag = True

        # Perform a TGS-REQ with the user account.

        kdc_exchange_dict = self.tgs_exchange_dict(
            creds=user_creds,
            expected_crealm=user_tgt.crealm,
            expected_cname=user_tgt.cname,
            expected_srealm=srealm,
            expected_sname=sname,
            expected_account_name=user_name,
            ticket_decryption_key=decryption_key,
            generate_fast_fn=self.generate_simple_fast,
            generate_fast_armor_fn=self.generate_ap_req,
            check_rep_fn=self.generic_check_kdc_rep,
            check_kdc_private_fn=self.generic_check_kdc_private,
            tgt=user_tgt,
            armor_key=armor_key,
            armor_tgt=mach_tgt,
            armor_subkey=armor_subkey,
            pac_options=pac_options,
            authenticator_subkey=subkey,
            kdc_options=kdc_options,
            expect_pac=True,
            expect_pac_attrs=tgs_to_krbtgt,
            expect_pac_attrs_pac_request=tgs_to_krbtgt,
            expected_sid=tgs_user_sid,
            expected_requester_sid=requester_sid,
            expected_domain_sid=tgs_user_domain_sid,
            expected_device_domain_sid=tgs_mach_domain_sid,
            expected_supported_etypes=target_supported_etypes,
            expect_resource_groups_flag=expect_resource_groups_flag,
            expected_groups=tgs_expected_mapped,
            unexpected_groups=None,
            expect_device_claims=None,
            expect_device_info=not tgs_to_krbtgt,
            expected_device_groups=tgs_device_expected_mapped)

        rep = self._generic_kdc_exchange(kdc_exchange_dict,
                                         cname=None,
                                         realm=srealm,
                                         sname=sname,
                                         etypes=etypes)
        self.check_reply(rep, KRB_TGS_REP)


if __name__ == '__main__':
    global_asn1_print = False
    global_hexdump = False
    import unittest
    unittest.main()
