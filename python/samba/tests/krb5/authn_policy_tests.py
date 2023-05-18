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

import random

import ldb

from samba import dsdb, ntstatus
from samba.dcerpc import netlogon, security
from samba.ndr import ndr_pack

import samba.tests.krb5.kcrypto as kcrypto
from samba.tests.krb5.kdc_base_test import GroupType
from samba.tests.krb5.kdc_tgs_tests import KdcTgsBaseTests
from samba.tests.krb5.rfc4120_constants import (
    FX_FAST_ARMOR_AP_REQUEST,
    KDC_ERR_BADOPTION,
    KDC_ERR_GENERIC,
    KDC_ERR_NEVER_VALID,
    KDC_ERR_POLICY,
    NT_PRINCIPAL,
    NT_SRV_INST,
)
import samba.tests.krb5.rfc4120_pyasn1 as krb5_asn1

global_asn1_print = False
global_hexdump = False

HRES_SEC_E_INVALID_TOKEN = 0x80090308
HRES_SEC_E_LOGON_DENIED = 0x8009030C


class AuthnPolicyTests(KdcTgsBaseTests):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        cls._max_ticket_life = None
        cls._max_renew_life = None

    def setUp(self):
        super().setUp()
        self.do_asn1_print = global_asn1_print
        self.do_hexdump = global_hexdump

    def get_max_ticket_life(self):
        if self._max_ticket_life is None:
            self._fetch_default_lifetimes()

        return self._max_ticket_life

    def get_max_renew_life(self):
        if self._max_renew_life is None:
            self._fetch_default_lifetimes()

        return self._max_renew_life

    def _fetch_default_lifetimes(self):
        samdb = self.get_samdb()

        domain_policy_dn = samdb.get_default_basedn()
        domain_policy_dn.add_child('CN=Default Domain Policy,CN=System')

        res = samdb.search(domain_policy_dn,
                           scope=ldb.SCOPE_BASE,
                           attrs=['maxTicketAge', 'maxRenewAge'])
        self.assertEqual(1, len(res))

        max_ticket_age = res[0].get('maxTicketAge', idx=0)
        max_renew_age = res[0].get('maxRenewAge', idx=0)

        if max_ticket_age is not None:
            max_ticket_age = int(max_ticket_age.decode('utf-8'))
        else:
            max_ticket_age = 10

        if max_renew_age is not None:
            max_renew_age = int(max_renew_age.decode('utf-8'))
        else:
            max_renew_age = 7

        type(self)._max_ticket_life = max_ticket_age * 60 * 60
        type(self)._max_renew_life = max_renew_age * 24 * 60 * 60

    # Get account credentials for testing.
    def _get_creds(self,
                   account_type=KdcTgsBaseTests.AccountType.USER,
                   member_of=None,
                   protected=False,
                   assigned_policy=None,
                   assigned_silo=None,
                   ntlm=False,
                   spn=None,
                   allowed_rodc=None,
                   cached=True):
        opts = {
            'kerberos_enabled': not ntlm,
            'spn': spn,
        }

        members = ()
        if protected:
            samdb = self.get_samdb()
            protected_users_group = (f'<SID={samdb.get_domain_sid()}-'
                                     f'{security.DOMAIN_RID_PROTECTED_USERS}>')
            members += (protected_users_group,)
        if member_of is not None:
            members += (member_of,)
        if assigned_policy is not None:
            opts['assigned_policy'] = str(assigned_policy)
            cached = False   # Policies are rarely reused between accounts.
        if assigned_silo is not None:
            opts['assigned_silo'] = str(assigned_silo)
            cached = False   # Silos are rarely reused between accounts.
        if allowed_rodc:
            opts['allowed_replication_mock'] = True
            opts['revealed_to_mock_rodc'] = True

        if members:
            opts['member_of'] = members

        return self.get_cached_creds(account_type=account_type,
                                     opts=opts,
                                     use_cache=cached)

    def test_authn_policy_tgt_lifetime_user(self):
        # Create an authentication policy with certain TGT lifetimes set.
        user_life = 111
        computer_life = 222
        service_life = 333
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_tgt_lifetime=user_life,
                                          computer_tgt_lifetime=computer_life,
                                          service_tgt_lifetime=service_life)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Request a Kerberos ticket with a lifetime of two hours, and assert
        # that the actual lifetime matches the user lifetime set in the policy.
        till = self.get_KerberosTime(offset=2 * 60 * 60)  # 2 hours
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=user_life,
                                expected_renew_life=user_life)

    def test_authn_policy_tgt_lifetime_computer(self):
        user_life = 111
        computer_life = 222
        service_life = 333
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_tgt_lifetime=user_life,
                                          computer_tgt_lifetime=computer_life,
                                          service_tgt_lifetime=service_life)

        # Create a computer account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Request a Kerberos ticket with a lifetime of two hours, and assert
        # that the actual lifetime matches the computer lifetime set in the
        # policy.
        till = self.get_KerberosTime(offset=2 * 60 * 60)  # 2 hours
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=computer_life,
                                expected_renew_life=computer_life)

    def test_authn_policy_tgt_lifetime_service(self):
        user_life = 111
        computer_life = 222
        service_life = 333
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_tgt_lifetime=user_life,
                                          computer_tgt_lifetime=computer_life,
                                          service_tgt_lifetime=service_life)

        # Create a managed service account with the assigned policy.
        client_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
            assigned_policy=policy)

        # Request a Kerberos ticket with a lifetime of two hours, and assert
        # that the actual lifetime matches the service lifetime set in the
        # policy.
        till = self.get_KerberosTime(offset=2 * 60 * 60)  # 2 hours
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=service_life,
                                expected_renew_life=service_life)

    def test_authn_silo_tgt_lifetime_user(self):
        # Create an authentication policy with certain TGT lifetimes set.
        user_life = 111
        computer_life = 222
        service_life = 333
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_tgt_lifetime=user_life,
                                          computer_tgt_lifetime=computer_life,
                                          service_tgt_lifetime=service_life)

        # Create a second policy with different lifetimes, so we can verify the
        # correct policy is enforced.
        wrong_policy_id = self.get_new_username()
        wrong_policy = self.create_authn_policy(wrong_policy_id,
                                                enforced=True,
                                                user_tgt_lifetime=444,
                                                computer_tgt_lifetime=555,
                                                service_tgt_lifetime=666)

        # Create an authentication silo with our existing policies.
        silo_id = self.get_new_username()
        silo = self.create_authn_silo(silo_id,
                                      user_policy=str(policy),
                                      computer_policy=str(wrong_policy),
                                      service_policy=str(wrong_policy),
                                      enforced=True)

        # Create a user account assigned to the silo.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_silo=silo)
        client_dn_str = str(client_creds.get_dn())

        # Add the user to the silo as a member.
        self.add_to_group(client_dn_str, silo, 'msDS-AuthNPolicySiloMembers',
                          expect_attr=False)

        # Request a Kerberos ticket with a lifetime of two hours, and assert
        # that the actual lifetime matches the user lifetime set in the
        # appropriate policy.
        till = self.get_KerberosTime(offset=2 * 60 * 60)  # 2 hours
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=user_life,
                                expected_renew_life=user_life)

    def test_authn_silo_tgt_lifetime_computer(self):
        user_life = 111
        computer_life = 222
        service_life = 333
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_tgt_lifetime=user_life,
                                          computer_tgt_lifetime=computer_life,
                                          service_tgt_lifetime=service_life)

        wrong_policy_id = self.get_new_username()
        wrong_policy = self.create_authn_policy(wrong_policy_id,
                                                enforced=True,
                                                user_tgt_lifetime=444,
                                                computer_tgt_lifetime=555,
                                                service_tgt_lifetime=666)

        # Create an authentication silo with our existing policies.
        silo_id = self.get_new_username()
        silo = self.create_authn_silo(silo_id,
                                      user_policy=str(wrong_policy),
                                      computer_policy=str(policy),
                                      service_policy=str(wrong_policy),
                                      enforced=True)

        # Create a computer account assigned to the silo.
        client_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_silo=silo)
        client_dn_str = str(client_creds.get_dn())

        # Add the computer to the silo as a member.
        self.add_to_group(client_dn_str, silo, 'msDS-AuthNPolicySiloMembers',
                          expect_attr=False)

        # Request a Kerberos ticket with a lifetime of two hours, and assert
        # that the actual lifetime matches the computer lifetime set in the
        # appropriate policy.
        till = self.get_KerberosTime(offset=2 * 60 * 60)  # 2 hours
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=computer_life,
                                expected_renew_life=computer_life)

    def test_authn_silo_tgt_lifetime_service(self):
        user_life = 111
        computer_life = 222
        service_life = 333
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_tgt_lifetime=user_life,
                                          computer_tgt_lifetime=computer_life,
                                          service_tgt_lifetime=service_life)

        wrong_policy_id = self.get_new_username()
        wrong_policy = self.create_authn_policy(wrong_policy_id,
                                                enforced=True,
                                                user_tgt_lifetime=444,
                                                computer_tgt_lifetime=555,
                                                service_tgt_lifetime=666)

        # Create an authentication silo with our existing policies.
        silo_id = self.get_new_username()
        silo = self.create_authn_silo(silo_id,
                                      user_policy=str(wrong_policy),
                                      computer_policy=str(wrong_policy),
                                      service_policy=str(policy),
                                      enforced=True)

        # Create a managed service account assigned to the silo.
        client_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
            assigned_silo=silo)
        client_dn_str = str(client_creds.get_dn())

        # Add the managed service account to the silo as a member.
        self.add_to_group(client_dn_str, silo, 'msDS-AuthNPolicySiloMembers',
                          expect_attr=False)

        # Request a Kerberos ticket with a lifetime of two hours, and assert
        # that the actual lifetime matches the service lifetime set in the
        # appropriate policy.
        till = self.get_KerberosTime(offset=2 * 60 * 60)  # 2 hours
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=service_life,
                                expected_renew_life=service_life)

    # Test that an authentication silo takes priority over a policy assigned
    # directly.
    def test_authn_silo_and_policy_tgt_lifetime_user(self):
        # Create an authentication policy with certain TGT lifetimes set.
        user_life = 111
        computer_life = 222
        service_life = 333
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_tgt_lifetime=user_life,
                                          computer_tgt_lifetime=computer_life,
                                          service_tgt_lifetime=service_life)

        # Create a second policy with different lifetimes, so we can verify the
        # correct policy is enforced.
        wrong_policy_id = self.get_new_username()
        wrong_policy = self.create_authn_policy(wrong_policy_id,
                                                enforced=True,
                                                user_tgt_lifetime=444,
                                                computer_tgt_lifetime=555,
                                                service_tgt_lifetime=666)

        # Create an authentication silo with our existing policies.
        silo_id = self.get_new_username()
        silo = self.create_authn_silo(silo_id,
                                      user_policy=str(policy),
                                      computer_policy=str(wrong_policy),
                                      service_policy=str(wrong_policy),
                                      enforced=True)

        # Create a user account assigned to the silo, and also to a policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_silo=silo,
                                       assigned_policy=wrong_policy)
        client_dn_str = str(client_creds.get_dn())

        # Add the user to the silo as a member.
        self.add_to_group(client_dn_str, silo, 'msDS-AuthNPolicySiloMembers',
                          expect_attr=False)

        # Request a Kerberos ticket with a lifetime of two hours, and assert
        # that the actual lifetime matches the user lifetime set in the
        # appropriate policy.
        till = self.get_KerberosTime(offset=2 * 60 * 60)  # 2 hours
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=user_life,
                                expected_renew_life=user_life)

    def test_authn_silo_and_policy_tgt_lifetime_computer(self):
        user_life = 111
        computer_life = 222
        service_life = 333
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_tgt_lifetime=user_life,
                                          computer_tgt_lifetime=computer_life,
                                          service_tgt_lifetime=service_life)

        wrong_policy_id = self.get_new_username()
        wrong_policy = self.create_authn_policy(wrong_policy_id,
                                                enforced=True,
                                                user_tgt_lifetime=444,
                                                computer_tgt_lifetime=555,
                                                service_tgt_lifetime=666)

        # Create an authentication silo with our existing policies.
        silo_id = self.get_new_username()
        silo = self.create_authn_silo(silo_id,
                                      user_policy=str(wrong_policy),
                                      computer_policy=str(policy),
                                      service_policy=str(wrong_policy),
                                      enforced=True)

        # Create a computer account assigned to the silo, and also to a policy.
        client_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_silo=silo,
                                       assigned_policy=wrong_policy)
        client_dn_str = str(client_creds.get_dn())

        # Add the computer to the silo as a member.
        self.add_to_group(client_dn_str, silo, 'msDS-AuthNPolicySiloMembers',
                          expect_attr=False)

        # Request a Kerberos ticket with a lifetime of two hours, and assert
        # that the actual lifetime matches the computer lifetime set in the
        # appropriate policy.
        till = self.get_KerberosTime(offset=2 * 60 * 60)  # 2 hours
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=computer_life,
                                expected_renew_life=computer_life)

    def test_authn_silo_and_policy_tgt_lifetime_service(self):
        user_life = 111
        computer_life = 222
        service_life = 333
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_tgt_lifetime=user_life,
                                          computer_tgt_lifetime=computer_life,
                                          service_tgt_lifetime=service_life)

        wrong_policy_id = self.get_new_username()
        wrong_policy = self.create_authn_policy(wrong_policy_id,
                                                enforced=True,
                                                user_tgt_lifetime=444,
                                                computer_tgt_lifetime=555,
                                                service_tgt_lifetime=666)

        # Create an authentication silo with our existing policies.
        silo_id = self.get_new_username()
        silo = self.create_authn_silo(silo_id,
                                      user_policy=str(wrong_policy),
                                      computer_policy=str(wrong_policy),
                                      service_policy=str(policy),
                                      enforced=True)

        # Create a managed service account assigned to the silo, and also to a
        # policy.
        client_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
            assigned_silo=silo,
            assigned_policy=wrong_policy)
        client_dn_str = str(client_creds.get_dn())

        # Add the managed service account to the silo as a member.
        self.add_to_group(client_dn_str, silo, 'msDS-AuthNPolicySiloMembers',
                          expect_attr=False)

        # Request a Kerberos ticket with a lifetime of two hours, and assert
        # that the actual lifetime matches the service lifetime set in the
        # appropriate policy.
        till = self.get_KerberosTime(offset=2 * 60 * 60)  # 2 hours
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=service_life,
                                expected_renew_life=service_life)

    def test_authn_policy_tgt_lifetime_max(self):
        # Create an authentication policy with the maximum allowable TGT
        # lifetime set.
        INT64_MAX = 0x7fff_ffff_ffff_ffff
        max_lifetime = INT64_MAX // 10_000_000
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_tgt_lifetime=max_lifetime)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Request a Kerberos ticket with a ‘till’ time far in the
        # future, and assert that the actual lifetime is the maximum
        # allowed by the Default Domain policy.
        till = '99991231235959Z'
        expected_lifetime = self.get_max_ticket_life()
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=expected_lifetime,
                                expected_renew_life=expected_lifetime)

    def test_authn_policy_tgt_lifetime_min(self):
        # Create an authentication policy with the minimum allowable TGT
        # lifetime set.
        INT64_MIN = -0x8000_0000_0000_0000
        min_lifetime = round(INT64_MIN / 10_000_000)
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_tgt_lifetime=min_lifetime)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Request a Kerberos ticket with a lifetime of two hours. The request
        # should fail with a NEVER_VALID error.
        till = self.get_KerberosTime(offset=2 * 60 * 60)  # 2 hours
        self._get_tgt(client_creds, till=till,
                      expected_error=KDC_ERR_NEVER_VALID,
                      expect_status=True,
                      expected_status=ntstatus.NT_STATUS_TIME_DIFFERENCE_AT_DC)

    def test_authn_policy_tgt_lifetime_zero(self):
        # Create an authentication policy with the TGT lifetime set to zero.
        lifetime = 0
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_tgt_lifetime=lifetime)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Request a Kerberos ticket with a ‘till’ time far in the
        # future. Assert that the actual lifetime is the maximum
        # allowed by the Default Domain Policy
        till = '99991231235959Z'
        expected_lifetime = self.get_max_ticket_life()
        expected_renew_life = self.get_max_renew_life()
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=expected_lifetime,
                                expected_renew_life=expected_renew_life)

    def test_authn_policy_tgt_lifetime_one_second(self):
        # Create an authentication policy with the TGT lifetime set to one
        # second.
        lifetime = 1
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_tgt_lifetime=lifetime)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Request a Kerberos ticket with a lifetime of two hours, and assert
        # that the actual lifetime matches the user lifetime set in the
        # appropriate policy.
        till = self.get_KerberosTime(offset=2 * 60 * 60)  # 2 hours
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=lifetime,
                                expected_renew_life=lifetime)

    def test_authn_policy_tgt_lifetime_kpasswd_lifetime(self):
        # Create an authentication policy with the TGT lifetime set to two
        # minutes (the lifetime of a kpasswd ticket).
        lifetime = 2 * 60
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_tgt_lifetime=lifetime)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Request a Kerberos ticket with a lifetime of two hours, and assert
        # that the actual lifetime matches the user lifetime set in the
        # appropriate policy.
        till = self.get_KerberosTime(offset=2 * 60 * 60)  # 2 hours
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=lifetime,
                                expected_renew_life=lifetime)

    def test_authn_policy_tgt_lifetime_short_protected(self):
        # Create an authentication policy with a short TGT lifetime set.
        lifetime = 111
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_tgt_lifetime=lifetime)

        # Create a user account with the assigned policy, belonging to the
        # Protected Users group.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       protected=True,
                                       assigned_policy=policy)

        # Request a Kerberos ticket with a lifetime of two hours, and assert
        # that the actual lifetime matches the user lifetime set in the policy.
        till = self.get_KerberosTime(offset=2 * 60 * 60)  # 2 hours
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=lifetime,
                                expected_renew_life=lifetime)

    def test_authn_policy_tgt_lifetime_long_protected(self):
        # Create an authentication policy with a long TGT lifetime set. This
        # exceeds the lifetime of four hours enforced by Protected Users.
        lifetime = 6 * 60 * 60  # 6 hours
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_tgt_lifetime=lifetime)

        # Create a user account with the assigned policy, belonging to the
        # Protected Users group.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       protected=True,
                                       assigned_policy=policy)

        # Request a Kerberos ticket with a lifetime of eight hours, and assert
        # that the actual lifetime matches the user lifetime set in the policy,
        # taking precedence over the lifetime enforced by Protected Users.
        till = self.get_KerberosTime(offset=8 * 60 * 60)  # 8 hours
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=lifetime,
                                expected_renew_life=lifetime)

    def test_authn_policy_tgt_lifetime_zero_protected(self):
        # Create an authentication policy with the TGT lifetime set to zero.
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_tgt_lifetime=0)

        # Create a user account with the assigned policy, belonging to the
        # Protected Users group.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       protected=True,
                                       assigned_policy=policy)

        # Request a Kerberos ticket with a lifetime of six hours, and assert
        # that the actual lifetime is the four hours enforced by Protected
        # Users.
        till = self.get_KerberosTime(offset=6 * 60 * 60)  # 6 hours
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=4 * 60 * 60,
                                expected_renew_life=4 * 60 * 60)

    def test_authn_policy_tgt_lifetime_none_protected(self):
        # Create an authentication policy with no TGT lifetime set.
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True)

        # Create a user account with the assigned policy, belonging to the
        # Protected Users group.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       protected=True,
                                       assigned_policy=policy)

        # Request a Kerberos ticket with a lifetime of six hours, and assert
        # that the actual lifetime is the four hours enforced by Protected
        # Users.
        till = self.get_KerberosTime(offset=6 * 60 * 60)  # 6 hours
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=4 * 60 * 60,
                                expected_renew_life=4 * 60 * 60)

    def test_authn_policy_tgt_lifetime_unenforced_protected(self):
        # Create an unenforced authentication policy with a TGT lifetime set.
        lifetime = 123
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=False,
                                          user_tgt_lifetime=lifetime)

        # Create a user account with the assigned policy, belonging to the
        # Protected Users group.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       protected=True,
                                       assigned_policy=policy)

        # Request a Kerberos ticket with a lifetime of six hours, and assert
        # that the actual lifetime is the four hours enforced by Protected
        # Users.
        till = self.get_KerberosTime(offset=6 * 60 * 60)  # 6 hours
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=4 * 60 * 60,
                                expected_renew_life=4 * 60 * 60)

    def test_authn_policy_not_enforced(self):
        # Create an authentication policy with the TGT lifetime set. The policy
        # is not enforced.
        lifetime = 123
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          user_tgt_lifetime=lifetime)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Request a Kerberos ticket with a ‘till’ time far in the
        # future. Assert that the actual lifetime is the maximum allowed by
        # the Default Domain Policy.
        till = '99991231235959Z'
        expected_lifetime = self.get_max_ticket_life()
        expected_renew_life = self.get_max_renew_life()
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=expected_lifetime,
                                expected_renew_life=expected_renew_life)

    def test_authn_policy_unenforced(self):
        # Create an authentication policy with the TGT lifetime set. The policy
        # is set to be unenforced.
        lifetime = 123
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=False,
                                          user_tgt_lifetime=lifetime)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Request a Kerberos ticket with a ‘till’ time far in the
        # future. Assert that the actual lifetime is the maximum allowed by
        # the Default Domain Policy.
        till = '99991231235959Z'
        expected_lifetime = self.get_max_ticket_life()
        expected_renew_life = self.get_max_renew_life()
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=expected_lifetime,
                                expected_renew_life=expected_renew_life)

    def test_authn_silo_not_enforced(self):
        # Create an authentication policy with the TGT lifetime set.
        lifetime = 123
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_tgt_lifetime=lifetime)

        # Create an authentication silo with our existing policy. The silo is
        # not enforced.
        silo_id = self.get_new_username()
        silo = self.create_authn_silo(silo_id,
                                      user_policy=str(policy))

        # Create a user account assigned to the silo.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_silo=silo)
        client_dn_str = str(client_creds.get_dn())

        # Add the user to the silo as a member.
        self.add_to_group(client_dn_str, silo, 'msDS-AuthNPolicySiloMembers',
                          expect_attr=False)

        # Request a Kerberos ticket with a ‘till’ time far in the
        # future. Assert that the actual lifetime is the maximum allowed by
        # the Default Domain Policy.
        till = '99991231235959Z'
        expected_lifetime = self.get_max_ticket_life()
        expected_renew_life = self.get_max_renew_life()
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=expected_lifetime,
                                expected_renew_life=expected_renew_life)

    def test_authn_silo_unenforced(self):
        # Create an authentication policy with the TGT lifetime set.
        lifetime = 123
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_tgt_lifetime=lifetime)

        # Create an authentication silo with our existing policy. The silo is
        # set to be unenforced.
        silo_id = self.get_new_username()
        silo = self.create_authn_silo(silo_id,
                                      user_policy=str(policy),
                                      enforced=False)

        # Create a user account assigned to the silo.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_silo=silo)
        client_dn_str = str(client_creds.get_dn())

        # Add the user to the silo as a member.
        self.add_to_group(client_dn_str, silo, 'msDS-AuthNPolicySiloMembers',
                          expect_attr=False)

        # Request a Kerberos ticket with a ‘till’ time far in the
        # future. Assert that the actual lifetime is the maximum allowed by
        # the Default Domain Policy.
        till = '99991231235959Z'
        expected_lifetime = self.get_max_ticket_life()
        expected_renew_life = self.get_max_renew_life()
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=expected_lifetime,
                                expected_renew_life=expected_renew_life)

    def test_authn_silo_not_enforced_policy(self):
        # Create an authentication policy with the TGT lifetime set. The policy
        # is not enforced.
        lifetime = 123
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          user_tgt_lifetime=lifetime)

        # Create an authentication silo with our existing policy.
        silo_id = self.get_new_username()
        silo = self.create_authn_silo(silo_id,
                                      user_policy=str(policy),
                                      enforced=True)

        # Create a user account assigned to the silo.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_silo=silo)
        client_dn_str = str(client_creds.get_dn())

        # Add the user to the silo as a member.
        self.add_to_group(client_dn_str, silo, 'msDS-AuthNPolicySiloMembers',
                          expect_attr=False)

        # Request a Kerberos ticket with a lifetime of two hours. Despite the
        # fact that the policy is unenforced, the actual lifetime matches the
        # user lifetime set in the appropriate policy.
        till = self.get_KerberosTime(offset=2 * 60 * 60)  # 2 hours
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=lifetime,
                                expected_renew_life=lifetime)

    def test_authn_silo_unenforced_policy(self):
        # Create an authentication policy with the TGT lifetime set. The policy
        # is set to be unenforced.
        lifetime = 123
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=False,
                                          user_tgt_lifetime=lifetime)

        # Create an authentication silo with our existing policy.
        silo_id = self.get_new_username()
        silo = self.create_authn_silo(silo_id,
                                      user_policy=str(policy),
                                      enforced=True)

        # Create a user account assigned to the silo.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_silo=silo)
        client_dn_str = str(client_creds.get_dn())

        # Add the user to the silo as a member.
        self.add_to_group(client_dn_str, silo, 'msDS-AuthNPolicySiloMembers',
                          expect_attr=False)

        # Request a Kerberos ticket with a lifetime of two hours. Despite the
        # fact that the policy is unenforced, the actual lifetime matches the
        # user lifetime set in the appropriate policy.
        till = self.get_KerberosTime(offset=2 * 60 * 60)  # 2 hours
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=lifetime,
                                expected_renew_life=lifetime)

    def test_authn_silo_not_enforced_and_assigned_policy(self):
        # Create an authentication policy with the TGT lifetime set.
        silo_lifetime = 123
        silo_policy_id = self.get_new_username()
        silo_policy = self.create_authn_policy(silo_policy_id,
                                               enforced=True,
                                               user_tgt_lifetime=silo_lifetime)

        # Create an authentication silo with our existing policy. The silo is
        # not enforced.
        silo_id = self.get_new_username()
        silo = self.create_authn_silo(silo_id,
                                      user_policy=str(silo_policy))

        # Create a second policy with a different lifetime, so we can verify
        # the correct policy is enforced.
        lifetime = 456
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_tgt_lifetime=lifetime)

        # Create a user account assigned to the silo, and also to the policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_silo=silo,
                                       assigned_policy=policy)
        client_dn_str = str(client_creds.get_dn())

        # Add the user to the silo as a member.
        self.add_to_group(client_dn_str, silo, 'msDS-AuthNPolicySiloMembers',
                          expect_attr=False)

        # Request a Kerberos ticket with a ‘till’ time far in the
        # future. Assert that the actual lifetime is the maximum
        # allowed by the Default Domain Policy. The directly-assigned
        # policy is not enforced.
        till = '99991231235959Z'
        expected_lifetime = self.get_max_ticket_life()
        expected_renew_life = self.get_max_renew_life()
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=expected_lifetime,
                                expected_renew_life=expected_renew_life)

    def test_authn_silo_unenforced_and_assigned_policy(self):
        # Create an authentication policy with the TGT lifetime set.
        silo_lifetime = 123
        silo_policy_id = self.get_new_username()
        silo_policy = self.create_authn_policy(silo_policy_id,
                                               enforced=True,
                                               user_tgt_lifetime=silo_lifetime)

        # Create an authentication silo with our existing policy. The silo is
        # set to be unenforced.
        silo_id = self.get_new_username()
        silo = self.create_authn_silo(silo_id,
                                      user_policy=str(silo_policy),
                                      enforced=False)

        # Create a second policy with a different lifetime, so we can verify
        # the correct policy is enforced.
        lifetime = 456
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_tgt_lifetime=lifetime)

        # Create a user account assigned to the silo, and also to the policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_silo=silo,
                                       assigned_policy=policy)
        client_dn_str = str(client_creds.get_dn())

        # Add the user to the silo as a member.
        self.add_to_group(client_dn_str, silo, 'msDS-AuthNPolicySiloMembers',
                          expect_attr=False)

        # Request a Kerberos ticket with a ‘till’ time far in the
        # future. Assert that the actual lifetime is the maximum
        # allowed by the Default Domain Policy. The directly-assigned
        # policy is not enforced.
        till = '99991231235959Z'
        expected_lifetime = self.get_max_ticket_life()
        expected_renew_life = self.get_max_renew_life()
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=expected_lifetime,
                                expected_renew_life=expected_renew_life)

    def test_authn_silo_not_enforced_policy_and_assigned_policy(self):
        # Create an authentication policy with the TGT lifetime set. The policy
        # is not enforced.
        silo_lifetime = 123
        silo_policy_id = self.get_new_username()
        silo_policy = self.create_authn_policy(silo_policy_id,
                                               user_tgt_lifetime=silo_lifetime)

        # Create an authentication silo with our existing policy.
        silo_id = self.get_new_username()
        silo = self.create_authn_silo(silo_id,
                                      user_policy=str(silo_policy),
                                      enforced=True)

        # Create a second policy with a different lifetime, so we can verify
        # the correct policy is enforced.
        lifetime = 456
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_tgt_lifetime=lifetime)

        # Create a user account assigned to the silo, and also to the policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_silo=silo,
                                       assigned_policy=policy)
        client_dn_str = str(client_creds.get_dn())

        # Add the user to the silo as a member.
        self.add_to_group(client_dn_str, silo, 'msDS-AuthNPolicySiloMembers',
                          expect_attr=False)

        # Request a Kerberos ticket with a lifetime of two hours. Despite the
        # fact that the policy is unenforced, the actual lifetime matches the
        # user lifetime set in the appropriate policy. The directly-assigned
        # policy is not enforced.
        till = self.get_KerberosTime(offset=2 * 60 * 60)  # 2 hours
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=silo_lifetime,
                                expected_renew_life=silo_lifetime)

    def test_authn_silo_unenforced_policy_and_assigned_policy(self):
        # Create an authentication policy with the TGT lifetime set. The policy
        # is set to be unenforced.
        silo_lifetime = 123
        silo_policy_id = self.get_new_username()
        silo_policy = self.create_authn_policy(silo_policy_id,
                                               enforced=False,
                                               user_tgt_lifetime=silo_lifetime)

        # Create an authentication silo with our existing policy.
        silo_id = self.get_new_username()
        silo = self.create_authn_silo(silo_id,
                                      user_policy=str(silo_policy),
                                      enforced=True)

        # Create a second policy with a different lifetime, so we can verify
        # the correct policy is enforced.
        lifetime = 456
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_tgt_lifetime=lifetime)

        # Create a user account assigned to the silo, and also to the policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_silo=silo,
                                       assigned_policy=policy)
        client_dn_str = str(client_creds.get_dn())

        # Add the user to the silo as a member.
        self.add_to_group(client_dn_str, silo, 'msDS-AuthNPolicySiloMembers',
                          expect_attr=False)

        # Request a Kerberos ticket with a lifetime of two hours. Despite the
        # fact that the policy is unenforced, the actual lifetime matches the
        # user lifetime set in the appropriate policy. The directly-assigned
        # policy is not enforced.
        till = self.get_KerberosTime(offset=2 * 60 * 60)  # 2 hours
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=silo_lifetime,
                                expected_renew_life=silo_lifetime)

    def test_authn_silo_not_a_member(self):
        # Create an authentication policy with the TGT lifetime set.
        lifetime = 123
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_tgt_lifetime=lifetime)

        # Create an authentication silo with our existing policy.
        silo_id = self.get_new_username()
        silo = self.create_authn_silo(silo_id,
                                      user_policy=str(policy),
                                      enforced=True)

        # Create a user account assigned to the silo.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_silo=silo)

        # Do not add the user to the silo as a member.

        # Request a Kerberos ticket with a ‘till’ time far in the
        # future. Assert that the actual lifetime is the maximum allowed by
        # the Default Domain Policy.
        till = '99991231235959Z'
        expected_lifetime = self.get_max_ticket_life()
        expected_renew_life = self.get_max_renew_life()
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=expected_lifetime,
                                expected_renew_life=expected_renew_life)

    def test_authn_silo_not_a_member_and_assigned_policy(self):
        # Create an authentication policy with the TGT lifetime set.
        silo_lifetime = 123
        silo_policy_id = self.get_new_username()
        silo_policy = self.create_authn_policy(silo_policy_id,
                                               enforced=True,
                                               user_tgt_lifetime=silo_lifetime)

        # Create an authentication silo with our existing policy.
        silo_id = self.get_new_username()
        silo = self.create_authn_silo(silo_id,
                                      user_policy=str(silo_policy),
                                      enforced=True)

        # Create a second policy with a different lifetime, so we can verify
        # the correct policy is enforced.
        lifetime = 456
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_tgt_lifetime=lifetime)

        # Create a user account assigned to the silo, and also to the policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_silo=silo,
                                       assigned_policy=policy)

        # Do not add the user to the silo as a member.

        # Request a Kerberos ticket with a lifetime of two hours, and assert
        # that the actual lifetime matches the user lifetime set in the
        # directly-assigned policy.
        till = self.get_KerberosTime(offset=2 * 60 * 60)  # 2 hours
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=lifetime,
                                expected_renew_life=lifetime)

    def test_authn_silo_not_assigned(self):
        # Create an authentication policy with the TGT lifetime set.
        lifetime = 123
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_tgt_lifetime=lifetime)

        # Create an authentication silo with our existing policies.
        silo_id = self.get_new_username()
        silo = self.create_authn_silo(silo_id,
                                      user_policy=str(policy),
                                      enforced=True)

        # Create a user account, but don’t assign it to the silo.
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        client_dn_str = str(client_creds.get_dn())

        # Add the user to the silo as a member.
        self.add_to_group(client_dn_str, silo, 'msDS-AuthNPolicySiloMembers',
                          expect_attr=False)

        # Request a Kerberos ticket with a ‘till’ time far in the
        # future. Assert that the actual lifetime is the maximum allowed by
        # the Default Domain Policy.
        till = '99991231235959Z'
        expected_lifetime = self.get_max_ticket_life()
        expected_renew_life = self.get_max_renew_life()
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=expected_lifetime,
                                expected_renew_life=expected_renew_life)

    def test_authn_silo_not_assigned_and_assigned_policy(self):
        # Create an authentication policy with the TGT lifetime set.
        lifetime = 123
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_tgt_lifetime=lifetime)

        # Create an authentication silo with our existing policies.
        silo_id = self.get_new_username()
        silo = self.create_authn_silo(silo_id,
                                      user_policy=str(policy),
                                      enforced=True)

        # Create a second policy with a different lifetime, so we can verify
        # the correct policy is enforced.
        lifetime = 456
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_tgt_lifetime=lifetime)

        # Create a user account assigned to the policy, but not to the silo.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)
        client_dn_str = str(client_creds.get_dn())

        # Add the user to the silo as a member.
        self.add_to_group(client_dn_str, silo, 'msDS-AuthNPolicySiloMembers',
                          expect_attr=False)

        # Request a Kerberos ticket with a lifetime of two hours, and assert
        # that the actual lifetime matches the user lifetime set in the
        # directly-assigned policy.
        till = self.get_KerberosTime(offset=2 * 60 * 60)  # 2 hours
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=lifetime,
                                expected_renew_life=lifetime)

    def test_authn_silo_no_applicable_policy(self):
        # Create an authentication policy with the TGT lifetime set.
        user_life = 111
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_tgt_lifetime=user_life)

        # Create an authentication silo containing no policies.
        silo_id = self.get_new_username()
        silo = self.create_authn_silo(silo_id,
                                      enforced=True)

        # Create a user account assigned to the silo, and also to a policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_silo=silo,
                                       assigned_policy=policy)
        client_dn_str = str(client_creds.get_dn())

        # Add the user to the silo as a member.
        self.add_to_group(client_dn_str, silo, 'msDS-AuthNPolicySiloMembers',
                          expect_attr=False)

        # Request a Kerberos ticket with a ‘till’ time far in the
        # future, and assert that the actual lifetime is the maximum
        # allowed by the Default Domain Policy.
        till = '99991231235959Z'
        expected_lifetime = self.get_max_ticket_life()
        expected_renew_life = self.get_max_renew_life()
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=expected_lifetime,
                                expected_renew_life=expected_renew_life)

    def test_authn_silo_no_tgt_lifetime(self):
        # Create an authentication policy with no TGT lifetime set.
        silo_policy_id = self.get_new_username()
        silo_policy = self.create_authn_policy(silo_policy_id,
                                               enforced=True)

        # Create a second policy with a lifetime set, so we can verify the
        # correct policy is enforced.
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_tgt_lifetime=456)

        # Create an authentication silo with our existing policy.
        silo_id = self.get_new_username()
        silo = self.create_authn_silo(silo_id,
                                      user_policy=str(silo_policy),
                                      enforced=True)

        # Create a user account assigned to the silo, and also to a policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_silo=silo,
                                       assigned_policy=policy)
        client_dn_str = str(client_creds.get_dn())

        # Add the user to the silo as a member.
        self.add_to_group(client_dn_str, silo, 'msDS-AuthNPolicySiloMembers',
                          expect_attr=False)

        # Request a Kerberos ticket with a ‘till’ time far in the
        # future, and assert that the actual lifetime is the maximum
        # allowed by the Default Domain Policy.
        till = '99991231235959Z'
        expected_lifetime = self.get_max_ticket_life()
        expected_renew_life = self.get_max_renew_life()
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=expected_lifetime,
                                expected_renew_life=expected_renew_life)

    def test_not_a_policy(self):
        # Create a user account with the assigned policy set to something that
        # isn’t a policy.
        samdb = self.get_samdb()
        client_creds = self._get_creds(
            account_type=self.AccountType.USER,
            assigned_policy=samdb.get_default_basedn())

        # Request a Kerberos ticket with a ‘till’ time far in the
        # future, and assert that the actual lifetime is the maximum
        # allowed by the Default Domain Policy.
        till = '99991231235959Z'
        expected_lifetime = self.get_max_ticket_life()
        expected_renew_life = self.get_max_renew_life()
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=expected_lifetime,
                                expected_renew_life=expected_renew_life)

    def test_not_a_silo(self):
        # Create a user account assigned to a silo that isn’t a silo.
        samdb = self.get_samdb()
        client_creds = self._get_creds(
            account_type=self.AccountType.USER,
            assigned_silo=samdb.get_default_basedn())

        # Request a Kerberos ticket with a ‘till’ time far in the
        # future, and assert that the actual lifetime is the maximum
        # allowed by the Default Domain Policy.
        till = '99991231235959Z'
        expected_lifetime = self.get_max_ticket_life()
        expected_renew_life = self.get_max_renew_life()
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=expected_lifetime,
                                expected_renew_life=expected_renew_life)

    def test_not_a_silo_and_policy(self):
        # Create an authentication policy with the TGT lifetime set.
        user_life = 123
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_tgt_lifetime=user_life)

        # Create a user account assigned to a silo that isn’t a silo, and also
        # to a policy.
        samdb = self.get_samdb()
        client_creds = self._get_creds(
            account_type=self.AccountType.USER,
            assigned_silo=samdb.get_default_basedn(),
            assigned_policy=policy)

        # Request a Kerberos ticket with a lifetime of two hours, and assert
        # that the actual lifetime matches the user lifetime set in the
        # directly-assigned policy.
        till = self.get_KerberosTime(offset=2 * 60 * 60)  # 2 hours
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=user_life,
                                expected_renew_life=user_life)

    def test_authn_policy_allowed_from_empty(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create an authentication policy with no DACL in the security
        # descriptor.
        allowed_from = 'O:SY'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_from=allowed_from)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that we can authenticate using an armor ticket.
        self._get_tgt(client_creds, armor_tgt=mach_tgt)

    def test_authn_policy_allowed_from_user_allow(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create an authentication policy that explicitly allows the machine
        # account for a user. Include some different TGT lifetimes for testing
        # what gets logged.
        allowed = f'O:SYD:(A;;CR;;;{mach_creds.get_sid()})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_from=allowed,
                                          user_tgt_lifetime=120,
                                          computer_tgt_lifetime=240,
                                          service_allowed_from=denied,
                                          service_tgt_lifetime=360)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that we can authenticate using an armor ticket.
        self._get_tgt(client_creds, armor_tgt=mach_tgt)

    def test_authn_policy_allowed_from_user_deny(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create an authentication policy that explicitly denies the machine
        # account for a user. Include some different TGT lifetimes for testing
        # what gets logged.
        allowed = 'O:SYD:(A;;CR;;;WD)'
        denied = f'O:SYD:(D;;CR;;;{mach_creds.get_sid()})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_from=denied,
                                          user_tgt_lifetime=120,
                                          computer_tgt_lifetime=240,
                                          service_allowed_from=allowed,
                                          service_tgt_lifetime=360)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that we get a policy error when trying to authenticate.
        self._get_tgt(client_creds, armor_tgt=mach_tgt,
                      expected_error=KDC_ERR_POLICY)

    def test_authn_policy_allowed_from_service_allow(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create an authentication policy that explicitly allows the machine
        # account for a service.
        allowed = f'O:SYD:(A;;CR;;;{mach_creds.get_sid()})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_from=denied,
                                          service_allowed_from=allowed)

        # Create a managed service account with the assigned policy.
        client_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
            assigned_policy=policy)

        # Show that we can authenticate using an armor ticket.
        self._get_tgt(client_creds, armor_tgt=mach_tgt)

    def test_authn_policy_allowed_from_service_deny(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create an authentication policy that explicitly denies the machine
        # account for a service.
        allowed = 'O:SYD:(A;;CR;;;WD)'
        denied = f'O:SYD:(D;;CR;;;{mach_creds.get_sid()})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_from=allowed,
                                          service_allowed_from=denied)

        # Create a managed service account with the assigned policy.
        client_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
            assigned_policy=policy)

        # Show that we get a policy error when trying to authenticate.
        self._get_tgt(client_creds, armor_tgt=mach_tgt,
                      expected_error=KDC_ERR_POLICY)

    def test_authn_policy_allowed_from_no_owner(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create an authentication policy that explicitly allows the machine
        # account for a user. Omit the owner (O:SY) from the SDDL.
        allowed = 'D:(A;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that we get a generic error if the security descriptor lacks an
        # owner.
        self._get_tgt(client_creds, armor_tgt=mach_tgt,
                      expected_error=KDC_ERR_GENERIC)

    def test_authn_policy_allowed_from_no_owner_unenforced(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create an unenforced authentication policy that explicitly allows the
        # machine account for a user. Omit the owner (O:SY) from the SDDL.
        allowed = 'D:(A;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=False,
                                          user_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that we don’t get an error if the policy is unenforced.
        self._get_tgt(client_creds, armor_tgt=mach_tgt)

    def test_authn_policy_allowed_from_owner_self(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create an authentication policy that explicitly allows the machine
        # account for a user. Set the owner to the machine account.
        allowed = f'O:{mach_creds.get_sid()}D:(A;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that we can authenticate using an armor ticket.
        self._get_tgt(client_creds, armor_tgt=mach_tgt)

    def test_authn_policy_allowed_from_owner_anon(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create an authentication policy that explicitly allows the machine
        # account for a user. Set the owner to be anonymous.
        allowed = 'O:AND:(A;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that we can authenticate using an armor ticket.
        self._get_tgt(client_creds, armor_tgt=mach_tgt)

    def test_authn_policy_allowed_from_no_fast(self):
        # Create an authentication policy that restricts authentication.
        # Include some different TGT lifetimes for testing what gets logged.
        allowed_from = 'O:SY'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_from=allowed_from,
                                          user_tgt_lifetime=115,
                                          computer_tgt_lifetime=235,
                                          service_tgt_lifetime=355)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that we cannot authenticate without using an armor ticket.
        self._get_tgt(client_creds, expected_error=KDC_ERR_POLICY,
                      expect_status=True,
                      expected_status=ntstatus.NT_STATUS_INVALID_WORKSTATION)

    def test_authn_policy_allowed_from_no_fast_negative_lifetime(self):
        # Create an authentication policy that restricts
        # authentication. Include some negative TGT lifetimes for testing what
        # gets logged.
        allowed_from = 'O:SY'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_from=allowed_from,
                                          user_tgt_lifetime=-115,
                                          computer_tgt_lifetime=-235,
                                          service_tgt_lifetime=-355)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that we cannot authenticate without using an armor ticket.
        self._get_tgt(client_creds, expected_error=KDC_ERR_POLICY,
                      expect_status=True,
                      expected_status=ntstatus.NT_STATUS_INVALID_WORKSTATION)

    def test_authn_policy_allowed_from_no_fast_unenforced(self):
        # Create an unenforced authentication policy that restricts
        # authentication.
        allowed_from = 'O:SY'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=False,
                                          user_allowed_from=allowed_from)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that we don’t get an error when the policy is unenforced.
        self._get_tgt(client_creds)

    def test_authn_policy_allowed_from_user_allow_group_not_a_member(self):
        samdb = self.get_samdb()

        # Create a new group.
        group_name = self.get_new_username()
        group_dn = self.create_group(samdb, group_name)
        group_sid = self.get_objectSid(samdb, group_dn)

        # Create a machine account with which to perform FAST and which does
        # not belong to the group.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create an authentication policy that allows accounts belonging to the
        # group.
        allowed = f'O:SYD:(A;;CR;;;{group_sid})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that we get a policy error, as the machine account does not
        # belong to the group.
        self._get_tgt(client_creds, armor_tgt=mach_tgt,
                      expected_error=KDC_ERR_POLICY)

    def test_authn_policy_allowed_from_user_allow_group_member(self):
        samdb = self.get_samdb()

        # Create a new group.
        group_name = self.get_new_username()
        group_dn = self.create_group(samdb, group_name)
        group_sid = self.get_objectSid(samdb, group_dn)

        # Create a machine account with which to perform FAST that belongs to
        # the group.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'member_of': (group_dn,)})
        mach_tgt = self.get_tgt(mach_creds)

        # Create an authentication policy that allows accounts belonging to the
        # group.
        allowed = f'O:SYD:(A;;CR;;;{group_sid})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that we can authenticate using an armor ticket, since the
        # machine account belongs to the group.
        self._get_tgt(client_creds, armor_tgt=mach_tgt)

    def test_authn_policy_allowed_from_user_allow_domain_local_group(self):
        samdb = self.get_samdb()

        # Create a new domain-local group.
        group_name = self.get_new_username()
        group_dn = self.create_group(samdb, group_name,
                                     gtype=GroupType.DOMAIN_LOCAL.value)
        group_sid = self.get_objectSid(samdb, group_dn)

        # Create a machine account with which to perform FAST that belongs to
        # the group.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'member_of': (group_dn,)})
        mach_tgt = self.get_tgt(mach_creds)

        # Create an authentication policy that allows accounts belonging to the
        # group.
        allowed = f'O:SYD:(A;;CR;;;{group_sid})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that the groups in the armor ticket are expanded to include the
        # domain-local group.
        self._get_tgt(client_creds, armor_tgt=mach_tgt)

    def test_authn_policy_allowed_from_user_allow_asserted_identity(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create an authentication policy that allows accounts with the
        # Authentication Authority Asserted Identity SID.
        allowed = (
            f'O:SYD:(A;;CR;;;'
            f'{security.SID_AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY})'
        )
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that authentication is allowed.
        self._get_tgt(client_creds, armor_tgt=mach_tgt)

    def test_authn_policy_allowed_from_user_allow_claims_valid(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create an authentication policy that allows accounts with the
        # Claims Valid SID.
        allowed = f'O:SYD:(A;;CR;;;{security.SID_CLAIMS_VALID})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that authentication is allowed.
        self._get_tgt(client_creds, armor_tgt=mach_tgt)

    def test_authn_policy_allowed_from_user_allow_compounded_auth(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create an authentication policy that allows accounts with the
        # Compounded Authentication SID.
        allowed = f'O:SYD:(A;;CR;;;{security.SID_COMPOUNDED_AUTHENTICATION})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that authentication is denied.
        self._get_tgt(client_creds, armor_tgt=mach_tgt,
                      expected_error=KDC_ERR_POLICY)

    def test_authn_policy_allowed_from_user_allow_authenticated_users(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create an authentication policy that allows accounts with the
        # Authenticated Users SID.
        allowed = f'O:SYD:(A;;CR;;;{security.SID_NT_AUTHENTICATED_USERS})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that authentication is allowed.
        self._get_tgt(client_creds, armor_tgt=mach_tgt)

    def test_authn_policy_allowed_from_user_allow_ntlm_authn(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create an authentication policy that allows accounts with the NTLM
        # Authentication SID.
        allowed = f'O:SYD:(A;;CR;;;{security.SID_NT_NTLM_AUTHENTICATION})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that authentication is denied.
        self._get_tgt(client_creds, armor_tgt=mach_tgt,
                      expected_error=KDC_ERR_POLICY)

    def test_authn_policy_allowed_from_user_allow_from_rodc(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                     allowed_rodc=True)
        # Modify the TGT to be issued by an RODC.
        mach_tgt = self.issued_by_rodc(self.get_tgt(mach_creds))

        # Create an authentication policy that explicitly allows the machine
        # account for a user.
        allowed = f'O:SYD:(A;;CR;;;{mach_creds.get_sid()})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_from=allowed,
                                          service_allowed_from=denied)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that we can authenticate using an armor ticket.
        self._get_tgt(client_creds, armor_tgt=mach_tgt)

    def test_authn_policy_allowed_from_user_deny_from_rodc(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                     allowed_rodc=True)
        # Modify the TGT to be issued by an RODC.
        mach_tgt = self.issued_by_rodc(self.get_tgt(mach_creds))

        # Create an authentication policy that explicitly denies the machine
        # account for a user.
        allowed = 'O:SYD:(A;;CR;;;WD)'
        denied = f'O:SYD:(D;;CR;;;{mach_creds.get_sid()})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_from=denied,
                                          service_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that we get a policy error when trying to authenticate.
        self._get_tgt(client_creds, armor_tgt=mach_tgt,
                      expected_error=KDC_ERR_POLICY)

    def test_authn_policy_allowed_from_service_allow_from_rodc(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                     allowed_rodc=True)
        # Modify the TGT to be issued by an RODC.
        mach_tgt = self.issued_by_rodc(self.get_tgt(mach_creds))

        # Create an authentication policy that explicitly allows the machine
        # account for a service.
        allowed = f'O:SYD:(A;;CR;;;{mach_creds.get_sid()})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_from=denied,
                                          service_allowed_from=allowed)

        # Create a managed service account with the assigned policy.
        client_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
            assigned_policy=policy)

        # Show that we can authenticate using an armor ticket.
        self._get_tgt(client_creds, armor_tgt=mach_tgt)

    def test_authn_policy_allowed_from_service_deny_from_rodc(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                     allowed_rodc=True)
        # Modify the TGT to be issued by an RODC.
        mach_tgt = self.issued_by_rodc(self.get_tgt(mach_creds))

        # Create an authentication policy that explicitly denies the machine
        # account for a service.
        allowed = 'O:SYD:(A;;CR;;;WD)'
        denied = f'O:SYD:(D;;CR;;;{mach_creds.get_sid()})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_from=allowed,
                                          service_allowed_from=denied)

        # Create a managed service account with the assigned policy.
        client_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
            assigned_policy=policy)

        # Show that we get a policy error when trying to authenticate.
        self._get_tgt(client_creds, armor_tgt=mach_tgt,
                      expected_error=KDC_ERR_POLICY)

    def test_authn_policy_allowed_from_user_allow_group_not_a_member_from_rodc(self):
        samdb = self.get_samdb()

        # Create a new group.
        group_name = self.get_new_username()
        group_dn = self.create_group(samdb, group_name)
        group_sid = self.get_objectSid(samdb, group_dn)

        # Create a machine account with which to perform FAST and which does
        # not belong to the group.
        mach_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                     allowed_rodc=True)
        # Modify the TGT to be issued by an RODC.
        mach_tgt = self.issued_by_rodc(self.get_tgt(mach_creds))

        # Create an authentication policy that allows accounts belonging to the
        # group.
        allowed = f'O:SYD:(A;;CR;;;{group_sid})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that we get a policy error, as the machine account does not
        # belong to the group.
        self._get_tgt(client_creds, armor_tgt=mach_tgt,
                      expected_error=KDC_ERR_POLICY)

    def test_authn_policy_allowed_from_user_allow_group_member_from_rodc(self):
        samdb = self.get_samdb()

        # Create a new group.
        group_name = self.get_new_username()
        group_dn = self.create_group(samdb, group_name)
        group_sid = self.get_objectSid(samdb, group_dn)

        # Create a machine account with which to perform FAST that belongs to
        # the group.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'member_of': (group_dn,),
                  'allowed_replication_mock': True,
                  'revealed_to_mock_rodc': True})
        # Modify the TGT to be issued by an RODC.
        mach_tgt = self.issued_by_rodc(self.get_tgt(mach_creds))

        # Create an authentication policy that allows accounts belonging to the
        # group.
        allowed = f'O:SYD:(A;;CR;;;{group_sid})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that we can authenticate using an armor ticket, since the
        # machine account belongs to the group.
        self._get_tgt(client_creds, armor_tgt=mach_tgt)

    def test_authn_policy_allowed_from_user_allow_domain_local_group_from_rodc(self):
        samdb = self.get_samdb()

        # Create a new domain-local group.
        group_name = self.get_new_username()
        group_dn = self.create_group(samdb, group_name,
                                     gtype=GroupType.DOMAIN_LOCAL.value)
        group_sid = self.get_objectSid(samdb, group_dn)

        # Create a machine account with which to perform FAST that belongs to
        # the group.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'member_of': (group_dn,),
                  'allowed_replication_mock': True,
                  'revealed_to_mock_rodc': True})
        # Modify the TGT to be issued by an RODC.
        mach_tgt = self.issued_by_rodc(self.get_tgt(mach_creds))

        # Create an authentication policy that allows accounts belonging to the
        # group.
        allowed = f'O:SYD:(A;;CR;;;{group_sid})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that the groups in the armor ticket are expanded to include the
        # domain-local group.
        self._get_tgt(client_creds, armor_tgt=mach_tgt)

    def test_authn_policy_allowed_from_user_allow_asserted_identity_from_rodc(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                     allowed_rodc=True)
        # Modify the TGT to be issued by an RODC.
        mach_tgt = self.issued_by_rodc(self.get_tgt(mach_creds))

        # Create an authentication policy that allows accounts with the
        # Authentication Authority Asserted Identity SID.
        allowed = (
            f'O:SYD:(A;;CR;;;'
            f'{security.SID_AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY})'
        )
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that authentication is allowed.
        self._get_tgt(client_creds, armor_tgt=mach_tgt)

    def test_authn_policy_allowed_from_user_allow_claims_valid_from_rodc(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                     allowed_rodc=True)
        # Modify the TGT to be issued by an RODC.
        mach_tgt = self.issued_by_rodc(self.get_tgt(mach_creds))

        # Create an authentication policy that allows accounts with the
        # Claims Valid SID.
        allowed = f'O:SYD:(A;;CR;;;{security.SID_CLAIMS_VALID})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that authentication is allowed.
        self._get_tgt(client_creds, armor_tgt=mach_tgt)

    def test_authn_policy_allowed_from_user_allow_compounded_authn_from_rodc(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                     allowed_rodc=True)
        # Modify the TGT to be issued by an RODC.
        mach_tgt = self.issued_by_rodc(self.get_tgt(mach_creds))

        # Create an authentication policy that allows accounts with the
        # Compounded Authentication SID.
        allowed = f'O:SYD:(A;;CR;;;{security.SID_COMPOUNDED_AUTHENTICATION})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that authentication is denied.
        self._get_tgt(client_creds, armor_tgt=mach_tgt,
                      expected_error=KDC_ERR_POLICY)

    def test_authn_policy_allowed_from_user_allow_authenticated_users_from_rodc(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                     allowed_rodc=True)
        # Modify the TGT to be issued by an RODC.
        mach_tgt = self.issued_by_rodc(self.get_tgt(mach_creds))

        # Create an authentication policy that allows accounts with the
        # Authenticated Users SID.
        allowed = f'O:SYD:(A;;CR;;;{security.SID_NT_AUTHENTICATED_USERS})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that authentication is allowed.
        self._get_tgt(client_creds, armor_tgt=mach_tgt)

    def test_authn_policy_allowed_from_user_allow_ntlm_authn_from_rodc(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                     allowed_rodc=True)
        # Modify the TGT to be issued by an RODC.
        mach_tgt = self.issued_by_rodc(self.get_tgt(mach_creds))

        # Create an authentication policy that allows accounts with the NTLM
        # Authentication SID.
        allowed = f'O:SYD:(A;;CR;;;{security.SID_NT_NTLM_AUTHENTICATION})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that authentication is denied.
        self._get_tgt(client_creds, armor_tgt=mach_tgt,
                      expected_error=KDC_ERR_POLICY)

    def test_authn_policy_allowed_from_user_deny_user(self):
        samdb = self.get_samdb()

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)
        mach_sid = mach_creds.get_sid()

        # Create a user account.
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER,
            use_cache=False)
        client_dn = client_creds.get_dn()
        client_sid = client_creds.get_sid()

        # Create an authentication policy that explicitly allows the machine
        # account for a user, while denying the user account itself.
        allowed = f'O:SYD:(A;;CR;;;{mach_sid})(D;;CR;;;{client_sid})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_from=allowed,
                                          service_allowed_from=denied)

        # Assign the policy to the user account.
        self.add_attribute(samdb, str(client_dn),
                           'msDS-AssignedAuthNPolicy', str(policy))

        # Show that authentication is allowed.
        self._get_tgt(client_creds, armor_tgt=mach_tgt)

    def test_authn_policy_allowed_to_empty(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a user account.
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        tgt = self.get_tgt(client_creds)

        # Create an authentication policy with no DACL in the security
        # descriptor.
        allowed_to = 'O:SY'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          computer_allowed_to=allowed_to)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that authentication is allowed.
        self._tgs_req(tgt, 0, client_creds, target_creds,
                      armor_tgt=mach_tgt)

    def test_authn_policy_allowed_to_computer_allow(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a user account.
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        tgt = self.get_tgt(client_creds)

        # Create an authentication policy that applies to a computer and
        # explicitly allows the user account to obtain a service ticket.
        allowed = f'O:SYD:(A;;CR;;;{client_creds.get_sid()})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=allowed,
                                          service_allowed_to=denied)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that obtaining a service ticket is allowed.
        self._tgs_req(tgt, 0, client_creds, target_creds,
                      armor_tgt=mach_tgt)

    def test_authn_policy_allowed_to_computer_deny(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a user account.
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        tgt = self.get_tgt(client_creds)

        # Create an authentication policy that applies to a computer and
        # explicitly denies the user account to obtain a service ticket.
        denied = f'O:SYD:(D;;CR;;;{client_creds.get_sid()})'
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=allowed,
                                          computer_allowed_to=denied,
                                          service_allowed_to=allowed)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that obtaining a service ticket is denied.
        self._tgs_req(
            tgt, KDC_ERR_POLICY, client_creds, target_creds,
            armor_tgt=mach_tgt,
            expect_edata=self.expect_padata_outer,
            # We aren’t particular about whether or not we get an NTSTATUS.
            expect_status=None,
            expected_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            check_patypes=False)

    def test_authn_policy_allowed_to_computer_allow_but_deny_mach(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)
        mach_sid = mach_creds.get_sid()

        # Create a user account.
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        client_sid = client_creds.get_sid()
        tgt = self.get_tgt(client_creds)

        # Create an authentication policy that applies to a computer and
        # explicitly allows the user account to obtain a service ticket, while
        # explicitly denying the machine account.
        allowed = f'O:SYD:(A;;CR;;;{client_sid})(D;;CR;;;{mach_sid})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=allowed,
                                          service_allowed_to=denied)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Despite the documentation’s claims that the machine account is also
        # access-checked, obtaining a service ticket is allowed.
        self._tgs_req(tgt, 0, client_creds, target_creds,
                      armor_tgt=mach_tgt)

    def test_authn_policy_allowed_to_computer_allow_mach(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a user account.
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        tgt = self.get_tgt(client_creds)

        # Create an authentication policy that applies to a computer and
        # explicitly allows the machine account to obtain a service ticket.
        allowed = f'O:SYD:(A;;CR;;;{mach_creds.get_sid()})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=allowed,
                                          service_allowed_to=denied)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that obtaining a service ticket is denied.
        self._tgs_req(
            tgt, KDC_ERR_POLICY, client_creds, target_creds,
            armor_tgt=mach_tgt,
            expect_edata=self.expect_padata_outer,
            # We aren’t particular about whether or not we get an NTSTATUS.
            expect_status=None,
            expected_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            check_patypes=False)

    def test_authn_policy_allowed_no_fast(self):
        # Create a user account.
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        tgt = self.get_tgt(client_creds)

        # Create an authentication policy that applies to a computer and
        # explicitly allows the user account to obtain a service ticket.
        allowed = f'O:SYD:(A;;CR;;;{client_creds.get_sid()})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=allowed,
                                          service_allowed_to=denied)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that obtaining a service ticket is allowed without an armor TGT.
        self._tgs_req(tgt, 0, client_creds, target_creds)

    def test_authn_policy_denied_no_fast(self):
        # Create a user account.
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        tgt = self.get_tgt(client_creds)

        # Create an authentication policy that applies to a computer and
        # explicitly disallows the user account to obtain a service ticket.
        denied = f'O:SYD:(D;;CR;;;{client_creds.get_sid()})'
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=allowed,
                                          computer_allowed_to=denied,
                                          service_allowed_to=allowed)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that obtaining a service ticket is not allowed.
        self._tgs_req(
            tgt, KDC_ERR_POLICY, client_creds, target_creds,
            expect_edata=self.expect_padata_outer,
            expect_status=True,
            expected_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

    def test_authn_policy_allowed_to_computer_allow_asserted_identity(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a user account.
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        tgt = self.get_tgt(client_creds)

        # Create an authentication policy that allows accounts with the
        # Authentication Authority Asserted Identity SID to obtain a service
        # ticket.
        allowed = (
            f'O:SYD:(A;;CR;;;'
            f'{security.SID_AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY})'
        )
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=allowed,
                                          service_allowed_to=denied)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that obtaining a service ticket is allowed.
        self._tgs_req(tgt, 0, client_creds, target_creds,
                      armor_tgt=mach_tgt)

    def test_authn_policy_allowed_to_computer_allow_claims_valid(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a user account.
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        tgt = self.get_tgt(client_creds)

        # Create an authentication policy that allows accounts with the Claims
        # Valid SID to obtain a service ticket.
        allowed = f'O:SYD:(A;;CR;;;{security.SID_CLAIMS_VALID})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=allowed,
                                          service_allowed_to=denied)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that obtaining a service ticket is allowed.
        self._tgs_req(tgt, 0, client_creds, target_creds,
                      armor_tgt=mach_tgt)

    def test_authn_policy_allowed_to_computer_allow_compounded_auth(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a user account.
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        tgt = self.get_tgt(client_creds)

        # Create an authentication policy that allows accounts with the
        # Compounded Authentication SID to obtain a service ticket.
        allowed = f'O:SYD:(A;;CR;;;{security.SID_COMPOUNDED_AUTHENTICATION})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=allowed,
                                          service_allowed_to=denied)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that obtaining a service ticket is denied.
        self._tgs_req(
            tgt, KDC_ERR_POLICY, client_creds, target_creds,
            armor_tgt=mach_tgt,
            expect_edata=self.expect_padata_outer,
            # We aren’t particular about whether or not we get an NTSTATUS.
            expect_status=None,
            expected_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            check_patypes=False)

    def test_authn_policy_allowed_to_computer_allow_authenticated_users(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a user account.
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        tgt = self.get_tgt(client_creds)

        # Create an authentication policy that allows accounts with the
        # Authenticated Users SID to obtain a service ticket.
        allowed = f'O:SYD:(A;;CR;;;{security.SID_NT_AUTHENTICATED_USERS})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=allowed,
                                          service_allowed_to=denied)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that obtaining a service ticket is allowed.
        self._tgs_req(tgt, 0, client_creds, target_creds,
                      armor_tgt=mach_tgt)

    def test_authn_policy_allowed_to_computer_allow_ntlm_authn(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a user account.
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        tgt = self.get_tgt(client_creds)

        # Create an authentication policy that allows accounts with the NTLM
        # Authentication SID to obtain a service ticket.
        allowed = f'O:SYD:(A;;CR;;;{security.SID_NT_NTLM_AUTHENTICATION})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=allowed,
                                          service_allowed_to=denied)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that obtaining a service ticket is denied.
        self._tgs_req(
            tgt, KDC_ERR_POLICY, client_creds, target_creds,
            armor_tgt=mach_tgt,
            expect_edata=self.expect_padata_outer,
            # We aren’t particular about whether or not we get an NTSTATUS.
            expect_status=None,
            expected_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            check_patypes=False)

    def test_authn_policy_allowed_to_no_owner(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a user account.
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        tgt = self.get_tgt(client_creds)

        # Create an authentication policy that applies to a computer and
        # explicitly allows the user account to obtain a service ticket. Omit
        # the owner (O:SY) from the SDDL.
        allowed = f'D:(A;;CR;;;{client_creds.get_sid()})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          computer_allowed_to=allowed)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that obtaining a service ticket is denied.
        self._tgs_req(tgt, KDC_ERR_POLICY, client_creds, target_creds,
                      armor_tgt=mach_tgt,
                      expect_edata=self.expect_padata_outer,
                      # We aren’t particular about whether or not we get an
                      # NTSTATUS.
                      expect_status=None,
                      expected_status=ntstatus.NT_STATUS_INVALID_PARAMETER,
                      check_patypes=False)

    def test_authn_policy_allowed_to_no_owner_unenforced(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a user account.
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        tgt = self.get_tgt(client_creds)

        # Create an unenforced authentication policy that applies to a computer
        # and explicitly allows the user account to obtain a service
        # ticket. Omit the owner (O:SY) from the SDDL.
        allowed = f'D:(A;;CR;;;{client_creds.get_sid()})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=False,
                                          computer_allowed_to=allowed)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that obtaining a service ticket is allowed.
        self._tgs_req(tgt, 0, client_creds, target_creds,
                      armor_tgt=mach_tgt)

    def test_authn_policy_allowed_to_owner_self(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a user account.
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        client_sid = client_creds.get_sid()
        tgt = self.get_tgt(client_creds)

        # Create an authentication policy that applies to a computer and
        # explicitly allows the user account to obtain a service ticket. Set
        # the owner to the user account.
        allowed = f'O:{client_sid}D:(A;;CR;;;{client_sid})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          computer_allowed_to=allowed)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that obtaining a service ticket is allowed.
        self._tgs_req(tgt, 0, client_creds, target_creds,
                      armor_tgt=mach_tgt)

    def test_authn_policy_allowed_to_owner_anon(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a user account.
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        tgt = self.get_tgt(client_creds)

        # Create an authentication policy that applies to a computer and
        # explicitly allows the user account to obtain a service ticket. Set
        # the owner to be anonymous.
        allowed = f'O:AND:(A;;CR;;;{client_creds.get_sid()})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          computer_allowed_to=allowed)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that obtaining a service ticket is allowed.
        self._tgs_req(tgt, 0, client_creds, target_creds,
                      armor_tgt=mach_tgt)

    def test_authn_policy_allowed_to_user_allow(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a user account.
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        tgt = self.get_tgt(client_creds)

        # Create an authentication policy that applies to a user and explicitly
        # allows the user account to obtain a service ticket.
        allowed = f'O:SYD:(A;;CR;;;{client_creds.get_sid()})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=allowed,
                                          computer_allowed_to=denied,
                                          service_allowed_to=denied)

        # Create a user account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy,
                                       spn='host/{account}')

        # Show that obtaining a service ticket is allowed.
        self._tgs_req(tgt, 0, client_creds, target_creds,
                      armor_tgt=mach_tgt)

    def test_authn_policy_allowed_to_user_deny(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a user account.
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        tgt = self.get_tgt(client_creds)

        # Create an authentication policy that applies to a user and
        # explicitly denies the user account to obtain a service ticket.
        denied = f'O:SYD:(D;;CR;;;{client_creds.get_sid()})'
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=allowed,
                                          service_allowed_to=allowed)

        # Create a user account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy,
                                       spn='host/{account}')

        # Show that obtaining a service ticket is denied.
        self._tgs_req(
            tgt, KDC_ERR_POLICY, client_creds, target_creds,
            armor_tgt=mach_tgt,
            expect_edata=self.expect_padata_outer,
            # We aren’t particular about whether or not we get an NTSTATUS.
            expect_status=None,
            expected_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            check_patypes=False)

    def test_authn_policy_allowed_to_service_allow(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a user account.
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        tgt = self.get_tgt(client_creds)

        # Create an authentication policy that applies to a managed service and
        # explicitly allows the user account to obtain a service ticket.
        allowed = f'O:SYD:(A;;CR;;;{client_creds.get_sid()})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=denied,
                                          service_allowed_to=allowed)

        # Create a managed service account with the assigned policy.
        target_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
            assigned_policy=policy)

        # Show that obtaining a service ticket is allowed.
        self._tgs_req(tgt, 0, client_creds, target_creds,
                      armor_tgt=mach_tgt)

    def test_authn_policy_allowed_to_service_deny(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a user account.
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        tgt = self.get_tgt(client_creds)

        # Create an authentication policy that applies to a managed service and
        # explicitly denies the user account to obtain a service ticket.
        denied = f'O:SYD:(D;;CR;;;{client_creds.get_sid()})'
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=allowed,
                                          computer_allowed_to=allowed,
                                          service_allowed_to=denied)

        # Create a managed service account with the assigned policy.
        target_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
            assigned_policy=policy)

        # Show that obtaining a service ticket is denied.
        self._tgs_req(
            tgt, KDC_ERR_POLICY, client_creds, target_creds,
            armor_tgt=mach_tgt,
            expect_edata=self.expect_padata_outer,
            # We aren’t particular about whether or not we get an NTSTATUS.
            expect_status=None,
            expected_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            check_patypes=False)

    def test_authn_policy_allowed_to_user_allow_from_rodc(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       allowed_rodc=True)
        # Modify the TGT to be issued by an RODC.
        tgt = self.issued_by_rodc(self.get_tgt(client_creds))

        # Create an authentication policy that applies to a user and explicitly
        # allows the user account to obtain a service ticket.
        allowed = f'O:SYD:(A;;CR;;;{client_creds.get_sid()})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=allowed,
                                          computer_allowed_to=denied,
                                          service_allowed_to=denied)

        # Create a user account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy,
                                       spn='host/{account}')

        # Show that obtaining a service ticket is allowed.
        self._tgs_req(tgt, 0, client_creds, target_creds,
                      armor_tgt=mach_tgt)

    def test_authn_policy_allowed_to_user_deny_from_rodc(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       allowed_rodc=True)
        # Modify the TGT to be issued by an RODC.
        tgt = self.issued_by_rodc(self.get_tgt(client_creds))

        # Create an authentication policy that applies to a user and
        # explicitly denies the user account to obtain a service ticket.
        denied = f'O:SYD:(D;;CR;;;{client_creds.get_sid()})'
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=allowed,
                                          service_allowed_to=allowed)

        # Create a user account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy,
                                       spn='host/{account}')

        # Show that obtaining a service ticket is denied.
        self._tgs_req(
            tgt, KDC_ERR_POLICY, client_creds, target_creds,
            armor_tgt=mach_tgt,
            expect_edata=self.expect_padata_outer,
            # We aren’t particular about whether or not we get an NTSTATUS.
            expect_status=None,
            expected_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

    def test_authn_policy_allowed_to_computer_allow_from_rodc(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       allowed_rodc=True)
        # Modify the TGT to be issued by an RODC.
        tgt = self.issued_by_rodc(self.get_tgt(client_creds))

        # Create an authentication policy that applies to a computer and
        # explicitly allows the user account to obtain a service ticket.
        allowed = f'O:SYD:(A;;CR;;;{client_creds.get_sid()})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=allowed,
                                          service_allowed_to=denied)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that obtaining a service ticket is allowed.
        self._tgs_req(tgt, 0, client_creds, target_creds,
                      armor_tgt=mach_tgt)

    def test_authn_policy_allowed_to_computer_deny_from_rodc(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       allowed_rodc=True)
        # Modify the TGT to be issued by an RODC.
        tgt = self.issued_by_rodc(self.get_tgt(client_creds))

        # Create an authentication policy that applies to a computer and
        # explicitly denies the user account to obtain a service ticket.
        denied = f'O:SYD:(D;;CR;;;{client_creds.get_sid()})'
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=allowed,
                                          computer_allowed_to=denied,
                                          service_allowed_to=allowed)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that obtaining a service ticket is denied.
        self._tgs_req(
            tgt, KDC_ERR_POLICY, client_creds, target_creds,
            armor_tgt=mach_tgt,
            expect_edata=self.expect_padata_outer,
            # We aren’t particular about whether or not we get an NTSTATUS.
            expect_status=None,
            expected_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,)

    def test_authn_policy_allowed_to_service_allow_from_rodc(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       allowed_rodc=True)
        # Modify the TGT to be issued by an RODC.
        tgt = self.issued_by_rodc(self.get_tgt(client_creds))

        # Create an authentication policy that applies to a managed service and
        # explicitly allows the user account to obtain a service ticket.
        allowed = f'O:SYD:(A;;CR;;;{client_creds.get_sid()})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=denied,
                                          service_allowed_to=allowed)

        # Create a managed service account with the assigned policy.
        target_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
            assigned_policy=policy)

        # Show that obtaining a service ticket is allowed.
        self._tgs_req(tgt, 0, client_creds, target_creds,
                      armor_tgt=mach_tgt)

    def test_authn_policy_allowed_to_service_deny_from_rodc(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       allowed_rodc=True)
        # Modify the TGT to be issued by an RODC.
        tgt = self.issued_by_rodc(self.get_tgt(client_creds))

        # Create an authentication policy that applies to a managed service and
        # explicitly denies the user account to obtain a service ticket.
        denied = f'O:SYD:(D;;CR;;;{client_creds.get_sid()})'
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=allowed,
                                          computer_allowed_to=allowed,
                                          service_allowed_to=denied)

        # Create a managed service account with the assigned policy.
        target_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
            assigned_policy=policy)

        # Show that obtaining a service ticket is denied.
        self._tgs_req(
            tgt, KDC_ERR_POLICY, client_creds, target_creds,
            armor_tgt=mach_tgt,
            expect_edata=self.expect_padata_outer,
            # We aren’t particular about whether or not we get an NTSTATUS.
            expect_status=None,
            expected_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

    def test_authn_policy_allowed_to_user_allow_group_not_a_member(self):
        samdb = self.get_samdb()

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a new group.
        group_name = self.get_new_username()
        group_dn = self.create_group(samdb, group_name)
        group_sid = self.get_objectSid(samdb, group_dn)

        # Create a user account which does not belong to the group.
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        tgt = self.get_tgt(client_creds)

        # Create an authentication policy that allows accounts belonging to the
        # group.
        allowed = f'O:SYD:(A;;CR;;;{group_sid})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=allowed)

        # Create a user account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy,
                                       spn='host/{account}')

        # Show that we get a policy error, as the user account does not belong
        # to the group.
        self._tgs_req(
            tgt, KDC_ERR_POLICY, client_creds, target_creds,
            armor_tgt=mach_tgt,
            expect_edata=self.expect_padata_outer,
            # We aren’t particular about whether or not we get an NTSTATUS.
            expect_status=None,
            expected_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            check_patypes=False)

    def test_authn_policy_allowed_to_user_allow_group_member(self):
        samdb = self.get_samdb()

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a new group.
        group_name = self.get_new_username()
        group_dn = self.create_group(samdb, group_name)
        group_sid = self.get_objectSid(samdb, group_dn)

        # Create a user account that belongs to the group.
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER,
            opts={'member_of': (group_dn,)})
        tgt = self.get_tgt(client_creds)

        # Create an authentication policy that allows accounts belonging to the
        # group.
        allowed = f'O:SYD:(A;;CR;;;{group_sid})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=allowed)

        # Create a user account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy,
                                       spn='host/{account}')

        # Show that we can get a service ticket, since the user account belongs
        # to the group.
        self._tgs_req(tgt, 0, client_creds, target_creds,
                      armor_tgt=mach_tgt)

    def test_authn_policy_allowed_to_user_allow_domain_local_group(self):
        samdb = self.get_samdb()

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a new domain-local group.
        group_name = self.get_new_username()
        group_dn = self.create_group(samdb, group_name,
                                     gtype=GroupType.DOMAIN_LOCAL.value)
        group_sid = self.get_objectSid(samdb, group_dn)

        # Create a user account that belongs to the group.
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER,
            opts={'member_of': (group_dn,)})
        tgt = self.get_tgt(client_creds)

        # Create an authentication policy that allows accounts belonging to the
        # group.
        allowed = f'O:SYD:(A;;CR;;;{group_sid})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=allowed)

        # Create a user account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy,
                                       spn='host/{account}')

        # Show that the groups in the TGT are expanded to include the
        # domain-local group.
        self._tgs_req(tgt, 0, client_creds, target_creds,
                      armor_tgt=mach_tgt)

    def test_authn_policy_allowed_to_computer_allow_asserted_identity_from_rodc(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       allowed_rodc=True)
        # Modify the TGT to be issued by an RODC.
        tgt = self.issued_by_rodc(self.get_tgt(client_creds))

        # Create an authentication policy that allows accounts with the
        # Authentication Authority Asserted Identity SID to obtain a service
        # ticket.
        allowed = (
            f'O:SYD:(A;;CR;;;'
            f'{security.SID_AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY})'
        )
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=allowed,
                                          service_allowed_to=denied)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that obtaining a service ticket is allowed.
        self._tgs_req(tgt, 0, client_creds, target_creds,
                      armor_tgt=mach_tgt)

    def test_authn_policy_allowed_to_computer_allow_claims_valid_from_rodc(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       allowed_rodc=True)
        # Modify the TGT to be issued by an RODC.
        tgt = self.issued_by_rodc(self.get_tgt(client_creds))

        # Create an authentication policy that allows accounts with the Claims
        # Valid SID to obtain a service ticket.
        allowed = f'O:SYD:(A;;CR;;;{security.SID_CLAIMS_VALID})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=allowed,
                                          service_allowed_to=denied)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that obtaining a service ticket is not allowed.
        self._tgs_req(tgt, KDC_ERR_POLICY, client_creds, target_creds,
                      armor_tgt=mach_tgt)

    def test_authn_policy_allowed_to_computer_allow_compounded_authn_from_rodc(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       allowed_rodc=True)
        # Modify the TGT to be issued by an RODC.
        tgt = self.issued_by_rodc(self.get_tgt(client_creds))

        # Create an authentication policy that allows accounts with the
        # Compounded Authentication SID to obtain a service ticket.
        allowed = f'O:SYD:(A;;CR;;;{security.SID_COMPOUNDED_AUTHENTICATION})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=allowed,
                                          service_allowed_to=denied)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that obtaining a service ticket is denied.
        self._tgs_req(
            tgt, KDC_ERR_POLICY, client_creds, target_creds,
            armor_tgt=mach_tgt,
            expect_edata=self.expect_padata_outer,
            # We aren’t particular about whether or not we get an NTSTATUS.
            expect_status=None,
            expected_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

    def test_authn_policy_allowed_to_computer_allow_authenticated_users_from_rodc(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       allowed_rodc=True)
        # Modify the TGT to be issued by an RODC.
        tgt = self.issued_by_rodc(self.get_tgt(client_creds))

        # Create an authentication policy that allows accounts with the
        # Authenticated Users SID to obtain a service ticket.
        allowed = f'O:SYD:(A;;CR;;;{security.SID_NT_AUTHENTICATED_USERS})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=allowed,
                                          service_allowed_to=denied)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that obtaining a service ticket is allowed.
        self._tgs_req(tgt, 0, client_creds, target_creds,
                      armor_tgt=mach_tgt)

    def test_authn_policy_allowed_to_computer_allow_ntlm_authn_from_rodc(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       allowed_rodc=True)
        # Modify the TGT to be issued by an RODC.
        tgt = self.issued_by_rodc(self.get_tgt(client_creds))

        # Create an authentication policy that allows accounts with the NTLM
        # Authentication SID to obtain a service ticket.
        allowed = f'O:SYD:(A;;CR;;;{security.SID_NT_NTLM_AUTHENTICATION})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=allowed,
                                          service_allowed_to=denied)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that obtaining a service ticket is denied.
        self._tgs_req(
            tgt, KDC_ERR_POLICY, client_creds, target_creds,
            armor_tgt=mach_tgt,
            expect_edata=self.expect_padata_outer,
            # We aren’t particular about whether or not we get an NTSTATUS.
            expect_status=None,
            expected_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

    def test_authn_policy_allowed_to_user_allow_group_not_a_member_from_rodc(self):
        samdb = self.get_samdb()

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a new group.
        group_name = self.get_new_username()
        group_dn = self.create_group(samdb, group_name)
        group_sid = self.get_objectSid(samdb, group_dn)

        # Create a user account which does not belong to the group.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       allowed_rodc=True)
        # Modify the TGT to be issued by an RODC.
        tgt = self.issued_by_rodc(self.get_tgt(client_creds))

        # Create an authentication policy that allows accounts belonging to the
        # group.
        allowed = f'O:SYD:(A;;CR;;;{group_sid})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=allowed)

        # Create a user account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy,
                                       spn='host/{account}')

        # Show that we get a policy error, as the user account does not belong
        # to the group.
        self._tgs_req(
            tgt, KDC_ERR_POLICY, client_creds, target_creds,
            armor_tgt=mach_tgt,
            expect_edata=self.expect_padata_outer,
            # We aren’t particular about whether or not we get an NTSTATUS.
            expect_status=None,
            expected_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

    def test_authn_policy_allowed_to_user_allow_group_member_from_rodc(self):
        samdb = self.get_samdb()

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a new group.
        group_name = self.get_new_username()
        group_dn = self.create_group(samdb, group_name)
        group_sid = self.get_objectSid(samdb, group_dn)

        # Create a user account that belongs to the group.
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER,
            opts={'member_of': (group_dn,),
                  'allowed_replication_mock': True,
                  'revealed_to_mock_rodc': True})
        # Modify the TGT to be issued by an RODC.
        tgt = self.issued_by_rodc(self.get_tgt(client_creds))

        # Create an authentication policy that allows accounts belonging to the
        # group.
        allowed = f'O:SYD:(A;;CR;;;{group_sid})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=allowed)

        # Create a user account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy,
                                       spn='host/{account}')

        # Show that we can get a service ticket, since the user account belongs
        # to the group.
        self._tgs_req(tgt, 0, client_creds, target_creds,
                      armor_tgt=mach_tgt)

    def test_authn_policy_allowed_to_user_allow_domain_local_group_from_rodc(self):
        samdb = self.get_samdb()

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a new domain-local group.
        group_name = self.get_new_username()
        group_dn = self.create_group(samdb, group_name,
                                     gtype=GroupType.DOMAIN_LOCAL.value)
        group_sid = self.get_objectSid(samdb, group_dn)

        # Create a user account that belongs to the group.
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER,
            opts={'member_of': (group_dn,),
                  'allowed_replication_mock': True,
                  'revealed_to_mock_rodc': True})
        # Modify the TGT to be issued by an RODC.
        tgt = self.issued_by_rodc(self.get_tgt(client_creds))

        # Create an authentication policy that allows accounts belonging to the
        # group.
        allowed = f'O:SYD:(A;;CR;;;{group_sid})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=allowed)

        # Create a user account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy,
                                       spn='host/{account}')

        # Show that the groups in the TGT are expanded to include the
        # domain-local group.
        self._tgs_req(tgt, 0, client_creds, target_creds,
                      armor_tgt=mach_tgt)

    def test_authn_policy_allowed_to_computer_allow_to_self(self):
        samdb = self.get_samdb()

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a computer account.
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'id': 1},
            use_cache=False)
        client_dn = client_creds.get_dn()
        tgt = self.get_tgt(client_creds)

        # Create an authentication policy that applies to a computer and
        # explicitly allows the user account to obtain a service ticket.
        allowed = f'O:SYD:(A;;CR;;;{client_creds.get_sid()})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=allowed,
                                          service_allowed_to=denied)

        # Assign the policy to the account.
        self.add_attribute(samdb, str(client_dn),
                           'msDS-AssignedAuthNPolicy', str(policy))

        # Show that obtaining a service ticket to ourselves is allowed.
        self._tgs_req(tgt, 0, client_creds, client_creds,
                      armor_tgt=mach_tgt)

    def test_authn_policy_allowed_to_computer_deny_to_self(self):
        samdb = self.get_samdb()

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a computer account.
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'id': 1},
            use_cache=False)
        client_dn = client_creds.get_dn()
        tgt = self.get_tgt(client_creds)

        # Create an authentication policy that applies to a computer and
        # explicitly denies the user account to obtain a service ticket.
        denied = f'O:SYD:(D;;CR;;;{client_creds.get_sid()})'
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=allowed,
                                          computer_allowed_to=denied,
                                          service_allowed_to=allowed)

        # Assign the policy to the account.
        self.add_attribute(samdb, str(client_dn),
                           'msDS-AssignedAuthNPolicy', str(policy))

        # Show that obtaining a service ticket to ourselves is allowed, despite
        # the policy disallowing it.
        self._tgs_req(tgt, 0, client_creds, client_creds,
                      armor_tgt=mach_tgt)

    def test_authn_policy_allowed_to_computer_allow_to_self_with_self(self):
        samdb = self.get_samdb()

        # Create a computer account.
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            use_cache=False)
        client_dn = client_creds.get_dn()
        tgt = self.get_tgt(client_creds)

        # Create an authentication policy that applies to a computer and
        # explicitly allows the account to obtain a service ticket.
        allowed = f'O:SYD:(A;;CR;;;{client_creds.get_sid()})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=allowed,
                                          service_allowed_to=denied)

        # Assign the policy to the account.
        self.add_attribute(samdb, str(client_dn),
                           'msDS-AssignedAuthNPolicy', str(policy))

        # Show that obtaining a service ticket to ourselves armored with our
        # own TGT is allowed.
        self._tgs_req(tgt, 0, client_creds, client_creds,
                      armor_tgt=tgt)

    def test_authn_policy_allowed_to_computer_deny_to_self_with_self(self):
        samdb = self.get_samdb()

        # Create a computer account.
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            use_cache=False)
        client_dn = client_creds.get_dn()
        tgt = self.get_tgt(client_creds)

        # Create an authentication policy that applies to a computer and
        # explicitly denies the account to obtain a service ticket.
        denied = f'O:SYD:(D;;CR;;;{client_creds.get_sid()})'
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=allowed,
                                          computer_allowed_to=denied,
                                          service_allowed_to=allowed)

        # Assign the policy to the account.
        self.add_attribute(samdb, str(client_dn),
                           'msDS-AssignedAuthNPolicy', str(policy))

        # Show that obtaining a service ticket to ourselves armored with our
        # own TGT is allowed, despite the policy’s disallowing it.
        self._tgs_req(tgt, 0, client_creds, client_creds,
                      armor_tgt=tgt)

    def test_authn_policy_allowed_to_user_allow_s4u2self(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a user account.
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        client_cname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL,
            names=[client_creds.get_username()])
        client_realm = client_creds.get_realm()

        # Create an authentication policy that applies to a computer and
        # explicitly allows the user account to obtain a service ticket.
        allowed = f'O:SYD:(A;;CR;;;{client_creds.get_sid()})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          computer_allowed_to=allowed)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)
        target_tgt = self.get_tgt(target_creds)

        def generate_s4u2self_padata(_kdc_exchange_dict,
                                     _callback_dict,
                                     req_body):
            padata = self.PA_S4U2Self_create(
                name=client_cname,
                realm=client_realm,
                tgt_session_key=target_tgt.session_key,
                ctype=None)

            return [padata], req_body

        # Show that obtaining a service ticket with S4U2Self is allowed.
        self._tgs_req(target_tgt, 0, target_creds, target_creds,
                      expected_cname=client_cname,
                      generate_fast_padata_fn=generate_s4u2self_padata,
                      armor_tgt=mach_tgt)

    def test_authn_policy_allowed_to_user_deny_s4u2self(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a user account.
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        client_cname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL,
            names=[client_creds.get_username()])
        client_realm = client_creds.get_realm()

        # Create an authentication policy that applies to a computer and
        # explicitly denies the user account to obtain a service ticket.
        denied = f'O:SYD:(D;;CR;;;{client_creds.get_sid()})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          computer_allowed_to=denied)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)
        target_tgt = self.get_tgt(target_creds)

        def generate_s4u2self_padata(_kdc_exchange_dict,
                                     _callback_dict,
                                     req_body):
            padata = self.PA_S4U2Self_create(
                name=client_cname,
                realm=client_realm,
                tgt_session_key=target_tgt.session_key,
                ctype=None)

            return [padata], req_body

        # Show that obtaining a service ticket with S4U2Self is allowed,
        # despite the policy.
        self._tgs_req(target_tgt, 0, target_creds, target_creds,
                      expected_cname=client_cname,
                      generate_fast_padata_fn=generate_s4u2self_padata,
                      armor_tgt=mach_tgt)

    # Obtain a service ticket with S4U2Self and use it to perform constrained
    # delegation while a policy is in place.
    def test_authn_policy_allowed_to_user_deny_s4u2self_constrained_delegation(self):
        samdb = self.get_samdb()

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a user account.
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        client_username = client_creds.get_username()
        client_cname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL,
            names=[client_username])
        client_realm = client_creds.get_realm()
        client_sid = client_creds.get_sid()

        # Create a target account.
        target_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'id': 1},
            use_cache=False)
        target_spn = target_creds.get_spn()

        # Create an authentication policy that applies to a computer and
        # explicitly denies the user account to obtain a service ticket.
        denied = f'O:SYD:(D;;CR;;;{client_creds.get_sid()})'
        service_policy_id = self.get_new_username()
        service_policy = self.create_authn_policy(service_policy_id,
                                                  enforced=True,
                                                  computer_allowed_to=denied)

        # Create a computer account with the assigned policy.
        service_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={
                'assigned_policy': str(service_policy),
                # Allow delegation to the target service.
                'delegation_to_spn': target_spn,
                'trusted_to_auth_for_delegation': True,
            })
        service_sid = service_creds.get_sid()
        service_tgt = self.get_tgt(service_creds)

        # Create an authentication policy that applies to a computer and
        # explicitly allows the service account to obtain a service ticket,
        # while denying the user.
        allowed = f'O:SYD:(A;;CR;;;{service_sid})(D;;CR;;;{client_sid})'
        target_policy_id = self.get_new_username()
        target_policy = self.create_authn_policy(target_policy_id,
                                                 enforced=True,
                                                 computer_allowed_to=allowed)

        # Assign the policy to the target account.
        self.add_attribute(samdb, str(target_creds.get_dn()),
                           'msDS-AssignedAuthNPolicy', str(target_policy))

        def generate_s4u2self_padata(_kdc_exchange_dict,
                                     _callback_dict,
                                     req_body):
            padata = self.PA_S4U2Self_create(
                name=client_cname,
                realm=client_realm,
                tgt_session_key=service_tgt.session_key,
                ctype=None)

            return [padata], req_body

        # Make sure the ticket is forwardable, so it can be used with
        # constrained delegation.
        forwardable_flag = 'forwardable'
        client_tkt_options = str(krb5_asn1.KDCOptions(forwardable_flag))
        expected_flags = krb5_asn1.TicketFlags(forwardable_flag)

        # Show that obtaining a service ticket with S4U2Self is allowed,
        # despite the policy.
        client_service_tkt = self._tgs_req(
            service_tgt, 0, service_creds, service_creds,
            kdc_options=client_tkt_options,
            expected_flags=expected_flags,
            expected_cname=client_cname,
            generate_fast_padata_fn=generate_s4u2self_padata,
            armor_tgt=mach_tgt)

        # Now perform constrained delegation with this service ticket.

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

        # Show that obtaining a service ticket with constrained delegation is
        # allowed.
        self._tgs_req(service_tgt, 0, service_creds, target_creds,
                      armor_tgt=mach_tgt,
                      kdc_options=kdc_options,
                      expected_cname=client_cname,
                      expected_account_name=client_username,
                      additional_ticket=client_service_tkt,
                      decryption_key=target_decryption_key,
                      expected_sid=client_sid,
                      expected_supported_etypes=target_etypes,
                      expected_proxy_target=target_spn,
                      expected_transited_services=expected_transited_services)

    def test_authn_policy_allowed_to_user_allow_constrained_delegation(self):
        samdb = self.get_samdb()

        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        client_sid = client_creds.get_sid()

        client_username = client_creds.get_username()
        client_cname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                                 names=[client_username])

        client_tkt_options = 'forwardable'
        expected_flags = krb5_asn1.TicketFlags(client_tkt_options)

        client_tgt = self.get_tgt(client_creds,
                                  kdc_options=client_tkt_options,
                                  expected_flags=expected_flags)

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a target account.
        target_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'id': 1},
            use_cache=False)
        target_spn = target_creds.get_spn()

        service_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={
                'delegation_to_spn': target_spn,
            })
        service_sid = service_creds.get_sid()
        service_tgt = self.get_tgt(service_creds)

        # Create an authentication policy that applies to a computer and
        # explicitly allows the service account to obtain a service ticket,
        # while denying the user.
        allowed = f'O:SYD:(A;;CR;;;{service_sid})(D;;CR;;;{client_sid})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          computer_allowed_to=allowed)

        # Assign the policy to the target account.
        self.add_attribute(samdb, str(target_creds.get_dn()),
                           'msDS-AssignedAuthNPolicy', str(policy))

        client_service_tkt = self.get_service_ticket(
            client_tgt,
            service_creds,
            kdc_options=client_tkt_options,
            expected_flags=expected_flags)

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

        # Show that obtaining a service ticket with constrained delegation is
        # allowed.
        self._tgs_req(service_tgt, 0, service_creds, target_creds,
                      armor_tgt=mach_tgt,
                      kdc_options=kdc_options,
                      expected_cname=client_cname,
                      expected_account_name=client_username,
                      additional_ticket=client_service_tkt,
                      decryption_key=target_decryption_key,
                      expected_sid=client_sid,
                      expected_supported_etypes=target_etypes,
                      expected_proxy_target=target_spn,
                      expected_transited_services=expected_transited_services)

    def test_authn_policy_allowed_to_user_deny_constrained_delegation(self):
        samdb = self.get_samdb()

        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        client_sid = client_creds.get_sid()

        client_tkt_options = 'forwardable'
        expected_flags = krb5_asn1.TicketFlags(client_tkt_options)

        client_tgt = self.get_tgt(client_creds,
                                  kdc_options=client_tkt_options,
                                  expected_flags=expected_flags)

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a target account.
        target_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'id': 1},
            use_cache=False)
        target_spn = target_creds.get_spn()

        service_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={
                'delegation_to_spn': target_spn,
            })
        service_sid = service_creds.get_sid()
        service_tgt = self.get_tgt(service_creds)

        # Create an authentication policy that applies to a computer and
        # explicitly denies the service account to obtain a service ticket,
        # while allowing the user.
        denied = f'O:SYD:(D;;CR;;;{service_sid})(A;;CR;;;{client_sid})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          computer_allowed_to=denied)

        # Assign the policy to the target account.
        self.add_attribute(samdb, str(target_creds.get_dn()),
                           'msDS-AssignedAuthNPolicy', str(policy))

        client_service_tkt = self.get_service_ticket(
            client_tgt,
            service_creds,
            kdc_options=client_tkt_options,
            expected_flags=expected_flags)

        kdc_options = str(krb5_asn1.KDCOptions('cname-in-addl-tkt'))

        target_decryption_key = self.TicketDecryptionKey_from_creds(
            target_creds)

        # Show that obtaining a service ticket with constrained delegation is
        # not allowed.
        self._tgs_req(
            service_tgt, KDC_ERR_POLICY, service_creds, target_creds,
            armor_tgt=mach_tgt,
            kdc_options=kdc_options,
            additional_ticket=client_service_tkt,
            decryption_key=target_decryption_key,
            expect_edata=self.expect_padata_outer,
            # We aren’t particular about whether or not we get an NTSTATUS.
            expect_status=None,
            expected_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            check_patypes=False)

    def test_authn_policy_allowed_to_user_allow_constrained_delegation_wrong_sname(self):
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER,
            use_cache=False)

        client_tkt_options = 'forwardable'
        expected_flags = krb5_asn1.TicketFlags(client_tkt_options)

        client_tgt = self.get_tgt(client_creds,
                                  kdc_options=client_tkt_options,
                                  expected_flags=expected_flags)

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a target account.
        target_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'id': 1})
        target_spn = target_creds.get_spn()

        service_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'delegation_to_spn': target_spn})
        service_tgt = self.get_tgt(service_creds)

        client_service_tkt = self.get_service_ticket(
            client_tgt,
            service_creds,
            kdc_options=client_tkt_options,
            expected_flags=expected_flags,
            fresh=True)
        # Change the ‘sname’ of the ticket to an incorrect value.
        client_service_tkt.set_sname(self.get_krbtgt_sname())

        kdc_options = str(krb5_asn1.KDCOptions('cname-in-addl-tkt'))

        target_decryption_key = self.TicketDecryptionKey_from_creds(
            target_creds)

        # Show that obtaining a service ticket with constrained delegation
        # fails if the sname doesn’t match.
        self._tgs_req(service_tgt, KDC_ERR_BADOPTION,
                      service_creds, target_creds,
                      armor_tgt=mach_tgt,
                      kdc_options=kdc_options,
                      additional_ticket=client_service_tkt,
                      decryption_key=target_decryption_key,
                      expect_edata=self.expect_padata_outer,
                      check_patypes=False)

    def test_authn_policy_allowed_to_user_allow_rbcd(self):
        samdb = self.get_samdb()
        functional_level = self.get_domain_functional_level(samdb)

        if functional_level < dsdb.DS_DOMAIN_FUNCTION_2008:
            self.skipTest('RBCD requires FL2008')

        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        client_sid = client_creds.get_sid()

        client_username = client_creds.get_username()
        client_cname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                                 names=[client_username])

        client_tkt_options = 'forwardable'
        expected_flags = krb5_asn1.TicketFlags(client_tkt_options)

        client_tgt = self.get_tgt(client_creds,
                                  kdc_options=client_tkt_options,
                                  expected_flags=expected_flags)

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        service_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'id': 1})
        service_sid = service_creds.get_sid()
        service_tgt = self.get_tgt(service_creds)

        # Create an authentication policy that applies to a computer and
        # explicitly allows the service account to obtain a service ticket,
        # while denying the user.
        allowed = f'O:SYD:(A;;CR;;;{service_sid})(D;;CR;;;{client_sid})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          computer_allowed_to=allowed)

        # Create a target account with the assigned policy.
        target_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={
                'assigned_policy': str(policy),
                'delegation_from_dn': str(service_creds.get_dn()),
            })

        client_service_tkt = self.get_service_ticket(
            client_tgt,
            service_creds,
            kdc_options=client_tkt_options,
            expected_flags=expected_flags)

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

        # Show that obtaining a service ticket with RBCD is allowed.
        self._tgs_req(service_tgt, 0, service_creds, target_creds,
                      armor_tgt=mach_tgt,
                      kdc_options=kdc_options,
                      pac_options='1001',  # supports claims, RBCD
                      expected_cname=client_cname,
                      expected_account_name=client_username,
                      additional_ticket=client_service_tkt,
                      decryption_key=target_decryption_key,
                      expected_sid=client_sid,
                      expected_supported_etypes=target_etypes,
                      expected_proxy_target=target_creds.get_spn(),
                      expected_transited_services=expected_transited_services)

    def test_authn_policy_allowed_to_user_deny_rbcd(self):
        samdb = self.get_samdb()
        functional_level = self.get_domain_functional_level(samdb)

        if functional_level < dsdb.DS_DOMAIN_FUNCTION_2008:
            self.skipTest('RBCD requires FL2008')

        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        client_sid = client_creds.get_sid()

        client_tkt_options = 'forwardable'
        expected_flags = krb5_asn1.TicketFlags(client_tkt_options)

        client_tgt = self.get_tgt(client_creds,
                                  kdc_options=client_tkt_options,
                                  expected_flags=expected_flags)

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        service_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'id': 1})
        service_sid = service_creds.get_sid()
        service_tgt = self.get_tgt(service_creds)

        # Create an authentication policy that applies to a computer and
        # explicitly denies the service account to obtain a service ticket,
        # while allowing the user.
        denied = f'O:SYD:(D;;CR;;;{service_sid})(A;;CR;;;{client_sid})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          computer_allowed_to=denied)

        # Create a target account with the assigned policy.
        target_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={
                'assigned_policy': str(policy),
                'delegation_from_dn': str(service_creds.get_dn()),
            })

        client_service_tkt = self.get_service_ticket(
            client_tgt,
            service_creds,
            kdc_options=client_tkt_options,
            expected_flags=expected_flags)

        kdc_options = str(krb5_asn1.KDCOptions('cname-in-addl-tkt'))

        target_decryption_key = self.TicketDecryptionKey_from_creds(
            target_creds)

        # Show that obtaining a service ticket with RBCD is not allowed.
        self._tgs_req(service_tgt, KDC_ERR_POLICY, service_creds, target_creds,
                      armor_tgt=mach_tgt,
                      kdc_options=kdc_options,
                      pac_options='1001',  # supports claims, RBCD
                      additional_ticket=client_service_tkt,
                      decryption_key=target_decryption_key,
                      expect_edata=self.expect_padata_outer,
                      check_patypes=False)

    def test_authn_policy_allowed_to_user_allow_rbcd_wrong_sname(self):
        samdb = self.get_samdb()
        functional_level = self.get_domain_functional_level(samdb)

        if functional_level < dsdb.DS_DOMAIN_FUNCTION_2008:
            self.skipTest('RBCD requires FL2008')

        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER,
            use_cache=False)

        client_tkt_options = 'forwardable'
        expected_flags = krb5_asn1.TicketFlags(client_tkt_options)

        client_tgt = self.get_tgt(client_creds,
                                  kdc_options=client_tkt_options,
                                  expected_flags=expected_flags)

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        service_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'id': 1})
        service_tgt = self.get_tgt(service_creds)

        # Create a target account with the assigned policy.
        target_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={
                'delegation_from_dn': str(service_creds.get_dn()),
            })

        client_service_tkt = self.get_service_ticket(
            client_tgt,
            service_creds,
            kdc_options=client_tkt_options,
            expected_flags=expected_flags,
            fresh=True)
        # Change the ‘sname’ of the ticket to an incorrect value.
        client_service_tkt.set_sname(self.get_krbtgt_sname())

        kdc_options = str(krb5_asn1.KDCOptions('cname-in-addl-tkt'))

        target_decryption_key = self.TicketDecryptionKey_from_creds(
            target_creds)

        # Show that obtaining a service ticket with RBCD fails if the sname
        # doesn’t match.
        self._tgs_req(service_tgt, KDC_ERR_BADOPTION,
                      service_creds, target_creds,
                      armor_tgt=mach_tgt,
                      kdc_options=kdc_options,
                      pac_options='1001',  # supports claims, RBCD
                      additional_ticket=client_service_tkt,
                      decryption_key=target_decryption_key,
                      expect_edata=self.expect_padata_outer,
                      check_patypes=False)

    def test_authn_policy_allowed_to_user_allow_constrained_delegation_to_self(self):
        samdb = self.get_samdb()

        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        client_sid = client_creds.get_sid()

        client_username = client_creds.get_username()
        client_cname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                                 names=[client_username])

        client_tkt_options = 'forwardable'
        expected_flags = krb5_asn1.TicketFlags(client_tkt_options)

        client_tgt = self.get_tgt(client_creds,
                                  kdc_options=client_tkt_options,
                                  expected_flags=expected_flags)

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a service account.
        service_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'id': 1},
            use_cache=False)
        service_dn_str = str(service_creds.get_dn())
        service_spn = service_creds.get_spn()
        service_sid = service_creds.get_sid()
        service_tgt = self.get_tgt(service_creds)

        # Allow delegation to ourselves.
        self.add_attribute(samdb, service_dn_str,
                           'msDS-AllowedToDelegateTo', service_spn)

        # Create an authentication policy that applies to a computer and
        # explicitly allows the client account to obtain a service ticket,
        # while denying the service.
        allowed = f'O:SYD:(A;;CR;;;{client_sid})(D;;CR;;;{service_sid})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          computer_allowed_to=allowed)

        # Assign the policy to the service account.
        self.add_attribute(samdb, service_dn_str,
                           'msDS-AssignedAuthNPolicy', str(policy))

        client_service_tkt = self.get_service_ticket(
            client_tgt,
            service_creds,
            kdc_options=client_tkt_options,
            expected_flags=expected_flags)

        kdc_options = str(krb5_asn1.KDCOptions('cname-in-addl-tkt'))

        target_decryption_key = self.TicketDecryptionKey_from_creds(
            service_creds)
        target_etypes = service_creds.tgs_supported_enctypes

        service_name = service_creds.get_username()
        if service_name[-1] == '$':
            service_name = service_name[:-1]
        expected_transited_services = [
            f'host/{service_name}@{service_creds.get_realm()}'
        ]

        # Show that obtaining a service ticket to ourselves with constrained
        # delegation is allowed.
        self._tgs_req(service_tgt, 0, service_creds, service_creds,
                      armor_tgt=mach_tgt,
                      kdc_options=kdc_options,
                      expected_cname=client_cname,
                      expected_account_name=client_username,
                      additional_ticket=client_service_tkt,
                      decryption_key=target_decryption_key,
                      expected_sid=client_sid,
                      expected_supported_etypes=target_etypes,
                      expected_proxy_target=service_spn,
                      expected_transited_services=expected_transited_services)

    def test_authn_policy_allowed_to_user_deny_constrained_delegation_to_self(self):
        samdb = self.get_samdb()

        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        client_sid = client_creds.get_sid()

        client_username = client_creds.get_username()
        client_cname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                                 names=[client_username])

        client_tkt_options = 'forwardable'
        expected_flags = krb5_asn1.TicketFlags(client_tkt_options)

        client_tgt = self.get_tgt(client_creds,
                                  kdc_options=client_tkt_options,
                                  expected_flags=expected_flags)

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a service account.
        service_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'id': 1},
            use_cache=False)
        service_dn_str = str(service_creds.get_dn())
        service_spn = service_creds.get_spn()
        service_sid = service_creds.get_sid()
        service_tgt = self.get_tgt(service_creds)

        # Allow delegation to ourselves.
        self.add_attribute(samdb, service_dn_str,
                           'msDS-AllowedToDelegateTo', service_spn)

        client_service_tkt = self.get_service_ticket(
            client_tgt,
            service_creds,
            kdc_options=client_tkt_options,
            expected_flags=expected_flags)

        # Create an authentication policy that applies to a computer and
        # explicitly denies the client account to obtain a service ticket,
        # while allowing the service.
        allowed = f'O:SYD:(D;;CR;;;{client_sid})(A;;CR;;;{service_sid})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          computer_allowed_to=allowed)

        # Assign the policy to the service account.
        self.add_attribute(samdb, service_dn_str,
                           'msDS-AssignedAuthNPolicy', str(policy))

        kdc_options = str(krb5_asn1.KDCOptions('cname-in-addl-tkt'))

        target_decryption_key = self.TicketDecryptionKey_from_creds(
            service_creds)
        target_etypes = service_creds.tgs_supported_enctypes

        service_name = service_creds.get_username()
        if service_name[-1] == '$':
            service_name = service_name[:-1]
        expected_transited_services = [
            f'host/{service_name}@{service_creds.get_realm()}'
        ]

        # Show that obtaining a service ticket to ourselves with constrained
        # delegation is allowed, despite the policy’s disallowing it.
        self._tgs_req(service_tgt, 0, service_creds, service_creds,
                      armor_tgt=mach_tgt,
                      kdc_options=kdc_options,
                      expected_cname=client_cname,
                      expected_account_name=client_username,
                      additional_ticket=client_service_tkt,
                      decryption_key=target_decryption_key,
                      expected_sid=client_sid,
                      expected_supported_etypes=target_etypes,
                      expected_proxy_target=service_spn,
                      expected_transited_services=expected_transited_services)

    def test_authn_policy_allowed_to_user_not_allowed_constrained_delegation_to_self(self):
        samdb = self.get_samdb()

        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        client_sid = client_creds.get_sid()

        client_tkt_options = 'forwardable'
        expected_flags = krb5_asn1.TicketFlags(client_tkt_options)

        client_tgt = self.get_tgt(client_creds,
                                  kdc_options=client_tkt_options,
                                  expected_flags=expected_flags)

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a service account.
        service_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'id': 1},
            use_cache=False)
        service_dn_str = str(service_creds.get_dn())
        service_sid = service_creds.get_sid()
        service_tgt = self.get_tgt(service_creds)

        # Don’t set msDS-AllowedToDelegateTo.

        # Create an authentication policy that applies to a computer and
        # explicitly allows the client account to obtain a service ticket,
        # while denying the service.
        allowed = f'O:SYD:(A;;CR;;;{client_sid})(D;;CR;;;{service_sid})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          computer_allowed_to=allowed)

        # Assign the policy to the service account.
        self.add_attribute(samdb, service_dn_str,
                           'msDS-AssignedAuthNPolicy', str(policy))

        client_service_tkt = self.get_service_ticket(
            client_tgt,
            service_creds,
            kdc_options=client_tkt_options,
            expected_flags=expected_flags)

        kdc_options = str(krb5_asn1.KDCOptions('cname-in-addl-tkt'))

        target_decryption_key = self.TicketDecryptionKey_from_creds(
            service_creds)

        # Show that obtaining a service ticket to ourselves with constrained
        # delegation is not allowed without msDS-AllowedToDelegateTo.
        self._tgs_req(service_tgt, KDC_ERR_BADOPTION,
                      service_creds, service_creds,
                      armor_tgt=mach_tgt,
                      kdc_options=kdc_options,
                      additional_ticket=client_service_tkt,
                      decryption_key=target_decryption_key,
                      expect_edata=self.expect_padata_outer,
                      check_patypes=False)

    def test_authn_policy_allowed_to_user_allow_rbcd_to_self(self):
        samdb = self.get_samdb()
        functional_level = self.get_domain_functional_level(samdb)

        if functional_level < dsdb.DS_DOMAIN_FUNCTION_2008:
            self.skipTest('RBCD requires FL2008')

        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        client_sid = client_creds.get_sid()

        client_username = client_creds.get_username()
        client_cname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                                 names=[client_username])

        client_tkt_options = 'forwardable'
        expected_flags = krb5_asn1.TicketFlags(client_tkt_options)

        client_tgt = self.get_tgt(client_creds,
                                  kdc_options=client_tkt_options,
                                  expected_flags=expected_flags)

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a service account allowed to delegate to itself. We can’t use
        # a more specific ACE containing the account’s SID (obtained
        # post-creation) as Samba (unlike Windows) won’t let us modify
        # msDS-AllowedToActOnBehalfOfOtherIdentity without being System.
        domain_sid = security.dom_sid(samdb.get_domain_sid())
        security_descriptor = security.descriptor.from_sddl(
            'O:BAD:(A;;CR;;;WD)', domain_sid)
        service_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'delegation_from_dn': ndr_pack(security_descriptor)},
            use_cache=False)
        service_dn_str = str(service_creds.get_dn())
        service_sid = service_creds.get_sid()
        service_tgt = self.get_tgt(service_creds)

        # Create an authentication policy that applies to a computer and
        # explicitly allows the client account to obtain a service ticket,
        # while denying the service.
        allowed = f'O:SYD:(A;;CR;;;{client_sid})(D;;CR;;;{service_sid})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          computer_allowed_to=allowed)

        # Assign the policy to the service account.
        self.add_attribute(samdb, service_dn_str,
                           'msDS-AssignedAuthNPolicy', str(policy))

        client_service_tkt = self.get_service_ticket(
            client_tgt,
            service_creds,
            kdc_options=client_tkt_options,
            expected_flags=expected_flags)

        kdc_options = str(krb5_asn1.KDCOptions('cname-in-addl-tkt'))

        service_decryption_key = self.TicketDecryptionKey_from_creds(
            service_creds)
        service_etypes = service_creds.tgs_supported_enctypes

        service_name = service_creds.get_username()
        if service_name[-1] == '$':
            service_name = service_name[:-1]
        expected_transited_services = [
            f'host/{service_name}@{service_creds.get_realm()}'
        ]

        # Show that obtaining a service ticket to ourselves with RBCD is
        # allowed.
        self._tgs_req(service_tgt, 0, service_creds, service_creds,
                      armor_tgt=mach_tgt,
                      kdc_options=kdc_options,
                      pac_options='1001',  # supports claims, RBCD
                      expected_cname=client_cname,
                      expected_account_name=client_username,
                      additional_ticket=client_service_tkt,
                      decryption_key=service_decryption_key,
                      expected_sid=client_sid,
                      expected_supported_etypes=service_etypes,
                      expected_proxy_target=service_creds.get_spn(),
                      expected_transited_services=expected_transited_services)

    def test_authn_policy_allowed_to_user_deny_rbcd_to_self(self):
        samdb = self.get_samdb()
        functional_level = self.get_domain_functional_level(samdb)

        if functional_level < dsdb.DS_DOMAIN_FUNCTION_2008:
            self.skipTest('RBCD requires FL2008')

        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        client_sid = client_creds.get_sid()

        client_username = client_creds.get_username()
        client_cname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                                 names=[client_username])

        client_tkt_options = 'forwardable'
        expected_flags = krb5_asn1.TicketFlags(client_tkt_options)

        client_tgt = self.get_tgt(client_creds,
                                  kdc_options=client_tkt_options,
                                  expected_flags=expected_flags)

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a service account allowed to delegate to itself. We can’t use
        # a more specific ACE containing the account’s SID (obtained
        # post-creation) as Samba (unlike Windows) won’t let us modify
        # msDS-AllowedToActOnBehalfOfOtherIdentity without being System.
        domain_sid = security.dom_sid(samdb.get_domain_sid())
        security_descriptor = security.descriptor.from_sddl(
            'O:BAD:(A;;CR;;;WD)', domain_sid)
        service_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'delegation_from_dn': ndr_pack(security_descriptor)},
            use_cache=False)
        service_dn_str = str(service_creds.get_dn())
        service_sid = service_creds.get_sid()
        service_tgt = self.get_tgt(service_creds)

        client_service_tkt = self.get_service_ticket(
            client_tgt,
            service_creds,
            kdc_options=client_tkt_options,
            expected_flags=expected_flags)

        # Create an authentication policy that applies to a computer and
        # explicitly denies the client account to obtain a service ticket,
        # while allowing the service.
        allowed = f'O:SYD:(D;;CR;;;{client_sid})(A;;CR;;;{service_sid})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          computer_allowed_to=allowed)

        # Assign the policy to the service account.
        self.add_attribute(samdb, service_dn_str,
                           'msDS-AssignedAuthNPolicy', str(policy))

        kdc_options = str(krb5_asn1.KDCOptions('cname-in-addl-tkt'))

        service_decryption_key = self.TicketDecryptionKey_from_creds(
            service_creds)
        service_etypes = service_creds.tgs_supported_enctypes

        service_name = service_creds.get_username()
        if service_name[-1] == '$':
            service_name = service_name[:-1]
        expected_transited_services = [
            f'host/{service_name}@{service_creds.get_realm()}'
        ]

        # Show that obtaining a service ticket to ourselves with RBCD is
        # allowed, despite the policy’s disallowing it.
        self._tgs_req(service_tgt, 0, service_creds, service_creds,
                      armor_tgt=mach_tgt,
                      kdc_options=kdc_options,
                      pac_options='1001',  # supports claims, RBCD
                      expected_cname=client_cname,
                      expected_account_name=client_username,
                      additional_ticket=client_service_tkt,
                      decryption_key=service_decryption_key,
                      expected_sid=client_sid,
                      expected_supported_etypes=service_etypes,
                      expected_proxy_target=service_creds.get_spn(),
                      expected_transited_services=expected_transited_services)

    def test_authn_policy_allowed_to_user_not_allowed_rbcd_to_self(self):
        samdb = self.get_samdb()
        functional_level = self.get_domain_functional_level(samdb)

        if functional_level < dsdb.DS_DOMAIN_FUNCTION_2008:
            self.skipTest('RBCD requires FL2008')

        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        client_sid = client_creds.get_sid()

        client_tkt_options = 'forwardable'
        expected_flags = krb5_asn1.TicketFlags(client_tkt_options)

        client_tgt = self.get_tgt(client_creds,
                                  kdc_options=client_tkt_options,
                                  expected_flags=expected_flags)

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a service account.
        service_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'id': 1},
            use_cache=False)
        service_dn_str = str(service_creds.get_dn())
        service_sid = service_creds.get_sid()
        service_tgt = self.get_tgt(service_creds)

        # Don’t set msDS-AllowedToActOnBehalfOfOtherIdentity.

        # Create an authentication policy that applies to a computer and
        # explicitly allows the client account to obtain a service ticket,
        # while denying the service.
        allowed = f'O:SYD:(A;;CR;;;{client_sid})(D;;CR;;;{service_sid})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          computer_allowed_to=allowed)

        # Assign the policy to the service account.
        self.add_attribute(samdb, service_dn_str,
                           'msDS-AssignedAuthNPolicy', str(policy))

        client_service_tkt = self.get_service_ticket(
            client_tgt,
            service_creds,
            kdc_options=client_tkt_options,
            expected_flags=expected_flags)

        kdc_options = str(krb5_asn1.KDCOptions('cname-in-addl-tkt'))

        service_decryption_key = self.TicketDecryptionKey_from_creds(
            service_creds)

        # Show that obtaining a service ticket to ourselves with RBCD
        # is not allowed without msDS-AllowedToActOnBehalfOfOtherIdentity.
        self._tgs_req(service_tgt, KDC_ERR_BADOPTION,
                      service_creds, service_creds,
                      armor_tgt=mach_tgt,
                      kdc_options=kdc_options,
                      pac_options='1001',  # supports claims, RBCD
                      additional_ticket=client_service_tkt,
                      decryption_key=service_decryption_key,
                      expect_edata=self.expect_padata_outer,
                      check_patypes=False)

    def test_authn_policy_allowed_to_computer_allow_user2user(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        client_creds = self.get_mach_creds()
        client_tgt = self.get_tgt(client_creds)

        # Create an authentication policy that applies to a computer and
        # explicitly allows the user account to obtain a service ticket.
        allowed = f'O:SYD:(A;;CR;;;{client_creds.get_sid()})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          computer_allowed_to=allowed)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)
        target_tgt = self._get_tgt(target_creds)

        kdc_options = str(krb5_asn1.KDCOptions('enc-tkt-in-skey'))

        # Show that obtaining a service ticket with user-to-user is allowed.
        self._tgs_req(client_tgt, 0, client_creds, target_creds,
                      armor_tgt=mach_tgt,
                      kdc_options=kdc_options,
                      additional_ticket=target_tgt)

    def test_authn_policy_allowed_to_computer_deny_user2user(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        client_creds = self.get_mach_creds()
        client_tgt = self.get_tgt(client_creds)

        # Create an authentication policy that applies to a computer and
        # explicitly denies the user account to obtain a service ticket.
        denied = f'O:SYD:(D;;CR;;;{client_creds.get_sid()})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          computer_allowed_to=denied)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)
        target_tgt = self._get_tgt(target_creds)

        kdc_options = str(krb5_asn1.KDCOptions('enc-tkt-in-skey'))

        # Show that obtaining a service ticket with user-to-user is not
        # allowed.
        self._tgs_req(
            client_tgt, KDC_ERR_POLICY, client_creds, target_creds,
            armor_tgt=mach_tgt,
            kdc_options=kdc_options,
            additional_ticket=target_tgt,
            expect_edata=self.expect_padata_outer,
            # We aren’t particular about whether or not we get an NTSTATUS.
            expect_status=None,
            expected_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            check_patypes=False)

    def test_authn_policy_allowed_to_user_derived_class_allow(self):
        samdb = self.get_samdb()

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a user account.
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        tgt = self.get_tgt(client_creds)

        # Create an authentication policy that applies to a user and explicitly
        # allows the user account to obtain a service ticket.
        allowed = f'O:SYD:(A;;CR;;;{client_creds.get_sid()})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=allowed,
                                          computer_allowed_to=denied,
                                          service_allowed_to=denied)

        # Create a schema class derived from ‘user’.
        class_id = random.randint(0, 100000000)
        user_class_cn = f'my-User-Class-{class_id}'
        user_class = user_class_cn.replace('-', '')
        class_dn = samdb.get_schema_basedn()
        class_dn.add_child(f'CN={user_class_cn}')
        governs_id = f'1.3.6.1.4.1.7165.4.6.2.9.{class_id}'

        samdb.add({
            'dn': class_dn,
            'objectClass': 'classSchema',
            'subClassOf': 'user',
            'governsId': governs_id,
            'lDAPDisplayName': user_class,
        })

        # Create an account derived from ‘user’ with the assigned policy.
        target_name = self.get_new_username()
        target_creds, target_dn = self.create_account(
            samdb, target_name,
            account_type=self.AccountType.USER,
            spn='host/{account}',
            additional_details={
                'msDS-AssignedAuthNPolicy': str(policy),
                'objectClass': user_class,
            })

        keys = self.get_keys(target_creds)
        self.creds_set_keys(target_creds, keys)

        # Show that obtaining a service ticket is allowed.
        self._tgs_req(tgt, 0, client_creds, target_creds,
                      armor_tgt=mach_tgt)

    def test_authn_policy_allowed_to_computer_derived_class_allow(self):
        samdb = self.get_samdb()

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a user account.
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        tgt = self.get_tgt(client_creds)

        # Create an authentication policy that applies to a computer and
        # explicitly allows the user account to obtain a service ticket.
        allowed = f'O:SYD:(A;;CR;;;{client_creds.get_sid()})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=allowed,
                                          service_allowed_to=denied)

        # Create a schema class derived from ‘computer’.
        class_id = random.randint(0, 100000000)
        computer_class_cn = f'my-Computer-Class-{class_id}'
        computer_class = computer_class_cn.replace('-', '')
        class_dn = samdb.get_schema_basedn()
        class_dn.add_child(f'CN={computer_class_cn}')
        governs_id = f'1.3.6.1.4.1.7165.4.6.2.9.{class_id}'

        samdb.add({
            'dn': class_dn,
            'objectClass': 'classSchema',
            'subClassOf': 'computer',
            'governsId': governs_id,
            'lDAPDisplayName': computer_class,
        })

        # Create an account derived from ‘computer’ with the assigned policy.
        target_name = self.get_new_username()
        target_creds, target_dn = self.create_account(
            samdb, target_name,
            account_type=self.AccountType.COMPUTER,
            spn=f'host/{target_name}',
            additional_details={
                'msDS-AssignedAuthNPolicy': str(policy),
                'objectClass': computer_class,
            })

        keys = self.get_keys(target_creds)
        self.creds_set_keys(target_creds, keys)

        # Show that obtaining a service ticket is allowed.
        self._tgs_req(tgt, 0, client_creds, target_creds,
                      armor_tgt=mach_tgt)

    def test_authn_policy_allowed_to_service_derived_class_allow(self):
        samdb = self.get_samdb()

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a user account.
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        tgt = self.get_tgt(client_creds)

        # Create an authentication policy that applies to a managed service and
        # explicitly allows the user account to obtain a service ticket.
        allowed = f'O:SYD:(A;;CR;;;{client_creds.get_sid()})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=denied,
                                          service_allowed_to=allowed)

        # Create a schema class derived from ‘msDS-ManagedServiceAccount’.
        class_id = random.randint(0, 100000000)
        service_class_cn = f'my-Managed-Service-Class-{class_id}'
        service_class = service_class_cn.replace('-', '')
        class_dn = samdb.get_schema_basedn()
        class_dn.add_child(f'CN={service_class_cn}')
        governs_id = f'1.3.6.1.4.1.7165.4.6.2.9.{class_id}'

        samdb.add({
            'dn': class_dn,
            'objectClass': 'classSchema',
            'subClassOf': 'msDS-ManagedServiceAccount',
            'governsId': governs_id,
            'lDAPDisplayName': service_class,
        })

        # Create an account derived from ‘msDS-ManagedServiceAccount’ with the
        # assigned policy.
        target_name = self.get_new_username()
        target_creds, target_dn = self.create_account(
            samdb, target_name,
            account_type=self.AccountType.MANAGED_SERVICE,
            spn=f'host/{target_name}',
            additional_details={
                'msDS-AssignedAuthNPolicy': str(policy),
                'objectClass': service_class,
            })

        # Show that obtaining a service ticket is allowed.
        self._tgs_req(tgt, 0, client_creds, target_creds,
                      armor_tgt=mach_tgt)

    def test_authn_policy_ntlm_allow_user(self):
        # Create an authentication policy allowing NTLM authentication for
        # users.
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_ntlm=True,
                                          user_allowed_from=allowed,
                                          service_allowed_ntlm=False,
                                          service_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy,
                                       ntlm=True)

        # Show that NTLM authentication succeeds.
        self._connect(client_creds, simple_bind=False)

    def test_authn_policy_ntlm_deny_user(self):
        # Create an authentication policy denying NTLM authentication for
        # users.
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_ntlm=False,
                                          user_allowed_from=allowed,
                                          service_allowed_ntlm=True,
                                          service_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy,
                                       ntlm=True)

        # Show that NTLM authentication fails.
        self._connect(client_creds, simple_bind=False,
                      expect_error=f'{HRES_SEC_E_LOGON_DENIED:08X}')

    def test_authn_policy_ntlm_computer(self):
        # Create an authentication policy denying NTLM authentication.
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_ntlm=False,
                                          user_allowed_from=denied,
                                          service_allowed_ntlm=False,
                                          service_allowed_from=denied)

        # Create a computer account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy,
                                       ntlm=True)

        # Show that NTLM authentication succeeds.
        self._connect(client_creds, simple_bind=False)

    def test_authn_policy_ntlm_allow_service(self):
        # Create an authentication policy allowing NTLM authentication for
        # services.
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_ntlm=False,
                                          user_allowed_from=allowed,
                                          service_allowed_ntlm=True,
                                          service_allowed_from=allowed)

        # Create a managed service account with the assigned policy.
        client_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
            assigned_policy=policy,
            ntlm=True)

        # Show that NTLM authentication succeeds.
        self._connect(client_creds, simple_bind=False)

    def test_authn_policy_ntlm_deny_service(self):
        # Create an authentication policy denying NTLM authentication for
        # services.
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_ntlm=True,
                                          user_allowed_from=allowed,
                                          service_allowed_ntlm=False,
                                          service_allowed_from=allowed)

        # Create a managed service account with the assigned policy.
        client_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
            assigned_policy=policy,
            ntlm=True)

        # Show that NTLM authentication fails.
        self._connect(client_creds, simple_bind=False,
                      expect_error=f'{HRES_SEC_E_LOGON_DENIED:08X}')

    def test_authn_policy_ntlm_deny_no_device_restrictions(self):
        # Create an authentication policy denying NTLM authentication for
        # users.
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_ntlm=False,
                                          service_allowed_ntlm=True)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy,
                                       ntlm=True)

        # Show that without AllowedToAuthenticateFrom set in the policy, NTLM
        # authentication succeeds.
        self._connect(client_creds, simple_bind=False)

    def test_authn_policy_simple_bind_allow_user(self):
        # Create an authentication policy allowing NTLM authentication for
        # users.
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_ntlm=True,
                                          user_allowed_from=allowed,
                                          service_allowed_ntlm=False,
                                          service_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy,
                                       ntlm=True)

        # Show that a simple bind succeeds.
        self._connect(client_creds, simple_bind=True)

    def test_authn_policy_simple_bind_deny_user(self):
        # Create an authentication policy denying NTLM authentication for
        # users.
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_ntlm=False,
                                          user_allowed_from=allowed,
                                          service_allowed_ntlm=True,
                                          service_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy,
                                       ntlm=True)

        # Show that a simple bind fails.
        self._connect(client_creds, simple_bind=True,
                      expect_error=f'{HRES_SEC_E_INVALID_TOKEN:08X}')

    def test_authn_policy_simple_bind_deny_no_device_restrictions(self):
        # Create an authentication policy denying NTLM authentication for
        # users.
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_ntlm=False,
                                          service_allowed_ntlm=True)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy,
                                       ntlm=True)

        # Show that without AllowedToAuthenticateFrom set in the policy, a
        # simple bind succeeds.
        self._connect(client_creds, simple_bind=True)

    def test_authn_policy_samr_pwd_change_allow_service_allowed_from(self):
        # Create an authentication policy allowing NTLM authentication for
        # managed service accounts.
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          service_allowed_ntlm=True,
                                          service_allowed_from=allowed)

        # Create a managed service account with the assigned policy.
        client_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
            assigned_policy=policy,
            ntlm=True)

        # Show that a SAMR password change is allowed.
        self._test_samr_change_password(client_creds, expect_error=None)

    def test_authn_policy_samr_pwd_change_allow_service_not_allowed_from(self):
        # Create an authentication policy allowing NTLM authentication for
        # managed service accounts.
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          service_allowed_ntlm=True,
                                          service_allowed_from=denied)

        # Create a managed service account with the assigned policy.
        client_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
            assigned_policy=policy,
            ntlm=True)

        # Show that a SAMR password change is allowed.
        self._test_samr_change_password(client_creds, expect_error=None)

    def test_authn_policy_samr_pwd_change_allow_service_no_allowed_from(self):
        # Create an authentication policy allowing NTLM authentication for
        # managed service accounts.
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          service_allowed_ntlm=True)

        # Create a managed service account with the assigned policy.
        client_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
            assigned_policy=policy,
            ntlm=True)

        # Show that a SAMR password change is allowed.
        self._test_samr_change_password(client_creds, expect_error=None)

    def test_authn_policy_samr_pwd_change_deny_service_allowed_from(self):
        # Create an authentication policy denying NTLM authentication for
        # managed service accounts.
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          service_allowed_ntlm=False,
                                          service_allowed_from=allowed)

        # Create a managed service account with the assigned policy.
        client_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
            assigned_policy=policy,
            ntlm=True)

        # Show that the SAMR connection fails.
        self._test_samr_change_password(
            client_creds, expect_error=None,
            connect_error=ntstatus.NT_STATUS_ACCOUNT_RESTRICTION)

    def test_authn_policy_samr_pwd_change_deny_service_not_allowed_from(self):
        # Create an authentication policy denying NTLM authentication for
        # managed service accounts.
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          service_allowed_ntlm=False,
                                          service_allowed_from=denied)

        # Create a managed service account with the assigned policy.
        client_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
            assigned_policy=policy,
            ntlm=True)

        # Show that the SAMR connection fails.
        self._test_samr_change_password(
            client_creds, expect_error=None,
            connect_error=ntstatus.NT_STATUS_ACCOUNT_RESTRICTION)

    def test_authn_policy_samr_pwd_change_deny_service_no_allowed_from(self):
        # Create an authentication policy denying NTLM authentication for
        # managed service accounts.
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          service_allowed_ntlm=False)

        # Create a managed service account with the assigned policy.
        client_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
            assigned_policy=policy,
            ntlm=True)

        # Show that a SAMR password change is allowed.
        self._test_samr_change_password(client_creds, expect_error=None)

    def test_authn_policy_samlogon_allow_user(self):
        # Create an authentication policy allowing NTLM authentication for
        # users.
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_ntlm=True,
                                          user_allowed_from=allowed,
                                          service_allowed_ntlm=False,
                                          service_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy,
                                       ntlm=True)

        # Show that a network SamLogon succeeds.
        self._test_samlogon(creds=client_creds,
                            logon_type=netlogon.NetlogonNetworkInformation)

        # Show that an interactive SamLogon succeeds. Although MS-APDS doesn’t
        # state it, AllowedNTLMNetworkAuthentication applies to interactive
        # logons too.
        self._test_samlogon(creds=client_creds,
                            logon_type=netlogon.NetlogonInteractiveInformation)

    def test_authn_policy_samlogon_deny_user(self):
        # Create an authentication policy denying NTLM authentication for
        # users.
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_ntlm=False,
                                          user_allowed_from=allowed,
                                          service_allowed_ntlm=True,
                                          service_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy,
                                       ntlm=True)

        # Show that a network SamLogon fails.
        self._test_samlogon(
            creds=client_creds,
            logon_type=netlogon.NetlogonNetworkInformation,
            expect_error=ntstatus.NT_STATUS_ACCOUNT_RESTRICTION)

        # Show that an interactive SamLogon fails.
        self._test_samlogon(
            creds=client_creds,
            logon_type=netlogon.NetlogonInteractiveInformation,
            expect_error=ntstatus.NT_STATUS_ACCOUNT_RESTRICTION)

    def test_authn_policy_samlogon_network_computer(self):
        # Create an authentication policy denying NTLM authentication.
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_ntlm=False,
                                          user_allowed_from=denied,
                                          service_allowed_ntlm=False,
                                          service_allowed_from=denied)

        # Create a computer account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy,
                                       ntlm=True)

        # Show that a network SamLogon succeeds.
        self._test_samlogon(
            creds=client_creds,
            logon_type=netlogon.NetlogonNetworkInformation)

    def test_authn_policy_samlogon_interactive_allow_user_allowed_from(self):
        # Create an authentication policy allowing NTLM authentication for
        # users.
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_ntlm=True,
                                          user_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy,
                                       ntlm=True,
                                       cached=False)

        # Show that an interactive SamLogon succeeds. Although MS-APDS doesn’t
        # state it, AllowedNTLMNetworkAuthentication applies to interactive
        # logons too.
        self._test_samlogon(creds=client_creds,
                            logon_type=netlogon.NetlogonInteractiveInformation)

    def test_authn_policy_samlogon_interactive_allow_user_not_allowed_from(self):
        # Create an authentication policy allowing NTLM authentication for
        # users.
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_ntlm=True,
                                          user_allowed_from=denied)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy,
                                       ntlm=True,
                                       cached=False)

        # Show that an interactive SamLogon succeeds. Although MS-APDS doesn’t
        # state it, AllowedNTLMNetworkAuthentication applies to interactive
        # logons too.
        self._test_samlogon(creds=client_creds,
                            logon_type=netlogon.NetlogonInteractiveInformation)

    def test_authn_policy_samlogon_interactive_allow_user_no_allowed_from(self):
        # Create an authentication policy allowing NTLM authentication for
        # users.
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_ntlm=True)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy,
                                       ntlm=True,
                                       cached=False)

        # Show that an interactive SamLogon succeeds.
        self._test_samlogon(creds=client_creds,
                            logon_type=netlogon.NetlogonInteractiveInformation)

    def test_authn_policy_samlogon_interactive_deny_user_allowed_from(self):
        # Create an authentication policy disallowing NTLM authentication for
        # users.
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_ntlm=False,
                                          user_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy,
                                       ntlm=True,
                                       cached=False)

        # Show that an interactive SamLogon fails.
        self._test_samlogon(
            creds=client_creds,
            logon_type=netlogon.NetlogonInteractiveInformation,
            expect_error=ntstatus.NT_STATUS_ACCOUNT_RESTRICTION)

    def test_authn_policy_samlogon_interactive_deny_user_not_allowed_from(self):
        # Create an authentication policy disallowing NTLM authentication for
        # users.
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_ntlm=False,
                                          user_allowed_from=denied)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy,
                                       ntlm=True,
                                       cached=False)

        # Show that an interactive SamLogon fails.
        self._test_samlogon(
            creds=client_creds,
            logon_type=netlogon.NetlogonInteractiveInformation,
            expect_error=ntstatus.NT_STATUS_ACCOUNT_RESTRICTION)

    def test_authn_policy_samlogon_interactive_deny_user_no_allowed_from(self):
        # Create an authentication policy disallowing NTLM authentication for
        # users.
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_ntlm=False)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy,
                                       ntlm=True,
                                       cached=False)

        # Show that an interactive SamLogon succeeds.
        self._test_samlogon(creds=client_creds,
                            logon_type=netlogon.NetlogonInteractiveInformation)

    def test_authn_policy_samlogon_interactive_user_allowed_from(self):
        # Create an authentication policy not specifying whether NTLM
        # authentication is allowed or not.
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy,
                                       ntlm=True,
                                       cached=False)

        # Show that an interactive SamLogon fails.
        self._test_samlogon(
            creds=client_creds,
            logon_type=netlogon.NetlogonInteractiveInformation,
            expect_error=ntstatus.NT_STATUS_ACCOUNT_RESTRICTION)

    def test_authn_policy_samlogon_network_user_allowed_from(self):
        # Create an authentication policy not specifying whether NTLM
        # authentication is allowed or not.
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy,
                                       ntlm=True,
                                       cached=False)

        # Show that a network SamLogon fails.
        self._test_samlogon(
            creds=client_creds,
            logon_type=netlogon.NetlogonNetworkInformation,
            expect_error=ntstatus.NT_STATUS_ACCOUNT_RESTRICTION)

    def test_authn_policy_samlogon_network_allow_service_allowed_from(self):
        # Create an authentication policy allowing NTLM authentication for
        # services.
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          service_allowed_ntlm=True,
                                          service_allowed_from=allowed)

        # Create a managed service account with the assigned policy.
        client_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
            assigned_policy=policy,
            ntlm=True,
            cached=False)

        # Show that a network SamLogon succeeds.
        self._test_samlogon(creds=client_creds,
                            logon_type=netlogon.NetlogonNetworkInformation)

    def test_authn_policy_samlogon_network_allow_service_not_allowed_from(self):
        # Create an authentication policy allowing NTLM authentication for
        # services.
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          service_allowed_ntlm=True,
                                          service_allowed_from=denied)

        # Create a managed service account with the assigned policy.
        client_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
            assigned_policy=policy,
            ntlm=True,
            cached=False)

        # Show that a network SamLogon succeeds.
        self._test_samlogon(creds=client_creds,
                            logon_type=netlogon.NetlogonNetworkInformation)

    def test_authn_policy_samlogon_network_allow_service_no_allowed_from(self):
        # Create an authentication policy allowing NTLM authentication for
        # services.
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          service_allowed_ntlm=True)

        # Create a managed service account with the assigned policy.
        client_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
            assigned_policy=policy,
            ntlm=True,
            cached=False)

        # Show that a network SamLogon succeeds.
        self._test_samlogon(creds=client_creds,
                            logon_type=netlogon.NetlogonNetworkInformation)

    def test_authn_policy_samlogon_network_deny_service_allowed_from(self):
        # Create an authentication policy disallowing NTLM authentication for
        # services.
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          service_allowed_ntlm=False,
                                          service_allowed_from=allowed)

        # Create a managed service account with the assigned policy.
        client_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
            assigned_policy=policy,
            ntlm=True,
            cached=False)

        # Show that a network SamLogon fails.
        self._test_samlogon(
            creds=client_creds,
            logon_type=netlogon.NetlogonNetworkInformation,
            expect_error=ntstatus.NT_STATUS_ACCOUNT_RESTRICTION)

    def test_authn_policy_samlogon_network_deny_service_not_allowed_from(self):
        # Create an authentication policy disallowing NTLM authentication for
        # services.
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          service_allowed_ntlm=False,
                                          service_allowed_from=denied)

        # Create a managed service account with the assigned policy.
        client_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
            assigned_policy=policy,
            ntlm=True,
            cached=False)

        # Show that a network SamLogon fails.
        self._test_samlogon(
            creds=client_creds,
            logon_type=netlogon.NetlogonNetworkInformation,
            expect_error=ntstatus.NT_STATUS_ACCOUNT_RESTRICTION)

    def test_authn_policy_samlogon_network_deny_service_no_allowed_from(self):
        # Create an authentication policy disallowing NTLM authentication for
        # services.
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          service_allowed_ntlm=False)

        # Create a managed service account with the assigned policy.
        client_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
            assigned_policy=policy,
            ntlm=True,
            cached=False)

        # Show that a network SamLogon succeeds.
        self._test_samlogon(creds=client_creds,
                            logon_type=netlogon.NetlogonNetworkInformation)

    def test_authn_policy_samlogon_network_allow_service_allowed_from_to_self(self):
        # Create an authentication policy allowing NTLM authentication for
        # services.
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          service_allowed_ntlm=True,
                                          service_allowed_from=allowed)

        # Create a managed service account with the assigned policy.
        client_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
            assigned_policy=policy,
            ntlm=True,
            cached=False)

        # Show that a network SamLogon to ourselves succeeds.
        self._test_samlogon(creds=client_creds,
                            domain_joined_mach_creds=client_creds,
                            logon_type=netlogon.NetlogonNetworkInformation)

    def test_authn_policy_samlogon_network_allow_service_not_allowed_from_to_self(self):
        # Create an authentication policy allowing NTLM authentication for
        # services.
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          service_allowed_ntlm=True,
                                          service_allowed_from=denied)

        # Create a managed service account with the assigned policy.
        client_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
            assigned_policy=policy,
            ntlm=True,
            cached=False)

        # Show that a network SamLogon to ourselves succeeds.
        self._test_samlogon(creds=client_creds,
                            domain_joined_mach_creds=client_creds,
                            logon_type=netlogon.NetlogonNetworkInformation)

    def test_authn_policy_samlogon_network_allow_service_no_allowed_from_to_self(self):
        # Create an authentication policy allowing NTLM authentication for
        # services.
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          service_allowed_ntlm=True)

        # Create a managed service account with the assigned policy.
        client_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
            assigned_policy=policy,
            ntlm=True,
            cached=False)

        # Show that a network SamLogon to ourselves succeeds.
        self._test_samlogon(creds=client_creds,
                            domain_joined_mach_creds=client_creds,
                            logon_type=netlogon.NetlogonNetworkInformation)

    def test_authn_policy_samlogon_network_deny_service_allowed_from_to_self(self):
        # Create an authentication policy disallowing NTLM authentication for
        # services.
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          service_allowed_ntlm=False,
                                          service_allowed_from=allowed)

        # Create a managed service account with the assigned policy.
        client_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
            assigned_policy=policy,
            ntlm=True,
            cached=False)

        # Show that a network SamLogon to ourselves fails.
        self._test_samlogon(
            creds=client_creds,
            domain_joined_mach_creds=client_creds,
            logon_type=netlogon.NetlogonNetworkInformation,
            expect_error=ntstatus.NT_STATUS_ACCOUNT_RESTRICTION)

    def test_authn_policy_samlogon_network_deny_service_not_allowed_from_to_self(self):
        # Create an authentication policy disallowing NTLM authentication for
        # services.
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          service_allowed_ntlm=False,
                                          service_allowed_from=denied)

        # Create a managed service account with the assigned policy.
        client_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
            assigned_policy=policy,
            ntlm=True,
            cached=False)

        # Show that a network SamLogon to ourselves fails.
        self._test_samlogon(
            creds=client_creds,
            domain_joined_mach_creds=client_creds,
            logon_type=netlogon.NetlogonNetworkInformation,
            expect_error=ntstatus.NT_STATUS_ACCOUNT_RESTRICTION)

    def test_authn_policy_samlogon_network_deny_service_no_allowed_from_to_self(self):
        # Create an authentication policy disallowing NTLM authentication for
        # services.
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          service_allowed_ntlm=False)

        # Create a managed service account with the assigned policy.
        client_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
            assigned_policy=policy,
            ntlm=True,
            cached=False)

        # Show that a network SamLogon to ourselves succeeds.
        self._test_samlogon(creds=client_creds,
                            domain_joined_mach_creds=client_creds,
                            logon_type=netlogon.NetlogonNetworkInformation)

    def test_authn_policy_samlogon_interactive_deny_no_device_restrictions(self):
        # Create an authentication policy denying NTLM authentication for
        # users.
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_ntlm=False,
                                          service_allowed_ntlm=True)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy,
                                       ntlm=True)

        # Show that without AllowedToAuthenticateFrom set in the policy, an
        # interactive SamLogon succeeds.
        self._test_samlogon(creds=client_creds,
                            logon_type=netlogon.NetlogonInteractiveInformation)

    def test_authn_policy_samlogon_network_deny_no_device_restrictions(self):
        # Create an authentication policy denying NTLM authentication for
        # users.
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_ntlm=False,
                                          service_allowed_ntlm=True)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy,
                                       ntlm=True)

        # Show that without AllowedToAuthenticateFrom set in the policy, a
        # network SamLogon succeeds.
        self._test_samlogon(creds=client_creds,
                            logon_type=netlogon.NetlogonNetworkInformation)

    def test_samlogon_allowed_to_computer_allow(self):
        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       ntlm=True)

        # Create an authentication policy that applies to a computer and
        # explicitly allows the user account to obtain a service ticket.
        allowed = f'O:SYD:(A;;CR;;;{client_creds.get_sid()})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=allowed,
                                          service_allowed_to=denied)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that a network SamLogon succeeds.
        self._test_samlogon(creds=client_creds,
                            domain_joined_mach_creds=target_creds,
                            logon_type=netlogon.NetlogonNetworkInformation)

        # Show that an interactive SamLogon succeeds.
        self._test_samlogon(creds=client_creds,
                            domain_joined_mach_creds=target_creds,
                            logon_type=netlogon.NetlogonInteractiveInformation)

    def test_samlogon_allowed_to_computer_deny(self):
        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       ntlm=True)

        # Create an authentication policy that applies to a computer and
        # explicitly denies the user account to obtain a service ticket.
        denied = f'O:SYD:(D;;CR;;;{client_creds.get_sid()})'
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=allowed,
                                          computer_allowed_to=denied,
                                          service_allowed_to=allowed)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that a network SamLogon fails.
        self._test_samlogon(
            creds=client_creds,
            domain_joined_mach_creds=target_creds,
            logon_type=netlogon.NetlogonNetworkInformation,
            expect_error=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

        # Show that an interactive SamLogon fails.
        self._test_samlogon(
            creds=client_creds,
            domain_joined_mach_creds=target_creds,
            logon_type=netlogon.NetlogonInteractiveInformation,
            expect_error=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

    def test_samlogon_allowed_to_computer_deny_protected(self):
        # Create a protected user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       protected=True,
                                       ntlm=True)

        # Create an authentication policy that applies to a computer and
        # explicitly denies the user account to obtain a service ticket.
        denied = f'O:SYD:(D;;CR;;;{client_creds.get_sid()})'
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=allowed,
                                          computer_allowed_to=denied,
                                          service_allowed_to=allowed)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that a network SamLogon fails.
        self._test_samlogon(
            creds=client_creds,
            domain_joined_mach_creds=target_creds,
            logon_type=netlogon.NetlogonNetworkInformation,
            expect_error=ntstatus.NT_STATUS_ACCOUNT_RESTRICTION)

        # Show that an interactive SamLogon fails.
        self._test_samlogon(
            creds=client_creds,
            domain_joined_mach_creds=target_creds,
            logon_type=netlogon.NetlogonInteractiveInformation,
            expect_error=ntstatus.NT_STATUS_ACCOUNT_RESTRICTION)

    def test_samlogon_allowed_to_computer_allow_asserted_identity(self):
        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       ntlm=True)

        # Create an authentication policy that allows accounts with the
        # Authentication Authority Asserted Identity SID to obtain a service
        # ticket.
        allowed = (
            f'O:SYD:(A;;CR;;;'
            f'{security.SID_AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY})'
        )
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=allowed,
                                          service_allowed_to=denied)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that a network SamLogon fails.
        self._test_samlogon(
            creds=client_creds,
            domain_joined_mach_creds=target_creds,
            logon_type=netlogon.NetlogonNetworkInformation,
            expect_error=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

        # Show that an interactive SamLogon fails.
        self._test_samlogon(
            creds=client_creds,
            domain_joined_mach_creds=target_creds,
            logon_type=netlogon.NetlogonInteractiveInformation,
            expect_error=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

    def test_samlogon_allowed_to_computer_allow_claims_valid(self):
        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       ntlm=True)

        # Create an authentication policy that allows accounts with the Claims
        # Valid SID to obtain a service ticket.
        allowed = f'O:SYD:(A;;CR;;;{security.SID_CLAIMS_VALID})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=allowed,
                                          service_allowed_to=denied)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that a network SamLogon fails.
        self._test_samlogon(
            creds=client_creds,
            domain_joined_mach_creds=target_creds,
            logon_type=netlogon.NetlogonNetworkInformation,
            expect_error=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

        # Show that an interactive SamLogon fails.
        self._test_samlogon(
            creds=client_creds,
            domain_joined_mach_creds=target_creds,
            logon_type=netlogon.NetlogonInteractiveInformation,
            expect_error=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

    def test_samlogon_allowed_to_computer_allow_compounded_auth(self):
        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       ntlm=True)

        # Create an authentication policy that allows accounts with the
        # Compounded Authentication SID to obtain a service ticket.
        allowed = f'O:SYD:(A;;CR;;;{security.SID_COMPOUNDED_AUTHENTICATION})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=allowed,
                                          service_allowed_to=denied)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that a network SamLogon fails.
        self._test_samlogon(
            creds=client_creds,
            domain_joined_mach_creds=target_creds,
            logon_type=netlogon.NetlogonNetworkInformation,
            expect_error=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

        # Show that an interactive SamLogon fails.
        self._test_samlogon(
            creds=client_creds,
            domain_joined_mach_creds=target_creds,
            logon_type=netlogon.NetlogonInteractiveInformation,
            expect_error=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

    def test_samlogon_allowed_to_computer_allow_authenticated_users(self):
        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       ntlm=True)

        # Create an authentication policy that allows accounts with the
        # Authenticated Users SID to obtain a service ticket.
        allowed = f'O:SYD:(A;;CR;;;{security.SID_NT_AUTHENTICATED_USERS})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=allowed,
                                          service_allowed_to=denied)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that a network SamLogon succeeds.
        self._test_samlogon(creds=client_creds,
                            domain_joined_mach_creds=target_creds,
                            logon_type=netlogon.NetlogonNetworkInformation)

        # Show that an interactive SamLogon succeeds.
        self._test_samlogon(creds=client_creds,
                            domain_joined_mach_creds=target_creds,
                            logon_type=netlogon.NetlogonInteractiveInformation)

    def test_samlogon_allowed_to_computer_allow_ntlm_authn(self):
        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       ntlm=True)

        # Create an authentication policy that allows accounts with the NTLM
        # Authentication SID to obtain a service ticket.
        allowed = f'O:SYD:(A;;CR;;;{security.SID_NT_NTLM_AUTHENTICATION})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=allowed,
                                          service_allowed_to=denied)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that a network SamLogon fails.
        self._test_samlogon(
            creds=client_creds,
            domain_joined_mach_creds=target_creds,
            logon_type=netlogon.NetlogonNetworkInformation,
            expect_error=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

        # Show that an interactive SamLogon fails.
        self._test_samlogon(
            creds=client_creds,
            domain_joined_mach_creds=target_creds,
            logon_type=netlogon.NetlogonInteractiveInformation,
            expect_error=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

    def test_samlogon_allowed_to_no_owner(self):
        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       ntlm=True)

        # Create an authentication policy that applies to a computer and
        # explicitly allows the user account to obtain a service ticket. Omit
        # the owner (O:SY) from the SDDL.
        allowed = f'D:(A;;CR;;;{client_creds.get_sid()})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          computer_allowed_to=allowed)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that a network SamLogon fails.
        self._test_samlogon(
            creds=client_creds,
            domain_joined_mach_creds=target_creds,
            logon_type=netlogon.NetlogonNetworkInformation,
            expect_error=ntstatus.NT_STATUS_INVALID_PARAMETER)

        # Show that an interactive SamLogon fails.
        self._test_samlogon(
            creds=client_creds,
            domain_joined_mach_creds=target_creds,
            logon_type=netlogon.NetlogonInteractiveInformation,
            expect_error=ntstatus.NT_STATUS_INVALID_PARAMETER)

    def test_samlogon_allowed_to_no_owner_unenforced(self):
        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       ntlm=True)

        # Create an unenforced authentication policy that applies to a computer
        # and explicitly allows the user account to obtain a service
        # ticket. Omit the owner (O:SY) from the SDDL.
        allowed = f'D:(A;;CR;;;{client_creds.get_sid()})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=False,
                                          computer_allowed_to=allowed)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that a network SamLogon succeeds.
        self._test_samlogon(creds=client_creds,
                            domain_joined_mach_creds=target_creds,
                            logon_type=netlogon.NetlogonNetworkInformation)

        # Show that an interactive SamLogon succeeds.
        self._test_samlogon(creds=client_creds,
                            domain_joined_mach_creds=target_creds,
                            logon_type=netlogon.NetlogonInteractiveInformation)

    def test_samlogon_allowed_to_service_allow(self):
        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       ntlm=True)

        # Create an authentication policy that applies to a managed service and
        # explicitly allows the user account to obtain a service ticket.
        allowed = f'O:SYD:(A;;CR;;;{client_creds.get_sid()})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=denied,
                                          service_allowed_to=allowed)

        # Create a managed service account with the assigned policy.
        target_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
            assigned_policy=policy)

        # Show that a network SamLogon succeeds.
        self._test_samlogon(creds=client_creds,
                            domain_joined_mach_creds=target_creds,
                            logon_type=netlogon.NetlogonNetworkInformation)

        # Show that an interactive SamLogon succeeds.
        self._test_samlogon(creds=client_creds,
                            domain_joined_mach_creds=target_creds,
                            logon_type=netlogon.NetlogonInteractiveInformation)

    def test_samlogon_allowed_to_service_deny(self):
        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       ntlm=True)

        # Create an authentication policy that applies to a managed service and
        # explicitly denies the user account to obtain a service ticket.
        denied = f'O:SYD:(D;;CR;;;{client_creds.get_sid()})'
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=allowed,
                                          computer_allowed_to=allowed,
                                          service_allowed_to=denied)

        # Create a managed service account with the assigned policy.
        target_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
            assigned_policy=policy)

        # Show that a network SamLogon fails.
        self._test_samlogon(
            creds=client_creds,
            domain_joined_mach_creds=target_creds,
            logon_type=netlogon.NetlogonNetworkInformation,
            expect_error=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

        # Show that an interactive SamLogon fails.
        self._test_samlogon(
            creds=client_creds,
            domain_joined_mach_creds=target_creds,
            logon_type=netlogon.NetlogonInteractiveInformation,
            expect_error=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

    def test_samlogon_allowed_to_computer_allow_group_not_a_member(self):
        samdb = self.get_samdb()

        # Create a new group.
        group_name = self.get_new_username()
        group_dn = self.create_group(samdb, group_name)
        group_sid = self.get_objectSid(samdb, group_dn)

        # Create a user account which does not belong to the group.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       ntlm=True)

        # Create an authentication policy that allows accounts belonging to the
        # group.
        allowed = f'O:SYD:(A;;CR;;;{group_sid})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          computer_allowed_to=allowed)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that a network SamLogon fails, as the user account does not
        # belong to the group.
        self._test_samlogon(
            creds=client_creds,
            domain_joined_mach_creds=target_creds,
            logon_type=netlogon.NetlogonNetworkInformation,
            expect_error=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

        # Show that an interactive SamLogon fails, as the user account does not
        # belong to the group.
        self._test_samlogon(
            creds=client_creds,
            domain_joined_mach_creds=target_creds,
            logon_type=netlogon.NetlogonInteractiveInformation,
            expect_error=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

    def test_samlogon_allowed_to_computer_allow_group_member(self):
        samdb = self.get_samdb()

        # Create a new group.
        group_name = self.get_new_username()
        group_dn = self.create_group(samdb, group_name)
        group_sid = self.get_objectSid(samdb, group_dn)

        # Create a user account that belongs to the group.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       member_of=group_dn,
                                       ntlm=True)

        # Create an authentication policy that allows accounts belonging to the
        # group.
        allowed = f'O:SYD:(A;;CR;;;{group_sid})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          computer_allowed_to=allowed)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that a network SamLogon succeeds, since the user account belongs
        # to the group.
        self._test_samlogon(creds=client_creds,
                            domain_joined_mach_creds=target_creds,
                            logon_type=netlogon.NetlogonNetworkInformation)

        # Show that an interactive SamLogon succeeds, since the user account
        # belongs to the group.
        self._test_samlogon(creds=client_creds,
                            domain_joined_mach_creds=target_creds,
                            logon_type=netlogon.NetlogonInteractiveInformation)

    def test_samlogon_allowed_to_computer_allow_domain_local_group(self):
        samdb = self.get_samdb()

        # Create a new domain-local group.
        group_name = self.get_new_username()
        group_dn = self.create_group(samdb, group_name,
                                     gtype=GroupType.DOMAIN_LOCAL.value)
        group_sid = self.get_objectSid(samdb, group_dn)

        # Create a user account that belongs to the group.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       member_of=group_dn,
                                       ntlm=True)

        # Create an authentication policy that allows accounts belonging to the
        # group.
        allowed = f'O:SYD:(A;;CR;;;{group_sid})'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          computer_allowed_to=allowed)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that a network SamLogon succeeds, since the user account belongs
        # to the group.
        self._test_samlogon(creds=client_creds,
                            domain_joined_mach_creds=target_creds,
                            logon_type=netlogon.NetlogonNetworkInformation)

        # Show that an interactive SamLogon succeeds, since the user account
        # belongs to the group.
        self._test_samlogon(creds=client_creds,
                            domain_joined_mach_creds=target_creds,
                            logon_type=netlogon.NetlogonInteractiveInformation)

    def test_samlogon_allowed_to_computer_allow_to_self(self):
        samdb = self.get_samdb()

        # Create a computer account.
        client_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       ntlm=True,
                                       cached=False)
        client_dn = client_creds.get_dn()

        # Create an authentication policy that applies to a computer and
        # explicitly allows the user account to obtain a service ticket.
        allowed = f'O:SYD:(A;;CR;;;{client_creds.get_sid()})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=allowed,
                                          service_allowed_to=denied)

        # Assign the policy to the account.
        self.add_attribute(samdb, str(client_dn),
                           'msDS-AssignedAuthNPolicy', str(policy))

        # Show that a network SamLogon to ourselves succeeds.
        self._test_samlogon(creds=client_creds,
                            domain_joined_mach_creds=client_creds,
                            logon_type=netlogon.NetlogonNetworkInformation)

    def test_samlogon_allowed_to_computer_deny_to_self(self):
        samdb = self.get_samdb()

        # Create a computer account.
        client_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       ntlm=True,
                                       cached=False)
        client_dn = client_creds.get_dn()

        # Create an authentication policy that applies to a computer and
        # explicitly denies the user account to obtain a service ticket.
        denied = f'O:SYD:(D;;CR;;;{client_creds.get_sid()})'
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=allowed,
                                          computer_allowed_to=denied,
                                          service_allowed_to=allowed)

        # Assign the policy to the account.
        self.add_attribute(samdb, str(client_dn),
                           'msDS-AssignedAuthNPolicy', str(policy))

        # Show that a network SamLogon to ourselves fails, despite
        # authentication being allowed in the Kerberos case.
        self._test_samlogon(
            creds=client_creds,
            domain_joined_mach_creds=client_creds,
            logon_type=netlogon.NetlogonNetworkInformation,
            expect_error=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

    def test_samlogon_allowed_to_service_allow_to_self(self):
        samdb = self.get_samdb()

        # Create a managed service account.
        client_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
            ntlm=True,
            cached=False)
        client_dn = client_creds.get_dn()

        # Create an authentication policy that applies to a managed service and
        # explicitly allows the user account to obtain a service ticket.
        allowed = f'O:SYD:(A;;CR;;;{client_creds.get_sid()})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=denied,
                                          service_allowed_to=allowed)

        # Assign the policy to the account.
        self.add_attribute(samdb, str(client_dn),
                           'msDS-AssignedAuthNPolicy', str(policy))

        # Show that a network SamLogon to ourselves succeeds.
        self._test_samlogon(creds=client_creds,
                            domain_joined_mach_creds=client_creds,
                            logon_type=netlogon.NetlogonNetworkInformation)

    def test_samlogon_allowed_to_service_deny_to_self(self):
        samdb = self.get_samdb()

        # Create a managed service account.
        client_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
            ntlm=True,
            cached=False)
        client_dn = client_creds.get_dn()

        # Create an authentication policy that applies to a managed service and
        # explicitly denies the user account to obtain a service ticket.
        denied = f'O:SYD:(D;;CR;;;{client_creds.get_sid()})'
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=allowed,
                                          computer_allowed_to=allowed,
                                          service_allowed_to=denied)

        # Assign the policy to the account.
        self.add_attribute(samdb, str(client_dn),
                           'msDS-AssignedAuthNPolicy', str(policy))

        # Show that a network SamLogon to ourselves fails, despite
        # authentication being allowed in the Kerberos case.
        self._test_samlogon(
            creds=client_creds,
            domain_joined_mach_creds=client_creds,
            logon_type=netlogon.NetlogonNetworkInformation,
            expect_error=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

    def test_samlogon_allowed_to_computer_derived_class_allow(self):
        samdb = self.get_samdb()

        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       ntlm=True)

        # Create an authentication policy that applies to a computer and
        # explicitly allows the user account to obtain a service ticket.
        allowed = f'O:SYD:(A;;CR;;;{client_creds.get_sid()})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=allowed,
                                          service_allowed_to=denied)

        # Create a schema class derived from ‘computer’.
        class_id = random.randint(0, 100000000)
        computer_class_cn = f'my-Computer-Class-{class_id}'
        computer_class = computer_class_cn.replace('-', '')
        class_dn = samdb.get_schema_basedn()
        class_dn.add_child(f'CN={computer_class_cn}')
        governs_id = f'1.3.6.1.4.1.7165.4.6.2.9.{class_id}'

        samdb.add({
            'dn': class_dn,
            'objectClass': 'classSchema',
            'subClassOf': 'computer',
            'governsId': governs_id,
            'lDAPDisplayName': computer_class,
        })

        # Create an account derived from ‘computer’ with the assigned policy.
        target_name = self.get_new_username()
        target_creds, target_dn = self.create_account(
            samdb, target_name,
            account_type=self.AccountType.COMPUTER,
            spn=f'host/{target_name}',
            additional_details={
                'msDS-AssignedAuthNPolicy': str(policy),
                'objectClass': computer_class,
            })

        keys = self.get_keys(target_creds)
        self.creds_set_keys(target_creds, keys)

        # Show that a network SamLogon succeeds.
        self._test_samlogon(creds=client_creds,
                            domain_joined_mach_creds=target_creds,
                            logon_type=netlogon.NetlogonNetworkInformation)

        # Show that an interactive SamLogon succeeds.
        self._test_samlogon(creds=client_creds,
                            domain_joined_mach_creds=target_creds,
                            logon_type=netlogon.NetlogonInteractiveInformation)

    def test_samlogon_allowed_to_service_derived_class_allow(self):
        samdb = self.get_samdb()

        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       ntlm=True)

        # Create an authentication policy that applies to a managed service and
        # explicitly allows the user account to obtain a service ticket.
        allowed = f'O:SYD:(A;;CR;;;{client_creds.get_sid()})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy_id = self.get_new_username()
        policy = self.create_authn_policy(policy_id,
                                          enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=denied,
                                          service_allowed_to=allowed)

        # Create a schema class derived from ‘msDS-ManagedServiceAccount’.
        class_id = random.randint(0, 100000000)
        service_class_cn = f'my-Managed-Service-Class-{class_id}'
        service_class = service_class_cn.replace('-', '')
        class_dn = samdb.get_schema_basedn()
        class_dn.add_child(f'CN={service_class_cn}')
        governs_id = f'1.3.6.1.4.1.7165.4.6.2.9.{class_id}'

        samdb.add({
            'dn': class_dn,
            'objectClass': 'classSchema',
            'subClassOf': 'msDS-ManagedServiceAccount',
            'governsId': governs_id,
            'lDAPDisplayName': service_class,
        })

        # Create an account derived from ‘msDS-ManagedServiceAccount’ with the
        # assigned policy.
        target_name = self.get_new_username()
        target_creds, target_dn = self.create_account(
            samdb, target_name,
            account_type=self.AccountType.MANAGED_SERVICE,
            spn=f'host/{target_name}',
            additional_details={
                'msDS-AssignedAuthNPolicy': str(policy),
                'objectClass': service_class,
            })

        # Show that a network SamLogon succeeds.
        self._test_samlogon(creds=client_creds,
                            domain_joined_mach_creds=target_creds,
                            logon_type=netlogon.NetlogonNetworkInformation)

        # Show that an interactive SamLogon succeeds.
        self._test_samlogon(creds=client_creds,
                            domain_joined_mach_creds=target_creds,
                            logon_type=netlogon.NetlogonInteractiveInformation)

    def check_ticket_times(self,
                           ticket_creds,
                           expected_life=None,
                           expected_renew_life=None):
        ticket = ticket_creds.ticket_private

        authtime = ticket['authtime']
        starttime = ticket.get('starttime', authtime)
        endtime = ticket['endtime']
        renew_till = ticket.get('renew-till', None)

        starttime = self.get_EpochFromKerberosTime(starttime)

        if expected_life is not None:
            actual_end = self.get_EpochFromKerberosTime(
                endtime.decode('ascii'))
            actual_lifetime = actual_end - starttime

            self.assertEqual(expected_life, actual_lifetime)

        if renew_till is None:
            self.assertIsNone(expected_renew_life)
        else:
            if expected_renew_life is not None:
                actual_renew_till = self.get_EpochFromKerberosTime(
                    renew_till.decode('ascii'))
                actual_renew_life = actual_renew_till - starttime

                self.assertEqual(expected_renew_life, actual_renew_life)

    def _get_tgt(self, creds, *,
                 armor_tgt=None,
                 till=None,
                 expected_error=0,
                 expect_status=None,
                 expected_status=None):
        user_name = creds.get_username()
        realm = creds.get_realm()
        salt = creds.get_salt()

        cname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                          names=user_name.split('/'))
        sname = self.PrincipalName_create(name_type=NT_SRV_INST,
                                          names=['krbtgt', realm])
        expected_sname = self.PrincipalName_create(
            name_type=NT_SRV_INST, names=['krbtgt', realm.upper()])

        expected_cname = cname

        if till is None:
            till = self.get_KerberosTime(offset=36000)

        renew_time = till

        krbtgt_creds = self.get_krbtgt_creds()
        ticket_decryption_key = (
            self.TicketDecryptionKey_from_creds(krbtgt_creds))

        expected_etypes = krbtgt_creds.tgs_supported_enctypes

        kdc_options = str(krb5_asn1.KDCOptions('renewable'))
        # Contrary to Microsoft’s documentation, the returned ticket is
        # renewable.
        expected_flags = krb5_asn1.TicketFlags('renewable')

        preauth_key = self.PasswordKey_from_creds(creds,
                                                  kcrypto.Enctype.AES256)

        expected_realm = realm.upper()

        etypes = kcrypto.Enctype.AES256, kcrypto.Enctype.RC4

        if armor_tgt is not None:
            authenticator_subkey = self.RandomKey(kcrypto.Enctype.AES256)
            armor_key = self.generate_armor_key(authenticator_subkey,
                                                armor_tgt.session_key)
            armor_subkey = authenticator_subkey

            client_challenge_key = self.generate_client_challenge_key(
                armor_key, preauth_key)
            enc_challenge_padata = self.get_challenge_pa_data(
                client_challenge_key)

            def generate_fast_padata_fn(kdc_exchange_dict,
                                        _callback_dict,
                                        req_body):
                return [enc_challenge_padata], req_body

            generate_fast_fn = self.generate_simple_fast
            generate_fast_armor_fn = self.generate_ap_req
            generate_padata_fn = None

            fast_armor_type = FX_FAST_ARMOR_AP_REQUEST
        else:
            ts_enc_padata = self.get_enc_timestamp_pa_data_from_key(
                preauth_key)

            def generate_padata_fn(kdc_exchange_dict,
                                   _callback_dict,
                                   req_body):
                return [ts_enc_padata], req_body

            generate_fast_fn = None
            generate_fast_padata_fn = None
            generate_fast_armor_fn = None

            armor_key = None
            armor_subkey = None

            fast_armor_type = None

        if not expected_error:
            check_error_fn = None
            check_rep_fn = self.generic_check_kdc_rep
        else:
            check_error_fn = self.generic_check_kdc_error
            check_rep_fn = None

        kdc_exchange_dict = self.as_exchange_dict(
            creds=creds,
            expected_error_mode=expected_error,
            expect_status=expect_status,
            expected_status=expected_status,
            expected_crealm=expected_realm,
            expected_cname=expected_cname,
            expected_srealm=expected_realm,
            expected_sname=expected_sname,
            expected_salt=salt,
            expected_flags=expected_flags,
            expected_supported_etypes=expected_etypes,
            generate_padata_fn=generate_padata_fn,
            generate_fast_padata_fn=generate_fast_padata_fn,
            generate_fast_fn=generate_fast_fn,
            generate_fast_armor_fn=generate_fast_armor_fn,
            fast_armor_type=fast_armor_type,
            check_error_fn=check_error_fn,
            check_rep_fn=check_rep_fn,
            check_kdc_private_fn=self.generic_check_kdc_private,
            armor_key=armor_key,
            armor_tgt=armor_tgt,
            armor_subkey=armor_subkey,
            kdc_options=kdc_options,
            preauth_key=preauth_key,
            ticket_decryption_key=ticket_decryption_key,
            # PA-DATA types are not important for these tests.
            check_patypes=False)

        rep = self._generic_kdc_exchange(kdc_exchange_dict,
                                         cname=cname,
                                         realm=realm,
                                         sname=sname,
                                         till_time=till,
                                         renew_time=renew_time,
                                         etypes=etypes)
        if expected_error:
            self.check_error_rep(rep, expected_error)

            return None

        self.check_as_reply(rep)

        ticket_creds = kdc_exchange_dict['rep_ticket_creds']
        return ticket_creds


if __name__ == '__main__':
    global_asn1_print = False
    global_hexdump = False
    import unittest
    unittest.main()
