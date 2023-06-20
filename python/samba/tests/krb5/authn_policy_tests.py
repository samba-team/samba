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

from datetime import datetime
from enum import Enum
import random
import re

import ldb

from samba import dsdb, ntstatus
from samba.dcerpc import netlogon, security
from samba.dcerpc import windows_event_ids as win_event
from samba.ndr import ndr_pack
from samba.netcmd.domain.models import AuthenticationPolicy, AuthenticationSilo

import samba.tests
import samba.tests.krb5.kcrypto as kcrypto
from samba.tests.krb5.kdc_base_test import GroupType
from samba.tests.krb5.kdc_tgs_tests import KdcTgsBaseTests
from samba.tests.auth_log_base import AuthLogTestBase, NoMessageException
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


AUTHN_VERSION = {'major': 1, 'minor': 3}
AUTHZ_VERSION = {'major': 1, 'minor': 2}
KDC_AUTHZ_VERSION = {'major': 1, 'minor': 0}


class AuditType(Enum):
    AUTHN = 'Authentication'
    AUTHZ = 'Authorization'
    KDC_AUTHZ = 'KDC Authorization'


class AuditEvent(Enum):
    OK = 'OK'
    KERBEROS_DEVICE_RESTRICTION = 'KERBEROS_DEVICE_RESTRICTION'
    KERBEROS_SERVER_RESTRICTION = 'KERBEROS_SERVER_RESTRICTION'
    NTLM_DEVICE_RESTRICTION = 'NTLM_DEVICE_RESTRICTION'
    NTLM_SERVER_RESTRICTION = 'NTLM_SERVER_RESTRICTION'
    OTHER_ERROR = 'OTHER_ERROR'


class AuditReason(Enum):
    NONE = None
    DESCRIPTOR_INVALID = 'DESCRIPTOR_INVALID'
    DESCRIPTOR_NO_OWNER = 'DESCRIPTOR_NO_OWNER'
    SECURITY_TOKEN_FAILURE = 'SECURITY_TOKEN_FAILURE'
    ACCESS_DENIED = 'ACCESS_DENIED'
    FAST_REQUIRED = 'FAST_REQUIRED'


# This decorator helps reduce boilerplate code in log-checking methods.
def policy_check_fn(fn):
    def wrapper_fn(self, client_creds, *,
                   client_policy=None,
                   client_policy_status=None,
                   server_policy=None,
                   server_policy_status=None,
                   status=None,
                   event=AuditEvent.OK,
                   reason=AuditReason.NONE,
                   **kwargs):
        if client_policy_status is not None:
            self.assertIsNotNone(client_policy,
                                 'specified client policy status without '
                                 'client policy')

            self.assertIsNone(
                server_policy_status,
                'don’t specify both client policy status and server policy '
                'status (at most one of which can appear in the logs)')
        elif server_policy_status is not None:
            self.assertIsNotNone(server_policy,
                                 'specified server policy status without '
                                 'server policy')
        elif client_policy is not None and server_policy is not None:
            self.assertIsNone(status,
                              'ambiguous: specify a client policy status or a '
                              'server policy status')

        overall_status = status
        if overall_status is None:
            overall_status = ntstatus.NT_STATUS_OK

        if client_policy_status is None:
            client_policy_status = ntstatus.NT_STATUS_OK
        elif status is None and client_policy.enforced:
            overall_status = client_policy_status

        if server_policy_status is None:
            server_policy_status = ntstatus.NT_STATUS_OK
        elif status is None and server_policy.enforced:
            overall_status = server_policy_status

        if client_policy_status:
            client_policy_event = event
            client_policy_reason = reason
        else:
            client_policy_event = AuditEvent.OK
            client_policy_reason = AuditReason.NONE

        if server_policy_status:
            server_policy_event = event
            server_policy_reason = reason
        else:
            server_policy_event = AuditEvent.OK
            server_policy_reason = AuditReason.NONE

        return fn(self, client_creds,
                  client_policy=client_policy,
                  client_policy_status=client_policy_status,
                  client_policy_event=client_policy_event,
                  client_policy_reason=client_policy_reason,
                  server_policy=server_policy,
                  server_policy_status=server_policy_status,
                  server_policy_event=server_policy_event,
                  server_policy_reason=server_policy_reason,
                  overall_status=overall_status,
                  **kwargs)

    return wrapper_fn


class AuthnPolicyTests(AuthLogTestBase, KdcTgsBaseTests):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        as_req_logging_support = samba.tests.env_get_var_value(
            'AS_REQ_LOGGING_SUPPORT',
            allow_missing=False)
        cls.as_req_logging_support = bool(int(as_req_logging_support))

        tgs_req_logging_support = samba.tests.env_get_var_value(
            'TGS_REQ_LOGGING_SUPPORT',
            allow_missing=False)
        cls.tgs_req_logging_support = bool(int(tgs_req_logging_support))

        cls._max_ticket_life = None
        cls._max_renew_life = None

    def setUp(self):
        super().setUp()
        self.do_asn1_print = global_asn1_print
        self.do_hexdump = global_hexdump

    def take(self, n, iterable, *, take_all=True):
        """Yield n items from an iterable."""
        i = -1
        for i in range(n):
            try:
                yield next(iterable)
            except StopIteration:
                self.fail(f'expected to find element{i}')

        if take_all:
            with self.assertRaises(
                    StopIteration,
                    msg=f'got unexpected element after {i+1} elements'):
                next(iterable)

    def take_pairs(self, n, iterable, *, take_all=True):
        """Yield n pairs of items from an iterable."""
        i = -1
        for i in range(n):
            try:
                yield next(iterable), next(iterable)
            except StopIteration:
                self.fail(f'expected to find pair of elements {i}')

        if take_all:
            with self.assertRaises(
                    StopIteration,
                    msg=f'got unexpected element after {i+1} pairs'):
                next(iterable)

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
            opts['assigned_policy'] = str(assigned_policy.dn)
            cached = False   # Policies are rarely reused between accounts.
        if assigned_silo is not None:
            opts['assigned_silo'] = str(assigned_silo.dn)
            cached = False   # Silos are rarely reused between accounts.
        if allowed_rodc:
            opts['allowed_replication_mock'] = True
            opts['revealed_to_mock_rodc'] = True

        if members:
            opts['member_of'] = members

        return self.get_cached_creds(account_type=account_type,
                                     opts=opts,
                                     use_cache=cached)

    @staticmethod
    def audit_type(msg):
        return AuditType(msg['type'])

    @staticmethod
    def auth_type(msg):
        audit_type = __class__.audit_type(msg)
        key = {
            AuditType.AUTHN: 'authDescription',
            AuditType.AUTHZ: 'authType',
            AuditType.KDC_AUTHZ: 'authType',
        }[audit_type]

        return msg[audit_type.value][key]

    @staticmethod
    def service_description(msg):
        audit_type = __class__.audit_type(msg)
        return msg[audit_type.value]['serviceDescription']

    @staticmethod
    def client_account(msg):
        audit_type = __class__.audit_type(msg)

        key = {
            AuditType.AUTHN: 'clientAccount',
            AuditType.AUTHZ: 'account',
            AuditType.KDC_AUTHZ: 'account',
        }[audit_type]

        return msg[audit_type.value][key]

    def filter_msg(self, audit_type, client_name, *,
                   auth_type=None,
                   service_description=None):
        def _filter_msg(msg):
            if audit_type is not self.audit_type(msg):
                return False

            if auth_type is not None:
                if isinstance(auth_type, re.Pattern):
                    # Check whether the pattern matches.
                    if not auth_type.fullmatch(self.auth_type(msg)):
                        return False
                else:
                    # Just do a standard equality check.
                    if auth_type != self.auth_type(msg):
                        return False

            if service_description is not None:
                if service_description != self.service_description(msg):
                    return False

            return client_name == self.client_account(msg)

        return _filter_msg

    PRE_AUTH_RE = re.compile('.* Pre-authentication')

    def as_req_filter(self, client_creds):
        username = client_creds.get_username()
        realm = client_creds.get_realm()
        client_name = f'{username}@{realm}'

        yield self.filter_msg(AuditType.AUTHN,
                              client_name,
                              auth_type=self.PRE_AUTH_RE,
                              service_description='Kerberos KDC')

    def tgs_req_filter(self, client_creds, target_creds):
        target_name = target_creds.get_username()
        if target_name[-1] == '$':
            target_name = target_name[:-1]
        target_realm = target_creds.get_realm()

        target_spn = f'host/{target_name}@{target_realm}'

        yield self.filter_msg(AuditType.KDC_AUTHZ,
                              client_creds.get_username(),
                              auth_type='TGS-REQ with Ticket-Granting Ticket',
                              service_description=target_spn)

    def samlogon_filter(self, client_creds, *, logon_type=None):
        if logon_type is None:
            auth_type = None
        elif logon_type == netlogon.NetlogonNetworkInformation:
            auth_type = 'network'
        elif logon_type == netlogon.NetlogonInteractiveInformation:
            auth_type = 'interactive'
        else:
            self.fail(f'unknown logon type ‘{logon_type}’')

        yield self.filter_msg(AuditType.AUTHN,
                              client_creds.get_username(),
                              auth_type=auth_type,
                              service_description='SamLogon')

    def ntlm_filter(self, client_creds):
        username = client_creds.get_username()

        yield self.filter_msg(AuditType.AUTHN,
                              username,
                              auth_type='NTLMSSP',
                              service_description='LDAP')

        yield self.filter_msg(AuditType.AUTHZ,
                              username,
                              auth_type='NTLMSSP',
                              service_description='LDAP')

    def simple_bind_filter(self, client_creds):
        yield self.filter_msg(AuditType.AUTHN,
                              str(client_creds.get_dn()),
                              auth_type='simple bind/TLS',
                              service_description='LDAP')

        yield self.filter_msg(AuditType.AUTHZ,
                              client_creds.get_username(),
                              auth_type='simple bind',
                              service_description='LDAP')

    def samr_pwd_change_filter(self, client_creds):
        username = client_creds.get_username()

        yield self.filter_msg(AuditType.AUTHN,
                              username,
                              auth_type='NTLMSSP',
                              service_description='SMB2')

        yield self.filter_msg(AuditType.AUTHZ,
                              username,
                              auth_type='NTLMSSP',
                              service_description='SMB2')

        yield self.filter_msg(AuditType.AUTHN,
                              username,
                              auth_type='NTLMSSP',
                              service_description='DCE/RPC')

        yield self.filter_msg(AuditType.AUTHZ,
                              username,
                              auth_type='NTLMSSP',
                              service_description='DCE/RPC')

        # Password changes are attempted twice, with two different methods.

        yield self.filter_msg(AuditType.AUTHN,
                              username,
                              auth_type='samr_ChangePasswordUser2',
                              service_description='SAMR Password Change')

        yield self.filter_msg(AuditType.AUTHN,
                              username,
                              auth_type='samr_ChangePasswordUser3',
                              service_description='SAMR Password Change')

    def nextMessage(self, *args, **kwargs):
        """Return the next relevant message, or throw a NoMessageException."""
        msg = super().nextMessage(*args, **kwargs)
        self.assert_is_timestamp(msg.pop('timestamp'))

        msg_type = msg.pop('type')
        inner = msg.pop(msg_type)
        self.assertFalse(msg, 'unexpected items in outer message')

        return inner

    def assert_is_timestamp(self, ts):
        try:
            datetime.strptime(ts, '%Y-%m-%dT%H:%M:%S.%f%z')
        except (TypeError, ValueError):
            self.fail(f'‘{ts}’ is not a timestamp')

    def assert_is_guid(self, guid):
        guid_re = (
            '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
        self.assertRegex(guid, guid_re)

    def assert_tgt_lifetime(self, checked_creds, policy, expected_policy):
        if checked_creds is None:
            self.assertNotIn('tgtLifetime', policy)
            return

        account_type = checked_creds.get_type()
        if account_type is self.AccountType.USER:
            expected = expected_policy.user_tgt_lifetime
        elif account_type is self.AccountType.COMPUTER:
            expected = expected_policy.computer_tgt_lifetime
        elif account_type is self.AccountType.MANAGED_SERVICE:
            expected = expected_policy.service_tgt_lifetime
        else:
            self.fail(f'unknown account type {account_type}')

        if expected is not None:
            expected /= 60 * 10_000_000
            expected = int(expected)
        else:
            expected = 0

        self.assertEqual(policy.pop('tgtLifetime'), expected)

    def assert_event_id(self, audit_event, policy, expected_policy):
        event_map = {
            AuditEvent.KERBEROS_DEVICE_RESTRICTION: (
                # unenforced
                win_event.AUTH_EVT_ID_KERBEROS_DEVICE_RESTRICTION_AUDIT,
                # enforced
                win_event.AUTH_EVT_ID_KERBEROS_DEVICE_RESTRICTION,
            ),
            AuditEvent.KERBEROS_SERVER_RESTRICTION: (
                # unenforced
                win_event.AUTH_EVT_ID_KERBEROS_SERVER_RESTRICTION_AUDIT,
                # enforced
                win_event.AUTH_EVT_ID_KERBEROS_SERVER_RESTRICTION,
            ),
            AuditEvent.NTLM_DEVICE_RESTRICTION: (
                win_event.AUTH_EVT_ID_NONE,  # unenforced
                win_event.AUTH_EVT_ID_NTLM_DEVICE_RESTRICTION,  # enforced
            ),
        }

        event_ids = event_map.get(audit_event)
        if event_ids is not None:
            expected_id = event_ids[expected_policy.enforced]
        else:
            expected_id = win_event.AUTH_EVT_ID_NONE

        self.assertEqual(expected_id, policy.pop('eventId'))

    def check_policy(self, checked_creds, policy, expected_policy, *,
                     client_creds=None,
                     expected_silo=None,
                     policy_status=ntstatus.NT_STATUS_OK,
                     audit_event=AuditEvent.OK,
                     reason=AuditReason.NONE):
        if expected_policy is None:
            self.assertIsNone(policy, 'got unexpected policy')
            self.assertIs(ntstatus.NT_STATUS_OK, policy_status)
            self.assertIs(AuditEvent.OK, audit_event)
            self.assertIs(AuditReason.NONE, reason)
            return

        self.assertIsNotNone(policy, 'expected to get a policy')

        policy.pop('location')  # A location in the source code, for debugging.

        if checked_creds is not None:
            checked_account = checked_creds.get_username()
            checked_domain = checked_creds.get_domain()
            checked_sid = checked_creds.get_sid()

            self.assertEqual(checked_account, policy.pop('checkedAccount'))
            self.assertRegex(policy.pop('checkedAccountFlags'), '^0x[0-9a-f]{8}$')
            self.assertEqual(checked_domain, policy.pop('checkedDomain'))
            self.assertEqual(checked_sid, policy.pop('checkedSid'))

            logon_server = os.environ['DC_NETBIOSNAME']
            self.assertEqual(logon_server, policy.pop('checkedLogonServer'))
        else:
            self.assertNotIn('checkedAccount', policy)
            self.assertNotIn('checkedAccountFlags', policy)
            self.assertNotIn('checkedDomain', policy)
            self.assertNotIn('checkedSid', policy)
            self.assertNotIn('checkedLogonServer', policy)

        self.assertEqual(expected_policy.enforced,
                         policy.pop('policyEnforced'))
        self.assertEqual(expected_policy.name, policy.pop('policyName'))

        self.assert_tgt_lifetime(client_creds, policy, expected_policy)

        silo_name = expected_silo.name if expected_silo is not None else None
        self.assertEqual(silo_name, policy.pop('siloName'))

        got_status = getattr(ntstatus, policy.pop('status'))
        self.assertEqual(policy_status, got_status)

        got_audit_event = policy.pop('auditEvent')
        try:
            got_audit_event = AuditEvent(got_audit_event)
        except ValueError:
            self.fail('got unrecognized audit event')
        self.assertEqual(audit_event, got_audit_event)
        self.assert_event_id(audit_event, policy, expected_policy)

        got_reason = policy.pop('reason')
        try:
            got_reason = AuditReason(got_reason)
        except ValueError:
            self.fail('got unrecognized audit reason')
        self.assertEqual(reason, got_reason)

        self.assertFalse(policy, 'unexpected items remain in policy')

    @policy_check_fn
    def check_as_log(self, client_creds, *,
                     client_policy,
                     client_policy_status,
                     client_policy_event,
                     client_policy_reason,
                     server_policy,
                     server_policy_status,
                     server_policy_event,
                     server_policy_reason,
                     overall_status,
                     armor_creds=None):
        if not self.as_req_logging_support:
            return

        as_req_filter = self.as_req_filter(client_creds)
        for msg_filter in self.take(1, as_req_filter):
            try:
                msg = self.nextMessage(msg_filter)
            except NoMessageException:
                self.fail('expected to receive authentication message')

            self.assertEqual(AUTHN_VERSION, msg.pop('version'))

            got_status = getattr(ntstatus, msg.pop('status'))
            self.assertEqual(overall_status, got_status)

            got_client_policy = msg.pop('clientPolicyAccessCheck', None)
            self.check_policy(armor_creds, got_client_policy, client_policy,
                              client_creds=client_creds,
                              policy_status=client_policy_status,
                              audit_event=client_policy_event,
                              reason=client_policy_reason)

            got_server_policy = msg.pop('serverPolicyAccessCheck', None)
            self.check_policy(client_creds, got_server_policy, server_policy,
                              policy_status=server_policy_status,
                              audit_event=server_policy_event,
                              reason=server_policy_reason)

    def check_tgs_log(self, client_creds, target_creds, *,
                      policy=None,
                      policy_status=None,
                      status=None,
                      checked_creds=None,
                      event=AuditEvent.OK,
                      reason=AuditReason.NONE):
        if not self.tgs_req_logging_support:
            return

        if checked_creds is None:
            checked_creds = client_creds

        overall_status = status if status is not None else ntstatus.NT_STATUS_OK

        if policy_status is None:
            policy_status = ntstatus.NT_STATUS_OK

            if policy is not None:
                policy_status = overall_status
        elif status is None and policy.enforced:
            overall_status = status

        client_domain = client_creds.get_domain()

        logon_server = os.environ['DC_NETBIOSNAME']

        # An example of a typical KDC Authorization log message:

        # {
        #     "KDC Authorization": {
        #         "account": "alice",
        #         "authTime": "2023-06-15T23:45:13.183564+0000",
        #         "authType": "TGS-REQ with Ticket-Granting Ticket",
        #         "domain": "ADDOMAIN",
        #         "localAddress": null,
        #         "logonServer": "ADDC",
        #         "remoteAddress": "ipv4:10.53.57.11:28004",
        #         "serverPolicyAccessCheck": {
        #             "auditEvent": "KERBEROS_SERVER_RESTRICTION",
        #             "checkedAccount": "alice",
        #             "checkedAccountFlags": "0x00000010",
        #             "checkedDomain": "ADDOMAIN",
        #             "checkedLogonServer": "ADDC",
        #             "checkedSid": "S-1-5-21-3907522332-2561495341-3138977981-1159",
        #             "eventId": 106,
        #             "location": "../../source4/kdc/authn_policy_util.c:1181",
        #             "policyEnforced": true,
        #             "policyName": "Example Policy",
        #             "reason": "ACCESS_DENIED",
        #             "siloName": null,
        #             "status": "NT_STATUS_AUTHENTICATION_FIREWALL_FAILED"
        #         },
        #         "serviceDescription": "host/target@ADDOM.SAMBA.EXAMPLE.COM",
        #         "sid": "S-1-5-21-3907522332-2561495341-3138977981-1159",
        #         "status": "NT_STATUS_AUTHENTICATION_FIREWALL_FAILED",
        #         "version": {
        #             "major": 1,
        #             "minor": 0
        #         }
        #     },
        #     "timestamp": "2023-06-15T23:45:13.202312+0000",
        #     "type": "KDC Authorization"
        # }

        tgs_req_filter = self.tgs_req_filter(client_creds, target_creds)
        for msg_filter in self.take(1, tgs_req_filter):
            try:
                msg = self.nextMessage(msg_filter)
            except NoMessageException:
                self.fail('expected to receive KDC authorization message')

            # These parameters have already been checked.
            msg.pop('account')
            msg.pop('authType')
            msg.pop('remoteAddress')
            msg.pop('serviceDescription')

            self.assertEqual(KDC_AUTHZ_VERSION, msg.pop('version'))

            self.assert_is_timestamp(msg.pop('authTime'))
            self.assertEqual(client_domain, msg.pop('domain'))
            self.assertIsNone(msg.pop('localAddress'))
            self.assertEqual(logon_server, msg.pop('logonServer'))
            self.assertEqual(client_creds.get_sid(), msg.pop('sid'))

            got_status = getattr(ntstatus, msg.pop('status'))
            self.assertEqual(overall_status, got_status)

            server_policy = msg.pop('serverPolicyAccessCheck', None)
            self.check_policy(checked_creds, server_policy, policy,
                              policy_status=policy_status,
                              audit_event=event,
                              reason=reason)

            self.assertFalse(msg, 'unexpected items remain in message')

    @policy_check_fn
    def check_samlogon_log(self, client_creds, *,
                           client_policy,
                           client_policy_status,
                           client_policy_event,
                           client_policy_reason,
                           server_policy,
                           server_policy_status,
                           server_policy_event,
                           server_policy_reason,
                           overall_status,
                           logon_type=None):
        samlogon_filter = self.samlogon_filter(client_creds,
                                               logon_type=logon_type)
        for msg_filter in self.take(1, samlogon_filter):
            try:
                msg = self.nextMessage(msg_filter)
            except NoMessageException:
                self.fail('expected to receive authentication message')

            self.assertEqual(AUTHN_VERSION, msg.pop('version'))

            got_status = getattr(ntstatus, msg.pop('status'))
            self.assertEqual(overall_status, got_status)

            got_client_policy = msg.pop('clientPolicyAccessCheck', None)
            self.check_policy(None, got_client_policy, client_policy,
                              policy_status=client_policy_status,
                              audit_event=client_policy_event,
                              reason=client_policy_reason)

            got_server_policy = msg.pop('serverPolicyAccessCheck', None)
            self.check_policy(client_creds, got_server_policy, server_policy,
                              policy_status=server_policy_status,
                              audit_event=server_policy_event,
                              reason=server_policy_reason)

    def check_samlogon_network_log(self, client_creds, **kwargs):
        return self.check_samlogon_log(
            client_creds,
            logon_type=netlogon.NetlogonNetworkInformation,
            **kwargs)

    def check_samlogon_interactive_log(self, client_creds, **kwargs):
        return self.check_samlogon_log(
            client_creds,
            logon_type=netlogon.NetlogonInteractiveInformation,
            **kwargs)

    @policy_check_fn
    def check_ntlm_log(self, client_creds, *,
                       client_policy,
                       client_policy_status,
                       client_policy_event,
                       client_policy_reason,
                       server_policy,
                       server_policy_status,
                       server_policy_event,
                       server_policy_reason,
                       overall_status):
        ntlm_filter = self.ntlm_filter(client_creds)

        for authn_filter, authz_filter in self.take_pairs(1, ntlm_filter):
            try:
                msg = self.nextMessage(authn_filter)
            except NoMessageException:
                self.fail('expected to receive authentication message')

            self.assertEqual(AUTHN_VERSION, msg.pop('version'))

            got_status = getattr(ntstatus, msg.pop('status'))
            self.assertEqual(overall_status, got_status)

            got_client_policy = msg.pop('clientPolicyAccessCheck', None)
            self.check_policy(None, got_client_policy, client_policy,
                              policy_status=client_policy_status,
                              audit_event=client_policy_event,
                              reason=client_policy_reason)

            got_server_policy = msg.pop('serverPolicyAccessCheck', None)
            self.check_policy(client_creds, got_server_policy, server_policy,
                              policy_status=server_policy_status,
                              audit_event=server_policy_event,
                              reason=server_policy_reason)

            if overall_status:
                # Authentication can proceed no further.
                return

            try:
                msg = self.nextMessage(authz_filter)
            except NoMessageException:
                self.fail('expected to receive authorization message')

            self.assertEqual(AUTHZ_VERSION, msg.pop('version'))

            got_server_policy = msg.pop('serverPolicyAccessCheck', None)
            self.check_policy(client_creds, got_server_policy, server_policy)

    @policy_check_fn
    def check_simple_bind_log(self, client_creds, *,
                              client_policy,
                              client_policy_status,
                              client_policy_event,
                              client_policy_reason,
                              server_policy,
                              server_policy_status,
                              server_policy_event,
                              server_policy_reason,
                              overall_status):
        simple_bind_filter = self.simple_bind_filter(client_creds)

        for authn_filter, authz_filter in self.take_pairs(1,
                                                          simple_bind_filter):
            try:
                msg = self.nextMessage(authn_filter)
            except NoMessageException:
                self.fail('expected to receive authentication message')

            self.assertEqual(AUTHN_VERSION, msg.pop('version'))

            got_status = getattr(ntstatus, msg.pop('status'))
            self.assertEqual(overall_status, got_status)

            got_client_policy = msg.pop('clientPolicyAccessCheck', None)
            self.check_policy(None, got_client_policy, client_policy,
                              policy_status=client_policy_status,
                              audit_event=client_policy_event,
                              reason=client_policy_reason)

            got_server_policy = msg.pop('serverPolicyAccessCheck', None)
            self.check_policy(client_creds, got_server_policy, server_policy,
                              policy_status=server_policy_status,
                              audit_event=server_policy_event,
                              reason=server_policy_reason)

            if overall_status:
                # Authentication can proceed no further.
                return

            try:
                msg = self.nextMessage(authz_filter)
            except NoMessageException:
                self.fail('expected to receive authorization message')

            self.assertEqual(AUTHZ_VERSION, msg.pop('version'))

            got_server_policy = msg.pop('serverPolicyAccessCheck', None)
            self.check_policy(client_creds, got_server_policy, server_policy,
                              policy_status=server_policy_status,
                              audit_event=server_policy_event,
                              reason=server_policy_reason)

    @policy_check_fn
    def check_samr_pwd_change_log(self, client_creds, *,
                                  client_policy,
                                  client_policy_status,
                                  client_policy_event,
                                  client_policy_reason,
                                  server_policy,
                                  server_policy_status,
                                  server_policy_event,
                                  server_policy_reason,
                                  overall_status):
        pwd_change_filter = self.samr_pwd_change_filter(client_creds)

        # There will be two authorization attempts.
        for authn_filter, authz_filter in self.take_pairs(2,
                                                          pwd_change_filter,
                                                          take_all=False):
            try:
                msg = self.nextMessage(authn_filter)
            except NoMessageException:
                self.fail('expected to receive authentication message')

            self.assertEqual(AUTHN_VERSION, msg.pop('version'))

            got_status = getattr(ntstatus, msg.pop('status'))
            self.assertEqual(overall_status, got_status)

            got_client_policy = msg.pop('clientPolicyAccessCheck', None)
            self.check_policy(None, got_client_policy, client_policy,
                              policy_status=client_policy_status,
                              audit_event=client_policy_event,
                              reason=client_policy_reason)

            got_server_policy = msg.pop('serverPolicyAccessCheck', None)
            self.check_policy(client_creds, got_server_policy, server_policy,
                              policy_status=server_policy_status,
                              audit_event=server_policy_event,
                              reason=server_policy_reason)

            if overall_status:
                # Authentication can proceed no further.
                return

            try:
                msg = self.nextMessage(authz_filter)
            except NoMessageException:
                self.fail('expected to receive authorization message')

            self.assertEqual(AUTHZ_VERSION, msg.pop('version'))

            got_server_policy = msg.pop('serverPolicyAccessCheck', None)
            self.check_policy(client_creds, got_server_policy, server_policy,
                              policy_status=server_policy_status,
                              audit_event=server_policy_event,
                              reason=server_policy_reason)

        # There will be two SAMR password change attempts.
        for msg_filter in self.take(2, pwd_change_filter):
            try:
                msg = self.nextMessage(msg_filter)
            except NoMessageException:
                self.fail('expected to receive SAMR password change message')

            self.assertEqual(AUTHN_VERSION, msg.pop('version'))

            got_status = getattr(ntstatus, msg.pop('status'))
            self.assertEqual(ntstatus.NT_STATUS_OK, got_status)

            got_client_policy = msg.pop('clientPolicyAccessCheck', None)
            self.check_policy(None, got_client_policy, None,
                              policy_status=client_policy_status,
                              audit_event=client_policy_event,
                              reason=client_policy_reason)

            got_server_policy = msg.pop('serverPolicyAccessCheck', None)
            self.check_policy(client_creds, got_server_policy, None,
                              policy_status=server_policy_status,
                              audit_event=server_policy_event,
                              reason=server_policy_reason)

    def test_authn_policy_tgt_lifetime_user(self):
        # Create an authentication policy with certain TGT lifetimes set.
        user_life = 111
        computer_life = 222
        service_life = 333
        policy = self.create_authn_policy(enforced=True,
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

        self.check_as_log(client_creds)

    def test_authn_policy_tgt_lifetime_computer(self):
        user_life = 111
        computer_life = 222
        service_life = 333
        policy = self.create_authn_policy(enforced=True,
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

        self.check_as_log(client_creds)

    def test_authn_policy_tgt_lifetime_service(self):
        user_life = 111
        computer_life = 222
        service_life = 333
        policy = self.create_authn_policy(enforced=True,
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

        self.check_as_log(client_creds)

    def test_authn_silo_tgt_lifetime_user(self):
        # Create an authentication policy with certain TGT lifetimes set.
        user_life = 111
        computer_life = 222
        service_life = 333
        policy = self.create_authn_policy(enforced=True,
                                          user_tgt_lifetime=user_life,
                                          computer_tgt_lifetime=computer_life,
                                          service_tgt_lifetime=service_life)

        # Create a second policy with different lifetimes, so we can verify the
        # correct policy is enforced.
        wrong_policy = self.create_authn_policy(enforced=True,
                                                user_tgt_lifetime=444,
                                                computer_tgt_lifetime=555,
                                                service_tgt_lifetime=666)

        # Create an authentication silo with our existing policies.
        silo = self.create_authn_silo(user_policy=policy,
                                      computer_policy=wrong_policy,
                                      service_policy=wrong_policy,
                                      enforced=True)

        # Create a user account assigned to the silo.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_silo=silo)
        client_dn_str = str(client_creds.get_dn())

        # Add the user to the silo as a member.
        self.add_to_group(client_dn_str, silo.dn,
                          'msDS-AuthNPolicySiloMembers',
                          expect_attr=False)

        # Request a Kerberos ticket with a lifetime of two hours, and assert
        # that the actual lifetime matches the user lifetime set in the
        # appropriate policy.
        till = self.get_KerberosTime(offset=2 * 60 * 60)  # 2 hours
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=user_life,
                                expected_renew_life=user_life)

        self.check_as_log(client_creds)

    def test_authn_silo_tgt_lifetime_computer(self):
        user_life = 111
        computer_life = 222
        service_life = 333
        policy = self.create_authn_policy(enforced=True,
                                          user_tgt_lifetime=user_life,
                                          computer_tgt_lifetime=computer_life,
                                          service_tgt_lifetime=service_life)

        wrong_policy = self.create_authn_policy(enforced=True,
                                                user_tgt_lifetime=444,
                                                computer_tgt_lifetime=555,
                                                service_tgt_lifetime=666)

        # Create an authentication silo with our existing policies.
        silo = self.create_authn_silo(user_policy=wrong_policy,
                                      computer_policy=policy,
                                      service_policy=wrong_policy,
                                      enforced=True)

        # Create a computer account assigned to the silo.
        client_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_silo=silo)
        client_dn_str = str(client_creds.get_dn())

        # Add the computer to the silo as a member.
        self.add_to_group(client_dn_str, silo.dn,
                          'msDS-AuthNPolicySiloMembers',
                          expect_attr=False)

        # Request a Kerberos ticket with a lifetime of two hours, and assert
        # that the actual lifetime matches the computer lifetime set in the
        # appropriate policy.
        till = self.get_KerberosTime(offset=2 * 60 * 60)  # 2 hours
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=computer_life,
                                expected_renew_life=computer_life)

        self.check_as_log(client_creds)

    def test_authn_silo_tgt_lifetime_service(self):
        user_life = 111
        computer_life = 222
        service_life = 333
        policy = self.create_authn_policy(enforced=True,
                                          user_tgt_lifetime=user_life,
                                          computer_tgt_lifetime=computer_life,
                                          service_tgt_lifetime=service_life)

        wrong_policy = self.create_authn_policy(enforced=True,
                                                user_tgt_lifetime=444,
                                                computer_tgt_lifetime=555,
                                                service_tgt_lifetime=666)

        # Create an authentication silo with our existing policies.
        silo = self.create_authn_silo(user_policy=wrong_policy,
                                      computer_policy=wrong_policy,
                                      service_policy=policy,
                                      enforced=True)

        # Create a managed service account assigned to the silo.
        client_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
            assigned_silo=silo)
        client_dn_str = str(client_creds.get_dn())

        # Add the managed service account to the silo as a member.
        self.add_to_group(client_dn_str, silo.dn,
                          'msDS-AuthNPolicySiloMembers',
                          expect_attr=False)

        # Request a Kerberos ticket with a lifetime of two hours, and assert
        # that the actual lifetime matches the service lifetime set in the
        # appropriate policy.
        till = self.get_KerberosTime(offset=2 * 60 * 60)  # 2 hours
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=service_life,
                                expected_renew_life=service_life)

        self.check_as_log(client_creds)

    # Test that an authentication silo takes priority over a policy assigned
    # directly.
    def test_authn_silo_and_policy_tgt_lifetime_user(self):
        # Create an authentication policy with certain TGT lifetimes set.
        user_life = 111
        computer_life = 222
        service_life = 333
        policy = self.create_authn_policy(enforced=True,
                                          user_tgt_lifetime=user_life,
                                          computer_tgt_lifetime=computer_life,
                                          service_tgt_lifetime=service_life)

        # Create a second policy with different lifetimes, so we can verify the
        # correct policy is enforced.
        wrong_policy = self.create_authn_policy(enforced=True,
                                                user_tgt_lifetime=444,
                                                computer_tgt_lifetime=555,
                                                service_tgt_lifetime=666)

        # Create an authentication silo with our existing policies.
        silo = self.create_authn_silo(user_policy=policy,
                                      computer_policy=wrong_policy,
                                      service_policy=wrong_policy,
                                      enforced=True)

        # Create a user account assigned to the silo, and also to a policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_silo=silo,
                                       assigned_policy=wrong_policy)
        client_dn_str = str(client_creds.get_dn())

        # Add the user to the silo as a member.
        self.add_to_group(client_dn_str, silo.dn,
                          'msDS-AuthNPolicySiloMembers',
                          expect_attr=False)

        # Request a Kerberos ticket with a lifetime of two hours, and assert
        # that the actual lifetime matches the user lifetime set in the
        # appropriate policy.
        till = self.get_KerberosTime(offset=2 * 60 * 60)  # 2 hours
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=user_life,
                                expected_renew_life=user_life)

        self.check_as_log(client_creds)

    def test_authn_silo_and_policy_tgt_lifetime_computer(self):
        user_life = 111
        computer_life = 222
        service_life = 333
        policy = self.create_authn_policy(enforced=True,
                                          user_tgt_lifetime=user_life,
                                          computer_tgt_lifetime=computer_life,
                                          service_tgt_lifetime=service_life)

        wrong_policy = self.create_authn_policy(enforced=True,
                                                user_tgt_lifetime=444,
                                                computer_tgt_lifetime=555,
                                                service_tgt_lifetime=666)

        # Create an authentication silo with our existing policies.
        silo = self.create_authn_silo(user_policy=wrong_policy,
                                      computer_policy=policy,
                                      service_policy=wrong_policy,
                                      enforced=True)

        # Create a computer account assigned to the silo, and also to a policy.
        client_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_silo=silo,
                                       assigned_policy=wrong_policy)
        client_dn_str = str(client_creds.get_dn())

        # Add the computer to the silo as a member.
        self.add_to_group(client_dn_str, silo.dn,
                          'msDS-AuthNPolicySiloMembers',
                          expect_attr=False)

        # Request a Kerberos ticket with a lifetime of two hours, and assert
        # that the actual lifetime matches the computer lifetime set in the
        # appropriate policy.
        till = self.get_KerberosTime(offset=2 * 60 * 60)  # 2 hours
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=computer_life,
                                expected_renew_life=computer_life)

        self.check_as_log(client_creds)

    def test_authn_silo_and_policy_tgt_lifetime_service(self):
        user_life = 111
        computer_life = 222
        service_life = 333
        policy = self.create_authn_policy(enforced=True,
                                          user_tgt_lifetime=user_life,
                                          computer_tgt_lifetime=computer_life,
                                          service_tgt_lifetime=service_life)

        wrong_policy = self.create_authn_policy(enforced=True,
                                                user_tgt_lifetime=444,
                                                computer_tgt_lifetime=555,
                                                service_tgt_lifetime=666)

        # Create an authentication silo with our existing policies.
        silo = self.create_authn_silo(user_policy=wrong_policy,
                                      computer_policy=wrong_policy,
                                      service_policy=policy,
                                      enforced=True)

        # Create a managed service account assigned to the silo, and also to a
        # policy.
        client_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
            assigned_silo=silo,
            assigned_policy=wrong_policy)
        client_dn_str = str(client_creds.get_dn())

        # Add the managed service account to the silo as a member.
        self.add_to_group(client_dn_str, silo.dn,
                          'msDS-AuthNPolicySiloMembers',
                          expect_attr=False)

        # Request a Kerberos ticket with a lifetime of two hours, and assert
        # that the actual lifetime matches the service lifetime set in the
        # appropriate policy.
        till = self.get_KerberosTime(offset=2 * 60 * 60)  # 2 hours
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=service_life,
                                expected_renew_life=service_life)

        self.check_as_log(client_creds)

    def test_authn_policy_tgt_lifetime_max(self):
        # Create an authentication policy with the maximum allowable TGT
        # lifetime set.
        INT64_MAX = 0x7fff_ffff_ffff_ffff
        max_lifetime = INT64_MAX // 10_000_000
        policy = self.create_authn_policy(enforced=True,
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

        self.check_as_log(client_creds)

    def test_authn_policy_tgt_lifetime_min(self):
        # Create an authentication policy with the minimum allowable TGT
        # lifetime set.
        INT64_MIN = -0x8000_0000_0000_0000
        min_lifetime = round(INT64_MIN / 10_000_000)
        policy = self.create_authn_policy(enforced=True,
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

        self.check_as_log(
            client_creds,
            status=ntstatus.NT_STATUS_TIME_DIFFERENCE_AT_DC)

    def test_authn_policy_tgt_lifetime_zero(self):
        # Create an authentication policy with the TGT lifetime set to zero.
        lifetime = 0
        policy = self.create_authn_policy(enforced=True,
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

        self.check_as_log(client_creds)

    def test_authn_policy_tgt_lifetime_one_second(self):
        # Create an authentication policy with the TGT lifetime set to one
        # second.
        lifetime = 1
        policy = self.create_authn_policy(enforced=True,
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

        self.check_as_log(client_creds)

    def test_authn_policy_tgt_lifetime_kpasswd_lifetime(self):
        # Create an authentication policy with the TGT lifetime set to two
        # minutes (the lifetime of a kpasswd ticket).
        lifetime = 2 * 60
        policy = self.create_authn_policy(enforced=True,
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

        self.check_as_log(client_creds)

    def test_authn_policy_tgt_lifetime_short_protected(self):
        # Create an authentication policy with a short TGT lifetime set.
        lifetime = 111
        policy = self.create_authn_policy(enforced=True,
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

        self.check_as_log(client_creds)

    def test_authn_policy_tgt_lifetime_long_protected(self):
        # Create an authentication policy with a long TGT lifetime set. This
        # exceeds the lifetime of four hours enforced by Protected Users.
        lifetime = 6 * 60 * 60  # 6 hours
        policy = self.create_authn_policy(enforced=True,
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

        self.check_as_log(client_creds)

    def test_authn_policy_tgt_lifetime_zero_protected(self):
        # Create an authentication policy with the TGT lifetime set to zero.
        policy = self.create_authn_policy(enforced=True,
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

        self.check_as_log(client_creds)

    def test_authn_policy_tgt_lifetime_none_protected(self):
        # Create an authentication policy with no TGT lifetime set.
        policy = self.create_authn_policy(enforced=True)

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

        self.check_as_log(client_creds)

    def test_authn_policy_tgt_lifetime_unenforced_protected(self):
        # Create an unenforced authentication policy with a TGT lifetime set.
        lifetime = 123
        policy = self.create_authn_policy(enforced=False,
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

        self.check_as_log(client_creds)

    def test_authn_policy_not_enforced(self):
        # Create an authentication policy with the TGT lifetime set. The policy
        # is not enforced.
        lifetime = 123
        policy = self.create_authn_policy(user_tgt_lifetime=lifetime)

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

        self.check_as_log(client_creds)

    def test_authn_policy_unenforced(self):
        # Create an authentication policy with the TGT lifetime set. The policy
        # is set to be unenforced.
        lifetime = 123
        policy = self.create_authn_policy(enforced=False,
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

        self.check_as_log(client_creds)

    def test_authn_silo_not_enforced(self):
        # Create an authentication policy with the TGT lifetime set.
        lifetime = 123
        policy = self.create_authn_policy(enforced=True,
                                          user_tgt_lifetime=lifetime)

        # Create an authentication silo with our existing policy. The silo is
        # not enforced.
        silo = self.create_authn_silo(user_policy=policy)

        # Create a user account assigned to the silo.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_silo=silo)
        client_dn_str = str(client_creds.get_dn())

        # Add the user to the silo as a member.
        self.add_to_group(client_dn_str, silo.dn,
                          'msDS-AuthNPolicySiloMembers',
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

        self.check_as_log(client_creds)

    def test_authn_silo_unenforced(self):
        # Create an authentication policy with the TGT lifetime set.
        lifetime = 123
        policy = self.create_authn_policy(enforced=True,
                                          user_tgt_lifetime=lifetime)

        # Create an authentication silo with our existing policy. The silo is
        # set to be unenforced.
        silo = self.create_authn_silo(user_policy=policy,
                                      enforced=False)

        # Create a user account assigned to the silo.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_silo=silo)
        client_dn_str = str(client_creds.get_dn())

        # Add the user to the silo as a member.
        self.add_to_group(client_dn_str, silo.dn,
                          'msDS-AuthNPolicySiloMembers',
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

        self.check_as_log(client_creds)

    def test_authn_silo_not_enforced_policy(self):
        # Create an authentication policy with the TGT lifetime set. The policy
        # is not enforced.
        lifetime = 123
        policy = self.create_authn_policy(user_tgt_lifetime=lifetime)

        # Create an authentication silo with our existing policy.
        silo = self.create_authn_silo(user_policy=policy,
                                      enforced=True)

        # Create a user account assigned to the silo.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_silo=silo)
        client_dn_str = str(client_creds.get_dn())

        # Add the user to the silo as a member.
        self.add_to_group(client_dn_str, silo.dn,
                          'msDS-AuthNPolicySiloMembers',
                          expect_attr=False)

        # Request a Kerberos ticket with a lifetime of two hours. Despite the
        # fact that the policy is unenforced, the actual lifetime matches the
        # user lifetime set in the appropriate policy.
        till = self.get_KerberosTime(offset=2 * 60 * 60)  # 2 hours
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=lifetime,
                                expected_renew_life=lifetime)

        self.check_as_log(client_creds)

    def test_authn_silo_unenforced_policy(self):
        # Create an authentication policy with the TGT lifetime set. The policy
        # is set to be unenforced.
        lifetime = 123
        policy = self.create_authn_policy(enforced=False,
                                          user_tgt_lifetime=lifetime)

        # Create an authentication silo with our existing policy.
        silo = self.create_authn_silo(user_policy=policy,
                                      enforced=True)

        # Create a user account assigned to the silo.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_silo=silo)
        client_dn_str = str(client_creds.get_dn())

        # Add the user to the silo as a member.
        self.add_to_group(client_dn_str, silo.dn,
                          'msDS-AuthNPolicySiloMembers',
                          expect_attr=False)

        # Request a Kerberos ticket with a lifetime of two hours. Despite the
        # fact that the policy is unenforced, the actual lifetime matches the
        # user lifetime set in the appropriate policy.
        till = self.get_KerberosTime(offset=2 * 60 * 60)  # 2 hours
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=lifetime,
                                expected_renew_life=lifetime)

        self.check_as_log(client_creds)

    def test_authn_silo_not_enforced_and_assigned_policy(self):
        # Create an authentication policy with the TGT lifetime set.
        silo_lifetime = 123
        silo_policy = self.create_authn_policy(enforced=True,
                                               user_tgt_lifetime=silo_lifetime)

        # Create an authentication silo with our existing policy. The silo is
        # not enforced.
        silo = self.create_authn_silo(user_policy=silo_policy)

        # Create a second policy with a different lifetime, so we can verify
        # the correct policy is enforced.
        lifetime = 456
        policy = self.create_authn_policy(enforced=True,
                                          user_tgt_lifetime=lifetime)

        # Create a user account assigned to the silo, and also to the policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_silo=silo,
                                       assigned_policy=policy)
        client_dn_str = str(client_creds.get_dn())

        # Add the user to the silo as a member.
        self.add_to_group(client_dn_str, silo.dn,
                          'msDS-AuthNPolicySiloMembers',
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

        self.check_as_log(client_creds)

    def test_authn_silo_unenforced_and_assigned_policy(self):
        # Create an authentication policy with the TGT lifetime set.
        silo_lifetime = 123
        silo_policy = self.create_authn_policy(enforced=True,
                                               user_tgt_lifetime=silo_lifetime)

        # Create an authentication silo with our existing policy. The silo is
        # set to be unenforced.
        silo = self.create_authn_silo(user_policy=silo_policy,
                                      enforced=False)

        # Create a second policy with a different lifetime, so we can verify
        # the correct policy is enforced.
        lifetime = 456
        policy = self.create_authn_policy(enforced=True,
                                          user_tgt_lifetime=lifetime)

        # Create a user account assigned to the silo, and also to the policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_silo=silo,
                                       assigned_policy=policy)
        client_dn_str = str(client_creds.get_dn())

        # Add the user to the silo as a member.
        self.add_to_group(client_dn_str, silo.dn,
                          'msDS-AuthNPolicySiloMembers',
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

        self.check_as_log(client_creds)

    def test_authn_silo_not_enforced_policy_and_assigned_policy(self):
        # Create an authentication policy with the TGT lifetime set. The policy
        # is not enforced.
        silo_lifetime = 123
        silo_policy = self.create_authn_policy(user_tgt_lifetime=silo_lifetime)

        # Create an authentication silo with our existing policy.
        silo = self.create_authn_silo(user_policy=silo_policy,
                                      enforced=True)

        # Create a second policy with a different lifetime, so we can verify
        # the correct policy is enforced.
        lifetime = 456
        policy = self.create_authn_policy(enforced=True,
                                          user_tgt_lifetime=lifetime)

        # Create a user account assigned to the silo, and also to the policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_silo=silo,
                                       assigned_policy=policy)
        client_dn_str = str(client_creds.get_dn())

        # Add the user to the silo as a member.
        self.add_to_group(client_dn_str, silo.dn,
                          'msDS-AuthNPolicySiloMembers',
                          expect_attr=False)

        # Request a Kerberos ticket with a lifetime of two hours. Despite the
        # fact that the policy is unenforced, the actual lifetime matches the
        # user lifetime set in the appropriate policy. The directly-assigned
        # policy is not enforced.
        till = self.get_KerberosTime(offset=2 * 60 * 60)  # 2 hours
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=silo_lifetime,
                                expected_renew_life=silo_lifetime)

        self.check_as_log(client_creds)

    def test_authn_silo_unenforced_policy_and_assigned_policy(self):
        # Create an authentication policy with the TGT lifetime set. The policy
        # is set to be unenforced.
        silo_lifetime = 123
        silo_policy = self.create_authn_policy(enforced=False,
                                               user_tgt_lifetime=silo_lifetime)

        # Create an authentication silo with our existing policy.
        silo = self.create_authn_silo(user_policy=silo_policy,
                                      enforced=True)

        # Create a second policy with a different lifetime, so we can verify
        # the correct policy is enforced.
        lifetime = 456
        policy = self.create_authn_policy(enforced=True,
                                          user_tgt_lifetime=lifetime)

        # Create a user account assigned to the silo, and also to the policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_silo=silo,
                                       assigned_policy=policy)
        client_dn_str = str(client_creds.get_dn())

        # Add the user to the silo as a member.
        self.add_to_group(client_dn_str, silo.dn,
                          'msDS-AuthNPolicySiloMembers',
                          expect_attr=False)

        # Request a Kerberos ticket with a lifetime of two hours. Despite the
        # fact that the policy is unenforced, the actual lifetime matches the
        # user lifetime set in the appropriate policy. The directly-assigned
        # policy is not enforced.
        till = self.get_KerberosTime(offset=2 * 60 * 60)  # 2 hours
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=silo_lifetime,
                                expected_renew_life=silo_lifetime)

        self.check_as_log(client_creds)

    def test_authn_silo_not_a_member(self):
        # Create an authentication policy with the TGT lifetime set.
        lifetime = 123
        policy = self.create_authn_policy(enforced=True,
                                          user_tgt_lifetime=lifetime)

        # Create an authentication silo with our existing policy.
        silo = self.create_authn_silo(user_policy=policy,
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

        self.check_as_log(client_creds)

    def test_authn_silo_not_a_member_and_assigned_policy(self):
        # Create an authentication policy with the TGT lifetime set.
        silo_lifetime = 123
        silo_policy = self.create_authn_policy(enforced=True,
                                               user_tgt_lifetime=silo_lifetime)

        # Create an authentication silo with our existing policy.
        silo = self.create_authn_silo(user_policy=silo_policy,
                                      enforced=True)

        # Create a second policy with a different lifetime, so we can verify
        # the correct policy is enforced.
        lifetime = 456
        policy = self.create_authn_policy(enforced=True,
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

        self.check_as_log(client_creds)

    def test_authn_silo_not_assigned(self):
        # Create an authentication policy with the TGT lifetime set.
        lifetime = 123
        policy = self.create_authn_policy(enforced=True,
                                          user_tgt_lifetime=lifetime)

        # Create an authentication silo with our existing policies.
        silo = self.create_authn_silo(user_policy=policy,
                                      enforced=True)

        # Create a user account, but don’t assign it to the silo.
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        client_dn_str = str(client_creds.get_dn())

        # Add the user to the silo as a member.
        self.add_to_group(client_dn_str, silo.dn,
                          'msDS-AuthNPolicySiloMembers',
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

        self.check_as_log(client_creds)

    def test_authn_silo_not_assigned_and_assigned_policy(self):
        # Create an authentication policy with the TGT lifetime set.
        lifetime = 123
        policy = self.create_authn_policy(enforced=True,
                                          user_tgt_lifetime=lifetime)

        # Create an authentication silo with our existing policies.
        silo = self.create_authn_silo(user_policy=policy,
                                      enforced=True)

        # Create a second policy with a different lifetime, so we can verify
        # the correct policy is enforced.
        lifetime = 456
        policy = self.create_authn_policy(enforced=True,
                                          user_tgt_lifetime=lifetime)

        # Create a user account assigned to the policy, but not to the silo.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)
        client_dn_str = str(client_creds.get_dn())

        # Add the user to the silo as a member.
        self.add_to_group(client_dn_str, silo.dn,
                          'msDS-AuthNPolicySiloMembers',
                          expect_attr=False)

        # Request a Kerberos ticket with a lifetime of two hours, and assert
        # that the actual lifetime matches the user lifetime set in the
        # directly-assigned policy.
        till = self.get_KerberosTime(offset=2 * 60 * 60)  # 2 hours
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=lifetime,
                                expected_renew_life=lifetime)

        self.check_as_log(client_creds)

    def test_authn_silo_no_applicable_policy(self):
        # Create an authentication policy with the TGT lifetime set.
        user_life = 111
        policy = self.create_authn_policy(enforced=True,
                                          user_tgt_lifetime=user_life)

        # Create an authentication silo containing no policies.
        silo = self.create_authn_silo(enforced=True)

        # Create a user account assigned to the silo, and also to a policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_silo=silo,
                                       assigned_policy=policy)
        client_dn_str = str(client_creds.get_dn())

        # Add the user to the silo as a member.
        self.add_to_group(client_dn_str, silo.dn,
                          'msDS-AuthNPolicySiloMembers',
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

        self.check_as_log(client_creds)

    def test_authn_silo_no_tgt_lifetime(self):
        # Create an authentication policy with no TGT lifetime set.
        silo_policy = self.create_authn_policy(enforced=True)

        # Create a second policy with a lifetime set, so we can verify the
        # correct policy is enforced.
        policy = self.create_authn_policy(enforced=True,
                                          user_tgt_lifetime=456)

        # Create an authentication silo with our existing policy.
        silo = self.create_authn_silo(user_policy=silo_policy,
                                      enforced=True)

        # Create a user account assigned to the silo, and also to a policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_silo=silo,
                                       assigned_policy=policy)
        client_dn_str = str(client_creds.get_dn())

        # Add the user to the silo as a member.
        self.add_to_group(client_dn_str, silo.dn,
                          'msDS-AuthNPolicySiloMembers',
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

        self.check_as_log(client_creds)

    def test_not_a_policy(self):
        samdb = self.get_samdb()

        not_a_policy = AuthenticationPolicy()
        not_a_policy.dn = samdb.get_default_basedn()

        # Create a user account with the assigned policy set to something that
        # isn’t a policy.
        client_creds = self._get_creds(
            account_type=self.AccountType.USER,
            assigned_policy=not_a_policy)

        # Request a Kerberos ticket with a ‘till’ time far in the
        # future, and assert that the actual lifetime is the maximum
        # allowed by the Default Domain Policy.
        till = '99991231235959Z'
        expected_lifetime = self.get_max_ticket_life()
        expected_renew_life = self.get_max_renew_life()
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=expected_lifetime,
                                expected_renew_life=expected_renew_life)

        self.check_as_log(client_creds)

    def test_not_a_silo(self):
        samdb = self.get_samdb()

        not_a_silo = AuthenticationSilo()
        not_a_silo.dn = samdb.get_default_basedn()

        # Create a user account assigned to a silo that isn’t a silo.
        client_creds = self._get_creds(
            account_type=self.AccountType.USER,
            assigned_silo=not_a_silo)

        # Request a Kerberos ticket with a ‘till’ time far in the
        # future, and assert that the actual lifetime is the maximum
        # allowed by the Default Domain Policy.
        till = '99991231235959Z'
        expected_lifetime = self.get_max_ticket_life()
        expected_renew_life = self.get_max_renew_life()
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=expected_lifetime,
                                expected_renew_life=expected_renew_life)

        self.check_as_log(client_creds)

    def test_not_a_silo_and_policy(self):
        samdb = self.get_samdb()

        not_a_silo = AuthenticationSilo()
        not_a_silo.dn = samdb.get_default_basedn()

        # Create an authentication policy with the TGT lifetime set.
        user_life = 123
        policy = self.create_authn_policy(enforced=True,
                                          user_tgt_lifetime=user_life)

        # Create a user account assigned to a silo that isn’t a silo, and also
        # to a policy.
        client_creds = self._get_creds(
            account_type=self.AccountType.USER,
            assigned_silo=not_a_silo,
            assigned_policy=policy)

        # Request a Kerberos ticket with a lifetime of two hours, and assert
        # that the actual lifetime matches the user lifetime set in the
        # directly-assigned policy.
        till = self.get_KerberosTime(offset=2 * 60 * 60)  # 2 hours
        tgt = self._get_tgt(client_creds, till=till)
        self.check_ticket_times(tgt, expected_life=user_life,
                                expected_renew_life=user_life)

        self.check_as_log(client_creds)

    def test_authn_policy_allowed_from_empty(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create an authentication policy with no DACL in the security
        # descriptor.
        allowed_from = 'O:SY'
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_from=allowed_from)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that we can authenticate using an armor ticket.
        self._get_tgt(client_creds, armor_tgt=mach_tgt)

        self.check_as_log(client_creds,
                          armor_creds=mach_creds,
                          client_policy=policy)

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
        policy = self.create_authn_policy(enforced=True,
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

        self.check_as_log(client_creds,
                          armor_creds=mach_creds,
                          client_policy=policy)

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
        policy = self.create_authn_policy(enforced=True,
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

        self.check_as_log(
            client_creds,
            armor_creds=mach_creds,
            client_policy=policy,
            client_policy_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.KERBEROS_DEVICE_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED,
            status=ntstatus.NT_STATUS_INVALID_WORKSTATION)

    def test_authn_policy_bad_pwd_allowed_from_user_deny(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create an authentication policy that explicitly denies the machine
        # account for a user.
        allowed = 'O:SYD:(A;;CR;;;WD)'
        denied = f'O:SYD:(D;;CR;;;{mach_creds.get_sid()})'
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_from=denied,
                                          service_allowed_from=allowed)

        # Create a user account with the assigned policy. Use a non-cached
        # account so that it is not locked out for other tests.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy,
                                       cached=False)

        # Set a wrong password.
        client_creds.set_password('wrong password')

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

    def test_authn_policy_allowed_from_service_allow(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create an authentication policy that explicitly allows the machine
        # account for a service.
        allowed = f'O:SYD:(A;;CR;;;{mach_creds.get_sid()})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_from=denied,
                                          service_allowed_from=allowed)

        # Create a managed service account with the assigned policy.
        client_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
            assigned_policy=policy)

        # Show that we can authenticate using an armor ticket.
        self._get_tgt(client_creds, armor_tgt=mach_tgt)

        self.check_as_log(client_creds,
                          armor_creds=mach_creds,
                          client_policy=policy)

    def test_authn_policy_allowed_from_service_deny(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create an authentication policy that explicitly denies the machine
        # account for a service.
        allowed = 'O:SYD:(A;;CR;;;WD)'
        denied = f'O:SYD:(D;;CR;;;{mach_creds.get_sid()})'
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_from=allowed,
                                          service_allowed_from=denied)

        # Create a managed service account with the assigned policy.
        client_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
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

    def test_authn_policy_allowed_from_no_owner(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create an authentication policy that explicitly allows the machine
        # account for a user. Omit the owner (O:SY) from the SDDL. Enforce a
        # TGT lifetime for testing what gets logged.
        allowed = 'D:(A;;CR;;;WD)'
        INT64_MAX = 0x7fff_ffff_ffff_ffff
        max_lifetime = INT64_MAX // 10_000_000
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_from=allowed,
                                          user_tgt_lifetime=max_lifetime)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that we get a generic error if the security descriptor lacks an
        # owner.
        self._get_tgt(client_creds, armor_tgt=mach_tgt,
                      expected_error=KDC_ERR_GENERIC)

        self.check_as_log(
            client_creds,
            armor_creds=mach_creds,
            client_policy=policy,
            client_policy_status=ntstatus.NT_STATUS_INVALID_PARAMETER,
            event=AuditEvent.KERBEROS_DEVICE_RESTRICTION,
            reason=AuditReason.DESCRIPTOR_NO_OWNER,
            status=ntstatus.NT_STATUS_UNSUCCESSFUL)

    def test_authn_policy_allowed_from_no_owner_unenforced(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create an unenforced authentication policy that explicitly allows the
        # machine account for a user. Omit the owner (O:SY) from the SDDL.
        allowed = 'D:(A;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=False,
                                          user_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that we don’t get an error if the policy is unenforced.
        self._get_tgt(client_creds, armor_tgt=mach_tgt)

        self.check_as_log(client_creds,
                          armor_creds=mach_creds,
                          client_policy=policy,
                          client_policy_status=ntstatus.NT_STATUS_INVALID_PARAMETER,
                          event=AuditEvent.KERBEROS_DEVICE_RESTRICTION,
                          reason=AuditReason.DESCRIPTOR_NO_OWNER)

    def test_authn_policy_allowed_from_owner_self(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create an authentication policy that explicitly allows the machine
        # account for a user. Set the owner to the machine account.
        allowed = f'O:{mach_creds.get_sid()}D:(A;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that we can authenticate using an armor ticket.
        self._get_tgt(client_creds, armor_tgt=mach_tgt)

        self.check_as_log(client_creds,
                          armor_creds=mach_creds,
                          client_policy=policy)

    def test_authn_policy_allowed_from_owner_anon(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create an authentication policy that explicitly allows the machine
        # account for a user. Set the owner to be anonymous.
        allowed = 'O:AND:(A;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that we can authenticate using an armor ticket.
        self._get_tgt(client_creds, armor_tgt=mach_tgt)

        self.check_as_log(client_creds,
                          armor_creds=mach_creds,
                          client_policy=policy)

    def test_authn_policy_allowed_from_no_fast(self):
        # Create an authentication policy that restricts authentication.
        # Include some different TGT lifetimes for testing what gets logged.
        allowed_from = 'O:SY'
        policy = self.create_authn_policy(enforced=True,
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

        self.check_as_log(
            client_creds,
            client_policy=policy,
            client_policy_status=ntstatus.NT_STATUS_INVALID_WORKSTATION,
            event=AuditEvent.KERBEROS_DEVICE_RESTRICTION,
            reason=AuditReason.FAST_REQUIRED)

    def test_authn_policy_allowed_from_no_fast_negative_lifetime(self):
        # Create an authentication policy that restricts
        # authentication. Include some negative TGT lifetimes for testing what
        # gets logged.
        allowed_from = 'O:SY'
        policy = self.create_authn_policy(enforced=True,
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

        self.check_as_log(
            client_creds,
            client_policy=policy,
            client_policy_status=ntstatus.NT_STATUS_INVALID_WORKSTATION,
            event=AuditEvent.KERBEROS_DEVICE_RESTRICTION,
            reason=AuditReason.FAST_REQUIRED)

    def test_authn_policy_allowed_from_no_fast_unenforced(self):
        # Create an unenforced authentication policy that restricts
        # authentication.
        allowed_from = 'O:SY'
        policy = self.create_authn_policy(enforced=False,
                                          user_allowed_from=allowed_from)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that we don’t get an error when the policy is unenforced.
        self._get_tgt(client_creds)

        self.check_as_log(
            client_creds,
            client_policy=policy,
            client_policy_status=ntstatus.NT_STATUS_INVALID_WORKSTATION,
            event=AuditEvent.KERBEROS_DEVICE_RESTRICTION,
            reason=AuditReason.FAST_REQUIRED)

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
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that we get a policy error, as the machine account does not
        # belong to the group.
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
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that we can authenticate using an armor ticket, since the
        # machine account belongs to the group.
        self._get_tgt(client_creds, armor_tgt=mach_tgt)

        self.check_as_log(client_creds,
                          armor_creds=mach_creds,
                          client_policy=policy)

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
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that the groups in the armor ticket are expanded to include the
        # domain-local group.
        self._get_tgt(client_creds, armor_tgt=mach_tgt)

        self.check_as_log(client_creds,
                          armor_creds=mach_creds,
                          client_policy=policy)

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
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that authentication is allowed.
        self._get_tgt(client_creds, armor_tgt=mach_tgt)

        self.check_as_log(client_creds,
                          armor_creds=mach_creds,
                          client_policy=policy)

    def test_authn_policy_allowed_from_user_allow_claims_valid(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create an authentication policy that allows accounts with the
        # Claims Valid SID.
        allowed = f'O:SYD:(A;;CR;;;{security.SID_CLAIMS_VALID})'
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that authentication is allowed.
        self._get_tgt(client_creds, armor_tgt=mach_tgt)

        self.check_as_log(client_creds,
                          armor_creds=mach_creds,
                          client_policy=policy)

    def test_authn_policy_allowed_from_user_allow_compounded_auth(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create an authentication policy that allows accounts with the
        # Compounded Authentication SID.
        allowed = f'O:SYD:(A;;CR;;;{security.SID_COMPOUNDED_AUTHENTICATION})'
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that authentication is denied.
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

    def test_authn_policy_allowed_from_user_allow_authenticated_users(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create an authentication policy that allows accounts with the
        # Authenticated Users SID.
        allowed = f'O:SYD:(A;;CR;;;{security.SID_NT_AUTHENTICATED_USERS})'
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that authentication is allowed.
        self._get_tgt(client_creds, armor_tgt=mach_tgt)

        self.check_as_log(client_creds,
                          armor_creds=mach_creds,
                          client_policy=policy)

    def test_authn_policy_allowed_from_user_allow_ntlm_authn(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create an authentication policy that allows accounts with the NTLM
        # Authentication SID.
        allowed = f'O:SYD:(A;;CR;;;{security.SID_NT_NTLM_AUTHENTICATION})'
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that authentication is denied.
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
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_from=allowed,
                                          service_allowed_from=denied)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that we can authenticate using an armor ticket.
        self._get_tgt(client_creds, armor_tgt=mach_tgt)

        self.check_as_log(client_creds,
                          armor_creds=mach_creds,
                          client_policy=policy)

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
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_from=denied,
                                          service_allowed_from=allowed)

        # Create a managed service account with the assigned policy.
        client_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
            assigned_policy=policy)

        # Show that we can authenticate using an armor ticket.
        self._get_tgt(client_creds, armor_tgt=mach_tgt)

        self.check_as_log(client_creds,
                          armor_creds=mach_creds,
                          client_policy=policy)

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
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_from=allowed,
                                          service_allowed_from=denied)

        # Create a managed service account with the assigned policy.
        client_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
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
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that we get a policy error, as the machine account does not
        # belong to the group.
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
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that we can authenticate using an armor ticket, since the
        # machine account belongs to the group.
        self._get_tgt(client_creds, armor_tgt=mach_tgt)

        self.check_as_log(client_creds,
                          armor_creds=mach_creds,
                          client_policy=policy)

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
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that the groups in the armor ticket are expanded to include the
        # domain-local group.
        self._get_tgt(client_creds, armor_tgt=mach_tgt)

        self.check_as_log(client_creds,
                          armor_creds=mach_creds,
                          client_policy=policy)

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
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that authentication is allowed.
        self._get_tgt(client_creds, armor_tgt=mach_tgt)

        self.check_as_log(client_creds,
                          armor_creds=mach_creds,
                          client_policy=policy)

    def test_authn_policy_allowed_from_user_allow_claims_valid_from_rodc(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                     allowed_rodc=True)
        # Modify the TGT to be issued by an RODC.
        mach_tgt = self.issued_by_rodc(self.get_tgt(mach_creds))

        # Create an authentication policy that allows accounts with the
        # Claims Valid SID.
        allowed = f'O:SYD:(A;;CR;;;{security.SID_CLAIMS_VALID})'
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that authentication is allowed.
        self._get_tgt(client_creds, armor_tgt=mach_tgt)

        self.check_as_log(client_creds,
                          armor_creds=mach_creds,
                          client_policy=policy)

    def test_authn_policy_allowed_from_user_allow_compounded_authn_from_rodc(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                     allowed_rodc=True)
        # Modify the TGT to be issued by an RODC.
        mach_tgt = self.issued_by_rodc(self.get_tgt(mach_creds))

        # Create an authentication policy that allows accounts with the
        # Compounded Authentication SID.
        allowed = f'O:SYD:(A;;CR;;;{security.SID_COMPOUNDED_AUTHENTICATION})'
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that authentication is denied.
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

    def test_authn_policy_allowed_from_user_allow_authenticated_users_from_rodc(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                     allowed_rodc=True)
        # Modify the TGT to be issued by an RODC.
        mach_tgt = self.issued_by_rodc(self.get_tgt(mach_creds))

        # Create an authentication policy that allows accounts with the
        # Authenticated Users SID.
        allowed = f'O:SYD:(A;;CR;;;{security.SID_NT_AUTHENTICATED_USERS})'
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that authentication is allowed.
        self._get_tgt(client_creds, armor_tgt=mach_tgt)

        self.check_as_log(client_creds,
                          armor_creds=mach_creds,
                          client_policy=policy)

    def test_authn_policy_allowed_from_user_allow_ntlm_authn_from_rodc(self):
        # Create a machine account with which to perform FAST.
        mach_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                     allowed_rodc=True)
        # Modify the TGT to be issued by an RODC.
        mach_tgt = self.issued_by_rodc(self.get_tgt(mach_creds))

        # Create an authentication policy that allows accounts with the NTLM
        # Authentication SID.
        allowed = f'O:SYD:(A;;CR;;;{security.SID_NT_NTLM_AUTHENTICATION})'
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_from=allowed)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy)

        # Show that authentication is denied.
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
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_from=allowed,
                                          service_allowed_from=denied)

        # Assign the policy to the user account.
        self.add_attribute(samdb, str(client_dn),
                           'msDS-AssignedAuthNPolicy', str(policy.dn))

        # Show that authentication is allowed.
        self._get_tgt(client_creds, armor_tgt=mach_tgt)

        self.check_as_log(client_creds,
                          armor_creds=mach_creds,
                          client_policy=policy)

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
        policy = self.create_authn_policy(enforced=True,
                                          computer_allowed_to=allowed_to)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that authentication is allowed.
        self._tgs_req(tgt, 0, client_creds, target_creds,
                      armor_tgt=mach_tgt)

        self.check_tgs_log(client_creds, target_creds,
                           policy=policy)

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
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=allowed,
                                          service_allowed_to=denied)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that obtaining a service ticket is allowed.
        self._tgs_req(tgt, 0, client_creds, target_creds,
                      armor_tgt=mach_tgt)

        self.check_tgs_log(client_creds, target_creds,
                           policy=policy)

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
        policy = self.create_authn_policy(enforced=True,
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

        self.check_tgs_log(
            client_creds, target_creds,
            policy=policy,
            status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

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
        policy = self.create_authn_policy(enforced=True,
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

        self.check_tgs_log(client_creds, target_creds, policy=policy)

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
        policy = self.create_authn_policy(enforced=True,
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

        self.check_tgs_log(
            client_creds, target_creds,
            policy=policy,
            status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

    def test_authn_policy_allowed_no_fast(self):
        # Create a user account.
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        tgt = self.get_tgt(client_creds)

        # Create an authentication policy that applies to a computer and
        # explicitly allows the user account to obtain a service ticket.
        allowed = f'O:SYD:(A;;CR;;;{client_creds.get_sid()})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=allowed,
                                          service_allowed_to=denied)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that obtaining a service ticket is allowed without an armor TGT.
        self._tgs_req(tgt, 0, client_creds, target_creds)

        self.check_tgs_log(client_creds, target_creds, policy=policy)

    def test_authn_policy_denied_no_fast(self):
        # Create a user account.
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        tgt = self.get_tgt(client_creds)

        # Create an authentication policy that applies to a computer and
        # explicitly disallows the user account to obtain a service ticket.
        denied = f'O:SYD:(D;;CR;;;{client_creds.get_sid()})'
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
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

        self.check_tgs_log(
            client_creds, target_creds,
            policy=policy,
            status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

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
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=allowed,
                                          service_allowed_to=denied)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that obtaining a service ticket is allowed.
        self._tgs_req(tgt, 0, client_creds, target_creds,
                      armor_tgt=mach_tgt)

        self.check_tgs_log(client_creds, target_creds, policy=policy)

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
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=allowed,
                                          service_allowed_to=denied)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that obtaining a service ticket is allowed.
        self._tgs_req(tgt, 0, client_creds, target_creds,
                      armor_tgt=mach_tgt)

        self.check_tgs_log(client_creds, target_creds, policy=policy)

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
        policy = self.create_authn_policy(enforced=True,
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

        self.check_tgs_log(
            client_creds, target_creds,
            policy=policy,
            status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

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
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=allowed,
                                          service_allowed_to=denied)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that obtaining a service ticket is allowed.
        self._tgs_req(tgt, 0, client_creds, target_creds,
                      armor_tgt=mach_tgt)

        self.check_tgs_log(client_creds, target_creds, policy=policy)

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
        policy = self.create_authn_policy(enforced=True,
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

        self.check_tgs_log(
            client_creds, target_creds,
            policy=policy,
            status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

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
        policy = self.create_authn_policy(enforced=True,
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

        self.check_tgs_log(
            client_creds, target_creds,
            policy=policy,
            status=ntstatus.NT_STATUS_INVALID_PARAMETER,
            event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
            reason=AuditReason.DESCRIPTOR_NO_OWNER)

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
        policy = self.create_authn_policy(enforced=False,
                                          computer_allowed_to=allowed)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that obtaining a service ticket is allowed.
        self._tgs_req(tgt, 0, client_creds, target_creds,
                      armor_tgt=mach_tgt)

        self.check_tgs_log(client_creds,
                           target_creds,
                           policy=policy,
                           policy_status=ntstatus.NT_STATUS_INVALID_PARAMETER,
                           event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
                           reason=AuditReason.DESCRIPTOR_NO_OWNER)

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
        policy = self.create_authn_policy(enforced=True,
                                          computer_allowed_to=allowed)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that obtaining a service ticket is allowed.
        self._tgs_req(tgt, 0, client_creds, target_creds,
                      armor_tgt=mach_tgt)

        self.check_tgs_log(client_creds, target_creds, policy=policy)

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
        policy = self.create_authn_policy(enforced=True,
                                          computer_allowed_to=allowed)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that obtaining a service ticket is allowed.
        self._tgs_req(tgt, 0, client_creds, target_creds,
                      armor_tgt=mach_tgt)

        self.check_tgs_log(client_creds, target_creds, policy=policy)

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
        policy = self.create_authn_policy(enforced=True,
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

        self.check_tgs_log(client_creds, target_creds, policy=policy)

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
        policy = self.create_authn_policy(enforced=True,
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

        self.check_tgs_log(
            client_creds, target_creds,
            policy=policy,
            status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

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
        policy = self.create_authn_policy(enforced=True,
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

        self.check_tgs_log(client_creds, target_creds, policy=policy)

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
        policy = self.create_authn_policy(enforced=True,
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

        self.check_tgs_log(
            client_creds, target_creds,
            policy=policy,
            status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

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
        policy = self.create_authn_policy(enforced=True,
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

        self.check_tgs_log(client_creds, target_creds, policy=policy)

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
        policy = self.create_authn_policy(enforced=True,
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

        self.check_tgs_log(
            client_creds, target_creds,
            policy=policy,
            status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

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
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=allowed,
                                          service_allowed_to=denied)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that obtaining a service ticket is allowed.
        self._tgs_req(tgt, 0, client_creds, target_creds,
                      armor_tgt=mach_tgt)

        self.check_tgs_log(client_creds, target_creds, policy=policy)

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
        policy = self.create_authn_policy(enforced=True,
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

        self.check_tgs_log(
            client_creds, target_creds,
            policy=policy,
            status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

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
        policy = self.create_authn_policy(enforced=True,
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

        self.check_tgs_log(client_creds, target_creds, policy=policy)

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
        policy = self.create_authn_policy(enforced=True,
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

        self.check_tgs_log(
            client_creds, target_creds,
            policy=policy,
            status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

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
        policy = self.create_authn_policy(enforced=True,
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

        self.check_tgs_log(
            client_creds, target_creds,
            policy=policy,
            status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

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
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_to=allowed)

        # Create a user account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy,
                                       spn='host/{account}')

        # Show that we can get a service ticket, since the user account belongs
        # to the group.
        self._tgs_req(tgt, 0, client_creds, target_creds,
                      armor_tgt=mach_tgt)

        self.check_tgs_log(client_creds, target_creds, policy=policy)

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
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_to=allowed)

        # Create a user account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy,
                                       spn='host/{account}')

        # Show that the groups in the TGT are expanded to include the
        # domain-local group.
        self._tgs_req(tgt, 0, client_creds, target_creds,
                      armor_tgt=mach_tgt)

        self.check_tgs_log(client_creds, target_creds, policy=policy)

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
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=allowed,
                                          service_allowed_to=denied)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that obtaining a service ticket is allowed.
        self._tgs_req(tgt, 0, client_creds, target_creds,
                      armor_tgt=mach_tgt)

        self.check_tgs_log(client_creds, target_creds, policy=policy)

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
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=allowed,
                                          service_allowed_to=denied)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that obtaining a service ticket is not allowed.
        self._tgs_req(tgt, KDC_ERR_POLICY, client_creds, target_creds,
                      armor_tgt=mach_tgt)

        self.check_tgs_log(
            client_creds, target_creds,
            policy=policy,
            status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

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
        policy = self.create_authn_policy(enforced=True,
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

        self.check_tgs_log(
            client_creds, target_creds,
            policy=policy,
            status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

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
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=allowed,
                                          service_allowed_to=denied)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that obtaining a service ticket is allowed.
        self._tgs_req(tgt, 0, client_creds, target_creds,
                      armor_tgt=mach_tgt)

        self.check_tgs_log(client_creds, target_creds, policy=policy)

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
        policy = self.create_authn_policy(enforced=True,
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

        self.check_tgs_log(
            client_creds, target_creds,
            policy=policy,
            status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

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
        policy = self.create_authn_policy(enforced=True,
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

        self.check_tgs_log(
            client_creds, target_creds,
            policy=policy,
            status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

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
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_to=allowed)

        # Create a user account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy,
                                       spn='host/{account}')

        # Show that we can get a service ticket, since the user account belongs
        # to the group.
        self._tgs_req(tgt, 0, client_creds, target_creds,
                      armor_tgt=mach_tgt)

        self.check_tgs_log(client_creds, target_creds, policy=policy)

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
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_to=allowed)

        # Create a user account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy,
                                       spn='host/{account}')

        # Show that the groups in the TGT are expanded to include the
        # domain-local group.
        self._tgs_req(tgt, 0, client_creds, target_creds,
                      armor_tgt=mach_tgt)

        self.check_tgs_log(client_creds, target_creds, policy=policy)

    def test_authn_policy_allowed_to_computer_allow_to_self(self):
        samdb = self.get_samdb()

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a computer account.
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            use_cache=False)
        client_dn = client_creds.get_dn()
        tgt = self.get_tgt(client_creds)

        # Create an authentication policy that applies to a computer and
        # explicitly allows the user account to obtain a service ticket.
        allowed = f'O:SYD:(A;;CR;;;{client_creds.get_sid()})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=allowed,
                                          service_allowed_to=denied)

        # Assign the policy to the account.
        self.add_attribute(samdb, str(client_dn),
                           'msDS-AssignedAuthNPolicy', str(policy.dn))

        # Show that obtaining a service ticket to ourselves is allowed.
        self._tgs_req(tgt, 0, client_creds, client_creds,
                      armor_tgt=mach_tgt)

        self.check_tgs_log(client_creds, client_creds, policy=policy)

    def test_authn_policy_allowed_to_computer_deny_to_self(self):
        samdb = self.get_samdb()

        # Create a machine account with which to perform FAST.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        # Create a computer account.
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            use_cache=False)
        client_dn = client_creds.get_dn()
        tgt = self.get_tgt(client_creds)

        # Create an authentication policy that applies to a computer and
        # explicitly denies the user account to obtain a service ticket.
        denied = f'O:SYD:(D;;CR;;;{client_creds.get_sid()})'
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_to=allowed,
                                          computer_allowed_to=denied,
                                          service_allowed_to=allowed)

        # Assign the policy to the account.
        self.add_attribute(samdb, str(client_dn),
                           'msDS-AssignedAuthNPolicy', str(policy.dn))

        # Show that obtaining a service ticket to ourselves is allowed, despite
        # the policy disallowing it.
        self._tgs_req(tgt, 0, client_creds, client_creds,
                      armor_tgt=mach_tgt)

        self.check_tgs_log(client_creds, client_creds, policy=policy)

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
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=allowed,
                                          service_allowed_to=denied)

        # Assign the policy to the account.
        self.add_attribute(samdb, str(client_dn),
                           'msDS-AssignedAuthNPolicy', str(policy.dn))

        # Show that obtaining a service ticket to ourselves armored with our
        # own TGT is allowed.
        self._tgs_req(tgt, 0, client_creds, client_creds,
                      armor_tgt=tgt)

        self.check_tgs_log(client_creds, client_creds, policy=policy)

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
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_to=allowed,
                                          computer_allowed_to=denied,
                                          service_allowed_to=allowed)

        # Assign the policy to the account.
        self.add_attribute(samdb, str(client_dn),
                           'msDS-AssignedAuthNPolicy', str(policy.dn))

        # Show that obtaining a service ticket to ourselves armored with our
        # own TGT is allowed, despite the policy’s disallowing it.
        self._tgs_req(tgt, 0, client_creds, client_creds,
                      armor_tgt=tgt)

        self.check_tgs_log(client_creds, client_creds, policy=policy)

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
        policy = self.create_authn_policy(enforced=True,
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

        # The policy does not apply for S4U2Self, and thus does not appear in
        # the logs.
        self.check_tgs_log(client_creds, target_creds, policy=None)

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
        policy = self.create_authn_policy(enforced=True,
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

        # The policy does not apply for S4U2Self, and thus does not appear in
        # the logs.
        self.check_tgs_log(client_creds, target_creds, policy=None)

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
            use_cache=False)
        target_spn = target_creds.get_spn()

        # Create an authentication policy that applies to a computer and
        # explicitly denies the user account to obtain a service ticket.
        denied = f'O:SYD:(D;;CR;;;{client_creds.get_sid()})'
        service_policy = self.create_authn_policy(enforced=True,
                                                  computer_allowed_to=denied)

        # Create a computer account with the assigned policy.
        service_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={
                'assigned_policy': str(service_policy.dn),
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
        target_policy = self.create_authn_policy(enforced=True,
                                                 computer_allowed_to=allowed)

        # Assign the policy to the target account.
        self.add_attribute(samdb, str(target_creds.get_dn()),
                           'msDS-AssignedAuthNPolicy', str(target_policy.dn))

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

        # The policy does not apply for S4U2Self, and thus does not appear in
        # the logs.
        self.check_tgs_log(client_creds, service_creds, policy=None)

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

        self.check_tgs_log(client_creds, target_creds,
                           policy=target_policy,
                           checked_creds=service_creds)

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
        policy = self.create_authn_policy(enforced=True,
                                          computer_allowed_to=allowed)

        # Assign the policy to the target account.
        self.add_attribute(samdb, str(target_creds.get_dn()),
                           'msDS-AssignedAuthNPolicy', str(policy.dn))

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

        # Don’t confuse the client’s TGS-REQ to the service, above, with the
        # following constrained delegation request to the service.
        self.discardMessages()

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

        self.check_tgs_log(client_creds, target_creds,
                           policy=policy,
                           checked_creds=service_creds)

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
        policy = self.create_authn_policy(enforced=True,
                                          computer_allowed_to=denied)

        # Assign the policy to the target account.
        self.add_attribute(samdb, str(target_creds.get_dn()),
                           'msDS-AssignedAuthNPolicy', str(policy.dn))

        client_service_tkt = self.get_service_ticket(
            client_tgt,
            service_creds,
            kdc_options=client_tkt_options,
            expected_flags=expected_flags)

        kdc_options = str(krb5_asn1.KDCOptions('cname-in-addl-tkt'))

        target_decryption_key = self.TicketDecryptionKey_from_creds(
            target_creds)

        # Don’t confuse the client’s TGS-REQ to the service, above, with the
        # following constrained delegation request to the service.
        self.discardMessages()

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

        self.check_tgs_log(
            service_creds, target_creds,
            policy=policy,
            checked_creds=service_creds,
            status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

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

        # Don’t confuse the client’s TGS-REQ to the service, above, with the
        # following constrained delegation request to the service.
        self.discardMessages()

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

        self.check_tgs_log(
            service_creds, target_creds,
            checked_creds=service_creds,
            status=ntstatus.NT_STATUS_UNSUCCESSFUL)

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
        policy = self.create_authn_policy(enforced=True,
                                          computer_allowed_to=allowed)

        # Create a target account with the assigned policy.
        target_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={
                'assigned_policy': str(policy.dn),
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

        # Don’t confuse the client’s TGS-REQ to the service, above, with the
        # following constrained delegation request to the service.
        self.discardMessages()

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

        self.check_tgs_log(client_creds, target_creds,
                           policy=policy,
                           checked_creds=service_creds)

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
        policy = self.create_authn_policy(enforced=True,
                                          computer_allowed_to=denied)

        # Create a target account with the assigned policy.
        target_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={
                'assigned_policy': str(policy.dn),
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

        # Don’t confuse the client’s TGS-REQ to the service, above, with the
        # following constrained delegation request to the service.
        self.discardMessages()

        # Show that obtaining a service ticket with RBCD is not allowed.
        self._tgs_req(service_tgt, KDC_ERR_POLICY, service_creds, target_creds,
                      armor_tgt=mach_tgt,
                      kdc_options=kdc_options,
                      pac_options='1001',  # supports claims, RBCD
                      additional_ticket=client_service_tkt,
                      decryption_key=target_decryption_key,
                      expect_edata=self.expect_padata_outer,
                      check_patypes=False)

        self.check_tgs_log(client_creds, target_creds,
                           policy=policy,
                           checked_creds=service_creds)

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

        # Don’t confuse the client’s TGS-REQ to the service, above, with the
        # following constrained delegation request to the service.
        self.discardMessages()

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

        self.check_tgs_log(client_creds, target_creds,
                           checked_creds=service_creds)

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
        policy = self.create_authn_policy(enforced=True,
                                          computer_allowed_to=allowed)

        # Assign the policy to the service account.
        self.add_attribute(samdb, service_dn_str,
                           'msDS-AssignedAuthNPolicy', str(policy.dn))

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

        # Don’t confuse the client’s TGS-REQ to the service, above, with the
        # following constrained delegation request to the service.
        self.discardMessages()

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

        self.check_tgs_log(client_creds, service_creds,
                           policy=policy,
                           checked_creds=service_creds)

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
        policy = self.create_authn_policy(enforced=True,
                                          computer_allowed_to=allowed)

        # Assign the policy to the service account.
        self.add_attribute(samdb, service_dn_str,
                           'msDS-AssignedAuthNPolicy', str(policy.dn))

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

        # Don’t confuse the client’s TGS-REQ to the service, above, with the
        # following constrained delegation request to the service.
        self.discardMessages()

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

        self.check_tgs_log(client_creds, service_creds,
                           policy=policy,
                           checked_creds=service_creds)

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
            use_cache=False)
        service_dn_str = str(service_creds.get_dn())
        service_sid = service_creds.get_sid()
        service_tgt = self.get_tgt(service_creds)

        # Don’t set msDS-AllowedToDelegateTo.

        # Create an authentication policy that applies to a computer and
        # explicitly allows the client account to obtain a service ticket,
        # while denying the service.
        allowed = f'O:SYD:(A;;CR;;;{client_sid})(D;;CR;;;{service_sid})'
        policy = self.create_authn_policy(enforced=True,
                                          computer_allowed_to=allowed)

        # Assign the policy to the service account.
        self.add_attribute(samdb, service_dn_str,
                           'msDS-AssignedAuthNPolicy', str(policy.dn))

        client_service_tkt = self.get_service_ticket(
            client_tgt,
            service_creds,
            kdc_options=client_tkt_options,
            expected_flags=expected_flags)

        kdc_options = str(krb5_asn1.KDCOptions('cname-in-addl-tkt'))

        target_decryption_key = self.TicketDecryptionKey_from_creds(
            service_creds)

        # Don’t confuse the client’s TGS-REQ to the service, above, with the
        # following constrained delegation request to the service.
        self.discardMessages()

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

        self.check_tgs_log(
            service_creds, service_creds,
            # The failure is not due to a policy error, so no policy appears in
            # the logs.
            policy=None,
            checked_creds=service_creds,
            status=ntstatus.NT_STATUS_UNSUCCESSFUL)

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
        policy = self.create_authn_policy(enforced=True,
                                          computer_allowed_to=allowed)

        # Assign the policy to the service account.
        self.add_attribute(samdb, service_dn_str,
                           'msDS-AssignedAuthNPolicy', str(policy.dn))

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

        # Don’t confuse the client’s TGS-REQ to the service, above, with the
        # following constrained delegation request to the service.
        self.discardMessages()

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

        self.check_tgs_log(client_creds, service_creds,
                           policy=policy,
                           checked_creds=service_creds)

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
        policy = self.create_authn_policy(enforced=True,
                                          computer_allowed_to=allowed)

        # Assign the policy to the service account.
        self.add_attribute(samdb, service_dn_str,
                           'msDS-AssignedAuthNPolicy', str(policy.dn))

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

        # Don’t confuse the client’s TGS-REQ to the service, above, with the
        # following constrained delegation request to the service.
        self.discardMessages()

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

        self.check_tgs_log(client_creds, service_creds,
                           policy=policy,
                           checked_creds=service_creds)

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
            use_cache=False)
        service_dn_str = str(service_creds.get_dn())
        service_sid = service_creds.get_sid()
        service_tgt = self.get_tgt(service_creds)

        # Don’t set msDS-AllowedToActOnBehalfOfOtherIdentity.

        # Create an authentication policy that applies to a computer and
        # explicitly allows the client account to obtain a service ticket,
        # while denying the service.
        allowed = f'O:SYD:(A;;CR;;;{client_sid})(D;;CR;;;{service_sid})'
        policy = self.create_authn_policy(enforced=True,
                                          computer_allowed_to=allowed)

        # Assign the policy to the service account.
        self.add_attribute(samdb, service_dn_str,
                           'msDS-AssignedAuthNPolicy', str(policy.dn))

        client_service_tkt = self.get_service_ticket(
            client_tgt,
            service_creds,
            kdc_options=client_tkt_options,
            expected_flags=expected_flags)

        kdc_options = str(krb5_asn1.KDCOptions('cname-in-addl-tkt'))

        service_decryption_key = self.TicketDecryptionKey_from_creds(
            service_creds)

        # Don’t confuse the client’s TGS-REQ to the service, above, with the
        # following constrained delegation request to the service.
        self.discardMessages()

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

        self.check_tgs_log(client_creds, service_creds,
                           policy=policy,
                           checked_creds=service_creds)

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
        policy = self.create_authn_policy(enforced=True,
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

        self.check_tgs_log(client_creds, target_creds, policy=policy)

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
        policy = self.create_authn_policy(enforced=True,
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

        self.check_tgs_log(
            client_creds, target_creds,
            policy=policy,
            status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.KERBEROS_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

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
        policy = self.create_authn_policy(enforced=True,
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
                'msDS-AssignedAuthNPolicy': str(policy.dn),
                'objectClass': user_class,
            })

        keys = self.get_keys(target_creds)
        self.creds_set_keys(target_creds, keys)

        # Show that obtaining a service ticket is allowed.
        self._tgs_req(tgt, 0, client_creds, target_creds,
                      armor_tgt=mach_tgt)

        self.check_tgs_log(client_creds, target_creds, policy=policy)

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
        policy = self.create_authn_policy(enforced=True,
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
                'msDS-AssignedAuthNPolicy': str(policy.dn),
                'objectClass': computer_class,
            })

        keys = self.get_keys(target_creds)
        self.creds_set_keys(target_creds, keys)

        # Show that obtaining a service ticket is allowed.
        self._tgs_req(tgt, 0, client_creds, target_creds,
                      armor_tgt=mach_tgt)

        self.check_tgs_log(client_creds, target_creds, policy=policy)

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
        policy = self.create_authn_policy(enforced=True,
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
                'msDS-AssignedAuthNPolicy': str(policy.dn),
                'objectClass': service_class,
            })

        # Show that obtaining a service ticket is allowed.
        self._tgs_req(tgt, 0, client_creds, target_creds,
                      armor_tgt=mach_tgt)

        self.check_tgs_log(client_creds, target_creds, policy=policy)

    def test_authn_policy_ntlm_allow_user(self):
        # Create an authentication policy allowing NTLM authentication for
        # users.
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
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

        self.check_ntlm_log(client_creds,
                            client_policy=policy)

    def test_authn_policy_ntlm_deny_user(self):
        # Create an authentication policy denying NTLM authentication for
        # users.
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
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

        self.check_ntlm_log(
            client_creds,
            client_policy=policy,
            client_policy_status=ntstatus.NT_STATUS_ACCOUNT_RESTRICTION,
            event=AuditEvent.NTLM_DEVICE_RESTRICTION)

    def test_authn_policy_ntlm_computer(self):
        # Create an authentication policy denying NTLM authentication.
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
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

        self.check_ntlm_log(
            client_creds,
            client_policy=None)  # Client policies don’t apply to computers.

    def test_authn_policy_ntlm_allow_service(self):
        # Create an authentication policy allowing NTLM authentication for
        # services.
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
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

        self.check_ntlm_log(client_creds,
                            client_policy=policy)

    def test_authn_policy_ntlm_deny_service(self):
        # Create an authentication policy denying NTLM authentication for
        # services.
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
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

        self.check_ntlm_log(
            client_creds,
            client_policy=policy,
            client_policy_status=ntstatus.NT_STATUS_ACCOUNT_RESTRICTION,
            event=AuditEvent.NTLM_DEVICE_RESTRICTION)

    def test_authn_policy_ntlm_deny_no_device_restrictions(self):
        # Create an authentication policy denying NTLM authentication for
        # users.
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_ntlm=False,
                                          service_allowed_ntlm=True)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy,
                                       ntlm=True)

        # Show that without AllowedToAuthenticateFrom set in the policy, NTLM
        # authentication succeeds.
        self._connect(client_creds, simple_bind=False)

        self.check_ntlm_log(client_creds,
                            client_policy=policy)

    def test_authn_policy_simple_bind_allow_user(self):
        # Create an authentication policy allowing NTLM authentication for
        # users.
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
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

        self.check_simple_bind_log(client_creds,
                                   client_policy=policy)

    def test_authn_policy_simple_bind_deny_user(self):
        # Create an authentication policy denying NTLM authentication for
        # users.
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
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

        self.check_simple_bind_log(
            client_creds,
            client_policy=policy,
            client_policy_status=ntstatus.NT_STATUS_ACCOUNT_RESTRICTION,
            event=AuditEvent.NTLM_DEVICE_RESTRICTION)

    def test_authn_policy_simple_bind_deny_no_device_restrictions(self):
        # Create an authentication policy denying NTLM authentication for
        # users.
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_ntlm=False,
                                          service_allowed_ntlm=True)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy,
                                       ntlm=True)

        # Show that without AllowedToAuthenticateFrom set in the policy, a
        # simple bind succeeds.
        self._connect(client_creds, simple_bind=True)

        self.check_simple_bind_log(client_creds,
                                   client_policy=policy)

    def test_authn_policy_samr_pwd_change_allow_service_allowed_from(self):
        # Create an authentication policy allowing NTLM authentication for
        # managed service accounts.
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
                                          service_allowed_ntlm=True,
                                          service_allowed_from=allowed)

        # Create a managed service account with the assigned policy.
        client_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
            assigned_policy=policy,
            ntlm=True)

        # Show that a SAMR password change is allowed.
        self._test_samr_change_password(client_creds, expect_error=None)

        self.check_samr_pwd_change_log(client_creds,
                                       client_policy=policy)

    def test_authn_policy_samr_pwd_change_allow_service_not_allowed_from(self):
        # Create an authentication policy allowing NTLM authentication for
        # managed service accounts.
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
                                          service_allowed_ntlm=True,
                                          service_allowed_from=denied)

        # Create a managed service account with the assigned policy.
        client_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
            assigned_policy=policy,
            ntlm=True)

        # Show that a SAMR password change is allowed.
        self._test_samr_change_password(client_creds, expect_error=None)

        self.check_samr_pwd_change_log(client_creds,
                                       client_policy=policy)

    def test_authn_policy_samr_pwd_change_allow_service_no_allowed_from(self):
        # Create an authentication policy allowing NTLM authentication for
        # managed service accounts.
        policy = self.create_authn_policy(enforced=True,
                                          service_allowed_ntlm=True)

        # Create a managed service account with the assigned policy.
        client_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
            assigned_policy=policy,
            ntlm=True)

        # Show that a SAMR password change is allowed.
        self._test_samr_change_password(client_creds, expect_error=None)

        self.check_samr_pwd_change_log(client_creds,
                                       client_policy=policy)

    def test_authn_policy_samr_pwd_change_deny_service_allowed_from(self):
        # Create an authentication policy denying NTLM authentication for
        # managed service accounts.
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
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

        self.check_samr_pwd_change_log(
            client_creds,
            client_policy=policy,
            client_policy_status=ntstatus.NT_STATUS_ACCOUNT_RESTRICTION,
            event=AuditEvent.NTLM_DEVICE_RESTRICTION)

    def test_authn_policy_samr_pwd_change_deny_service_not_allowed_from(self):
        # Create an authentication policy denying NTLM authentication for
        # managed service accounts.
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
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

        self.check_samr_pwd_change_log(
            client_creds,
            client_policy=policy,
            client_policy_status=ntstatus.NT_STATUS_ACCOUNT_RESTRICTION,
            event=AuditEvent.NTLM_DEVICE_RESTRICTION)

    def test_authn_policy_samr_pwd_change_deny_service_no_allowed_from(self):
        # Create an authentication policy denying NTLM authentication for
        # managed service accounts.
        policy = self.create_authn_policy(enforced=True,
                                          service_allowed_ntlm=False)

        # Create a managed service account with the assigned policy.
        client_creds = self._get_creds(
            account_type=self.AccountType.MANAGED_SERVICE,
            assigned_policy=policy,
            ntlm=True)

        # Show that a SAMR password change is allowed.
        self._test_samr_change_password(client_creds, expect_error=None)

        self.check_samr_pwd_change_log(client_creds,
                                       client_policy=policy)

    def test_authn_policy_samlogon_allow_user(self):
        # Create an authentication policy allowing NTLM authentication for
        # users.
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
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

        self.check_samlogon_network_log(client_creds,
                                        client_policy=policy)

        # Show that an interactive SamLogon succeeds. Although MS-APDS doesn’t
        # state it, AllowedNTLMNetworkAuthentication applies to interactive
        # logons too.
        self._test_samlogon(creds=client_creds,
                            logon_type=netlogon.NetlogonInteractiveInformation)

        self.check_samlogon_interactive_log(client_creds,
                                            client_policy=policy)

    def test_authn_policy_samlogon_deny_user(self):
        # Create an authentication policy denying NTLM authentication for
        # users.
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
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

        self.check_samlogon_network_log(
            client_creds,
            client_policy=policy,
            client_policy_status=ntstatus.NT_STATUS_ACCOUNT_RESTRICTION,
            event=AuditEvent.NTLM_DEVICE_RESTRICTION)

        # Show that an interactive SamLogon fails.
        self._test_samlogon(
            creds=client_creds,
            logon_type=netlogon.NetlogonInteractiveInformation,
            expect_error=ntstatus.NT_STATUS_ACCOUNT_RESTRICTION)

        self.check_samlogon_interactive_log(
            client_creds,
            client_policy=policy,
            client_policy_status=ntstatus.NT_STATUS_ACCOUNT_RESTRICTION,
            event=AuditEvent.NTLM_DEVICE_RESTRICTION)

    def test_authn_policy_samlogon_network_computer(self):
        # Create an authentication policy denying NTLM authentication.
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
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

        self.check_samlogon_network_log(
            client_creds,
            client_policy=None)  # Client policies don’t apply to computers.

    def test_authn_policy_samlogon_interactive_allow_user_allowed_from(self):
        # Create an authentication policy allowing NTLM authentication for
        # users.
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
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

        self.check_samlogon_interactive_log(client_creds,
                                            client_policy=policy)

    def test_authn_policy_samlogon_interactive_allow_user_not_allowed_from(self):
        # Create an authentication policy allowing NTLM authentication for
        # users.
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
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

        self.check_samlogon_interactive_log(client_creds,
                                            client_policy=policy)

    def test_authn_policy_samlogon_interactive_allow_user_no_allowed_from(self):
        # Create an authentication policy allowing NTLM authentication for
        # users.
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_ntlm=True)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy,
                                       ntlm=True,
                                       cached=False)

        # Show that an interactive SamLogon succeeds.
        self._test_samlogon(creds=client_creds,
                            logon_type=netlogon.NetlogonInteractiveInformation)

        self.check_samlogon_interactive_log(client_creds,
                                            client_policy=policy)

    def test_authn_policy_samlogon_interactive_deny_user_allowed_from(self):
        # Create an authentication policy disallowing NTLM authentication for
        # users.
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
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

        self.check_samlogon_interactive_log(
            client_creds,
            client_policy=policy,
            client_policy_status=ntstatus.NT_STATUS_ACCOUNT_RESTRICTION,
            event=AuditEvent.NTLM_DEVICE_RESTRICTION)

    def test_authn_policy_samlogon_interactive_deny_user_not_allowed_from(self):
        # Create an authentication policy disallowing NTLM authentication for
        # users.
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
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

        self.check_samlogon_interactive_log(
            client_creds,
            client_policy=policy,
            client_policy_status=ntstatus.NT_STATUS_ACCOUNT_RESTRICTION,
            event=AuditEvent.NTLM_DEVICE_RESTRICTION)

    def test_authn_policy_samlogon_interactive_deny_user_no_allowed_from(self):
        # Create an authentication policy disallowing NTLM authentication for
        # users.
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_ntlm=False)

        # Create a user account with the assigned policy.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy,
                                       ntlm=True,
                                       cached=False)

        # Show that an interactive SamLogon succeeds.
        self._test_samlogon(creds=client_creds,
                            logon_type=netlogon.NetlogonInteractiveInformation)

        self.check_samlogon_interactive_log(client_creds,
                                            client_policy=policy)

    def test_authn_policy_samlogon_interactive_user_allowed_from(self):
        # Create an authentication policy not specifying whether NTLM
        # authentication is allowed or not.
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
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

        self.check_samlogon_interactive_log(
            client_creds,
            client_policy=policy,
            client_policy_status=ntstatus.NT_STATUS_ACCOUNT_RESTRICTION,
            event=AuditEvent.NTLM_DEVICE_RESTRICTION)

    def test_authn_policy_samlogon_network_user_allowed_from(self):
        # Create an authentication policy not specifying whether NTLM
        # authentication is allowed or not.
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
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

        self.check_samlogon_network_log(
            client_creds,
            client_policy=policy,
            client_policy_status=ntstatus.NT_STATUS_ACCOUNT_RESTRICTION,
            event=AuditEvent.NTLM_DEVICE_RESTRICTION)

    def test_authn_policy_samlogon_network_allow_service_allowed_from(self):
        # Create an authentication policy allowing NTLM authentication for
        # services.
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
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

        self.check_samlogon_network_log(client_creds,
                                        client_policy=policy)

    def test_authn_policy_samlogon_network_allow_service_not_allowed_from(self):
        # Create an authentication policy allowing NTLM authentication for
        # services.
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
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

        self.check_samlogon_network_log(client_creds,
                                        client_policy=policy)

    def test_authn_policy_samlogon_network_allow_service_no_allowed_from(self):
        # Create an authentication policy allowing NTLM authentication for
        # services.
        policy = self.create_authn_policy(enforced=True,
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

        self.check_samlogon_network_log(client_creds,
                                        client_policy=policy)

    def test_authn_policy_samlogon_network_deny_service_allowed_from(self):
        # Create an authentication policy disallowing NTLM authentication for
        # services.
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
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

        self.check_samlogon_network_log(
            client_creds,
            client_policy=policy,
            client_policy_status=ntstatus.NT_STATUS_ACCOUNT_RESTRICTION,
            event=AuditEvent.NTLM_DEVICE_RESTRICTION)

    def test_authn_policy_samlogon_network_deny_service_not_allowed_from(self):
        # Create an authentication policy disallowing NTLM authentication for
        # services.
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
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

        self.check_samlogon_network_log(
            client_creds,
            client_policy=policy,
            client_policy_status=ntstatus.NT_STATUS_ACCOUNT_RESTRICTION,
            event=AuditEvent.NTLM_DEVICE_RESTRICTION)

    def test_authn_policy_samlogon_network_deny_service_no_allowed_from(self):
        # Create an authentication policy disallowing NTLM authentication for
        # services.
        policy = self.create_authn_policy(enforced=True,
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

        self.check_samlogon_network_log(client_creds,
                                        client_policy=policy)

    def test_authn_policy_samlogon_network_allow_service_allowed_from_to_self(self):
        # Create an authentication policy allowing NTLM authentication for
        # services.
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
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

        self.check_samlogon_network_log(client_creds,
                                        client_policy=policy,
                                        server_policy=policy)

    def test_authn_policy_samlogon_network_allow_service_not_allowed_from_to_self(self):
        # Create an authentication policy allowing NTLM authentication for
        # services.
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
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

        self.check_samlogon_network_log(client_creds,
                                        client_policy=policy,
                                        server_policy=policy)

    def test_authn_policy_samlogon_network_allow_service_no_allowed_from_to_self(self):
        # Create an authentication policy allowing NTLM authentication for
        # services.
        policy = self.create_authn_policy(enforced=True,
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

        self.check_samlogon_network_log(client_creds,
                                        client_policy=policy,
                                        server_policy=policy)

    def test_authn_policy_samlogon_network_deny_service_allowed_from_to_self(self):
        # Create an authentication policy disallowing NTLM authentication for
        # services.
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
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

        self.check_samlogon_network_log(
            client_creds,
            client_policy=policy,
            server_policy=None,  # Only the client policy appears in the logs.
            client_policy_status=ntstatus.NT_STATUS_ACCOUNT_RESTRICTION,
            event=AuditEvent.NTLM_DEVICE_RESTRICTION)

    def test_authn_policy_samlogon_network_deny_service_not_allowed_from_to_self(self):
        # Create an authentication policy disallowing NTLM authentication for
        # services.
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
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

        self.check_samlogon_network_log(
            client_creds,
            client_policy=policy,
            client_policy_status=ntstatus.NT_STATUS_ACCOUNT_RESTRICTION,
            event=AuditEvent.NTLM_DEVICE_RESTRICTION,
            server_policy=None)  # Only the client policy appears in the logs.

    def test_authn_policy_samlogon_network_deny_service_no_allowed_from_to_self(self):
        # Create an authentication policy disallowing NTLM authentication for
        # services.
        policy = self.create_authn_policy(enforced=True,
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

        self.check_samlogon_network_log(client_creds,
                                        client_policy=policy,
                                        server_policy=policy)

    def test_authn_policy_samlogon_interactive_deny_no_device_restrictions(self):
        # Create an authentication policy denying NTLM authentication for
        # users.
        policy = self.create_authn_policy(enforced=True,
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

        self.check_samlogon_interactive_log(client_creds,
                                            client_policy=policy)

    def test_authn_policy_samlogon_network_deny_no_device_restrictions(self):
        # Create an authentication policy denying NTLM authentication for
        # users.
        policy = self.create_authn_policy(enforced=True,
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

        self.check_samlogon_network_log(client_creds,
                                        client_policy=policy)

    def test_samlogon_allowed_to_computer_allow(self):
        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       ntlm=True)

        # Create an authentication policy that applies to a computer and
        # explicitly allows the user account to obtain a service ticket.
        allowed = f'O:SYD:(A;;CR;;;{client_creds.get_sid()})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
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

        self.check_samlogon_network_log(client_creds,
                                        server_policy=policy)

        # Show that an interactive SamLogon succeeds.
        self._test_samlogon(creds=client_creds,
                            domain_joined_mach_creds=target_creds,
                            logon_type=netlogon.NetlogonInteractiveInformation)

        self.check_samlogon_interactive_log(client_creds,
                                            server_policy=policy)

    def test_samlogon_allowed_to_computer_deny(self):
        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       ntlm=True)

        # Create an authentication policy that applies to a computer and
        # explicitly denies the user account to obtain a service ticket.
        denied = f'O:SYD:(D;;CR;;;{client_creds.get_sid()})'
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
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

        self.check_samlogon_network_log(
            client_creds,
            server_policy=policy,
            server_policy_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.NTLM_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

        # Show that an interactive SamLogon fails.
        self._test_samlogon(
            creds=client_creds,
            domain_joined_mach_creds=target_creds,
            logon_type=netlogon.NetlogonInteractiveInformation,
            expect_error=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

        self.check_samlogon_interactive_log(
            client_creds,
            server_policy=policy,
            server_policy_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.NTLM_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

    def test_samlogon_allowed_to_computer_deny_protected(self):
        # Create a protected user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       protected=True,
                                       ntlm=True)

        # Create an authentication policy that applies to a computer and
        # explicitly denies the user account to obtain a service ticket.
        denied = f'O:SYD:(D;;CR;;;{client_creds.get_sid()})'
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
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

        self.check_samlogon_network_log(
            client_creds,
            # The account’s protection takes precedence, and no policy appears
            # in the log.
            server_policy=None,
            status=ntstatus.NT_STATUS_ACCOUNT_RESTRICTION)

        # Show that an interactive SamLogon fails.
        self._test_samlogon(
            creds=client_creds,
            domain_joined_mach_creds=target_creds,
            logon_type=netlogon.NetlogonInteractiveInformation,
            expect_error=ntstatus.NT_STATUS_ACCOUNT_RESTRICTION)

        self.check_samlogon_interactive_log(
            client_creds,
            # The account’s protection takes precedence, and no policy appears
            # in the log.
            server_policy=None,
            status=ntstatus.NT_STATUS_ACCOUNT_RESTRICTION)

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
        policy = self.create_authn_policy(enforced=True,
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

        self.check_samlogon_network_log(
            client_creds,
            server_policy=policy,
            server_policy_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.NTLM_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

        # Show that an interactive SamLogon fails.
        self._test_samlogon(
            creds=client_creds,
            domain_joined_mach_creds=target_creds,
            logon_type=netlogon.NetlogonInteractiveInformation,
            expect_error=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

        self.check_samlogon_interactive_log(
            client_creds,
            server_policy=policy,
            server_policy_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.NTLM_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

    def test_samlogon_allowed_to_computer_allow_claims_valid(self):
        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       ntlm=True)

        # Create an authentication policy that allows accounts with the Claims
        # Valid SID to obtain a service ticket.
        allowed = f'O:SYD:(A;;CR;;;{security.SID_CLAIMS_VALID})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
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

        self.check_samlogon_network_log(
            client_creds,
            server_policy=policy,
            server_policy_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.NTLM_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

        # Show that an interactive SamLogon fails.
        self._test_samlogon(
            creds=client_creds,
            domain_joined_mach_creds=target_creds,
            logon_type=netlogon.NetlogonInteractiveInformation,
            expect_error=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

        self.check_samlogon_interactive_log(
            client_creds,
            server_policy=policy,
            server_policy_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.NTLM_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

    def test_samlogon_allowed_to_computer_allow_compounded_auth(self):
        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       ntlm=True)

        # Create an authentication policy that allows accounts with the
        # Compounded Authentication SID to obtain a service ticket.
        allowed = f'O:SYD:(A;;CR;;;{security.SID_COMPOUNDED_AUTHENTICATION})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
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

        self.check_samlogon_network_log(
            client_creds,
            server_policy=policy,
            server_policy_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.NTLM_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

        # Show that an interactive SamLogon fails.
        self._test_samlogon(
            creds=client_creds,
            domain_joined_mach_creds=target_creds,
            logon_type=netlogon.NetlogonInteractiveInformation,
            expect_error=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

        self.check_samlogon_interactive_log(
            client_creds,
            server_policy=policy,
            server_policy_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.NTLM_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

    def test_samlogon_allowed_to_computer_allow_authenticated_users(self):
        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       ntlm=True)

        # Create an authentication policy that allows accounts with the
        # Authenticated Users SID to obtain a service ticket.
        allowed = f'O:SYD:(A;;CR;;;{security.SID_NT_AUTHENTICATED_USERS})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
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

        self.check_samlogon_network_log(client_creds,
                                        server_policy=policy)

        # Show that an interactive SamLogon succeeds.
        self._test_samlogon(creds=client_creds,
                            domain_joined_mach_creds=target_creds,
                            logon_type=netlogon.NetlogonInteractiveInformation)

        self.check_samlogon_interactive_log(client_creds,
                                            server_policy=policy)

    def test_samlogon_allowed_to_computer_allow_ntlm_authn(self):
        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       ntlm=True)

        # Create an authentication policy that allows accounts with the NTLM
        # Authentication SID to obtain a service ticket.
        allowed = f'O:SYD:(A;;CR;;;{security.SID_NT_NTLM_AUTHENTICATION})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
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

        self.check_samlogon_network_log(
            client_creds,
            server_policy=policy,
            server_policy_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.NTLM_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

        # Show that an interactive SamLogon fails.
        self._test_samlogon(
            creds=client_creds,
            domain_joined_mach_creds=target_creds,
            logon_type=netlogon.NetlogonInteractiveInformation,
            expect_error=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

        self.check_samlogon_interactive_log(
            client_creds,
            server_policy=policy,
            server_policy_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.NTLM_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

    def test_samlogon_allowed_to_no_owner(self):
        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       ntlm=True)

        # Create an authentication policy that applies to a computer and
        # explicitly allows the user account to obtain a service ticket. Omit
        # the owner (O:SY) from the SDDL.
        allowed = f'D:(A;;CR;;;{client_creds.get_sid()})'
        policy = self.create_authn_policy(enforced=True,
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

        self.check_samlogon_network_log(
            client_creds,
            server_policy=policy,
            server_policy_status=ntstatus.NT_STATUS_INVALID_PARAMETER,
            event=AuditEvent.NTLM_SERVER_RESTRICTION,
            reason=AuditReason.DESCRIPTOR_NO_OWNER)

        # Show that an interactive SamLogon fails.
        self._test_samlogon(
            creds=client_creds,
            domain_joined_mach_creds=target_creds,
            logon_type=netlogon.NetlogonInteractiveInformation,
            expect_error=ntstatus.NT_STATUS_INVALID_PARAMETER)

        self.check_samlogon_interactive_log(
            client_creds,
            server_policy=policy,
            server_policy_status=ntstatus.NT_STATUS_INVALID_PARAMETER,
            event=AuditEvent.NTLM_SERVER_RESTRICTION,
            reason=AuditReason.DESCRIPTOR_NO_OWNER)

    def test_samlogon_allowed_to_no_owner_unenforced(self):
        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       ntlm=True)

        # Create an unenforced authentication policy that applies to a computer
        # and explicitly allows the user account to obtain a service
        # ticket. Omit the owner (O:SY) from the SDDL.
        allowed = f'D:(A;;CR;;;{client_creds.get_sid()})'
        policy = self.create_authn_policy(enforced=False,
                                          computer_allowed_to=allowed)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that a network SamLogon succeeds.
        self._test_samlogon(creds=client_creds,
                            domain_joined_mach_creds=target_creds,
                            logon_type=netlogon.NetlogonNetworkInformation)

        self.check_samlogon_network_log(
            client_creds,
            server_policy=policy,
            server_policy_status=ntstatus.NT_STATUS_INVALID_PARAMETER,
            event=AuditEvent.NTLM_SERVER_RESTRICTION,
            reason=AuditReason.DESCRIPTOR_NO_OWNER)

        # Show that an interactive SamLogon succeeds.
        self._test_samlogon(creds=client_creds,
                            domain_joined_mach_creds=target_creds,
                            logon_type=netlogon.NetlogonInteractiveInformation)

        self.check_samlogon_interactive_log(
            client_creds,
            server_policy=policy,
            server_policy_status=ntstatus.NT_STATUS_INVALID_PARAMETER,
            event=AuditEvent.NTLM_SERVER_RESTRICTION,
            reason=AuditReason.DESCRIPTOR_NO_OWNER)

    def test_samlogon_allowed_to_service_allow(self):
        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       ntlm=True)

        # Create an authentication policy that applies to a managed service and
        # explicitly allows the user account to obtain a service ticket.
        allowed = f'O:SYD:(A;;CR;;;{client_creds.get_sid()})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
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

        self.check_samlogon_network_log(client_creds,
                                        server_policy=policy)

        # Show that an interactive SamLogon succeeds.
        self._test_samlogon(creds=client_creds,
                            domain_joined_mach_creds=target_creds,
                            logon_type=netlogon.NetlogonInteractiveInformation)

        self.check_samlogon_interactive_log(client_creds,
                                            server_policy=policy)

    def test_samlogon_allowed_to_service_deny(self):
        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       ntlm=True)

        # Create an authentication policy that applies to a managed service and
        # explicitly denies the user account to obtain a service ticket.
        denied = f'O:SYD:(D;;CR;;;{client_creds.get_sid()})'
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
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

        self.check_samlogon_network_log(
            client_creds,
            server_policy=policy,
            server_policy_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.NTLM_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

        # Show that an interactive SamLogon fails.
        self._test_samlogon(
            creds=client_creds,
            domain_joined_mach_creds=target_creds,
            logon_type=netlogon.NetlogonInteractiveInformation,
            expect_error=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

        self.check_samlogon_interactive_log(
            client_creds,
            server_policy=policy,
            server_policy_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.NTLM_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

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
        policy = self.create_authn_policy(enforced=True,
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

        self.check_samlogon_network_log(
            client_creds,
            server_policy=policy,
            server_policy_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.NTLM_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

        # Show that an interactive SamLogon fails, as the user account does not
        # belong to the group.
        self._test_samlogon(
            creds=client_creds,
            domain_joined_mach_creds=target_creds,
            logon_type=netlogon.NetlogonInteractiveInformation,
            expect_error=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

        self.check_samlogon_interactive_log(
            client_creds,
            server_policy=policy,
            server_policy_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.NTLM_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

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
        policy = self.create_authn_policy(enforced=True,
                                          computer_allowed_to=allowed)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that a network SamLogon succeeds, since the user account belongs
        # to the group.
        self._test_samlogon(creds=client_creds,
                            domain_joined_mach_creds=target_creds,
                            logon_type=netlogon.NetlogonNetworkInformation)

        self.check_samlogon_network_log(client_creds,
                                        server_policy=policy)

        # Show that an interactive SamLogon succeeds, since the user account
        # belongs to the group.
        self._test_samlogon(creds=client_creds,
                            domain_joined_mach_creds=target_creds,
                            logon_type=netlogon.NetlogonInteractiveInformation)

        self.check_samlogon_interactive_log(client_creds,
                                            server_policy=policy)

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
        policy = self.create_authn_policy(enforced=True,
                                          computer_allowed_to=allowed)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Show that a network SamLogon succeeds, since the user account belongs
        # to the group.
        self._test_samlogon(creds=client_creds,
                            domain_joined_mach_creds=target_creds,
                            logon_type=netlogon.NetlogonNetworkInformation)

        self.check_samlogon_network_log(client_creds,
                                        server_policy=policy)

        # Show that an interactive SamLogon succeeds, since the user account
        # belongs to the group.
        self._test_samlogon(creds=client_creds,
                            domain_joined_mach_creds=target_creds,
                            logon_type=netlogon.NetlogonInteractiveInformation)

        self.check_samlogon_interactive_log(client_creds,
                                            server_policy=policy)

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
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=allowed,
                                          service_allowed_to=denied)

        # Assign the policy to the account.
        self.add_attribute(samdb, str(client_dn),
                           'msDS-AssignedAuthNPolicy', str(policy.dn))

        # Show that a network SamLogon to ourselves succeeds.
        self._test_samlogon(creds=client_creds,
                            domain_joined_mach_creds=client_creds,
                            logon_type=netlogon.NetlogonNetworkInformation)

        self.check_samlogon_network_log(
            client_creds,
            client_policy=None,  # Client policies don’t apply to computers.
            server_policy=policy)

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
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_to=allowed,
                                          computer_allowed_to=denied,
                                          service_allowed_to=allowed)

        # Assign the policy to the account.
        self.add_attribute(samdb, str(client_dn),
                           'msDS-AssignedAuthNPolicy', str(policy.dn))

        # Show that a network SamLogon to ourselves fails, despite
        # authentication being allowed in the Kerberos case.
        self._test_samlogon(
            creds=client_creds,
            domain_joined_mach_creds=client_creds,
            logon_type=netlogon.NetlogonNetworkInformation,
            expect_error=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

        self.check_samlogon_network_log(
            client_creds,
            client_policy=None,  # Client policies don’t apply to computers.
            server_policy=policy,
            server_policy_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.NTLM_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

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
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_to=denied,
                                          computer_allowed_to=denied,
                                          service_allowed_to=allowed)

        # Assign the policy to the account.
        self.add_attribute(samdb, str(client_dn),
                           'msDS-AssignedAuthNPolicy', str(policy.dn))

        # Show that a network SamLogon to ourselves succeeds.
        self._test_samlogon(creds=client_creds,
                            domain_joined_mach_creds=client_creds,
                            logon_type=netlogon.NetlogonNetworkInformation)

        self.check_samlogon_network_log(client_creds,
                                        client_policy=policy,
                                        server_policy=policy)

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
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_to=allowed,
                                          computer_allowed_to=allowed,
                                          service_allowed_to=denied)

        # Assign the policy to the account.
        self.add_attribute(samdb, str(client_dn),
                           'msDS-AssignedAuthNPolicy', str(policy.dn))

        # Show that a network SamLogon to ourselves fails, despite
        # authentication being allowed in the Kerberos case.
        self._test_samlogon(
            creds=client_creds,
            domain_joined_mach_creds=client_creds,
            logon_type=netlogon.NetlogonNetworkInformation,
            expect_error=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)

        self.check_samlogon_network_log(
            client_creds,
            client_policy=policy,
            server_policy=policy,
            server_policy_status=ntstatus.NT_STATUS_AUTHENTICATION_FIREWALL_FAILED,
            event=AuditEvent.NTLM_SERVER_RESTRICTION,
            reason=AuditReason.ACCESS_DENIED)

    def test_samlogon_allowed_to_computer_derived_class_allow(self):
        samdb = self.get_samdb()

        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       ntlm=True)

        # Create an authentication policy that applies to a computer and
        # explicitly allows the user account to obtain a service ticket.
        allowed = f'O:SYD:(A;;CR;;;{client_creds.get_sid()})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
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
                'msDS-AssignedAuthNPolicy': str(policy.dn),
                'objectClass': computer_class,
            })

        keys = self.get_keys(target_creds)
        self.creds_set_keys(target_creds, keys)

        # Show that a network SamLogon succeeds.
        self._test_samlogon(creds=client_creds,
                            domain_joined_mach_creds=target_creds,
                            logon_type=netlogon.NetlogonNetworkInformation)

        self.check_samlogon_network_log(client_creds,
                                        server_policy=policy)

        # Show that an interactive SamLogon succeeds.
        self._test_samlogon(creds=client_creds,
                            domain_joined_mach_creds=target_creds,
                            logon_type=netlogon.NetlogonInteractiveInformation)

        self.check_samlogon_interactive_log(client_creds,
                                            server_policy=policy)

    def test_samlogon_allowed_to_service_derived_class_allow(self):
        samdb = self.get_samdb()

        # Create a user account.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       ntlm=True)

        # Create an authentication policy that applies to a managed service and
        # explicitly allows the user account to obtain a service ticket.
        allowed = f'O:SYD:(A;;CR;;;{client_creds.get_sid()})'
        denied = 'O:SYD:(D;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
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
                'msDS-AssignedAuthNPolicy': str(policy.dn),
                'objectClass': service_class,
            })

        # Show that a network SamLogon succeeds.
        self._test_samlogon(creds=client_creds,
                            domain_joined_mach_creds=target_creds,
                            logon_type=netlogon.NetlogonNetworkInformation)

        self.check_samlogon_network_log(client_creds,
                                        server_policy=policy)

        # Show that an interactive SamLogon succeeds.
        self._test_samlogon(creds=client_creds,
                            domain_joined_mach_creds=target_creds,
                            logon_type=netlogon.NetlogonInteractiveInformation)

        self.check_samlogon_interactive_log(client_creds,
                                            server_policy=policy)

    def test_samlogon_bad_pwd_client_policy(self):
        # Create an authentication policy with device restrictions for users.
        allowed = 'O:SY'
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_from=allowed)

        # Create a user account with the assigned policy. Use a non-cached
        # account so that it is not locked out for other tests.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy,
                                       ntlm=True,
                                       cached=False)

        # Set a wrong password.
        client_creds.set_password('wrong password')

        # Show that a network SamLogon fails.
        self._test_samlogon(
            creds=client_creds,
            logon_type=netlogon.NetlogonNetworkInformation,
            expect_error=ntstatus.NT_STATUS_ACCOUNT_RESTRICTION)

        self.check_samlogon_network_log(
            client_creds,
            client_policy=policy,
            client_policy_status=ntstatus.NT_STATUS_ACCOUNT_RESTRICTION,
            event=AuditEvent.NTLM_DEVICE_RESTRICTION)

        # Show that an interactive SamLogon fails.
        self._test_samlogon(
            creds=client_creds,
            logon_type=netlogon.NetlogonInteractiveInformation,
            expect_error=ntstatus.NT_STATUS_ACCOUNT_RESTRICTION)

        self.check_samlogon_interactive_log(
            client_creds,
            client_policy=policy,
            client_policy_status=ntstatus.NT_STATUS_ACCOUNT_RESTRICTION,
            event=AuditEvent.NTLM_DEVICE_RESTRICTION)

    def test_samlogon_bad_pwd_server_policy(self):
        # Create a user account. Use a non-cached account so that it is not
        # locked out for other tests.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       ntlm=True,
                                       cached=False)

        # Create an authentication policy that applies to a computer and
        # explicitly denies the user account to obtain a service ticket.
        denied = f'O:SYD:(D;;CR;;;{client_creds.get_sid()})'
        allowed = 'O:SYD:(A;;CR;;;WD)'
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_to=allowed,
                                          computer_allowed_to=denied,
                                          service_allowed_to=allowed)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=policy)

        # Set a wrong password.
        client_creds.set_password('wrong password')

        # Show that a network SamLogon fails.
        self._test_samlogon(
            creds=client_creds,
            domain_joined_mach_creds=target_creds,
            logon_type=netlogon.NetlogonNetworkInformation,
            expect_error=ntstatus.NT_STATUS_WRONG_PASSWORD)

        self.check_samlogon_network_log(
            client_creds,
            # The bad password failure takes precedence, and no policy appears
            # in the log.
            server_policy=None,
            status=ntstatus.NT_STATUS_WRONG_PASSWORD)

        # Show that an interactive SamLogon fails.
        self._test_samlogon(
            creds=client_creds,
            domain_joined_mach_creds=target_creds,
            logon_type=netlogon.NetlogonInteractiveInformation,
            expect_error=ntstatus.NT_STATUS_WRONG_PASSWORD)

        self.check_samlogon_interactive_log(
            client_creds,
            # The bad password failure takes precedence, and no policy appears
            # in the log.
            server_policy=None,
            status=ntstatus.NT_STATUS_WRONG_PASSWORD)

    def test_samlogon_bad_pwd_client_and_server_policy(self):
        # Create an authentication policy with device restrictions for users.
        allowed = 'O:SY'
        policy = self.create_authn_policy(enforced=True,
                                          user_allowed_from=allowed)

        # Create a user account with the assigned policy. Use a non-cached
        # account so that it is not locked out for other tests.
        client_creds = self._get_creds(account_type=self.AccountType.USER,
                                       assigned_policy=policy,
                                       ntlm=True,
                                       cached=False)

        # Create an authentication policy that applies to a computer and
        # explicitly denies the user account to obtain a service ticket.
        denied = f'O:SYD:(D;;CR;;;{client_creds.get_sid()})'
        allowed = 'O:SYD:(A;;CR;;;WD)'
        server_policy = self.create_authn_policy(enforced=True,
                                                 user_allowed_to=allowed,
                                                 computer_allowed_to=denied,
                                                 service_allowed_to=allowed)

        # Create a computer account with the assigned policy.
        target_creds = self._get_creds(account_type=self.AccountType.COMPUTER,
                                       assigned_policy=server_policy)

        # Set a wrong password.
        client_creds.set_password('wrong password')

        # Show that a network SamLogon fails.
        self._test_samlogon(
            creds=client_creds,
            domain_joined_mach_creds=target_creds,
            logon_type=netlogon.NetlogonNetworkInformation,
            expect_error=ntstatus.NT_STATUS_ACCOUNT_RESTRICTION)

        self.check_samlogon_network_log(
            client_creds,
            client_policy=policy,
            client_policy_status=ntstatus.NT_STATUS_ACCOUNT_RESTRICTION,
            event=AuditEvent.NTLM_DEVICE_RESTRICTION)

        # Show that an interactive SamLogon fails.
        self._test_samlogon(
            creds=client_creds,
            domain_joined_mach_creds=target_creds,
            logon_type=netlogon.NetlogonInteractiveInformation,
            expect_error=ntstatus.NT_STATUS_ACCOUNT_RESTRICTION)

        self.check_samlogon_interactive_log(
            client_creds,
            client_policy=policy,
            client_policy_status=ntstatus.NT_STATUS_ACCOUNT_RESTRICTION,
            event=AuditEvent.NTLM_DEVICE_RESTRICTION)

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
