#!/usr/bin/env python3
# Unix SMB/CIFS implementation.
# Copyright (C) Stefan Metzmacher 2020
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
import functools

sys.path.insert(0, "bin/python")
os.environ["PYTHONUNBUFFERED"] = "1"

from samba import ntstatus
from samba.dcerpc import krb5pac, lsa

from samba.tests import env_get_var_value
from samba.tests.krb5.kcrypto import Cksumtype, Enctype
from samba.tests.krb5.kdc_base_test import KDCBaseTest
from samba.tests.krb5.raw_testcase import (
    RodcPacEncryptionKey,
    ZeroedChecksumKey
)
from samba.tests.krb5.rfc4120_constants import (
    AES256_CTS_HMAC_SHA1_96,
    ARCFOUR_HMAC_MD5,
    KDC_ERR_BADOPTION,
    KDC_ERR_BAD_INTEGRITY,
    KDC_ERR_GENERIC,
    KDC_ERR_INAPP_CKSUM,
    KDC_ERR_MODIFIED,
    KDC_ERR_SUMTYPE_NOSUPP,
    KU_PA_ENC_TIMESTAMP,
    KU_AS_REP_ENC_PART,
    KU_TGS_REP_ENC_PART_SUB_KEY,
    NT_PRINCIPAL
)
import samba.tests.krb5.rfc4120_pyasn1 as krb5_asn1

global_asn1_print = False
global_hexdump = False


class S4UKerberosTests(KDCBaseTest):

    def setUp(self):
        super(S4UKerberosTests, self).setUp()
        self.do_asn1_print = global_asn1_print
        self.do_hexdump = global_hexdump

    def _test_s4u2self(self, pa_s4u2self_ctype=None):
        service_creds = self.get_service_creds()
        service = service_creds.get_username()
        realm = service_creds.get_realm()

        cname = self.PrincipalName_create(name_type=1, names=[service])
        sname = self.PrincipalName_create(name_type=2, names=["krbtgt", realm])

        till = self.get_KerberosTime(offset=36000)

        kdc_options = krb5_asn1.KDCOptions('forwardable')
        padata = None

        etypes = (18, 17, 23)

        req = self.AS_REQ_create(padata=padata,
                                 kdc_options=str(kdc_options),
                                 cname=cname,
                                 realm=realm,
                                 sname=sname,
                                 from_time=None,
                                 till_time=till,
                                 renew_time=None,
                                 nonce=0x7fffffff,
                                 etypes=etypes,
                                 addresses=None,
                                 additional_tickets=None)
        rep = self.send_recv_transaction(req)
        self.assertIsNotNone(rep)

        self.assertEqual(rep['msg-type'], 30)
        self.assertEqual(rep['error-code'], 25)
        rep_padata = self.der_decode(
            rep['e-data'], asn1Spec=krb5_asn1.METHOD_DATA())

        for pa in rep_padata:
            if pa['padata-type'] == 19:
                etype_info2 = pa['padata-value']
                break

        etype_info2 = self.der_decode(
            etype_info2, asn1Spec=krb5_asn1.ETYPE_INFO2())

        key = self.PasswordKey_from_etype_info2(service_creds, etype_info2[0])

        (patime, pausec) = self.get_KerberosTimeWithUsec()
        pa_ts = self.PA_ENC_TS_ENC_create(patime, pausec)
        pa_ts = self.der_encode(pa_ts, asn1Spec=krb5_asn1.PA_ENC_TS_ENC())

        pa_ts = self.EncryptedData_create(key, KU_PA_ENC_TIMESTAMP, pa_ts)
        pa_ts = self.der_encode(pa_ts, asn1Spec=krb5_asn1.EncryptedData())

        pa_ts = self.PA_DATA_create(2, pa_ts)

        kdc_options = krb5_asn1.KDCOptions('forwardable')
        padata = [pa_ts]

        req = self.AS_REQ_create(padata=padata,
                                 kdc_options=str(kdc_options),
                                 cname=cname,
                                 realm=realm,
                                 sname=sname,
                                 from_time=None,
                                 till_time=till,
                                 renew_time=None,
                                 nonce=0x7fffffff,
                                 etypes=etypes,
                                 addresses=None,
                                 additional_tickets=None)
        rep = self.send_recv_transaction(req)
        self.assertIsNotNone(rep)

        msg_type = rep['msg-type']
        self.assertEqual(msg_type, 11)

        enc_part2 = key.decrypt(KU_AS_REP_ENC_PART, rep['enc-part']['cipher'])
        # MIT KDC encodes both EncASRepPart and EncTGSRepPart with
        # application tag 26
        try:
            enc_part2 = self.der_decode(
                enc_part2, asn1Spec=krb5_asn1.EncASRepPart())
        except Exception:
            enc_part2 = self.der_decode(
                enc_part2, asn1Spec=krb5_asn1.EncTGSRepPart())

        # S4U2Self Request
        sname = cname

        for_user_name = env_get_var_value('FOR_USER')
        uname = self.PrincipalName_create(name_type=1, names=[for_user_name])

        kdc_options = krb5_asn1.KDCOptions('forwardable')
        till = self.get_KerberosTime(offset=36000)
        ticket = rep['ticket']
        ticket_session_key = self.EncryptionKey_import(enc_part2['key'])
        pa_s4u = self.PA_S4U2Self_create(name=uname, realm=realm,
                                         tgt_session_key=ticket_session_key,
                                         ctype=pa_s4u2self_ctype)
        padata = [pa_s4u]

        subkey = self.RandomKey(ticket_session_key.etype)

        (ctime, cusec) = self.get_KerberosTimeWithUsec()

        req = self.TGS_REQ_create(padata=padata,
                                  cusec=cusec,
                                  ctime=ctime,
                                  ticket=ticket,
                                  kdc_options=str(kdc_options),
                                  cname=cname,
                                  realm=realm,
                                  sname=sname,
                                  from_time=None,
                                  till_time=till,
                                  renew_time=None,
                                  nonce=0x7ffffffe,
                                  etypes=etypes,
                                  addresses=None,
                                  EncAuthorizationData=None,
                                  EncAuthorizationData_key=None,
                                  additional_tickets=None,
                                  ticket_session_key=ticket_session_key,
                                  authenticator_subkey=subkey)
        rep = self.send_recv_transaction(req)
        self.assertIsNotNone(rep)

        msg_type = rep['msg-type']
        if msg_type == 13:
            enc_part2 = subkey.decrypt(
                KU_TGS_REP_ENC_PART_SUB_KEY, rep['enc-part']['cipher'])
            enc_part2 = self.der_decode(
                enc_part2, asn1Spec=krb5_asn1.EncTGSRepPart())

        return msg_type

    # Using the checksum type from the tgt_session_key happens to work
    # everywhere
    def test_s4u2self(self):
        msg_type = self._test_s4u2self()
        self.assertEqual(msg_type, 13)

    # Per spec, the checksum of PA-FOR-USER is HMAC_MD5, see [MS-SFU] 2.2.1
    def test_s4u2self_hmac_md5_checksum(self):
        msg_type = self._test_s4u2self(pa_s4u2self_ctype=Cksumtype.HMAC_MD5)
        self.assertEqual(msg_type, 13)

    def test_s4u2self_md5_unkeyed_checksum(self):
        msg_type = self._test_s4u2self(pa_s4u2self_ctype=Cksumtype.MD5)
        self.assertEqual(msg_type, 30)

    def test_s4u2self_sha1_unkeyed_checksum(self):
        msg_type = self._test_s4u2self(pa_s4u2self_ctype=Cksumtype.SHA1)
        self.assertEqual(msg_type, 30)

    def test_s4u2self_crc32_unkeyed_checksum(self):
        msg_type = self._test_s4u2self(pa_s4u2self_ctype=Cksumtype.CRC32)
        self.assertEqual(msg_type, 30)

    def _run_s4u2self_test(self, kdc_dict):
        client_opts = kdc_dict.pop('client_opts', None)
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER,
            opts=client_opts)

        service_opts = kdc_dict.pop('service_opts', None)
        service_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts=service_opts)

        service_tgt = self.get_tgt(service_creds)
        modify_service_tgt_fn = kdc_dict.pop('modify_service_tgt_fn', None)
        if modify_service_tgt_fn is not None:
            service_tgt = modify_service_tgt_fn(service_tgt)

        client_name = client_creds.get_username()
        client_cname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                                 names=[client_name])

        samdb = self.get_samdb()
        client_dn = client_creds.get_dn()
        sid = self.get_objectSid(samdb, client_dn)

        service_name = service_creds.get_username()[:-1]
        service_sname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                                  names=['host', service_name])

        realm = client_creds.get_realm()

        expected_flags = kdc_dict.pop('expected_flags', None)
        if expected_flags is not None:
            expected_flags = krb5_asn1.TicketFlags(expected_flags)

        unexpected_flags = kdc_dict.pop('unexpected_flags', None)
        if unexpected_flags is not None:
            unexpected_flags = krb5_asn1.TicketFlags(unexpected_flags)

        kdc_options = kdc_dict.pop('kdc_options', '0')
        kdc_options = krb5_asn1.KDCOptions(kdc_options)

        service_decryption_key = self.TicketDecryptionKey_from_creds(
            service_creds)

        authenticator_subkey = self.RandomKey(Enctype.AES256)

        etypes = kdc_dict.pop('etypes', (AES256_CTS_HMAC_SHA1_96,
                                         ARCFOUR_HMAC_MD5))

        def generate_s4u2self_padata(_kdc_exchange_dict,
                                     _callback_dict,
                                     req_body):
            pa_s4u = self.PA_S4U2Self_create(
                name=client_cname,
                realm=realm,
                tgt_session_key=service_tgt.session_key,
                ctype=None)

            return [pa_s4u], req_body

        kdc_exchange_dict = self.tgs_exchange_dict(
            expected_crealm=realm,
            expected_cname=client_cname,
            expected_srealm=realm,
            expected_sname=service_sname,
            expected_account_name=client_name,
            expected_sid=sid,
            expected_flags=expected_flags,
            unexpected_flags=unexpected_flags,
            ticket_decryption_key=service_decryption_key,
            expect_ticket_checksum=True,
            generate_padata_fn=generate_s4u2self_padata,
            check_rep_fn=self.generic_check_kdc_rep,
            check_kdc_private_fn=self.generic_check_kdc_private,
            expected_error_mode=0,
            tgt=service_tgt,
            authenticator_subkey=authenticator_subkey,
            kdc_options=str(kdc_options),
            expect_claims=False)

        self._generic_kdc_exchange(kdc_exchange_dict,
                                   cname=None,
                                   realm=realm,
                                   sname=service_sname,
                                   etypes=etypes)

        # Ensure we used all the parameters given to us.
        self.assertEqual({}, kdc_dict)

    # Test performing an S4U2Self operation with a forwardable ticket. The
    # resulting ticket should have the 'forwardable' flag set.
    def test_s4u2self_forwardable(self):
        self._run_s4u2self_test(
            {
                'client_opts': {
                    'not_delegated': False
                },
                'kdc_options': 'forwardable',
                'modify_service_tgt_fn': functools.partial(
                    self.set_ticket_forwardable, flag=True),
                'expected_flags': 'forwardable'
            })

    # Test performing an S4U2Self operation without requesting a forwardable
    # ticket. The resulting ticket should not have the 'forwardable' flag set.
    def test_s4u2self_without_forwardable(self):
        self._run_s4u2self_test(
            {
                'client_opts': {
                    'not_delegated': False
                },
                'modify_service_tgt_fn': functools.partial(
                    self.set_ticket_forwardable, flag=True),
                'unexpected_flags': 'forwardable'
            })

    # Do an S4U2Self with a non-forwardable TGT. The 'forwardable' flag should
    # not be set on the ticket.
    def test_s4u2self_not_forwardable(self):
        self._run_s4u2self_test(
            {
                'client_opts': {
                    'not_delegated': False
                },
                'kdc_options': 'forwardable',
                'modify_service_tgt_fn': functools.partial(
                    self.set_ticket_forwardable, flag=False),
                'unexpected_flags': 'forwardable'
            })

    # Do an S4U2Self with the not_delegated flag set on the client. The
    # 'forwardable' flag should not be set on the ticket.
    def test_s4u2self_client_not_delegated(self):
        self._run_s4u2self_test(
            {
                'client_opts': {
                    'not_delegated': True
                },
                'kdc_options': 'forwardable',
                'modify_service_tgt_fn': functools.partial(
                    self.set_ticket_forwardable, flag=True),
                'unexpected_flags': 'forwardable'
            })

    # Do an S4U2Self with a service not trusted to authenticate for delegation,
    # but having an empty msDS-AllowedToDelegateTo attribute. The 'forwardable'
    # flag should be set on the ticket.
    def test_s4u2self_not_trusted_empty_allowed(self):
        self._run_s4u2self_test(
            {
                'client_opts': {
                    'not_delegated': False
                },
                'service_opts': {
                    'trusted_to_auth_for_delegation': False,
                    'delegation_to_spn': ()
                },
                'kdc_options': 'forwardable',
                'modify_service_tgt_fn': functools.partial(
                    self.set_ticket_forwardable, flag=True),
                'expected_flags': 'forwardable'
            })

    # Do an S4U2Self with a service not trusted to authenticate for delegation
    # and having a non-empty msDS-AllowedToDelegateTo attribute. The
    # 'forwardable' flag should not be set on the ticket.
    def test_s4u2self_not_trusted_nonempty_allowed(self):
        self._run_s4u2self_test(
            {
                'client_opts': {
                    'not_delegated': False
                },
                'service_opts': {
                    'trusted_to_auth_for_delegation': False,
                    'delegation_to_spn': ('test',)
                },
                'kdc_options': 'forwardable',
                'modify_service_tgt_fn': functools.partial(
                    self.set_ticket_forwardable, flag=True),
                'unexpected_flags': 'forwardable'
            })

    # Do an S4U2Self with a service trusted to authenticate for delegation and
    # having an empty msDS-AllowedToDelegateTo attribute. The 'forwardable'
    # flag should be set on the ticket.
    def test_s4u2self_trusted_empty_allowed(self):
        self._run_s4u2self_test(
            {
                'client_opts': {
                    'not_delegated': False
                },
                'service_opts': {
                    'trusted_to_auth_for_delegation': True,
                    'delegation_to_spn': ()
                },
                'kdc_options': 'forwardable',
                'modify_service_tgt_fn': functools.partial(
                    self.set_ticket_forwardable, flag=True),
                'expected_flags': 'forwardable'
            })

    # Do an S4U2Self with a service trusted to authenticate for delegation and
    # having a non-empty msDS-AllowedToDelegateTo attribute. The 'forwardable'
    # flag should be set on the ticket.
    def test_s4u2self_trusted_nonempty_allowed(self):
        self._run_s4u2self_test(
            {
                'client_opts': {
                    'not_delegated': False
                },
                'service_opts': {
                    'trusted_to_auth_for_delegation': True,
                    'delegation_to_spn': ('test',)
                },
                'kdc_options': 'forwardable',
                'modify_service_tgt_fn': functools.partial(
                    self.set_ticket_forwardable, flag=True),
                'expected_flags': 'forwardable'
            })

    def _run_delegation_test(self, kdc_dict):
        client_opts = kdc_dict.pop('client_opts', None)
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER,
            opts=client_opts)

        samdb = self.get_samdb()
        client_dn = client_creds.get_dn()
        sid = self.get_objectSid(samdb, client_dn)

        service1_opts = kdc_dict.pop('service1_opts', {})
        service2_opts = kdc_dict.pop('service2_opts', {})

        allow_delegation = kdc_dict.pop('allow_delegation', False)
        allow_rbcd = kdc_dict.pop('allow_rbcd', False)
        self.assertFalse(allow_delegation and allow_rbcd)

        if allow_rbcd:
            service1_creds = self.get_cached_creds(
                account_type=self.AccountType.COMPUTER,
                opts=service1_opts)

            self.assertNotIn('delegation_from_dn', service2_opts)
            service2_opts['delegation_from_dn'] = str(service1_creds.get_dn())

            service2_creds = self.get_cached_creds(
                account_type=self.AccountType.COMPUTER,
                opts=service2_opts)
        else:
            service2_creds = self.get_cached_creds(
                account_type=self.AccountType.COMPUTER,
                opts=service2_opts)

            if allow_delegation:
                self.assertNotIn('delegation_to_spn', service1_opts)
                service1_opts['delegation_to_spn'] = service2_creds.get_spn()

            service1_creds = self.get_cached_creds(
                account_type=self.AccountType.COMPUTER,
                opts=service1_opts)

        client_tkt_options = kdc_dict.pop('client_tkt_options', 'forwardable')
        expected_flags = krb5_asn1.TicketFlags(client_tkt_options)

        client_tgt = self.get_tgt(client_creds,
                                  kdc_options=client_tkt_options,
                                  expected_flags=expected_flags)
        client_service_tkt = self.get_service_ticket(
            client_tgt,
            service1_creds,
            kdc_options=client_tkt_options,
            expected_flags=expected_flags)

        service1_tgt = self.get_tgt(service1_creds)

        modify_client_tkt_fn = kdc_dict.pop('modify_client_tkt_fn', None)
        if modify_client_tkt_fn is not None:
            client_service_tkt = modify_client_tkt_fn(client_service_tkt)

        additional_tickets = [client_service_tkt.ticket]

        modify_service_tgt_fn = kdc_dict.pop('modify_service_tgt_fn', None)
        if modify_service_tgt_fn is not None:
            service1_tgt = modify_service_tgt_fn(service1_tgt)

        kdc_options = kdc_dict.pop('kdc_options', None)
        if kdc_options is None:
            kdc_options = str(krb5_asn1.KDCOptions('cname-in-addl-tkt'))

        client_username = client_creds.get_username()
        client_realm = client_creds.get_realm()
        client_cname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                                 names=[client_username])

        service1_name = service1_creds.get_username()[:-1]
        service1_realm = service1_creds.get_realm()

        service2_name = service2_creds.get_username()[:-1]
        service2_realm = service2_creds.get_realm()
        service2_service = 'host'
        service2_sname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL, names=[service2_service,
                                           service2_name])
        service2_decryption_key = self.TicketDecryptionKey_from_creds(
            service2_creds)
        service2_etypes = service2_creds.tgs_supported_enctypes

        expected_error_mode = kdc_dict.pop('expected_error_mode')
        expected_status = kdc_dict.pop('expected_status', None)
        if expected_error_mode:
            check_error_fn = self.generic_check_kdc_error
            check_rep_fn = None
        else:
            check_error_fn = None
            check_rep_fn = self.generic_check_kdc_rep

            self.assertIsNone(expected_status)

        expect_edata = kdc_dict.pop('expect_edata', None)
        if expect_edata is not None:
            self.assertTrue(expected_error_mode)

        pac_options = kdc_dict.pop('pac_options', None)

        authenticator_subkey = self.RandomKey(Enctype.AES256)

        etypes = kdc_dict.pop('etypes', (AES256_CTS_HMAC_SHA1_96,
                                         ARCFOUR_HMAC_MD5))

        expected_proxy_target = service2_creds.get_spn()

        expected_transited_services = kdc_dict.pop(
            'expected_transited_services', [])

        transited_service = f'host/{service1_name}@{service1_realm}'
        expected_transited_services.append(transited_service)

        expect_pac = kdc_dict.pop('expect_pac', True)

        kdc_exchange_dict = self.tgs_exchange_dict(
            expected_crealm=client_realm,
            expected_cname=client_cname,
            expected_srealm=service2_realm,
            expected_sname=service2_sname,
            expected_account_name=client_username,
            expected_sid=sid,
            expected_supported_etypes=service2_etypes,
            ticket_decryption_key=service2_decryption_key,
            check_error_fn=check_error_fn,
            check_rep_fn=check_rep_fn,
            check_kdc_private_fn=self.generic_check_kdc_private,
            expected_error_mode=expected_error_mode,
            expected_status=expected_status,
            callback_dict={},
            tgt=service1_tgt,
            authenticator_subkey=authenticator_subkey,
            kdc_options=kdc_options,
            pac_options=pac_options,
            expect_edata=expect_edata,
            expected_proxy_target=expected_proxy_target,
            expected_transited_services=expected_transited_services,
            expect_pac=expect_pac)

        self._generic_kdc_exchange(kdc_exchange_dict,
                                   cname=None,
                                   realm=service2_realm,
                                   sname=service2_sname,
                                   etypes=etypes,
                                   additional_tickets=additional_tickets)

        # Ensure we used all the parameters given to us.
        self.assertEqual({}, kdc_dict)

    def test_constrained_delegation(self):
        # Test constrained delegation.
        self._run_delegation_test(
            {
                'expected_error_mode': 0,
                'allow_delegation': True
            })

    def test_constrained_delegation_no_auth_data_required(self):
        # Test constrained delegation.
        self._run_delegation_test(
            {
                'expected_error_mode': 0,
                'allow_delegation': True,
                'service2_opts': {
                    'no_auth_data_required': True
                },
                'expect_pac': False
            })

    def test_constrained_delegation_existing_delegation_info(self):
        # Test constrained delegation with an existing S4U_DELEGATION_INFO
        # structure in the PAC.

        services = ['service1', 'service2', 'service3']

        self._run_delegation_test(
            {
                'expected_error_mode': 0,
                'allow_delegation': True,
                'modify_client_tkt_fn': functools.partial(
                    self.add_delegation_info, services=services),
                'expected_transited_services': services
            })

    def test_constrained_delegation_not_allowed(self):
        # Test constrained delegation when the delegating service does not
        # allow it.
        self._run_delegation_test(
            {
                'expected_error_mode': KDC_ERR_BADOPTION,
                'expected_status': ntstatus.NT_STATUS_NOT_SUPPORTED,
                'allow_delegation': False
            })

    def test_constrained_delegation_no_client_pac(self):
        # Test constrained delegation when the client service ticket does not
        # contain a PAC.
        self._run_delegation_test(
            {
                'expected_error_mode': (KDC_ERR_BADOPTION,
                                        KDC_ERR_MODIFIED),
                'allow_delegation': True,
                'modify_client_tkt_fn': self.remove_ticket_pac,
                'expect_edata': False
            })

    def test_constrained_delegation_no_service_pac(self):
        # Test constrained delegation when the service TGT does not contain a
        # PAC.
        self._run_delegation_test(
            {
                'expected_error_mode': 0,
                'allow_delegation': True,
                'modify_service_tgt_fn': self.remove_ticket_pac
            })

    def test_constrained_delegation_no_client_pac_no_auth_data_required(self):
        # Test constrained delegation when the client service ticket does not
        # contain a PAC.
        self._run_delegation_test(
            {
                'expected_error_mode': (KDC_ERR_BADOPTION,
                                        KDC_ERR_MODIFIED),
                'allow_delegation': True,
                'modify_client_tkt_fn': self.remove_ticket_pac,
                'expect_edata': False,
                'service2_opts': {
                    'no_auth_data_required': True
                }
            })

    def test_constrained_delegation_no_service_pac_no_auth_data_required(self):
        # Test constrained delegation when the service TGT does not contain a
        # PAC.
        self._run_delegation_test(
            {
                'expected_error_mode': (KDC_ERR_BADOPTION,
                                        KDC_ERR_MODIFIED),
                'allow_delegation': True,
                'modify_service_tgt_fn': self.remove_ticket_pac,
                'service2_opts': {
                    'no_auth_data_required': True
                }
            })

    def test_constrained_delegation_non_forwardable(self):
        # Test constrained delegation with a non-forwardable ticket.
        self._run_delegation_test(
            {
                'expected_error_mode': KDC_ERR_BADOPTION,
                'expected_status': ntstatus.NT_STATUS_ACCOUNT_RESTRICTION,
                'allow_delegation': True,
                'modify_client_tkt_fn': functools.partial(
                    self.set_ticket_forwardable, flag=False)
            })

    def test_constrained_delegation_pac_options_rbcd(self):
        # Test constrained delegation, but with the RBCD bit set in the PAC
        # options.
        self._run_delegation_test(
            {
                'expected_error_mode': 0,
                'pac_options': '0001',  # supports RBCD
                'allow_delegation': True
            })

    def test_rbcd_no_auth_data_required(self):
        self._run_delegation_test(
            {
                'expected_error_mode': 0,
                'allow_rbcd': True,
                'pac_options': '0001',  # supports RBCD
                'service2_opts': {
                    'no_auth_data_required': True
                },
                'expect_pac': False
            })

    def test_rbcd_existing_delegation_info(self):
        # Test constrained delegation with an existing S4U_DELEGATION_INFO
        # structure in the PAC.

        services = ['service1', 'service2', 'service3']

        self._run_delegation_test(
            {
                'expected_error_mode': 0,
                'allow_rbcd': True,
                'pac_options': '0001',  # supports RBCD
                'modify_client_tkt_fn': functools.partial(
                    self.add_delegation_info, services=services),
                'expected_transited_services': services
            })

    def test_rbcd_not_allowed(self):
        # Test resource-based constrained delegation when the target service
        # does not allow it.
        self._run_delegation_test(
            {
                'expected_error_mode': KDC_ERR_BADOPTION,
                'expected_status': ntstatus.NT_STATUS_NOT_FOUND,
                'allow_rbcd': False,
                'pac_options': '0001'  # supports RBCD
            })

    def test_rbcd_no_client_pac_a(self):
        # Test constrained delegation when the client service ticket does not
        # contain a PAC, and an empty msDS-AllowedToDelegateTo attribute.
        self._run_delegation_test(
            {
                'expected_error_mode': KDC_ERR_MODIFIED,
                'expected_status': ntstatus.NT_STATUS_NOT_SUPPORTED,
                'allow_rbcd': True,
                'pac_options': '0001',  # supports RBCD
                'modify_client_tkt_fn': self.remove_ticket_pac
            })

    def test_rbcd_no_client_pac_b(self):
        # Test constrained delegation when the client service ticket does not
        # contain a PAC, and a non-empty msDS-AllowedToDelegateTo attribute.
        self._run_delegation_test(
            {
                'expected_error_mode': KDC_ERR_MODIFIED,
                'expected_status': ntstatus.NT_STATUS_NO_MATCH,
                'allow_rbcd': True,
                'pac_options': '0001',  # supports RBCD
                'modify_client_tkt_fn': self.remove_ticket_pac,
                'service1_opts': {
                    'delegation_to_spn': ('host/test')
                }
            })

    def test_rbcd_no_service_pac(self):
        # Test constrained delegation when the service TGT does not contain a
        # PAC.
        self._run_delegation_test(
            {
                'expected_error_mode': KDC_ERR_BADOPTION,
                'expected_status':
                    ntstatus.NT_STATUS_NOT_FOUND,
                'allow_rbcd': True,
                'pac_options': '0001',  # supports RBCD
                'modify_service_tgt_fn': self.remove_ticket_pac
            })

    def test_rbcd_no_client_pac_no_auth_data_required_a(self):
        # Test constrained delegation when the client service ticket does not
        # contain a PAC, and an empty msDS-AllowedToDelegateTo attribute.
        self._run_delegation_test(
            {
                'expected_error_mode': KDC_ERR_MODIFIED,
                'expected_status': ntstatus.NT_STATUS_NOT_SUPPORTED,
                'allow_rbcd': True,
                'pac_options': '0001',  # supports RBCD
                'modify_client_tkt_fn': self.remove_ticket_pac,
                'service2_opts': {
                    'no_auth_data_required': True
                }
            })

    def test_rbcd_no_client_pac_no_auth_data_required_b(self):
        # Test constrained delegation when the client service ticket does not
        # contain a PAC, and a non-empty msDS-AllowedToDelegateTo attribute.
        self._run_delegation_test(
            {
                'expected_error_mode': KDC_ERR_MODIFIED,
                'expected_status': ntstatus.NT_STATUS_NO_MATCH,
                'allow_rbcd': True,
                'pac_options': '0001',  # supports RBCD
                'modify_client_tkt_fn': self.remove_ticket_pac,
                'service1_opts': {
                    'delegation_to_spn': ('host/test')
                },
                'service2_opts': {
                    'no_auth_data_required': True
                }
            })

    def test_rbcd_no_service_pac_no_auth_data_required(self):
        # Test constrained delegation when the service TGT does not contain a
        # PAC.
        self._run_delegation_test(
            {
                'expected_error_mode': KDC_ERR_BADOPTION,
                'expected_status':
                    ntstatus.NT_STATUS_NOT_FOUND,
                'allow_rbcd': True,
                'pac_options': '0001',  # supports RBCD
                'modify_service_tgt_fn': self.remove_ticket_pac,
                'service2_opts': {
                    'no_auth_data_required': True
                }
            })

    def test_rbcd_non_forwardable(self):
        # Test resource-based constrained delegation with a non-forwardable
        # ticket.
        self._run_delegation_test(
            {
                'expected_error_mode': KDC_ERR_BADOPTION,
                'expected_status': ntstatus.NT_STATUS_ACCOUNT_RESTRICTION,
                'allow_rbcd': True,
                'pac_options': '0001',  # supports RBCD
                'modify_client_tkt_fn': functools.partial(
                    self.set_ticket_forwardable, flag=False)
            })

    def test_rbcd_no_pac_options_a(self):
        # Test resource-based constrained delegation without the RBCD bit set
        # in the PAC options, and an empty msDS-AllowedToDelegateTo attribute.
        self._run_delegation_test(
            {
                'expected_error_mode': KDC_ERR_BADOPTION,
                'expected_status': ntstatus.NT_STATUS_NOT_SUPPORTED,
                'allow_rbcd': True,
                'pac_options': '1'  # does not support RBCD
            })

    def test_rbcd_no_pac_options_b(self):
        # Test resource-based constrained delegation without the RBCD bit set
        # in the PAC options, and a non-empty msDS-AllowedToDelegateTo
        # attribute.
        self._run_delegation_test(
            {
                'expected_error_mode': KDC_ERR_BADOPTION,
                'expected_status': ntstatus.NT_STATUS_NO_MATCH,
                'allow_rbcd': True,
                'pac_options': '1',  # does not support RBCD
                'service1_opts': {
                    'delegation_to_spn': ('host/test')
                }
            })

    def test_bronze_bit_constrained_delegation_old_checksum(self):
        # Attempt to modify the ticket without updating the PAC checksums.
        self._run_delegation_test(
            {
                'expected_error_mode': (KDC_ERR_MODIFIED,
                                        KDC_ERR_BAD_INTEGRITY),
                'allow_delegation': True,
                'client_tkt_options': '0',  # non-forwardable ticket
                'modify_client_tkt_fn': functools.partial(
                    self.set_ticket_forwardable,
                    flag=True, update_pac_checksums=False),
                'expect_edata': False
            })

    def test_bronze_bit_rbcd_old_checksum(self):
        # Attempt to modify the ticket without updating the PAC checksums.
        self._run_delegation_test(
            {
                'expected_error_mode': KDC_ERR_MODIFIED,
                'expected_status': ntstatus.NT_STATUS_NOT_SUPPORTED,
                'allow_rbcd': True,
                'pac_options': '0001',  # supports RBCD
                'client_tkt_options': '0',  # non-forwardable ticket
                'modify_client_tkt_fn': functools.partial(
                    self.set_ticket_forwardable,
                    flag=True, update_pac_checksums=False)
            })

    def test_constrained_delegation_missing_client_checksum(self):
        # Present a user ticket without the required checksums.
        for checksum in self.pac_checksum_types:
            with self.subTest(checksum=checksum):
                if checksum == krb5pac.PAC_TYPE_TICKET_CHECKSUM:
                    expected_error_mode = (KDC_ERR_BADOPTION,
                                           KDC_ERR_MODIFIED)
                else:
                    expected_error_mode = KDC_ERR_GENERIC

                self._run_delegation_test(
                    {
                        'expected_error_mode': expected_error_mode,
                        'allow_delegation': True,
                        'modify_client_tkt_fn': functools.partial(
                            self.remove_pac_checksum, checksum=checksum),
                        'expect_edata': False
                    })

    def test_constrained_delegation_missing_service_checksum(self):
        # Present the service's ticket without the required checksums.
        for checksum in filter(lambda x: x != krb5pac.PAC_TYPE_TICKET_CHECKSUM,
                               self.pac_checksum_types):
            with self.subTest(checksum=checksum):
                self._run_delegation_test(
                    {
                        'expected_error_mode': KDC_ERR_GENERIC,
                        'expected_status':
                            ntstatus.NT_STATUS_INSUFFICIENT_RESOURCES,
                        'allow_delegation': True,
                        'modify_service_tgt_fn': functools.partial(
                            self.remove_pac_checksum, checksum=checksum)
                    })

    def test_rbcd_missing_client_checksum(self):
        # Present a user ticket without the required checksums.
        for checksum in self.pac_checksum_types:
            with self.subTest(checksum=checksum):
                if checksum == krb5pac.PAC_TYPE_TICKET_CHECKSUM:
                    expected_error_mode = KDC_ERR_MODIFIED
                else:
                    expected_error_mode = KDC_ERR_GENERIC

                self._run_delegation_test(
                    {
                        'expected_error_mode': expected_error_mode,
                        'expected_status':
                            ntstatus.NT_STATUS_NOT_SUPPORTED,
                        'allow_rbcd': True,
                        'pac_options': '0001',  # supports RBCD
                        'modify_client_tkt_fn': functools.partial(
                            self.remove_pac_checksum, checksum=checksum)
                    })

    def test_rbcd_missing_service_checksum(self):
        # Present the service's ticket without the required checksums.
        for checksum in filter(lambda x: x != krb5pac.PAC_TYPE_TICKET_CHECKSUM,
                               self.pac_checksum_types):
            with self.subTest(checksum=checksum):
                self._run_delegation_test(
                    {
                        'expected_error_mode': KDC_ERR_GENERIC,
                        'expected_status':
                            ntstatus.NT_STATUS_INSUFFICIENT_RESOURCES,
                        'allow_rbcd': True,
                        'pac_options': '0001',  # supports RBCD
                        'modify_service_tgt_fn': functools.partial(
                            self.remove_pac_checksum, checksum=checksum)
                    })

    def test_constrained_delegation_zeroed_client_checksum(self):
        # Present a user ticket with invalid checksums.
        for checksum in self.pac_checksum_types:
            with self.subTest(checksum=checksum):
                self._run_delegation_test(
                    {
                        'expected_error_mode': (KDC_ERR_MODIFIED,
                                                KDC_ERR_BAD_INTEGRITY),
                        'allow_delegation': True,
                        'modify_client_tkt_fn': functools.partial(
                            self.zeroed_pac_checksum, checksum=checksum),
                        'expect_edata': False
                    })

    def test_constrained_delegation_zeroed_service_checksum(self):
        # Present the service's ticket with invalid checksums.
        for checksum in self.pac_checksum_types:
            with self.subTest(checksum=checksum):
                if checksum == krb5pac.PAC_TYPE_SRV_CHECKSUM:
                    expected_error_mode = (KDC_ERR_MODIFIED,
                                           KDC_ERR_BAD_INTEGRITY)
                    expected_status = ntstatus.NT_STATUS_WRONG_PASSWORD
                else:
                    expected_error_mode = 0
                    expected_status = None

                self._run_delegation_test(
                    {
                        'expected_error_mode': expected_error_mode,
                        'expected_status': expected_status,
                        'allow_delegation': True,
                        'modify_service_tgt_fn': functools.partial(
                            self.zeroed_pac_checksum, checksum=checksum)
                    })

    def test_rbcd_zeroed_client_checksum(self):
        # Present a user ticket with invalid checksums.
        for checksum in self.pac_checksum_types:
            with self.subTest(checksum=checksum):
                self._run_delegation_test(
                    {
                        'expected_error_mode': KDC_ERR_MODIFIED,
                        'expected_status':
                            ntstatus.NT_STATUS_NOT_SUPPORTED,
                        'allow_rbcd': True,
                        'pac_options': '0001',  # supports RBCD
                        'modify_client_tkt_fn': functools.partial(
                            self.zeroed_pac_checksum, checksum=checksum)
                    })

    def test_rbcd_zeroed_service_checksum(self):
        # Present the service's ticket with invalid checksums.
        for checksum in self.pac_checksum_types:
            with self.subTest(checksum=checksum):
                if checksum == krb5pac.PAC_TYPE_SRV_CHECKSUM:
                    expected_error_mode = (KDC_ERR_MODIFIED,
                                           KDC_ERR_BAD_INTEGRITY)
                    expected_status = ntstatus.NT_STATUS_WRONG_PASSWORD
                else:
                    expected_error_mode = 0
                    expected_status = None

                self._run_delegation_test(
                    {
                        'expected_error_mode': expected_error_mode,
                        'expected_status': expected_status,
                        'allow_rbcd': True,
                        'pac_options': '0001',  # supports RBCD
                        'modify_service_tgt_fn': functools.partial(
                            self.zeroed_pac_checksum, checksum=checksum)
                    })

    unkeyed_ctypes = {Cksumtype.MD5, Cksumtype.SHA1, Cksumtype.CRC32}

    def test_constrained_delegation_unkeyed_client_checksum(self):
        # Present a user ticket with invalid checksums.
        for checksum in self.pac_checksum_types:
            for ctype in self.unkeyed_ctypes:
                with self.subTest(checksum=checksum, ctype=ctype):
                    if (checksum == krb5pac.PAC_TYPE_SRV_CHECKSUM
                            and ctype == Cksumtype.SHA1):
                        expected_error_mode = (KDC_ERR_SUMTYPE_NOSUPP,
                                               KDC_ERR_INAPP_CKSUM)
                    else:
                        expected_error_mode = (KDC_ERR_GENERIC,
                                               KDC_ERR_INAPP_CKSUM)

                    self._run_delegation_test(
                        {
                            'expected_error_mode': expected_error_mode,
                            'allow_delegation': True,
                            'modify_client_tkt_fn': functools.partial(
                                self.unkeyed_pac_checksum,
                                checksum=checksum, ctype=ctype),
                            'expect_edata': False
                        })

    def test_constrained_delegation_unkeyed_service_checksum(self):
        # Present the service's ticket with invalid checksums.
        for checksum in self.pac_checksum_types:
            for ctype in self.unkeyed_ctypes:
                with self.subTest(checksum=checksum, ctype=ctype):
                    if checksum == krb5pac.PAC_TYPE_SRV_CHECKSUM:
                        if ctype == Cksumtype.SHA1:
                            expected_error_mode = (KDC_ERR_SUMTYPE_NOSUPP,
                                                   KDC_ERR_INAPP_CKSUM)
                            expected_status = ntstatus.NT_STATUS_LOGON_FAILURE
                        else:
                            expected_error_mode = (KDC_ERR_GENERIC,
                                                   KDC_ERR_INAPP_CKSUM)
                            expected_status = (
                                ntstatus.NT_STATUS_INSUFFICIENT_RESOURCES)
                    else:
                        expected_error_mode = 0
                        expected_status = None

                    self._run_delegation_test(
                        {
                            'expected_error_mode': expected_error_mode,
                            'expected_status': expected_status,
                            'allow_delegation': True,
                            'modify_service_tgt_fn': functools.partial(
                                self.unkeyed_pac_checksum,
                                checksum=checksum, ctype=ctype)
                        })

    def test_rbcd_unkeyed_client_checksum(self):
        # Present a user ticket with invalid checksums.
        for checksum in self.pac_checksum_types:
            for ctype in self.unkeyed_ctypes:
                with self.subTest(checksum=checksum, ctype=ctype):
                    if (checksum == krb5pac.PAC_TYPE_SRV_CHECKSUM
                            and ctype == Cksumtype.SHA1):
                        expected_error_mode = KDC_ERR_SUMTYPE_NOSUPP
                    else:
                        expected_error_mode = KDC_ERR_GENERIC

                    self._run_delegation_test(
                        {
                            'expected_error_mode': expected_error_mode,
                            'expected_status':
                                ntstatus.NT_STATUS_NOT_SUPPORTED,
                            'allow_rbcd': True,
                            'pac_options': '0001',  # supports RBCD
                            'modify_client_tkt_fn': functools.partial(
                                self.unkeyed_pac_checksum,
                                checksum=checksum, ctype=ctype)
                        })

    def test_rbcd_unkeyed_service_checksum(self):
        # Present the service's ticket with invalid checksums.
        for checksum in self.pac_checksum_types:
            for ctype in self.unkeyed_ctypes:
                with self.subTest(checksum=checksum, ctype=ctype):
                    if checksum == krb5pac.PAC_TYPE_SRV_CHECKSUM:
                        if ctype == Cksumtype.SHA1:
                            expected_error_mode = (KDC_ERR_SUMTYPE_NOSUPP,
                                                   KDC_ERR_BAD_INTEGRITY)
                            expected_status = ntstatus.NT_STATUS_LOGON_FAILURE
                        else:
                            expected_error_mode = KDC_ERR_GENERIC
                            expected_status = (
                                ntstatus.NT_STATUS_INSUFFICIENT_RESOURCES)
                    else:
                        expected_error_mode = 0
                        expected_status = None

                    self._run_delegation_test(
                        {
                            'expected_error_mode': expected_error_mode,
                            'expected_status': expected_status,
                            'allow_rbcd': True,
                            'pac_options': '0001',  # supports RBCD
                            'modify_service_tgt_fn': functools.partial(
                                self.unkeyed_pac_checksum,
                                checksum=checksum, ctype=ctype)
                        })

    def remove_pac_checksum(self, ticket, checksum):
        checksum_keys = self.get_krbtgt_checksum_key()

        return self.modified_ticket(ticket,
                                    checksum_keys=checksum_keys,
                                    include_checksums={checksum: False})

    def zeroed_pac_checksum(self, ticket, checksum):
        krbtgt_creds = self.get_krbtgt_creds()
        krbtgt_key = self.TicketDecryptionKey_from_creds(krbtgt_creds)

        server_key = ticket.decryption_key

        checksum_keys = {
            krb5pac.PAC_TYPE_SRV_CHECKSUM: server_key,
            krb5pac.PAC_TYPE_KDC_CHECKSUM: krbtgt_key,
            krb5pac.PAC_TYPE_TICKET_CHECKSUM: krbtgt_key,
        }

        if checksum == krb5pac.PAC_TYPE_SRV_CHECKSUM:
            zeroed_key = server_key
        else:
            zeroed_key = krbtgt_key

        checksum_keys[checksum] = ZeroedChecksumKey(zeroed_key.key,
                                                    zeroed_key.kvno)

        return self.modified_ticket(ticket,
                                    checksum_keys=checksum_keys,
                                    include_checksums={checksum: True})

    def unkeyed_pac_checksum(self, ticket, checksum, ctype):
        krbtgt_creds = self.get_krbtgt_creds()
        krbtgt_key = self.TicketDecryptionKey_from_creds(krbtgt_creds)

        server_key = ticket.decryption_key

        checksum_keys = {
            krb5pac.PAC_TYPE_SRV_CHECKSUM: server_key,
            krb5pac.PAC_TYPE_KDC_CHECKSUM: krbtgt_key,
            krb5pac.PAC_TYPE_TICKET_CHECKSUM: krbtgt_key,
        }

        # Make a copy of the existing key and change the ctype.
        key = checksum_keys[checksum]
        new_key = RodcPacEncryptionKey(key.key, key.kvno)
        new_key.ctype = ctype
        checksum_keys[checksum] = new_key

        return self.modified_ticket(ticket,
                                    checksum_keys=checksum_keys,
                                    include_checksums={checksum: True})

    def add_delegation_info(self, ticket, services=None):
        def modify_pac_fn(pac):
            pac_buffers = pac.buffers
            self.assertNotIn(krb5pac.PAC_TYPE_CONSTRAINED_DELEGATION,
                             (buffer.type for buffer in pac_buffers))

            transited_services = list(map(lsa.String, services))

            delegation = krb5pac.PAC_CONSTRAINED_DELEGATION()
            delegation.proxy_target = lsa.String('test_proxy_target')
            delegation.transited_services = transited_services
            delegation.num_transited_services = len(transited_services)

            info = krb5pac.PAC_CONSTRAINED_DELEGATION_CTR()
            info.info = delegation

            pac_buffer = krb5pac.PAC_BUFFER()
            pac_buffer.type = krb5pac.PAC_TYPE_CONSTRAINED_DELEGATION
            pac_buffer.info = info

            pac_buffers.append(pac_buffer)

            pac.buffers = pac_buffers
            pac.num_buffers += 1

            return pac

        checksum_keys = self.get_krbtgt_checksum_key()

        return self.modified_ticket(ticket,
                                    checksum_keys=checksum_keys,
                                    modify_pac_fn=modify_pac_fn)

    def set_ticket_forwardable(self, ticket, flag, update_pac_checksums=True):
        flag = '1' if flag else '0'

        def modify_fn(enc_part):
            # Reset the forwardable flag
            forwardable_pos = (len(tuple(krb5_asn1.TicketFlags('forwardable')))
                               - 1)

            flags = enc_part['flags']
            self.assertLessEqual(forwardable_pos, len(flags))
            enc_part['flags'] = (flags[:forwardable_pos] +
                                 flag +
                                 flags[forwardable_pos+1:])

            return enc_part

        if update_pac_checksums:
            checksum_keys = self.get_krbtgt_checksum_key()
        else:
            checksum_keys = None

        return self.modified_ticket(ticket,
                                    modify_fn=modify_fn,
                                    checksum_keys=checksum_keys,
                                    update_pac_checksums=update_pac_checksums)

    def remove_ticket_pac(self, ticket):
        return self.modified_ticket(ticket,
                                    exclude_pac=True)


if __name__ == "__main__":
    global_asn1_print = False
    global_hexdump = False
    import unittest
    unittest.main()
