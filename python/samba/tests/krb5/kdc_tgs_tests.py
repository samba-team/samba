#!/usr/bin/env python3
# Unix SMB/CIFS implementation.
# Copyright (C) Stefan Metzmacher 2020
# Copyright (C) 2020 Catalyst.Net Ltd
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

sys.path.insert(0, "bin/python")
os.environ["PYTHONUNBUFFERED"] = "1"

from functools import partial

import ldb

from samba import dsdb, ntstatus

from samba.dcerpc import krb5pac, security


import samba.tests.krb5.kcrypto as kcrypto
from samba.tests.krb5.kdc_base_test import KDCBaseTest
from samba.tests.krb5.raw_testcase import Krb5EncryptionKey
from samba.tests.krb5.rfc4120_constants import (
    AES256_CTS_HMAC_SHA1_96,
    ARCFOUR_HMAC_MD5,
    FX_FAST_ARMOR_AP_REQUEST,
    KRB_ERROR,
    KDC_ERR_BADKEYVER,
    KDC_ERR_BADMATCH,
    KDC_ERR_ETYPE_NOSUPP,
    KDC_ERR_GENERIC,
    KDC_ERR_MODIFIED,
    KDC_ERR_NOT_US,
    KDC_ERR_POLICY,
    KDC_ERR_PREAUTH_REQUIRED,
    KDC_ERR_C_PRINCIPAL_UNKNOWN,
    KDC_ERR_S_PRINCIPAL_UNKNOWN,
    KDC_ERR_SERVER_NOMATCH,
    KDC_ERR_TKT_EXPIRED,
    KDC_ERR_TGT_REVOKED,
    KRB_ERR_TKT_NYV,
    KDC_ERR_WRONG_REALM,
    NT_ENTERPRISE_PRINCIPAL,
    NT_PRINCIPAL,
    NT_SRV_INST,
)
import samba.tests.krb5.rfc4120_pyasn1 as krb5_asn1

global_asn1_print = False
global_hexdump = False


class KdcTgsBaseTests(KDCBaseTest):
    def _as_req(self,
                creds,
                expected_error,
                target_creds,
                etype,
                expected_ticket_etype=None):
        user_name = creds.get_username()
        cname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                          names=user_name.split('/'))

        target_name = target_creds.get_username()
        sname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                          names=['host', target_name[:-1]])

        if expected_error:
            expected_sname = sname
        else:
            expected_sname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                                       names=[target_name])

        realm = creds.get_realm()
        salt = creds.get_salt()

        till = self.get_KerberosTime(offset=36000)

        ticket_decryption_key = (
            self.TicketDecryptionKey_from_creds(target_creds,
                                                etype=expected_ticket_etype))
        expected_etypes = target_creds.tgs_supported_enctypes

        kdc_options = ('forwardable,'
                       'renewable,'
                       'canonicalize,'
                       'renewable-ok')
        kdc_options = krb5_asn1.KDCOptions(kdc_options)

        if expected_error:
            initial_error = (KDC_ERR_PREAUTH_REQUIRED, expected_error)
        else:
            initial_error = KDC_ERR_PREAUTH_REQUIRED

        rep, kdc_exchange_dict = self._test_as_exchange(
            creds=creds,
            cname=cname,
            realm=realm,
            sname=sname,
            till=till,
            expected_error_mode=initial_error,
            expected_crealm=realm,
            expected_cname=cname,
            expected_srealm=realm,
            expected_sname=sname,
            expected_salt=salt,
            expected_supported_etypes=expected_etypes,
            etypes=etype,
            padata=None,
            kdc_options=kdc_options,
            preauth_key=None,
            ticket_decryption_key=ticket_decryption_key)
        self.assertIsNotNone(rep)
        self.assertEqual(KRB_ERROR, rep['msg-type'])
        error_code = rep['error-code']
        if expected_error:
            self.assertIn(error_code, initial_error)
            if error_code == expected_error:
                return
        else:
            self.assertEqual(initial_error, error_code)

        etype_info2 = kdc_exchange_dict['preauth_etype_info2']

        preauth_key = self.PasswordKey_from_etype_info2(creds,
                                                        etype_info2[0],
                                                        creds.get_kvno())

        ts_enc_padata = self.get_enc_timestamp_pa_data_from_key(preauth_key)

        padata = [ts_enc_padata]

        expected_realm = realm.upper()

        rep, kdc_exchange_dict = self._test_as_exchange(
            creds=creds,
            cname=cname,
            realm=realm,
            sname=sname,
            till=till,
            expected_error_mode=expected_error,
            expected_crealm=expected_realm,
            expected_cname=cname,
            expected_srealm=expected_realm,
            expected_sname=expected_sname,
            expected_salt=salt,
            expected_supported_etypes=expected_etypes,
            etypes=etype,
            padata=padata,
            kdc_options=kdc_options,
            preauth_key=preauth_key,
            ticket_decryption_key=ticket_decryption_key,
            expect_edata=False)
        if expected_error:
            self.check_error_rep(rep, expected_error)
            return None

        self.check_as_reply(rep)
        return kdc_exchange_dict['rep_ticket_creds']

    def _armored_as_req(self,
                        client_creds,
                        target_creds,
                        armor_tgt,
                        *,
                        target_sname=None,
                        expected_error=0,
                        expected_sname=None,
                        expect_edata=None,
                        expect_status=None,
                        expected_status=None,
                        expected_groups=None,
                        expect_device_info=None,
                        expected_device_groups=None,
                        expect_device_claims=None,
                        expected_device_claims=None):
        client_username = client_creds.get_username()
        client_realm = client_creds.get_realm()
        client_cname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                                 names=[client_username])

        if target_sname is None:
            target_name = target_creds.get_username()
            target_sname = self.PrincipalName_create(
                name_type=NT_PRINCIPAL, names=[target_name])
        target_realm = target_creds.get_realm()
        target_decryption_key = self.TicketDecryptionKey_from_creds(
            target_creds)
        target_etypes = target_creds.tgs_supported_enctypes

        authenticator_subkey = self.RandomKey(kcrypto.Enctype.AES256)
        armor_key = self.generate_armor_key(authenticator_subkey,
                                            armor_tgt.session_key)

        preauth_key = self.PasswordKey_from_creds(client_creds,
                                                  kcrypto.Enctype.AES256)

        client_challenge_key = (
            self.generate_client_challenge_key(armor_key, preauth_key))
        fast_padata = [self.get_challenge_pa_data(client_challenge_key)]

        def _generate_fast_padata(kdc_exchange_dict,
                                  _callback_dict,
                                  req_body):
            return list(fast_padata), req_body

        etypes = kcrypto.Enctype.AES256, kcrypto.Enctype.RC4

        if expected_error:
            check_error_fn = self.generic_check_kdc_error
            check_rep_fn = None
        else:
            check_error_fn = None
            check_rep_fn = self.generic_check_kdc_rep

        pac_options = '1'  # claims support

        samdb = self.get_samdb()
        domain_sid_str = samdb.get_domain_sid()

        if expected_groups is not None:
            expected_groups = self.map_sids(expected_groups, None, domain_sid_str)

        if expected_device_groups is not None:
            expected_device_groups = self.map_sids(expected_device_groups, None, domain_sid_str)

        if expected_sname is None:
            expected_sname = target_sname

        kdc_exchange_dict = self.as_exchange_dict(
            creds=client_creds,
            expected_crealm=client_realm,
            expected_cname=client_cname,
            expected_srealm=target_realm,
            expected_sname=expected_sname,
            expected_supported_etypes=target_etypes,
            ticket_decryption_key=target_decryption_key,
            generate_fast_fn=self.generate_simple_fast,
            generate_fast_armor_fn=self.generate_ap_req,
            generate_fast_padata_fn=_generate_fast_padata,
            fast_armor_type=FX_FAST_ARMOR_AP_REQUEST,
            check_error_fn=check_error_fn,
            check_rep_fn=check_rep_fn,
            check_kdc_private_fn=self.generic_check_kdc_private,
            expected_error_mode=expected_error,
            expected_salt=client_creds.get_salt(),
            expect_edata=expect_edata,
            expect_status=expect_status,
            expected_status=expected_status,
            expected_groups=expected_groups,
            expect_device_info=expect_device_info,
            expected_device_domain_sid=domain_sid_str,
            expected_device_groups=expected_device_groups,
            expect_device_claims=expect_device_claims,
            expected_device_claims=expected_device_claims,
            authenticator_subkey=authenticator_subkey,
            preauth_key=preauth_key,
            armor_key=armor_key,
            armor_tgt=armor_tgt,
            armor_subkey=authenticator_subkey,
            kdc_options='0',
            pac_options=pac_options,
            # PA-DATA types are not important for these tests.
            check_patypes=False)

        rep = self._generic_kdc_exchange(
            kdc_exchange_dict,
            cname=client_cname,
            realm=client_realm,
            sname=target_sname,
            etypes=etypes)
        if expected_error:
            self.check_error_rep(rep, expected_error)
            return None
        else:
            self.check_as_reply(rep)
            return kdc_exchange_dict['rep_ticket_creds']

    def _tgs_req(self, tgt, expected_error, creds, target_creds, *,
                 armor_tgt=None,
                 kdc_options='0',
                 pac_options=None,
                 expected_cname=None,
                 expected_sname=None,
                 expected_account_name=None,
                 expected_flags=None,
                 additional_ticket=None,
                 decryption_key=None,
                 generate_padata_fn=None,
                 generate_fast_padata_fn=None,
                 sname=None,
                 srealm=None,
                 till=None,
                 etypes=None,
                 expected_ticket_etype=None,
                 expected_supported_etypes=None,
                 expect_pac=True,
                 expect_pac_attrs=None,
                 expect_pac_attrs_pac_request=None,
                 expect_requester_sid=None,
                 expect_edata=False,
                 expected_sid=None,
                 expected_groups=None,
                 unexpected_groups=None,
                 expect_device_info=None,
                 expected_device_domain_sid=None,
                 expected_device_groups=None,
                 expect_client_claims=None,
                 expected_client_claims=None,
                 unexpected_client_claims=None,
                 expect_device_claims=None,
                 expected_device_claims=None,
                 expect_status=None,
                 expected_status=None,
                 expected_proxy_target=None,
                 expected_transited_services=None,
                 expected_extra_pac_buffers=None,
                 check_patypes=True):
        if srealm is False:
            srealm = None
        elif srealm is None:
            srealm = target_creds.get_realm()

        if sname is False:
            sname = None
            if expected_sname is None:
                expected_sname = self.get_krbtgt_sname()
        else:
            if sname is None:
                target_name = target_creds.get_username()
                if target_name == 'krbtgt':
                    sname = self.PrincipalName_create(
                        name_type=NT_SRV_INST,
                        names=[target_name, srealm])
                else:
                    if target_name[-1] == '$':
                        target_name = target_name[:-1]
                    sname = self.PrincipalName_create(
                        name_type=NT_PRINCIPAL,
                        names=['host', target_name])

            if expected_sname is None:
                expected_sname = sname

        if additional_ticket is not None:
            additional_tickets = [additional_ticket.ticket]
            if decryption_key is None:
                decryption_key = additional_ticket.session_key
        else:
            additional_tickets = None
            if decryption_key is None:
                decryption_key = self.TicketDecryptionKey_from_creds(
                    target_creds, etype=expected_ticket_etype)

        subkey = self.RandomKey(tgt.session_key.etype)

        if armor_tgt is not None:
            armor_subkey = self.RandomKey(subkey.etype)
            explicit_armor_key = self.generate_armor_key(armor_subkey,
                                                         armor_tgt.session_key)
            armor_key = kcrypto.cf2(explicit_armor_key.key,
                                    subkey.key,
                                    b'explicitarmor',
                                    b'tgsarmor')
            armor_key = Krb5EncryptionKey(armor_key, None)

            generate_fast_fn = self.generate_simple_fast
            generate_fast_armor_fn = self.generate_ap_req

            if pac_options is None:
                pac_options = '1'  # claims support
        else:
            armor_subkey = None
            armor_key = None
            generate_fast_fn = None
            generate_fast_armor_fn = None

        if etypes is None:
            etypes = (AES256_CTS_HMAC_SHA1_96, ARCFOUR_HMAC_MD5)

        if expected_error:
            check_error_fn = self.generic_check_kdc_error
            check_rep_fn = None
        else:
            check_error_fn = None
            check_rep_fn = self.generic_check_kdc_rep

        if expected_cname is None:
            expected_cname = tgt.cname

        kdc_exchange_dict = self.tgs_exchange_dict(
            creds=creds,
            expected_crealm=tgt.crealm,
            expected_cname=expected_cname,
            expected_srealm=srealm,
            expected_sname=expected_sname,
            expected_account_name=expected_account_name,
            expected_flags=expected_flags,
            ticket_decryption_key=decryption_key,
            generate_padata_fn=generate_padata_fn,
            generate_fast_padata_fn=generate_fast_padata_fn,
            generate_fast_fn=generate_fast_fn,
            generate_fast_armor_fn=generate_fast_armor_fn,
            check_error_fn=check_error_fn,
            check_rep_fn=check_rep_fn,
            check_kdc_private_fn=self.generic_check_kdc_private,
            expected_error_mode=expected_error,
            expect_status=expect_status,
            expected_status=expected_status,
            tgt=tgt,
            armor_key=armor_key,
            armor_tgt=armor_tgt,
            armor_subkey=armor_subkey,
            pac_options=pac_options,
            authenticator_subkey=subkey,
            kdc_options=kdc_options,
            expected_supported_etypes=expected_supported_etypes,
            expect_edata=expect_edata,
            expect_pac=expect_pac,
            expect_pac_attrs=expect_pac_attrs,
            expect_pac_attrs_pac_request=expect_pac_attrs_pac_request,
            expect_requester_sid=expect_requester_sid,
            expected_sid=expected_sid,
            expected_groups=expected_groups,
            unexpected_groups=unexpected_groups,
            expect_device_info=expect_device_info,
            expected_device_domain_sid=expected_device_domain_sid,
            expected_device_groups=expected_device_groups,
            expect_client_claims=expect_client_claims,
            expected_client_claims=expected_client_claims,
            unexpected_client_claims=unexpected_client_claims,
            expect_device_claims=expect_device_claims,
            expected_device_claims=expected_device_claims,
            expected_proxy_target=expected_proxy_target,
            expected_transited_services=expected_transited_services,
            expected_extra_pac_buffers=expected_extra_pac_buffers,
            check_patypes=check_patypes)

        rep = self._generic_kdc_exchange(kdc_exchange_dict,
                                         cname=None,
                                         realm=srealm,
                                         sname=sname,
                                         till_time=till,
                                         etypes=etypes,
                                         additional_tickets=additional_tickets)
        if expected_error:
            self.check_error_rep(rep, expected_error)
            return None
        else:
            self.check_tgs_reply(rep)
            return kdc_exchange_dict['rep_ticket_creds']


class KdcTgsTests(KdcTgsBaseTests):

    def setUp(self):
        super().setUp()
        self.do_asn1_print = global_asn1_print
        self.do_hexdump = global_hexdump

    def test_tgs_req_cname_does_not_not_match_authenticator_cname(self):
        """ Try and obtain a ticket from the TGS, but supply a cname
            that differs from that provided to the krbtgt
        """
        # Create the user account
        samdb = self.get_samdb()
        user_name = "tsttktusr"
        (uc, _) = self.create_account(samdb, user_name)
        realm = uc.get_realm().lower()

        # Do the initial AS-REQ, should get a pre-authentication required
        # response
        etype = (AES256_CTS_HMAC_SHA1_96,)
        cname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL, names=[user_name])
        sname = self.PrincipalName_create(
            name_type=NT_SRV_INST, names=["krbtgt", realm])

        rep = self.as_req(cname, sname, realm, etype)
        self.check_pre_authentication(rep)

        # Do the next AS-REQ
        padata = self.get_enc_timestamp_pa_data(uc, rep)
        key = self.get_as_rep_key(uc, rep)
        rep = self.as_req(cname, sname, realm, etype, padata=[padata])
        self.check_as_reply(rep)

        # Request a service ticket, but use a cname that does not match
        # that in the original AS-REQ
        enc_part2 = self.get_as_rep_enc_data(key, rep)
        key = self.EncryptionKey_import(enc_part2['key'])
        ticket = rep['ticket']

        cname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL,
            names=["Administrator"])
        sname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL,
            names=["host", samdb.host_dns_name()])

        (rep, enc_part) = self.tgs_req(cname, sname, realm, ticket, key, etype,
                                       creds=uc,
                                       expected_error_mode=KDC_ERR_BADMATCH,
                                       expect_edata=False)

        self.assertIsNone(
            enc_part,
            "rep = {%s}, enc_part = {%s}" % (rep, enc_part))
        self.assertEqual(KRB_ERROR, rep['msg-type'], "rep = {%s}" % rep)
        self.assertEqual(
            KDC_ERR_BADMATCH,
            rep['error-code'],
            "rep = {%s}" % rep)

    def test_ldap_service_ticket(self):
        """Get a ticket to the ldap service
        """
        # Create the user account
        samdb = self.get_samdb()
        user_name = "tsttktusr"
        (uc, _) = self.create_account(samdb, user_name)
        realm = uc.get_realm().lower()

        # Do the initial AS-REQ, should get a pre-authentication required
        # response
        etype = (AES256_CTS_HMAC_SHA1_96,)
        cname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL, names=[user_name])
        sname = self.PrincipalName_create(
            name_type=NT_SRV_INST, names=["krbtgt", realm])

        rep = self.as_req(cname, sname, realm, etype)
        self.check_pre_authentication(rep)

        # Do the next AS-REQ
        padata = self.get_enc_timestamp_pa_data(uc, rep)
        key = self.get_as_rep_key(uc, rep)
        rep = self.as_req(cname, sname, realm, etype, padata=[padata])
        self.check_as_reply(rep)

        enc_part2 = self.get_as_rep_enc_data(key, rep)
        key = self.EncryptionKey_import(enc_part2['key'])
        ticket = rep['ticket']

        # Request a ticket to the ldap service
        sname = self.PrincipalName_create(
            name_type=NT_SRV_INST,
            names=["ldap", samdb.host_dns_name()])

        (rep, _) = self.tgs_req(
            cname, sname, uc.get_realm(), ticket, key, etype,
            service_creds=self.get_dc_creds())

        self.check_tgs_reply(rep)

    def test_get_ticket_for_host_service_of_machine_account(self):

        # Create a user and machine account for the test.
        #
        samdb = self.get_samdb()
        user_name = "tsttktusr"
        (uc, dn) = self.create_account(samdb, user_name)
        (mc, _) = self.create_account(samdb, "tsttktmac",
                                      account_type=self.AccountType.COMPUTER)
        realm = uc.get_realm().lower()

        # Do the initial AS-REQ, should get a pre-authentication required
        # response
        etype = (AES256_CTS_HMAC_SHA1_96, ARCFOUR_HMAC_MD5)
        cname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL, names=[user_name])
        sname = self.PrincipalName_create(
            name_type=NT_SRV_INST, names=["krbtgt", realm])

        rep = self.as_req(cname, sname, realm, etype)
        self.check_pre_authentication(rep)

        # Do the next AS-REQ
        padata = self.get_enc_timestamp_pa_data(uc, rep)
        key = self.get_as_rep_key(uc, rep)
        rep = self.as_req(cname, sname, realm, etype, padata=[padata])
        self.check_as_reply(rep)

        # Request a ticket to the host service on the machine account
        ticket = rep['ticket']
        enc_part2 = self.get_as_rep_enc_data(key, rep)
        key = self.EncryptionKey_import(enc_part2['key'])
        cname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL,
            names=[user_name])
        sname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL,
            names=[mc.get_username()])

        (rep, enc_part) = self.tgs_req(
            cname, sname, uc.get_realm(), ticket, key, etype,
            service_creds=mc)
        self.check_tgs_reply(rep)

        # Check the contents of the service ticket
        ticket = rep['ticket']
        enc_part = self.decode_service_ticket(mc, ticket)

        pac_data = self.get_pac_data(enc_part['authorization-data'])
        sid = uc.get_sid()
        upn = "%s@%s" % (uc.get_username(), realm)
        self.assertEqual(
            uc.get_username(),
            str(pac_data.account_name),
            "rep = {%s},%s" % (rep, pac_data))
        self.assertEqual(
            uc.get_username(),
            pac_data.logon_name,
            "rep = {%s},%s" % (rep, pac_data))
        self.assertEqual(
            uc.get_realm(),
            pac_data.domain_name,
            "rep = {%s},%s" % (rep, pac_data))
        self.assertEqual(
            upn,
            pac_data.upn,
            "rep = {%s},%s" % (rep, pac_data))
        self.assertEqual(
            sid,
            pac_data.account_sid,
            "rep = {%s},%s" % (rep, pac_data))

    def test_request(self):
        client_creds = self.get_client_creds()
        service_creds = self.get_service_creds()

        tgt = self.get_tgt(client_creds)

        pac = self.get_ticket_pac(tgt)
        self.assertIsNotNone(pac)

        ticket = self._make_tgs_request(client_creds, service_creds, tgt)

        pac = self.get_ticket_pac(ticket)
        self.assertIsNotNone(pac)

    def test_request_no_pac(self):
        client_creds = self.get_client_creds()
        service_creds = self.get_service_creds()

        tgt = self.get_tgt(client_creds, pac_request=False)

        pac = self.get_ticket_pac(tgt)
        self.assertIsNotNone(pac)

        ticket = self._make_tgs_request(client_creds, service_creds, tgt,
                                        pac_request=False, expect_pac=False)

        pac = self.get_ticket_pac(ticket, expect_pac=False)
        if not self.always_include_pac:
            self.assertIsNone(pac)
        else:
            self.assertIsNotNone(pac)

    def test_request_enterprise_canon(self):
        upn = self.get_new_username()
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER,
            opts={'upn': upn})
        service_creds = self.get_service_creds()

        user_name = client_creds.get_username()
        realm = client_creds.get_realm()
        client_account = f'{user_name}@{realm}'

        expected_cname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL,
            names=[user_name])

        kdc_options = 'canonicalize'

        tgt = self.get_tgt(client_creds,
                           client_account=client_account,
                           client_name_type=NT_ENTERPRISE_PRINCIPAL,
                           expected_cname=expected_cname,
                           expected_account_name=user_name,
                           kdc_options=kdc_options)

        self._make_tgs_request(
            client_creds, service_creds, tgt,
            client_account=client_account,
            client_name_type=NT_ENTERPRISE_PRINCIPAL,
            expected_cname=expected_cname,
            expected_account_name=user_name,
            kdc_options=kdc_options)

    def test_request_enterprise_canon_case(self):
        upn = self.get_new_username()
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER,
            opts={'upn': upn})
        service_creds = self.get_service_creds()

        user_name = client_creds.get_username()
        realm = client_creds.get_realm().lower()
        client_account = f'{user_name}@{realm}'

        expected_cname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL,
            names=[user_name])

        kdc_options = 'canonicalize'

        tgt = self.get_tgt(client_creds,
                           client_account=client_account,
                           client_name_type=NT_ENTERPRISE_PRINCIPAL,
                           expected_cname=expected_cname,
                           expected_account_name=user_name,
                           kdc_options=kdc_options)

        self._make_tgs_request(
            client_creds, service_creds, tgt,
            client_account=client_account,
            client_name_type=NT_ENTERPRISE_PRINCIPAL,
            expected_cname=expected_cname,
            expected_account_name=user_name,
            kdc_options=kdc_options)

    def test_request_enterprise_canon_mac(self):
        upn = self.get_new_username()
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'upn': upn})
        service_creds = self.get_service_creds()

        user_name = client_creds.get_username()
        realm = client_creds.get_realm()
        client_account = f'{user_name}@{realm}'

        expected_cname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL,
            names=[user_name])

        kdc_options = 'canonicalize'

        tgt = self.get_tgt(client_creds,
                           client_account=client_account,
                           client_name_type=NT_ENTERPRISE_PRINCIPAL,
                           expected_cname=expected_cname,
                           expected_account_name=user_name,
                           kdc_options=kdc_options)

        self._make_tgs_request(
            client_creds, service_creds, tgt,
            client_account=client_account,
            client_name_type=NT_ENTERPRISE_PRINCIPAL,
            expected_cname=expected_cname,
            expected_account_name=user_name,
            kdc_options=kdc_options)

    def test_request_enterprise_canon_case_mac(self):
        upn = self.get_new_username()
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'upn': upn})
        service_creds = self.get_service_creds()

        user_name = client_creds.get_username()
        realm = client_creds.get_realm().lower()
        client_account = f'{user_name}@{realm}'

        expected_cname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL,
            names=[user_name])

        kdc_options = 'canonicalize'

        tgt = self.get_tgt(client_creds,
                           client_account=client_account,
                           client_name_type=NT_ENTERPRISE_PRINCIPAL,
                           expected_cname=expected_cname,
                           expected_account_name=user_name,
                           kdc_options=kdc_options)

        self._make_tgs_request(
            client_creds, service_creds, tgt,
            client_account=client_account,
            client_name_type=NT_ENTERPRISE_PRINCIPAL,
            expected_cname=expected_cname,
            expected_account_name=user_name,
            kdc_options=kdc_options)

    def test_request_enterprise_no_canon(self):
        upn = self.get_new_username()
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER,
            opts={'upn': upn})
        service_creds = self.get_service_creds()

        user_name = client_creds.get_username()
        realm = client_creds.get_realm()
        client_account = f'{user_name}@{realm}'

        kdc_options = '0'

        tgt = self.get_tgt(client_creds,
                           client_account=client_account,
                           client_name_type=NT_ENTERPRISE_PRINCIPAL,
                           expected_account_name=user_name,
                           kdc_options=kdc_options)

        self._make_tgs_request(
            client_creds, service_creds, tgt,
            client_account=client_account,
            client_name_type=NT_ENTERPRISE_PRINCIPAL,
            expected_account_name=user_name,
            kdc_options=kdc_options)

    def test_request_enterprise_no_canon_case(self):
        upn = self.get_new_username()
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER,
            opts={'upn': upn})
        service_creds = self.get_service_creds()

        user_name = client_creds.get_username()
        realm = client_creds.get_realm().lower()
        client_account = f'{user_name}@{realm}'

        kdc_options = '0'

        tgt = self.get_tgt(client_creds,
                           client_account=client_account,
                           client_name_type=NT_ENTERPRISE_PRINCIPAL,
                           expected_account_name=user_name,
                           kdc_options=kdc_options)

        self._make_tgs_request(
            client_creds, service_creds, tgt,
            client_account=client_account,
            client_name_type=NT_ENTERPRISE_PRINCIPAL,
            expected_account_name=user_name,
            kdc_options=kdc_options)

    def test_request_enterprise_no_canon_mac(self):
        upn = self.get_new_username()
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'upn': upn})
        service_creds = self.get_service_creds()

        user_name = client_creds.get_username()
        realm = client_creds.get_realm()
        client_account = f'{user_name}@{realm}'

        kdc_options = '0'

        tgt = self.get_tgt(client_creds,
                           client_account=client_account,
                           client_name_type=NT_ENTERPRISE_PRINCIPAL,
                           expected_account_name=user_name,
                           kdc_options=kdc_options)

        self._make_tgs_request(
            client_creds, service_creds, tgt,
            client_account=client_account,
            client_name_type=NT_ENTERPRISE_PRINCIPAL,
            expected_account_name=user_name,
            kdc_options=kdc_options)

    def test_request_enterprise_no_canon_case_mac(self):
        upn = self.get_new_username()
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'upn': upn})
        service_creds = self.get_service_creds()

        user_name = client_creds.get_username()
        realm = client_creds.get_realm().lower()
        client_account = f'{user_name}@{realm}'

        kdc_options = '0'

        tgt = self.get_tgt(client_creds,
                           client_account=client_account,
                           client_name_type=NT_ENTERPRISE_PRINCIPAL,
                           expected_account_name=user_name,
                           kdc_options=kdc_options)

        self._make_tgs_request(
            client_creds, service_creds, tgt,
            client_account=client_account,
            client_name_type=NT_ENTERPRISE_PRINCIPAL,
            expected_account_name=user_name,
            kdc_options=kdc_options)

    def test_client_no_auth_data_required(self):
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER,
            opts={'no_auth_data_required': True})
        service_creds = self.get_service_creds()

        tgt = self.get_tgt(client_creds)

        pac = self.get_ticket_pac(tgt)
        self.assertIsNotNone(pac)

        ticket = self._make_tgs_request(client_creds, service_creds, tgt)

        pac = self.get_ticket_pac(ticket)
        self.assertIsNotNone(pac)

    def test_no_pac_client_no_auth_data_required(self):
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER,
            opts={'no_auth_data_required': True})
        service_creds = self.get_service_creds()

        tgt = self.get_tgt(client_creds)

        pac = self.get_ticket_pac(tgt)
        self.assertIsNotNone(pac)

        ticket = self._make_tgs_request(client_creds, service_creds, tgt,
                                        pac_request=False, expect_pac=True)

        pac = self.get_ticket_pac(ticket)
        self.assertIsNotNone(pac)

    def test_service_no_auth_data_required(self):
        client_creds = self.get_client_creds()
        service_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'no_auth_data_required': True})

        tgt = self.get_tgt(client_creds)

        pac = self.get_ticket_pac(tgt)
        self.assertIsNotNone(pac)

        ticket = self._make_tgs_request(client_creds, service_creds, tgt,
                                        expect_pac=False)

        pac = self.get_ticket_pac(ticket, expect_pac=False)
        self.assertIsNone(pac)

    def test_no_pac_service_no_auth_data_required(self):
        client_creds = self.get_client_creds()
        service_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'no_auth_data_required': True})

        tgt = self.get_tgt(client_creds, pac_request=False)

        pac = self.get_ticket_pac(tgt)
        self.assertIsNotNone(pac)

        ticket = self._make_tgs_request(client_creds, service_creds, tgt,
                                        pac_request=False, expect_pac=False)

        pac = self.get_ticket_pac(ticket, expect_pac=False)
        self.assertIsNone(pac)

    def test_remove_pac_service_no_auth_data_required(self):
        client_creds = self.get_client_creds()
        service_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'no_auth_data_required': True})

        tgt = self.modified_ticket(self.get_tgt(client_creds),
                                   exclude_pac=True)

        pac = self.get_ticket_pac(tgt, expect_pac=False)
        self.assertIsNone(pac)

        self._make_tgs_request(client_creds, service_creds, tgt,
                               expect_error=True)

    def test_remove_pac_client_no_auth_data_required(self):
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER,
            opts={'no_auth_data_required': True})
        service_creds = self.get_service_creds()

        tgt = self.modified_ticket(self.get_tgt(client_creds),
                                   exclude_pac=True)

        pac = self.get_ticket_pac(tgt, expect_pac=False)
        self.assertIsNone(pac)

        self._make_tgs_request(client_creds, service_creds, tgt,
                               expect_error=True)

    def test_remove_pac(self):
        client_creds = self.get_client_creds()
        service_creds = self.get_service_creds()

        tgt = self.modified_ticket(self.get_tgt(client_creds),
                                   exclude_pac=True)

        pac = self.get_ticket_pac(tgt, expect_pac=False)
        self.assertIsNone(pac)

        self._make_tgs_request(client_creds, service_creds, tgt,
                               expect_error=True)

    def test_upn_dns_info_ex_user(self):
        client_creds = self.get_client_creds()
        self._run_upn_dns_info_ex_test(client_creds)

    def test_upn_dns_info_ex_mac(self):
        mach_creds = self.get_mach_creds()
        self._run_upn_dns_info_ex_test(mach_creds)

    def test_upn_dns_info_ex_upn_user(self):
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER,
            opts={'upn': 'upn_dns_info_test_upn0@bar'})
        self._run_upn_dns_info_ex_test(client_creds)

    def test_upn_dns_info_ex_upn_mac(self):
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'upn': 'upn_dns_info_test_upn1@bar'})
        self._run_upn_dns_info_ex_test(mach_creds)

    def _run_upn_dns_info_ex_test(self, client_creds):
        service_creds = self.get_service_creds()

        account_name = client_creds.get_username()
        upn_name = client_creds.get_upn()
        if upn_name is None:
            realm = client_creds.get_realm().lower()
            upn_name = f'{account_name}@{realm}'
        sid = client_creds.get_sid()

        tgt = self.get_tgt(client_creds,
                           expected_account_name=account_name,
                           expected_upn_name=upn_name,
                           expected_sid=sid)

        self._make_tgs_request(client_creds, service_creds, tgt,
                               expected_account_name=account_name,
                               expected_upn_name=upn_name,
                               expected_sid=sid)

    # Test making a TGS request.
    def test_tgs_req(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds)
        self._run_tgs(tgt, creds, expected_error=0)

    def test_renew_req(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds, renewable=True)
        self._renew_tgt(tgt, creds, expected_error=0,
                        expect_pac_attrs=True,
                        expect_pac_attrs_pac_request=True,
                        expect_requester_sid=True)

    def test_validate_req(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds, invalid=True)
        self._validate_tgt(tgt, creds, expected_error=0,
                           expect_pac_attrs=True,
                           expect_pac_attrs_pac_request=True,
                           expect_requester_sid=True)

    def test_s4u2self_req(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds)
        self._s4u2self(tgt, creds, expected_error=0)

    def test_user2user_req(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds)
        self._user2user(tgt, creds, expected_error=0)

    def test_user2user_user_self_req(self):
        creds = self._get_user_creds()
        tgt = self._get_tgt(creds)
        username = creds.get_username()
        sname = self.PrincipalName_create(
                        name_type=NT_PRINCIPAL,
                        names=[username])
        self._user2user(tgt, creds, sname=sname, user_tgt=tgt, user_creds=creds, expected_error=0)

    def test_user2user_computer_self_princ1_req(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds)
        username = creds.get_username()
        sname = self.PrincipalName_create(
                        name_type=NT_PRINCIPAL,
                        names=[username])
        self._user2user(tgt, creds, sname=sname, user_tgt=tgt, user_creds=creds, expected_error=0)

    def test_user2user_computer_self_princ2_req(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds)
        self._user2user(tgt, creds, user_tgt=tgt, user_creds=creds, expected_error=0)

    def test_fast_req(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds)
        self._fast(tgt, creds, expected_error=0)

    def test_tgs_req_invalid(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds, invalid=True)
        self._run_tgs(tgt, creds, expected_error=KRB_ERR_TKT_NYV)

    def test_s4u2self_req_invalid(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds, invalid=True)
        self._s4u2self(tgt, creds, expected_error=KRB_ERR_TKT_NYV)

    def test_user2user_req_invalid(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds, invalid=True)
        self._user2user(tgt, creds, expected_error=KRB_ERR_TKT_NYV)

    def test_fast_req_invalid(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds, invalid=True)
        self._fast(tgt, creds, expected_error=KRB_ERR_TKT_NYV,
                   expected_sname=self.get_krbtgt_sname())

    def test_tgs_req_no_requester_sid(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds, remove_requester_sid=True)

        self._run_tgs(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_tgs_req_no_pac_attrs(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds, remove_pac_attrs=True)

        self._run_tgs(tgt, creds, expected_error=0, expect_pac=True,
                      expect_pac_attrs=False)

    def test_tgs_req_from_rodc_no_requester_sid(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, from_rodc=True, remove_requester_sid=True)

        self._run_tgs(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_tgs_req_from_rodc_no_pac_attrs(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, from_rodc=True, remove_pac_attrs=True)
        self._run_tgs(tgt, creds, expected_error=0, expect_pac=True,
                      expect_pac_attrs=False)

    def test_tgs_req_extra_pac_buffers(self):
        extra_pac_buffers = [123, 456, 789]

        creds = self._get_creds()
        tgt = self._get_tgt(creds, extra_pac_buffers=extra_pac_buffers)

        # Expect that the extra PAC buffers are retained in the TGT.
        self._run_tgs(tgt, creds, expected_error=0,
                      expected_extra_pac_buffers=extra_pac_buffers)

    def test_tgs_req_from_rodc_extra_pac_buffers(self):
        extra_pac_buffers = [123, 456, 789]

        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, from_rodc=True,
                            extra_pac_buffers=extra_pac_buffers)

        # Expect that the extra PAC buffers are removed from the RODC‐issued
        # TGT.
        self._run_tgs(tgt, creds, expected_error=0)

    # Test making a request without a PAC.
    def test_tgs_no_pac(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds, remove_pac=True)
        self._run_tgs(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_renew_no_pac(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds, renewable=True, remove_pac=True)
        self._renew_tgt(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_validate_no_pac(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds, invalid=True, remove_pac=True)
        self._validate_tgt(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_s4u2self_no_pac(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds, remove_pac=True)
        self._s4u2self(tgt, creds,
                       expected_error=KDC_ERR_TGT_REVOKED,
                       expect_edata=False)

    def test_user2user_no_pac(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds, remove_pac=True)
        self._user2user(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_fast_no_pac(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds, remove_pac=True)
        self._fast(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED,
                   expected_sname=self.get_krbtgt_sname())

    def test_fast_as_req_no_pac(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds, remove_pac=True)
        self._fast_as_req(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED,
                          expected_sname=self.get_krbtgt_sname())

    # Test making a request with authdata and without a PAC.
    def test_tgs_authdata_no_pac(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds, remove_pac=True, allow_empty_authdata=True)
        self._run_tgs(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_renew_authdata_no_pac(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds, renewable=True, remove_pac=True,
                            allow_empty_authdata=True)
        self._renew_tgt(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_validate_authdata_no_pac(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds, invalid=True, remove_pac=True,
                            allow_empty_authdata=True)
        self._validate_tgt(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_s4u2self_authdata_no_pac(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds, remove_pac=True, allow_empty_authdata=True)
        self._s4u2self(tgt, creds,
                       expected_error=KDC_ERR_TGT_REVOKED,
                       expect_edata=False)

    def test_user2user_authdata_no_pac(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds, remove_pac=True, allow_empty_authdata=True)
        self._user2user(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_fast_authdata_no_pac(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds, remove_pac=True, allow_empty_authdata=True)
        self._fast(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED,
                   expected_sname=self.get_krbtgt_sname())

    def test_fast_as_req_authdata_no_pac(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds, remove_pac=True, allow_empty_authdata=True)
        self._fast_as_req(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED,
                          expected_sname=self.get_krbtgt_sname())

    # Test changing the SID in the PAC to that of another account.
    def test_tgs_sid_mismatch_existing(self):
        creds = self._get_creds()
        existing_rid = self._get_existing_rid()
        tgt = self._get_tgt(creds, new_rid=existing_rid)
        self._run_tgs(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_renew_sid_mismatch_existing(self):
        creds = self._get_creds()
        existing_rid = self._get_existing_rid()
        tgt = self._get_tgt(creds, renewable=True, new_rid=existing_rid)
        self._renew_tgt(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_validate_sid_mismatch_existing(self):
        creds = self._get_creds()
        existing_rid = self._get_existing_rid()
        tgt = self._get_tgt(creds, invalid=True, new_rid=existing_rid)
        self._validate_tgt(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_s4u2self_sid_mismatch_existing(self):
        creds = self._get_creds()
        existing_rid = self._get_existing_rid()
        tgt = self._get_tgt(creds, new_rid=existing_rid)
        self._s4u2self(tgt, creds,
                       expected_error=KDC_ERR_TGT_REVOKED)

    def test_user2user_sid_mismatch_existing(self):
        creds = self._get_creds()
        existing_rid = self._get_existing_rid()
        tgt = self._get_tgt(creds, new_rid=existing_rid)
        self._user2user(tgt, creds,
                        expected_error=KDC_ERR_TGT_REVOKED)

    def test_fast_sid_mismatch_existing(self):
        creds = self._get_creds()
        existing_rid = self._get_existing_rid()
        tgt = self._get_tgt(creds, new_rid=existing_rid)
        self._fast(tgt, creds,
                   expected_error=KDC_ERR_TGT_REVOKED,
                   expected_sname=self.get_krbtgt_sname())

    def test_fast_as_req_sid_mismatch_existing(self):
        creds = self._get_creds()
        existing_rid = self._get_existing_rid()
        tgt = self._get_tgt(creds, new_rid=existing_rid)
        self._fast_as_req(tgt, creds,
                          expected_error=KDC_ERR_TGT_REVOKED,
                          expected_sname=self.get_krbtgt_sname())

    def test_requester_sid_mismatch_existing(self):
        creds = self._get_creds()
        existing_rid = self._get_existing_rid()
        tgt = self._get_tgt(creds, new_rid=existing_rid,
                            can_modify_logon_info=False)
        self._run_tgs(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_logon_info_sid_mismatch_existing(self):
        creds = self._get_creds()
        existing_rid = self._get_existing_rid()
        tgt = self._get_tgt(creds, new_rid=existing_rid,
                            can_modify_requester_sid=False)
        self._run_tgs(tgt, creds, expected_error=0)

    def test_logon_info_only_sid_mismatch_existing(self):
        creds = self._get_creds()
        existing_rid = self._get_existing_rid()
        tgt = self._get_tgt(creds, new_rid=existing_rid,
                            remove_requester_sid=True)
        self._run_tgs(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    # Test changing the SID in the PAC to a non-existent one.
    def test_tgs_sid_mismatch_nonexisting(self):
        creds = self._get_creds()
        nonexistent_rid = self._get_non_existent_rid()
        tgt = self._get_tgt(creds, new_rid=nonexistent_rid)
        self._run_tgs(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_renew_sid_mismatch_nonexisting(self):
        creds = self._get_creds()
        nonexistent_rid = self._get_non_existent_rid()
        tgt = self._get_tgt(creds, renewable=True,
                            new_rid=nonexistent_rid)
        self._renew_tgt(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_validate_sid_mismatch_nonexisting(self):
        creds = self._get_creds()
        nonexistent_rid = self._get_non_existent_rid()
        tgt = self._get_tgt(creds, invalid=True,
                            new_rid=nonexistent_rid)
        self._validate_tgt(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_s4u2self_sid_mismatch_nonexisting(self):
        creds = self._get_creds()
        nonexistent_rid = self._get_non_existent_rid()
        tgt = self._get_tgt(creds, new_rid=nonexistent_rid)
        self._s4u2self(tgt, creds,
                       expected_error=KDC_ERR_TGT_REVOKED)

    def test_user2user_sid_mismatch_nonexisting(self):
        creds = self._get_creds()
        nonexistent_rid = self._get_non_existent_rid()
        tgt = self._get_tgt(creds, new_rid=nonexistent_rid)
        self._user2user(tgt, creds,
                        expected_error=KDC_ERR_TGT_REVOKED)

    def test_fast_sid_mismatch_nonexisting(self):
        creds = self._get_creds()
        nonexistent_rid = self._get_non_existent_rid()
        tgt = self._get_tgt(creds, new_rid=nonexistent_rid)
        self._fast(tgt, creds,
                   expected_error=KDC_ERR_TGT_REVOKED,
                   expected_sname=self.get_krbtgt_sname())

    def test_fast_as_req_sid_mismatch_nonexisting(self):
        creds = self._get_creds()
        nonexistent_rid = self._get_non_existent_rid()
        tgt = self._get_tgt(creds, new_rid=nonexistent_rid)
        self._fast_as_req(tgt, creds,
                          expected_error=KDC_ERR_TGT_REVOKED,
                          expected_sname=self.get_krbtgt_sname())

    def test_requester_sid_mismatch_nonexisting(self):
        creds = self._get_creds()
        nonexistent_rid = self._get_non_existent_rid()
        tgt = self._get_tgt(creds, new_rid=nonexistent_rid,
                            can_modify_logon_info=False)
        self._run_tgs(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_logon_info_sid_mismatch_nonexisting(self):
        creds = self._get_creds()
        nonexistent_rid = self._get_non_existent_rid()
        tgt = self._get_tgt(creds, new_rid=nonexistent_rid,
                            can_modify_requester_sid=False)
        self._run_tgs(tgt, creds, expected_error=0)

    def test_logon_info_only_sid_mismatch_nonexisting(self):
        creds = self._get_creds()
        nonexistent_rid = self._get_non_existent_rid()
        tgt = self._get_tgt(creds, new_rid=nonexistent_rid,
                            remove_requester_sid=True)
        self._run_tgs(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    # Test with an RODC-issued ticket where the client is revealed to the RODC.
    def test_tgs_rodc_revealed(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, from_rodc=True)
        self._run_tgs(tgt, creds, expected_error=0)

    def test_renew_rodc_revealed(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, renewable=True, from_rodc=True)
        self._renew_tgt(tgt, creds, expected_error=0,
                        expect_pac_attrs=False,
                        expect_requester_sid=True)

    def test_validate_rodc_revealed(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, invalid=True, from_rodc=True)
        self._validate_tgt(tgt, creds, expected_error=0,
                           expect_pac_attrs=False,
                           expect_requester_sid=True)

    # This test fails on Windows, which gives KDC_ERR_C_PRINCIPAL_UNKNOWN when
    # attempting to use S4U2Self with a TGT from an RODC.
    def test_s4u2self_rodc_revealed(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, from_rodc=True)
        self._s4u2self(tgt, creds,
                       expected_error=KDC_ERR_C_PRINCIPAL_UNKNOWN)

    def test_user2user_rodc_revealed(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, from_rodc=True)
        self._user2user(tgt, creds, expected_error=0)

    # Test with an RODC-issued ticket where the SID in the PAC is changed to
    # that of another account.
    def test_tgs_rodc_sid_mismatch_existing(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        existing_rid = self._get_existing_rid(replication_allowed=True,
                                              revealed_to_rodc=True)
        tgt = self._get_tgt(creds, from_rodc=True, new_rid=existing_rid)
        self._run_tgs(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_renew_rodc_sid_mismatch_existing(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        existing_rid = self._get_existing_rid(replication_allowed=True,
                                              revealed_to_rodc=True)
        tgt = self._get_tgt(creds, renewable=True, from_rodc=True,
                            new_rid=existing_rid)
        self._renew_tgt(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_validate_rodc_sid_mismatch_existing(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        existing_rid = self._get_existing_rid(replication_allowed=True,
                                       revealed_to_rodc=True)
        tgt = self._get_tgt(creds, invalid=True, from_rodc=True,
                            new_rid=existing_rid)
        self._validate_tgt(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_s4u2self_rodc_sid_mismatch_existing(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        existing_rid = self._get_existing_rid(replication_allowed=True,
                                              revealed_to_rodc=True)
        tgt = self._get_tgt(creds, from_rodc=True, new_rid=existing_rid)
        self._s4u2self(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_user2user_rodc_sid_mismatch_existing(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        existing_rid = self._get_existing_rid(replication_allowed=True,
                                              revealed_to_rodc=True)
        tgt = self._get_tgt(creds, from_rodc=True, new_rid=existing_rid)
        self._user2user(tgt, creds,
                        expected_error=KDC_ERR_TGT_REVOKED)

    def test_fast_rodc_sid_mismatch_existing(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        existing_rid = self._get_existing_rid(replication_allowed=True,
                                              revealed_to_rodc=True)
        tgt = self._get_tgt(creds, from_rodc=True, new_rid=existing_rid)
        self._fast(tgt, creds,
                   expected_error=KDC_ERR_TGT_REVOKED,
                   expected_sname=self.get_krbtgt_sname())

    def test_tgs_rodc_requester_sid_mismatch_existing(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        existing_rid = self._get_existing_rid(replication_allowed=True,
                                              revealed_to_rodc=True)
        tgt = self._get_tgt(creds, from_rodc=True, new_rid=existing_rid,
                            can_modify_logon_info=False)
        self._run_tgs(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_tgs_rodc_logon_info_sid_mismatch_existing(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        existing_rid = self._get_existing_rid(replication_allowed=True,
                                              revealed_to_rodc=True)
        tgt = self._get_tgt(creds, from_rodc=True, new_rid=existing_rid,
                            can_modify_requester_sid=False)
        self._run_tgs(tgt, creds, expected_error=0)

    def test_tgs_rodc_logon_info_only_sid_mismatch_existing(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        existing_rid = self._get_existing_rid(replication_allowed=True,
                                              revealed_to_rodc=True)
        tgt = self._get_tgt(creds, from_rodc=True, new_rid=existing_rid,
                            remove_requester_sid=True)
        self._run_tgs(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    # Test with an RODC-issued ticket where the SID in the PAC is changed to a
    # non-existent one.
    def test_tgs_rodc_sid_mismatch_nonexisting(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        nonexistent_rid = self._get_non_existent_rid()
        tgt = self._get_tgt(creds, from_rodc=True, new_rid=nonexistent_rid)
        self._run_tgs(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_renew_rodc_sid_mismatch_nonexisting(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        nonexistent_rid = self._get_non_existent_rid()
        tgt = self._get_tgt(creds, renewable=True, from_rodc=True,
                            new_rid=nonexistent_rid)
        self._renew_tgt(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_validate_rodc_sid_mismatch_nonexisting(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        nonexistent_rid = self._get_non_existent_rid()
        tgt = self._get_tgt(creds, invalid=True, from_rodc=True,
                            new_rid=nonexistent_rid)
        self._validate_tgt(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_s4u2self_rodc_sid_mismatch_nonexisting(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        nonexistent_rid = self._get_non_existent_rid()
        tgt = self._get_tgt(creds, from_rodc=True, new_rid=nonexistent_rid)
        self._s4u2self(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_user2user_rodc_sid_mismatch_nonexisting(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        nonexistent_rid = self._get_non_existent_rid()
        tgt = self._get_tgt(creds, from_rodc=True, new_rid=nonexistent_rid)
        self._user2user(tgt, creds,
                        expected_error=KDC_ERR_TGT_REVOKED)

    def test_fast_rodc_sid_mismatch_nonexisting(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        nonexistent_rid = self._get_non_existent_rid()
        tgt = self._get_tgt(creds, from_rodc=True, new_rid=nonexistent_rid)
        self._fast(tgt, creds,
                   expected_error=KDC_ERR_TGT_REVOKED,
                   expected_sname=self.get_krbtgt_sname())

    def test_tgs_rodc_requester_sid_mismatch_nonexisting(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        nonexistent_rid = self._get_non_existent_rid()
        tgt = self._get_tgt(creds, from_rodc=True, new_rid=nonexistent_rid,
                            can_modify_logon_info=False)
        self._run_tgs(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_tgs_rodc_logon_info_sid_mismatch_nonexisting(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        nonexistent_rid = self._get_non_existent_rid()
        tgt = self._get_tgt(creds, from_rodc=True, new_rid=nonexistent_rid,
                            can_modify_requester_sid=False)
        self._run_tgs(tgt, creds, expected_error=0)

    def test_tgs_rodc_logon_info_only_sid_mismatch_nonexisting(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        nonexistent_rid = self._get_non_existent_rid()
        tgt = self._get_tgt(creds, from_rodc=True, new_rid=nonexistent_rid,
                            remove_requester_sid=True)
        self._run_tgs(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    # Test with an RODC-issued ticket where the client is not revealed to the
    # RODC.
    def test_tgs_rodc_not_revealed(self):
        creds = self._get_creds(replication_allowed=True)
        tgt = self._get_tgt(creds, from_rodc=True)
        # TODO: error code
        self._run_tgs(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_renew_rodc_not_revealed(self):
        creds = self._get_creds(replication_allowed=True)
        tgt = self._get_tgt(creds, renewable=True, from_rodc=True)
        self._renew_tgt(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_validate_rodc_not_revealed(self):
        creds = self._get_creds(replication_allowed=True)
        tgt = self._get_tgt(creds, invalid=True, from_rodc=True)
        self._validate_tgt(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_s4u2self_rodc_not_revealed(self):
        creds = self._get_creds(replication_allowed=True)
        tgt = self._get_tgt(creds, from_rodc=True)
        self._s4u2self(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_user2user_rodc_not_revealed(self):
        creds = self._get_creds(replication_allowed=True)
        tgt = self._get_tgt(creds, from_rodc=True)
        self._user2user(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    # Test with an RODC-issued ticket where the RODC account does not have the
    # PARTIAL_SECRETS bit set.
    def test_tgs_rodc_no_partial_secrets(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, from_rodc=True)
        self._remove_rodc_partial_secrets()
        self._run_tgs(tgt, creds, expected_error=KDC_ERR_POLICY)

    def test_renew_rodc_no_partial_secrets(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, renewable=True, from_rodc=True)
        self._remove_rodc_partial_secrets()
        self._renew_tgt(tgt, creds, expected_error=KDC_ERR_POLICY)

    def test_validate_rodc_no_partial_secrets(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, invalid=True, from_rodc=True)
        self._remove_rodc_partial_secrets()
        self._validate_tgt(tgt, creds, expected_error=KDC_ERR_POLICY)

    def test_s4u2self_rodc_no_partial_secrets(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, from_rodc=True)
        self._remove_rodc_partial_secrets()
        self._s4u2self(tgt, creds, expected_error=KDC_ERR_POLICY)

    def test_user2user_rodc_no_partial_secrets(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, from_rodc=True)
        self._remove_rodc_partial_secrets()
        self._user2user(tgt, creds, expected_error=KDC_ERR_POLICY)

    def test_fast_rodc_no_partial_secrets(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, from_rodc=True)
        self._remove_rodc_partial_secrets()
        self._fast(tgt, creds, expected_error=KDC_ERR_POLICY,
                   expected_sname=self.get_krbtgt_sname())

    # Test with an RODC-issued ticket where the RODC account does not have an
    # msDS-KrbTgtLink.
    def test_tgs_rodc_no_krbtgt_link(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, from_rodc=True)
        self._remove_rodc_krbtgt_link()
        self._run_tgs(tgt, creds, expected_error=KDC_ERR_POLICY)

    def test_renew_rodc_no_krbtgt_link(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, renewable=True, from_rodc=True)
        self._remove_rodc_krbtgt_link()
        self._renew_tgt(tgt, creds, expected_error=KDC_ERR_POLICY)

    def test_validate_rodc_no_krbtgt_link(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, invalid=True, from_rodc=True)
        self._remove_rodc_krbtgt_link()
        self._validate_tgt(tgt, creds, expected_error=KDC_ERR_POLICY)

    def test_s4u2self_rodc_no_krbtgt_link(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, from_rodc=True)
        self._remove_rodc_krbtgt_link()
        self._s4u2self(tgt, creds, expected_error=KDC_ERR_POLICY)

    def test_user2user_rodc_no_krbtgt_link(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, from_rodc=True)
        self._remove_rodc_krbtgt_link()
        self._user2user(tgt, creds, expected_error=KDC_ERR_POLICY)

    def test_fast_rodc_no_krbtgt_link(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, from_rodc=True)
        self._remove_rodc_krbtgt_link()
        self._fast(tgt, creds, expected_error=KDC_ERR_POLICY,
                   expected_sname=self.get_krbtgt_sname())

    # Test with an RODC-issued ticket where the client is not allowed to
    # replicate to the RODC.
    def test_tgs_rodc_not_allowed(self):
        creds = self._get_creds(revealed_to_rodc=True)
        tgt = self._get_tgt(creds, from_rodc=True)
        self._run_tgs(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_renew_rodc_not_allowed(self):
        creds = self._get_creds(revealed_to_rodc=True)
        tgt = self._get_tgt(creds, renewable=True, from_rodc=True)
        self._renew_tgt(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_validate_rodc_not_allowed(self):
        creds = self._get_creds(revealed_to_rodc=True)
        tgt = self._get_tgt(creds, invalid=True, from_rodc=True)
        self._validate_tgt(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_s4u2self_rodc_not_allowed(self):
        creds = self._get_creds(revealed_to_rodc=True)
        tgt = self._get_tgt(creds, from_rodc=True)
        self._s4u2self(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_user2user_rodc_not_allowed(self):
        creds = self._get_creds(revealed_to_rodc=True)
        tgt = self._get_tgt(creds, from_rodc=True)
        self._user2user(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_fast_rodc_not_allowed(self):
        creds = self._get_creds(revealed_to_rodc=True)
        tgt = self._get_tgt(creds, from_rodc=True)
        self._fast(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED,
                   expected_sname=self.get_krbtgt_sname())

    # Test with an RODC-issued ticket where the client is denied from
    # replicating to the RODC.
    def test_tgs_rodc_denied(self):
        creds = self._get_creds(replication_denied=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, from_rodc=True)
        self._run_tgs(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_renew_rodc_denied(self):
        creds = self._get_creds(replication_denied=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, renewable=True, from_rodc=True)
        self._renew_tgt(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_validate_rodc_denied(self):
        creds = self._get_creds(replication_denied=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, invalid=True, from_rodc=True)
        self._validate_tgt(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_s4u2self_rodc_denied(self):
        creds = self._get_creds(replication_denied=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, from_rodc=True)
        self._s4u2self(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_user2user_rodc_denied(self):
        creds = self._get_creds(replication_denied=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, from_rodc=True)
        self._user2user(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_fast_rodc_denied(self):
        creds = self._get_creds(replication_denied=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, from_rodc=True)
        self._fast(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED,
                   expected_sname=self.get_krbtgt_sname())

    # Test with an RODC-issued ticket where the client is both allowed and
    # denied replicating to the RODC.
    def test_tgs_rodc_allowed_denied(self):
        creds = self._get_creds(replication_allowed=True,
                                replication_denied=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, from_rodc=True)
        self._run_tgs(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_renew_rodc_allowed_denied(self):
        creds = self._get_creds(replication_allowed=True,
                                replication_denied=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, renewable=True, from_rodc=True)
        self._renew_tgt(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_validate_rodc_allowed_denied(self):
        creds = self._get_creds(replication_allowed=True,
                                replication_denied=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, invalid=True, from_rodc=True)
        self._validate_tgt(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_s4u2self_rodc_allowed_denied(self):
        creds = self._get_creds(replication_allowed=True,
                                replication_denied=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, from_rodc=True)
        self._s4u2self(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_user2user_rodc_allowed_denied(self):
        creds = self._get_creds(replication_allowed=True,
                                replication_denied=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, from_rodc=True)
        self._user2user(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_fast_rodc_allowed_denied(self):
        creds = self._get_creds(replication_allowed=True,
                                replication_denied=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, from_rodc=True)
        self._fast(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED,
                   expected_sname=self.get_krbtgt_sname())

    # Test making a TGS request with an RC4-encrypted TGT.
    def test_tgs_rc4(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds, etype=kcrypto.Enctype.RC4)
        self._run_tgs(tgt, creds, expected_error=(KDC_ERR_GENERIC,
                                           KDC_ERR_BADKEYVER),
                      expect_edata=True,
                      # We aren’t particular about whether or not we get an
                      # NTSTATUS.
                      expect_status=None,
                      expected_status=ntstatus.NT_STATUS_INSUFFICIENT_RESOURCES)

    def test_renew_rc4(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds, renewable=True, etype=kcrypto.Enctype.RC4)
        self._renew_tgt(tgt, creds, expected_error=(KDC_ERR_GENERIC,
                                                    KDC_ERR_BADKEYVER),
                        expect_pac_attrs=True,
                        expect_pac_attrs_pac_request=True,
                        expect_requester_sid=True)

    def test_validate_rc4(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds, invalid=True, etype=kcrypto.Enctype.RC4)
        self._validate_tgt(tgt, creds, expected_error=(KDC_ERR_GENERIC,
                                                       KDC_ERR_BADKEYVER),
                           expect_pac_attrs=True,
                           expect_pac_attrs_pac_request=True,
                           expect_requester_sid=True)

    def test_s4u2self_rc4(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds, etype=kcrypto.Enctype.RC4)
        self._s4u2self(tgt, creds, expected_error=(KDC_ERR_GENERIC,
                                                   KDC_ERR_BADKEYVER),
                       expect_edata=True,
                       # We aren’t particular about whether or not we get an
                       # NTSTATUS.
                       expect_status=None,
                       expected_status=ntstatus.NT_STATUS_INSUFFICIENT_RESOURCES)

    def test_user2user_rc4(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds, etype=kcrypto.Enctype.RC4)
        self._user2user(tgt, creds, expected_error=KDC_ERR_ETYPE_NOSUPP)

    def test_fast_rc4(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds, etype=kcrypto.Enctype.RC4)
        self._fast(tgt, creds, expected_error=KDC_ERR_GENERIC,
                   expect_edata=self.expect_padata_outer)

    # Test with a TGT that has the lifetime of a kpasswd ticket (two minutes).
    def test_tgs_kpasswd(self):
        creds = self._get_creds()
        tgt = self.modify_lifetime(self._get_tgt(creds), lifetime=2 * 60)
        self._run_tgs(tgt, creds, expected_error=KDC_ERR_TKT_EXPIRED)

    def test_renew_kpasswd(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds, renewable=True)
        tgt = self.modify_lifetime(tgt, lifetime=2 * 60)
        self._renew_tgt(tgt, creds, expected_error=KDC_ERR_TKT_EXPIRED)

    def test_validate_kpasswd(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds, invalid=True)
        tgt = self.modify_lifetime(tgt, lifetime=2 * 60)
        self._validate_tgt(tgt, creds, expected_error=KDC_ERR_TKT_EXPIRED)

    def test_s4u2self_kpasswd(self):
        creds = self._get_creds()
        tgt = self.modify_lifetime(self._get_tgt(creds), lifetime=2 * 60)
        self._s4u2self(tgt, creds, expected_error=KDC_ERR_TKT_EXPIRED)

    def test_user2user_kpasswd(self):
        creds = self._get_creds()
        tgt = self.modify_lifetime(self._get_tgt(creds), lifetime=2 * 60)
        self._user2user(tgt, creds, expected_error=KDC_ERR_TKT_EXPIRED)

    def test_fast_kpasswd(self):
        creds = self._get_creds()
        tgt = self.modify_lifetime(self._get_tgt(creds), lifetime=2 * 60)
        self._fast(tgt, creds, expected_error=KDC_ERR_TKT_EXPIRED)

    # Test user-to-user with incorrect service principal names.
    def test_user2user_matching_sname_host(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds)

        user_name = creds.get_username()
        sname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                          names=['host', user_name])

        self._user2user(tgt, creds, sname=sname,
                        expected_error=KDC_ERR_S_PRINCIPAL_UNKNOWN)

    def test_user2user_matching_sname_no_host(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds)

        user_name = creds.get_username()
        sname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                          names=[user_name])

        self._user2user(tgt, creds, sname=sname, expected_error=0)

    def test_user2user_wrong_sname(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds)

        other_creds = self._get_mach_creds()
        user_name = other_creds.get_username()
        sname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                          names=[user_name])

        self._user2user(tgt, creds, sname=sname,
                        expected_error=KDC_ERR_BADMATCH)

    def test_user2user_other_sname(self):
        other_name = self.get_new_username()
        spn = f'host/{other_name}'
        creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'spn': spn})
        tgt = self._get_tgt(creds)

        sname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                          names=['host', other_name])

        self._user2user(tgt, creds, sname=sname, expected_error=0)

    def test_user2user_wrong_sname_krbtgt(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds)

        sname = self.get_krbtgt_sname()

        self._user2user(tgt, creds, sname=sname,
                        expected_error=KDC_ERR_BADMATCH)

    def test_user2user_wrong_srealm(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds)

        self._user2user(tgt, creds, srealm='OTHER.REALM',
                        expected_error=(KDC_ERR_WRONG_REALM,
                                        KDC_ERR_S_PRINCIPAL_UNKNOWN))

    def test_user2user_tgt_correct_realm(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds)

        realm = creds.get_realm().encode('utf-8')
        tgt = self._modify_tgt(tgt, crealm=realm)

        self._user2user(tgt, creds,
                        expected_error=0)

    def test_user2user_tgt_wrong_realm(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds)

        tgt = self._modify_tgt(tgt, crealm=b'OTHER.REALM')

        self._user2user(tgt, creds,
                        expected_error=(
                            KDC_ERR_POLICY,  # Windows
                            KDC_ERR_C_PRINCIPAL_UNKNOWN,  # Heimdal
                            KDC_ERR_SERVER_NOMATCH,  # MIT
                        ),
                        expect_edata=True,
                        expected_status=ntstatus.NT_STATUS_NO_MATCH)

    def test_user2user_tgt_correct_cname(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds)

        user_name = creds.get_username()
        user_name = user_name.encode('utf-8')
        cname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                          names=[user_name])

        tgt = self._modify_tgt(tgt, cname=cname)

        self._user2user(tgt, creds, expected_error=0)

    def test_user2user_tgt_other_cname(self):
        samdb = self.get_samdb()

        other_name = self.get_new_username()
        upn = f'{other_name}@{samdb.domain_dns_name()}'

        creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'upn': upn})
        tgt = self._get_tgt(creds)

        cname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                          names=[other_name.encode('utf-8')])

        tgt = self._modify_tgt(tgt, cname=cname)

        self._user2user(tgt, creds, expected_error=0)

    def test_user2user_tgt_cname_host(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds)

        user_name = creds.get_username()
        user_name = user_name.encode('utf-8')
        cname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                          names=[b'host', user_name])

        tgt = self._modify_tgt(tgt, cname=cname)

        self._user2user(tgt, creds,
                        expected_error=(KDC_ERR_TGT_REVOKED,
                                        KDC_ERR_C_PRINCIPAL_UNKNOWN))

    def test_user2user_non_existent_sname(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds)

        sname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                          names=['host', 'non_existent_user'])

        self._user2user(tgt, creds, sname=sname,
                        expected_error=KDC_ERR_S_PRINCIPAL_UNKNOWN)

    def test_user2user_no_sname(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds)

        self._user2user(tgt, creds, sname=False,
                        expected_error=(KDC_ERR_GENERIC,
                                        KDC_ERR_S_PRINCIPAL_UNKNOWN))

    def test_tgs_service_ticket(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds)

        service_creds = self.get_service_creds()
        service_ticket = self.get_service_ticket(tgt, service_creds)

        self._run_tgs(service_ticket, creds,
                      expected_error=(KDC_ERR_NOT_US, KDC_ERR_POLICY))

    def test_renew_service_ticket(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds)

        service_creds = self.get_service_creds()
        service_ticket = self.get_service_ticket(tgt, service_creds)

        service_ticket = self.modified_ticket(
            service_ticket,
            modify_fn=self._modify_renewable,
            checksum_keys=self.get_krbtgt_checksum_key())

        self._renew_tgt(service_ticket, creds,
                        expected_error=KDC_ERR_POLICY)

    def test_validate_service_ticket(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds)

        service_creds = self.get_service_creds()
        service_ticket = self.get_service_ticket(tgt, service_creds)

        service_ticket = self.modified_ticket(
            service_ticket,
            modify_fn=self._modify_invalid,
            checksum_keys=self.get_krbtgt_checksum_key())

        self._validate_tgt(service_ticket, creds,
                           expected_error=KDC_ERR_POLICY)

    def test_s4u2self_service_ticket(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds)

        service_creds = self.get_service_creds()
        service_ticket = self.get_service_ticket(tgt, service_creds)

        self._s4u2self(service_ticket, creds,
                       expected_error=(KDC_ERR_NOT_US, KDC_ERR_POLICY))

    def test_user2user_service_ticket(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds)

        service_creds = self.get_service_creds()
        service_ticket = self.get_service_ticket(tgt, service_creds)

        self._user2user(service_ticket, creds,
                        expected_error=(KDC_ERR_MODIFIED, KDC_ERR_POLICY))

    # Expected to fail against Windows, which does not produce an error.
    def test_fast_service_ticket(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds)

        service_creds = self.get_service_creds()
        service_ticket = self.get_service_ticket(tgt, service_creds)

        self._fast(service_ticket, creds,
                   expected_error=(KDC_ERR_POLICY,
                                   KDC_ERR_S_PRINCIPAL_UNKNOWN))

    def test_single_component_krbtgt_requester_sid_as_req(self):
        """Test that TGTs issued to a single‐component krbtgt principal always
        contain a requester SID PAC buffer.
        """

        creds = self._get_creds()

        # Create a single‐component principal of the form ‘krbtgt@REALM’.
        sname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                          names=['krbtgt'])

        # Don’t request canonicalization.
        kdc_options = 'forwardable,renewable,renewable-ok'

        # Get a TGT and assert that the requester SID PAC buffer is present.
        self.get_tgt(creds,
                     sname=sname,
                     kdc_options=kdc_options,
                     expect_requester_sid=True)

    def test_single_component_krbtgt_requester_sid_tgs_req(self):
        """Test that TGTs issued to a single‐component krbtgt principal always
        contain a requester SID PAC buffer.
        """

        creds = self._get_creds()
        tgt = self.get_tgt(creds)

        # Create a single‐component principal of the form ‘krbtgt@REALM’.
        sname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                          names=['krbtgt'])

        # Don’t request canonicalization.
        kdc_options = '0'

        # Get a TGT and assert that the requester SID PAC buffer is present.
        self.get_service_ticket(tgt,
                                self.get_krbtgt_creds(),
                                sname=sname,
                                kdc_options=kdc_options,
                                expect_requester_sid=True)

    def test_single_component_krbtgt_no_pac_as_req(self):
        """Test that TGTs issued to a single‐component krbtgt principal always
        contain a PAC.
        """

        creds = self._get_creds()

        # Create a single‐component principal of the form ‘krbtgt@REALM’.
        sname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                          names=['krbtgt'])

        # Don’t request canonicalization.
        kdc_options = 'forwardable,renewable,renewable-ok'

        # Get a TGT and assert that the requester SID PAC buffer is present.
        self.get_tgt(creds,
                     sname=sname,
                     kdc_options=kdc_options,
                     # Request that no PAC be issued.
                     pac_request=False,
                     # Ensure that a PAC is issued nonetheless.
                     expect_pac=True)

    def test_single_component_krbtgt_no_pac_tgs_req(self):
        """Test that TGTs issued to a single‐component krbtgt principal always
        contain a PAC.
        """

        creds = self._get_creds()
        tgt = self.get_tgt(creds)

        # Create a single‐component principal of the form ‘krbtgt@REALM’.
        sname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                          names=['krbtgt'])

        # Don’t request canonicalization.
        kdc_options = '0'

        # Get a TGT and assert that the requester SID PAC buffer is present.
        self.get_service_ticket(tgt,
                                self.get_krbtgt_creds(),
                                sname=sname,
                                kdc_options=kdc_options,
                                # Request that no PAC be issued.
                                pac_request=False,
                                # Ensure that a PAC is issued nonetheless.
                                expect_pac=True,
                                expect_pac_attrs=True,
                                expect_pac_attrs_pac_request=True)

    def test_single_component_krbtgt_service_ticket(self):
        """Test that TGTs issued to a single‐component krbtgt principal can be
        used to get service tickets.
        """

        creds = self._get_creds()

        # Create a single‐component principal of the form ‘krbtgt@REALM’.
        sname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                          names=['krbtgt'])

        # Don’t request canonicalization.
        kdc_options = 'forwardable,renewable,renewable-ok'

        # Get a TGT.
        tgt = self.get_tgt(creds,
                     sname=sname,
                     kdc_options=kdc_options)

        # Ensure that we can use the TGT to get a service ticket.
        self._run_tgs(tgt, creds, expected_error=0)

    def test_pac_attrs_none(self):
        creds = self._get_creds()
        self.get_tgt(creds, pac_request=None,
                     expect_pac=True,
                     expect_pac_attrs=True,
                     expect_pac_attrs_pac_request=None)

    def test_pac_attrs_false(self):
        creds = self._get_creds()
        self.get_tgt(creds, pac_request=False,
                     expect_pac=True,
                     expect_pac_attrs=True,
                     expect_pac_attrs_pac_request=False)

    def test_pac_attrs_true(self):
        creds = self._get_creds()
        self.get_tgt(creds, pac_request=True,
                     expect_pac=True,
                     expect_pac_attrs=True,
                     expect_pac_attrs_pac_request=True)

    def test_pac_attrs_renew_none(self):
        creds = self._get_creds()
        tgt = self.get_tgt(creds, pac_request=None,
                           expect_pac=True,
                           expect_pac_attrs=True,
                           expect_pac_attrs_pac_request=None)
        tgt = self._modify_tgt(tgt, renewable=True)

        self._renew_tgt(tgt, creds, expected_error=0,
                        expect_pac=True,
                        expect_pac_attrs=True,
                        expect_pac_attrs_pac_request=None,
                        expect_requester_sid=True)

    def test_pac_attrs_renew_false(self):
        creds = self._get_creds()
        tgt = self.get_tgt(creds, pac_request=False,
                           expect_pac=True,
                           expect_pac_attrs=True,
                           expect_pac_attrs_pac_request=False)
        tgt = self._modify_tgt(tgt, renewable=True)

        self._renew_tgt(tgt, creds, expected_error=0,
                        expect_pac=True,
                        expect_pac_attrs=True,
                        expect_pac_attrs_pac_request=False,
                        expect_requester_sid=True)

    def test_pac_attrs_renew_true(self):
        creds = self._get_creds()
        tgt = self.get_tgt(creds, pac_request=True,
                           expect_pac=True,
                           expect_pac_attrs=True,
                           expect_pac_attrs_pac_request=True)
        tgt = self._modify_tgt(tgt, renewable=True)

        self._renew_tgt(tgt, creds, expected_error=0,
                        expect_pac=True,
                        expect_pac_attrs=True,
                        expect_pac_attrs_pac_request=True,
                        expect_requester_sid=True)

    def test_pac_attrs_rodc_renew_none(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        tgt = self.get_tgt(creds, pac_request=None,
                           expect_pac=True,
                           expect_pac_attrs=True,
                           expect_pac_attrs_pac_request=None)
        tgt = self._modify_tgt(tgt, from_rodc=True, renewable=True)

        self._renew_tgt(tgt, creds, expected_error=0,
                        expect_pac=True,
                        expect_pac_attrs=False,
                        expect_requester_sid=True)

    def test_pac_attrs_rodc_renew_false(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        tgt = self.get_tgt(creds, pac_request=False,
                           expect_pac=True,
                           expect_pac_attrs=True,
                           expect_pac_attrs_pac_request=False)
        tgt = self._modify_tgt(tgt, from_rodc=True, renewable=True)

        self._renew_tgt(tgt, creds, expected_error=0,
                        expect_pac=True,
                        expect_pac_attrs=False,
                        expect_requester_sid=True)

    def test_pac_attrs_rodc_renew_true(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        tgt = self.get_tgt(creds, pac_request=True,
                           expect_pac=True,
                           expect_pac_attrs=True,
                           expect_pac_attrs_pac_request=True)
        tgt = self._modify_tgt(tgt, from_rodc=True, renewable=True)

        self._renew_tgt(tgt, creds, expected_error=0,
                        expect_pac=True,
                        expect_pac_attrs=False,
                        expect_requester_sid=True)

    def test_pac_attrs_missing_renew_none(self):
        creds = self._get_creds()
        tgt = self.get_tgt(creds, pac_request=None,
                           expect_pac=True,
                           expect_pac_attrs=True,
                           expect_pac_attrs_pac_request=None)
        tgt = self._modify_tgt(tgt, renewable=True,
                               remove_pac_attrs=True)

        self._renew_tgt(tgt, creds, expected_error=0,
                        expect_pac=True,
                        expect_pac_attrs=False,
                        expect_requester_sid=True)

    def test_pac_attrs_missing_renew_false(self):
        creds = self._get_creds()
        tgt = self.get_tgt(creds, pac_request=False,
                           expect_pac=True,
                           expect_pac_attrs=True,
                           expect_pac_attrs_pac_request=False)
        tgt = self._modify_tgt(tgt, renewable=True,
                               remove_pac_attrs=True)

        self._renew_tgt(tgt, creds, expected_error=0,
                        expect_pac=True,
                        expect_pac_attrs=False,
                        expect_requester_sid=True)

    def test_pac_attrs_missing_renew_true(self):
        creds = self._get_creds()
        tgt = self.get_tgt(creds, pac_request=True,
                           expect_pac=True,
                           expect_pac_attrs=True,
                           expect_pac_attrs_pac_request=True)
        tgt = self._modify_tgt(tgt, renewable=True,
                               remove_pac_attrs=True)

        self._renew_tgt(tgt, creds, expected_error=0,
                        expect_pac=True,
                        expect_pac_attrs=False,
                        expect_requester_sid=True)

    def test_pac_attrs_missing_rodc_renew_none(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        tgt = self.get_tgt(creds, pac_request=None,
                           expect_pac=True,
                           expect_pac_attrs=True,
                           expect_pac_attrs_pac_request=None)
        tgt = self._modify_tgt(tgt, from_rodc=True, renewable=True,
                               remove_pac_attrs=True)

        self._renew_tgt(tgt, creds, expected_error=0,
                        expect_pac=True,
                        expect_pac_attrs=False,
                        expect_requester_sid=True)

    def test_pac_attrs_missing_rodc_renew_false(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        tgt = self.get_tgt(creds, pac_request=False,
                           expect_pac=True,
                           expect_pac_attrs=True,
                           expect_pac_attrs_pac_request=False)
        tgt = self._modify_tgt(tgt, from_rodc=True, renewable=True,
                               remove_pac_attrs=True)

        self._renew_tgt(tgt, creds, expected_error=0,
                        expect_pac=True,
                        expect_pac_attrs=False,
                        expect_requester_sid=True)

    def test_pac_attrs_missing_rodc_renew_true(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        tgt = self.get_tgt(creds, pac_request=True,
                           expect_pac=True,
                           expect_pac_attrs=True,
                           expect_pac_attrs_pac_request=True)
        tgt = self._modify_tgt(tgt, from_rodc=True, renewable=True,
                               remove_pac_attrs=True)

        self._renew_tgt(tgt, creds, expected_error=0,
                        expect_pac=True,
                        expect_pac_attrs=False,
                        expect_requester_sid=True)

    def test_tgs_pac_attrs_none(self):
        creds = self._get_creds()
        tgt = self.get_tgt(creds, pac_request=None,
                           expect_pac=True,
                           expect_pac_attrs=True,
                           expect_pac_attrs_pac_request=None)

        self._run_tgs(tgt, creds, expected_error=0, expect_pac=True,
                      expect_pac_attrs=False)

    def test_tgs_pac_attrs_false(self):
        creds = self._get_creds()
        tgt = self.get_tgt(creds, pac_request=False,
                           expect_pac=True,
                           expect_pac_attrs=True,
                           expect_pac_attrs_pac_request=False)

        self._run_tgs(tgt, creds, expected_error=0, expect_pac=False,
                      expect_pac_attrs=False)

    def test_tgs_pac_attrs_true(self):
        creds = self._get_creds()
        tgt = self.get_tgt(creds, pac_request=True,
                           expect_pac=True,
                           expect_pac_attrs=True,
                           expect_pac_attrs_pac_request=True)

        self._run_tgs(tgt, creds, expected_error=0, expect_pac=True,
                      expect_pac_attrs=False)

    def test_as_requester_sid(self):
        creds = self._get_creds()

        sid = creds.get_sid()

        self.get_tgt(creds, pac_request=None,
                     expect_pac=True,
                     expected_sid=sid,
                     expect_requester_sid=True)

    def test_tgs_requester_sid(self):
        creds = self._get_creds()

        sid = creds.get_sid()

        tgt = self.get_tgt(creds, pac_request=None,
                           expect_pac=True,
                           expected_sid=sid,
                           expect_requester_sid=True)

        self._run_tgs(tgt, creds, expected_error=0, expect_pac=True,
                      expect_requester_sid=False)

    def test_tgs_requester_sid_renew(self):
        creds = self._get_creds()

        sid = creds.get_sid()

        tgt = self.get_tgt(creds, pac_request=None,
                           expect_pac=True,
                           expected_sid=sid,
                           expect_requester_sid=True)
        tgt = self._modify_tgt(tgt, renewable=True)

        self._renew_tgt(tgt, creds, expected_error=0, expect_pac=True,
                        expect_pac_attrs=True,
                        expect_pac_attrs_pac_request=None,
                        expected_sid=sid,
                        expect_requester_sid=True)

    def test_tgs_requester_sid_rodc_renew(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)

        sid = creds.get_sid()

        tgt = self.get_tgt(creds, pac_request=None,
                           expect_pac=True,
                           expected_sid=sid,
                           expect_requester_sid=True)
        tgt = self._modify_tgt(tgt, from_rodc=True, renewable=True)

        self._renew_tgt(tgt, creds, expected_error=0, expect_pac=True,
                        expect_pac_attrs=False,
                        expected_sid=sid,
                        expect_requester_sid=True)

    def test_tgs_requester_sid_missing_renew(self):
        creds = self._get_creds()

        sid = creds.get_sid()

        tgt = self.get_tgt(creds, pac_request=None,
                           expect_pac=True,
                           expected_sid=sid,
                           expect_requester_sid=True)
        tgt = self._modify_tgt(tgt, renewable=True,
                               remove_requester_sid=True)

        self._renew_tgt(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_tgs_requester_sid_missing_rodc_renew(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)

        sid = creds.get_sid()

        tgt = self.get_tgt(creds, pac_request=None,
                           expect_pac=True,
                           expected_sid=sid,
                           expect_requester_sid=True)
        tgt = self._modify_tgt(tgt, from_rodc=True, renewable=True,
                               remove_requester_sid=True)

        self._renew_tgt(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_tgs_requester_sid_validate(self):
        creds = self._get_creds()

        sid = creds.get_sid()

        tgt = self.get_tgt(creds, pac_request=None,
                           expect_pac=True,
                           expected_sid=sid,
                           expect_requester_sid=True)
        tgt = self._modify_tgt(tgt, invalid=True)

        self._validate_tgt(tgt, creds, expected_error=0, expect_pac=True,
                           expect_pac_attrs=True,
                           expect_pac_attrs_pac_request=None,
                           expected_sid=sid,
                           expect_requester_sid=True)

    def test_tgs_requester_sid_rodc_validate(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)

        sid = creds.get_sid()

        tgt = self.get_tgt(creds, pac_request=None,
                           expect_pac=True,
                           expected_sid=sid,
                           expect_requester_sid=True)
        tgt = self._modify_tgt(tgt, from_rodc=True, invalid=True)

        self._validate_tgt(tgt, creds, expected_error=0, expect_pac=True,
                           expect_pac_attrs=False,
                           expected_sid=sid,
                           expect_requester_sid=True)

    def test_tgs_requester_sid_missing_validate(self):
        creds = self._get_creds()

        sid = creds.get_sid()

        tgt = self.get_tgt(creds, pac_request=None,
                           expect_pac=True,
                           expected_sid=sid,
                           expect_requester_sid=True)
        tgt = self._modify_tgt(tgt, invalid=True,
                               remove_requester_sid=True)

        self._validate_tgt(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_tgs_requester_sid_missing_rodc_validate(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)

        sid = creds.get_sid()

        tgt = self.get_tgt(creds, pac_request=None,
                           expect_pac=True,
                           expected_sid=sid,
                           expect_requester_sid=True)
        tgt = self._modify_tgt(tgt, from_rodc=True, invalid=True,
                               remove_requester_sid=True)

        self._validate_tgt(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_tgs_pac_request_none(self):
        creds = self._get_creds()
        tgt = self.get_tgt(creds, pac_request=None)

        ticket = self._run_tgs(tgt, creds, expected_error=0, expect_pac=True)

        pac = self.get_ticket_pac(ticket)
        self.assertIsNotNone(pac)

    def test_tgs_pac_request_false(self):
        creds = self._get_creds()
        tgt = self.get_tgt(creds, pac_request=False, expect_pac=None)

        ticket = self._run_tgs(tgt, creds, expected_error=0, expect_pac=False)

        pac = self.get_ticket_pac(ticket, expect_pac=False)
        if not self.always_include_pac:
            self.assertIsNone(pac)
        else:
            self.assertIsNotNone(pac)

    def test_tgs_pac_request_true(self):
        creds = self._get_creds()
        tgt = self.get_tgt(creds, pac_request=True)

        ticket = self._run_tgs(tgt, creds, expected_error=0, expect_pac=True)

        pac = self.get_ticket_pac(ticket)
        self.assertIsNotNone(pac)

    def test_renew_pac_request_none(self):
        creds = self._get_creds()
        tgt = self.get_tgt(creds, pac_request=None)
        tgt = self._modify_tgt(tgt, renewable=True)

        tgt = self._renew_tgt(tgt, creds, expected_error=0, expect_pac=None,
                              expect_pac_attrs=True,
                              expect_pac_attrs_pac_request=None,
                              expect_requester_sid=True)

        ticket = self._run_tgs(tgt, creds, expected_error=0, expect_pac=True)

        pac = self.get_ticket_pac(ticket)
        self.assertIsNotNone(pac)

    def test_renew_pac_request_false(self):
        creds = self._get_creds()
        tgt = self.get_tgt(creds, pac_request=False, expect_pac=None)
        tgt = self._modify_tgt(tgt, renewable=True)

        tgt = self._renew_tgt(tgt, creds, expected_error=0, expect_pac=None,
                              expect_pac_attrs=True,
                              expect_pac_attrs_pac_request=False,
                              expect_requester_sid=True)

        ticket = self._run_tgs(tgt, creds, expected_error=0, expect_pac=False)

        pac = self.get_ticket_pac(ticket, expect_pac=False)
        if not self.always_include_pac:
            self.assertIsNone(pac)
        else:
            self.assertIsNotNone(pac)

    def test_renew_pac_request_true(self):
        creds = self._get_creds()
        tgt = self.get_tgt(creds, pac_request=True)
        tgt = self._modify_tgt(tgt, renewable=True)

        tgt = self._renew_tgt(tgt, creds, expected_error=0, expect_pac=None,
                              expect_pac_attrs=True,
                              expect_pac_attrs_pac_request=True,
                              expect_requester_sid=True)

        ticket = self._run_tgs(tgt, creds, expected_error=0, expect_pac=True)

        pac = self.get_ticket_pac(ticket)
        self.assertIsNotNone(pac)

    def test_rodc_renew_pac_request_none(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        tgt = self.get_tgt(creds, pac_request=None)
        tgt = self._modify_tgt(tgt, renewable=True, from_rodc=True)

        tgt = self._renew_tgt(tgt, creds, expected_error=0, expect_pac=None,
                              expect_pac_attrs=False,
                              expect_requester_sid=True)

        ticket = self._run_tgs(tgt, creds, expected_error=0, expect_pac=True)

        pac = self.get_ticket_pac(ticket)
        self.assertIsNotNone(pac)

    def test_rodc_renew_pac_request_false(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        tgt = self.get_tgt(creds, pac_request=False, expect_pac=None)
        tgt = self._modify_tgt(tgt, renewable=True, from_rodc=True)

        tgt = self._renew_tgt(tgt, creds, expected_error=0, expect_pac=None,
                              expect_pac_attrs=False,
                              expect_requester_sid=True)

        ticket = self._run_tgs(tgt, creds, expected_error=0, expect_pac=True)

        pac = self.get_ticket_pac(ticket)
        self.assertIsNotNone(pac)

    def test_rodc_renew_pac_request_true(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        tgt = self.get_tgt(creds, pac_request=True)
        tgt = self._modify_tgt(tgt, renewable=True, from_rodc=True)

        tgt = self._renew_tgt(tgt, creds, expected_error=0, expect_pac=None,
                              expect_pac_attrs=False,
                              expect_requester_sid=True)

        ticket = self._run_tgs(tgt, creds, expected_error=0, expect_pac=True)

        pac = self.get_ticket_pac(ticket)
        self.assertIsNotNone(pac)

    def test_validate_pac_request_none(self):
        creds = self._get_creds()
        tgt = self.get_tgt(creds, pac_request=None)
        tgt = self._modify_tgt(tgt, invalid=True)

        tgt = self._validate_tgt(tgt, creds, expected_error=0, expect_pac=None,
                                 expect_pac_attrs=True,
                                 expect_pac_attrs_pac_request=None,
                                 expect_requester_sid=True)

        ticket = self._run_tgs(tgt, creds, expected_error=0, expect_pac=True)

        pac = self.get_ticket_pac(ticket)
        self.assertIsNotNone(pac)

    def test_validate_pac_request_false(self):
        creds = self._get_creds()
        tgt = self.get_tgt(creds, pac_request=False, expect_pac=None)
        tgt = self._modify_tgt(tgt, invalid=True)

        tgt = self._validate_tgt(tgt, creds, expected_error=0, expect_pac=None,
                                 expect_pac_attrs=True,
                                 expect_pac_attrs_pac_request=False,
                                 expect_requester_sid=True)

        ticket = self._run_tgs(tgt, creds, expected_error=0, expect_pac=False)

        pac = self.get_ticket_pac(ticket, expect_pac=False)
        if not self.always_include_pac:
            self.assertIsNone(pac)
        else:
            self.assertIsNotNone(pac)

    def test_validate_pac_request_true(self):
        creds = self._get_creds()
        tgt = self.get_tgt(creds, pac_request=True)
        tgt = self._modify_tgt(tgt, invalid=True)

        tgt = self._validate_tgt(tgt, creds, expected_error=0, expect_pac=None,
                                 expect_pac_attrs=True,
                                 expect_pac_attrs_pac_request=True,
                                 expect_requester_sid=True)

        ticket = self._run_tgs(tgt, creds, expected_error=0, expect_pac=True)

        pac = self.get_ticket_pac(ticket)
        self.assertIsNotNone(pac)

    def test_rodc_validate_pac_request_none(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        tgt = self.get_tgt(creds, pac_request=None)
        tgt = self._modify_tgt(tgt, invalid=True, from_rodc=True)

        tgt = self._validate_tgt(tgt, creds, expected_error=0, expect_pac=None,
                                 expect_pac_attrs=False,
                                 expect_requester_sid=True)

        ticket = self._run_tgs(tgt, creds, expected_error=0, expect_pac=True)

        pac = self.get_ticket_pac(ticket)
        self.assertIsNotNone(pac)

    def test_rodc_validate_pac_request_false(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        tgt = self.get_tgt(creds, pac_request=False, expect_pac=None)
        tgt = self._modify_tgt(tgt, invalid=True, from_rodc=True)

        tgt = self._validate_tgt(tgt, creds, expected_error=0, expect_pac=None,
                                 expect_pac_attrs=False,
                                 expect_requester_sid=True)

        ticket = self._run_tgs(tgt, creds, expected_error=0, expect_pac=True)

        pac = self.get_ticket_pac(ticket)
        self.assertIsNotNone(pac)

    def test_rodc_validate_pac_request_true(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        tgt = self.get_tgt(creds, pac_request=True)
        tgt = self._modify_tgt(tgt, invalid=True, from_rodc=True)

        tgt = self._validate_tgt(tgt, creds, expected_error=0, expect_pac=None,
                                 expect_pac_attrs=False,
                                 expect_requester_sid=True)

        ticket = self._run_tgs(tgt, creds, expected_error=0, expect_pac=True)

        pac = self.get_ticket_pac(ticket)
        self.assertIsNotNone(pac)

    def test_s4u2self_pac_request_none(self):
        creds = self._get_creds()
        tgt = self.get_tgt(creds, pac_request=None)

        ticket = self._s4u2self(tgt, creds, expected_error=0, expect_pac=True)

        pac = self.get_ticket_pac(ticket)
        self.assertIsNotNone(pac)

    def test_s4u2self_pac_request_false(self):
        creds = self._get_creds()
        tgt = self.get_tgt(creds, pac_request=False, expect_pac=None)

        ticket = self._s4u2self(tgt, creds, expected_error=0, expect_pac=True)

        pac = self.get_ticket_pac(ticket)
        self.assertIsNotNone(pac)

    def test_s4u2self_pac_request_true(self):
        creds = self._get_creds()
        tgt = self.get_tgt(creds, pac_request=True)

        ticket = self._s4u2self(tgt, creds, expected_error=0, expect_pac=True)

        pac = self.get_ticket_pac(ticket)
        self.assertIsNotNone(pac)

    def test_user2user_pac_request_none(self):
        creds = self._get_creds()
        tgt = self.get_tgt(creds, pac_request=None)

        ticket = self._user2user(tgt, creds, expected_error=0, expect_pac=True)

        pac = self.get_ticket_pac(ticket)
        self.assertIsNotNone(pac)

    def test_user2user_pac_request_false(self):
        creds = self._get_creds()
        tgt = self.get_tgt(creds, pac_request=False, expect_pac=None)

        ticket = self._user2user(tgt, creds, expected_error=0,
                                 expect_pac=True)

        pac = self.get_ticket_pac(ticket, expect_pac=True)
        self.assertIsNotNone(pac)

    def test_user2user_pac_request_true(self):
        creds = self._get_creds()
        tgt = self.get_tgt(creds, pac_request=True)

        ticket = self._user2user(tgt, creds, expected_error=0, expect_pac=True)

        pac = self.get_ticket_pac(ticket)
        self.assertIsNotNone(pac)

    def test_user2user_user_pac_request_none(self):
        creds = self._get_creds()
        tgt = self.get_tgt(creds)

        user_creds = self._get_mach_creds()
        user_tgt = self.get_tgt(user_creds, pac_request=None)

        ticket = self._user2user(tgt, creds, expected_error=0,
                                 user_tgt=user_tgt, user_creds=user_creds,
                                 expect_pac=True)

        pac = self.get_ticket_pac(ticket)
        self.assertIsNotNone(pac)

    def test_user2user_user_pac_request_false(self):
        creds = self._get_creds()
        tgt = self.get_tgt(creds)

        user_creds = self._get_mach_creds()
        user_tgt = self.get_tgt(user_creds, pac_request=False, expect_pac=None)

        ticket = self._user2user(tgt, creds, expected_error=0,
                                 user_tgt=user_tgt, user_creds=user_creds,
                                 expect_pac=False)

        pac = self.get_ticket_pac(ticket, expect_pac=False)
        if not self.always_include_pac:
            self.assertIsNone(pac)
        else:
            self.assertIsNotNone(pac)

    def test_user2user_user_pac_request_true(self):
        creds = self._get_creds()
        tgt = self.get_tgt(creds)

        user_creds = self._get_mach_creds()
        user_tgt = self.get_tgt(user_creds, pac_request=True)

        ticket = self._user2user(tgt, creds, expected_error=0,
                                 user_tgt=user_tgt, user_creds=user_creds,
                                 expect_pac=True)

        pac = self.get_ticket_pac(ticket)
        self.assertIsNotNone(pac)

    def test_fast_pac_request_none(self):
        creds = self._get_creds()
        tgt = self.get_tgt(creds, pac_request=None)

        ticket = self._fast(tgt, creds, expected_error=0, expect_pac=True)

        pac = self.get_ticket_pac(ticket)
        self.assertIsNotNone(pac)

    def test_fast_pac_request_false(self):
        creds = self._get_creds()
        tgt = self.get_tgt(creds, pac_request=False)

        ticket = self._fast(tgt, creds, expected_error=0,
                            expect_pac=True)

        pac = self.get_ticket_pac(ticket, expect_pac=True)
        self.assertIsNotNone(pac)

    def test_fast_pac_request_true(self):
        creds = self._get_creds()
        tgt = self.get_tgt(creds, pac_request=True)

        ticket = self._fast(tgt, creds, expected_error=0, expect_pac=True)

        pac = self.get_ticket_pac(ticket)
        self.assertIsNotNone(pac)

    def test_tgs_rodc_pac_request_none(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        tgt = self.get_tgt(creds, pac_request=None)
        tgt = self._modify_tgt(tgt, from_rodc=True)

        ticket = self._run_tgs(tgt, creds, expected_error=0, expect_pac=True)

        pac = self.get_ticket_pac(ticket)
        self.assertIsNotNone(pac)

    def test_tgs_rodc_pac_request_false(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        tgt = self.get_tgt(creds, pac_request=False, expect_pac=None)
        tgt = self._modify_tgt(tgt, from_rodc=True)

        ticket = self._run_tgs(tgt, creds, expected_error=0, expect_pac=True)

        pac = self.get_ticket_pac(ticket)
        self.assertIsNotNone(pac)

    def test_tgs_rodc_pac_request_true(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        tgt = self.get_tgt(creds, pac_request=True)
        tgt = self._modify_tgt(tgt, from_rodc=True)

        ticket = self._run_tgs(tgt, creds, expected_error=0, expect_pac=True)

        pac = self.get_ticket_pac(ticket)
        self.assertIsNotNone(pac)

    def test_tgs_rename(self):
        creds = self.get_cached_creds(account_type=self.AccountType.USER,
                                      use_cache=False)
        tgt = self.get_tgt(creds)

        # Rename the account.
        new_name = self.get_new_username()

        samdb = self.get_samdb()
        msg = ldb.Message(creds.get_dn())
        msg['sAMAccountName'] = ldb.MessageElement(new_name,
                                                   ldb.FLAG_MOD_REPLACE,
                                                   'sAMAccountName')
        samdb.modify(msg)

        self._run_tgs(tgt, creds, expected_error=(KDC_ERR_TGT_REVOKED,
                                                  KDC_ERR_C_PRINCIPAL_UNKNOWN))

    # Test making a TGS request for a ticket expiring post-2038.
    def test_tgs_req_future_till(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds)

        target_creds = self.get_service_creds()
        self._tgs_req(
            tgt=tgt,
            expected_error=0,
            creds=creds,
            target_creds=target_creds,
            till='99990913024805Z')

    def test_tgs_unicode(self):
        creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'name_prefix': '🔐'})
        tgt = self._get_tgt(creds)
        self._run_tgs(tgt, creds, expected_error=0)

    def test_renew_unicode(self):
        creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'name_prefix': '🔐'})
        tgt = self._get_tgt(creds, renewable=True)
        self._renew_tgt(tgt, creds, expected_error=0,
                        expect_pac_attrs=True,
                        expect_pac_attrs_pac_request=True,
                        expect_requester_sid=True)

    def test_validate_unicode(self):
        creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'name_prefix': '🔐'})
        tgt = self._get_tgt(creds, invalid=True)
        self._validate_tgt(tgt, creds, expected_error=0,
                           expect_pac_attrs=True,
                           expect_pac_attrs_pac_request=True,
                           expect_requester_sid=True)

    def test_s4u2self_unicode(self):
        creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'name_prefix': '🔐'})
        tgt = self._get_tgt(creds)
        self._s4u2self(tgt, creds,
                       expected_error=0,
                       expect_edata=False)

    def test_user2user_unicode(self):
        creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'name_prefix': '🔐'})
        tgt = self._get_tgt(creds)
        self._user2user(tgt, creds, expected_error=0)

    def test_fast_unicode(self):
        creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'name_prefix': '🔐'})
        tgt = self._get_tgt(creds)
        self._fast(tgt, creds, expected_error=0)

    def test_fast_as_req_unicode(self):
        creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'name_prefix': '🔐'})
        tgt = self._get_tgt(creds)
        self._fast_as_req(tgt, creds, expected_error=0)

    def _modify_renewable(self, enc_part):
        # Set the renewable flag.
        enc_part = self.modify_ticket_flag(enc_part, 'renewable', value=True)

        # Set the renew-till time to be in the future.
        renew_till = self.get_KerberosTime(offset=100 * 60 * 60)
        enc_part['renew-till'] = renew_till

        return enc_part

    def _modify_invalid(self, enc_part):
        # Set the invalid flag.
        enc_part = self.modify_ticket_flag(enc_part, 'invalid', value=True)

        # Set the ticket start time to be in the past.
        past_time = self.get_KerberosTime(offset=-100 * 60 * 60)
        enc_part['starttime'] = past_time

        return enc_part

    def _get_tgt(self,
                 client_creds,
                 renewable=False,
                 invalid=False,
                 from_rodc=False,
                 new_rid=None,
                 remove_pac=False,
                 allow_empty_authdata=False,
                 can_modify_logon_info=True,
                 can_modify_requester_sid=True,
                 can_modify_upn_dns_ex=True,
                 remove_pac_attrs=False,
                 remove_requester_sid=False,
                 etype=None,
                 cksum_etype=None,
                 extra_pac_buffers=None):
        self.assertFalse(renewable and invalid)

        if remove_pac:
            self.assertIsNone(new_rid)

        tgt = self.get_tgt(client_creds)

        return self._modify_tgt(
            tgt=tgt,
            renewable=renewable,
            invalid=invalid,
            from_rodc=from_rodc,
            new_rid=new_rid,
            remove_pac=remove_pac,
            allow_empty_authdata=allow_empty_authdata,
            can_modify_logon_info=can_modify_logon_info,
            can_modify_requester_sid=can_modify_requester_sid,
            can_modify_upn_dns_ex=can_modify_upn_dns_ex,
            remove_pac_attrs=remove_pac_attrs,
            remove_requester_sid=remove_requester_sid,
            etype=etype,
            cksum_etype=cksum_etype,
            extra_pac_buffers=extra_pac_buffers)

    def _modify_tgt(self,
                    tgt,
                    *,
                    renewable=False,
                    invalid=False,
                    from_rodc=False,
                    new_rid=None,
                    remove_pac=False,
                    allow_empty_authdata=False,
                    cname=None,
                    crealm=None,
                    can_modify_logon_info=True,
                    can_modify_requester_sid=True,
                    can_modify_upn_dns_ex=True,
                    remove_pac_attrs=False,
                    remove_requester_sid=False,
                    etype=None,
                    cksum_etype=None,
                    extra_pac_buffers=None):
        if from_rodc:
            krbtgt_creds = self.get_mock_rodc_krbtgt_creds()
        else:
            krbtgt_creds = self.get_krbtgt_creds()

        modify_pac_fns = []

        if new_rid is not None or remove_requester_sid or remove_pac_attrs:
            def change_sid_fn(pac):
                pac_buffers = pac.buffers
                for pac_buffer in pac_buffers:
                    if pac_buffer.type == krb5pac.PAC_TYPE_LOGON_INFO:
                        if new_rid is not None and can_modify_logon_info:
                            logon_info = pac_buffer.info.info

                            logon_info.info3.base.rid = new_rid
                    elif pac_buffer.type == krb5pac.PAC_TYPE_UPN_DNS_INFO:
                        if new_rid is not None and can_modify_upn_dns_ex:
                            upn_dns = pac_buffer.info

                            samdb = self.get_samdb()
                            domain_sid = samdb.get_domain_sid()

                            new_sid = f'{domain_sid}-{new_rid}'
                            if upn_dns.flags & krb5pac.PAC_UPN_DNS_FLAG_HAS_SAM_NAME_AND_SID:
                                upn_dns.ex.objectsid = security.dom_sid(new_sid)
                    elif pac_buffer.type == krb5pac.PAC_TYPE_REQUESTER_SID:
                        if remove_requester_sid:
                            pac.num_buffers -= 1
                            pac_buffers.remove(pac_buffer)
                        elif new_rid is not None and can_modify_requester_sid:
                            requester_sid = pac_buffer.info

                            samdb = self.get_samdb()
                            domain_sid = samdb.get_domain_sid()

                            new_sid = f'{domain_sid}-{new_rid}'

                            requester_sid.sid = security.dom_sid(new_sid)
                    elif pac_buffer.type == krb5pac.PAC_TYPE_ATTRIBUTES_INFO:
                        if remove_pac_attrs:
                            pac.num_buffers -= 1
                            pac_buffers.remove(pac_buffer)

                pac.buffers = pac_buffers

                return pac

            modify_pac_fns.append(change_sid_fn)

        krbtgt_key = self.TicketDecryptionKey_from_creds(krbtgt_creds,
                                                         etype)

        if remove_pac:
            checksum_keys = None
        else:
            if etype == cksum_etype:
                cksum_key = krbtgt_key
            else:
                cksum_key = self.TicketDecryptionKey_from_creds(krbtgt_creds,
                                                                cksum_etype)
            checksum_keys = {
                krb5pac.PAC_TYPE_KDC_CHECKSUM: cksum_key
            }

        if renewable:
            flags_modify_fn = self._modify_renewable
        elif invalid:
            flags_modify_fn = self._modify_invalid
        else:
            flags_modify_fn = None

        if cname is not None or crealm is not None:
            def modify_fn(enc_part):
                if flags_modify_fn is not None:
                    enc_part = flags_modify_fn(enc_part)

                if cname is not None:
                    enc_part['cname'] = cname

                if crealm is not None:
                    enc_part['crealm'] = crealm

                return enc_part
        else:
            modify_fn = flags_modify_fn

        if cname is not None:
            def change_cname_fn(pac):
                for pac_buffer in pac.buffers:
                    if pac_buffer.type == krb5pac.PAC_TYPE_LOGON_NAME:
                        logon_info = pac_buffer.info

                        logon_info.account_name = (
                            cname['name-string'][0].decode('utf-8'))

                return pac

            modify_pac_fns.append(change_cname_fn)

        if extra_pac_buffers is not None:
            modify_pac_fns.append(partial(self.add_extra_pac_buffers,
                                          buffers=extra_pac_buffers))

        return self.modified_ticket(
            tgt,
            new_ticket_key=krbtgt_key,
            modify_fn=modify_fn,
            modify_pac_fn=modify_pac_fns or None,
            exclude_pac=remove_pac,
            allow_empty_authdata=allow_empty_authdata,
            update_pac_checksums=not remove_pac,
            checksum_keys=checksum_keys)

    def _remove_rodc_partial_secrets(self):
        samdb = self.get_samdb()

        rodc_ctx = self.get_mock_rodc_ctx()
        rodc_dn = ldb.Dn(samdb, rodc_ctx.acct_dn)

        def add_rodc_partial_secrets():
            msg = ldb.Message()
            msg.dn = rodc_dn
            msg['userAccountControl'] = ldb.MessageElement(
                str(rodc_ctx.userAccountControl),
                ldb.FLAG_MOD_REPLACE,
                'userAccountControl')
            samdb.modify(msg)

        self.addCleanup(add_rodc_partial_secrets)

        uac = rodc_ctx.userAccountControl & ~dsdb.UF_PARTIAL_SECRETS_ACCOUNT

        msg = ldb.Message()
        msg.dn = rodc_dn
        msg['userAccountControl'] = ldb.MessageElement(
            str(uac),
            ldb.FLAG_MOD_REPLACE,
            'userAccountControl')
        samdb.modify(msg)

    def _remove_rodc_krbtgt_link(self):
        samdb = self.get_samdb()

        rodc_ctx = self.get_mock_rodc_ctx()
        rodc_dn = ldb.Dn(samdb, rodc_ctx.acct_dn)

        def add_rodc_krbtgt_link():
            msg = ldb.Message()
            msg.dn = rodc_dn
            msg['msDS-KrbTgtLink'] = ldb.MessageElement(
                rodc_ctx.new_krbtgt_dn,
                ldb.FLAG_MOD_ADD,
                'msDS-KrbTgtLink')
            samdb.modify(msg)

        self.addCleanup(add_rodc_krbtgt_link)

        msg = ldb.Message()
        msg.dn = rodc_dn
        msg['msDS-KrbTgtLink'] = ldb.MessageElement(
            [],
            ldb.FLAG_MOD_DELETE,
            'msDS-KrbTgtLink')
        samdb.modify(msg)

    def _get_creds(self,
                   replication_allowed=False,
                   replication_denied=False,
                   revealed_to_rodc=False):
        return self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={
                'allowed_replication_mock': replication_allowed,
                'denied_replication_mock': replication_denied,
                'revealed_to_mock_rodc': revealed_to_rodc,
                'id': 0
            })

    def _get_existing_rid(self,
                          replication_allowed=False,
                          replication_denied=False,
                          revealed_to_rodc=False):
        other_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={
                'allowed_replication_mock': replication_allowed,
                'denied_replication_mock': replication_denied,
                'revealed_to_mock_rodc': revealed_to_rodc,
                'id': 1
            })

        other_sid = other_creds.get_sid()
        other_rid = int(other_sid.rsplit('-', 1)[1])

        return other_rid

    def _get_mach_creds(self):
        return self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={
                'allowed_replication_mock': True,
                'denied_replication_mock': False,
                'revealed_to_mock_rodc': True,
                'id': 2
            })

    def _get_user_creds(self,
                   replication_allowed=False,
                   replication_denied=False,
                   revealed_to_rodc=False):
        return self.get_cached_creds(
            account_type=self.AccountType.USER,
            opts={
                'allowed_replication_mock': replication_allowed,
                'denied_replication_mock': replication_denied,
                'revealed_to_mock_rodc': revealed_to_rodc,
                'id': 3
            })

    def _get_non_existent_rid(self):
        return (1 << 30) - 1

    def _run_tgs(self, tgt, creds, expected_error, *, expect_pac=True,
                 expect_pac_attrs=None, expect_pac_attrs_pac_request=None,
                 expect_requester_sid=None, expected_sid=None,
                 expect_edata=False, expect_status=None, expected_status=None,
                 expected_extra_pac_buffers=None):
        target_creds = self.get_service_creds()
        return self._tgs_req(
            tgt, expected_error, creds, target_creds,
            expect_pac=expect_pac,
            expect_pac_attrs=expect_pac_attrs,
            expect_pac_attrs_pac_request=expect_pac_attrs_pac_request,
            expect_requester_sid=expect_requester_sid,
            expected_sid=expected_sid,
            expect_edata=expect_edata,
            expect_status=expect_status,
            expected_status=expected_status,
            expected_extra_pac_buffers=expected_extra_pac_buffers)

    # These tests fail against Windows, which does not implement ticket
    # renewal.
    def _renew_tgt(self, tgt, creds, expected_error, *, expect_pac=True,
                   expect_pac_attrs=None, expect_pac_attrs_pac_request=None,
                   expect_requester_sid=None, expected_sid=None):
        krbtgt_creds = self.get_krbtgt_creds()
        kdc_options = str(krb5_asn1.KDCOptions('renew'))
        return self._tgs_req(
            tgt, expected_error, creds, krbtgt_creds,
            kdc_options=kdc_options,
            expect_pac=expect_pac,
            expect_pac_attrs=expect_pac_attrs,
            expect_pac_attrs_pac_request=expect_pac_attrs_pac_request,
            expect_requester_sid=expect_requester_sid,
            expected_sid=expected_sid)

    # These tests fail against Windows, which does not implement ticket
    # validation.
    def _validate_tgt(self, tgt, creds, expected_error, *, expect_pac=True,
                      expect_pac_attrs=None,
                      expect_pac_attrs_pac_request=None,
                      expect_requester_sid=None,
                      expected_sid=None):
        krbtgt_creds = self.get_krbtgt_creds()
        kdc_options = str(krb5_asn1.KDCOptions('validate'))
        return self._tgs_req(
            tgt, expected_error, creds, krbtgt_creds,
            kdc_options=kdc_options,
            expect_pac=expect_pac,
            expect_pac_attrs=expect_pac_attrs,
            expect_pac_attrs_pac_request=expect_pac_attrs_pac_request,
            expect_requester_sid=expect_requester_sid,
            expected_sid=expected_sid)

    def _s4u2self(self, tgt, tgt_creds, expected_error, *, expect_pac=True,
                  expect_edata=False, expect_status=None,
                  expected_status=None):
        user_creds = self._get_mach_creds()

        user_name = user_creds.get_username()
        user_cname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                               names=[user_name])
        user_realm = user_creds.get_realm()

        def generate_s4u2self_padata(_kdc_exchange_dict,
                                     _callback_dict,
                                     req_body):
            padata = self.PA_S4U2Self_create(
                name=user_cname,
                realm=user_realm,
                tgt_session_key=tgt.session_key,
                ctype=None)

            return [padata], req_body

        return self._tgs_req(tgt, expected_error, tgt_creds, tgt_creds,
                             expected_cname=user_cname,
                             generate_padata_fn=generate_s4u2self_padata,
                             expect_edata=expect_edata,
                             expect_status=expect_status,
                             expected_status=expected_status,
                             expect_pac=expect_pac)

    def _user2user(self, tgt, tgt_creds, expected_error, *,
                   sname=None,
                   srealm=None, user_tgt=None, user_creds=None,
                   expect_edata=False,
                   expect_pac=True, expected_status=None):
        if user_tgt is None:
            user_creds = self._get_mach_creds()
            user_tgt = self.get_tgt(user_creds)
        else:
            self.assertIsNotNone(user_creds,
                                 'if supplying user_tgt, user_creds should be '
                                 'supplied also')

        kdc_options = str(krb5_asn1.KDCOptions('enc-tkt-in-skey'))
        return self._tgs_req(user_tgt, expected_error, user_creds, tgt_creds,
                             kdc_options=kdc_options,
                             additional_ticket=tgt,
                             sname=sname,
                             srealm=srealm,
                             expect_edata=expect_edata,
                             expect_pac=expect_pac,
                             expected_status=expected_status)

    def _fast(self, armor_tgt, armor_tgt_creds, expected_error,
              expected_sname=None, expect_pac=True, expect_edata=False):
        user_creds = self._get_mach_creds()
        user_tgt = self.get_tgt(user_creds)

        target_creds = self.get_service_creds()

        return self._tgs_req(user_tgt, expected_error,
                             user_creds, target_creds,
                             armor_tgt=armor_tgt,
                             expected_sname=expected_sname,
                             expect_pac=expect_pac,
                             expect_edata=expect_edata)

    def _fast_as_req(self, armor_tgt, armor_tgt_creds, expected_error,
                     expected_sname=None):
        user_creds = self._get_mach_creds()
        target_creds = self.get_service_creds()

        return self._armored_as_req(user_creds, target_creds, armor_tgt,
                                    expected_error=expected_error,
                                    expected_sname=expected_sname,
                                    expect_edata=False)


if __name__ == "__main__":
    global_asn1_print = False
    global_hexdump = False
    import unittest
    unittest.main()
