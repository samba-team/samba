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

import ldb


from samba import dsdb

from samba.dcerpc import krb5pac

sys.path.insert(0, "bin/python")
os.environ["PYTHONUNBUFFERED"] = "1"

import samba.tests.krb5.kcrypto as kcrypto
from samba.tests.krb5.kdc_base_test import KDCBaseTest
from samba.tests.krb5.rfc4120_constants import (
    AES256_CTS_HMAC_SHA1_96,
    ARCFOUR_HMAC_MD5,
    KRB_ERROR,
    KRB_TGS_REP,
    KDC_ERR_BADMATCH,
    KDC_ERR_BADOPTION,
    KDC_ERR_CLIENT_NAME_MISMATCH,
    KDC_ERR_POLICY,
    KDC_ERR_S_PRINCIPAL_UNKNOWN,
    KDC_ERR_TGT_REVOKED,
    NT_PRINCIPAL,
    NT_SRV_INST,
)
import samba.tests.krb5.rfc4120_pyasn1 as krb5_asn1

global_asn1_print = False
global_hexdump = False


class KdcTgsTests(KDCBaseTest):

    def setUp(self):
        super().setUp()
        self.do_asn1_print = global_asn1_print
        self.do_hexdump = global_hexdump

    def test_tgs_req_cname_does_not_not_match_authenticator_cname(self):
        ''' Try and obtain a ticket from the TGS, but supply a cname
            that differs from that provided to the krbtgt
        '''
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
        '''Get a ticket to the ldap service
        '''
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
        sid = self.get_objectSid(samdb, dn)
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

    def _make_tgs_request(self, client_creds, service_creds, tgt,
                          pac_request=None, expect_pac=True,
                          expect_error=False,
                          expected_account_name=None,
                          expected_upn_name=None,
                          expected_sid=None):
        client_account = client_creds.get_username()
        cname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                          names=[client_account])

        service_account = service_creds.get_username()
        sname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                          names=[service_account])

        realm = service_creds.get_realm()

        expected_crealm = realm
        expected_cname = cname
        expected_srealm = realm
        expected_sname = sname

        expected_supported_etypes = service_creds.tgs_supported_enctypes

        etypes = (AES256_CTS_HMAC_SHA1_96, ARCFOUR_HMAC_MD5)

        kdc_options = str(krb5_asn1.KDCOptions('canonicalize'))

        target_decryption_key = self.TicketDecryptionKey_from_creds(
            service_creds)

        authenticator_subkey = self.RandomKey(kcrypto.Enctype.AES256)

        if expect_error:
            expected_error_mode = KDC_ERR_BADOPTION
            check_error_fn = self.generic_check_kdc_error
            check_rep_fn = None
        else:
            expected_error_mode = 0
            check_error_fn = None
            check_rep_fn = self.generic_check_kdc_rep

        kdc_exchange_dict = self.tgs_exchange_dict(
            expected_crealm=expected_crealm,
            expected_cname=expected_cname,
            expected_srealm=expected_srealm,
            expected_sname=expected_sname,
            expected_account_name=expected_account_name,
            expected_upn_name=expected_upn_name,
            expected_sid=expected_sid,
            expected_supported_etypes=expected_supported_etypes,
            ticket_decryption_key=target_decryption_key,
            check_error_fn=check_error_fn,
            check_rep_fn=check_rep_fn,
            check_kdc_private_fn=self.generic_check_kdc_private,
            expected_error_mode=expected_error_mode,
            tgt=tgt,
            authenticator_subkey=authenticator_subkey,
            kdc_options=kdc_options,
            pac_request=pac_request,
            expect_pac=expect_pac)

        rep = self._generic_kdc_exchange(kdc_exchange_dict,
                                         cname=cname,
                                         realm=realm,
                                         sname=sname,
                                         etypes=etypes)
        if expect_error:
            self.check_error_rep(rep, expected_error_mode)

            return None
        else:
            self.check_reply(rep, KRB_TGS_REP)

            return kdc_exchange_dict['rep_ticket_creds']

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
        self.assertIsNone(pac)

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
                               expect_pac=False, expect_error=True)

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
                               expect_pac=False, expect_error=True)

    def test_remove_pac(self):
        client_creds = self.get_client_creds()
        service_creds = self.get_service_creds()

        tgt = self.modified_ticket(self.get_tgt(client_creds),
                                   exclude_pac=True)

        pac = self.get_ticket_pac(tgt, expect_pac=False)
        self.assertIsNone(pac)

        self._make_tgs_request(client_creds, service_creds, tgt,
                               expect_pac=False, expect_error=True)

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

        samdb = self.get_samdb()
        dn = client_creds.get_dn()

        account_name = client_creds.get_username()
        upn_name = client_creds.get_upn()
        if upn_name is None:
            realm = client_creds.get_realm().lower()
            upn_name = f'{account_name}@{realm}'
        sid = self.get_objectSid(samdb, dn)

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
        self._run_tgs(tgt, expected_error=0)

    def test_renew_req(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds, renewable=True)
        self._renew_tgt(tgt, expected_error=0)

    def test_validate_req(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds, invalid=True)
        self._validate_tgt(tgt, expected_error=0)

    def test_s4u2self_req(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds)
        self._s4u2self(tgt, creds, expected_error=0)

    def test_user2user_req(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds)
        self._user2user(tgt, creds, expected_error=0)

    # Test making a request without a PAC.
    def test_tgs_no_pac(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds, remove_pac=True)
        self._run_tgs(tgt, expected_error=KDC_ERR_BADOPTION)

    def test_renew_no_pac(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds, renewable=True, remove_pac=True)
        self._renew_tgt(tgt, expected_error=KDC_ERR_BADOPTION)

    def test_validate_no_pac(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds, invalid=True, remove_pac=True)
        self._validate_tgt(tgt, expected_error=KDC_ERR_BADOPTION)

    def test_s4u2self_no_pac(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds, remove_pac=True)
        self._s4u2self(tgt, creds, expected_error=KDC_ERR_BADOPTION)

    def test_user2user_no_pac(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds, remove_pac=True)
        self._user2user(tgt, creds, expected_error=KDC_ERR_BADOPTION)

    # Test making a request with authdata and without a PAC.
    def test_tgs_authdata_no_pac(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds, remove_pac=True, allow_empty_authdata=True)
        self._run_tgs(tgt, expected_error=KDC_ERR_BADOPTION)

    def test_renew_authdata_no_pac(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds, renewable=True, remove_pac=True,
                            allow_empty_authdata=True)
        self._renew_tgt(tgt, expected_error=KDC_ERR_BADOPTION)

    def test_validate_authdata_no_pac(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds, invalid=True, remove_pac=True,
                            allow_empty_authdata=True)
        self._validate_tgt(tgt, expected_error=KDC_ERR_BADOPTION)

    def test_s4u2self_authdata_no_pac(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds, remove_pac=True, allow_empty_authdata=True)
        self._s4u2self(tgt, creds, expected_error=KDC_ERR_BADOPTION)

    def test_user2user_authdata_no_pac(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds, remove_pac=True, allow_empty_authdata=True)
        self._user2user(tgt, creds, expected_error=KDC_ERR_BADOPTION)

    # Test changing the SID in the PAC to that of another account.
    def test_tgs_sid_mismatch_existing(self):
        creds = self._get_creds()
        existing_rid = self._get_existing_rid()
        tgt = self._get_tgt(creds, new_rid=existing_rid)
        self._run_tgs(tgt, expected_error=KDC_ERR_CLIENT_NAME_MISMATCH)

    def test_renew_sid_mismatch_existing(self):
        creds = self._get_creds()
        existing_rid = self._get_existing_rid()
        tgt = self._get_tgt(creds, renewable=True, new_rid=existing_rid)
        self._renew_tgt(tgt, expected_error=KDC_ERR_CLIENT_NAME_MISMATCH)

    def test_validate_sid_mismatch_existing(self):
        creds = self._get_creds()
        existing_rid = self._get_existing_rid()
        tgt = self._get_tgt(creds, invalid=True, new_rid=existing_rid)
        self._validate_tgt(tgt, expected_error=KDC_ERR_CLIENT_NAME_MISMATCH)

    def test_s4u2self_sid_mismatch_existing(self):
        creds = self._get_creds()
        existing_rid = self._get_existing_rid()
        tgt = self._get_tgt(creds, new_rid=existing_rid)
        self._s4u2self(tgt, creds,
                       expected_error=KDC_ERR_CLIENT_NAME_MISMATCH)

    def test_user2user_sid_mismatch_existing(self):
        creds = self._get_creds()
        existing_rid = self._get_existing_rid()
        tgt = self._get_tgt(creds, new_rid=existing_rid)
        self._user2user(tgt, creds,
                        expected_error=KDC_ERR_CLIENT_NAME_MISMATCH)

    # Test changing the SID in the PAC to a non-existent one.
    def test_tgs_sid_mismatch_nonexisting(self):
        creds = self._get_creds()
        nonexistent_rid = self._get_non_existent_rid()
        tgt = self._get_tgt(creds, new_rid=nonexistent_rid)
        self._run_tgs(tgt, expected_error=KDC_ERR_CLIENT_NAME_MISMATCH)

    def test_renew_sid_mismatch_nonexisting(self):
        creds = self._get_creds()
        nonexistent_rid = self._get_non_existent_rid()
        tgt = self._get_tgt(creds, renewable=True,
                            new_rid=nonexistent_rid)
        self._renew_tgt(tgt, expected_error=KDC_ERR_CLIENT_NAME_MISMATCH)

    def test_validate_sid_mismatch_nonexisting(self):
        creds = self._get_creds()
        nonexistent_rid = self._get_non_existent_rid()
        tgt = self._get_tgt(creds, invalid=True,
                            new_rid=nonexistent_rid)
        self._validate_tgt(tgt, expected_error=KDC_ERR_CLIENT_NAME_MISMATCH)

    def test_s4u2self_sid_mismatch_nonexisting(self):
        creds = self._get_creds()
        nonexistent_rid = self._get_non_existent_rid()
        tgt = self._get_tgt(creds, new_rid=nonexistent_rid)
        self._s4u2self(tgt, creds,
                       expected_error=KDC_ERR_CLIENT_NAME_MISMATCH)

    def test_user2user_sid_mismatch_nonexisting(self):
        creds = self._get_creds()
        nonexistent_rid = self._get_non_existent_rid()
        tgt = self._get_tgt(creds, new_rid=nonexistent_rid)
        self._user2user(tgt, creds,
                        expected_error=KDC_ERR_CLIENT_NAME_MISMATCH)

    # Test with an RODC-issued ticket where the client is revealed to the RODC.
    def test_tgs_rodc_revealed(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, from_rodc=True)
        self._run_tgs(tgt, expected_error=0)

    def test_renew_rodc_revealed(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, renewable=True, from_rodc=True)
        self._renew_tgt(tgt, expected_error=0)

    def test_validate_rodc_revealed(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, invalid=True, from_rodc=True)
        self._validate_tgt(tgt, expected_error=0)

    def test_s4u2self_rodc_revealed(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, from_rodc=True)
        self._s4u2self(tgt, creds, expected_error=0)

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
        self._run_tgs(tgt, expected_error=KDC_ERR_CLIENT_NAME_MISMATCH)

    def test_renew_rodc_sid_mismatch_existing(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        existing_rid = self._get_existing_rid(replication_allowed=True,
                                              revealed_to_rodc=True)
        tgt = self._get_tgt(creds, renewable=True, from_rodc=True,
                            new_rid=existing_rid)
        self._renew_tgt(tgt, expected_error=KDC_ERR_CLIENT_NAME_MISMATCH)

    def test_validate_rodc_sid_mismatch_existing(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        existing_rid = self._get_existing_rid(replication_allowed=True,
                                       revealed_to_rodc=True)
        tgt = self._get_tgt(creds, invalid=True, from_rodc=True,
                            new_rid=existing_rid)
        self._validate_tgt(tgt, expected_error=KDC_ERR_CLIENT_NAME_MISMATCH)

    def test_s4u2self_rodc_sid_mismatch_existing(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        existing_rid = self._get_existing_rid(replication_allowed=True,
                                              revealed_to_rodc=True)
        tgt = self._get_tgt(creds, from_rodc=True, new_rid=existing_rid)
        self._s4u2self(tgt, creds, expected_error=KDC_ERR_CLIENT_NAME_MISMATCH)

    def test_user2user_rodc_sid_mismatch_existing(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        existing_rid = self._get_existing_rid(replication_allowed=True,
                                              revealed_to_rodc=True)
        tgt = self._get_tgt(creds, from_rodc=True, new_rid=existing_rid)
        self._user2user(tgt, creds,
                        expected_error=KDC_ERR_CLIENT_NAME_MISMATCH)

    # Test with an RODC-issued ticket where the SID in the PAC is changed to a
    # non-existent one.
    def test_tgs_rodc_sid_mismatch_nonexisting(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        nonexistent_rid = self._get_non_existent_rid()
        tgt = self._get_tgt(creds, from_rodc=True, new_rid=nonexistent_rid)
        self._run_tgs(tgt, expected_error=KDC_ERR_CLIENT_NAME_MISMATCH)

    def test_renew_rodc_sid_mismatch_nonexisting(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        nonexistent_rid = self._get_non_existent_rid()
        tgt = self._get_tgt(creds, renewable=True, from_rodc=True,
                            new_rid=nonexistent_rid)
        self._renew_tgt(tgt, expected_error=KDC_ERR_CLIENT_NAME_MISMATCH)

    def test_validate_rodc_sid_mismatch_nonexisting(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        nonexistent_rid = self._get_non_existent_rid()
        tgt = self._get_tgt(creds, invalid=True, from_rodc=True,
                            new_rid=nonexistent_rid)
        self._validate_tgt(tgt, expected_error=KDC_ERR_CLIENT_NAME_MISMATCH)

    def test_s4u2self_rodc_sid_mismatch_nonexisting(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        nonexistent_rid = self._get_non_existent_rid()
        tgt = self._get_tgt(creds, from_rodc=True, new_rid=nonexistent_rid)
        self._s4u2self(tgt, creds, expected_error=KDC_ERR_CLIENT_NAME_MISMATCH)

    def test_user2user_rodc_sid_mismatch_nonexisting(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        nonexistent_rid = self._get_non_existent_rid()
        tgt = self._get_tgt(creds, from_rodc=True, new_rid=nonexistent_rid)
        self._user2user(tgt, creds,
                        expected_error=KDC_ERR_CLIENT_NAME_MISMATCH)

    # Test with an RODC-issued ticket where the client is not revealed to the
    # RODC.
    def test_tgs_rodc_not_revealed(self):
        creds = self._get_creds(replication_allowed=True)
        tgt = self._get_tgt(creds, from_rodc=True)
        # TODO: error code
        self._run_tgs(tgt, expected_error=KDC_ERR_TGT_REVOKED)

    def test_renew_rodc_not_revealed(self):
        creds = self._get_creds(replication_allowed=True)
        tgt = self._get_tgt(creds, renewable=True, from_rodc=True)
        self._renew_tgt(tgt, expected_error=KDC_ERR_TGT_REVOKED)

    def test_validate_rodc_not_revealed(self):
        creds = self._get_creds(replication_allowed=True)
        tgt = self._get_tgt(creds, invalid=True, from_rodc=True)
        self._validate_tgt(tgt, expected_error=KDC_ERR_TGT_REVOKED)

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
        self._run_tgs(tgt, expected_error=KDC_ERR_POLICY)

    def test_renew_rodc_no_partial_secrets(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, renewable=True, from_rodc=True)
        self._remove_rodc_partial_secrets()
        self._renew_tgt(tgt, expected_error=KDC_ERR_POLICY)

    def test_validate_rodc_no_partial_secrets(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, invalid=True, from_rodc=True)
        self._remove_rodc_partial_secrets()
        self._validate_tgt(tgt, expected_error=KDC_ERR_POLICY)

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

    # Test with an RODC-issued ticket where the RODC account does not have an
    # msDS-KrbTgtLink.
    def test_tgs_rodc_no_krbtgt_link(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, from_rodc=True)
        self._remove_rodc_krbtgt_link()
        self._run_tgs(tgt, expected_error=KDC_ERR_POLICY)

    def test_renew_rodc_no_krbtgt_link(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, renewable=True, from_rodc=True)
        self._remove_rodc_krbtgt_link()
        self._renew_tgt(tgt, expected_error=KDC_ERR_POLICY)

    def test_validate_rodc_no_krbtgt_link(self):
        creds = self._get_creds(replication_allowed=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, invalid=True, from_rodc=True)
        self._remove_rodc_krbtgt_link()
        self._validate_tgt(tgt, expected_error=KDC_ERR_POLICY)

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

    # Test with an RODC-issued ticket where the client is not allowed to
    # replicate to the RODC.
    def test_tgs_rodc_not_allowed(self):
        creds = self._get_creds(revealed_to_rodc=True)
        tgt = self._get_tgt(creds, from_rodc=True)
        self._run_tgs(tgt, expected_error=KDC_ERR_TGT_REVOKED)

    def test_renew_rodc_not_allowed(self):
        creds = self._get_creds(revealed_to_rodc=True)
        tgt = self._get_tgt(creds, renewable=True, from_rodc=True)
        self._renew_tgt(tgt, expected_error=KDC_ERR_TGT_REVOKED)

    def test_validate_rodc_not_allowed(self):
        creds = self._get_creds(revealed_to_rodc=True)
        tgt = self._get_tgt(creds, invalid=True, from_rodc=True)
        self._validate_tgt(tgt, expected_error=KDC_ERR_TGT_REVOKED)

    def test_s4u2self_rodc_not_allowed(self):
        creds = self._get_creds(revealed_to_rodc=True)
        tgt = self._get_tgt(creds, from_rodc=True)
        self._s4u2self(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    def test_user2user_rodc_not_allowed(self):
        creds = self._get_creds(revealed_to_rodc=True)
        tgt = self._get_tgt(creds, from_rodc=True)
        self._user2user(tgt, creds, expected_error=KDC_ERR_TGT_REVOKED)

    # Test with an RODC-issued ticket where the client is denied from
    # replicating to the RODC.
    def test_tgs_rodc_denied(self):
        creds = self._get_creds(replication_denied=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, from_rodc=True)
        self._run_tgs(tgt, expected_error=KDC_ERR_TGT_REVOKED)

    def test_renew_rodc_denied(self):
        creds = self._get_creds(replication_denied=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, renewable=True, from_rodc=True)
        self._renew_tgt(tgt, expected_error=KDC_ERR_TGT_REVOKED)

    def test_validate_rodc_denied(self):
        creds = self._get_creds(replication_denied=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, invalid=True, from_rodc=True)
        self._validate_tgt(tgt, expected_error=KDC_ERR_TGT_REVOKED)

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

    # Test with an RODC-issued ticket where the client is both allowed and
    # denied replicating to the RODC.
    def test_tgs_rodc_allowed_denied(self):
        creds = self._get_creds(replication_allowed=True,
                                replication_denied=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, from_rodc=True)
        self._run_tgs(tgt, expected_error=KDC_ERR_TGT_REVOKED)

    def test_renew_rodc_allowed_denied(self):
        creds = self._get_creds(replication_allowed=True,
                                replication_denied=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, renewable=True, from_rodc=True)
        self._renew_tgt(tgt, expected_error=KDC_ERR_TGT_REVOKED)

    def test_validate_rodc_allowed_denied(self):
        creds = self._get_creds(replication_allowed=True,
                                replication_denied=True,
                                revealed_to_rodc=True)
        tgt = self._get_tgt(creds, invalid=True, from_rodc=True)
        self._validate_tgt(tgt, expected_error=KDC_ERR_TGT_REVOKED)

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
                        expected_error=(KDC_ERR_BADMATCH,
                                        KDC_ERR_BADOPTION))

    def test_user2user_non_existent_sname(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds)

        sname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                          names=['host', 'non_existent_user'])

        self._user2user(tgt, creds, sname=sname,
                        expected_error=KDC_ERR_S_PRINCIPAL_UNKNOWN)

    def test_user2user_service_ticket(self):
        creds = self._get_creds()
        tgt = self._get_tgt(creds)

        service_creds = self.get_service_creds()
        service_ticket = self.get_service_ticket(tgt, service_creds)

        self._user2user(service_ticket, creds, expected_error=KDC_ERR_POLICY)

    def _get_tgt(self,
                 client_creds,
                 renewable=False,
                 invalid=False,
                 from_rodc=False,
                 new_rid=None,
                 remove_pac=False,
                 allow_empty_authdata=False):
        self.assertFalse(renewable and invalid)

        if remove_pac:
            self.assertIsNone(new_rid)

        tgt = self.get_tgt(client_creds)

        if from_rodc:
            krbtgt_creds = self.get_mock_rodc_krbtgt_creds()
        else:
            krbtgt_creds = self.get_krbtgt_creds()

        if new_rid is not None:
            def change_sid_fn(pac):
                for pac_buffer in pac.buffers:
                    if pac_buffer.type == krb5pac.PAC_TYPE_LOGON_INFO:
                        logon_info = pac_buffer.info.info

                        logon_info.info3.base.rid = new_rid

                return pac

            modify_pac_fn = change_sid_fn
        else:
            modify_pac_fn = None

        krbtgt_key = self.TicketDecryptionKey_from_creds(krbtgt_creds)

        if remove_pac:
            checksum_keys = None
        else:
            checksum_keys = {
                krb5pac.PAC_TYPE_KDC_CHECKSUM: krbtgt_key
            }

        if renewable:
            def set_renewable(enc_part):
                # Set the renewable flag.
                renewable_flag = krb5_asn1.TicketFlags('renewable')
                pos = len(tuple(renewable_flag)) - 1

                flags = enc_part['flags']
                self.assertLessEqual(pos, len(flags))

                new_flags = flags[:pos] + '1' + flags[pos + 1:]
                enc_part['flags'] = new_flags

                # Set the renew-till time to be in the future.
                renew_till = self.get_KerberosTime(offset=100 * 60 * 60)
                enc_part['renew-till'] = renew_till

                return enc_part

            modify_fn = set_renewable
        elif invalid:
            def set_invalid(enc_part):
                # Set the invalid flag.
                invalid_flag = krb5_asn1.TicketFlags('invalid')
                pos = len(tuple(invalid_flag)) - 1

                flags = enc_part['flags']
                self.assertLessEqual(pos, len(flags))

                new_flags = flags[:pos] + '1' + flags[pos + 1:]
                enc_part['flags'] = new_flags

                # Set the ticket start time to be in the past.
                past_time = self.get_KerberosTime(offset=-100 * 60 * 60)
                enc_part['starttime'] = past_time

                return enc_part

            modify_fn = set_invalid
        else:
            modify_fn = None

        return self.modified_ticket(
            tgt,
            new_ticket_key=krbtgt_key,
            modify_fn=modify_fn,
            modify_pac_fn=modify_pac_fn,
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

        samdb = self.get_samdb()

        other_dn = other_creds.get_dn()
        other_sid = self.get_objectSid(samdb, other_dn)

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

    def _get_non_existent_rid(self):
        return (1 << 30) - 1

    def _run_tgs(self, tgt, expected_error):
        target_creds = self.get_service_creds()
        self._tgs_req(tgt, expected_error, target_creds)

    def _renew_tgt(self, tgt, expected_error):
        krbtgt_creds = self.get_krbtgt_creds()
        kdc_options = str(krb5_asn1.KDCOptions('renew'))
        self._tgs_req(tgt, expected_error, krbtgt_creds,
                      kdc_options=kdc_options)

    def _validate_tgt(self, tgt, expected_error):
        krbtgt_creds = self.get_krbtgt_creds()
        kdc_options = str(krb5_asn1.KDCOptions('validate'))
        self._tgs_req(tgt, expected_error, krbtgt_creds,
                      kdc_options=kdc_options)

    def _s4u2self(self, tgt, tgt_creds, expected_error):
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

        self._tgs_req(tgt, expected_error, tgt_creds,
                      expected_cname=user_cname,
                      generate_padata_fn=generate_s4u2self_padata,
                      expect_claims=False)

    def _user2user(self, tgt, tgt_creds, expected_error, sname=None):
        user_creds = self._get_mach_creds()
        user_tgt = self.get_tgt(user_creds)

        kdc_options = str(krb5_asn1.KDCOptions('enc-tkt-in-skey'))
        self._tgs_req(user_tgt, expected_error, tgt_creds,
                      kdc_options=kdc_options,
                      additional_ticket=tgt,
                      sname=sname)

    def _tgs_req(self, tgt, expected_error, target_creds,
                 kdc_options='0',
                 expected_cname=None,
                 additional_ticket=None,
                 generate_padata_fn=None,
                 sname=None,
                 expect_claims=True):
        srealm = target_creds.get_realm()

        if sname is None:
            target_name = target_creds.get_username()
            if target_name == 'krbtgt':
                sname = self.PrincipalName_create(name_type=NT_SRV_INST,
                                                  names=[target_name, srealm])
            else:
                if target_name[-1] == '$':
                    target_name = target_name[:-1]
                sname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                                  names=['host', target_name])

        if additional_ticket is not None:
            additional_tickets = [additional_ticket.ticket]
            decryption_key = additional_ticket.session_key
        else:
            additional_tickets = None
            decryption_key = self.TicketDecryptionKey_from_creds(
                target_creds)

        subkey = self.RandomKey(tgt.session_key.etype)

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
            expected_crealm=tgt.crealm,
            expected_cname=expected_cname,
            expected_srealm=srealm,
            expected_sname=sname,
            ticket_decryption_key=decryption_key,
            generate_padata_fn=generate_padata_fn,
            check_error_fn=check_error_fn,
            check_rep_fn=check_rep_fn,
            check_kdc_private_fn=self.generic_check_kdc_private,
            expected_error_mode=expected_error,
            tgt=tgt,
            authenticator_subkey=subkey,
            kdc_options=kdc_options,
            expect_edata=False,
            expect_claims=expect_claims)

        rep = self._generic_kdc_exchange(kdc_exchange_dict,
                                         cname=None,
                                         realm=srealm,
                                         sname=sname,
                                         etypes=etypes,
                                         additional_tickets=additional_tickets)
        if expected_error:
            self.check_error_rep(rep, expected_error)
            return None
        else:
            self.check_reply(rep, KRB_TGS_REP)
            return kdc_exchange_dict['rep_ticket_creds']


if __name__ == "__main__":
    global_asn1_print = False
    global_hexdump = False
    import unittest
    unittest.main()
