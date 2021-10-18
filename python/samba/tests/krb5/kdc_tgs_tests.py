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

import samba.tests.krb5.kcrypto as kcrypto
from samba.tests.krb5.kdc_base_test import KDCBaseTest
from samba.tests.krb5.rfc4120_constants import (
    AES256_CTS_HMAC_SHA1_96,
    ARCFOUR_HMAC_MD5,
    KRB_ERROR,
    KRB_TGS_REP,
    KDC_ERR_BADMATCH,
    KDC_ERR_BADOPTION,
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
                          expect_error=False):
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
                                        pac_request=False)

        pac = self.get_ticket_pac(ticket)
        self.assertIsNotNone(pac)

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

        tgt = self.get_tgt(client_creds, pac_request=False)

        pac = self.get_ticket_pac(tgt)
        self.assertIsNotNone(pac)

        ticket = self._make_tgs_request(client_creds, service_creds, tgt,
                                        pac_request=False)

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


if __name__ == "__main__":
    global_asn1_print = False
    global_hexdump = False
    import unittest
    unittest.main()
