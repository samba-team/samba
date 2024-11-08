#!/usr/bin/env python3
# Unix SMB/CIFS implementation.
# Copyright (C) Stefan Metzmacher 2024
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

from samba import (
    credentials,
    ntstatus,
    NTSTATUSError,
    generate_random_password,
    generate_random_bytes,
)
from samba.dcerpc import netlogon, samr, misc, ntlmssp, krb5pac
from samba.ndr import ndr_deepcopy, ndr_print, ndr_pack
from samba.crypto import md4_hash_blob
from samba.tests import DynamicTestCase
from samba.tests.krb5.kdc_base_test import KDCBaseTest
import samba.tests.krb5.rfc4120_pyasn1 as krb5_asn1
from samba.tests.krb5.rfc4120_constants import KU_NON_KERB_CKSUM_SALT

global_asn1_print = False
global_ndr_print = False
global_hexdump = False

@DynamicTestCase
class NetlogonSchannel(KDCBaseTest):

    @classmethod
    def setUpDynamicTestCases(cls):
        def setup_test(name, trust, authX, flags):
            fnname = "test_%s" % name
            tname = "%s_%s_%08x" % (trust, authX, flags)
            targs = (trust, authX, flags)
            cls.generate_dynamic_test(fnname, tname, *targs)
            return

        tests = [
            "check_passwords",
            "send_to_sam",
            "network_samlogon",
            "interactive_samlogon",
            "generic_samlogon",
            "ticket_samlogon",
        ]

        for test in tests:
            for trust in ["wks", "bdc"]:
                for auth3_flags in [0x603fffff, 0x613fffff]:
                    setup_test(test, trust, "auth3", auth3_flags)
                for auth3_flags in [0x00004004, 0x01000000]:
                    setup_test(test, trust, "auth3", auth3_flags)

    def setUp(self):
        super().setUp()
        self.do_asn1_print = global_asn1_print
        self.do_ndr_print = global_ndr_print
        self.do_hexdump = global_hexdump

        self.empty_pwd_nt4_hash = self.get_samr_Password(md4_hash_blob(b''))

        self.user_creds = self.get_cached_creds(
                account_type=self.AccountType.USER,
                opts={'name_prefix': 'u_',
                      'kerberos_enabled': False})

        samdb = self.get_samdb()
        self.dc_server = samdb.host_dns_name()

    def get_wks1_creds(self):
        return self.get_cached_creds(
                account_type=self.AccountType.COMPUTER,
                use_cache=False,
                opts={'name_prefix': 'w1_',
                      'supported_enctypes': 0x18,
                      'secure_channel_type': misc.SEC_CHAN_WKSTA})

    def get_bdc1_creds(self):
        return self.get_cached_creds(
                account_type=self.AccountType.SERVER,
                use_cache=False,
                opts={'name_prefix': 'b1_',
                      'supported_enctypes': 0x18,
                      'secure_channel_type': misc.SEC_CHAN_BDC})

    def get_anon_conn(self):
        dc_server = self.dc_server
        conn = netlogon.netlogon(f'ncacn_ip_tcp:{dc_server}',
                                 self.get_lp())
        return conn

    def get_schannel_conn(self, trust_creds, ncreds):
        dc_server = self.dc_server
        trust_creds.set_netlogon_creds(ncreds)
        conn = netlogon.netlogon(f'ncacn_ip_tcp:{dc_server}[schannel,seal]',
                                 self.get_lp(),
                                 trust_creds)
        trust_creds.set_netlogon_creds(None)
        return conn

    def get_samr_Password(self, nt_hash):
        v = samr.Password()
        v.hash = list(nt_hash)
        return v

    def get_netr_CryptPassword(self, utf8_pwd):
        print("utf8_pwd len=%d" % len(utf8_pwd))
        pwd = netlogon.netr_CryptPassword()
        utf16_pwd = utf8_pwd.encode('utf-16-le')
        pwd_len = len(utf16_pwd)
        print("utf16_pwd len=%d" % pwd_len)
        confounder_len = len(pwd.data) - pwd_len
        print("confounder_len len=%d" % confounder_len)
        confounder = generate_random_bytes(confounder_len)
        pwd.length = pwd_len
        pwd.data = list(confounder) + list(utf16_pwd)
        if self.do_ndr_print:
            print("get_netr_CryptPassword:\n%s" % ndr_print(pwd, print_secrets=True))
        return pwd

    def is_domain_trust(self, ncreds):
        domain_types = [
            misc.SEC_CHAN_DOMAIN,
            misc.SEC_CHAN_DNS_DOMAIN
        ]
        if ncreds.secure_channel_type in domain_types:
            return True
        return False

    def do_Authenticate3(self, conn, trust_creds,
            negotiate_flags, required_flags,
            expect_error=None):
        (auth_type, auth_level) = conn.auth_info()

        trust_account_name = trust_creds.get_username()
        trust_computer_name = trust_creds.get_workstation()

        client_challenge = credentials.netlogon_creds_random_challenge()

        (server_challenge) = \
            conn.netr_ServerReqChallenge(self.dc_server,
                                         trust_computer_name,
                                         client_challenge)

        nt_hash = trust_creds.get_nt_hash()
        machine_password = self.get_samr_Password(nt_hash)

        (ncreds, initial_credential) = \
            credentials.netlogon_creds_client_init(
                client_account=trust_account_name,
                client_computer_name=trust_computer_name,
                secure_channel_type=trust_creds.get_secure_channel_type(),
                client_challenge=client_challenge,
                server_challenge=server_challenge,
                machine_password=machine_password,
                client_requested_flags=negotiate_flags,
                negotiate_flags=negotiate_flags)

        try:
            (return_credentials, negotiated_flags, client_rid) = \
                conn.netr_ServerAuthenticate3(self.dc_server,
                                              ncreds.account_name,
                                              ncreds.secure_channel_type,
                                              ncreds.computer_name,
                                              initial_credential,
                                              ncreds.client_requested_flags)
        except NTSTATUSError as err:
            status, _ = err.args
            self.assertIsNotNone(expect_error,
                                 f'unexpectedly failed with {status:08X}')
            self.assertEqual(expect_error, status, 'got wrong status code')
            return

        self.assertIsNone(expect_error, 'expected error')

        credentials.netlogon_creds_client_verify(ncreds,
                                                 return_credentials,
                                                 auth_type,
                                                 auth_level)

        self.assertEqual((negotiated_flags & required_flags), required_flags)
        self.assertEqual((negotiated_flags & negotiate_flags), negotiated_flags)
        credentials.netlogon_creds_client_update(ncreds,
                                                 negotiated_flags,
                                                 client_rid)

        return ncreds

    def do_CheckCapabilities(self, ncreds, conn,
            expect_error1=None,
            expect_error2=None):

        (auth_type, auth_level) = conn.auth_info()

        zero_authenticator = netlogon.netr_Authenticator()

        req_authenticator = credentials.netlogon_creds_client_authenticator(ncreds)
        try:
           (rep_authenticator, server_capabilities) = \
               conn.netr_LogonGetCapabilities(self.dc_server,
                                              ncreds.computer_name,
                                              req_authenticator,
                                              zero_authenticator,
                                              1)
        except NTSTATUSError as err:
            status, _ = err.args
            self.assertIsNotNone(expect_error1,
                                 f'unexpectedly failed with {status:08X}')
            self.assertEqual(expect_error1, status, 'got wrong status code')
            return

        self.assertIsNone(expect_error1, 'expected error')

        credentials.netlogon_creds_client_verify(ncreds,
                                                 rep_authenticator.cred,
                                                 auth_type,
                                                 auth_level)
        self.assertEqual(server_capabilities, ncreds.negotiate_flags)

        req_authenticator = credentials.netlogon_creds_client_authenticator(ncreds)
        try:
            (rep_authenticator, requested_flags) = \
                conn.netr_LogonGetCapabilities(self.dc_server,
                                               ncreds.computer_name,
                                               req_authenticator,
                                               zero_authenticator,
                                               2)
        except NTSTATUSError as err:
            status, _ = err.args
            self.assertIsNotNone(expect_error2,
                                 f'unexpectedly failed with {status:08X}')
            self.assertEqual(expect_error2, status, 'got wrong status code')
            return

        self.assertIsNone(expect_error2, 'expected error')

        credentials.netlogon_creds_client_verify(ncreds,
                                                 rep_authenticator.cred,
                                                 auth_type,
                                                 auth_level)
        self.assertEqual(requested_flags, ncreds.client_requested_flags)

        return

    def do_ServerPasswordGet(self, ncreds, conn,
            expect_encrypted,
            expect_password,
            expect_broken_crypto=False,
            expect_error=None,
            req_ncreds=None,
            rep_ncreds=None,
            decryption_ncreds=None):

        if req_ncreds is None:
            req_ncreds = ncreds
        if rep_ncreds is None:
            rep_ncreds = ncreds
        if decryption_ncreds is None:
            decryption_ncreds = ncreds

        (auth_type, auth_level) = conn.auth_info()

        req_authenticator = credentials.netlogon_creds_client_authenticator(req_ncreds)
        try:
            (rep_authenticator, password) = \
                conn.netr_ServerPasswordGet(self.dc_server,
                                            ncreds.account_name,
                                            ncreds.secure_channel_type,
                                            ncreds.computer_name,
                                            req_authenticator)
        except NTSTATUSError as err:
            status, _ = err.args
            self.assertIsNotNone(expect_error,
                                 f'unexpectedly failed with {status:08X}')
            self.assertEqual(expect_error, status, 'got wrong status code')
            return

        self.assertIsNone(expect_error, 'expected error')

        credentials.netlogon_creds_client_verify(rep_ncreds,
                                                 rep_authenticator.cred,
                                                 auth_type,
                                                 auth_level)

        if self.do_ndr_print:
            print("do_ServerPasswordGet(raw_pwd):\n%s" % ndr_print(password, print_secrets=True))
        if expect_encrypted and expect_password:
            self.assertNotEqual(ndr_print(password, print_secrets=True), ndr_print(expect_password, print_secrets=True))
        elif expect_password:
            self.assertEqual(ndr_print(password, print_secrets=True), ndr_print(expect_password, print_secrets=True))
        if decryption_ncreds:
            credentials.netlogon_creds_decrypt_samr_Password(decryption_ncreds,
                                                             password,
                                                             auth_type,
                                                             auth_level)
        if self.do_ndr_print:
            print("do_ServerPasswordGet(pwd):\n%s" % ndr_print(password, print_secrets=True))
        if expect_broken_crypto and expect_password:
            self.assertNotEqual(ndr_print(password, print_secrets=True), ndr_print(expect_password, print_secrets=True))
        elif expect_password:
            self.assertEqual(ndr_print(password, print_secrets=True), ndr_print(expect_password, print_secrets=True))
        return

    def do_ServerTrustPasswordsGet(self, ncreds, conn,
            expect_encrypted,
            expect_new_password,
            expect_old_password,
            expect_broken_crypto=False,
            expect_error=None,
            req_ncreds=None,
            rep_ncreds=None,
            decryption_ncreds=None):

        if req_ncreds is None:
            req_ncreds = ncreds
        if rep_ncreds is None:
            rep_ncreds = ncreds
        if decryption_ncreds is None:
            decryption_ncreds = ncreds

        (auth_type, auth_level) = conn.auth_info()

        req_authenticator = credentials.netlogon_creds_client_authenticator(req_ncreds)
        try:
            (rep_authenticator, new_password, old_password) = \
                conn.netr_ServerTrustPasswordsGet(self.dc_server,
                                                  ncreds.account_name,
                                                  ncreds.secure_channel_type,
                                                  ncreds.computer_name,
                                                  req_authenticator)
        except NTSTATUSError as err:
            status, _ = err.args
            self.assertIsNotNone(expect_error,
                                 f'unexpectedly failed with {status:08X}')
            self.assertEqual(expect_error, status, 'got wrong status code')
            return (None, None)

        self.assertIsNone(expect_error, 'expected error')

        credentials.netlogon_creds_client_verify(rep_ncreds,
                                                 rep_authenticator.cred,
                                                 auth_type,
                                                 auth_level)

        if self.do_ndr_print:
            print("do_ServerTrustPasswordsGet(raw_new):\n%s" % ndr_print(new_password, print_secrets=True))
            print("do_ServerTrustPasswordsGet(raw_old):\n%s" % ndr_print(old_password, print_secrets=True))
        if expect_encrypted and expect_new_password:
            self.assertNotEqual(ndr_print(new_password, print_secrets=True), ndr_print(expect_new_password, print_secrets=True))
        elif expect_new_password:
            self.assertEqual(ndr_print(new_password, print_secrets=True), ndr_print(expect_new_password, print_secrets=True))
        if expect_encrypted and expect_old_password:
            self.assertNotEqual(ndr_print(old_password, print_secrets=True), ndr_print(expect_old_password, print_secrets=True))
        elif expect_old_password:
            self.assertEqual(ndr_print(old_password, print_secrets=True), ndr_print(expect_old_password, print_secrets=True))
        if decryption_ncreds:
            credentials.netlogon_creds_decrypt_samr_Password(decryption_ncreds,
                                                             new_password,
                                                             auth_type,
                                                             auth_level)
            credentials.netlogon_creds_decrypt_samr_Password(decryption_ncreds,
                                                             old_password,
                                                             auth_type,
                                                             auth_level)
        if self.do_ndr_print:
            print("do_ServerTrustPasswordsGet(new):\n%s" % ndr_print(new_password, print_secrets=True))
            print("do_ServerTrustPasswordsGet(old):\n%s" % ndr_print(old_password, print_secrets=True))
        if expect_broken_crypto and expect_new_password:
            self.assertNotEqual(ndr_print(new_password, print_secrets=True), ndr_print(expect_new_password, print_secrets=True))
        elif expect_new_password:
            self.assertEqual(ndr_print(new_password, print_secrets=True), ndr_print(expect_new_password, print_secrets=True))
        if expect_broken_crypto and expect_old_password:
            self.assertNotEqual(ndr_print(old_password, print_secrets=True), ndr_print(expect_old_password, print_secrets=True))
        elif expect_old_password:
            self.assertEqual(ndr_print(old_password, print_secrets=True), ndr_print(expect_old_password, print_secrets=True))
        return

    def do_ServerGetTrustInfo(self, ncreds, conn,
            expect_encrypted,
            expect_new_password,
            expect_old_password,
            expect_broken_crypto=False,
            expect_error=None,
            req_ncreds=None,
            rep_ncreds=None,
            decryption_ncreds=None):

        if req_ncreds is None:
            req_ncreds = ncreds
        if rep_ncreds is None:
            rep_ncreds = ncreds
        if decryption_ncreds is None:
            decryption_ncreds = ncreds

        (auth_type, auth_level) = conn.auth_info()

        req_authenticator = credentials.netlogon_creds_client_authenticator(req_ncreds)
        try:
            (rep_authenticator, new_password, old_password, trust_info) = \
                conn.netr_ServerGetTrustInfo(self.dc_server,
                                             ncreds.account_name,
                                             ncreds.secure_channel_type,
                                             ncreds.computer_name,
                                             req_authenticator)
        except NTSTATUSError as err:
            status, _ = err.args
            self.assertIsNotNone(expect_error,
                                 f'unexpectedly failed with {status:08X}')
            self.assertEqual(expect_error, status, 'got wrong status code')
            return (None, None, None)

        self.assertIsNone(expect_error, 'expected error')

        credentials.netlogon_creds_client_verify(rep_ncreds,
                                                 rep_authenticator.cred,
                                                 auth_type,
                                                 auth_level)

        if self.do_ndr_print:
            print("do_ServerGetTrustInfo(raw_new):\n%s" % ndr_print(new_password, print_secrets=True))
            print("do_ServerGetTrustInfo(raw_old):\n%s" % ndr_print(old_password, print_secrets=True))
        if expect_encrypted and expect_new_password:
            self.assertNotEqual(ndr_print(new_password, print_secrets=True), ndr_print(expect_new_password, print_secrets=True))
        elif expect_new_password:
            self.assertEqual(ndr_print(new_password, print_secrets=True), ndr_print(expect_new_password, print_secrets=True))
        if expect_encrypted and expect_old_password:
            self.assertNotEqual(ndr_print(old_password, print_secrets=True), ndr_print(expect_old_password, print_secrets=True))
        elif expect_old_password:
            self.assertEqual(ndr_print(old_password, print_secrets=True), ndr_print(expect_old_password, print_secrets=True))
        if decryption_ncreds:
            credentials.netlogon_creds_decrypt_samr_Password(decryption_ncreds,
                                                             new_password,
                                                             auth_type,
                                                             auth_level)
            credentials.netlogon_creds_decrypt_samr_Password(decryption_ncreds,
                                                             old_password,
                                                             auth_type,
                                                             auth_level)
        if self.do_ndr_print:
            print("do_ServerGetTrustInfo(new):\n%s" % ndr_print(new_password, print_secrets=True))
            print("do_ServerGetTrustInfo(old):\n%s" % ndr_print(old_password, print_secrets=True))
        if expect_broken_crypto and expect_new_password:
            self.assertNotEqual(ndr_print(new_password, print_secrets=True), ndr_print(expect_new_password, print_secrets=True))
        elif expect_new_password:
            self.assertEqual(ndr_print(new_password, print_secrets=True), ndr_print(expect_new_password, print_secrets=True))
        if expect_broken_crypto and expect_old_password:
            self.assertNotEqual(ndr_print(old_password, print_secrets=True), ndr_print(expect_old_password, print_secrets=True))
        elif expect_old_password:
            self.assertEqual(ndr_print(old_password, print_secrets=True), ndr_print(expect_old_password, print_secrets=True))
        return (new_password, old_password, trust_info)

    def do_ServerPasswordSet(self, ncreds, conn,
            expect_encrypted,
            new_password,
            expect_error=None,
            req_ncreds=None,
            rep_ncreds=None,
            encryption_ncreds=None):

        if req_ncreds is None:
            req_ncreds = ncreds
        if rep_ncreds is None:
            rep_ncreds = ncreds
        if encryption_ncreds is None:
            encryption_ncreds = ncreds

        (auth_type, auth_level) = conn.auth_info()

        if self.do_ndr_print:
            print("do_ServerPasswordSet(new):\n%s" % ndr_print(new_password, print_secrets=True))
        send_password = ndr_deepcopy(new_password)
        if encryption_ncreds:
            credentials.netlogon_creds_encrypt_samr_Password(encryption_ncreds,
                                                             send_password,
                                                             auth_type,
                                                             auth_level)
        if self.do_ndr_print:
            print("do_ServerPasswordSet(send_new):\n%s" % ndr_print(send_password, print_secrets=True))
        if expect_encrypted:
            self.assertNotEqual(ndr_print(send_password, print_secrets=True), ndr_print(new_password, print_secrets=True))

        req_authenticator = credentials.netlogon_creds_client_authenticator(req_ncreds)
        try:
            rep_authenticator = \
                conn.netr_ServerPasswordSet(self.dc_server,
                                            ncreds.account_name,
                                            ncreds.secure_channel_type,
                                            ncreds.computer_name,
                                            req_authenticator,
                                            send_password)
        except NTSTATUSError as err:
            status, _ = err.args
            self.assertIsNotNone(expect_error,
                                 f'unexpectedly failed with {status:08X}')
            self.assertEqual(expect_error, status, 'got wrong status code')
            return

        self.assertIsNone(expect_error, 'expected error')

        credentials.netlogon_creds_client_verify(rep_ncreds,
                                                 rep_authenticator.cred,
                                                 auth_type,
                                                 auth_level)

        return

    def do_ServerPasswordSet2(self, ncreds, conn,
            expect_encrypted,
            new_password,
            expect_error=None,
            req_ncreds=None,
            rep_ncreds=None,
            encryption_ncreds=None):

        if req_ncreds is None:
            req_ncreds = ncreds
        if rep_ncreds is None:
            rep_ncreds = ncreds
        if encryption_ncreds is None:
            encryption_ncreds = ncreds

        (auth_type, auth_level) = conn.auth_info()

        if self.do_ndr_print:
            print("do_ServerPasswordSet2(new):\n%s" % ndr_print(new_password, print_secrets=True))
        send_password = ndr_deepcopy(new_password)
        if encryption_ncreds:
            credentials.netlogon_creds_encrypt_netr_CryptPassword(encryption_ncreds,
                                                                  send_password,
                                                                  auth_type,
                                                                  auth_level)
        if self.do_ndr_print:
            print("do_ServerPasswordSet2(send_new):\n%s" % ndr_print(send_password, print_secrets=True))
        if expect_encrypted:
            self.assertNotEqual(ndr_print(send_password, print_secrets=True), ndr_print(new_password, print_secrets=True))

        req_authenticator = credentials.netlogon_creds_client_authenticator(req_ncreds)
        try:
            rep_authenticator = \
                conn.netr_ServerPasswordSet2(self.dc_server,
                                            ncreds.account_name,
                                            ncreds.secure_channel_type,
                                            ncreds.computer_name,
                                            req_authenticator,
                                            send_password)
        except NTSTATUSError as err:
            status, _ = err.args
            self.assertIsNotNone(expect_error,
                                 f'unexpectedly failed with {status:08X}')
            self.assertEqual(expect_error, status, 'got wrong status code')
            return

        self.assertIsNone(expect_error, 'expected error')

        credentials.netlogon_creds_client_verify(rep_ncreds,
                                                 rep_authenticator.cred,
                                                 auth_type,
                                                 auth_level)

        return

    def do_SendToSam(self, ncreds, conn,
            opaque_buffer,
            expect_send_encrypted,
            expect_error=None,
            opaque_ncreds=None,
            req_ncreds=None,
            rep_ncreds=None):

        if opaque_ncreds is None:
            opaque_ncreds = ncreds
        if req_ncreds is None:
            req_ncreds = ncreds
        if rep_ncreds is None:
            rep_ncreds = ncreds

        (auth_type, auth_level) = conn.auth_info()

        opaque_buffer = bytes(list(opaque_buffer))
        if self.do_ndr_print:
            print("do_SendToSam(opaque_buffer):\n%r" % opaque_buffer)
        send_opaque_buffer = bytes(list(opaque_buffer))
        if opaque_ncreds:
            credentials.netlogon_creds_encrypt_SendToSam(opaque_ncreds,
                                                         send_opaque_buffer,
                                                         auth_type,
                                                         auth_level)
        if self.do_ndr_print:
            print("do_SendToSam(send_opaque_buffer):\n%r" % send_opaque_buffer)
        if expect_send_encrypted:
            self.assertNotEqual(send_opaque_buffer, opaque_buffer)
        else:
            self.assertEqual(send_opaque_buffer, opaque_buffer)

        req_authenticator = credentials.netlogon_creds_client_authenticator(req_ncreds)
        try:
            (rep_authenticator) = \
                conn.netr_NetrLogonSendToSam(self.dc_server,
                                             ncreds.computer_name,
                                             req_authenticator,
                                             list(send_opaque_buffer))
        except NTSTATUSError as err:
            status, _ = err.args
            self.assertIsNotNone(expect_error,
                                 f'unexpectedly failed with {status:08X}')
            self.assertEqual(expect_error, status, 'got wrong status code')
            return

        self.assertIsNone(expect_error, 'expected error')

        credentials.netlogon_creds_client_verify(rep_ncreds,
                                                 rep_authenticator.cred,
                                                 auth_type,
                                                 auth_level)
        return

    def _prepare_samlogon(self, ncreds, conn, logon_type, user_creds,
                          generic_package=None, generic_data=None,
                          trust_creds=None,
                          encrypt=False):

        username, domain = user_creds.get_ntlm_username_domain()
        workstation = ncreds.computer_name

        identity_info = netlogon.netr_IdentityInfo()
        identity_info.domain_name.string = domain
        identity_info.account_name.string = username
        identity_info.parameter_control = (
            netlogon.MSV1_0_ALLOW_SERVER_TRUST_ACCOUNT) | (
                netlogon.MSV1_0_ALLOW_WORKSTATION_TRUST_ACCOUNT)
        identity_info.workstation.string = workstation

        (auth_type, auth_level) = conn.auth_info()

        if logon_type == netlogon.NetlogonInteractiveInformation:
            logon = netlogon.netr_PasswordInfo()

            lm_pass = samr.Password()
            lm_pass.hash = [0] * 16

            nt_pass = samr.Password()
            nt_pass.hash = list(user_creds.get_nt_hash())

            logon.lmpassword = lm_pass
            logon.ntpassword = nt_pass

        elif logon_type == netlogon.NetlogonNetworkInformation:
            computername = ntlmssp.AV_PAIR()
            computername.AvId = ntlmssp.MsvAvNbComputerName
            computername.Value = workstation

            domainname = ntlmssp.AV_PAIR()
            domainname.AvId = ntlmssp.MsvAvNbDomainName
            domainname.Value = domain

            eol = ntlmssp.AV_PAIR()
            eol.AvId = ntlmssp.MsvAvEOL

            target_info = ntlmssp.AV_PAIR_LIST()
            target_info.count = 3
            target_info.pair = [domainname, computername, eol]

            target_info_blob = ndr_pack(target_info)

            challenge = b'fixedval'
            response = user_creds.get_ntlm_response(flags=0,
                                                    challenge=challenge,
                                                    target_info=target_info_blob)

            logon = netlogon.netr_NetworkInfo()

            logon.challenge = list(challenge)
            logon.nt = netlogon.netr_ChallengeResponse()
            logon.nt.length = len(response['nt_response'])
            logon.nt.data = list(response['nt_response'])

        elif logon_type == netlogon.NetlogonGenericInformation:
            self.assertIsNotNone(generic_package)
            self.assertIsNotNone(generic_data)

            logon = netlogon.netr_GenericInfo()
            logon.package_name.string = generic_package
            logon.length = len(generic_data)
            logon.data = list(generic_data)

            identity_info = netlogon.netr_IdentityInfo()
            identity_info.domain_name.string = domain

        elif logon_type == netlogon.NetlogonTicketLogonInformation:
            user_tgt = self.get_tgt(user_creds)

            service_ticket = self.get_service_ticket(user_tgt, trust_creds)
            service_ticket_data = self.der_encode(service_ticket.ticket,
                                                  asn1Spec=krb5_asn1.Ticket())

            logon = netlogon.netr_TicketLogonInfo()
            logon.request_options = 0
            logon.service_ticket_length = len(service_ticket_data)
            logon.service_ticket = list(service_ticket_data)
            logon.additional_ticket_length = 0
            logon.additional_ticket = None

            identity_info = netlogon.netr_IdentityInfo()
            identity_info.domain_name.string = domain
        else:
            self.fail(f'unknown logon type {logon_type}')

        logon.identity_info = identity_info

        if encrypt:
            credentials.netlogon_creds_encrypt_netr_LogonLevel(ncreds,
                                                               logon_type,
                                                               logon,
                                                               auth_type,
                                                               auth_level)

        return logon

    def do_LogonWithFlags(self, ncreds, conn,
            logon_type, logon_info, validation_level,
            expect_send_encrypted,
            expect_recv_encrypted,
            expect_error=None,
            logon_ncreds=None,
            req_ncreds=None,
            rep_ncreds=None,
            validation_ncreds=None):

        if logon_ncreds is None:
            logon_ncreds = ncreds
        if req_ncreds is None:
            req_ncreds = ncreds
        if rep_ncreds is None:
            rep_ncreds = ncreds
        if validation_ncreds is None:
            validation_ncreds = ncreds

        (auth_type, auth_level) = conn.auth_info()

        logon_info = ndr_deepcopy(logon_info)
        if self.do_ndr_print:
            print("do_LogonWithFlags(logon):\n%s" % ndr_print(logon_info, print_secrets=True))
        send_logon_info = ndr_deepcopy(logon_info)
        if logon_ncreds:
            credentials.netlogon_creds_encrypt_netr_LogonLevel(logon_ncreds,
                                                               logon_type,
                                                               send_logon_info,
                                                               auth_type,
                                                               auth_level)
        if self.do_ndr_print:
            print("do_LogonWithFlags(send_logon):\n%s" % ndr_print(send_logon_info, print_secrets=True))
        if expect_send_encrypted:
            self.assertNotEqual(ndr_print(send_logon_info, print_secrets=True), ndr_print(logon_info, print_secrets=True))
        else:
            self.assertEqual(ndr_print(send_logon_info, print_secrets=True), ndr_print(logon_info, print_secrets=True))

        zero_authenticator = netlogon.netr_Authenticator()

        req_flags = 0
        req_authenticator = credentials.netlogon_creds_client_authenticator(req_ncreds)
        try:
            (rep_authenticator, recv_validation, authoritative, rep_flags) = \
                conn.netr_LogonSamLogonWithFlags(self.dc_server,
                                                 ncreds.computer_name,
                                                 req_authenticator,
                                                 zero_authenticator,
                                                 logon_type,
                                                 send_logon_info,
                                                 validation_level,
                                                 req_flags)
        except NTSTATUSError as err:
            status, _ = err.args
            self.assertIsNotNone(expect_error,
                                 f'unexpectedly failed with {status:08X}')
            self.assertEqual(expect_error, status, 'got wrong status code')
            return None

        self.assertIsNone(expect_error, 'expected error')

        self.assertEqual(1, authoritative)
        self.assertEqual(0, rep_flags)

        credentials.netlogon_creds_client_verify(rep_ncreds,
                                                 rep_authenticator.cred,
                                                 auth_type,
                                                 auth_level)

        recv_validation = ndr_deepcopy(recv_validation)
        if self.do_ndr_print:
            print("do_LogonWithFlags(%d,recv):\n%s" % (logon_type, ndr_print(recv_validation, print_secrets=True)))
        validation = ndr_deepcopy(recv_validation)
        if validation_ncreds:
            credentials.netlogon_creds_decrypt_netr_Validation(validation_ncreds,
                                                               validation_level,
                                                               validation,
                                                               auth_type,
                                                               auth_level)
        if self.do_ndr_print:
            print("do_LogonWithFlags(%d):\n%s" % (logon_type, ndr_print(validation, print_secrets=True)))
        if expect_recv_encrypted:
            self.assertNotEqual(ndr_print(validation, print_secrets=True), ndr_print(recv_validation, print_secrets=True))
        else:
            self.assertEqual(ndr_print(validation, print_secrets=True), ndr_print(recv_validation, print_secrets=True))
        return validation

    def do_LogonEx(self, ncreds, conn,
            logon_type, logon_info, validation_level,
            expect_send_encrypted,
            expect_recv_encrypted,
            expect_error=None,
            logon_ncreds=None,
            validation_ncreds=None):

        if logon_ncreds is None:
            logon_ncreds = ncreds
        if validation_ncreds is None:
            validation_ncreds = ncreds

        (auth_type, auth_level) = conn.auth_info()

        logon_info = ndr_deepcopy(logon_info)
        if self.do_ndr_print:
            print("do_LogonEx(logon):\n%s" % ndr_print(logon_info, print_secrets=True))
        send_logon_info = ndr_deepcopy(logon_info)
        if logon_ncreds:
            credentials.netlogon_creds_encrypt_netr_LogonLevel(logon_ncreds,
                                                               logon_type,
                                                               send_logon_info,
                                                               auth_type,
                                                               auth_level)
        if self.do_ndr_print:
            print("do_LogonEx(send_logon):\n%s" % ndr_print(send_logon_info, print_secrets=True))
        if expect_send_encrypted:
            self.assertNotEqual(ndr_print(send_logon_info, print_secrets=True), ndr_print(logon_info, print_secrets=True))
        else:
            self.assertEqual(ndr_print(send_logon_info, print_secrets=True), ndr_print(logon_info, print_secrets=True))

        req_flags = 0
        try:
            (recv_validation, authoritative, rep_flags) = \
                conn.netr_LogonSamLogonEx(self.dc_server,
                                          ncreds.computer_name,
                                          logon_type,
                                          send_logon_info,
                                          validation_level,
                                          req_flags)
        except NTSTATUSError as err:
            status, _ = err.args
            self.assertIsNotNone(expect_error,
                                 f'unexpectedly failed with {status:08X}')
            self.assertEqual(expect_error, status, 'got wrong status code')
            return None

        self.assertIsNone(expect_error, 'expected error')

        self.assertEqual(1, authoritative)
        self.assertEqual(0, rep_flags)

        recv_validation = ndr_deepcopy(recv_validation)
        if self.do_ndr_print:
            print("do_LogonEx(%d,recv):\n%s" % (logon_type, ndr_print(recv_validation, print_secrets=True)))
        validation = ndr_deepcopy(recv_validation)
        if validation_ncreds:
            credentials.netlogon_creds_decrypt_netr_Validation(validation_ncreds,
                                                               validation_level,
                                                               validation,
                                                               auth_type,
                                                               auth_level)
        if self.do_ndr_print:
            print("do_LogonEx(%d):\n%s" % (logon_type, ndr_print(validation, print_secrets=True)))
        if expect_recv_encrypted:
            self.assertNotEqual(ndr_print(validation, print_secrets=True), ndr_print(recv_validation, print_secrets=True))
        else:
            self.assertEqual(ndr_print(validation, print_secrets=True), ndr_print(recv_validation, print_secrets=True))
        return validation

    def _prepare_ncreds_conn_with_args(self, trust, authX, flags):
        if trust == "wks":
            creds = self.get_wks1_creds()
        elif trust == "bdc":
            creds = self.get_bdc1_creds()
        self.assertIsNotNone(creds)

        if authX == "auth3":
            anon_conn = self.get_anon_conn()
            ncreds = self.do_Authenticate3(anon_conn, creds, flags, flags)
            conn = self.get_schannel_conn(creds, ncreds)
        self.assertIsNotNone(ncreds)
        self.assertIsNotNone(conn)

        expect_encrypted = True

        return (creds, ncreds, conn, expect_encrypted)

    def _test_check_passwords(self, trust_creds, ncreds, conn,
                              expect_encrypted):
        self.do_CheckCapabilities(ncreds, conn)

        nt_hash = trust_creds.get_nt_hash()
        expect_new_password = self.get_samr_Password(nt_hash)
        old_nt_hash = None
        if self.is_domain_trust(ncreds):
            old_nt_hash = trust_creds.get_old_hash()
        if old_nt_hash:
            expect_old_password = self.get_samr_Password(old_nt_hash)
        else:
            expect_old_password = self.empty_pwd_nt4_hash

        expect_broken_crypto = False
        expect_broken_set2_crypto = False

        if expect_broken_crypto:
            expect_encrypted = True
            expect_set_encrypted = False
            encryption_set_ncreds = False
            expect_set2_encrypted = False
            encryption_set2_ncreds = False
        else:
            expect_set_encrypted = expect_encrypted
            encryption_set_ncreds = ncreds
            expect_set2_encrypted = expect_encrypted
            encryption_set2_ncreds = ncreds

        if ncreds.secure_channel_type == misc.SEC_CHAN_WKSTA:
            expect_get_error = ntstatus.NT_STATUS_ACCESS_DENIED
        else:
            expect_get_error = None
        self.do_ServerPasswordGet(ncreds, conn,
                                  expect_encrypted,
                                  expect_new_password,
                                  expect_broken_crypto=expect_broken_crypto,
                                  expect_error=expect_get_error)
        self.do_ServerTrustPasswordsGet(ncreds, conn,
                                        expect_encrypted,
                                        expect_new_password,
                                        expect_old_password,
                                        expect_broken_crypto=expect_broken_crypto)
        self.do_ServerGetTrustInfo(ncreds, conn,
                                   expect_encrypted,
                                   expect_new_password,
                                   expect_old_password,
                                   expect_broken_crypto=expect_broken_crypto)

        if self.is_domain_trust(ncreds):
            self.do_CheckCapabilities(ncreds, conn)
            return

        if expect_encrypted:
            old_utf8 = trust_creds.get_password()
            new_utf8 = generate_random_password(120, 120)
            tmp_creds = credentials.Credentials()
            tmp_creds.set_password(new_utf8)
            tmp_nt_hash = tmp_creds.get_nt_hash()
            new_set_password = self.get_samr_Password(tmp_nt_hash)
            expect_set_error = None
        else:
            old_utf8 = None
            new_utf8 = None
            tmp_nt_hash = generate_random_bytes(16)
            new_set_password = self.get_samr_Password(tmp_nt_hash)
            expect_set_error = ntstatus.NT_STATUS_NOT_SUPPORTED
        self.do_ServerPasswordSet(ncreds, conn,
                                  expect_set_encrypted,
                                  new_set_password,
                                  encryption_ncreds=encryption_set_ncreds,
                                  expect_error=expect_set_error)

        if old_utf8:
            trust_creds.set_old_password(old_utf8)
        if new_utf8:
            trust_creds.set_password(new_utf8)
            tmp_nt_hash = trust_creds.get_nt_hash()
            expect_new_password = self.get_samr_Password(tmp_nt_hash)

        self.do_ServerPasswordGet(ncreds, conn,
                                  expect_encrypted,
                                  expect_new_password,
                                  expect_broken_crypto=expect_broken_crypto,
                                  expect_error=expect_get_error)
        self.do_ServerTrustPasswordsGet(ncreds, conn,
                                        expect_encrypted,
                                        expect_new_password,
                                        expect_old_password,
                                        expect_broken_crypto=expect_broken_crypto)
        self.do_ServerGetTrustInfo(ncreds, conn,
                                   expect_encrypted,
                                   expect_new_password,
                                   expect_old_password,
                                   expect_broken_crypto=expect_broken_crypto)

        if expect_broken_set2_crypto:
            old_utf8 = None
            new_utf8 = None
            tmp_utf8 = generate_random_password(120, 120)
            new_set2_password = self.get_netr_CryptPassword(tmp_utf8)
            expect_set2_error = ntstatus.NT_STATUS_ACCESS_DENIED
        else:
            old_utf8 = trust_creds.get_password()
            new_utf8 = generate_random_password(120, 120)
            new_set2_password = self.get_netr_CryptPassword(new_utf8)
            expect_set2_error = None
        self.do_ServerPasswordSet2(ncreds, conn,
                                   expect_set2_encrypted,
                                   new_set2_password,
                                   encryption_ncreds=encryption_set2_ncreds,
                                   expect_error=expect_set2_error)
        if old_utf8:
            trust_creds.set_old_password(old_utf8)
        if new_utf8:
            trust_creds.set_password(new_utf8)
            tmp_nt_hash = trust_creds.get_nt_hash()
            expect_new_password = self.get_samr_Password(tmp_nt_hash)

        self.do_ServerPasswordGet(ncreds, conn,
                                  expect_encrypted,
                                  expect_new_password,
                                  expect_broken_crypto=expect_broken_crypto,
                                  expect_error=expect_get_error)
        self.do_ServerTrustPasswordsGet(ncreds, conn,
                                        expect_encrypted,
                                        expect_new_password,
                                        expect_old_password,
                                        expect_broken_crypto=expect_broken_crypto)
        self.do_ServerGetTrustInfo(ncreds, conn,
                                   expect_encrypted,
                                   expect_new_password,
                                   expect_old_password,
                                   expect_broken_crypto=expect_broken_crypto)

        self.do_CheckCapabilities(ncreds, conn)
        return

    def _test_check_passwords_with_args(self, trust, authX, flags):
        (creds, ncreds, conn, expect_encrypted) = \
            self._prepare_ncreds_conn_with_args(trust, authX, flags)

        return self._test_check_passwords(creds,
                                          ncreds,
                                          conn,
                                          expect_encrypted)

    def _test_send_to_sam(self, trust_creds, ncreds, conn,
                          expect_encrypted):
        self.do_CheckCapabilities(ncreds, conn)

        expect_broken_crypto = False

        opaque_buffer = b'invalid_opaque_buffer'
        if ncreds.secure_channel_type == misc.SEC_CHAN_WKSTA:
            expect_invalid_error = ntstatus.NT_STATUS_ACCESS_DENIED
        else:
            expect_invalid_error = ntstatus.NT_STATUS_INVALID_PARAMETER
        self.do_SendToSam(ncreds, conn, opaque_buffer,
                          expect_encrypted,
                          expect_error=expect_invalid_error)

        rbpc = netlogon.netr_SendToSamResetBadPasswordCount()
        rbpc.guid = misc.GUID("00000001-0001-0001-0001-000000000001")
        bmsg = netlogon.netr_SendToSamBase()
        bmsg.message_type = netlogon.SendToSamResetBadPasswordCount
        bmsg.message_size = 16
        bmsg.message = rbpc
        opaque_buffer = ndr_pack(bmsg)
        if ncreds.secure_channel_type == misc.SEC_CHAN_WKSTA:
            expect_not_found_error = ntstatus.NT_STATUS_ACCESS_DENIED
        elif expect_broken_crypto:
            expect_not_found_error = ntstatus.NT_STATUS_INVALID_PARAMETER
        else:
            expect_not_found_error = ntstatus.NT_STATUS_OBJECT_NAME_NOT_FOUND
        self.do_SendToSam(ncreds, conn, opaque_buffer,
                          expect_encrypted,
                          expect_error=expect_not_found_error)

        rbpc = netlogon.netr_SendToSamResetBadPasswordCount()
        rbpc.guid = misc.GUID(self.user_creds.get_guid())
        bmsg = netlogon.netr_SendToSamBase()
        bmsg.message_type = netlogon.SendToSamResetBadPasswordCount
        bmsg.message_size = 16
        bmsg.message = rbpc
        opaque_buffer = ndr_pack(bmsg)
        if ncreds.secure_channel_type == misc.SEC_CHAN_WKSTA:
            expect_no_error = ntstatus.NT_STATUS_ACCESS_DENIED
        elif expect_broken_crypto:
            expect_no_error = ntstatus.NT_STATUS_INVALID_PARAMETER
        else:
            expect_no_error = None
        self.do_SendToSam(ncreds, conn, opaque_buffer,
                          expect_encrypted,
                          expect_error=expect_no_error)

        self.do_CheckCapabilities(ncreds, conn)
        return

    def _test_send_to_sam_with_args(self, trust, authX, flags):
        (creds, ncreds, conn, expect_encrypted) = \
            self._prepare_ncreds_conn_with_args(trust, authX, flags)

        return self._test_send_to_sam(creds,
                                      ncreds,
                                      conn,
                                      expect_encrypted)

    def _test_network_samlogon(self, trust_creds, ncreds, conn,
                               expect_encrypted):
        self.do_CheckCapabilities(ncreds, conn)

        expect_broken_nt_crypto = False
        expect_broken_lm_crypto = False

        validation_level6 = netlogon.NetlogonValidationSamInfo4
        validation_level3 = netlogon.NetlogonValidationSamInfo2
        validation_level2 = netlogon.NetlogonValidationSamInfo
        logon_type_n = netlogon.NetlogonNetworkInformation
        logon_info_n = self._prepare_samlogon(ncreds,
                                              conn,
                                              logon_type_n,
                                              self.user_creds)

        expect_send_encrypted = False
        expect_recv_encrypted = False
        validationRef_n6 = self.do_LogonEx(ncreds, conn,
                                           logon_type_n, logon_info_n,
                                           validation_level6,
                                           expect_send_encrypted,
                                           expect_recv_encrypted)
        self.assertNotEqual(validationRef_n6.base.rid, 0)
        self.assertNotEqual(validationRef_n6.base.key.key, list(b'\x00' *16))
        self.assertEqual(validationRef_n6.base.LMSessKey.key, list(b'\x00' *8))

        expect_send_encrypted = False
        expect_recv_encrypted = expect_encrypted
        validationWF_n2 = self.do_LogonWithFlags(ncreds, conn,
                                                 logon_type_n, logon_info_n,
                                                 validation_level2,
                                                 expect_send_encrypted,
                                                 expect_recv_encrypted)
        self.assertEqual(validationWF_n2.base.rid, validationRef_n6.base.rid)
        if expect_broken_nt_crypto:
            self.assertNotEqual(validationWF_n2.base.key.key, list(b'\x00' *16))
            self.assertNotEqual(validationWF_n2.base.key.key, validationRef_n6.base.key.key)
        else:
            self.assertEqual(validationWF_n2.base.key.key, validationRef_n6.base.key.key)
        if expect_broken_lm_crypto:
            self.assertNotEqual(validationWF_n2.base.LMSessKey.key, list(b'\x00' *8))
            self.assertNotEqual(validationWF_n2.base.LMSessKey.key, validationRef_n6.base.LMSessKey.key)
        else:
            self.assertEqual(validationWF_n2.base.LMSessKey.key, validationRef_n6.base.LMSessKey.key)
        validationEx_n2 = self.do_LogonEx(ncreds, conn,
                                          logon_type_n, logon_info_n,
                                          validation_level2,
                                          expect_send_encrypted,
                                          expect_recv_encrypted)
        self.assertEqual(validationEx_n2.base.rid, validationRef_n6.base.rid)
        if expect_broken_nt_crypto:
            self.assertNotEqual(validationEx_n2.base.key.key, list(b'\x00' *16))
            self.assertNotEqual(validationEx_n2.base.key.key, validationRef_n6.base.key.key)
        else:
            self.assertEqual(validationEx_n2.base.key.key, validationRef_n6.base.key.key)
        if expect_broken_lm_crypto:
            self.assertNotEqual(validationEx_n2.base.LMSessKey.key, list(b'\x00' *8))
            self.assertNotEqual(validationEx_n2.base.LMSessKey.key, validationRef_n6.base.LMSessKey.key)
        else:
            self.assertEqual(validationEx_n2.base.LMSessKey.key, validationRef_n6.base.LMSessKey.key)

        expect_send_encrypted = False
        expect_recv_encrypted = expect_encrypted
        validationWF_n3 = self.do_LogonWithFlags(ncreds, conn,
                                                 logon_type_n, logon_info_n,
                                                 validation_level3,
                                                 expect_send_encrypted,
                                                 expect_recv_encrypted)
        self.assertEqual(validationWF_n3.base.rid, validationRef_n6.base.rid)
        if expect_broken_nt_crypto:
            self.assertNotEqual(validationWF_n3.base.key.key, list(b'\x00' *16))
            self.assertNotEqual(validationWF_n3.base.key.key, validationRef_n6.base.key.key)
        else:
            self.assertEqual(validationWF_n3.base.key.key, validationRef_n6.base.key.key)
        if expect_broken_lm_crypto:
            self.assertNotEqual(validationWF_n3.base.LMSessKey.key, list(b'\x00' *8))
            self.assertNotEqual(validationWF_n3.base.LMSessKey.key, validationRef_n6.base.LMSessKey.key)
        else:
            self.assertEqual(validationWF_n3.base.LMSessKey.key, validationRef_n6.base.LMSessKey.key)
        validationEx_n3 = self.do_LogonEx(ncreds, conn,
                                          logon_type_n, logon_info_n,
                                          validation_level3,
                                          expect_send_encrypted,
                                          expect_recv_encrypted)
        self.assertEqual(validationEx_n3.base.rid, validationRef_n6.base.rid)
        if expect_broken_nt_crypto:
            self.assertNotEqual(validationEx_n3.base.key.key, list(b'\x00' *16))
            self.assertNotEqual(validationEx_n3.base.key.key, validationRef_n6.base.key.key)
        else:
            self.assertEqual(validationEx_n3.base.key.key, validationRef_n6.base.key.key)
        if expect_broken_lm_crypto:
            self.assertNotEqual(validationEx_n3.base.LMSessKey.key, list(b'\x00' *8))
            self.assertNotEqual(validationEx_n3.base.LMSessKey.key, validationRef_n6.base.LMSessKey.key)
        else:
            self.assertEqual(validationEx_n3.base.LMSessKey.key, validationRef_n6.base.LMSessKey.key)

        expect_send_encrypted = False
        expect_recv_encrypted = False
        validationWF_n6 = self.do_LogonWithFlags(ncreds, conn,
                                                 logon_type_n, logon_info_n,
                                                 validation_level6,
                                                 expect_send_encrypted,
                                                 expect_recv_encrypted)
        self.assertEqual(validationWF_n6.base.rid, validationRef_n6.base.rid)
        self.assertEqual(validationWF_n6.base.key.key, validationRef_n6.base.key.key)
        validationEx_n6 = self.do_LogonEx(ncreds, conn,
                                          logon_type_n, logon_info_n,
                                          validation_level6,
                                          expect_send_encrypted,
                                          expect_recv_encrypted)
        self.assertEqual(validationEx_n6.base.rid, validationRef_n6.base.rid)
        self.assertEqual(validationEx_n6.base.key.key, validationRef_n6.base.key.key)

        self.do_CheckCapabilities(ncreds, conn)
        return

    def _test_network_samlogon_with_args(self, trust, authX, flags):
        (creds, ncreds, conn, expect_encrypted) = \
            self._prepare_ncreds_conn_with_args(trust, authX, flags)

        return self._test_network_samlogon(creds,
                                           ncreds,
                                           conn,
                                           expect_encrypted)

    def _test_interactive_samlogon(self, trust_creds, ncreds, conn,
                                   expect_encrypted):
        self.do_CheckCapabilities(ncreds, conn)

        validation_level6 = netlogon.NetlogonValidationSamInfo4
        validation_level3 = netlogon.NetlogonValidationSamInfo2
        validation_level2 = netlogon.NetlogonValidationSamInfo
        logon_type_i = netlogon.NetlogonInteractiveInformation
        logon_info_i = self._prepare_samlogon(ncreds,
                                              conn,
                                              logon_type_i,
                                              self.user_creds)

        expect_broken_crypto = False

        if expect_broken_crypto:
            expect_error = ntstatus.NT_STATUS_WRONG_PASSWORD
        else:
            expect_error = None

        expect_send_encrypted = expect_encrypted
        expect_recv_encrypted = False
        validationRef_i6 = self.do_LogonEx(ncreds, conn,
                                           logon_type_i, logon_info_i,
                                           validation_level6,
                                           expect_send_encrypted,
                                           expect_recv_encrypted,
                                           expect_error=expect_error)
        if expect_error is not None:
            self.do_CheckCapabilities(ncreds, conn)
            return
        self.assertNotEqual(validationRef_i6.base.rid, 0)
        self.assertEqual(validationRef_i6.base.key.key, list(b'\x00' *16))
        self.assertEqual(validationRef_i6.base.LMSessKey.key, list(b'\x00' *8))

        expect_send_encrypted = expect_encrypted
        expect_recv_encrypted = False
        validationWF_i2 = self.do_LogonWithFlags(ncreds, conn,
                                                 logon_type_i, logon_info_i,
                                                 validation_level2,
                                                 expect_send_encrypted,
                                                 expect_recv_encrypted)
        self.assertEqual(validationWF_i2.base.rid, validationRef_i6.base.rid)
        self.assertEqual(validationWF_i2.base.key.key, validationRef_i6.base.key.key)
        self.assertEqual(validationWF_i2.base.LMSessKey.key, validationRef_i6.base.LMSessKey.key)
        validationEx_i2 = self.do_LogonEx(ncreds, conn,
                                          logon_type_i, logon_info_i,
                                          validation_level2,
                                          expect_send_encrypted,
                                          expect_recv_encrypted)
        self.assertEqual(validationEx_i2.base.rid, validationRef_i6.base.rid)
        self.assertEqual(validationEx_i2.base.key.key, validationRef_i6.base.key.key)
        self.assertEqual(validationEx_i2.base.LMSessKey.key, validationRef_i6.base.LMSessKey.key)

        expect_send_encrypted = expect_encrypted
        expect_recv_encrypted = False
        validationWF_i3 = self.do_LogonWithFlags(ncreds, conn,
                                                 logon_type_i, logon_info_i,
                                                 validation_level3,
                                                 expect_send_encrypted,
                                                 expect_recv_encrypted)
        self.assertEqual(validationWF_i3.base.rid, validationRef_i6.base.rid)
        self.assertEqual(validationWF_i3.base.key.key, validationRef_i6.base.key.key)
        self.assertEqual(validationWF_i3.base.LMSessKey.key, validationRef_i6.base.LMSessKey.key)
        validationEx_i3 = self.do_LogonEx(ncreds, conn,
                                          logon_type_i, logon_info_i,
                                          validation_level3,
                                          expect_send_encrypted,
                                          expect_recv_encrypted)
        self.assertEqual(validationEx_i3.base.rid, validationRef_i6.base.rid)
        self.assertEqual(validationEx_i3.base.key.key, validationRef_i6.base.key.key)
        self.assertEqual(validationEx_i3.base.LMSessKey.key, validationRef_i6.base.LMSessKey.key)

        expect_send_encrypted = expect_encrypted
        expect_recv_encrypted = False
        validationWF_i6 = self.do_LogonWithFlags(ncreds, conn,
                                                 logon_type_i, logon_info_i,
                                                 validation_level6,
                                                 expect_send_encrypted,
                                                 expect_recv_encrypted)
        self.assertEqual(validationWF_i6.base.rid, validationRef_i6.base.rid)
        self.assertEqual(validationWF_i6.base.key.key, validationRef_i6.base.key.key)
        self.assertEqual(validationWF_i6.base.LMSessKey.key, validationRef_i6.base.LMSessKey.key)
        validationEx_i6 = self.do_LogonEx(ncreds, conn,
                                          logon_type_i, logon_info_i,
                                          validation_level6,
                                          expect_send_encrypted,
                                          expect_recv_encrypted)
        self.assertEqual(validationEx_i6.base.rid, validationRef_i6.base.rid)
        self.assertEqual(validationEx_i6.base.key.key, validationRef_i6.base.key.key)
        self.assertEqual(validationEx_i6.base.LMSessKey.key, validationRef_i6.base.LMSessKey.key)

        self.do_CheckCapabilities(ncreds, conn)
        return

    def _test_interactive_samlogon_with_args(self, trust, authX, flags):
        (creds, ncreds, conn, expect_encrypted) = \
            self._prepare_ncreds_conn_with_args(trust, authX, flags)

        return self._test_interactive_samlogon(creds,
                                               ncreds,
                                               conn,
                                               expect_encrypted)

    def _test_generic_samlogon(self, trust_creds, ncreds, conn,
                               expect_encrypted):
        self.do_CheckCapabilities(ncreds, conn)

        expect_broken_crypto = False

        if expect_broken_crypto:
            expect_error = ntstatus.NT_STATUS_INVALID_PARAMETER
        else:
            expect_error = None

        krbtgt_creds = self.get_krbtgt_creds()
        krbtgt_key = self.TicketDecryptionKey_from_creds(krbtgt_creds)

        cks = krbtgt_key.make_checksum(KU_NON_KERB_CKSUM_SALT, b'')
        sig = krbtgt_key.make_checksum(KU_NON_KERB_CKSUM_SALT, cks)

        pv = krb5pac.PAC_Validate()
        pv.ChecksumLength = len(cks)
        pv.SignatureType = krbtgt_key.ctype
        pv.SignatureLength = len(sig)
        pv.ChecksumAndSignature = cks + sig
        pv_blob = ndr_pack(pv)

        validation_level = netlogon.NetlogonValidationGenericInfo2
        logon_type = netlogon.NetlogonGenericInformation
        logon_info_pv = self._prepare_samlogon(ncreds,
                                               conn,
                                               logon_type,
                                               self.user_creds,
                                               generic_package="Kerberos",
                                               generic_data=pv_blob)

        expect_send_encrypted = expect_encrypted
        expect_recv_encrypted = False
        validationEx = self.do_LogonEx(ncreds, conn,
                                       logon_type, logon_info_pv,
                                       validation_level,
                                       expect_send_encrypted,
                                       expect_recv_encrypted,
                                       expect_error=expect_error)
        if expect_error is None:
            self.assertEqual(validationEx.length, 0)

        expect_send_encrypted = expect_encrypted
        expect_recv_encrypted = False
        validationWF = self.do_LogonWithFlags(ncreds, conn,
                                              logon_type, logon_info_pv,
                                              validation_level,
                                              expect_send_encrypted,
                                              expect_recv_encrypted,
                                              expect_error=expect_error)
        if expect_error is None:
            self.assertEqual(validationWF.length, 0)

        self.do_CheckCapabilities(ncreds, conn)
        return

    def _test_generic_samlogon_with_args(self, trust, authX, flags):
        (creds, ncreds, conn, expect_encrypted) = \
            self._prepare_ncreds_conn_with_args(trust, authX, flags)

        return self._test_generic_samlogon(creds,
                                           ncreds,
                                           conn,
                                           expect_encrypted)

    def _test_ticket_samlogon(self, trust_creds, ncreds, conn,
                              expect_encrypted):
        self.do_CheckCapabilities(ncreds, conn)

        validation_level = netlogon.NetlogonValidationTicketLogon
        logon_type = netlogon.NetlogonTicketLogonInformation
        logon_info = self._prepare_samlogon(ncreds,
                                            conn,
                                            logon_type,
                                            self.user_creds,
                                            trust_creds=trust_creds)

        expect_send_encrypted = False
        expect_recv_encrypted = False
        validationEx = self.do_LogonEx(ncreds, conn,
                                       logon_type, logon_info,
                                       validation_level,
                                       expect_send_encrypted,
                                       expect_recv_encrypted)
        self.assertEqual(validationEx.results,
                         netlogon.NETLOGON_TICKET_LOGON_FULL_SIGNATURE_PRESENT)
        self.assertEqual(validationEx.kerberos_status[0], ntstatus.NT_STATUS_OK)
        self.assertEqual(validationEx.netlogon_status[0], ntstatus.NT_STATUS_OK)
        self.assertIsNone(validationEx.source_of_status.string)
        self.assertIsNotNone(validationEx.user_information)
        self.assertNotEqual(validationEx.user_information.base.rid, 0)
        self.assertEqual(validationEx.user_information.base.key.key, list(b'\x00' *16))
        self.assertIsNone(validationEx.device_information)

        expect_send_encrypted = False
        expect_recv_encrypted = False
        validationWF = self.do_LogonWithFlags(ncreds, conn,
                                              logon_type, logon_info,
                                              validation_level,
                                              expect_send_encrypted,
                                              expect_recv_encrypted)
        self.assertEqual(validationWF.results,
                         netlogon.NETLOGON_TICKET_LOGON_FULL_SIGNATURE_PRESENT)
        self.assertEqual(validationWF.kerberos_status[0], ntstatus.NT_STATUS_OK)
        self.assertEqual(validationWF.netlogon_status[0], ntstatus.NT_STATUS_OK)
        self.assertIsNone(validationWF.source_of_status.string)
        self.assertIsNotNone(validationWF.user_information)
        self.assertEqual(validationWF.user_information.base.rid,
                         validationEx.user_information.base.rid)
        self.assertEqual(validationWF.user_information.base.key.key, list(b'\x00' *16))
        self.assertIsNone(validationWF.device_information)

        self.do_CheckCapabilities(ncreds, conn)
        return

    def _test_ticket_samlogon_with_args(self, trust, authX, flags):
        (creds, ncreds, conn, expect_encrypted) = \
            self._prepare_ncreds_conn_with_args(trust, authX, flags)

        return self._test_ticket_samlogon(creds,
                                          ncreds,
                                          conn,
                                          expect_encrypted)


if __name__ == "__main__":
    global_asn1_print = True
    global_ndr_print = True
    global_hexdump = True
    import unittest
    unittest.main()
