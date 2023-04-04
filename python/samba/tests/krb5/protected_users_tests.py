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

sys.path.insert(0, 'bin/python')
os.environ['PYTHONUNBUFFERED'] = '1'

from functools import partial

import ldb

from samba import NTSTATUSError, generate_random_password, ntstatus
from samba.dcerpc import lsa, netlogon, samr, security
from samba.ndr import ndr_unpack
from samba.samdb import SamDB

import samba.tests.krb5.kcrypto as kcrypto
from samba.tests.krb5.kdc_base_test import KDCBaseTest
from samba.tests.krb5.rfc4120_constants import (
    AES128_CTS_HMAC_SHA1_96,
    AES256_CTS_HMAC_SHA1_96,
    ARCFOUR_HMAC_MD5,
    DES3_CBC_MD5,
    DES3_CBC_SHA1,
    DES_CBC_CRC,
    DES_CBC_MD5,
    KDC_ERR_ETYPE_NOSUPP,
    KDC_ERR_POLICY,
    KDC_ERR_PREAUTH_REQUIRED,
    KRB_ERROR,
    NT_PRINCIPAL,
    NT_SRV_INST,
)
import samba.tests.krb5.rfc4120_pyasn1 as krb5_asn1

global_asn1_print = False
global_hexdump = False


class ProtectedUsersTests(KDCBaseTest):
    def setUp(self):
        super().setUp()
        self.do_asn1_print = global_asn1_print
        self.do_hexdump = global_hexdump

    # Get account credentials for testing.
    def _get_creds(self,
                   protected,
                   account_type=KDCBaseTest.AccountType.USER,
                   ntlm=False,
                   member_of=None,
                   supported_enctypes=None,
                   cached=True):
        opts = {
            'kerberos_enabled': not ntlm,
        }
        members = ()
        if protected:
            samdb = self.get_samdb()
            protected_users_group = (f'<SID={samdb.get_domain_sid()}-'
                                     f'{security.DOMAIN_RID_PROTECTED_USERS}>')
            members += (protected_users_group,)
        if member_of is not None:
            members += (member_of,)

        if members:
            opts['member_of'] = members

        return self.get_cached_creds(account_type=account_type,
                                     opts=opts,
                                     use_cache=cached)

    # Test credentials by connecting to the DC through LDAP.
    def _connect(self, creds, expect_error=False):
        samdb = self.get_samdb()
        try:
            ldap = SamDB(url=f'ldap://{samdb.host_dns_name()}',
                         credentials=creds,
                         lp=self.get_lp())
        except ldb.LdbError as err:
            self.assertTrue(expect_error, 'got unexpected error')
            num, _ = err.args
            if num != ldb.ERR_INVALID_CREDENTIALS:
                raise

            return
        else:
            self.assertFalse(expect_error, 'expected to get an error')

        res = ldap.search('',
                          scope=ldb.SCOPE_BASE,
                          attrs=['tokenGroups'])
        self.assertEqual(1, len(res))

        sid = self.get_objectSid(samdb, creds.get_dn())

        token_groups = res[0].get('tokenGroups', idx=0)
        token_sid = ndr_unpack(security.dom_sid, token_groups)

        self.assertEqual(sid, str(token_sid))

    # Test NTLM authentication with a normal account. Authentication should
    # succeed.
    def test_ntlm_not_protected(self):
        client_creds = self._get_creds(protected=False,
                                       ntlm=True,
                                       cached=False)

        self._connect(client_creds)

    # Test NTLM authentication with a protected account. Authentication should
    # fail, as Protected User accounts cannot use NTLM authentication.
    def test_ntlm_protected(self):
        client_creds = self._get_creds(protected=True,
                                       ntlm=True,
                                       cached=False)

        self._connect(client_creds, expect_error=True)

    # Test that the Protected Users restrictions still apply when the user is a
    # member of a group that is itself a member of Protected Users.
    def test_ntlm_protected_nested(self):
        samdb = self.get_samdb()
        group_name = self.get_new_username()
        group_dn = self.create_group(samdb, group_name)

        protected_users_group = (f'<SID={samdb.get_domain_sid()}-'
                                 f'{security.DOMAIN_RID_PROTECTED_USERS}>')
        self.add_to_group(group_dn, ldb.Dn(samdb, protected_users_group),
                          'member', expect_attr=False)

        client_creds = self._get_creds(protected=False,
                                       ntlm=True,
                                       member_of=group_dn)

        self._connect(client_creds, expect_error=True)

    # Test the three SAMR password change methods implemented in Samba. If the
    # user is protected, we should get an ACCOUNT_RESTRICTION error indicating
    # that the password change is not allowed; otherwise we should get a
    # WRONG_PASSWORD error.
    def _test_samr_change_password(self, creds, protected):
        samdb = self.get_samdb()
        server_name = samdb.host_dns_name()
        conn = samr.samr(f'ncacn_np:{server_name}[krb5,seal,smb2]')

        username = creds.get_username()

        server = lsa.String()
        server.string = server_name

        account = lsa.String()
        account.string = username

        nt_password = samr.CryptPassword()
        nt_verifier = samr.Password()

        with self.assertRaises(NTSTATUSError) as err:
            conn.ChangePasswordUser2(server=server,
                                     account=account,
                                     nt_password=nt_password,
                                     nt_verifier=nt_verifier,
                                     lm_change=True,
                                     lm_password=None,
                                     lm_verifier=None)

        num, _ = err.exception.args
        if protected:
            self.assertEqual(ntstatus.NT_STATUS_ACCOUNT_RESTRICTION, num)
        else:
            self.assertEqual(ntstatus.NT_STATUS_WRONG_PASSWORD, num)

        with self.assertRaises(NTSTATUSError) as err:
            conn.ChangePasswordUser3(server=server,
                                     account=account,
                                     nt_password=nt_password,
                                     nt_verifier=nt_verifier,
                                     lm_change=True,
                                     lm_password=None,
                                     lm_verifier=None,
                                     password3=None)

        num, _ = err.exception.args
        if protected:
            self.assertEqual(ntstatus.NT_STATUS_ACCOUNT_RESTRICTION, num)
        else:
            self.assertEqual(ntstatus.NT_STATUS_WRONG_PASSWORD, num)

        server = lsa.AsciiString()
        server.string = server_name

        account = lsa.AsciiString()
        account.string = username

        with self.assertRaises(NTSTATUSError) as err:
            conn.OemChangePasswordUser2(server=server,
                                        account=account,
                                        password=nt_password,
                                        hash=nt_verifier)

        num, _ = err.exception.args
        if num != ntstatus.NT_STATUS_NOT_IMPLEMENTED:
            if protected:
                self.assertEqual(ntstatus.NT_STATUS_ACCOUNT_RESTRICTION, num)
            else:
                self.assertEqual(ntstatus.NT_STATUS_WRONG_PASSWORD, num)

    # Test SAMR password changes for unprotected and protected accounts.
    def test_samr_change_password_not_protected(self):
        # Use a non-cached account so that it is not locked out for other
        # tests.
        client_creds = self._get_creds(protected=False,
                                       cached=False)

        self._test_samr_change_password(client_creds, protected=False)

    def test_samr_change_password_protected(self):
        # Use a non-cached account so that it is not locked out for other
        # tests.
        client_creds = self._get_creds(protected=True,
                                       cached=False)

        self._test_samr_change_password(client_creds, protected=True)

    # Test interactive SamLogon with an unprotected account.
    def test_samlogon_interactive_not_protected(self):
        client_creds = self._get_creds(protected=False,
                                       ntlm=True)
        self._test_samlogon(creds=client_creds,
                            logon_type=netlogon.NetlogonInteractiveInformation,
                            protected=False)

    # Test interactive SamLogon with a protected account.
    def test_samlogon_interactive_protected(self):
        client_creds = self._get_creds(protected=True,
                                       ntlm=True)
        self._test_samlogon(creds=client_creds,
                            logon_type=netlogon.NetlogonInteractiveInformation,
                            protected=True)

    # Test network SamLogon with an unprotected account.
    def test_samlogon_network_not_protected(self):
        client_creds = self._get_creds(protected=False,
                                       ntlm=True)
        self._test_samlogon(creds=client_creds,
                            logon_type=netlogon.NetlogonNetworkInformation,
                            protected=False)

    # Test network SamLogon with a protected account.
    def test_samlogon_network_protected(self):
        client_creds = self._get_creds(protected=True,
                                       ntlm=True)
        self._test_samlogon(creds=client_creds,
                            logon_type=netlogon.NetlogonNetworkInformation,
                            protected=True)

    # Test that changing the password of an account in the Protected Users
    # group still generates an NT hash.
    def test_protected_nt_hash(self):
        # Use a non-cached account, as we are changing the password.
        client_creds = self._get_creds(protected=True,
                                       cached=False)
        client_dn = client_creds.get_dn()

        new_password = generate_random_password(32, 32)
        utf16pw = f'"{new_password}"'.encode('utf-16-le')

        samdb = self.get_samdb()
        msg = ldb.Message(client_dn)
        msg['unicodePwd'] = ldb.MessageElement(utf16pw,
                                               ldb.FLAG_MOD_REPLACE,
                                               'unicodePwd')
        samdb.modify(msg)

        client_creds.set_password(new_password)

        self.get_keys(client_dn,
                      expected_etypes={kcrypto.Enctype.AES256,
                                       kcrypto.Enctype.AES128,
                                       kcrypto.Enctype.RC4})

    # Test that DES-CBC-CRC cannot be used whether or not the user is
    # protected.
    def test_des_cbc_crc_not_protected(self):
        client_creds = self._get_creds(protected=False)

        self._test_etype(client_creds, etype=DES_CBC_CRC,
                         expect_error=True)

    def test_des_cbc_crc_protected(self):
        client_creds = self._get_creds(protected=True)

        self._test_etype(client_creds, etype=DES_CBC_CRC,
                         expect_error=True, rc4_support=False)

    # Test that DES-CBC-MD5 cannot be used whether or not the user is
    # protected.
    def test_des_cbc_md5_not_protected(self):
        client_creds = self._get_creds(protected=False)

        self._test_etype(client_creds, etype=DES_CBC_MD5,
                         expect_error=True)

    def test_des_cbc_md5_protected(self):
        client_creds = self._get_creds(protected=True)

        self._test_etype(client_creds, etype=DES_CBC_MD5,
                         expect_error=True, rc4_support=False)

    # Test that DES3-CBC-MD5 cannot be used whether or not the user is
    # protected.
    def test_des3_cbc_md5_not_protected(self):
        client_creds = self._get_creds(protected=False)

        self._test_etype(client_creds, etype=DES3_CBC_MD5,
                         expect_error=True)

    def test_des3_cbc_md5_protected(self):
        client_creds = self._get_creds(protected=True)

        self._test_etype(client_creds, etype=DES3_CBC_MD5,
                         expect_error=True, rc4_support=False)

    # Test that DES3-CBC-SHA1 cannot be used whether or not the user is
    # protected.
    def test_des3_cbc_sha1_not_protected(self):
        client_creds = self._get_creds(protected=False)

        self._test_etype(client_creds, etype=DES3_CBC_SHA1,
                         expect_error=True)

    def test_des3_cbc_sha1_protected(self):
        client_creds = self._get_creds(protected=True)

        self._test_etype(client_creds, etype=DES3_CBC_SHA1,
                         expect_error=True, rc4_support=False)

    # Test that RC4 may only be used if the user is not protected.
    def test_rc4_not_protected(self):
        client_creds = self._get_creds(protected=False)

        self._test_etype(client_creds, etype=ARCFOUR_HMAC_MD5)

    def test_rc4_protected_aes256_preauth(self):
        client_creds = self._get_creds(protected=True)

        self._test_etype(client_creds, etype=ARCFOUR_HMAC_MD5,
                         preauth_etype=AES256_CTS_HMAC_SHA1_96,
                         rc4_support=False)

    def test_rc4_protected_rc4_preauth(self):
        client_creds = self._get_creds(protected=True)

        self._test_etype(client_creds, etype=ARCFOUR_HMAC_MD5,
                         preauth_etype=ARCFOUR_HMAC_MD5,
                         expect_error=True, rc4_support=False,
                         expect_edata=False)

    # Test that AES256 can always be used.
    def test_aes256_not_protected(self):
        client_creds = self._get_creds(protected=False)

        self._test_etype(client_creds, etype=AES256_CTS_HMAC_SHA1_96)

    def test_aes256_protected(self):
        client_creds = self._get_creds(protected=True)

        self._test_etype(client_creds, etype=AES256_CTS_HMAC_SHA1_96,
                         rc4_support=False)

    def test_aes256_rc4_not_protected(self):
        client_creds = self._get_creds(protected=False)

        self._test_etype(client_creds, etype=(AES256_CTS_HMAC_SHA1_96,
                                              ARCFOUR_HMAC_MD5))

    def test_aes256_rc4_protected(self):
        client_creds = self._get_creds(protected=True)

        self._test_etype(client_creds, etype=(AES256_CTS_HMAC_SHA1_96,
                                              ARCFOUR_HMAC_MD5),
                         rc4_support=False)

    def test_rc4_aes256_not_protected(self):
        client_creds = self._get_creds(protected=False)

        self._test_etype(client_creds, etype=(ARCFOUR_HMAC_MD5,
                                              AES256_CTS_HMAC_SHA1_96))

    def test_rc4_aes256_protected(self):
        client_creds = self._get_creds(protected=True)

        self._test_etype(client_creds, etype=(ARCFOUR_HMAC_MD5,
                                              AES256_CTS_HMAC_SHA1_96),
                         rc4_support=False)

    # Test that AES128 can always be used.
    def test_aes128_not_protected(self):
        client_creds = self._get_creds(protected=False)

        self._test_etype(client_creds, etype=AES128_CTS_HMAC_SHA1_96)

    def test_aes128_protected(self):
        client_creds = self._get_creds(protected=True)

        self._test_etype(client_creds, etype=AES128_CTS_HMAC_SHA1_96,
                         rc4_support=False)

    def test_aes128_rc4_not_protected(self):
        client_creds = self._get_creds(protected=False)

        self._test_etype(client_creds, etype=(AES128_CTS_HMAC_SHA1_96,
                                              ARCFOUR_HMAC_MD5))

    def test_aes128_rc4_protected(self):
        client_creds = self._get_creds(protected=True)

        self._test_etype(client_creds, etype=(AES128_CTS_HMAC_SHA1_96,
                                              ARCFOUR_HMAC_MD5),
                         rc4_support=False)

    def test_rc4_aes128_not_protected(self):
        client_creds = self._get_creds(protected=False)

        self._test_etype(client_creds, etype=(ARCFOUR_HMAC_MD5,
                                              AES128_CTS_HMAC_SHA1_96))

    def test_rc4_aes128_protected(self):
        client_creds = self._get_creds(protected=True)

        self._test_etype(client_creds, etype=(ARCFOUR_HMAC_MD5,
                                              AES128_CTS_HMAC_SHA1_96),
                         rc4_support=False)

    # Test also with computer accounts.
    def test_rc4_mac_not_protected(self):
        client_creds = self._get_creds(
            protected=False,
            account_type=self.AccountType.COMPUTER)

        self._test_etype(client_creds, etype=ARCFOUR_HMAC_MD5)

    def test_rc4_mac_protected_aes256_preauth(self):
        client_creds = self._get_creds(
            protected=True,
            account_type=self.AccountType.COMPUTER)

        self._test_etype(client_creds, etype=ARCFOUR_HMAC_MD5,
                         preauth_etype=AES256_CTS_HMAC_SHA1_96,
                         rc4_support=False)

    def test_rc4_mac_protected_rc4_preauth(self):
        client_creds = self._get_creds(
            protected=True,
            account_type=self.AccountType.COMPUTER)

        self._test_etype(client_creds, etype=ARCFOUR_HMAC_MD5,
                         preauth_etype=ARCFOUR_HMAC_MD5,
                         expect_error=True, rc4_support=False,
                         expect_edata=False)

    def test_aes256_rc4_mac_not_protected(self):
        client_creds = self._get_creds(
            protected=False,
            account_type=self.AccountType.COMPUTER)

        self._test_etype(client_creds, etype=(AES256_CTS_HMAC_SHA1_96,
                                              ARCFOUR_HMAC_MD5))

    def test_aes256_rc4_mac_protected(self):
        client_creds = self._get_creds(
            protected=True,
            account_type=self.AccountType.COMPUTER)

        self._test_etype(client_creds, etype=(AES256_CTS_HMAC_SHA1_96,
                                              ARCFOUR_HMAC_MD5),
                         rc4_support=False)

    def test_rc4_aes256_mac_not_protected(self):
        client_creds = self._get_creds(
            protected=False,
            account_type=self.AccountType.COMPUTER)

        self._test_etype(client_creds, etype=(ARCFOUR_HMAC_MD5,
                                              AES256_CTS_HMAC_SHA1_96))

    def test_rc4_aes256_mac_protected(self):
        client_creds = self._get_creds(
            protected=True,
            account_type=self.AccountType.COMPUTER)

        self._test_etype(client_creds, etype=(ARCFOUR_HMAC_MD5,
                                              AES256_CTS_HMAC_SHA1_96),
                         rc4_support=False)

    def test_aes128_rc4_mac_not_protected(self):
        client_creds = self._get_creds(
            protected=False,
            account_type=self.AccountType.COMPUTER)

        self._test_etype(client_creds, etype=(AES128_CTS_HMAC_SHA1_96,
                                              ARCFOUR_HMAC_MD5))

    def test_aes128_rc4_mac_protected(self):
        client_creds = self._get_creds(
            protected=True,
            account_type=self.AccountType.COMPUTER)

        self._test_etype(client_creds, etype=(AES128_CTS_HMAC_SHA1_96,
                                              ARCFOUR_HMAC_MD5),
                         rc4_support=False)

    def test_rc4_aes128_mac_not_protected(self):
        client_creds = self._get_creds(
            protected=False,
            account_type=self.AccountType.COMPUTER)

        self._test_etype(client_creds, etype=(ARCFOUR_HMAC_MD5,
                                              AES128_CTS_HMAC_SHA1_96))

    def test_rc4_aes128_mac_protected(self):
        client_creds = self._get_creds(
            protected=True,
            account_type=self.AccountType.COMPUTER)

        self._test_etype(client_creds, etype=(ARCFOUR_HMAC_MD5,
                                              AES128_CTS_HMAC_SHA1_96),
                         rc4_support=False)

    # Test that RC4 can only be used as a preauth etype if the user is not
    # protected.
    def test_ts_rc4_not_protected(self):
        client_creds = self._get_creds(protected=False)

        self._test_etype(client_creds, preauth_etype=ARCFOUR_HMAC_MD5)

    def test_ts_rc4_protected(self):
        client_creds = self._get_creds(protected=True)

        self._test_etype(client_creds, preauth_etype=ARCFOUR_HMAC_MD5,
                         expect_error=True, rc4_support=False,
                         expect_edata=False)

    # Test that the etype restrictions still apply if the user is a member of a
    # group that is itself in the Protected Users group.
    def test_ts_rc4_protected_nested(self):
        samdb = self.get_samdb()
        group_name = self.get_new_username()
        group_dn = self.create_group(samdb, group_name)

        protected_users_group = (f'<SID={samdb.get_domain_sid()}-'
                                 f'{security.DOMAIN_RID_PROTECTED_USERS}>')
        self.add_to_group(group_dn, ldb.Dn(samdb, protected_users_group),
                          'member', expect_attr=False)

        client_creds = self._get_creds(protected=False,
                                       member_of=group_dn)

        self._test_etype(client_creds, preauth_etype=ARCFOUR_HMAC_MD5,
                         expect_error=True, rc4_support=False,
                         expect_edata=False)

    # Test that AES256 can always be used as a preauth etype.
    def test_ts_aes256_not_protected(self):
        client_creds = self._get_creds(protected=False)

        self._test_etype(client_creds, preauth_etype=AES256_CTS_HMAC_SHA1_96)

    def test_ts_aes256_protected(self):
        client_creds = self._get_creds(protected=True)

        self._test_etype(client_creds, preauth_etype=AES256_CTS_HMAC_SHA1_96,
                         rc4_support=False)

    # Test that AES128 can always be used as a preauth etype.
    def test_ts_aes128_not_protected(self):
        client_creds = self._get_creds(protected=False)

        self._test_etype(client_creds, preauth_etype=AES128_CTS_HMAC_SHA1_96)

    def test_ts_aes128_protected(self):
        client_creds = self._get_creds(protected=True)

        self._test_etype(client_creds, preauth_etype=AES128_CTS_HMAC_SHA1_96,
                         rc4_support=False)

    # Test also with machine accounts.
    def test_ts_rc4_mac_not_protected(self):
        client_creds = self._get_creds(
            protected=False,
            account_type=self.AccountType.COMPUTER)

        self._test_etype(client_creds, preauth_etype=ARCFOUR_HMAC_MD5)

    def test_ts_rc4_mac_protected(self):
        client_creds = self._get_creds(
            protected=True,
            account_type=self.AccountType.COMPUTER)

        self._test_etype(client_creds, preauth_etype=ARCFOUR_HMAC_MD5,
                         expect_error=True, rc4_support=False,
                         expect_edata=False)

    def test_ts_aes256_mac_not_protected(self):
        client_creds = self._get_creds(
            protected=False,
            account_type=self.AccountType.COMPUTER)

        self._test_etype(client_creds, preauth_etype=AES256_CTS_HMAC_SHA1_96)

    def test_ts_aes256_mac_protected(self):
        client_creds = self._get_creds(
            protected=True,
            account_type=self.AccountType.COMPUTER)

        self._test_etype(client_creds, preauth_etype=AES256_CTS_HMAC_SHA1_96,
                         rc4_support=False)

    def test_ts_aes128_mac_not_protected(self):
        client_creds = self._get_creds(
            protected=False,
            account_type=self.AccountType.COMPUTER)

        self._test_etype(client_creds, preauth_etype=AES128_CTS_HMAC_SHA1_96)

    def test_ts_aes128_mac_protected(self):
        client_creds = self._get_creds(
            protected=True,
            account_type=self.AccountType.COMPUTER)

        self._test_etype(client_creds, preauth_etype=AES128_CTS_HMAC_SHA1_96,
                         rc4_support=False)

    # Test that the restrictions do not apply to accounts acting as services,
    # and that RC4 service tickets can still be obtained.
    def test_service_rc4_only_not_protected(self):
        client_creds = self.get_client_creds()
        service_creds = self._get_creds(protected=False,
                                        account_type=self.AccountType.COMPUTER,
                                        supported_enctypes=kcrypto.Enctype.RC4)
        tgt = self.get_tgt(client_creds)
        self.get_service_ticket(tgt, service_creds)

    def test_service_rc4_only_protected(self):
        client_creds = self.get_client_creds()
        service_creds = self._get_creds(protected=True,
                                        account_type=self.AccountType.COMPUTER,
                                        supported_enctypes=kcrypto.Enctype.RC4)
        tgt = self.get_tgt(client_creds)
        self.get_service_ticket(tgt, service_creds)

    # Test that requesting a ticket with a short lifetime results in a ticket
    # with that lifetime.
    def test_tgt_lifetime_shorter_not_protected(self):
        client_creds = self._get_creds(protected=False)

        till = self.get_KerberosTime(offset=2 * 60 * 60)  # 2 hours
        tgt = self._test_etype(client_creds,
                               preauth_etype=AES256_CTS_HMAC_SHA1_96,
                               till=till)
        self.check_ticket_times(tgt, expected_end=till)

    def test_tgt_lifetime_shorter_protected(self):
        client_creds = self._get_creds(protected=True)

        till = self.get_KerberosTime(offset=2 * 60 * 60)  # 2 hours
        tgt = self._test_etype(client_creds,
                               preauth_etype=AES256_CTS_HMAC_SHA1_96,
                               till=till, rc4_support=False)

        self.check_ticket_times(tgt, expected_end=till,
                                expected_renew_time=till)

    # Test that requesting a ticket with a long lifetime produces a ticket with
    # that lifetime, unless the user is protected, whereupon the lifetime will
    # be capped at four hours.
    def test_tgt_lifetime_longer_not_protected(self):
        client_creds = self._get_creds(protected=False)

        till = self.get_KerberosTime(offset=6 * 60 * 60)  # 6 hours
        tgt = self._test_etype(client_creds,
                               preauth_etype=AES256_CTS_HMAC_SHA1_96,
                               till=till)
        self.check_ticket_times(tgt, expected_end=till)

    def test_tgt_lifetime_longer_protected(self):
        client_creds = self._get_creds(protected=True)

        till = self.get_KerberosTime(offset=6 * 60 * 60)  # 6 hours
        tgt = self._test_etype(client_creds,
                               preauth_etype=AES256_CTS_HMAC_SHA1_96,
                               till=till, rc4_support=False)

        expected_life = 4 * 60 * 60  # 4 hours
        self.check_ticket_times(tgt, expected_life=expected_life,
                                expected_renew_life=expected_life)

    # Test that the lifetime of a service ticket is capped to the lifetime of
    # the TGT.
    def test_ticket_lifetime_not_protected(self):
        client_creds = self._get_creds(protected=False)

        till = self.get_KerberosTime(offset=2 * 60 * 60)  # 2 hours
        tgt = self._test_etype(
            client_creds, preauth_etype=AES256_CTS_HMAC_SHA1_96, till=till)
        self.check_ticket_times(tgt, expected_end=till)

        service_creds = self.get_service_creds()
        till2 = self.get_KerberosTime(offset=10 * 60 * 60)  # 10 hours
        ticket = self.get_service_ticket(tgt, service_creds, till=till2)

        self.check_ticket_times(ticket, expected_end=till)

    def test_ticket_lifetime_protected(self):
        client_creds = self._get_creds(protected=True)

        till = self.get_KerberosTime(offset=2 * 60 * 60)  # 2 hours
        tgt = self._test_etype(
            client_creds, preauth_etype=AES256_CTS_HMAC_SHA1_96, till=till,
            rc4_support=False)

        self.check_ticket_times(tgt, expected_end=till,
                                expected_renew_time=till)

        service_creds = self.get_service_creds()
        till2 = self.get_KerberosTime(offset=10 * 60 * 60)  # 10 hours
        ticket = self.get_service_ticket(tgt, service_creds, till=till2)

        self.check_ticket_times(ticket, expected_end=till)

    # Test that a request for a forwardable ticket will only be fulfilled if
    # the user is not protected.
    def test_forwardable_as_not_protected(self):
        client_creds = self._get_creds(protected=False)

        self._get_tgt_check_flags(client_creds, kdc_options='forwardable',
                                  expected_flags='forwardable')

    def test_forwardable_as_protected(self):
        client_creds = self._get_creds(protected=True)

        self._get_tgt_check_flags(client_creds, kdc_options='forwardable',
                                  unexpected_flags='forwardable',
                                  rc4_support=False)

    # Test that a request for a proxiable ticket will only be fulfilled if the
    # user is not protected.
    def test_proxiable_as_not_protected(self):
        client_creds = self._get_creds(protected=False)

        self._get_tgt_check_flags(client_creds, kdc_options='proxiable',
                                  expected_flags='proxiable')

    def test_proxiable_as_protected(self):
        client_creds = self._get_creds(protected=True)

        self._get_tgt_check_flags(client_creds, kdc_options='proxiable',
                                  unexpected_flags='proxiable',
                                  rc4_support=False)

    # An alternate test for Protected Users that passes if we get a policy
    # error rather than a ticket that is not proxiable.
    def test_proxiable_as_protected_policy_error(self):
        client_creds = self._get_creds(protected=True)

        self._get_tgt_check_flags(client_creds, kdc_options='proxiable',
                                  unexpected_flags='proxiable',
                                  rc4_support=False, expect_error=True)

    # Test that if we have a forwardable TGT, then we can use it to obtain a
    # forwardable service ticket, whether or not the account is protected.
    def test_forwardable_tgs_not_protected(self):
        client_creds = self._get_creds(protected=False)

        tgt = self.get_tgt(client_creds)
        tgt = self.modified_ticket(
            tgt,
            modify_fn=partial(self.modify_ticket_flag, flag='forwardable',
                              value=True),
            checksum_keys=self.get_krbtgt_checksum_key())

        service_creds = self.get_service_creds()
        self.get_service_ticket(
            tgt, service_creds, kdc_options='forwardable',
            expected_flags=krb5_asn1.TicketFlags('forwardable'))

    def test_forwardable_tgs_protected(self):
        client_creds = self._get_creds(protected=True)

        tgt = self.get_tgt(client_creds, rc4_support=False)
        tgt = self.modified_ticket(
            tgt,
            modify_fn=partial(self.modify_ticket_flag, flag='forwardable',
                              value=True),
            checksum_keys=self.get_krbtgt_checksum_key())

        service_creds = self.get_service_creds()
        self.get_service_ticket(
            tgt, service_creds, kdc_options='forwardable',
            expected_flags=krb5_asn1.TicketFlags('forwardable'),
            rc4_support=False)

    # Test that if we have a proxiable TGT, then we can use it to obtain a
    # forwardable service ticket, whether or not the account is protected.
    def test_proxiable_tgs_not_protected(self):
        client_creds = self._get_creds(protected=False)

        tgt = self.get_tgt(client_creds)
        tgt = self.modified_ticket(
            tgt,
            modify_fn=partial(self.modify_ticket_flag, flag='proxiable',
                              value=True),
            checksum_keys=self.get_krbtgt_checksum_key())

        service_creds = self.get_service_creds()
        self.get_service_ticket(
            tgt, service_creds, kdc_options='proxiable',
            expected_flags=krb5_asn1.TicketFlags('proxiable'))

    def test_proxiable_tgs_protected(self):
        client_creds = self._get_creds(protected=True)

        tgt = self.get_tgt(client_creds, rc4_support=False)
        tgt = self.modified_ticket(
            tgt,
            modify_fn=partial(self.modify_ticket_flag, flag='proxiable',
                              value=True),
            checksum_keys=self.get_krbtgt_checksum_key())

        service_creds = self.get_service_creds()
        self.get_service_ticket(
            tgt, service_creds, kdc_options='proxiable',
            expected_flags=krb5_asn1.TicketFlags('proxiable'),
            rc4_support=False)

    def check_ticket_times(self,
                           ticket_creds,
                           expected_end=None,
                           expected_life=None,
                           expected_renew_time=None,
                           expected_renew_life=None):
        ticket = ticket_creds.ticket_private

        authtime = ticket['authtime']
        starttime = ticket.get('starttime', authtime)
        endtime = ticket['endtime']
        renew_till = ticket.get('renew-till', None)

        starttime = self.get_EpochFromKerberosTime(starttime)

        if expected_end is None:
            self.assertIsNotNone(expected_life,
                                 'did not supply expected endtime or lifetime')

            expected_end = self.get_KerberosTime(epoch=starttime,
                                                 offset=expected_life)
        else:
            self.assertIsNone(expected_life,
                              'supplied both expected endtime and lifetime')

        self.assertEqual(expected_end, endtime.decode('ascii'))

        if renew_till is None:
            self.assertIsNone(expected_renew_time)
            self.assertIsNone(expected_renew_life)
        else:
            if expected_renew_life is not None:
                self.assertIsNone(
                    expected_renew_time,
                    'supplied both expected renew time and lifetime')

                expected_renew_time = self.get_KerberosTime(
                    epoch=starttime, offset=expected_renew_life)

            if expected_renew_time is not None:
                self.assertEqual(expected_renew_time,
                                 renew_till.decode('ascii'))

    def _test_etype(self,
                    creds,
                    expect_error=False,
                    etype=None,
                    preauth_etype=None,
                    till=None,
                    rc4_support=True,
                    expect_edata=None):
        if etype is None:
            etype = (AES256_CTS_HMAC_SHA1_96, ARCFOUR_HMAC_MD5)
        elif isinstance(etype, int):
            etype = (etype,)

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

        kdc_options = krb5_asn1.KDCOptions('renewable')
        expected_flags = krb5_asn1.TicketFlags('renewable')

        expected_error = KDC_ERR_ETYPE_NOSUPP if expect_error else 0

        if preauth_etype is None:
            if expected_error:
                expected_error_mode = KDC_ERR_PREAUTH_REQUIRED, expected_error
            else:
                expected_error_mode = KDC_ERR_PREAUTH_REQUIRED

            rep, kdc_exchange_dict = self._test_as_exchange(
                cname=cname,
                realm=realm,
                sname=sname,
                till=till,
                renew_time=renew_time,
                expected_error_mode=expected_error_mode,
                expected_crealm=realm,
                expected_cname=expected_cname,
                expected_srealm=realm,
                expected_sname=sname,
                expected_salt=salt,
                expected_flags=expected_flags,
                expected_supported_etypes=expected_etypes,
                etypes=etype,
                padata=None,
                kdc_options=kdc_options,
                ticket_decryption_key=ticket_decryption_key,
                rc4_support=rc4_support,
                expect_edata=expect_edata)
            self.assertIsNotNone(rep)
            self.assertEqual(KRB_ERROR, rep['msg-type'])
            error_code = rep['error-code']
            if expected_error:
                self.assertIn(error_code, expected_error_mode)
                if error_code == expected_error:
                    return
            else:
                self.assertEqual(expected_error_mode, error_code)

            etype_info2 = kdc_exchange_dict['preauth_etype_info2']

            preauth_key = self.PasswordKey_from_etype_info2(creds,
                                                            etype_info2[0],
                                                            creds.get_kvno())
        else:
            preauth_key = self.PasswordKey_from_creds(creds, preauth_etype)

        ts_enc_padata = self.get_enc_timestamp_pa_data_from_key(preauth_key)
        padata = [ts_enc_padata]

        expected_realm = realm.upper()

        rep, kdc_exchange_dict = self._test_as_exchange(
            cname=cname,
            realm=realm,
            sname=sname,
            till=till,
            renew_time=renew_time,
            expected_error_mode=expected_error,
            expected_crealm=expected_realm,
            expected_cname=expected_cname,
            expected_srealm=expected_realm,
            expected_sname=expected_sname,
            expected_salt=salt,
            expected_flags=expected_flags,
            expected_supported_etypes=expected_etypes,
            etypes=etype,
            padata=padata,
            kdc_options=kdc_options,
            preauth_key=preauth_key,
            ticket_decryption_key=ticket_decryption_key,
            rc4_support=rc4_support,
            expect_edata=expect_edata)
        if expect_error:
            self.check_error_rep(rep, expected_error)

            return None

        self.check_as_reply(rep)

        ticket_creds = kdc_exchange_dict['rep_ticket_creds']
        return ticket_creds

    def _get_tgt_check_flags(self,
                             creds,
                             kdc_options,
                             rc4_support=True,
                             expect_error=False,
                             expected_flags=None,
                             unexpected_flags=None):
        user_name = creds.get_username()

        realm = creds.get_realm()

        salt = creds.get_salt()

        etype = (AES256_CTS_HMAC_SHA1_96, ARCFOUR_HMAC_MD5)
        cname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                          names=user_name.split('/'))
        sname = self.PrincipalName_create(name_type=NT_SRV_INST,
                                          names=['krbtgt', realm])
        expected_sname = self.PrincipalName_create(
            name_type=NT_SRV_INST, names=['krbtgt', realm.upper()])

        expected_cname = cname

        till = self.get_KerberosTime(offset=36000)

        krbtgt_creds = self.get_krbtgt_creds()
        ticket_decryption_key = (
            self.TicketDecryptionKey_from_creds(krbtgt_creds))

        expected_etypes = krbtgt_creds.tgs_supported_enctypes

        kdc_options = krb5_asn1.KDCOptions(kdc_options)

        if expected_flags is not None:
            expected_flags = krb5_asn1.TicketFlags(expected_flags)
        if unexpected_flags is not None:
            unexpected_flags = krb5_asn1.TicketFlags(unexpected_flags)

        rep, kdc_exchange_dict = self._test_as_exchange(
            cname=cname,
            realm=realm,
            sname=sname,
            till=till,
            expected_error_mode=KDC_ERR_PREAUTH_REQUIRED,
            expected_crealm=realm,
            expected_cname=expected_cname,
            expected_srealm=realm,
            expected_sname=sname,
            expected_salt=salt,
            expected_flags=expected_flags,
            unexpected_flags=unexpected_flags,
            expected_supported_etypes=expected_etypes,
            etypes=etype,
            padata=None,
            kdc_options=kdc_options,
            ticket_decryption_key=ticket_decryption_key,
            rc4_support=rc4_support)
        self.check_pre_authentication(rep)

        etype_info2 = kdc_exchange_dict['preauth_etype_info2']

        preauth_key = self.PasswordKey_from_etype_info2(creds,
                                                        etype_info2[0],
                                                        creds.get_kvno())

        ts_enc_padata = self.get_enc_timestamp_pa_data_from_key(preauth_key)
        padata = [ts_enc_padata]

        expected_realm = realm.upper()

        expected_error = KDC_ERR_POLICY if expect_error else 0

        rep, kdc_exchange_dict = self._test_as_exchange(
            cname=cname,
            realm=realm,
            sname=sname,
            till=till,
            expected_error_mode=expected_error,
            expected_crealm=expected_realm,
            expected_cname=expected_cname,
            expected_srealm=expected_realm,
            expected_sname=expected_sname,
            expected_salt=salt,
            expected_flags=expected_flags,
            unexpected_flags=unexpected_flags,
            expected_supported_etypes=expected_etypes,
            etypes=etype,
            padata=padata,
            kdc_options=kdc_options,
            preauth_key=preauth_key,
            ticket_decryption_key=ticket_decryption_key,
            rc4_support=rc4_support)
        if expect_error:
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
