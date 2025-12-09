#!/usr/bin/env python3
# Unix SMB/CIFS implementation.
# Copyright (C) Stefan Metzmacher 2020
# Copyright (C) Catalyst.Net Ltd
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

from concurrent import futures
from enum import Enum
from functools import partial
import multiprocessing
from multiprocessing import Pipe
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.base import Cipher
from cryptography.hazmat.primitives.ciphers import algorithms

import ldb

from samba import (
    NTSTATUSError,
    dsdb,
    generate_random_bytes,
    generate_random_password,
    ntstatus,
    unix2nttime,
    werror,
)
from samba.credentials import DONT_USE_KERBEROS, MUST_USE_KERBEROS
from samba.crypto import (
    aead_aes_256_cbc_hmac_sha512_blob,
    des_crypt_blob_16,
    md4_hash_blob,
    sha512_pbkdf2,
)
from samba.dcerpc import lsa, samr
from samba.samdb import SamDB

from samba.tests import connect_samdb, env_get_var_value, env_loadparm

from samba.tests.krb5.as_req_tests import AsReqBaseTest
from samba.tests.krb5 import kcrypto
from samba.tests.krb5.kdc_tgs_tests import KdcTgsBaseTests
from samba.tests.krb5.raw_testcase import KerberosCredentials
import samba.tests.krb5.rfc4120_pyasn1 as krb5_asn1
from samba.tests.krb5.rfc4120_constants import (
    KDC_ERR_CLIENT_REVOKED,
    KDC_ERR_KEY_EXPIRED,
    KDC_ERR_PREAUTH_FAILED,
    KRB_AS_REP,
    KRB_ERROR,
    NT_PRINCIPAL,
    NT_SRV_INST,
)

global_asn1_print = False
global_hexdump = False


class ConnectionResult(Enum):
    LOCKED_OUT = 1
    WRONG_PASSWORD = 2
    SUCCESS = 3


def connect_kdc(pipe,
                url,
                hostname,
                username,
                password,
                domain,
                realm,
                workstation,
                dn,
                expect_error=True,
                expect_status=None):
    AsReqBaseTest.setUpClass()
    as_req_base = AsReqBaseTest()
    as_req_base.setUp()

    user_creds = KerberosCredentials()
    user_creds.set_username(username)
    user_creds.set_password(password)
    user_creds.set_domain(domain)
    user_creds.set_realm(realm)
    user_creds.set_workstation(workstation)
    user_creds.set_kerberos_state(DONT_USE_KERBEROS)

    user_name = user_creds.get_username()
    cname = as_req_base.PrincipalName_create(name_type=NT_PRINCIPAL,
                                             names=user_name.split('/'))

    krbtgt_creds = as_req_base.get_krbtgt_creds()
    krbtgt_supported_etypes = krbtgt_creds.tgs_supported_enctypes
    realm = krbtgt_creds.get_realm()

    krbtgt_account = krbtgt_creds.get_username()
    sname = as_req_base.PrincipalName_create(name_type=NT_SRV_INST,
                                             names=[krbtgt_account, realm])

    expected_salt = user_creds.get_salt()

    till = as_req_base.get_KerberosTime(offset=36000)

    kdc_options = krb5_asn1.KDCOptions('postdated')

    preauth_key = as_req_base.PasswordKey_from_creds(user_creds,
                                                     kcrypto.Enctype.AES256)

    ts_enc_padata = as_req_base.get_enc_timestamp_pa_data_from_key(preauth_key)
    padata = [ts_enc_padata]

    krbtgt_decryption_key = (
        as_req_base.TicketDecryptionKey_from_creds(krbtgt_creds))

    etypes = as_req_base.get_default_enctypes(user_creds)

    # Remove the LDAP connection.
    del type(as_req_base)._ldb

    if expect_error:
        expected_error_modes = (KDC_ERR_CLIENT_REVOKED,
                                KDC_ERR_PREAUTH_FAILED)

        # Wrap generic_check_kdc_error() to expect an NTSTATUS code when the
        # account is locked out.
        def check_error_fn(kdc_exchange_dict,
                           callback_dict,
                           rep):
            error_code = rep.get('error-code')
            if error_code == KDC_ERR_CLIENT_REVOKED:
                # The account was locked out.
                kdc_exchange_dict['expected_status'] = (
                    ntstatus.NT_STATUS_ACCOUNT_LOCKED_OUT)

                if expect_status:
                    # Expect to get a LOCKED_OUT NTSTATUS code.
                    kdc_exchange_dict['expect_edata'] = True
                    kdc_exchange_dict['expect_status'] = True

            elif error_code == KDC_ERR_PREAUTH_FAILED:
                # Just a wrong password: the account wasn’t locked out. Don’t
                # expect an NTSTATUS code.
                kdc_exchange_dict['expect_status'] = False

            # Continue with the generic error-checking logic.
            return as_req_base.generic_check_kdc_error(
                kdc_exchange_dict,
                callback_dict,
                rep)

        check_rep_fn = None
    else:
        expected_error_modes = 0

        check_error_fn = None
        check_rep_fn = as_req_base.generic_check_kdc_rep

    def _generate_padata_copy(_kdc_exchange_dict,
                              _callback_dict,
                              req_body):
        return padata, req_body

    kdc_exchange_dict = as_req_base.as_exchange_dict(
        creds=user_creds,
        expected_crealm=realm,
        expected_cname=cname,
        expected_srealm=realm,
        expected_sname=sname,
        expected_account_name=user_name,
        expected_supported_etypes=krbtgt_supported_etypes,
        ticket_decryption_key=krbtgt_decryption_key,
        generate_padata_fn=_generate_padata_copy,
        check_error_fn=check_error_fn,
        check_rep_fn=check_rep_fn,
        check_kdc_private_fn=as_req_base.generic_check_kdc_private,
        expected_error_mode=expected_error_modes,
        expected_salt=expected_salt,
        preauth_key=preauth_key,
        kdc_options=str(kdc_options),
        pac_request=True)

    # Indicate that we're ready. This ensures we hit the right transaction
    # lock.
    pipe.send_bytes(b'0')

    # Wait for the main process to take out a transaction lock.
    if not pipe.poll(timeout=5):
        raise AssertionError('main process failed to indicate readiness')

    # Try making a Kerberos AS-REQ to the KDC. This might fail, either due to
    # the user's account being locked out or due to using the wrong password.
    as_rep = as_req_base._generic_kdc_exchange(kdc_exchange_dict,
                                               cname=cname,
                                               realm=realm,
                                               sname=sname,
                                               till_time=till,
                                               etypes=etypes)

    as_req_base.assertIsNotNone(as_rep)

    msg_type = as_rep['msg-type']
    if expect_error and msg_type != KRB_ERROR or (
            not expect_error and msg_type != KRB_AS_REP):
        raise AssertionError(f'wrong message type {msg_type}')

    if not expect_error:
        return ConnectionResult.SUCCESS

    error_code = as_rep['error-code']
    if error_code == KDC_ERR_CLIENT_REVOKED:
        return ConnectionResult.LOCKED_OUT
    elif error_code == KDC_ERR_PREAUTH_FAILED:
        return ConnectionResult.WRONG_PASSWORD
    else:
        raise AssertionError(f'wrong error code {error_code}')


def connect_ntlm(pipe,
                 url,
                 hostname,
                 username,
                 password,
                 domain,
                 realm,
                 workstation,
                 dn):
    user_creds = KerberosCredentials()
    user_creds.set_username(username)
    user_creds.set_password(password)
    user_creds.set_domain(domain)
    user_creds.set_workstation(workstation)
    user_creds.set_kerberos_state(DONT_USE_KERBEROS)

    # Indicate that we're ready. This ensures we hit the right transaction
    # lock.
    pipe.send_bytes(b'0')

    # Wait for the main process to take out a transaction lock.
    if not pipe.poll(timeout=5):
        raise AssertionError('main process failed to indicate readiness')

    try:
        # Try connecting to SamDB. This should fail, either due to our
        # account being locked out or due to using the wrong password.
        SamDB(url=url,
              credentials=user_creds,
              lp=env_loadparm())
    except ldb.LdbError as err:
        num, estr = err.args

        if num != ldb.ERR_INVALID_CREDENTIALS:
            raise AssertionError(f'connection raised wrong error code '
                                 f'({err})')

        if f'data {werror.WERR_ACCOUNT_LOCKED_OUT:x},' in estr:
            return ConnectionResult.LOCKED_OUT
        elif f'data {werror.WERR_LOGON_FAILURE:x},' in estr:
            return ConnectionResult.WRONG_PASSWORD
        else:
            raise AssertionError(f'connection raised wrong error code '
                                 f'({estr})')
    else:
        return ConnectionResult.SUCCESS


def connect_samr(pipe,
                 url,
                 hostname,
                 username,
                 password,
                 domain,
                 realm,
                 workstation,
                 dn):
    # Get the user's NT hash.
    user_creds = KerberosCredentials()
    user_creds.set_password(password)
    nt_hash = user_creds.get_nt_hash()

    # Generate a new UTF-16 password.
    new_password = generate_random_password(32, 32)
    new_password = new_password.encode('utf-16le')

    # Generate the MD4 hash of the password.
    new_password_md4 = md4_hash_blob(new_password)

    # Prefix the password with padding so it is 512 bytes long.
    new_password_len = len(new_password)
    remaining_len = 512 - new_password_len
    new_password = bytes(remaining_len) + new_password

    # Append the 32-bit length of the password..
    new_password += int.to_bytes(new_password_len,
                                 length=4,
                                 byteorder='little')

    # Encrypt the password with RC4 and the existing NT hash.
    encryptor = Cipher(algorithms.ARC4(nt_hash),
                       None,
                       default_backend()).encryptor()
    new_password = encryptor.update(new_password)

    # Create a key from the MD4 hash of the new password.
    key = new_password_md4[:14]

    # Encrypt the old NT hash with DES to obtain the verifier.
    verifier = des_crypt_blob_16(nt_hash, key)

    server = lsa.String()
    server.string = hostname

    account = lsa.String()
    account.string = username

    nt_password = samr.CryptPassword()
    nt_password.data = list(new_password)

    nt_verifier = samr.Password()
    nt_verifier.hash = list(verifier)

    conn = samr.samr(f'ncacn_np:{hostname}[krb5,seal,smb2]')

    # Indicate that we're ready. This ensures we hit the right transaction
    # lock.
    pipe.send_bytes(b'0')

    # Wait for the main process to take out a transaction lock.
    if not pipe.poll(timeout=5):
        raise AssertionError('main process failed to indicate readiness')

    try:
        # Try changing the password. This should fail, either due to our
        # account being locked out or due to using the wrong password.
        conn.ChangePasswordUser3(server=server,
                                 account=account,
                                 nt_password=nt_password,
                                 nt_verifier=nt_verifier,
                                 lm_change=True,
                                 lm_password=None,
                                 lm_verifier=None,
                                 password3=None)
    except NTSTATUSError as err:
        num, estr = err.args

        if num == ntstatus.NT_STATUS_ACCOUNT_LOCKED_OUT:
            return ConnectionResult.LOCKED_OUT
        elif num == ntstatus.NT_STATUS_WRONG_PASSWORD:
            return ConnectionResult.WRONG_PASSWORD
        else:
            raise AssertionError(f'pwd change raised wrong error code '
                                 f'({num:08X})')
    else:
        return ConnectionResult.SUCCESS


def connect_samr_aes(pipe,
                     url,
                     hostname,
                     username,
                     password,
                     domain,
                     realm,
                     workstation,
                     dn):
    # Get the user's NT hash.
    user_creds = KerberosCredentials()
    user_creds.set_password(password)
    nt_hash = user_creds.get_nt_hash()

    # Generate a new UTF-16 password.
    new_password = generate_random_password(32, 32)
    new_password = new_password.encode('utf-16le')

    # Prepend the 16-bit length of the password..
    new_password_len = int.to_bytes(len(new_password),
                                    length=2,
                                    byteorder='little')
    new_password = new_password_len + new_password

    server = lsa.String()
    server.string = hostname

    account = lsa.String()
    account.string = username

    # Derive a key from the user's NT hash.
    iv = generate_random_bytes(16)
    iterations = 5555
    cek = sha512_pbkdf2(nt_hash, iv, iterations)

    enc_key_salt = (b'Microsoft SAM encryption key '
                    b'AEAD-AES-256-CBC-HMAC-SHA512 16\0')
    mac_key_salt = (b'Microsoft SAM MAC key '
                    b'AEAD-AES-256-CBC-HMAC-SHA512 16\0')

    # Encrypt the new password.
    ciphertext, auth_data = aead_aes_256_cbc_hmac_sha512_blob(new_password,
                                                              cek,
                                                              enc_key_salt,
                                                              mac_key_salt,
                                                              iv)

    # Create the new password structure
    pwd_buf = samr.EncryptedPasswordAES()
    pwd_buf.auth_data = list(auth_data)
    pwd_buf.salt = list(iv)
    pwd_buf.cipher_len = len(ciphertext)
    pwd_buf.cipher = list(ciphertext)
    pwd_buf.PBKDF2Iterations = iterations

    conn = samr.samr(f'ncacn_np:{hostname}[krb5,seal,smb2]')

    # Indicate that we're ready. This ensures we hit the right transaction
    # lock.
    pipe.send_bytes(b'0')

    # Wait for the main process to take out a transaction lock.
    if not pipe.poll(timeout=5):
        raise AssertionError('main process failed to indicate readiness')

    try:
        # Try changing the password. This should fail, either due to our
        # account being locked out or due to using the wrong password.
        conn.ChangePasswordUser4(server=server,
                                 account=account,
                                 password=pwd_buf)
    except NTSTATUSError as err:
        num, estr = err.args

        if num == ntstatus.NT_STATUS_ACCOUNT_LOCKED_OUT:
            return ConnectionResult.LOCKED_OUT
        elif num == ntstatus.NT_STATUS_WRONG_PASSWORD:
            return ConnectionResult.WRONG_PASSWORD
        else:
            raise AssertionError(f'pwd change raised wrong error code '
                                 f'({num:08X})')
    else:
        return ConnectionResult.SUCCESS


def ldap_pwd_change(pipe,
                    url,
                    hostname,
                    username,
                    password,
                    domain,
                    realm,
                    workstation,
                    dn):
    lp = env_loadparm()

    admin_creds = KerberosCredentials()
    admin_creds.guess(lp)
    admin_creds.set_username(env_get_var_value('ADMIN_USERNAME'))
    admin_creds.set_password(env_get_var_value('ADMIN_PASSWORD'))
    admin_creds.set_kerberos_state(MUST_USE_KERBEROS)

    samdb = SamDB(url=url,
                  credentials=admin_creds,
                  lp=lp)

    old_utf16pw = f'"{password}"'.encode('utf-16le')

    new_password = generate_random_password(32, 32)
    new_utf16pw = f'"{new_password}"'.encode('utf-16le')

    msg = ldb.Message(ldb.Dn(samdb, dn))
    msg['0'] = ldb.MessageElement(old_utf16pw,
                                  ldb.FLAG_MOD_DELETE,
                                  'unicodePwd')
    msg['1'] = ldb.MessageElement(new_utf16pw,
                                  ldb.FLAG_MOD_ADD,
                                  'unicodePwd')

    # Indicate that we're ready. This ensures we hit the right transaction
    # lock.
    pipe.send_bytes(b'0')

    # Wait for the main process to take out a transaction lock.
    if not pipe.poll(timeout=5):
        raise AssertionError('main process failed to indicate readiness')

    # Try changing the user's password. This should fail, either due to the
    # user's account being locked out or due to specifying the wrong password.
    try:
        samdb.modify(msg)
    except ldb.LdbError as err:
        num, estr = err.args
        if num != ldb.ERR_CONSTRAINT_VIOLATION:
            raise AssertionError(f'pwd change raised wrong error code ({err})')

        if f'<{werror.WERR_ACCOUNT_LOCKED_OUT:08X}:' in estr:
            return ConnectionResult.LOCKED_OUT
        elif f'<{werror.WERR_INVALID_PASSWORD:08X}:' in estr:
            return ConnectionResult.WRONG_PASSWORD
        else:
            raise AssertionError(f'pwd change raised wrong error code '
                                 f'({estr})')
    else:
        return ConnectionResult.SUCCESS


class LockoutTests(KdcTgsBaseTests):

    def setUp(self):
        super().setUp()
        self.do_asn1_print = global_asn1_print
        self.do_hexdump = global_hexdump

        samdb = self.get_samdb()
        base_dn = ldb.Dn(samdb, samdb.domain_dn())

        def modify_attr(attr, value):
            if value is None:
                value = []
                flag = ldb.FLAG_MOD_DELETE
            else:
                value = str(value)
                flag = ldb.FLAG_MOD_REPLACE

                msg = ldb.Message(base_dn)
                msg[attr] = ldb.MessageElement(
                    value, flag, attr)
                samdb.modify(msg)

        res = samdb.search(base_dn,
                           scope=ldb.SCOPE_BASE,
                           attrs=['lockoutDuration',
                                  'lockoutThreshold',
                                  'msDS-LogonTimeSyncInterval'])
        self.assertEqual(1, len(res))

        # Reset the lockout duration as it was before.
        lockout_duration = res[0].get('lockoutDuration', idx=0)
        self.addCleanup(modify_attr, 'lockoutDuration', lockout_duration)

        # Set the new lockout duration: locked out accounts now stay locked
        # out.
        modify_attr('lockoutDuration', 0)

        # Reset the lockout threshold as it was before.
        lockout_threshold = res[0].get('lockoutThreshold', idx=0)
        self.addCleanup(modify_attr, 'lockoutThreshold', lockout_threshold)

        # Set the new lockout threshold.
        self.lockout_threshold = 3
        modify_attr('lockoutThreshold', self.lockout_threshold)

        # Reset the logon time sync interval as it was before.
        sync_interval = res[0].get('msDS-LogonTimeSyncInterval', idx=0)
        self.addCleanup(modify_attr,
                        'msDS-LogonTimeSyncInterval',
                        sync_interval)

        # Set the new logon time sync interval. Setting it to 0 eliminates the
        # need for this attribute to be updated on logon, and thus the
        # requirement to take out a transaction.
        modify_attr('msDS-LogonTimeSyncInterval', 0)

        # Get the old 'minPwdAge'.
        minPwdAge = samdb.get_minPwdAge()

        # Reset the 'minPwdAge' as it was before.
        self.addCleanup(samdb.set_minPwdAge, minPwdAge)

        # Set it temporarily to '0'.
        samdb.set_minPwdAge('0')

    def wait_for_ready(self, pipe, future):
        if pipe.poll(timeout=5):
            return

        # We failed to read a response from the pipe, so see if the test raised
        # an exception with more information.
        if future.done():
            exception = future.exception(timeout=0)
            if exception is not None:
                raise exception

        self.fail('test failed to indicate readiness')

    def test_lockout_transaction_kdc(self):
        self.do_lockout_transaction(connect_kdc)

    def test_lockout_transaction_kdc_ntstatus(self):
        self.do_lockout_transaction(partial(connect_kdc, expect_status=True))

    # Test that performing AS‐REQs with accounts in various states of
    # unusability results in appropriate NTSTATUS and Kerberos error codes.

    def test_lockout_status_disabled(self):
        self._run_lockout_status(
            self._get_creds_disabled(),
            expected_status=ntstatus.NT_STATUS_ACCOUNT_DISABLED,
            expected_error=KDC_ERR_CLIENT_REVOKED,
        )

    def test_lockout_status_locked_out(self):
        self._run_lockout_status(
            self._get_creds_locked_out(),
            expected_status=ntstatus.NT_STATUS_ACCOUNT_LOCKED_OUT,
            expected_error=KDC_ERR_CLIENT_REVOKED,
        )

    def test_lockout_status_expired(self):
        self._run_lockout_status(
            self._get_creds_expired(),
            expected_status=ntstatus.NT_STATUS_ACCOUNT_EXPIRED,
            expected_error=KDC_ERR_CLIENT_REVOKED,
        )

    def test_lockout_status_must_change(self):
        self._run_lockout_status(
            self._get_creds_must_change(),
            expected_status=ntstatus.NT_STATUS_PASSWORD_MUST_CHANGE,
            expected_error=KDC_ERR_KEY_EXPIRED,
        )

    def test_lockout_status_password_expired(self):
        self._run_lockout_status(
            self._get_creds_password_expired(),
            expected_status=ntstatus.NT_STATUS_PASSWORD_EXPIRED,
            expected_error=KDC_ERR_KEY_EXPIRED,
        )

    # Test that performing the same AS‐REQs, this time with FAST, does not
    # result in NTSTATUS codes.

    def test_lockout_status_disabled_fast(self):
        self._run_lockout_status_fast(
            self._get_creds_disabled(), expected_error=KDC_ERR_CLIENT_REVOKED
        )

    def test_lockout_status_locked_out_fast(self):
        self._run_lockout_status_fast(
            self._get_creds_locked_out(), expected_error=KDC_ERR_CLIENT_REVOKED
        )

    def test_lockout_status_expired_fast(self):
        self._run_lockout_status_fast(
            self._get_creds_expired(), expected_error=KDC_ERR_CLIENT_REVOKED
        )

    def test_lockout_status_must_change_fast(self):
        self._run_lockout_status_fast(
            self._get_creds_must_change(), expected_error=KDC_ERR_KEY_EXPIRED
        )

    def test_lockout_status_password_expired_fast(self):
        self._run_lockout_status_fast(
            self._get_creds_password_expired(), expected_error=KDC_ERR_KEY_EXPIRED
        )

    def _get_creds_disabled(self):
        return self.get_cached_creds(
            account_type=self.AccountType.USER, opts={"enabled": False}
        )

    def _get_creds_locked_out(self) -> KerberosCredentials:
        samdb = self.get_samdb()

        user_creds = self.get_cached_creds(
            account_type=self.AccountType.USER, use_cache=False
        )
        user_dn = user_creds.get_dn()

        # Lock out the account.

        old_utf16pw = '"Secret007"'.encode("utf-16le")  # invalid pwd
        new_utf16pw = '"Secret008"'.encode("utf-16le")

        msg = ldb.Message(user_dn)
        msg["0"] = ldb.MessageElement(old_utf16pw, ldb.FLAG_MOD_DELETE, "unicodePwd")
        msg["1"] = ldb.MessageElement(new_utf16pw, ldb.FLAG_MOD_ADD, "unicodePwd")

        for _ in range(self.lockout_threshold):
            try:
                samdb.modify(msg)
            except ldb.LdbError as err:
                num, _ = err.args

                # We get an error, but the bad password count should
                # still be updated.
                self.assertEqual(num, ldb.ERR_CONSTRAINT_VIOLATION)
            else:
                self.fail("pwd change should have failed")

        # Ensure the account is locked out.

        res = samdb.search(
            user_dn, scope=ldb.SCOPE_BASE, attrs=["msDS-User-Account-Control-Computed"]
        )
        self.assertEqual(1, len(res))

        uac = int(res[0].get("msDS-User-Account-Control-Computed", idx=0))
        self.assertTrue(uac & dsdb.UF_LOCKOUT)

        return user_creds

    def _get_creds_expired(self) -> KerberosCredentials:
        return self.get_cached_creds(
            account_type=self.AccountType.USER,
            opts={"additional_details": self.freeze({"accountExpires": "1"})},
        )

    def _get_creds_must_change(self) -> KerberosCredentials:
        return self.get_cached_creds(
            account_type=self.AccountType.USER,
            opts={"additional_details": self.freeze({"pwdLastSet": "0"})},
        )

    def _get_creds_password_expired(self) -> KerberosCredentials:
        samdb = self.get_samdb()
        self.addCleanup(samdb.set_maxPwdAge, samdb.get_maxPwdAge())
        low_pwd_age = -2
        samdb.set_maxPwdAge(low_pwd_age)

        return self.get_cached_creds(account_type=self.AccountType.USER)

    def _run_lockout_status(
        self,
        user_creds: KerberosCredentials,
        *,
        expected_status: int,
        expected_error: int,
    ) -> None:
        user_name = user_creds.get_username()
        cname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL, names=user_name.split("/")
        )

        krbtgt_creds = self.get_krbtgt_creds()
        realm = krbtgt_creds.get_realm()

        sname = self.get_krbtgt_sname()

        preauth_key = self.PasswordKey_from_creds(user_creds, kcrypto.Enctype.AES256)

        ts_enc_padata = self.get_enc_timestamp_pa_data_from_key(preauth_key)
        padata = [ts_enc_padata]

        def _generate_padata_copy(_kdc_exchange_dict, _callback_dict, req_body):
            return padata, req_body

        kdc_exchange_dict = self.as_exchange_dict(
            creds=user_creds,
            expected_crealm=realm,
            expected_cname=cname,
            expected_srealm=realm,
            expected_sname=sname,
            expected_account_name=user_name,
            expected_supported_etypes=krbtgt_creds.tgs_supported_enctypes,
            expect_edata=True,
            expect_status=True,
            expected_status=expected_status,
            ticket_decryption_key=self.TicketDecryptionKey_from_creds(krbtgt_creds),
            generate_padata_fn=_generate_padata_copy,
            check_error_fn=self.generic_check_kdc_error,
            check_rep_fn=None,
            check_kdc_private_fn=self.generic_check_kdc_private,
            expected_error_mode=expected_error,
            expected_salt=user_creds.get_salt(),
            preauth_key=preauth_key,
            kdc_options=str(krb5_asn1.KDCOptions("postdated")),
            pac_request=True,
        )

        # Try making a Kerberos AS-REQ to the KDC. This might fail, either due
        # to the user's account being locked out or due to using the wrong
        # password.
        self._generic_kdc_exchange(
            kdc_exchange_dict,
            cname=cname,
            realm=realm,
            sname=sname,
            till_time=self.get_KerberosTime(offset=36000),
            etypes=self.get_default_enctypes(user_creds),
        )

    def _run_lockout_status_fast(
        self, user_creds: KerberosCredentials, *, expected_error: int
    ) -> None:
        self._armored_as_req(
            user_creds,
            self.get_krbtgt_creds(),
            self.get_tgt(self.get_mach_creds()),
            expected_error=expected_error,
            expect_edata=self.expect_padata_outer,
            # FAST‐armored responses never contain an NTSTATUS code.
            expect_status=False,
        )

    def test_lockout_transaction_ntlm(self):
        self.do_lockout_transaction(connect_ntlm)

    def test_lockout_transaction_samr(self):
        self.do_lockout_transaction(connect_samr)

    def test_lockout_transaction_samr_aes(self):
        self.do_lockout_transaction(connect_samr_aes)

    def test_lockout_transaction_ldap_pw_change(self):
        self.do_lockout_transaction(ldap_pwd_change)

    # Tests to ensure we can handle the account being renamed. We do not test
    # renames with SAMR password changes, because in that case the entire
    # process happens inside a transaction, and the password change method only
    # receives the account username. By the time it searches for the account,
    # it will have already been renamed, and so it will always fail to find the
    # account.

    def test_lockout_transaction_rename_kdc(self):
        self.do_lockout_transaction(connect_kdc, rename=True)

    def test_lockout_transaction_rename_kdc_ntstatus(self):
        self.do_lockout_transaction(partial(connect_kdc, expect_status=True),
                                    rename=True)

    def test_lockout_transaction_rename_ntlm(self):
        self.do_lockout_transaction(connect_ntlm, rename=True)

    def test_lockout_transaction_rename_ldap_pw_change(self):
        self.do_lockout_transaction(ldap_pwd_change, rename=True)

    def test_lockout_transaction_bad_pwd_kdc(self):
        self.do_lockout_transaction(connect_kdc, correct_pw=False)

    def test_lockout_transaction_bad_pwd_kdc_ntstatus(self):
        self.do_lockout_transaction(partial(connect_kdc, expect_status=True),
                                    correct_pw=False)

    def test_lockout_transaction_bad_pwd_ntlm(self):
        self.do_lockout_transaction(connect_ntlm, correct_pw=False)

    def test_lockout_transaction_bad_pwd_samr(self):
        self.do_lockout_transaction(connect_samr, correct_pw=False)

    def test_lockout_transaction_bad_pwd_samr_aes(self):
        self.do_lockout_transaction(connect_samr_aes, correct_pw=False)

    def test_lockout_transaction_bad_pwd_ldap_pw_change(self):
        self.do_lockout_transaction(ldap_pwd_change, correct_pw=False)

    def test_bad_pwd_count_transaction_kdc(self):
        self.do_bad_pwd_count_transaction(connect_kdc)

    def test_bad_pwd_count_transaction_ntlm(self):
        self.do_bad_pwd_count_transaction(connect_ntlm)

    def test_bad_pwd_count_transaction_samr(self):
        self.do_bad_pwd_count_transaction(connect_samr)

    def test_bad_pwd_count_transaction_samr_aes(self):
        self.do_bad_pwd_count_transaction(connect_samr_aes)

    def test_bad_pwd_count_transaction_ldap_pw_change(self):
        self.do_bad_pwd_count_transaction(ldap_pwd_change)

    def test_bad_pwd_count_transaction_rename_kdc(self):
        self.do_bad_pwd_count_transaction(connect_kdc, rename=True)

    def test_bad_pwd_count_transaction_rename_ntlm(self):
        self.do_bad_pwd_count_transaction(connect_ntlm, rename=True)

    def test_bad_pwd_count_transaction_rename_ldap_pw_change(self):
        self.do_bad_pwd_count_transaction(ldap_pwd_change, rename=True)

    def test_lockout_race_kdc(self):
        self.do_lockout_race(connect_kdc)

    def test_lockout_race_kdc_ntstatus(self):
        self.do_lockout_race(partial(connect_kdc, expect_status=True))

    def test_lockout_race_ntlm(self):
        self.do_lockout_race(connect_ntlm)

    def test_lockout_race_samr(self):
        self.do_lockout_race(connect_samr)

    def test_lockout_race_samr_aes(self):
        self.do_lockout_race(connect_samr_aes)

    def test_lockout_race_ldap_pw_change(self):
        self.do_lockout_race(ldap_pwd_change)

    def test_logon_without_transaction_ntlm(self):
        self.do_logon_without_transaction(connect_ntlm)

    # Tests to ensure that the connection functions work correctly in the happy
    # path.

    def test_logon_kdc(self):
        self.do_logon(partial(connect_kdc, expect_error=False))

    def test_logon_ntlm(self):
        self.do_logon(connect_ntlm)

    def test_logon_samr(self):
        self.do_logon(connect_samr)

    def test_logon_samr_aes(self):
        self.do_logon(connect_samr_aes)

    def test_logon_ldap_pw_change(self):
        self.do_logon(ldap_pwd_change)

    # Test that connection without a correct password works.
    def do_logon(self, connect_fn):
        # Create the user account for testing.
        user_creds = self.get_cached_creds(account_type=self.AccountType.USER,
                                           use_cache=False)
        admin_creds = self.get_admin_creds()
        lp = self.get_lp()

        # Get a connection to our local SamDB.
        samdb = connect_samdb(samdb_url=lp.samdb_url(), lp=lp,
                              credentials=admin_creds)
        self.assertLocalSamDB(samdb)
        user_dn = ldb.Dn(samdb, str(user_creds.get_dn()))

        password = user_creds.get_password()

        # Prepare to connect to the server with a valid password.
        our_pipe, their_pipe = Pipe(duplex=True)

        # Inform the test function that it may proceed.
        our_pipe.send_bytes(b'0')

        result = connect_fn(pipe=their_pipe,
                            url=f'ldap://{samdb.host_dns_name()}',
                            hostname=samdb.host_dns_name(),
                            username=user_creds.get_username(),
                            password=password,
                            domain=user_creds.get_domain(),
                            realm=user_creds.get_realm(),
                            workstation=user_creds.get_workstation(),
                            dn=str(user_dn))

        # The connection should succeed.
        self.assertEqual(result, ConnectionResult.SUCCESS)

    # Lock out the account while holding a transaction lock, then release the
    # lock. A logon attempt already in progress should reread the account
    # details and recognise the account is locked out. The account can
    # additionally be renamed within the transaction to ensure that, by using
    # the GUID, rereading the account's details still succeeds.
    def do_lockout_transaction(self, connect_fn,
                               rename=False,
                               correct_pw=True):
        # Create the user account for testing.
        user_creds = self.get_cached_creds(account_type=self.AccountType.USER,
                                           use_cache=False)

        admin_creds = self.get_admin_creds()
        lp = self.get_lp()

        # Get a connection to our local SamDB.
        samdb = connect_samdb(samdb_url=lp.samdb_url(), lp=lp,
                              credentials=admin_creds)
        self.assertLocalSamDB(samdb)

        user_dn = ldb.Dn(samdb, str(user_creds.get_dn()))

        password = user_creds.get_password()
        if not correct_pw:
            password = password[:-1]

        # Prepare to connect to the server.
        mp_context = multiprocessing.get_context('fork')
        with futures.ProcessPoolExecutor(max_workers=1,
                                         mp_context=mp_context) as executor:
            our_pipe, their_pipe = Pipe(duplex=True)
            connect_future = executor.submit(
                connect_fn,
                pipe=their_pipe,
                url=f'ldap://{samdb.host_dns_name()}',
                hostname=samdb.host_dns_name(),
                username=user_creds.get_username(),
                password=password,
                domain=user_creds.get_domain(),
                realm=user_creds.get_realm(),
                workstation=user_creds.get_workstation(),
                dn=str(user_dn))

            # Wait until the test process indicates it's ready.
            self.wait_for_ready(our_pipe, connect_future)

            # Take out a transaction.
            samdb.transaction_start()
            try:
                # Lock out the account. We must do it using an actual password
                # change like so, rather than directly with a database
                # modification, so that the account is also added to the
                # auxiliary bad password database. Our goal is to get lockouts
                # to happen, i.e. password checking.

                old_utf16pw = '"Secret007"'.encode('utf-16le')  # invalid pwd
                new_utf16pw = '"Secret008"'.encode('utf-16le')

                msg = ldb.Message(user_dn)
                msg['0'] = ldb.MessageElement(old_utf16pw,
                                              ldb.FLAG_MOD_DELETE,
                                              'unicodePwd')
                msg['1'] = ldb.MessageElement(new_utf16pw,
                                              ldb.FLAG_MOD_ADD,
                                              'unicodePwd')

                for i in range(self.lockout_threshold):
                    try:
                        samdb.modify(msg)
                    except ldb.LdbError as err:
                        num, estr = err.args

                        # We get an error, but the bad password count should
                        # still be updated.
                        self.assertEqual(num, ldb.ERR_OPERATIONS_ERROR)
                        self.assertEqual('Failed to obtain remote address for '
                                         'the LDAP client while changing the '
                                         'password',
                                         estr)
                    else:
                        self.fail('pwd change should have failed')

                # Ensure the account is locked out.

                res = samdb.search(
                    user_dn, scope=ldb.SCOPE_BASE,
                    attrs=['msDS-User-Account-Control-Computed'])
                self.assertEqual(1, len(res))

                uac = int(res[0].get('msDS-User-Account-Control-Computed',
                                     idx=0))
                self.assertTrue(uac & dsdb.UF_LOCKOUT)

                # Now the bad password database has been updated, inform the
                # test process that it may proceed.
                our_pipe.send_bytes(b'0')

                # Wait one second to ensure the test process hits the
                # transaction lock.
                time.sleep(1)

                if rename:
                    # While we're at it, rename the account to ensure that is
                    # also safe if a race occurs.
                    msg = ldb.Message(user_dn)
                    new_username = self.get_new_username()
                    msg['sAMAccountName'] = ldb.MessageElement(
                        new_username,
                        ldb.FLAG_MOD_REPLACE,
                        'sAMAccountName')
                    samdb.modify(msg)

            except Exception:
                samdb.transaction_cancel()
                raise

            # Commit the local transaction.
            samdb.transaction_commit()

            result = connect_future.result(timeout=5)
            self.assertEqual(result, ConnectionResult.LOCKED_OUT)

    # Update the bad password count while holding a transaction lock, then
    # release the lock. A logon attempt already in progress should reread the
    # account details and ensure the bad password count is atomically
    # updated. The account can additionally be renamed within the transaction
    # to ensure that, by using the GUID, rereading the account's details still
    # succeeds.
    def do_bad_pwd_count_transaction(self, connect_fn, rename=False):
        # Create the user account for testing.
        user_creds = self.get_cached_creds(account_type=self.AccountType.USER,
                                           use_cache=False)

        admin_creds = self.get_admin_creds()
        lp = self.get_lp()

        # Get a connection to our local SamDB.
        samdb = connect_samdb(samdb_url=lp.samdb_url(), lp=lp,
                              credentials=admin_creds)
        self.assertLocalSamDB(samdb)
        user_dn = ldb.Dn(samdb, str(user_creds.get_dn()))

        # Prepare to connect to the server with an invalid password.
        mp_context = multiprocessing.get_context('fork')
        with futures.ProcessPoolExecutor(max_workers=1,
                                         mp_context=mp_context) as executor:
            our_pipe, their_pipe = Pipe(duplex=True)
            connect_future = executor.submit(
                connect_fn,
                pipe=their_pipe,
                url=f'ldap://{samdb.host_dns_name()}',
                hostname=samdb.host_dns_name(),
                username=user_creds.get_username(),
                password=user_creds.get_password()[:-1],  # invalid password
                domain=user_creds.get_domain(),
                realm=user_creds.get_realm(),
                workstation=user_creds.get_workstation(),
                dn=str(user_dn))

            # Wait until the test process indicates it's ready.
            self.wait_for_ready(our_pipe, connect_future)

            # Take out a transaction.
            samdb.transaction_start()
            try:
                # Inform the test process that it may proceed.
                our_pipe.send_bytes(b'0')

                # Wait one second to ensure the test process hits the
                # transaction lock.
                time.sleep(1)

                # Set badPwdCount to 1.
                msg = ldb.Message(user_dn)
                now = int(time.time())
                bad_pwd_time = unix2nttime(now)
                msg['badPwdCount'] = ldb.MessageElement(
                    '1',
                    ldb.FLAG_MOD_REPLACE,
                    'badPwdCount')
                msg['badPasswordTime'] = ldb.MessageElement(
                    str(bad_pwd_time),
                    ldb.FLAG_MOD_REPLACE,
                    'badPasswordTime')
                if rename:
                    # While we're at it, rename the account to ensure that is
                    # also safe if a race occurs.
                    new_username = self.get_new_username()
                    msg['sAMAccountName'] = ldb.MessageElement(
                        new_username,
                        ldb.FLAG_MOD_REPLACE,
                        'sAMAccountName')
                samdb.modify(msg)

                # Ensure the account is not yet locked out.

                res = samdb.search(
                    user_dn, scope=ldb.SCOPE_BASE,
                    attrs=['msDS-User-Account-Control-Computed'])
                self.assertEqual(1, len(res))

                uac = int(res[0].get('msDS-User-Account-Control-Computed',
                                     idx=0))
                self.assertFalse(uac & dsdb.UF_LOCKOUT)
            except Exception:
                samdb.transaction_cancel()
                raise

            # Commit the local transaction.
            samdb.transaction_commit()

            result = connect_future.result(timeout=5)
            self.assertEqual(result, ConnectionResult.WRONG_PASSWORD, result)

        # Check that badPwdCount has now increased to 2.

        res = samdb.search(user_dn,
                           scope=ldb.SCOPE_BASE,
                           attrs=['badPwdCount'])
        self.assertEqual(1, len(res))

        bad_pwd_count = int(res[0].get('badPwdCount', idx=0))
        self.assertEqual(2, bad_pwd_count)

    # Attempt to log in to the account with an incorrect password, using
    # lockoutThreshold+1 simultaneous attempts. We should get three 'wrong
    # password' errors and one 'locked out' error, showing that the bad
    # password count is checked and incremented atomically.
    def do_lockout_race(self, connect_fn):
        # Create the user account for testing.
        user_creds = self.get_cached_creds(account_type=self.AccountType.USER,
                                           use_cache=False)

        admin_creds = self.get_admin_creds()
        lp = self.get_lp()

        # Get a connection to our local SamDB.
        samdb = connect_samdb(samdb_url=lp.samdb_url(), lp=lp,
                              credentials=admin_creds)
        self.assertLocalSamDB(samdb)
        user_dn = ldb.Dn(samdb, str(user_creds.get_dn()))

        # Prepare to connect to the server with an invalid password, using four
        # simultaneous requests. Only three of those attempts should get
        # through before the account is locked out.
        num_attempts = self.lockout_threshold + 1
        mp_context = multiprocessing.get_context('fork')
        with futures.ProcessPoolExecutor(max_workers=num_attempts,
                                         mp_context=mp_context) as executor:
            connect_futures = []
            our_pipes = []
            for i in range(num_attempts):
                our_pipe, their_pipe = Pipe(duplex=True)
                our_pipes.append(our_pipe)

                connect_future = executor.submit(
                    connect_fn,
                    pipe=their_pipe,
                    url=f'ldap://{samdb.host_dns_name()}',
                    hostname=samdb.host_dns_name(),
                    username=user_creds.get_username(),
                    password=user_creds.get_password()[:-1],  # invalid pw
                    domain=user_creds.get_domain(),
                    realm=user_creds.get_realm(),
                    workstation=user_creds.get_workstation(),
                    dn=str(user_dn))
                connect_futures.append(connect_future)

                # Wait until the test process indicates it's ready.
                self.wait_for_ready(our_pipe, connect_future)

            # Take out a transaction.
            samdb.transaction_start()
            try:
                # Inform the test processes that they may proceed.
                for our_pipe in our_pipes:
                    our_pipe.send_bytes(b'0')

                # Wait one second to ensure the test processes hit the
                # transaction lock.
                time.sleep(1)
            except Exception:
                samdb.transaction_cancel()
                raise

            # Commit the local transaction.
            samdb.transaction_commit()

            lockouts = 0
            wrong_passwords = 0
            for i, connect_future in enumerate(connect_futures):
                result = connect_future.result(timeout=5)
                if result == ConnectionResult.LOCKED_OUT:
                    lockouts += 1
                elif result == ConnectionResult.WRONG_PASSWORD:
                    wrong_passwords += 1
                else:
                    self.fail(f'process {i} gave an unexpected result '
                              f'{result}')

            self.assertEqual(wrong_passwords, self.lockout_threshold)
            self.assertEqual(lockouts, num_attempts - self.lockout_threshold)

        # Ensure the account is now locked out.

        res = samdb.search(
            user_dn, scope=ldb.SCOPE_BASE,
            attrs=['badPwdCount',
                   'msDS-User-Account-Control-Computed'])
        self.assertEqual(1, len(res))

        bad_pwd_count = int(res[0].get('badPwdCount', idx=0))
        self.assertEqual(self.lockout_threshold, bad_pwd_count)

        uac = int(res[0].get('msDS-User-Account-Control-Computed',
                             idx=0))
        self.assertTrue(uac & dsdb.UF_LOCKOUT)

    # Test that logon is possible even while we locally hold a transaction
    # lock. This test only works with NTLM authentication; Kerberos
    # authentication must take out a transaction to update the logonCount
    # attribute, and LDAP and SAMR password changes both take out a transaction
    # to effect the password change. NTLM is the only logon method that does
    # not require a transaction, and can thus be performed while we're holding
    # the lock.
    def do_logon_without_transaction(self, connect_fn):
        # Create the user account for testing.
        user_creds = self.get_cached_creds(account_type=self.AccountType.USER,
                                           use_cache=False)

        admin_creds = self.get_admin_creds()
        lp = self.get_lp()

        # Get a connection to our local SamDB.
        samdb = connect_samdb(samdb_url=lp.samdb_url(), lp=lp,
                              credentials=admin_creds)
        self.assertLocalSamDB(samdb)
        user_dn = ldb.Dn(samdb, str(user_creds.get_dn()))
        password = user_creds.get_password()

        # Prepare to connect to the server with a valid password.
        mp_context = multiprocessing.get_context('fork')
        with futures.ProcessPoolExecutor(max_workers=1,
                                         mp_context=mp_context) as executor:
            our_pipe, their_pipe = Pipe(duplex=True)
            connect_future = executor.submit(
                connect_fn,
                pipe=their_pipe,
                url=f'ldap://{samdb.host_dns_name()}',
                hostname=samdb.host_dns_name(),
                username=user_creds.get_username(),
                password=password,
                domain=user_creds.get_domain(),
                realm=user_creds.get_realm(),
                workstation=user_creds.get_workstation(),
                dn=str(user_dn))

            # Wait until the test process indicates it's ready.
            self.wait_for_ready(our_pipe, connect_future)

            # Take out a transaction.
            samdb.transaction_start()
            try:
                # Inform the test process that it may proceed.
                our_pipe.send_bytes(b'0')

                # The connection should succeed, despite our holding a
                # transaction.
                result = connect_future.result(timeout=5)
                self.assertEqual(result, ConnectionResult.SUCCESS)
            except Exception:
                samdb.transaction_cancel()
                raise

            # Commit the local transaction.
            samdb.transaction_commit()


if __name__ == '__main__':
    global_asn1_print = False
    global_hexdump = False
    import unittest
    unittest.main()
