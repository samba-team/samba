#!/usr/bin/env python3
# Unix SMB/CIFS implementation.
# Copyright (C) Stefan Metzmacher 2020
# Copyright (C) 2021 Catalyst.Net Ltd
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

from samba.tests import delete_force
import samba.tests.krb5.kcrypto as kcrypto
from samba.tests.krb5.kdc_base_test import KDCBaseTest
from samba.tests.krb5.rfc4120_constants import (
    AES256_CTS_HMAC_SHA1_96,
    ARCFOUR_HMAC_MD5,
    KDC_ERR_CLIENT_NAME_MISMATCH,
    NT_PRINCIPAL,
)

sys.path.insert(0, 'bin/python')
os.environ['PYTHONUNBUFFERED'] = '1'

global_asn1_print = False
global_hexdump = False


class AliasTests(KDCBaseTest):
    def test_dc_alias_rename(self):
        self._run_dc_alias(action='rename')

    def test_dc_alias_delete(self):
        self._run_dc_alias(action='delete')

    def _run_dc_alias(self, action=None):
        target_creds = self.get_dc_creds()
        target_name = target_creds.get_username()[:-1]

        self._run_alias(target_name, lambda: target_creds, action=action)

    def test_create_alias_rename(self):
        self._run_create_alias(action='rename')

    def test_create_alias_delete(self):
        self._run_create_alias(action='delete')

    def _run_create_alias(self, action=None):
        target_name = self.get_new_username()

        def create_target():
            samdb = self.get_samdb()

            realm = samdb.domain_dns_name().lower()

            hostname = f'{target_name}.{realm}'
            spn = f'ldap/{hostname}'

            details = {
                'dNSHostName': hostname
            }

            creds, fn = self.create_account(
                samdb,
                target_name,
                account_type=self.AccountType.COMPUTER,
                spn=spn,
                additional_details=details)

            return creds

        self._run_alias(target_name, create_target, action=action)

    def _run_alias(self, target_name, target_creds_fn, action=None):
        samdb = self.get_samdb()

        mach_name = self.get_new_username()

        # Create a machine account.
        mach_creds, mach_dn = self.create_account(
            samdb, mach_name, account_type=self.AccountType.COMPUTER)
        self.addCleanup(delete_force, samdb, mach_dn)

        mach_sid = self.get_objectSid(samdb, mach_dn)
        realm = mach_creds.get_realm()

        # The account salt doesn't change when the account is renamed.
        old_salt = mach_creds.get_salt()
        mach_creds.set_forced_salt(old_salt)

        # Rename the account to alias with the target account.
        msg = ldb.Message(ldb.Dn(samdb, mach_dn))
        msg['sAMAccountName'] = ldb.MessageElement(target_name,
                                                   ldb.FLAG_MOD_REPLACE,
                                                   'sAMAccountName')
        samdb.modify(msg)
        mach_creds.set_username(target_name)

        # Get a TGT for the machine account.
        tgt = self.get_tgt(mach_creds, kdc_options='0', fresh=True)

        # Check the PAC.
        pac_data = self.get_pac_data(tgt.ticket_private['authorization-data'])

        upn = f'{target_name}@{realm.lower()}'

        self.assertEqual(target_name, str(pac_data.account_name))
        self.assertEqual(mach_sid, pac_data.account_sid)
        self.assertEqual(target_name, pac_data.logon_name)
        self.assertEqual(upn, pac_data.upn)
        self.assertEqual(realm, pac_data.domain_name)

        # Rename or delete the machine account.
        if action == 'rename':
            mach_name2 = self.get_new_username()

            msg = ldb.Message(ldb.Dn(samdb, mach_dn))
            msg['sAMAccountName'] = ldb.MessageElement(mach_name2,
                                                       ldb.FLAG_MOD_REPLACE,
                                                       'sAMAccountName')
            samdb.modify(msg)
        elif action == 'delete':
            samdb.delete(mach_dn)
        else:
            self.fail(action)

        # Get the credentials for the target account.
        target_creds = target_creds_fn()

        # Look up the DNS host name of the target account.
        target_dn = target_creds.get_dn()
        res = samdb.search(target_dn,
                           scope=ldb.SCOPE_BASE,
                           attrs=['dNSHostName'])
        target_hostname = str(res[0].get('dNSHostName', idx=0))

        sname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                          names=['ldap', target_hostname])
        target_cname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                                 names=[target_name])

        target_decryption_key = self.TicketDecryptionKey_from_creds(
            target_creds)

        authenticator_subkey = self.RandomKey(kcrypto.Enctype.AES256)

        etypes = (AES256_CTS_HMAC_SHA1_96, ARCFOUR_HMAC_MD5)

        def generate_s4u2self_padata(_kdc_exchange_dict,
                                     _callback_dict,
                                     req_body):
            padata = self.PA_S4U2Self_create(name=target_cname,
                                             realm=realm,
                                             tgt_session_key=tgt.session_key,
                                             ctype=None)
            return [padata], req_body

        expected_error_mode = KDC_ERR_CLIENT_NAME_MISMATCH

        # Make a request using S4U2Self. The request should fail.
        kdc_exchange_dict = self.tgs_exchange_dict(
            expected_crealm=realm,
            expected_cname=target_cname,
            expected_srealm=realm,
            expected_sname=sname,
            ticket_decryption_key=target_decryption_key,
            generate_padata_fn=generate_s4u2self_padata,
            expected_error_mode=expected_error_mode,
            check_error_fn=self.generic_check_kdc_error,
            check_kdc_private_fn=self.generic_check_kdc_private,
            tgt=tgt,
            authenticator_subkey=authenticator_subkey,
            kdc_options='0',
            expect_pac=True)

        rep = self._generic_kdc_exchange(kdc_exchange_dict,
                                         cname=None,
                                         realm=realm,
                                         sname=sname,
                                         etypes=etypes)
        self.check_error_rep(rep, expected_error_mode)


if __name__ == '__main__':
    global_asn1_print = False
    global_hexdump = False
    import unittest
    unittest.main()
