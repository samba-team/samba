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

import ldb

from samba import generate_random_password, net
from samba.dcerpc import drsuapi, misc

from samba.tests.krb5.kdc_base_test import KDCBaseTest

global_asn1_print = False
global_hexdump = False


class NtHashTests(KDCBaseTest):

    def setUp(self):
        super().setUp()
        self.do_asn1_print = global_asn1_print
        self.do_hexdump = global_hexdump

    def _check_nt_hash(self, dn, history_len):
        expect_nt_hash = bool(int(os.environ.get('EXPECT_NT_HASH', '1')))

        samdb = self.get_samdb()
        admin_creds = self.get_admin_creds()

        bind, identifier, attributes = self.get_secrets(
            dn,
            destination_dsa_guid=misc.GUID(samdb.get_ntds_GUID()),
            source_dsa_invocation_id=misc.GUID())

        rid = identifier.sid.split()[1]

        net_ctx = net.Net(admin_creds)

        def num_hashes(attr):
            if attr.value_ctr.values is None:
                return 0

            net_ctx.replicate_decrypt(bind, attr, rid)

            length = sum(len(value.blob) for value in attr.value_ctr.values)
            self.assertEqual(0, length & 0xf)
            return length // 16

        def is_unicodePwd(attr):
            return attr.attid == drsuapi.DRSUAPI_ATTID_unicodePwd

        def is_ntPwdHistory(attr):
            return attr.attid == drsuapi.DRSUAPI_ATTID_ntPwdHistory

        unicode_pwd_count = sum(attr.value_ctr.num_values
                                for attr in filter(is_unicodePwd, attributes))

        nt_history_count = sum(num_hashes(attr)
                               for attr in filter(is_ntPwdHistory, attributes))

        if expect_nt_hash:
            self.assertEqual(1, unicode_pwd_count,
                             'expected to find NT hash')
        else:
            self.assertEqual(0, unicode_pwd_count,
                             'got unexpected NT hash')

        if expect_nt_hash:
            self.assertEqual(history_len, nt_history_count,
                             'expected to find NT password history')
        else:
            self.assertEqual(0, nt_history_count,
                             'got unexpected NT password history')

    # Test that the NT hash and its history is not generated or stored for an
    # account when we disable NTLM authentication.
    def test_nt_hash(self):
        samdb = self.get_samdb()
        user_name = self.get_new_username()

        client_creds, client_dn = self.create_account(
            samdb, user_name,
            account_type=KDCBaseTest.AccountType.USER)

        self._check_nt_hash(client_dn, history_len=1)

        # Change the password and check that the NT hash is still not present.

        # Get the old "minPwdAge"
        minPwdAge = samdb.get_minPwdAge()

        # Reset the "minPwdAge" as it was before
        self.addCleanup(samdb.set_minPwdAge, minPwdAge)

        # Set it temporarily to '0'
        samdb.set_minPwdAge('0')

        old_utf16pw = f'"{client_creds.get_password()}"'.encode('utf-16-le')

        history_len = 3
        for _ in range(history_len - 1):
            password = generate_random_password(32, 32)
            utf16pw = f'"{password}"'.encode('utf-16-le')

            msg = ldb.Message(ldb.Dn(samdb, client_dn))
            msg['0'] = ldb.MessageElement(old_utf16pw,
                                          ldb.FLAG_MOD_DELETE,
                                          'unicodePwd')
            msg['1'] = ldb.MessageElement(utf16pw,
                                          ldb.FLAG_MOD_ADD,
                                          'unicodePwd')
            samdb.modify(msg)

            old_utf16pw = utf16pw

        self._check_nt_hash(client_dn, history_len)


if __name__ == '__main__':
    global_asn1_print = False
    global_hexdump = False
    import unittest
    unittest.main()
