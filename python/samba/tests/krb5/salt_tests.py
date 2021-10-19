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

import ldb

from samba.tests.krb5.as_req_tests import AsReqKerberosTests
import samba.tests.krb5.kcrypto as kcrypto

sys.path.insert(0, "bin/python")
os.environ["PYTHONUNBUFFERED"] = "1"

global_asn1_print = False
global_hexdump = False


class SaltTests(AsReqKerberosTests):

    def setUp(self):
        super().setUp()
        self.do_asn1_print = global_asn1_print
        self.do_hexdump = global_hexdump

    def _get_creds(self, *,
                   account_type,
                   opts=None):
        try:
            return self.get_cached_creds(
                account_type=account_type,
                opts=opts)
        except ldb.LdbError:
            self.fail()

    def _run_salt_test(self, client_creds):
        expected_salt = self.get_salt(client_creds)
        self.assertIsNotNone(expected_salt)

        etype_info2 = self._run_as_req_enc_timestamp(client_creds)

        self.assertEqual(etype_info2[0]['etype'], kcrypto.Enctype.AES256)
        self.assertEqual(etype_info2[0]['salt'], expected_salt)

    def test_salt_at_user(self):
        client_creds = self._get_creds(
            account_type=self.AccountType.USER,
            opts={'name_suffix': 'foo@bar'})
        self._run_as_req_enc_timestamp(client_creds)

    def test_salt_at_mac(self):
        client_creds = self._get_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'name_suffix': 'foo@bar'})
        self._run_as_req_enc_timestamp(client_creds)

    def test_salt_at_case_user(self):
        client_creds = self._get_creds(
            account_type=self.AccountType.USER,
            opts={'name_suffix': 'Foo@bar'})
        self._run_as_req_enc_timestamp(client_creds)

    def test_salt_at_case_mac(self):
        client_creds = self._get_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'name_suffix': 'Foo@bar'})
        self._run_as_req_enc_timestamp(client_creds)

    def test_salt_double_at_user(self):
        client_creds = self._get_creds(
            account_type=self.AccountType.USER,
            opts={'name_suffix': 'foo@@bar'})
        self._run_as_req_enc_timestamp(client_creds)

    def test_salt_double_at_mac(self):
        client_creds = self._get_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'name_suffix': 'foo@@bar'})
        self._run_as_req_enc_timestamp(client_creds)

    def test_salt_at_start_user(self):
        client_creds = self._get_creds(
            account_type=self.AccountType.USER,
            opts={'name_prefix': '@foo'})
        self._run_as_req_enc_timestamp(client_creds)

    def test_salt_at_start_mac(self):
        client_creds = self._get_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'name_prefix': '@foo'})
        self._run_as_req_enc_timestamp(client_creds)

    def test_salt_at_end_user(self):
        client_creds = self._get_creds(
            account_type=self.AccountType.USER,
            opts={'name_suffix': 'foo@'})
        self._run_as_req_enc_timestamp(client_creds)

    def test_salt_at_end_mac(self):
        client_creds = self._get_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'name_suffix': 'foo@'})
        self._run_as_req_enc_timestamp(client_creds)

    def test_salt_at_end_no_dollar_mac(self):
        client_creds = self._get_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'name_suffix': 'foo@',
                  'add_dollar': False})
        self._run_as_req_enc_timestamp(client_creds)

    def test_salt_no_dollar_mac(self):
        client_creds = self._get_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'add_dollar': False})
        self._run_as_req_enc_timestamp(client_creds)

    def test_salt_dollar_mid_mac(self):
        client_creds = self._get_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'name_suffix': 'foo$bar',
                  'add_dollar': False})
        self._run_as_req_enc_timestamp(client_creds)

    def test_salt_dollar_user(self):
        client_creds = self._get_creds(
            account_type=self.AccountType.USER,
            opts={'name_suffix': 'foo$bar'})
        self._run_as_req_enc_timestamp(client_creds)

    def test_salt_dollar_mac(self):
        client_creds = self._get_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'name_suffix': 'foo$bar'})
        self._run_as_req_enc_timestamp(client_creds)

    def test_salt_dollar_end_user(self):
        client_creds = self._get_creds(
            account_type=self.AccountType.USER,
            opts={'name_suffix': 'foo$'})
        self._run_as_req_enc_timestamp(client_creds)

    def test_salt_dollar_end_mac(self):
        client_creds = self._get_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'name_suffix': 'foo$'})
        self._run_as_req_enc_timestamp(client_creds)

    def test_salt_upn_user(self):
        client_creds = self._get_creds(
            account_type=self.AccountType.USER,
            opts={'upn': 'foo0'})
        self._run_as_req_enc_timestamp(client_creds)

    def test_salt_upn_mac(self):
        client_creds = self._get_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'upn': 'foo1'})
        self._run_as_req_enc_timestamp(client_creds)

    def test_salt_upn_host_user(self):
        client_creds = self._get_creds(
            account_type=self.AccountType.USER,
            opts={'upn': 'host/foo2'})
        self._run_as_req_enc_timestamp(client_creds)

    def test_salt_upn_host_mac(self):
        client_creds = self._get_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'upn': 'host/foo3'})
        self._run_as_req_enc_timestamp(client_creds)

    def test_salt_upn_realm_user(self):
        realm = self.get_samdb().domain_dns_name()
        client_creds = self._get_creds(
            account_type=self.AccountType.USER,
            opts={'upn': 'foo4@' + realm})
        self._run_as_req_enc_timestamp(client_creds)

    def test_salt_upn_realm_mac(self):
        realm = self.get_samdb().domain_dns_name()
        client_creds = self._get_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'upn': 'foo5@' + realm})
        self._run_as_req_enc_timestamp(client_creds)

    def test_salt_upn_host_realm_user(self):
        realm = self.get_samdb().domain_dns_name()
        client_creds = self._get_creds(
            account_type=self.AccountType.USER,
            opts={'upn': 'host/foo6@' + realm})
        self._run_as_req_enc_timestamp(client_creds)

    def test_salt_upn_host_realm_mac(self):
        realm = self.get_samdb().domain_dns_name()
        client_creds = self._get_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'upn': 'host/foo7@' + realm})
        self._run_as_req_enc_timestamp(client_creds)

    def test_salt_upn_dollar_realm_user(self):
        realm = self.get_samdb().domain_dns_name()
        client_creds = self._get_creds(
            account_type=self.AccountType.USER,
            opts={'upn': 'foo8$@' + realm})
        self._run_as_req_enc_timestamp(client_creds)

    def test_salt_upn_dollar_realm_mac(self):
        realm = self.get_samdb().domain_dns_name()
        client_creds = self._get_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'upn': 'foo9$@' + realm})
        self._run_as_req_enc_timestamp(client_creds)

    def test_salt_upn_host_dollar_realm_user(self):
        realm = self.get_samdb().domain_dns_name()
        client_creds = self._get_creds(
            account_type=self.AccountType.USER,
            opts={'upn': 'host/foo10$@' + realm})
        self._run_as_req_enc_timestamp(client_creds)

    def test_salt_upn_host_dollar_realm_mac(self):
        realm = self.get_samdb().domain_dns_name()
        client_creds = self._get_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'upn': 'host/foo11$@' + realm})
        self._run_as_req_enc_timestamp(client_creds)

    def test_salt_upn_other_realm_user(self):
        client_creds = self._get_creds(
            account_type=self.AccountType.USER,
            opts={'upn': 'foo12@other.realm'})
        self._run_as_req_enc_timestamp(client_creds)

    def test_salt_upn_other_realm_mac(self):
        client_creds = self._get_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'upn': 'foo13@other.realm'})
        self._run_as_req_enc_timestamp(client_creds)

    def test_salt_upn_host_other_realm_user(self):
        client_creds = self._get_creds(
            account_type=self.AccountType.USER,
            opts={'upn': 'host/foo14@other.realm'})
        self._run_as_req_enc_timestamp(client_creds)

    def test_salt_upn_host_other_realm_mac(self):
        client_creds = self._get_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'upn': 'host/foo15@other.realm'})
        self._run_as_req_enc_timestamp(client_creds)

    def test_salt_upn_case_user(self):
        client_creds = self._get_creds(
            account_type=self.AccountType.USER,
            opts={'upn': 'Foo16'})
        self._run_as_req_enc_timestamp(client_creds)

    def test_salt_upn_case_mac(self):
        client_creds = self._get_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'upn': 'Foo17'})
        self._run_as_req_enc_timestamp(client_creds)

    def test_salt_upn_dollar_mid_realm_user(self):
        realm = self.get_samdb().domain_dns_name()
        client_creds = self._get_creds(
            account_type=self.AccountType.USER,
            opts={'upn': 'foo$18@' + realm})
        self._run_as_req_enc_timestamp(client_creds)

    def test_salt_upn_dollar_mid_realm_mac(self):
        realm = self.get_samdb().domain_dns_name()
        client_creds = self._get_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'upn': 'foo$19@' + realm})
        self._run_as_req_enc_timestamp(client_creds)

    def test_salt_upn_host_dollar_mid_realm_user(self):
        realm = self.get_samdb().domain_dns_name()
        client_creds = self._get_creds(
            account_type=self.AccountType.USER,
            opts={'upn': 'host/foo$20@' + realm})
        self._run_as_req_enc_timestamp(client_creds)

    def test_salt_upn_host_dollar_mid_realm_mac(self):
        realm = self.get_samdb().domain_dns_name()
        client_creds = self._get_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'upn': 'host/foo$21@' + realm})
        self._run_as_req_enc_timestamp(client_creds)

    def test_salt_upn_at_realm_user(self):
        realm = self.get_samdb().domain_dns_name()
        client_creds = self._get_creds(
            account_type=self.AccountType.USER,
            opts={'upn': 'foo22@bar@' + realm})
        self._run_as_req_enc_timestamp(client_creds)

    def test_salt_upn_at_realm_mac(self):
        realm = self.get_samdb().domain_dns_name()
        client_creds = self._get_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'upn': 'foo23@bar@' + realm})
        self._run_as_req_enc_timestamp(client_creds)


if __name__ == "__main__":
    global_asn1_print = False
    global_hexdump = False
    import unittest
    unittest.main()
