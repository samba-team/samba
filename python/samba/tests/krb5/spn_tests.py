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

import os
import sys

from samba.tests import DynamicTestCase

import ldb

from samba.tests.krb5.kdc_base_test import KDCBaseTest
from samba.tests.krb5.raw_testcase import KerberosCredentials
from samba.tests.krb5.rfc4120_constants import (
    AES256_CTS_HMAC_SHA1_96,
    ARCFOUR_HMAC_MD5,
    KDC_ERR_S_PRINCIPAL_UNKNOWN,
    NT_PRINCIPAL,
)

sys.path.insert(0, "bin/python")
os.environ["PYTHONUNBUFFERED"] = "1"

global_asn1_print = False
global_hexdump = False


@DynamicTestCase
class SpnTests(KDCBaseTest):
    test_account_types = {
        'computer': KDCBaseTest.AccountType.COMPUTER,
        'server': KDCBaseTest.AccountType.SERVER,
        'rodc': KDCBaseTest.AccountType.RODC
    }
    test_spns = {
        '2_part': 'ldap/{{account}}',
        '3_part_our_domain': 'ldap/{{account}}/{netbios_domain_name}',
        '3_part_our_realm': 'ldap/{{account}}/{dns_domain_name}',
        '3_part_not_our_realm': 'ldap/{{account}}/test',
        '3_part_instance': 'ldap/{{account}}:test/{dns_domain_name}'
    }

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        cls._mock_rodc_creds = None

    @classmethod
    def setUpDynamicTestCases(cls):
        for account_type_name, account_type in cls.test_account_types.items():
            for spn_name, spn in cls.test_spns.items():
                tname = f'{spn_name}_spn_{account_type_name}'
                targs = (account_type, spn)
                cls.generate_dynamic_test('test_spn', tname, *targs)

    def _test_spn_with_args(self, account_type, spn):
        target_creds = self._get_creds(account_type)
        spn = self._format_spn(spn, target_creds)

        sname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                          names=spn.split('/'))

        client_creds = self.get_client_creds()
        tgt = self.get_tgt(client_creds)

        samdb = self.get_samdb()
        netbios_domain_name = samdb.domain_netbios_name()
        dns_domain_name = samdb.domain_dns_name()

        subkey = self.RandomKey(tgt.session_key.etype)

        etypes = (AES256_CTS_HMAC_SHA1_96, ARCFOUR_HMAC_MD5,)

        if account_type is self.AccountType.SERVER:
            ticket_etype = AES256_CTS_HMAC_SHA1_96
        else:
            ticket_etype = None
        decryption_key = self.TicketDecryptionKey_from_creds(
            target_creds, etype=ticket_etype)

        if (spn.count('/') > 1
                and (spn.endswith(netbios_domain_name)
                     or spn.endswith(dns_domain_name))
                and account_type is not self.AccountType.SERVER
                and account_type is not self.AccountType.RODC):
            expected_error_mode = KDC_ERR_S_PRINCIPAL_UNKNOWN
            check_error_fn = self.generic_check_kdc_error
            check_rep_fn = None
        else:
            expected_error_mode = 0
            check_error_fn = None
            check_rep_fn = self.generic_check_kdc_rep

        kdc_exchange_dict = self.tgs_exchange_dict(
            expected_crealm=tgt.crealm,
            expected_cname=tgt.cname,
            expected_srealm=tgt.srealm,
            expected_sname=sname,
            ticket_decryption_key=decryption_key,
            check_rep_fn=check_rep_fn,
            check_error_fn=check_error_fn,
            check_kdc_private_fn=self.generic_check_kdc_private,
            expected_error_mode=expected_error_mode,
            tgt=tgt,
            authenticator_subkey=subkey,
            kdc_options='0',
            expect_edata=False)

        self._generic_kdc_exchange(kdc_exchange_dict,
                                   cname=None,
                                   realm=tgt.srealm,
                                   sname=sname,
                                   etypes=etypes)

    def setUp(self):
        super().setUp()
        self.do_asn1_print = global_asn1_print
        self.do_hexdump = global_hexdump

    def _format_spns(self, spns, creds=None):
        return map(lambda spn: self._format_spn(spn, creds), spns)

    def _format_spn(self, spn, creds=None):
        samdb = self.get_samdb()

        spn = spn.format(netbios_domain_name=samdb.domain_netbios_name(),
                         dns_domain_name=samdb.domain_dns_name())

        if creds is not None:
            account_name = creds.get_username()
            spn = spn.format(account=account_name)

        return spn

    def _get_creds(self, account_type):
        spns = self._format_spns(self.test_spns.values())

        if account_type is self.AccountType.RODC:
            creds = self._mock_rodc_creds
            if creds is None:
                creds = self._get_mock_rodc_creds(spns)
                type(self)._mock_rodc_creds = creds
        else:
            creds = self.get_cached_creds(
                account_type=account_type,
                opts={
                    'spn': spns
                })

        return creds

    def _get_mock_rodc_creds(self, spns):
        rodc_ctx = self.get_mock_rodc_ctx()

        for spn in spns:
            spn = spn.format(account=rodc_ctx.myname)
            if spn not in rodc_ctx.SPNs:
                rodc_ctx.SPNs.append(spn)

        samdb = self.get_samdb()
        rodc_dn = ldb.Dn(samdb, rodc_ctx.acct_dn)

        msg = ldb.Message(rodc_dn)
        msg['servicePrincipalName'] = ldb.MessageElement(
            rodc_ctx.SPNs,
            ldb.FLAG_MOD_REPLACE,
            'servicePrincipalName')
        samdb.modify(msg)

        creds = KerberosCredentials()
        creds.guess(self.get_lp())
        creds.set_realm(rodc_ctx.realm.upper())
        creds.set_domain(rodc_ctx.domain_name)
        creds.set_password(rodc_ctx.acct_pass)
        creds.set_username(rodc_ctx.myname)
        creds.set_workstation(rodc_ctx.samname)
        creds.set_dn(rodc_dn)
        creds.set_spn(rodc_ctx.SPNs)

        res = samdb.search(base=rodc_dn,
                           scope=ldb.SCOPE_BASE,
                           attrs=['msDS-KeyVersionNumber'])
        kvno = int(res[0].get('msDS-KeyVersionNumber', idx=0))
        creds.set_kvno(kvno)

        keys = self.get_keys(samdb, rodc_dn)
        self.creds_set_keys(creds, keys)

        return creds


if __name__ == "__main__":
    global_asn1_print = False
    global_hexdump = False
    import unittest
    unittest.main()
