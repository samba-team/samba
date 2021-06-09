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

from samba.tests.krb5.kdc_base_test import KDCBaseTest
from samba.tests.krb5.rfc4120_constants import (
    AES256_CTS_HMAC_SHA1_96,
    ARCFOUR_HMAC_MD5,
    NT_PRINCIPAL,
    NT_SRV_INST,
    PADATA_FX_COOKIE,
    PADATA_FX_FAST,
)
import samba.tests.krb5.rfc4120_pyasn1 as krb5_asn1

global_asn1_print = False
global_hexdump = False


class FAST_Tests(KDCBaseTest):
    '''
    '''

    def setUp(self):
        super().setUp()
        self.do_asn1_print = global_asn1_print
        self.do_hexdump = global_hexdump

    def get_padata_element(self, rep, padata_type):
        rep_padata = self.der_decode(
            rep['e-data'], asn1Spec=krb5_asn1.METHOD_DATA())
        for pa in rep_padata:
            if pa['padata-type'] == padata_type:
                return pa['padata-value']
        return None

    def test_fast_supported(self):
        '''Confirm that the kdc supports FAST
           The KDC SHOULD return an empty PA-FX-FAST in a
               PREAUTH_REQUIRED error if FAST is supported


        '''

        # Create a user account for the test.
        #
        samdb = self.get_samdb()
        user_name = "krb5fastusr"
        (uc, dn) = self.create_account(samdb, user_name)
        realm = uc.get_realm().lower()

        # Do the initial AS-REQ, should get a pre-authentication required
        # response
        etype = (AES256_CTS_HMAC_SHA1_96, ARCFOUR_HMAC_MD5)
        cname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL, names=[user_name])
        sname = self.PrincipalName_create(
            name_type=NT_SRV_INST, names=["krbtgt", realm])

        rep = self.as_req(cname, sname, realm, etype)
        self.assertIsNotNone(rep)
        self.assertEqual(rep['msg-type'], 30)
        self.assertEqual(rep['error-code'], 25)

        fx_fast = self.get_padata_element(rep, PADATA_FX_FAST)
        self.assertIsNotNone(fx_fast, "No PADATA_FX_FAST element")

    def test_explicit_PA_FX_FAST_in_as_req(self):
        '''
           Add an empty PA-FX-FAST in the initial AS-REQ
           This should get rejected with a Generic error.

        '''

        # Create a user account for the test.
        #
        samdb = self.get_samdb()
        user_name = "krb5fastusr"
        (uc, dn) = self.create_account(samdb, user_name)
        realm = uc.get_realm().lower()

        # Do the initial AS-REQ, should get a generic error response
        # response
        etype = (AES256_CTS_HMAC_SHA1_96, ARCFOUR_HMAC_MD5)
        cname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL, names=[user_name])
        sname = self.PrincipalName_create(
            name_type=NT_SRV_INST, names=["krbtgt", realm])

        x = self.PA_DATA_create(PADATA_FX_FAST, b'')
        padata = [x]
        rep = self.as_req(cname, sname, realm, etype, padata)

        self.assertIsNotNone(rep)
        self.assertEqual(rep['msg-type'], 30)
        self.assertEqual(rep['error-code'], 60)

    def test_fast_cookie_retured_in_pre_auth(self):
        '''Confirm that the kdc returns PA-FX-COOKIE
        '''

        # Create a user account for the test.
        #
        samdb = self.get_samdb()
        user_name = "krb5fastusr"
        (uc, dn) = self.create_account(samdb, user_name)
        realm = uc.get_realm().lower()

        # Do the initial AS-REQ, should get a pre-authentication required
        # response
        etype = (AES256_CTS_HMAC_SHA1_96, ARCFOUR_HMAC_MD5)
        cname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL, names=[user_name])
        sname = self.PrincipalName_create(
            name_type=NT_SRV_INST, names=["krbtgt", realm])

        rep = self.as_req(cname, sname, realm, etype)
        self.assertIsNotNone(rep)
        self.assertEqual(rep['msg-type'], 30)
        self.assertEqual(rep['error-code'], 25)

        fx_fast = self.get_padata_element(rep, PADATA_FX_FAST)
        self.assertIsNotNone(fx_fast, "No PADATA_FX_FAST element")

        fx_cookie = self.get_padata_element(rep, PADATA_FX_COOKIE)
        self.assertIsNotNone(fx_cookie, "No PADATA_FX_COOKIE element")

    def test_ignore_fast(self):
        '''
            TODO reword this
            Attempt to authenticate with out FAST, i.e. ignoring the
            FAST advertised in the pre-auth
        '''

        # Create a user account for the test.
        #
        samdb = self.get_samdb()
        user_name = "krb5fastusr"
        (uc, dn) = self.create_account(samdb, user_name)
        realm = uc.get_realm().lower()

        # Do the initial AS-REQ, should get a pre-authentication required
        # response
        etype = (AES256_CTS_HMAC_SHA1_96, ARCFOUR_HMAC_MD5)
        cname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL, names=[user_name])
        sname = self.PrincipalName_create(
            name_type=NT_SRV_INST, names=["krbtgt", realm])

        rep = self.as_req(cname, sname, realm, etype)
        self.assertIsNotNone(rep)
        self.assertEqual(rep['msg-type'], 30)
        self.assertEqual(rep['error-code'], 25)

        fx_fast = self.get_padata_element(rep, PADATA_FX_FAST)
        self.assertIsNotNone(fx_fast, "No PADATA_FX_FAST element")

        fx_cookie = self.get_padata_element(rep, PADATA_FX_COOKIE)
        self.assertIsNotNone(fx_cookie, "No PADATA_FX_COOKIE element")

        # Do the next AS-REQ
        padata = [self.get_enc_timestamp_pa_data(uc, rep)]
        rep = self.as_req(cname, sname, realm, etype, padata=padata)
        self.check_as_reply(rep)

    def test_fast(self):
        '''
            Attempt to authenticate with
        '''

        # Create a user account for the test.
        #
        samdb = self.get_samdb()
        user_name = "krb5fastusr"
        (uc, dn) = self.create_account(samdb, user_name)
        realm = uc.get_realm().lower()

        # Do the initial AS-REQ, should get a pre-authentication required
        # response
        etype = (AES256_CTS_HMAC_SHA1_96, ARCFOUR_HMAC_MD5)
        cname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL, names=[user_name])
        sname = self.PrincipalName_create(
            name_type=NT_SRV_INST, names=["krbtgt", realm])

        rep = self.as_req(cname, sname, realm, etype)
        self.assertIsNotNone(rep)
        self.assertEqual(rep['msg-type'], 30)
        self.assertEqual(rep['error-code'], 25)

        fx_fast = self.get_padata_element(rep, PADATA_FX_FAST)
        self.assertIsNotNone(fx_fast, "No PADATA_FX_FAST element")

        fx_cookie = self.get_padata_element(rep, PADATA_FX_COOKIE)
        self.assertIsNotNone(fx_cookie, "No PADATA_FX_COOKIE element")

        cookie = self.PA_DATA_create(PADATA_FX_COOKIE, fx_cookie)

        # Do the next AS-REQ
        padata = [self.get_enc_timestamp_pa_data(uc, rep)]
        padata.append(cookie)
        # req = self.AS_REQ_create(padata=padata,
        #                         kdc_options=str(kdc_options),
        #                         cname=cname,
        #                         realm=realm,
        #                         sname=sname,
        #                         from_time=None,
        #                         till_time=till,
        #                         renew_time=None,
        #                         nonce=0x7fffffff,
        #                         etypes=etypes,
        #                         addresses=None,
        #                         EncAuthorizationData=None,
        #                         EncAuthorizationData_key=None,
        #                         additional_tickets=None)
        # rep = self.as_req(cname, sname, realm, etype, padata=padata)
        # self.check_as_reply(rep)


if __name__ == "__main__":
    global_asn1_print = False
    global_hexdump = False
    import unittest
    unittest.main()
