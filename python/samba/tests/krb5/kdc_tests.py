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

from samba.tests.krb5.raw_testcase import RawKerberosTest
import samba.tests.krb5.rfc4120_pyasn1 as krb5_asn1
from samba.tests.krb5.rfc4120_constants import (
    AES256_CTS_HMAC_SHA1_96,
    ARCFOUR_HMAC_MD5,
    KDC_ERR_PREAUTH_FAILED,
    KDC_ERR_PREAUTH_REQUIRED,
    KDC_ERR_SKEW,
    KRB_AS_REP,
    KRB_ERROR,
    KU_PA_ENC_TIMESTAMP,
    PADATA_ENC_TIMESTAMP,
    PADATA_ETYPE_INFO2,
    NT_PRINCIPAL,
    NT_SRV_INST,
)

global_asn1_print = False
global_hexdump = False


class KdcTests(RawKerberosTest):
    """ Port of the tests in source4/torture/krb5/kdc-heimdal.c
        To python.
    """

    def setUp(self):
        super(KdcTests, self).setUp()
        self.do_asn1_print = global_asn1_print
        self.do_hexdump = global_hexdump

    def as_req(self, creds, etypes, padata=None):
        user = creds.get_username()
        realm = creds.get_realm()

        cname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL,
            names=[user])
        sname = self.PrincipalName_create(
            name_type=NT_SRV_INST,
            names=["krbtgt", realm])
        till = self.get_KerberosTime(offset=36000)

        kdc_options = 0

        req = self.AS_REQ_create(padata=padata,
                                 kdc_options=str(kdc_options),
                                 cname=cname,
                                 realm=realm,
                                 sname=sname,
                                 from_time=None,
                                 till_time=till,
                                 renew_time=None,
                                 nonce=0x7fffffff,
                                 etypes=etypes,
                                 addresses=None,
                                 additional_tickets=None)
        rep = self.send_recv_transaction(req)
        return rep

    def get_enc_timestamp_pa_data(self, creds, rep, skew=0):
        rep_padata = self.der_decode(
            rep['e-data'],
            asn1Spec=krb5_asn1.METHOD_DATA())

        for pa in rep_padata:
            if pa['padata-type'] == PADATA_ETYPE_INFO2:
                etype_info2 = pa['padata-value']
                break

        etype_info2 = self.der_decode(
            etype_info2, asn1Spec=krb5_asn1.ETYPE_INFO2())

        key = self.PasswordKey_from_etype_info2(creds, etype_info2[0])

        (patime, pausec) = self.get_KerberosTimeWithUsec(offset=skew)
        pa_ts = self.PA_ENC_TS_ENC_create(patime, pausec)
        pa_ts = self.der_encode(pa_ts, asn1Spec=krb5_asn1.PA_ENC_TS_ENC())

        pa_ts = self.EncryptedData_create(key, KU_PA_ENC_TIMESTAMP, pa_ts)
        pa_ts = self.der_encode(pa_ts, asn1Spec=krb5_asn1.EncryptedData())

        pa_ts = self.PA_DATA_create(PADATA_ENC_TIMESTAMP, pa_ts)

        return pa_ts

    def check_pre_authenication(self, rep):
        """ Check that the kdc response was pre-authentication required
        """
        self.check_error_rep(rep, KDC_ERR_PREAUTH_REQUIRED)

    def check_as_reply(self, rep):
        """ Check that the kdc response is an AS-REP and that the
            values for:
                msg-type
                pvno
                tkt-pvno
                kvno
            match the expected values
        """

        # Should have a reply, and it should an AS-REP message.
        self.assertIsNotNone(rep)
        self.assertEqual(rep['msg-type'], KRB_AS_REP)

        # Protocol version number should be 5
        pvno = int(rep['pvno'])
        self.assertEqual(5, pvno)

        # The ticket version number should be 5
        tkt_vno = int(rep['ticket']['tkt-vno'])
        self.assertEqual(5, tkt_vno)

        # Check that the kvno is not an RODC kvno
        # MIT kerberos does not provide the kvno, so we treat it as optional.
        # This is tested in compatability_test.py
        if 'kvno' in rep['enc-part']:
            kvno = int(rep['enc-part']['kvno'])
            # If the high order bits are set this is an RODC kvno.
            self.assertEqual(0, kvno & 0xFFFF0000)

    def check_error_rep(self, rep, expected):
        """ Check that the reply is an error message, with the expected
            error-code specified.
        """
        self.assertIsNotNone(rep)
        self.assertEqual(rep['msg-type'], KRB_ERROR)
        self.assertEqual(rep['error-code'], expected)

    def test_aes256_cts_hmac_sha1_96(self):
        creds = self.get_user_creds()
        etype = (AES256_CTS_HMAC_SHA1_96,)

        rep = self.as_req(creds, etype)
        self.check_pre_authenication(rep)

        padata = self.get_enc_timestamp_pa_data(creds, rep)
        rep = self.as_req(creds, etype, padata=[padata])
        self.check_as_reply(rep)

        etype = rep['enc-part']['etype']
        self.assertEquals(AES256_CTS_HMAC_SHA1_96, etype)

    def test_arc4_hmac_md5(self):
        creds = self.get_user_creds()
        etype = (ARCFOUR_HMAC_MD5,)

        rep = self.as_req(creds, etype)
        self.check_pre_authenication(rep)

        padata = self.get_enc_timestamp_pa_data(creds, rep)
        rep = self.as_req(creds, etype, padata=[padata])
        self.check_as_reply(rep)

        etype = rep['enc-part']['etype']
        self.assertEquals(ARCFOUR_HMAC_MD5, etype)

    def test_aes_rc4(self):
        creds = self.get_user_creds()
        etype = (AES256_CTS_HMAC_SHA1_96, ARCFOUR_HMAC_MD5)

        rep = self.as_req(creds, etype)
        self.check_pre_authenication(rep)

        padata = self.get_enc_timestamp_pa_data(creds, rep)
        rep = self.as_req(creds, etype, padata=[padata])
        self.check_as_reply(rep)

        etype = rep['enc-part']['etype']
        self.assertEquals(AES256_CTS_HMAC_SHA1_96, etype)

    def test_clock_skew(self):
        creds = self.get_user_creds()
        etype = (AES256_CTS_HMAC_SHA1_96, ARCFOUR_HMAC_MD5)

        rep = self.as_req(creds, etype)
        self.check_pre_authenication(rep)

        padata = self.get_enc_timestamp_pa_data(creds, rep, skew=3600)
        rep = self.as_req(creds, etype, padata=[padata])

        self.check_error_rep(rep, KDC_ERR_SKEW)

    def test_invalid_password(self):
        creds = self.insta_creds(template=self.get_user_creds())
        creds.set_password("Not the correct password")

        etype = (AES256_CTS_HMAC_SHA1_96,)

        rep = self.as_req(creds, etype)
        self.check_pre_authenication(rep)

        padata = self.get_enc_timestamp_pa_data(creds, rep)
        rep = self.as_req(creds, etype, padata=[padata])

        self.check_error_rep(rep, KDC_ERR_PREAUTH_FAILED)


if __name__ == "__main__":
    global_asn1_print = False
    global_hexdump = False
    import unittest
    unittest.main()
