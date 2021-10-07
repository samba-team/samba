#!/usr/bin/env python3
# Unix SMB/CIFS implementation.
# Copyright (C) Stefan Metzmacher 2020
# Copyright (C) Catalyst.Net Ltd 2020
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
import samba.tests.krb5.rfc4120_pyasn1 as krb5_asn1
from samba.tests.krb5.rfc4120_constants import (
    AES128_CTS_HMAC_SHA1_96,
    AES256_CTS_HMAC_SHA1_96,
    ARCFOUR_HMAC_MD5,
    KDC_ERR_PREAUTH_REQUIRED,
    KRB_AS_REP,
    KRB_ERROR,
    KU_AS_REP_ENC_PART,
    KU_PA_ENC_TIMESTAMP,
    PADATA_ENC_TIMESTAMP,
    PADATA_ETYPE_INFO2,
    NT_PRINCIPAL,
    NT_SRV_INST,
)

global_asn1_print = False
global_hexdump = False

HIEMDAL_ENC_AS_REP_PART_TYPE_TAG = 0x79
# MIT uses the EncTGSRepPart tag for the EncASRepPart
MIT_ENC_AS_REP_PART_TYPE_TAG = 0x7A

ENC_PA_REP_FLAG = 0x00010000


class SimpleKerberosTests(KDCBaseTest):

    def setUp(self):
        super(SimpleKerberosTests, self).setUp()
        self.do_asn1_print = global_asn1_print
        self.do_hexdump = global_hexdump

    def test_mit_EncASRepPart_tag(self):
        creds = self.get_user_creds()
        (enc, _) = self.as_req(creds)
        self.assertEqual(MIT_ENC_AS_REP_PART_TYPE_TAG, enc[0])

    def test_heimdal_EncASRepPart_tag(self):
        creds = self.get_user_creds()
        (enc, _) = self.as_req(creds)
        self.assertEqual(HIEMDAL_ENC_AS_REP_PART_TYPE_TAG, enc[0])

    def test_mit_EncryptedData_kvno(self):
        creds = self.get_user_creds()
        (_, enc) = self.as_req(creds)
        if 'kvno' in enc:
            self.fail("kvno present in EncryptedData")

    def test_heimdal_EncryptedData_kvno(self):
        creds = self.get_user_creds()
        (_, enc) = self.as_req(creds)
        if 'kvno' not in enc:
            self.fail("kvno absent in EncryptedData")

    def test_mit_EncASRepPart_FAST_support(self):
        creds = self.get_user_creds()
        (enc, _) = self.as_req(creds)
        self.assertEqual(MIT_ENC_AS_REP_PART_TYPE_TAG, enc[0])
        as_rep = self.der_decode(enc, asn1Spec=krb5_asn1.EncTGSRepPart())
        flags = int(as_rep['flags'], base=2)
        # MIT sets enc-pa-rep, flag bit 15
        # RFC 6806 11. Negotiation of FAST and Detecting Modified Requests
        self.assertTrue(ENC_PA_REP_FLAG & flags)

    def test_heimdal_EncASRepPart_FAST_support(self):
        creds = self.get_user_creds()
        (enc, _) = self.as_req(creds)
        self.assertEqual(HIEMDAL_ENC_AS_REP_PART_TYPE_TAG, enc[0])
        as_rep = self.der_decode(enc, asn1Spec=krb5_asn1.EncASRepPart())
        flags = as_rep['flags']
        flags = int(as_rep['flags'], base=2)
        # Heimdal does not set enc-pa-rep, flag bit 15
        # RFC 6806 11. Negotiation of FAST and Detecting Modified Requests
        self.assertFalse(ENC_PA_REP_FLAG & flags)

    def test_mit_arcfour_salt(self):
        creds = self.get_user_creds()
        etypes = (ARCFOUR_HMAC_MD5,)
        (rep, *_) = self.as_pre_auth_req(creds, etypes)
        self.check_preauth_rep(rep)
        etype_info2 = self.get_etype_info2(rep)
        if 'salt' not in etype_info2[0]:
            self.fail(
                "(MIT) Salt not populated for ARCFOUR_HMAC_MD5 encryption")

    def test_heimdal_arcfour_salt(self):
        creds = self.get_user_creds()
        etypes = (ARCFOUR_HMAC_MD5,)
        (rep, *_) = self.as_pre_auth_req(creds, etypes)
        self.check_preauth_rep(rep)
        etype_info2 = self.get_etype_info2(rep)
        if 'salt' in etype_info2[0]:
            self.fail(
                "(Heimdal) Salt populated for ARCFOUR_HMAC_MD5 encryption")

    def test_heimdal_ticket_signature(self):
        # Ensure that a DC correctly issues tickets signed with its krbtgt key.
        user_creds = self.get_client_creds()
        target_creds = self.get_service_creds()

        krbtgt_creds = self.get_krbtgt_creds()
        key = self.TicketDecryptionKey_from_creds(krbtgt_creds)

        # Get a TGT from the DC.
        tgt = self.get_tgt(user_creds)

        # Ensure the PAC contains the expected checksums.
        self.verify_ticket(tgt, key)

        # Get a service ticket from the DC.
        service_ticket = self.get_service_ticket(tgt, target_creds)

        # Ensure the PAC contains the expected checksums.
        self.verify_ticket(service_ticket, key, expect_ticket_checksum=True)

    def test_mit_ticket_signature(self):
        # Ensure that a DC does not issue tickets signed with its krbtgt key.
        user_creds = self.get_client_creds()
        target_creds = self.get_service_creds()

        krbtgt_creds = self.get_krbtgt_creds()
        key = self.TicketDecryptionKey_from_creds(krbtgt_creds)

        # Get a TGT from the DC.
        tgt = self.get_tgt(user_creds)

        # Ensure the PAC contains the expected checksums.
        self.verify_ticket(tgt, key)

        # Get a service ticket from the DC.
        service_ticket = self.get_service_ticket(tgt, target_creds)

        # Ensure the PAC does not contain the expected checksums.
        self.verify_ticket(service_ticket, key, expect_ticket_checksum=False)

    def as_pre_auth_req(self, creds, etypes):
        user = creds.get_username()
        realm = creds.get_realm()

        cname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL,
            names=[user])
        sname = self.PrincipalName_create(
            name_type=NT_SRV_INST,
            names=["krbtgt", realm])

        till = self.get_KerberosTime(offset=36000)

        kdc_options = krb5_asn1.KDCOptions('forwardable')
        padata = None

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

        return (rep, cname, sname, realm, till)

    def check_preauth_rep(self, rep):
        self.assertIsNotNone(rep)
        self.assertEqual(rep['msg-type'], KRB_ERROR)
        self.assertEqual(rep['error-code'], KDC_ERR_PREAUTH_REQUIRED)

    def get_etype_info2(self, rep):

        rep_padata = self.der_decode(
            rep['e-data'],
            asn1Spec=krb5_asn1.METHOD_DATA())

        for pa in rep_padata:
            if pa['padata-type'] == PADATA_ETYPE_INFO2:
                etype_info2 = pa['padata-value']
                break

        etype_info2 = self.der_decode(
            etype_info2,
            asn1Spec=krb5_asn1.ETYPE_INFO2())
        return etype_info2

    def as_req(self, creds):
        etypes = (
            AES256_CTS_HMAC_SHA1_96,
            AES128_CTS_HMAC_SHA1_96,
            ARCFOUR_HMAC_MD5)
        (rep, cname, sname, realm, till) = self.as_pre_auth_req(creds, etypes)
        self.check_preauth_rep(rep)

        etype_info2 = self.get_etype_info2(rep)
        key = self.PasswordKey_from_etype_info2(creds, etype_info2[0])

        (patime, pausec) = self.get_KerberosTimeWithUsec()
        pa_ts = self.PA_ENC_TS_ENC_create(patime, pausec)
        pa_ts = self.der_encode(pa_ts, asn1Spec=krb5_asn1.PA_ENC_TS_ENC())

        pa_ts = self.EncryptedData_create(key, KU_PA_ENC_TIMESTAMP, pa_ts)
        pa_ts = self.der_encode(pa_ts, asn1Spec=krb5_asn1.EncryptedData())

        pa_ts = self.PA_DATA_create(PADATA_ENC_TIMESTAMP, pa_ts)

        kdc_options = krb5_asn1.KDCOptions('forwardable')
        padata = [pa_ts]

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
        self.assertIsNotNone(rep)

        msg_type = rep['msg-type']
        self.assertEqual(msg_type, KRB_AS_REP)

        enc_part = rep['enc-part']
        enc_as_rep_part = key.decrypt(
            KU_AS_REP_ENC_PART, rep['enc-part']['cipher'])
        return (enc_as_rep_part, enc_part)


if __name__ == "__main__":
    global_asn1_print = False
    global_hexdump = False
    import unittest
    unittest.main()
