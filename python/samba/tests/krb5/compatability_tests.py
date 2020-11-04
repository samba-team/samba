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

from samba.tests.krb5.raw_testcase import RawKerberosTest
import samba.tests.krb5.rfc4120_pyasn1 as krb5_asn1

global_asn1_print = False
global_hexdump = False


class SimpleKerberosTests(RawKerberosTest):

    def setUp(self):
        super(SimpleKerberosTests, self).setUp()
        self.do_asn1_print = global_asn1_print
        self.do_hexdump = global_hexdump

    def test_mit_EncASRepPart_tag(self):
        creds = self.get_user_creds()
        (enc, _) = self.as_req(creds)
        self.assertEqual(0x7a, enc[0])

    def test_heimdal_EncASRepPart_tag(self):
        creds = self.get_user_creds()
        (enc, _) = self.as_req(creds)
        self.assertEqual(0x79, enc[0])

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
        self.assertEqual(0x7A, enc[0])
        as_rep = self.der_decode(enc, asn1Spec=krb5_asn1.EncTGSRepPart())
        flags = int(as_rep['flags'], base=2)
        # MIT sets enc-pa-rep, flag bit 15
        # RFC 6806 11. Negotiation of FAST and Detecting Modified Requests
        self.assertTrue(0x00010000 & flags)

    def test_heimdal_EncASRepPart_FAST_support(self):
        creds = self.get_user_creds()
        (enc, _) = self.as_req(creds)
        self.assertEqual(0x79, enc[0])
        as_rep = self.der_decode(enc, asn1Spec=krb5_asn1.EncASRepPart())
        flags = as_rep['flags']
        flags = int(as_rep['flags'], base=2)
        # Heimdal does not set enc-pa-rep, flag bit 15
        # RFC 6806 11. Negotiation of FAST and Detecting Modified Requests
        self.assertFalse(0x00010000 & flags)

    def as_req(self, creds):
        user = creds.get_username()
        realm = creds.get_realm()

        cname = self.PrincipalName_create(name_type=1, names=[user])
        sname = self.PrincipalName_create(name_type=2, names=["krbtgt", realm])

        till = self.get_KerberosTime(offset=36000)

        kdc_options = krb5_asn1.KDCOptions('forwardable')
        padata = None

        etypes = (18, 17, 23)

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
                                 EncAuthorizationData=None,
                                 EncAuthorizationData_key=None,
                                 additional_tickets=None)
        rep = self.send_recv_transaction(req)
        self.assertIsNotNone(rep)

        self.assertEqual(rep['msg-type'], 30)
        self.assertEqual(rep['error-code'], 25)
        rep_padata = self.der_decode(
            rep['e-data'],
            asn1Spec=krb5_asn1.METHOD_DATA())

        for pa in rep_padata:
            if pa['padata-type'] == 19:
                etype_info2 = pa['padata-value']
                break

        etype_info2 = self.der_decode(
            etype_info2,
            asn1Spec=krb5_asn1.ETYPE_INFO2())

        key = self.PasswordKey_from_etype_info2(creds, etype_info2[0])

        (patime, pausec) = self.get_KerberosTimeWithUsec()
        pa_ts = self.PA_ENC_TS_ENC_create(patime, pausec)
        pa_ts = self.der_encode(pa_ts, asn1Spec=krb5_asn1.PA_ENC_TS_ENC())

        enc_pa_ts_usage = 1
        pa_ts = self.EncryptedData_create(key, enc_pa_ts_usage, pa_ts)
        pa_ts = self.der_encode(pa_ts, asn1Spec=krb5_asn1.EncryptedData())

        pa_ts = self.PA_DATA_create(2, pa_ts)

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
                                 EncAuthorizationData=None,
                                 EncAuthorizationData_key=None,
                                 additional_tickets=None)
        rep = self.send_recv_transaction(req)
        self.assertIsNotNone(rep)

        msg_type = rep['msg-type']
        self.assertEqual(msg_type, 11)

        usage = 3
        enc_part = rep['enc-part']
        enc_as_rep_part = key.decrypt(usage, rep['enc-part']['cipher'])
        return (enc_as_rep_part, enc_part)


if __name__ == "__main__":
    global_asn1_print = True
    global_hexdump = True
    import unittest
    unittest.main()
