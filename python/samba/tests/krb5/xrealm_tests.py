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

sys.path.insert(0, "bin/python")
os.environ["PYTHONUNBUFFERED"] = "1"

from samba.tests.krb5.raw_testcase import RawKerberosTest
from samba.tests.krb5.rfc4120_constants import (
    KU_PA_ENC_TIMESTAMP,
    KU_AS_REP_ENC_PART,
    KU_TGS_REP_ENC_PART_SUB_KEY,
)
import samba.tests.krb5.rfc4120_pyasn1 as krb5_asn1
import samba.tests

global_asn1_print = False
global_hexdump = False


class XrealmKerberosTests(RawKerberosTest):

    def setUp(self):
        super(XrealmKerberosTests, self).setUp()
        self.do_asn1_print = global_asn1_print
        self.do_hexdump = global_hexdump

    def test_xrealm(self):
        user_creds = self.get_user_creds()
        user = user_creds.get_username()
        realm = user_creds.get_realm()

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
                                 additional_tickets=None)
        rep = self.send_recv_transaction(req)
        self.assertIsNotNone(rep)

        self.assertEqual(rep['msg-type'], 30)
        self.assertEqual(rep['error-code'], 25)
        rep_padata = self.der_decode(
            rep['e-data'], asn1Spec=krb5_asn1.METHOD_DATA())

        for pa in rep_padata:
            if pa['padata-type'] == 19:
                etype_info2 = pa['padata-value']
                break

        etype_info2 = self.der_decode(
            etype_info2, asn1Spec=krb5_asn1.ETYPE_INFO2())

        key = self.PasswordKey_from_etype_info2(user_creds, etype_info2[0])

        (patime, pausec) = self.get_KerberosTimeWithUsec()
        pa_ts = self.PA_ENC_TS_ENC_create(patime, pausec)
        pa_ts = self.der_encode(pa_ts, asn1Spec=krb5_asn1.PA_ENC_TS_ENC())

        pa_ts = self.EncryptedData_create(key, KU_PA_ENC_TIMESTAMP, pa_ts)
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
                                 additional_tickets=None)
        rep = self.send_recv_transaction(req)
        self.assertIsNotNone(rep)

        msg_type = rep['msg-type']
        self.assertEqual(msg_type, 11)

        enc_part2 = key.decrypt(KU_AS_REP_ENC_PART, rep['enc-part']['cipher'])

        # MIT KDC encodes both EncASRepPart and EncTGSRepPart with
        # application tag 26
        try:
            enc_part2 = self.der_decode(
                enc_part2, asn1Spec=krb5_asn1.EncASRepPart())
        except Exception:
            enc_part2 = self.der_decode(
                enc_part2, asn1Spec=krb5_asn1.EncTGSRepPart())

        # TGS Request (for cross-realm TGT)
        trust_realm = samba.tests.env_get_var_value('TRUST_REALM')
        sname = self.PrincipalName_create(
            name_type=2, names=["krbtgt", trust_realm])

        kdc_options = krb5_asn1.KDCOptions('forwardable')
        till = self.get_KerberosTime(offset=36000)
        ticket = rep['ticket']
        ticket_session_key = self.EncryptionKey_import(enc_part2['key'])
        padata = []

        subkey = self.RandomKey(ticket_session_key.etype)

        (ctime, cusec) = self.get_KerberosTimeWithUsec()

        req = self.TGS_REQ_create(padata=padata,
                                  cusec=cusec,
                                  ctime=ctime,
                                  ticket=ticket,
                                  kdc_options=str(kdc_options),
                                  cname=cname,
                                  realm=realm,
                                  sname=sname,
                                  from_time=None,
                                  till_time=till,
                                  renew_time=None,
                                  nonce=0x7ffffffe,
                                  etypes=etypes,
                                  addresses=None,
                                  EncAuthorizationData=None,
                                  EncAuthorizationData_key=None,
                                  additional_tickets=None,
                                  ticket_session_key=ticket_session_key,
                                  authenticator_subkey=subkey)
        rep = self.send_recv_transaction(req)
        self.assertIsNotNone(rep)

        msg_type = rep['msg-type']
        self.assertEqual(msg_type, 13)

        enc_part2 = subkey.decrypt(
            KU_TGS_REP_ENC_PART_SUB_KEY, rep['enc-part']['cipher'])
        enc_part2 = self.der_decode(
            enc_part2, asn1Spec=krb5_asn1.EncTGSRepPart())

        # Check the forwardable flag
        fwd_pos = len(tuple(krb5_asn1.TicketFlags('forwardable'))) - 1
        assert(krb5_asn1.TicketFlags(enc_part2['flags'])[fwd_pos])

        return


if __name__ == "__main__":
    global_asn1_print = False
    global_hexdump = False
    import unittest
    unittest.main()
