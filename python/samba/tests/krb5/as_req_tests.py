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

from samba.tests import DynamicTestCase
from samba.tests.krb5.kdc_base_test import KDCBaseTest
import samba.tests.krb5.kcrypto as kcrypto
import samba.tests.krb5.rfc4120_pyasn1 as krb5_asn1
from samba.tests.krb5.rfc4120_constants import (
    KDC_ERR_ETYPE_NOSUPP,
    KDC_ERR_PREAUTH_REQUIRED,
    KU_PA_ENC_TIMESTAMP,
    NT_PRINCIPAL,
    NT_SRV_INST,
    PADATA_ENC_TIMESTAMP
)

global_asn1_print = False
global_hexdump = False

@DynamicTestCase
class AsReqKerberosTests(KDCBaseTest):

    @classmethod
    def setUpDynamicTestCases(cls):
        for (name, idx) in cls.etype_test_permutation_name_idx():
            for pac in [None, True, False]:
                tname = "%s_pac_%s" % (name, pac)
                targs = (idx, pac)
                cls.generate_dynamic_test("test_as_req_no_preauth", tname, *targs)

    def setUp(self):
        super(AsReqKerberosTests, self).setUp()
        self.do_asn1_print = global_asn1_print
        self.do_hexdump = global_hexdump

    def _test_as_req_nopreauth(self,
                               initial_etypes,
                               pac=None,
                               initial_kdc_options=None):
        client_creds = self.get_client_creds()
        client_account = client_creds.get_username()
        client_as_etypes = self.get_default_enctypes()
        krbtgt_creds = self.get_krbtgt_creds(require_keys=False)
        krbtgt_account = krbtgt_creds.get_username()
        realm = krbtgt_creds.get_realm()

        cname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                          names=[client_account])
        sname = self.PrincipalName_create(name_type=NT_SRV_INST,
                                          names=[krbtgt_account, realm])

        expected_crealm = realm
        expected_cname = cname
        expected_srealm = realm
        expected_sname = sname
        expected_salt = client_creds.get_salt()

        if any(etype in client_as_etypes and etype in initial_etypes
               for etype in (kcrypto.Enctype.AES256,
                             kcrypto.Enctype.AES128,
                             kcrypto.Enctype.RC4)):
            expected_error_mode = KDC_ERR_PREAUTH_REQUIRED
        else:
            expected_error_mode = KDC_ERR_ETYPE_NOSUPP

        kdc_exchange_dict = self.as_exchange_dict(
            expected_crealm=expected_crealm,
            expected_cname=expected_cname,
            expected_srealm=expected_srealm,
            expected_sname=expected_sname,
            generate_padata_fn=None,
            check_error_fn=self.generic_check_kdc_error,
            check_rep_fn=None,
            expected_error_mode=expected_error_mode,
            client_as_etypes=client_as_etypes,
            expected_salt=expected_salt,
            kdc_options=str(initial_kdc_options),
            pac_request=pac)

        self._generic_kdc_exchange(kdc_exchange_dict,
                                   cname=cname,
                                   realm=realm,
                                   sname=sname,
                                   etypes=initial_etypes)

    def _test_as_req_no_preauth_with_args(self, etype_idx, pac):
        name, etypes = self.etype_test_permutation_by_idx(etype_idx)
        self._test_as_req_nopreauth(
                     pac=pac,
                     initial_etypes=etypes,
                     initial_kdc_options=krb5_asn1.KDCOptions('forwardable'))

    def test_as_req_enc_timestamp(self):
        client_creds = self.get_client_creds()
        self._run_as_req_enc_timestamp(client_creds)

    def test_as_req_enc_timestamp_mac(self):
        client_creds = self.get_mach_creds()
        self._run_as_req_enc_timestamp(client_creds)

    def _run_as_req_enc_timestamp(self, client_creds):
        client_account = client_creds.get_username()
        client_as_etypes = self.get_default_enctypes()
        client_kvno = client_creds.get_kvno()
        krbtgt_creds = self.get_krbtgt_creds(require_strongest_key=True)
        krbtgt_account = krbtgt_creds.get_username()
        realm = krbtgt_creds.get_realm()

        cname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                          names=[client_account])
        sname = self.PrincipalName_create(name_type=NT_SRV_INST,
                                          names=[krbtgt_account, realm])

        expected_crealm = realm
        expected_cname = cname
        expected_srealm = realm
        expected_sname = sname
        expected_salt = client_creds.get_salt()

        till = self.get_KerberosTime(offset=36000)

        initial_etypes = client_as_etypes
        initial_kdc_options = krb5_asn1.KDCOptions('forwardable')
        initial_error_mode = KDC_ERR_PREAUTH_REQUIRED

        rep, kdc_exchange_dict = self._test_as_exchange(cname,
                                                        realm,
                                                        sname,
                                                        till,
                                                        client_as_etypes,
                                                        initial_error_mode,
                                                        expected_crealm,
                                                        expected_cname,
                                                        expected_srealm,
                                                        expected_sname,
                                                        expected_salt,
                                                        initial_etypes,
                                                        None,
                                                        initial_kdc_options,
                                                        pac_request=True)
        etype_info2 = kdc_exchange_dict['preauth_etype_info2']
        self.assertIsNotNone(etype_info2)

        preauth_key = self.PasswordKey_from_etype_info2(client_creds,
                                                        etype_info2[0],
                                                        kvno=client_kvno)

        (patime, pausec) = self.get_KerberosTimeWithUsec()
        pa_ts = self.PA_ENC_TS_ENC_create(patime, pausec)
        pa_ts = self.der_encode(pa_ts, asn1Spec=krb5_asn1.PA_ENC_TS_ENC())

        enc_pa_ts_usage = KU_PA_ENC_TIMESTAMP
        pa_ts = self.EncryptedData_create(preauth_key, enc_pa_ts_usage, pa_ts)
        pa_ts = self.der_encode(pa_ts, asn1Spec=krb5_asn1.EncryptedData())

        pa_ts = self.PA_DATA_create(PADATA_ENC_TIMESTAMP, pa_ts)

        preauth_padata = [pa_ts]
        preauth_etypes = client_as_etypes
        preauth_kdc_options = krb5_asn1.KDCOptions('forwardable')
        preauth_error_mode = 0 # AS-REP

        krbtgt_decryption_key = (
            self.TicketDecryptionKey_from_creds(krbtgt_creds))

        as_rep, kdc_exchange_dict = self._test_as_exchange(
            cname,
            realm,
            sname,
            till,
            client_as_etypes,
            preauth_error_mode,
            expected_crealm,
            expected_cname,
            expected_srealm,
            expected_sname,
            expected_salt,
            preauth_etypes,
            preauth_padata,
            preauth_kdc_options,
            preauth_key=preauth_key,
            ticket_decryption_key=krbtgt_decryption_key,
            pac_request=True)
        self.assertIsNotNone(as_rep)

        return etype_info2


if __name__ == "__main__":
    global_asn1_print = False
    global_hexdump = False
    import unittest
    unittest.main()

