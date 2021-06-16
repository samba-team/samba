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
import samba.tests.krb5.rfc4120_pyasn1 as krb5_asn1
from samba.tests.krb5.rfc4120_constants import (
    KDC_ERR_PREAUTH_REQUIRED,
    NT_PRINCIPAL,
    NT_SRV_INST
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
        return

    def setUp(self):
        super(AsReqKerberosTests, self).setUp()
        self.do_asn1_print = global_asn1_print
        self.do_hexdump = global_hexdump

    def _test_as_req_nopreauth(self,
                               initial_etypes,
                               initial_padata=None,
                               initial_kdc_options=None):
        client_creds = self.get_client_creds()
        client_account = client_creds.get_username()
        client_as_etypes = client_creds.get_as_krb5_etypes()
        krbtgt_creds = self.get_krbtgt_creds(require_keys=False)
        krbtgt_account = krbtgt_creds.get_username()
        realm = krbtgt_creds.get_realm()

        cname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                          names=[client_account])
        sname = self.PrincipalName_create(name_type=NT_SRV_INST,
                                          names=[krbtgt_account, realm])

        expected_error_mode = KDC_ERR_PREAUTH_REQUIRED
        expected_crealm = realm
        expected_cname = cname
        expected_srealm = realm
        expected_sname = sname
        expected_salt = client_creds.get_forced_salt()

        def _generate_padata_copy(_kdc_exchange_dict,
                                  _callback_dict,
                                  req_body):
            return initial_padata, req_body

        kdc_exchange_dict = self.as_exchange_dict(
                         expected_crealm=expected_crealm,
                         expected_cname=expected_cname,
                         expected_srealm=expected_srealm,
                         expected_sname=expected_sname,
                         generate_padata_fn=_generate_padata_copy,
                         check_error_fn=self.generic_check_as_error,
                         check_rep_fn=self.generic_check_kdc_rep,
                         expected_error_mode=expected_error_mode,
                         client_as_etypes=client_as_etypes,
                         expected_salt=expected_salt)

        rep = self._generic_kdc_exchange(kdc_exchange_dict,
                                         kdc_options=str(initial_kdc_options),
                                         cname=cname,
                                         realm=realm,
                                         sname=sname,
                                         etypes=initial_etypes)

        return kdc_exchange_dict['preauth_etype_info2']

    def _test_as_req_no_preauth_with_args(self, etype_idx, pac):
        name, etypes = self.etype_test_permutation_by_idx(etype_idx)
        if pac is None:
            padata = None
        else:
            pa_pac = self.KERB_PA_PAC_REQUEST_create(pac)
            padata = [pa_pac]
        return self._test_as_req_nopreauth(
                     initial_padata=padata,
                     initial_etypes=etypes,
                     initial_kdc_options=krb5_asn1.KDCOptions('forwardable'))


if __name__ == "__main__":
    global_asn1_print = True
    global_hexdump = True
    import unittest
    unittest.main()

