#!/usr/bin/env python3
# Unix SMB/CIFS implementation.
#
# Copyright (C) Catalyst IT Ltd. 2020
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
from enum import Enum, unique
import pyasn1

sys.path.insert(0, "bin/python")
os.environ["PYTHONUNBUFFERED"] = "1"

from samba.tests.krb5.kdc_base_test import KDCBaseTest
import samba.tests.krb5.rfc4120_pyasn1 as krb5_asn1
from samba.credentials import DONT_USE_KERBEROS
from samba.dcerpc.misc import SEC_CHAN_WKSTA
from samba.tests import DynamicTestCase
from samba.tests.krb5.rfc4120_constants import (
    AES256_CTS_HMAC_SHA1_96,
    AES128_CTS_HMAC_SHA1_96,
    ARCFOUR_HMAC_MD5,
    KDC_ERR_PREAUTH_REQUIRED,
    KRB_AS_REP,
    KU_AS_REP_ENC_PART,
    KRB_ERROR,
    KU_PA_ENC_TIMESTAMP,
    PADATA_ENC_TIMESTAMP,
    NT_ENTERPRISE_PRINCIPAL,
    NT_PRINCIPAL,
    NT_SRV_INST,
)

global_asn1_print = False
global_hexdump = False


@unique
class TestOptions(Enum):
    Canonicalize = 1
    Enterprise = 2
    UpperRealm = 4
    UpperUserName = 8
    NetbiosRealm = 16
    UPN = 32
    RemoveDollar = 64
    AsReqSelf = 128
    Last = 256

    def is_set(self, x):
        return self.value & x


@unique
class CredentialsType(Enum):
    User = 1
    Machine = 2

    def is_set(self, x):
        return self.value & x


class TestData:

    def __init__(self, options, creds):
        self.options = options
        self.user_creds = creds
        self.user_name = self._get_username(options, creds)
        self.realm = self._get_realm(options, creds)

        if TestOptions.Enterprise.is_set(options):
            client_name_type = NT_ENTERPRISE_PRINCIPAL
        else:
            client_name_type = NT_PRINCIPAL

        self.cname = KDCBaseTest.PrincipalName_create(
            name_type=client_name_type, names=[self.user_name])
        if TestOptions.AsReqSelf.is_set(options):
            self.sname = self.cname
        else:
            self.sname = KDCBaseTest.PrincipalName_create(
                name_type=NT_SRV_INST, names=["krbtgt", self.realm])
        self.canonicalize = TestOptions.Canonicalize.is_set(options)

    def _get_realm(self, options, creds):
        realm = creds.get_realm()
        if TestOptions.NetbiosRealm.is_set(options):
            realm = creds.get_domain()
        if TestOptions.UpperRealm.is_set(options):
            realm = realm.upper()
        else:
            realm = realm.lower()
        return realm

    def _get_username(self, options, creds):
        name = creds.get_username()
        if TestOptions.RemoveDollar.is_set(options) and name.endswith("$"):
            name = name[:-1]
        if TestOptions.Enterprise.is_set(options):
            realm = creds.get_realm()
            name = "{0}@{1}".format(name, realm)
        if TestOptions.UpperUserName.is_set(options):
            name = name.upper()
        return name

    def __repr__(self):
        rep = "Test Data: "
        rep += "options = '" + "{:08b}".format(self.options) + "'"
        rep += "user name = '" + self.user_name + "'"
        rep += ", realm = '" + self.realm + "'"
        rep += ", cname = '" + str(self.cname) + "'"
        rep += ", sname = '" + str(self.sname) + "'"
        return rep


MACHINE_NAME = "tstkrb5cnnmch"
USER_NAME = "tstkrb5cnnusr"


@DynamicTestCase
class KerberosASCanonicalizationTests(KDCBaseTest):

    @classmethod
    def setUpDynamicTestCases(cls):

        def skip(ct, options):
            ''' Filter out any mutually exclusive test options '''
            if ct != CredentialsType.Machine and\
                    TestOptions.RemoveDollar.is_set(options):
                return True
            if ct != CredentialsType.Machine and\
                    TestOptions.AsReqSelf.is_set(options):
                return True
            return False

        def build_test_name(ct, options):
            name = "%sCredentials" % ct.name
            for opt in TestOptions:
                if opt.is_set(options):
                    name += ("_%s" % opt.name)
            return name

        for ct in CredentialsType:
            for x in range(TestOptions.Last.value):
                if skip(ct, x):
                    continue
                name = build_test_name(ct, x)
                cls.generate_dynamic_test("test", name, x, ct)

    def user_account_creds(self):
        if self.user_creds is None:
            samdb = self.get_samdb()
            self.user_creds, _ = self.create_account(samdb, USER_NAME)

        return self.user_creds

    def machine_account_creds(self):
        if self.machine_creds is None:
            samdb = self.get_samdb()
            self.machine_creds, _ = self.create_account(
                samdb,
                MACHINE_NAME,
                account_type=self.AccountType.COMPUTER)
            self.machine_creds.set_secure_channel_type(SEC_CHAN_WKSTA)
            self.machine_creds.set_kerberos_state(DONT_USE_KERBEROS)

        return self.machine_creds

    def setUp(self):
        super().setUp()
        self.do_asn1_print = global_asn1_print
        self.do_hexdump = global_hexdump

        self.user_creds = None
        self.machine_creds = None

    def _test_with_args(self, x, ct):
        if ct == CredentialsType.User:
            creds = self.user_account_creds()
        elif ct == CredentialsType.Machine:
            creds = self.machine_account_creds()
        else:
            raise Exception("Unexpected credential type")
        data = TestData(x, creds)

        try:
            (rep, as_rep) = self.as_req(data)
        except pyasn1.error.PyAsn1Error as e:
            import traceback
            self.fail("ASN1 Error, Options {0:08b}:{1} {2}".format(
                data.options,
                traceback.format_exc(),
                e))
        # If as_req triggered an expected server error response
        # No need to test the response data.
        if rep is not None:
            # The kvno is optional, heimdal includes it
            # MIT does not.
            if 'kvno' in rep['enc-part']:
                kvno = rep['enc-part']['kvno']
                self.check_kvno(kvno, data)

            cname = rep['cname']
            self.check_cname(cname, data)

            crealm = rep['crealm'].decode('ascii')
            self.check_crealm(crealm, data)

            sname = as_rep['sname']
            self.check_sname(sname, data)

            srealm = as_rep['srealm'].decode('ascii')
            self.check_srealm(srealm, data)

    def as_req(self, data):
        user_creds = data.user_creds
        realm = data.realm

        cname = data.cname
        sname = data.sname

        till = self.get_KerberosTime(offset=36000)

        kdc_options = "0"
        if data.canonicalize:
            kdc_options = str(krb5_asn1.KDCOptions('canonicalize'))

        padata = None

        # Set the allowable encryption types
        etypes = (
            AES256_CTS_HMAC_SHA1_96,
            AES128_CTS_HMAC_SHA1_96,
            ARCFOUR_HMAC_MD5)

        req = self.AS_REQ_create(padata=padata,
                                 kdc_options=kdc_options,
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

        #
        # Check the protocol version, should be 5
        self.assertEqual(
            rep['pvno'], 5, "Data {0}".format(str(data)))

        self.assertEqual(
            rep['msg-type'], KRB_ERROR, "Data {0}".format(str(data)))

        self.assertEqual(
            rep['error-code'],
            KDC_ERR_PREAUTH_REQUIRED,
            "Error code {0}, Data {1}".format(rep['error-code'], str(data)))

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

        pa_ts = self.PA_DATA_create(PADATA_ENC_TIMESTAMP, pa_ts)

        kdc_options = "0"
        if data.canonicalize:
            kdc_options = str(krb5_asn1.KDCOptions('canonicalize'))
        padata = [pa_ts]

        req = self.AS_REQ_create(padata=padata,
                                 kdc_options=kdc_options,
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

        #
        # Check the protocol version, should be 5
        self.assertEqual(
            rep['pvno'], 5, "Data {0}".format(str(data)))

        msg_type = rep['msg-type']
        # Should not have got an error.
        # If we did, fail and print the error code to help debugging
        self.assertNotEqual(
            msg_type,
            KRB_ERROR,
            "Error code {0}, Data {1}".format(
                rep.get('error-code', ''),
                str(data)))

        self.assertEqual(msg_type, KRB_AS_REP, "Data {0}".format(str(data)))

        # Decrypt and decode the EncKdcRepPart
        enc = key.decrypt(KU_AS_REP_ENC_PART, rep['enc-part']['cipher'])
        if enc[0] == 0x7A:
            # MIT Kerberos Tags the EncASRepPart as a EncKDCRepPart
            # i.e. tag number 26 instead of tag number 25
            as_rep = self.der_decode(enc, asn1Spec=krb5_asn1.EncTGSRepPart())
        else:
            as_rep = self.der_decode(enc, asn1Spec=krb5_asn1.EncASRepPart())

        return (rep, as_rep)

    def check_cname(self, cname, data):
        if TestOptions.Canonicalize.is_set(data.options):
            expected_name_type = NT_PRINCIPAL
        elif TestOptions.Enterprise.is_set(data.options):
            expected_name_type = NT_ENTERPRISE_PRINCIPAL
        else:
            expected_name_type = NT_PRINCIPAL

        name_type = cname['name-type']
        self.assertEqual(
            expected_name_type,
            name_type,
            "cname name-type, Options {0:08b}".format(data.options))

        ns = cname['name-string']
        name = ns[0].decode('ascii')

        expected = data.user_name
        if TestOptions.Canonicalize.is_set(data.options):
            expected = data.user_creds.get_username()
        self.assertEqual(
            expected,
            name,
            "cname principal, Options {0:08b}".format(data.options))

    def check_crealm(self, crealm, data):
        realm = data.user_creds.get_realm()
        self.assertEqual(
            realm, crealm, "crealm, Options {0:08b}".format(data.options))

    def check_sname(self, sname, data):
        nt = sname['name-type']
        ns = sname['name-string']
        name = ns[0].decode('ascii')

        if TestOptions.AsReqSelf.is_set(data.options):
            expected_name_type = NT_PRINCIPAL
            if not TestOptions.Canonicalize.is_set(data.options)\
               and TestOptions.Enterprise.is_set(data.options):

                expected_name_type = NT_ENTERPRISE_PRINCIPAL

            self.assertEqual(
                expected_name_type,
                nt,
                "sname name-type, Options {0:08b}".format(data.options))
            expected = data.user_name
            if TestOptions.Canonicalize.is_set(data.options):
                expected = data.user_creds.get_username()
            self.assertEqual(
                expected,
                name,
                "sname principal, Options {0:08b}".format(data.options))
        else:
            self.assertEqual(
                NT_SRV_INST,
                nt,
                "sname name-type, Options {0:08b}".format(data.options))
            self.assertEqual(
                'krbtgt',
                name,
                "sname principal, Options {0:08b}".format(data.options))

            realm = ns[1].decode('ascii')
            expected = data.realm
            if TestOptions.Canonicalize.is_set(data.options):
                expected = data.user_creds.get_realm().upper()
            self.assertEqual(
                expected,
                realm,
                "sname realm, Options {0:08b}".format(data.options))

    def check_srealm(self, srealm, data):
        realm = data.user_creds.get_realm()
        self.assertEqual(
            realm, srealm, "srealm, Options {0:08b}".format(data.options))

    def check_kvno(self, kvno, data):
        self.assertEqual(
            1, kvno, "kvno, Options {0:08b}".format(data.options))


if __name__ == "__main__":
    global_asn1_print = False
    global_hexdump = False
    import unittest

    unittest.main()
