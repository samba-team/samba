#!/usr/bin/env python3
# Unix SMB/CIFS implementation.
# Copyright (C) Stefan Metzmacher 2020
# Copyright (C) 2022 Catalyst.Net Ltd
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

from samba.dcerpc import security

from samba.tests.krb5.kdc_tgs_tests import KdcTgsBaseTests
from samba.tests.krb5.rfc4120_constants import (
    AES256_CTS_HMAC_SHA1_96,
    ARCFOUR_HMAC_MD5,
    KDC_ERR_ETYPE_NOSUPP,
)

sys.path.insert(0, "bin/python")
os.environ["PYTHONUNBUFFERED"] = "1"

global_asn1_print = False
global_hexdump = False


class EtypeTests(KdcTgsBaseTests):
    def setUp(self):
        super().setUp()
        self.do_asn1_print = global_asn1_print
        self.do_hexdump = global_hexdump

    # Perform an AS-REQ for a service ticket, specifying AES. The request
    # should fail with an error.
    def test_as_aes_requested(self):
        creds = self.get_mach_creds()
        target_creds = self.get_service_creds()

        self._as_req(creds, expected_error=KDC_ERR_ETYPE_NOSUPP,
                     target_creds=target_creds,
                     etype=(AES256_CTS_HMAC_SHA1_96,))

    # Perform an AS-REQ for a service ticket, specifying RC4. The resulting
    # ticket should be encrypted with RC4, with an RC4 session key.
    def test_as_rc4_requested(self):
        creds = self.get_mach_creds()
        target_creds = self.get_service_creds()

        ticket = self._as_req(creds, expected_error=0,
                              target_creds=target_creds,
                              etype=(ARCFOUR_HMAC_MD5,))

        self.assertEqual(ARCFOUR_HMAC_MD5, ticket.decryption_key.etype)
        self.assertEqual(ARCFOUR_HMAC_MD5, ticket.session_key.etype)

    # Perform an AS-REQ for a service ticket, specifying AES, when the target
    # service only supports AES. The resulting ticket should be encrypted with
    # AES, with an AES session key.
    def test_as_aes_supported_aes_requested(self):
        creds = self.get_mach_creds()

        target_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={
                'supported_enctypes':
                security.KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96,
            })

        ticket = self._as_req(creds, expected_error=0,
                              target_creds=target_creds,
                              etype=(AES256_CTS_HMAC_SHA1_96,))

        self.assertEqual(AES256_CTS_HMAC_SHA1_96, ticket.decryption_key.etype)
        self.assertEqual(AES256_CTS_HMAC_SHA1_96, ticket.session_key.etype)

    # Perform an AS-REQ for a service ticket, specifying RC4, when the target
    # service only supports AES. The resulting ticket should be encrypted with
    # AES, with an RC4 session key.
    def test_as_aes_supported_rc4_requested(self):
        creds = self.get_mach_creds()

        target_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={
                'supported_enctypes':
                security.KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96,
            })

        ticket = self._as_req(creds, expected_error=0,
                              target_creds=target_creds,
                              etype=(ARCFOUR_HMAC_MD5,))

        self.assertEqual(AES256_CTS_HMAC_SHA1_96, ticket.decryption_key.etype)
        self.assertEqual(ARCFOUR_HMAC_MD5, ticket.session_key.etype)

    # Perform an AS-REQ for a service ticket, specifying AES, when the target
    # service only supports RC4. The request should fail with an error.
    def test_as_rc4_supported_aes_requested(self):
        creds = self.get_mach_creds()

        target_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={
                'supported_enctypes':
                security.KERB_ENCTYPE_RC4_HMAC_MD5,
            })

        self._as_req(creds, expected_error=KDC_ERR_ETYPE_NOSUPP,
                     target_creds=target_creds,
                     etype=(AES256_CTS_HMAC_SHA1_96,))

    # Perform an AS-REQ for a service ticket, specifying RC4, when the target
    # service only supports RC4. The resulting ticket should be encrypted with
    # RC4, with an RC4 session key.
    def test_as_rc4_supported_rc4_requested(self):
        creds = self.get_mach_creds()

        target_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={
                'supported_enctypes':
                security.KERB_ENCTYPE_RC4_HMAC_MD5,
            })

        ticket = self._as_req(creds, expected_error=0,
                              target_creds=target_creds,
                              etype=(ARCFOUR_HMAC_MD5,))

        self.assertEqual(ARCFOUR_HMAC_MD5, ticket.decryption_key.etype)
        self.assertEqual(ARCFOUR_HMAC_MD5, ticket.session_key.etype)

    # Perform a TGS-REQ for a service ticket, specifying AES. The request
    # should fail with an error.
    def test_tgs_aes_requested(self):
        creds = self.get_mach_creds()
        tgt = self.get_tgt(creds)

        target_creds = self.get_mach_creds()

        self._tgs_req(tgt, expected_error=KDC_ERR_ETYPE_NOSUPP,
                      target_creds=target_creds,
                      etypes=(AES256_CTS_HMAC_SHA1_96,))

    # Perform a TGS-REQ for a service ticket, specifying RC4. The resulting
    # ticket should be encrypted with RC4, with an RC4 session key.
    def test_tgs_rc4_requested(self):
        creds = self.get_mach_creds()
        tgt = self.get_tgt(creds)

        target_creds = self.get_mach_creds()

        ticket = self._tgs_req(tgt, expected_error=0,
                               target_creds=target_creds,
                               etypes=(ARCFOUR_HMAC_MD5,))

        self.assertEqual(ARCFOUR_HMAC_MD5, ticket.decryption_key.etype)
        self.assertEqual(ARCFOUR_HMAC_MD5, ticket.session_key.etype)

    # Perform a TGS-REQ for a service ticket, specifying AES, when the target
    # service only supports AES. The resulting ticket should be encrypted with
    # AES, with an AES session key.
    def test_tgs_aes_supported_aes_requested(self):
        creds = self.get_mach_creds()
        tgt = self.get_tgt(creds)

        target_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={
                'supported_enctypes':
                security.KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96,
            })

        ticket = self._tgs_req(tgt, expected_error=0,
                               target_creds=target_creds,
                               etypes=(AES256_CTS_HMAC_SHA1_96,))

        self.assertEqual(AES256_CTS_HMAC_SHA1_96, ticket.decryption_key.etype)
        self.assertEqual(AES256_CTS_HMAC_SHA1_96, ticket.session_key.etype)

    # Perform a TGS-REQ for a service ticket, specifying RC4, when the target
    # service only supports AES. The resulting ticket should be encrypted with
    # AES, with an RC4 session key.
    def test_tgs_aes_supported_rc4_requested(self):
        creds = self.get_mach_creds()
        tgt = self.get_tgt(creds)

        target_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={
                'supported_enctypes':
                security.KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96,
            })

        ticket = self._tgs_req(tgt, expected_error=0,
                               target_creds=target_creds,
                               etypes=(ARCFOUR_HMAC_MD5,))

        self.assertEqual(AES256_CTS_HMAC_SHA1_96, ticket.decryption_key.etype)
        self.assertEqual(ARCFOUR_HMAC_MD5, ticket.session_key.etype)

    # Perform a TGS-REQ for a service ticket, specifying AES, when the target
    # service only supports RC4. The request should fail with an error.
    def test_tgs_rc4_supported_aes_requested(self):
        creds = self.get_mach_creds()
        tgt = self.get_tgt(creds)

        target_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={
                'supported_enctypes':
                security.KERB_ENCTYPE_RC4_HMAC_MD5,
            })

        self._tgs_req(tgt, expected_error=KDC_ERR_ETYPE_NOSUPP,
                      target_creds=target_creds,
                      etypes=(AES256_CTS_HMAC_SHA1_96,))

    # Perform a TGS-REQ for a service ticket, specifying RC4, when the target
    # service only supports RC4. The resulting ticket should be encrypted with
    # RC4, with an RC4 session key.
    def test_tgs_rc4_supported_rc4_requested(self):
        creds = self.get_mach_creds()
        tgt = self.get_tgt(creds)

        target_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={
                'supported_enctypes':
                security.KERB_ENCTYPE_RC4_HMAC_MD5,
            })

        ticket = self._tgs_req(tgt, expected_error=0,
                               target_creds=target_creds,
                               etypes=(ARCFOUR_HMAC_MD5,))

        self.assertEqual(ARCFOUR_HMAC_MD5, ticket.decryption_key.etype)
        self.assertEqual(ARCFOUR_HMAC_MD5, ticket.session_key.etype)


if __name__ == "__main__":
    global_asn1_print = False
    global_hexdump = False
    import unittest
    unittest.main()
