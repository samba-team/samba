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

sys.path.insert(0, "bin/python")
os.environ["PYTHONUNBUFFERED"] = "1"

import itertools

from samba.dcerpc import security

from samba.tests import DynamicTestCase
from samba.tests.krb5.kdc_tgs_tests import KdcTgsBaseTests
from samba.tests.krb5.raw_testcase import KerberosCredentials
from samba.tests.krb5.rfc4120_constants import (
    AES128_CTS_HMAC_SHA1_96,
    AES256_CTS_HMAC_SHA1_96,
    ARCFOUR_HMAC_MD5,
    KDC_ERR_ETYPE_NOSUPP,
)
import samba.tests.krb5.rfc4120_pyasn1 as krb5_asn1


global_asn1_print = False
global_hexdump = False

des_bits = security.KERB_ENCTYPE_DES_CBC_MD5 | security.KERB_ENCTYPE_DES_CBC_CRC
rc4_bit = security.KERB_ENCTYPE_RC4_HMAC_MD5
aes128_bit = security.KERB_ENCTYPE_AES128_CTS_HMAC_SHA1_96
aes256_bit = security.KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96
aes256_sk_bit = security.KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96_SK
fast_bit = security.KERB_ENCTYPE_FAST_SUPPORTED

etype_bits = rc4_bit | aes128_bit | aes256_bit
extra_bits = aes256_sk_bit | fast_bit


@DynamicTestCase
class EtypeTests(KdcTgsBaseTests):
    def setUp(self):
        super().setUp()
        self.do_asn1_print = global_asn1_print
        self.do_hexdump = global_hexdump

    def _server_creds(self, supported=None, force_nt4_hash=False,
                      account_type=None):
        if account_type is None:
            account_type= self.AccountType.COMPUTER
        return self.get_cached_creds(
            account_type=account_type,
            opts={
                'supported_enctypes': supported,
                'force_nt4_hash': force_nt4_hash,
            })

    def only_non_etype_bits_set(self, bits):
        return bits is not None and (
            bits & extra_bits and
            not (bits & etype_bits))

    @classmethod
    def setUpDynamicTestCases(cls):
        all_etypes = (AES256_CTS_HMAC_SHA1_96,
                      AES128_CTS_HMAC_SHA1_96,
                      ARCFOUR_HMAC_MD5)

        # An iterator yielding all permutations consisting of at least one
        # etype.
        requested_etype_cases = itertools.chain.from_iterable(
            itertools.permutations(all_etypes, x)
            for x in range(1, len(all_etypes) + 1))

        # Some combinations of msDS-SupportedEncryptionTypes bits to be set on
        # the target server.
        supported_etype_cases = (
            # Not set.
            None,
            # Every possible combination of RC4, AES128, AES256, and AES256-SK.
            0,
            rc4_bit,
            aes256_sk_bit,
            aes256_sk_bit | rc4_bit,
            aes256_bit,
            aes256_bit | rc4_bit,
            aes256_bit | aes256_sk_bit,
            aes256_bit | aes256_sk_bit | rc4_bit,
            aes128_bit,
            aes128_bit | rc4_bit,
            aes128_bit | aes256_sk_bit,
            aes128_bit | aes256_sk_bit | rc4_bit,
            aes128_bit | aes256_bit,
            aes128_bit | aes256_bit | rc4_bit,
            aes128_bit | aes256_bit | aes256_sk_bit,
            aes128_bit | aes256_bit | aes256_sk_bit | rc4_bit,
            # Some combinations with an extra bit (the FAST-supported bit) set.
            fast_bit,
            fast_bit | rc4_bit,
            fast_bit | aes256_sk_bit,
            fast_bit | aes256_bit,
        )

        for _requested_etypes in requested_etype_cases:
            _s = str(_requested_etypes)
            _t = _s.maketrans(",", "_", "( )")
            requested_etypes = _s.translate(_t)

            for _supported_etypes in supported_etype_cases:
                if _supported_etypes is None:
                    supported_etypes = "None"
                else:
                    supported_etypes = f'0x{_supported_etypes:X}'

                for account_type in ["member", "dc"]:
                    if account_type == "dc":
                        _account_type = cls.AccountType.SERVER
                    elif account_type == "member":
                        _account_type = cls.AccountType.COMPUTER

                    for stored_type in ["aes_rc4", "rc4_only"]:
                        if stored_type == "aes_rc4":
                            force_nt4_hash = False
                        elif stored_type == "rc4_only":
                            force_nt4_hash = True

                        tname = (f'{supported_etypes}_supported_'
                                 f'{requested_etypes}_requested_'
                                 f'{account_type}_account_'
                                 f'stored_{stored_type}')
                        targs = _supported_etypes, _requested_etypes, _account_type, force_nt4_hash
                        cls.generate_dynamic_test('test_etype_as', tname, *targs)
                        cls.generate_dynamic_test('test_etype_tgs', tname, *targs)

    def _test_etype_as_with_args(self, supported_bits, requested_etypes, account_type, force_nt4_hash):
        # The ticket will be encrypted with the strongest enctype for which the
        # server explicitly declares support, falling back to RC4 if the server
        # has no declared supported encryption types. The enctype of the
        # session key is the first enctype listed in the request that the
        # server supports, taking the AES-SK bit as an indication of support
        # for both AES types.

        # If none of the enctypes in the request are supported by the target
        # server, implicitly or explicitly, return ETYPE_NOSUPP.

        expected_error = 0

        if not supported_bits:
            # If msDS-SupportedEncryptionTypes is missing or set to zero, the
            # default value, provided by smb.conf, is assumed.
            supported_bits = self.default_supported_enctypes()

        # If msDS-SupportedEncryptionTypes specifies only non-etype bits, we
        # expect an error.
        if self.only_non_etype_bits_set(supported_bits):
            expected_error = KDC_ERR_ETYPE_NOSUPP

        virtual_bits = supported_bits

        if self.forced_rc4 and not (virtual_bits & rc4_bit):
            # If our fallback smb.conf option is set, force in RC4 support.
            virtual_bits |= rc4_bit

        if force_nt4_hash and not (virtual_bits & rc4_bit):
            virtual_bits |= rc4_bit

        if virtual_bits & aes256_sk_bit:
            # If strong session keys are enabled, force in the AES bits.
            virtual_bits |= aes256_bit | aes128_bit

        if account_type == self.AccountType.SERVER:
            virtual_bits |= etype_bits
            expected_error = 0

        virtual_etypes = KerberosCredentials.bits_to_etypes(virtual_bits)

        # The enctype of the session key is the first listed in the request
        # that the server supports, implicitly or explicitly.
        for requested_etype in requested_etypes:
            if requested_etype in virtual_etypes:
                expected_session_etype = requested_etype
                break
        else:
            # If there is no such enctype, expect an error.
            expected_error = KDC_ERR_ETYPE_NOSUPP

        # Get the credentials of the client and server accounts.
        creds = self.get_client_creds()
        target_creds = self._server_creds(supported=supported_bits,
                                          account_type=account_type,
                                          force_nt4_hash=force_nt4_hash)
        if account_type == self.AccountType.SERVER:
            target_supported_etypes = target_creds.tgs_supported_enctypes
            target_supported_etypes |= des_bits
            target_supported_etypes |= etype_bits
            target_creds.set_tgs_supported_enctypes(target_supported_etypes)
            supported_bits |= (target_supported_etypes & etype_bits)

        # We expect the ticket etype to be the strongest the server claims to
        # support, with a fallback to RC4.
        expected_etype = ARCFOUR_HMAC_MD5
        if not force_nt4_hash and supported_bits is not None:
            if supported_bits & aes256_bit:
                expected_etype = AES256_CTS_HMAC_SHA1_96
            elif supported_bits & aes128_bit:
                expected_etype = AES128_CTS_HMAC_SHA1_96

        # Perform the AS-REQ.
        ticket = self._as_req(creds, expected_error=expected_error,
                              target_creds=target_creds,
                              etype=requested_etypes,
                              expected_ticket_etype=expected_etype)
        if expected_error:
            # There's no more to check. Return.
            return

        # Check the etypes of the ticket and session key.
        self.assertEqual(expected_etype, ticket.decryption_key.etype)
        self.assertEqual(expected_session_etype, ticket.session_key.etype)

    def _test_etype_tgs_with_args(self, supported_bits, requested_etypes, account_type, force_nt4_hash):
        expected_error = 0

        if not supported_bits:
            # If msDS-SupportedEncryptionTypes is missing or set to zero, the
            # default value, provided by smb.conf, is assumed.
            supported_bits = self.default_supported_enctypes()

        # If msDS-SupportedEncryptionTypes specifies only non-etype bits, we
        # expect an error.
        if self.only_non_etype_bits_set(supported_bits):
            expected_error = KDC_ERR_ETYPE_NOSUPP

        virtual_bits = supported_bits

        if self.forced_rc4 and not (virtual_bits & rc4_bit):
            # If our fallback smb.conf option is set, force in RC4 support.
            virtual_bits |= rc4_bit

        if force_nt4_hash and not (virtual_bits & rc4_bit):
            virtual_bits |= rc4_bit

        if virtual_bits & aes256_sk_bit:
            # If strong session keys are enabled, force in the AES bits.
            virtual_bits |= aes256_bit | aes128_bit

        if account_type == self.AccountType.SERVER:
            virtual_bits |= etype_bits
            expected_error = 0

        virtual_etypes = KerberosCredentials.bits_to_etypes(virtual_bits)

        # The enctype of the session key is the first listed in the request
        # that the server supports, implicitly or explicitly.
        for requested_etype in requested_etypes:
            if requested_etype in virtual_etypes:
                expected_session_etype = requested_etype
                break
        else:
            # If there is no such enctype, expect an error.
            expected_error = KDC_ERR_ETYPE_NOSUPP

        # Get the credentials of the client and server accounts.
        creds = self.get_client_creds()
        tgt = self.get_tgt(creds)
        target_creds = self._server_creds(supported=supported_bits,
                                          account_type=account_type,
                                          force_nt4_hash=force_nt4_hash)
        if account_type == self.AccountType.SERVER:
            target_supported_etypes = target_creds.tgs_supported_enctypes
            target_supported_etypes |= des_bits
            target_supported_etypes |= etype_bits
            target_creds.set_tgs_supported_enctypes(target_supported_etypes)
            supported_bits |= (target_supported_etypes & etype_bits)

        # We expect the ticket etype to be the strongest the server claims to
        # support, with a fallback to RC4.
        expected_etype = ARCFOUR_HMAC_MD5
        if not force_nt4_hash and supported_bits is not None:
            if supported_bits & aes256_bit:
                expected_etype = AES256_CTS_HMAC_SHA1_96
            elif supported_bits & aes128_bit:
                expected_etype = AES128_CTS_HMAC_SHA1_96

        # Perform the TGS-REQ.
        ticket = self._tgs_req(tgt, expected_error=expected_error,
                               creds=creds, target_creds=target_creds,
                               kdc_options=str(krb5_asn1.KDCOptions('canonicalize')),
                               expected_supported_etypes=target_creds.tgs_supported_enctypes,
                               expected_ticket_etype=expected_etype,
                               etypes=requested_etypes)
        if expected_error:
            # There's no more to check. Return.
            return

        # Check the etypes of the ticket and session key.
        self.assertEqual(expected_etype, ticket.decryption_key.etype)
        self.assertEqual(expected_session_etype, ticket.session_key.etype)

    # Perform an AS-REQ for a service ticket, specifying AES, when the target
    # service only supports AES. The resulting ticket should be encrypted with
    # AES, with an AES session key.
    def test_as_aes_supported_aes_requested(self):
        creds = self.get_client_creds()
        target_creds = self._server_creds(supported=aes256_bit)

        ticket = self._as_req(creds, expected_error=0,
                              target_creds=target_creds,
                              etype=(AES256_CTS_HMAC_SHA1_96,))

        self.assertEqual(AES256_CTS_HMAC_SHA1_96, ticket.decryption_key.etype)
        self.assertEqual(AES256_CTS_HMAC_SHA1_96, ticket.session_key.etype)

    # Perform an AS-REQ for a service ticket, specifying RC4, when the target
    # service only supports AES. The request should fail with an error.
    def test_as_aes_supported_rc4_requested(self):
        creds = self.get_client_creds()
        target_creds = self._server_creds(supported=aes256_bit)

        if self.forced_rc4:
            expected_error = 0
            expected_session_etype = ARCFOUR_HMAC_MD5
        else:
            expected_error = KDC_ERR_ETYPE_NOSUPP
            expected_session_etype = AES256_CTS_HMAC_SHA1_96

        ticket = self._as_req(creds, expected_error=expected_error,
                              target_creds=target_creds,
                              etype=(ARCFOUR_HMAC_MD5,))

        if not self.forced_rc4:
            return

        self.assertEqual(AES256_CTS_HMAC_SHA1_96, ticket.decryption_key.etype)
        self.assertEqual(expected_session_etype, ticket.session_key.etype)

    # Perform an AS-REQ for a service ticket, specifying AES, when the target
    # service only supports AES, and supports AES256 session keys. The
    # resulting ticket should be encrypted with AES, with an AES session key.
    def test_as_aes_supported_aes_session_aes_requested(self):
        creds = self.get_client_creds()
        target_creds = self._server_creds(supported=aes256_bit | aes256_sk_bit)

        ticket = self._as_req(creds, expected_error=0,
                              target_creds=target_creds,
                              etype=(AES256_CTS_HMAC_SHA1_96,))

        self.assertEqual(AES256_CTS_HMAC_SHA1_96, ticket.decryption_key.etype)
        self.assertEqual(AES256_CTS_HMAC_SHA1_96, ticket.session_key.etype)

    # Perform an AS-REQ for a service ticket, specifying RC4, when the target
    # service only supports AES, and supports AES256 session keys. The request
    # should fail with an error.
    def test_as_aes_supported_aes_session_rc4_requested(self):
        creds = self.get_client_creds()
        target_creds = self._server_creds(supported=aes256_bit | aes256_sk_bit)

        if self.forced_rc4:
            expected_error = 0
            expected_session_etype = ARCFOUR_HMAC_MD5
        else:
            expected_error = KDC_ERR_ETYPE_NOSUPP
            expected_session_etype = AES256_CTS_HMAC_SHA1_96

        ticket = self._as_req(creds, expected_error=expected_error,
                     target_creds=target_creds,
                     etype=(ARCFOUR_HMAC_MD5,))

        if not self.forced_rc4:
            return

        self.assertEqual(AES256_CTS_HMAC_SHA1_96, ticket.decryption_key.etype)
        self.assertEqual(expected_session_etype, ticket.session_key.etype)

    # Perform an AS-REQ for a service ticket, specifying AES, when the target
    # service only supports RC4. The request should fail with an error.
    def test_as_rc4_supported_aes_requested(self):
        creds = self.get_client_creds()
        target_creds = self._server_creds(supported=rc4_bit)

        self._as_req(creds, expected_error=KDC_ERR_ETYPE_NOSUPP,
                     target_creds=target_creds,
                     etype=(AES256_CTS_HMAC_SHA1_96,))

    # Perform an AS-REQ for a service ticket, specifying RC4, when the target
    # service only supports RC4. The resulting ticket should be encrypted with
    # RC4, with an RC4 session key.
    def test_as_rc4_supported_rc4_requested(self):
        creds = self.get_client_creds()
        target_creds = self._server_creds(supported=rc4_bit)

        ticket = self._as_req(creds, expected_error=0,
                              target_creds=target_creds,
                              etype=(ARCFOUR_HMAC_MD5,))

        self.assertEqual(ARCFOUR_HMAC_MD5, ticket.decryption_key.etype)
        self.assertEqual(ARCFOUR_HMAC_MD5, ticket.session_key.etype)

    # Perform an AS-REQ for a service ticket, specifying AES, when the target
    # service only supports RC4, but supports AES256 session keys. The
    # resulting ticket should be encrypted with RC4, with an AES256 session
    # key.
    def test_as_rc4_supported_aes_session_aes_requested(self):
        creds = self.get_client_creds()
        target_creds = self._server_creds(supported=rc4_bit | aes256_sk_bit)

        ticket = self._as_req(creds, expected_error=0,
                              target_creds=target_creds,
                              etype=(AES256_CTS_HMAC_SHA1_96,))

        self.assertEqual(ARCFOUR_HMAC_MD5, ticket.decryption_key.etype)
        self.assertEqual(AES256_CTS_HMAC_SHA1_96, ticket.session_key.etype)

    # Perform an AS-REQ for a service ticket, specifying RC4, when the target
    # service only supports RC4, but supports AES256 session keys. The
    # resulting ticket should be encrypted with RC4, with an RC4 session key.
    def test_as_rc4_supported_aes_session_rc4_requested(self):
        creds = self.get_client_creds()
        target_creds = self._server_creds(supported=rc4_bit | aes256_sk_bit)

        ticket = self._as_req(creds, expected_error=0,
                              target_creds=target_creds,
                              etype=(ARCFOUR_HMAC_MD5,))

        self.assertEqual(ARCFOUR_HMAC_MD5, ticket.decryption_key.etype)
        self.assertEqual(ARCFOUR_HMAC_MD5, ticket.session_key.etype)

    # Perform a TGS-REQ for a service ticket, specifying AES, when the target
    # service only supports AES. The resulting ticket should be encrypted with
    # AES, with an AES session key.
    def test_tgs_aes_supported_aes_requested(self):
        creds = self.get_client_creds()
        tgt = self.get_tgt(creds)

        target_creds = self._server_creds(supported=aes256_bit)

        ticket = self._tgs_req(tgt, expected_error=0,
                               creds=creds, target_creds=target_creds,
                               etypes=(AES256_CTS_HMAC_SHA1_96,))

        self.assertEqual(AES256_CTS_HMAC_SHA1_96, ticket.decryption_key.etype)
        self.assertEqual(AES256_CTS_HMAC_SHA1_96, ticket.session_key.etype)

    # Perform a TGS-REQ for a service ticket, specifying RC4, when the target
    # service only supports AES. The request should fail with an error.
    def test_tgs_aes_supported_rc4_requested(self):
        creds = self.get_client_creds()
        tgt = self.get_tgt(creds)

        target_creds = self._server_creds(supported=aes256_bit)

        if self.forced_rc4:
            expected_error = 0
        else:
            expected_error = KDC_ERR_ETYPE_NOSUPP

        ticket = self._tgs_req(tgt, expected_error=expected_error,
                               creds=creds, target_creds=target_creds,
                               etypes=(ARCFOUR_HMAC_MD5,))

        if not self.forced_rc4:
            return

        self.assertEqual(AES256_CTS_HMAC_SHA1_96, ticket.decryption_key.etype)
        self.assertEqual(ARCFOUR_HMAC_MD5, ticket.session_key.etype)

    # Perform a TGS-REQ for a service ticket, specifying AES, when the target
    # service only supports AES, and supports AES256 session keys. The
    # resulting ticket should be encrypted with AES, with an AES session key.
    def test_tgs_aes_supported_aes_session_aes_requested(self):
        creds = self.get_client_creds()
        tgt = self.get_tgt(creds)

        target_creds = self._server_creds(supported=aes256_bit | aes256_sk_bit)

        ticket = self._tgs_req(tgt, expected_error=0,
                               creds=creds, target_creds=target_creds,
                               etypes=(AES256_CTS_HMAC_SHA1_96,))

        self.assertEqual(AES256_CTS_HMAC_SHA1_96, ticket.decryption_key.etype)
        self.assertEqual(AES256_CTS_HMAC_SHA1_96, ticket.session_key.etype)

    # Perform a TGS-REQ for a service ticket, specifying RC4, when the target
    # service only supports AES, and supports AES256 session keys. The request
    # should fail with an error.
    def test_tgs_aes_supported_aes_session_rc4_requested(self):
        creds = self.get_client_creds()
        tgt = self.get_tgt(creds)

        target_creds = self._server_creds(supported=aes256_bit | aes256_sk_bit)

        if self.forced_rc4:
            expected_error = 0
        else:
            expected_error = KDC_ERR_ETYPE_NOSUPP

        ticket = self._tgs_req(tgt, expected_error=expected_error,
                               creds=creds, target_creds=target_creds,
                               etypes=(ARCFOUR_HMAC_MD5,))

        if not self.forced_rc4:
            return

        self.assertEqual(AES256_CTS_HMAC_SHA1_96, ticket.decryption_key.etype)
        self.assertEqual(ARCFOUR_HMAC_MD5, ticket.session_key.etype)

    # Perform a TGS-REQ for a service ticket, specifying AES, when the target
    # service only supports RC4. The request should fail with an error.
    def test_tgs_rc4_supported_aes_requested(self):
        creds = self.get_client_creds()
        tgt = self.get_tgt(creds)

        target_creds = self._server_creds(supported=rc4_bit)

        self._tgs_req(tgt, expected_error=KDC_ERR_ETYPE_NOSUPP,
                      creds=creds, target_creds=target_creds,
                      etypes=(AES256_CTS_HMAC_SHA1_96,))

    # Perform a TGS-REQ for a service ticket, specifying RC4, when the target
    # service only supports RC4. The resulting ticket should be encrypted with
    # RC4, with an RC4 session key.
    def test_tgs_rc4_supported_rc4_requested(self):
        creds = self.get_client_creds()
        tgt = self.get_tgt(creds)

        target_creds = self._server_creds(supported=rc4_bit)

        ticket = self._tgs_req(tgt, expected_error=0,
                               creds=creds, target_creds=target_creds,
                               etypes=(ARCFOUR_HMAC_MD5,))

        self.assertEqual(ARCFOUR_HMAC_MD5, ticket.decryption_key.etype)
        self.assertEqual(ARCFOUR_HMAC_MD5, ticket.session_key.etype)

    # Perform a TGS-REQ for a service ticket, specifying AES, when the target
    # service only supports RC4, but supports AES256 session keys. The
    # resulting ticket should be encrypted with RC4, with an AES256 session
    # key.
    def test_tgs_rc4_supported_aes_session_aes_requested(self):
        creds = self.get_client_creds()
        tgt = self.get_tgt(creds)

        target_creds = self._server_creds(supported=rc4_bit | aes256_sk_bit)

        ticket = self._tgs_req(tgt, expected_error=0,
                               creds=creds, target_creds=target_creds,
                               etypes=(AES256_CTS_HMAC_SHA1_96,))

        self.assertEqual(ARCFOUR_HMAC_MD5, ticket.decryption_key.etype)
        self.assertEqual(AES256_CTS_HMAC_SHA1_96, ticket.session_key.etype)

    # Perform a TGS-REQ for a service ticket, specifying RC4, when the target
    # service only supports RC4, but supports AES256 session keys. The
    # resulting ticket should be encrypted with RC4, with an RC4 session key.
    def test_tgs_rc4_supported_aes_session_rc4_requested(self):
        creds = self.get_client_creds()
        tgt = self.get_tgt(creds)

        target_creds = self._server_creds(supported=rc4_bit | aes256_sk_bit)

        ticket = self._tgs_req(tgt, expected_error=0,
                               creds=creds, target_creds=target_creds,
                               etypes=(ARCFOUR_HMAC_MD5,))

        self.assertEqual(ARCFOUR_HMAC_MD5, ticket.decryption_key.etype)
        self.assertEqual(ARCFOUR_HMAC_MD5, ticket.session_key.etype)


if __name__ == "__main__":
    global_asn1_print = False
    global_hexdump = False
    import unittest
    unittest.main()
