#!/usr/bin/env python3
# Tests for NDR packing and unpacking of TPM 2.0 public keys
#
# Copyright (C) Gary Lockyer 2025
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

from samba.dcerpc import tpm20_rsakey_blob
from samba.ndr import ndr_pack, ndr_unpack
from samba.tests import TestCase


class Tpm20RsaKeyBlobTests(TestCase):
    def test_unpack_empty_key_blob(self):
        """
        ensure that a minimal header only TPM_KEY_BLOB
        can be unpacked, then packed into an identical bytes
        """
        key_blob = bytes.fromhex(
            "50 43 50 4D"                     # Magic value PCPM
            "2E 00 00 00"                     # header length
            "02 00 00 00"                     # type TPM 2.0
            "00 00 00 00"                     # flags
            "00 00 00 00"                     # public_length
            "00 00 00 00"                     # private length
            "00 00 00 00"                     # migration public length
            "00 00 00 00"                     # migration private length
            "00 00 00 00"                     # policy digest list length
            "00 00 00 00"                     # PCR binding length
            "00 00 00 00"                     # PCR digest length
            "00 00 00 00"                     # Encrypted secret length
            "00 00 00 00"                     # TPM 1.2 hostage blob length
            "00 00"                           # PCRA Algorithm Id
            "00 00"                           # size
            "00 01"                           # type
            "00 0B"                           # hash algorithm
            "00 00 00 00"                     # attributes
            "00 00"                           # auth_policy empty
            "00 10"                           # algorithm
            "00 14"                           # scheme
            "00 0B"                           # hash algorithm
            "00 00"                           # key bits
            "00 00 00 00"                     # exponent
            "00 00"                           # public key length
        )
        blob = ndr_unpack(tpm20_rsakey_blob.TPM20_RSAKEY_BLOB, key_blob)

        self.assertEqual(blob.type, 2)
        self.assertEqual(blob.public_key.type, 1)
        packed = ndr_pack(blob)
        self.assertEqual(key_blob, packed)

    def test_unpack_sample_key_blob(self):
        """
        ensure that a sample TPM_KEY_BLOB
        can be unpacked, then packed into an identical bytes
        """
        key_blob = bytes.fromhex(
            "50 43 50 4D"                     # Magic value PCPM
            "2E 00 00 00"                     # header length
            "02 00 00 00"                     # type TPM 2.0
            "00 00 00 00"                     # flags
            "00 00 00 00"                     # public_length
            "00 00 00 00"                     # private length
            "00 00 00 00"                     # migration public length
            "00 00 00 00"                     # migration private length
            "00 00 00 00"                     # policy digest list length
            "00 00 00 00"                     # PCR binding length
            "00 00 00 00"                     # PCR digest length
            "00 00 00 00"                     # Encrypted secret length
            "00 00 00 00"                     # TPM 1.2 hostage blob length
            "00 00"                           # PCRA Algorithm Id
            "18 01"                           # size 280 bytes
            "00 01"                           # type
            "00 0B"                           # hash algorithm
            "00 05 24 72"                     # attributes
            "00 00"                           # auth policy"
            "00 10"                           # algorithm
            "00 14"                           # scheme
            "00 0B"                           # hash algorithm
            "08 00"                           # key bits
            "00 00 00 00"                     # exponent
            "01 00"                           # size 256 bytes
            "9A 9E F6 5D E2 92 D6 D0 E5 B3 C4 35 B1 5B 36 F3"
            "9E 83 7B A9 34 AB D9 67 E1 1C 75 43 E5 B6 48 9B"
            "6E CD 8D FC 30 5F 4C B6 8E A0 69 A4 07 21 E7 D7"
            "A1 74 4A 29 BC C9 5D 78 70 C4 3B E4 20 54 BC D0"
            "AA FF 21 44 54 FC 09 08 2A CC DE 44 68 ED 9F B2"
            "3E F7 ED 82 D7 2D 28 74 42 2A 2F 55 A2 E0 DA 45"
            "F1 08 C0 83 8C 95 81 6D 92 CC A8 5D A4 B8 06 8C"
            "76 F5 68 94 E7 60 E6 F4 EE 40 50 28 6C 82 47 89"
            "07 E7 BC 0D 56 5D DA 86 57 E2 CE D3 19 A1 A2 7F"
            "56 F8 99 8B 4A 71 32 6A 57 3B F9 E5 2D 39 35 6E"
            "13 3E 84 DC 5C 96 E1 75 38 C3 AA 23 5B 68 BE 41"
            "52 49 72 7A F6 2A 8F C5 C5 E0 6C DB 99 D1 A8 84"
            "5F 70 21 87 2E A0 D2 68 D3 76 5C 9E D4 9C B5 E1"
            "72 9D 17 8B DC 11 55 09 90 8D 96 F3 68 34 DD 50"
            "63 AC 4A 74 A7 AF 0D DC 15 06 07 D7 5A B3 86 1A"
            "54 96 E0 FA 66 25 31 F5 B4 C7 97 C7 7C 70 94 E3"
        )

        blob = ndr_unpack(tpm20_rsakey_blob.TPM20_RSAKEY_BLOB, key_blob)

        self.assertEqual(blob.type, 2)
        self.assertEqual(blob.public_key.type, 1)
        packed = ndr_pack(blob)
        self.assertEqual(key_blob, packed)

if __name__ == "__main__":
    import unittest

    unittest.main()
