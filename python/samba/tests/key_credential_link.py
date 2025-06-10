#!/usr/bin/env python3
# Tests for NDR packing and unpacking of msDS-KeyCredentialLink structures
#
# See [MS-ADTS] 2.2.20 Key Credential Link Structures
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

from samba.dcerpc import keycredlink
from samba.ndr import ndr_pack, ndr_unpack
from samba.tests import TestCase


class KeyCredentialLinkTests(TestCase):
    def test_unpack_empty_key_blob(self):
        """ensure that a minimal KEYCREDENTIALLINK_BLOB (only the version)
        can be unpacked, then packed into an identical bytes
        """
        empty_key_blob = bytes.fromhex(
            "00 02 00 00"  # Version 2 value 0x00000200
        )
        blob = ndr_unpack(keycredlink.KEYCREDENTIALLINK_BLOB, empty_key_blob)

        self.assertEqual(blob.version, 0x0200)
        self.assertEqual(blob.count, 0)
        self.assertEqual(len(blob.entries), 0)

        packed = ndr_pack(blob)
        self.assertEqual(empty_key_blob, packed)

    def test_unpack_empty_key_blob_invalid_version(self):
        """ensure that a KEYCREDENTIALLINK_BLOB with an invalid version
        is rejected.
        """
        invalid_version_key_blob = bytes.fromhex(
            "00 03 00 00"  # Version 3 value 0x00000300
        )
        with self.assertRaises(RuntimeError) as e:
            ndr_unpack(keycredlink.KEYCREDENTIALLINK_BLOB, invalid_version_key_blob)

        self.assertEqual(e.exception.args[0], 13)
        self.assertEqual(e.exception.args[1], "Range Error")

    def test_unpack_short_key_blob(self):
        """ensure that a KEYCREDENTIALLINK_BLOB with only 3 bytes
        is rejected.
        """
        short_key_blob = bytes.fromhex(
            "00 02 00"  # Version 2 value 0x00000200
        )
        with self.assertRaises(RuntimeError) as e:
            ndr_unpack(keycredlink.KEYCREDENTIALLINK_BLOB, short_key_blob)

        self.assertEqual(e.exception.args[0], 11)
        self.assertEqual(e.exception.args[1], "Buffer Size Error")

    def test_unpack_KeyId(self):
        """ensure that a KEYCREDENTIALLINK_BLOB with a keyId
        is correctly packed and unpacked.
        """
        source = bytes.fromhex(
            "00 02 00 00"  # Version 2 value 0x00000200
            "20 00"  # 32 bytes of data
            "01"  # a Key Id
            "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F"
            "10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F"
        )
        key_id = bytes.fromhex(
            "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F"
            "10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F"
        )
        blob = ndr_unpack(keycredlink.KEYCREDENTIALLINK_BLOB, source)

        self.assertEqual(blob.version, 0x0200)
        self.assertEqual(blob.count, 1)
        self.assertEqual(len(blob.entries), 1)
        self.assertEqual(blob.entries[0].length, 32)
        self.assertEqual(blob.entries[0].identifier, keycredlink.KeyID)
        self.assertEqual(bytes(blob.entries[0].value), key_id)

        packed = ndr_pack(blob)
        self.assertEqual(source, packed)

    def test_unpack_KeyHash(self):
        """ensure that a KEYCREDENTIALLINK_BLOB with a keyHash
        is correctly packed and unpacked.
        """
        key_blob_key_source = bytes.fromhex(
            "00 02 00 00"  # Version 2 value 0x00000200
            "20 00"  # 32 bytes of data
            "02"  # a Key Hash
            "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F"
            "10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F"
        )
        key_hash = bytes.fromhex(
            "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F"
            "10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F"
        )
        blob = ndr_unpack(keycredlink.KEYCREDENTIALLINK_BLOB, key_blob_key_source)

        self.assertEqual(blob.version, 0x0200)
        self.assertEqual(blob.count, 1)
        self.assertEqual(len(blob.entries), 1)
        self.assertEqual(blob.entries[0].length, 32)
        self.assertEqual(blob.entries[0].identifier, keycredlink.KeyHash)
        self.assertEqual(bytes(blob.entries[0].value), key_hash)

        packed = ndr_pack(blob)
        self.assertEqual(key_blob_key_source, packed)

    def test_unpack_KeyUsage(self):
        """ensure that a KEYCREDENTIALLINK_BLOB with a keyUsage
        is correctly packed and unpacked.
        """
        key_blob_key_source = bytes.fromhex(
            "00 02 00 00"  # Version 2 value 0x00000200
            "01 00"  # 1 byte of data
            "04"  # a Key Usage
            "01"  # KEY_USAGE_NGC
        )
        blob = ndr_unpack(keycredlink.KEYCREDENTIALLINK_BLOB, key_blob_key_source)

        self.assertEqual(blob.version, 0x0200)
        self.assertEqual(blob.count, 1)
        self.assertEqual(len(blob.entries), 1)
        self.assertEqual(blob.entries[0].length, 1)
        self.assertEqual(blob.entries[0].identifier, keycredlink.KeyUsage)
        self.assertEqual(blob.entries[0].value, keycredlink.KEY_USAGE_NGC)

        packed = ndr_pack(blob)
        self.assertEqual(key_blob_key_source, packed)

    def test_unpack_KeySource(self):
        """ensure that a KEYCREDENTIALLINK_BLOB with a keySource
        is correctly packed and unpacked.
        """
        blob_source = bytes.fromhex(
            "00 02 00 00"  # Version 2 value 0x00000200
            "01 00"  # 1 byte of data
            "05"  # a Key Source
            "00"  # KEY_SOURCE_AD
        )
        blob = ndr_unpack(keycredlink.KEYCREDENTIALLINK_BLOB, blob_source)

        self.assertEqual(blob.version, 0x0200)
        self.assertEqual(blob.count, 1)
        self.assertEqual(len(blob.entries), 1)
        self.assertEqual(blob.entries[0].length, 1)
        self.assertEqual(blob.entries[0].identifier, keycredlink.KeySource)
        self.assertEqual(blob.entries[0].value, keycredlink.KEY_SOURCE_AD)

        packed = ndr_pack(blob)
        self.assertEqual(blob_source, packed)

    def test_unpack_DeviceId(self):
        """ensure that a KEYCREDENTIALLINK_BLOB with a deviceId
        is correctly packed and unpacked.
        """
        blob_source = bytes.fromhex(
            "00 02 00 00"  # Version 2 value 0x00000200
            "10 00"  # 16 bytes of data
            "06"  # a Device Id
            "00 01 02 03 04 05 06 07"
            "08 09 0A 0B 0C 0D 0E 0F"
        )
        device_id = bytes.fromhex("00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F")

        blob = ndr_unpack(keycredlink.KEYCREDENTIALLINK_BLOB, blob_source)

        self.assertEqual(blob.version, 0x0200)
        self.assertEqual(blob.count, 1)
        self.assertEqual(len(blob.entries), 1)
        self.assertEqual(blob.entries[0].length, 16)
        self.assertEqual(blob.entries[0].identifier, keycredlink.DeviceId)
        self.assertEqual(bytes(blob.entries[0].value), device_id)

        packed = ndr_pack(blob)
        self.assertEqual(blob_source, packed)

    def test_unpack_CustomKeyInformation(self):
        """ensure that a KEYCREDENTIALLINK_BLOB with a short custom key
        (2 bytes) is correctly packed and unpacked.
        """
        blob_source = bytes.fromhex(
            "00 02 00 00"  # Version 2 value 0x00000200
            "02 00"  # 2 bytes of data
            "07"  # Custom Key Information
            "01"  # Version 1
            "02"  # Flags MFA not used
        )

        blob = ndr_unpack(keycredlink.KEYCREDENTIALLINK_BLOB, blob_source)

        self.assertEqual(blob.version, 0x0200)
        self.assertEqual(blob.count, 1)
        self.assertEqual(len(blob.entries), 1)
        self.assertEqual(blob.entries[0].length, 2)
        self.assertEqual(blob.entries[0].identifier, keycredlink.CustomKeyInformation)
        self.assertEqual(blob.entries[0].value.version, 1)
        self.assertEqual(blob.entries[0].value.flags, 0x02)
        self.assertFalse(blob.entries[0].value.isExtended)

        # The remaining fields should have been set to zeros
        zeros = bytes.fromhex("00 00 00 00 00 00 00 00 00 00")
        self.assertEqual(blob.entries[0].value.volType, 0x00)
        self.assertEqual(blob.entries[0].value.supportsNotification, 0x00)
        self.assertEqual(blob.entries[0].value.fekKeyVersion, 0x00)
        self.assertEqual(blob.entries[0].value.keyStrength, 0x00)
        self.assertEqual(bytes(blob.entries[0].value.reserved), zeros)
        self.assertEqual(blob.entries[0].value.count, 0)
        self.assertEqual(len(blob.entries[0].value.cki), 0)

        packed = ndr_pack(blob)
        self.assertEqual(blob_source, packed)

    def test_unpack_CustomKeyInformationExtendedNoCki(self):
        """ensure that a KEYCREDENTIALLINK_BLOB with long custom key
        information (16 bytes), and no EncodedExtendedCki is
        correctly packed and unpacked.
        """
        blob_source = bytes.fromhex(
            "00 02 00 00"  # Version 2 value 0x00000200
            "10 00"  # 16 bytes of data
            "07"  # Custom Key Information
            "01"  # Version 1
            "03"  # Flags MFA not used and attestation
            "02"  # fixed volume
            "01"  # Notification supported
            "01"  # Fek Key Version
            "01"  # weak key strength
            "00 00 00 00 00 00 00 00 00 00"  # reserved space
        )
        reserved = bytes.fromhex("00 00 00 00 00 00 00 00 00 00")

        blob = ndr_unpack(keycredlink.KEYCREDENTIALLINK_BLOB, blob_source)

        self.assertEqual(blob.version, 0x0200)
        self.assertEqual(blob.count, 1)
        self.assertEqual(len(blob.entries), 1)
        self.assertEqual(blob.entries[0].length, 16)
        self.assertEqual(blob.entries[0].identifier, keycredlink.CustomKeyInformation)
        self.assertEqual(blob.entries[0].value.version, 1)
        self.assertEqual(blob.entries[0].value.flags, 0x03)
        self.assertTrue(blob.entries[0].value.isExtended)
        self.assertEqual(blob.entries[0].value.volType, keycredlink.FDV)
        self.assertEqual(
            blob.entries[0].value.supportsNotification, keycredlink.Supported
        )
        self.assertEqual(blob.entries[0].value.fekKeyVersion, 0x01)
        self.assertEqual(blob.entries[0].value.keyStrength, keycredlink.Weak)
        self.assertEqual(bytes(blob.entries[0].value.reserved), reserved)
        self.assertEqual(blob.entries[0].value.count, 0)
        self.assertEqual(len(blob.entries[0].value.cki), 0)

        packed = ndr_pack(blob)
        self.assertEqual(blob_source, packed)

    def test_unpack_CustomKeyInformationExtendedOneCki(self):
        """ensure that a KEYCREDENTIALLINK_BLOB with long custom key
        information (16 bytes), and one EncodedExtendedCki is
        correctly packed and unpacked.
        """
        blob_source = bytes.fromhex(
            "00 02 00 00"  # Version 2 value 0x00000200
            "14 00"  # 16 byte header + 4 bytes
            "   07"  # Custom Key Information
            "   01"  # Version 1
            "   00"  # Flags MFA not used
            "   00"  # No volume type
            "   00"  # Unsupported
            "   01"  # Fek Key Version
            "   00"  # Unknown key strength
            "   00 00 00 00 00 00 00 00 00 00"  # reserved space
            "   00 02 0D 0A"
        )
        reserved = bytes.fromhex("00 00 00 00 00 00 00 00 00 00")

        blob = ndr_unpack(keycredlink.KEYCREDENTIALLINK_BLOB, blob_source)

        self.assertEqual(blob.version, 0x0200)
        self.assertEqual(blob.count, 1)
        self.assertEqual(len(blob.entries), 1)
        self.assertEqual(blob.entries[0].length, 20)
        self.assertEqual(blob.entries[0].identifier, keycredlink.CustomKeyInformation)
        self.assertEqual(blob.entries[0].value.version, 1)
        self.assertEqual(blob.entries[0].value.flags, 0x00)
        self.assertTrue(blob.entries[0].value.isExtended)
        self.assertEqual(blob.entries[0].value.volType, keycredlink.Unspecified)
        self.assertEqual(
            blob.entries[0].value.supportsNotification, keycredlink.Unsupported
        )
        self.assertEqual(blob.entries[0].value.fekKeyVersion, 1)
        self.assertEqual(blob.entries[0].value.keyStrength, keycredlink.Unknown)
        self.assertEqual(bytes(blob.entries[0].value.reserved), reserved)
        self.assertEqual(blob.entries[0].value.count, 1)
        self.assertEqual(len(blob.entries[0].value.cki), 1)
        self.assertEqual(blob.entries[0].value.cki[0].size, 2)
        self.assertEqual(blob.entries[0].value.cki[0].data, [13, 10])
        self.assertEqual(len(blob.entries[0].value.cki[0].data), 2)

        packed = ndr_pack(blob)
        self.assertEqual(blob_source, packed)

    def test_unpack_CustomKeyInformationExtendedTwoCki(self):
        """ensure that a KEYCREDENTIALLINK_BLOB with long custom key
        information (16 bytes), and two EncodedExtendedCkis is
        correctly packed and unpacked.
        """
        blob_source = bytes.fromhex(
            "00 02 00 00"  # Version 2 value 0x00000200
            "19 00"  # 16 bytes header + 9 bytes CKI info
            "07"  # Custom Key Information
            "01"  # Version 1
            "01"  # Flags Attestation
            "03"  # Removablevolume
            "01"  # Notification supported
            "01"  # Fek Key Version
            "02"  # Normal key strength
            "00 00 00 00 00 00 00 00 00 00"  # reserved space
            "00 02 0D 0A"
            "00 03 01 02 03"
        )
        reserved = bytes.fromhex("00 00 00 00 00 00 00 00 00 00")

        blob = ndr_unpack(keycredlink.KEYCREDENTIALLINK_BLOB, blob_source)

        self.assertEqual(blob.version, 0x0200)
        self.assertEqual(blob.count, 1)
        self.assertEqual(len(blob.entries), 1)
        self.assertEqual(blob.entries[0].length, 25)
        self.assertEqual(blob.entries[0].identifier, keycredlink.CustomKeyInformation)
        self.assertEqual(blob.entries[0].value.version, 1)
        self.assertEqual(
            blob.entries[0].value.flags, keycredlink.CUSTOM_KEY_INFO_FLAGS_ATTESTATION
        )
        self.assertTrue(blob.entries[0].value.isExtended)
        self.assertEqual(blob.entries[0].value.volType, keycredlink.RDV)
        self.assertEqual(
            blob.entries[0].value.supportsNotification, keycredlink.Supported
        )
        self.assertEqual(blob.entries[0].value.fekKeyVersion, 0x01)
        self.assertEqual(blob.entries[0].value.keyStrength, keycredlink.Normal)
        self.assertEqual(bytes(blob.entries[0].value.reserved), reserved)
        self.assertEqual(blob.entries[0].value.count, 2)
        self.assertEqual(len(blob.entries[0].value.cki), 2)
        self.assertEqual(blob.entries[0].value.cki[0].size, 2)
        self.assertEqual(blob.entries[0].value.cki[0].data, [13, 10])
        self.assertEqual(blob.entries[0].value.cki[1].size, 3)
        self.assertEqual(blob.entries[0].value.cki[1].data, [1, 2, 3])

        packed = ndr_pack(blob)
        self.assertEqual(blob_source, packed)

    def test_unpack_LastLogon(self):
        """ensure that a KEYCREDENTIALLINK_BLOB with a last logon is
        correctly packed and unpacked.
        """
        blob_source = bytes.fromhex(
            "00 02 00 00"  # Version 2 value 0x00000200
            "08 00"  # 8 bytes of data
            "08"  # Approximate Last Logon Timestamp
            "80 30 68 87 D0 D4 DB 01"  # Wed Jun 04 2025 09:43:22 GMT+1200
        )
        time = 0x1DBD4D087683080  # 133934606027600000 decimal
        blob = ndr_unpack(keycredlink.KEYCREDENTIALLINK_BLOB, blob_source)

        self.assertEqual(blob.version, 0x0200)
        self.assertEqual(blob.count, 1)
        self.assertEqual(len(blob.entries), 1)
        self.assertEqual(blob.entries[0].length, 8)
        self.assertEqual(
            blob.entries[0].identifier, keycredlink.KeyApproximateLastLogonTimeStamp
        )
        self.assertEqual(blob.entries[0].value, time)

        packed = ndr_pack(blob)
        self.assertEqual(blob_source, packed)

    def test_unpack_KeyCreationTime(self):
        """ensure that a KEYCREDENTIALLINK_BLOB with a key creation time is
        correctly packed and unpacked.
        """
        blob_source = bytes.fromhex(
            "00 02 00 00"  # Version 2 value 0x00000200
            "08 00"  # 8 bytes of data
            "09"  # Key Creation Time
            "80 96 26 FA DE 4D B8 01"  # Sun Sep 26 1993 08:03:02 GMT+1200
        )
        time = 0x1B84DDEFA269680  # 123934609827600000 decimal
        blob = ndr_unpack(keycredlink.KEYCREDENTIALLINK_BLOB, blob_source)

        self.assertEqual(blob.version, 0x0200)
        self.assertEqual(blob.count, 1)
        self.assertEqual(len(blob.entries), 1)
        self.assertEqual(blob.entries[0].length, 8)
        self.assertEqual(blob.entries[0].identifier, keycredlink.KeyCreationTime)
        self.assertEqual(blob.entries[0].value, time)

        packed = ndr_pack(blob)
        self.assertEqual(blob_source, packed)

    def test_unpack_full(self):
        """ensure that fully populated KEYCREDENTIALLINK_BLOB is
        correctly packed and unpacked.
        """
        source = bytes.fromhex(
            "00 02 00 00"  # Version 2 value 0x00000200
            "20 00 01"  # 32 bytes of data, identifier = key id
            "          00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F"
            "          10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F"
            "20 00 02"  # 32 bytes of data, identifier = key hash
            "          10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F"
            "          00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F"
            "40 00 03"  # 64 bytes of data, identifier = key material
            "          43 05 A2 02 C6 8F 94 48 9B 82 C4 99 C6 F2 1A 74 "
            "          42 D7 FE C1 F5 EE AE 52 B5 C7 59 DE 32 14 91 98 "
            "          44 4D 95 82 75 11 38 32 EA 7B 52 E9 1E 8E D4 14 "
            "          51 DF 93 25 39 3F E1 18 9C E5 3E 7A E6 D0 2E 77 "
            "01 00 04 01 "  # 1 byte data, identifier = key usage (KEY_USAGE_NGC)
            "01 00 05 00 "  # 1 byte data, identifier = key source (KEY_SOURCE_AD)
            "10 00 06"  # 16 bytes of data, identifier = Device Id
            "          00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F"
            "19 00"  # 16 bytes header + 9 bytes CKI info
            "   07"  # Custom Key Information
            "      01"  # Version 1
            "      02"  # Flags MFA not used
            "      01"  # Operating system volume
            "      01"  # Notification supported
            "      01"  # Fek Key Version
            "      02"  # Normal key strength
            "          00 00 00 00 00 00 00 00 00 00"  # reserved space
            "          00 02 0D 0A"  # two bytes custom key info
            "          00 03 01 02 03"  # three bytes custom key information
            "08 00 08"  # 8 bytes of data, identifier = Approximate Last Logon
            "          80 30 68 87 D0 D4 DB 01"  # Wed Jun 04 2025 09:43:22 GMT+1200
            "08 00 09"  # 8 bytes of data, identifier = Key Creation Time
            "          80 96 26 FA DE 4D B8 01"  # Sun Sep 26 1993 08:03:02 GMT+1200
        )
        blob = ndr_unpack(keycredlink.KEYCREDENTIALLINK_BLOB, source)
        self.assertEqual(len(blob.entries), 9)

        # Check the key Id
        key_id = bytes.fromhex(
            "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F"
            "10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F"
        )
        self.assertEqual(blob.entries[0].length, 32)
        self.assertEqual(blob.entries[0].identifier, keycredlink.KeyID)
        self.assertEqual(bytes(blob.entries[0].value), key_id)

        # Check the key hash
        key_hash = bytes.fromhex(
            "10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F"
            "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F"
        )
        self.assertEqual(blob.entries[1].length, 32)
        self.assertEqual(blob.entries[1].identifier, keycredlink.KeyHash)
        self.assertEqual(bytes(blob.entries[1].value), key_hash)

        # Check the key material
        key_material = bytes.fromhex(
            "43 05 A2 02 C6 8F 94 48 9B 82 C4 99 C6 F2 1A 74 "
            "42 D7 FE C1 F5 EE AE 52 B5 C7 59 DE 32 14 91 98 "
            "44 4D 95 82 75 11 38 32 EA 7B 52 E9 1E 8E D4 14 "
            "51 DF 93 25 39 3F E1 18 9C E5 3E 7A E6 D0 2E 77 "
        )
        self.assertEqual(blob.entries[2].length, 64)
        self.assertEqual(blob.entries[2].identifier, keycredlink.KeyMaterial)
        self.assertEqual(bytes(blob.entries[2].value), key_material)

        # Check the key usage
        self.assertEqual(blob.entries[3].length, 1)
        self.assertEqual(blob.entries[3].identifier, keycredlink.KeyUsage)
        self.assertEqual(blob.entries[3].value, keycredlink.KEY_USAGE_NGC)

        # Check the key source
        self.assertEqual(blob.entries[4].length, 1)
        self.assertEqual(blob.entries[4].identifier, keycredlink.KeySource)
        self.assertEqual(blob.entries[4].value, keycredlink.KEY_SOURCE_AD)

        # Check the key device id
        device_id = bytes.fromhex("00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F")
        self.assertEqual(blob.entries[5].length, 16)
        self.assertEqual(blob.entries[5].identifier, keycredlink.DeviceId)
        self.assertEqual(bytes(blob.entries[5].value), device_id)

        # Check custom key information
        reserved = bytes.fromhex("00 00 00 00 00 00 00 00 00 00")

        self.assertEqual(blob.entries[6].length, 25)
        self.assertEqual(blob.entries[6].identifier, keycredlink.CustomKeyInformation)
        self.assertEqual(blob.entries[6].value.version, 1)
        self.assertEqual(
            blob.entries[6].value.flags, keycredlink.CUSTOM_KEY_INFO_FLAGS_MFA_NOT_USED
        )
        self.assertTrue(blob.entries[6].value.isExtended)
        self.assertEqual(blob.entries[6].value.volType, keycredlink.OSV)
        self.assertEqual(
            blob.entries[6].value.supportsNotification, keycredlink.Supported
        )
        self.assertEqual(blob.entries[6].value.fekKeyVersion, 0x01)
        self.assertEqual(blob.entries[6].value.keyStrength, keycredlink.Normal)
        self.assertEqual(bytes(blob.entries[6].value.reserved), reserved)
        # Check the EncodedExtendedCKI entries
        self.assertEqual(blob.entries[6].value.count, 2)
        self.assertEqual(len(blob.entries[6].value.cki), 2)

        self.assertEqual(blob.entries[6].value.cki[0].size, 2)
        self.assertEqual(blob.entries[6].value.cki[0].data, [13, 10])
        self.assertEqual(blob.entries[6].value.cki[1].size, 3)
        self.assertEqual(blob.entries[6].value.cki[1].data, [1, 2, 3])

        # check last logon
        last_logon = 0x1DBD4D087683080  # 133934606027600000 decimal
        self.assertEqual(blob.entries[7].length, 8)
        self.assertEqual(
            blob.entries[7].identifier, keycredlink.KeyApproximateLastLogonTimeStamp
        )
        self.assertEqual(blob.entries[7].value, last_logon)

        # check key creation time
        key_created = 0x1B84DDEFA269680  # 123934609827600000 decimal
        self.assertEqual(blob.entries[8].length, 8)
        self.assertEqual(blob.entries[8].identifier, keycredlink.KeyCreationTime)
        self.assertEqual(blob.entries[8].value, key_created)

        # Check that when the object is packed, the bytes generated equal
        # the source.
        packed = ndr_pack(blob)
        self.assertEqual(source, packed)


if __name__ == "__main__":
    import unittest

    unittest.main()
