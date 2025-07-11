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

    def test_unpack_tpm_key_material(self):
        """
        ensure that sample TPM 20 key material can be unpacked
        into a KeyMaterialInternal structure
        """
        key_material = bytes.fromhex(
            "50 43 50 4D"  # Magic value PCPM
            "2E 00 00 00"  # header length
            "02 00 00 00"  # type TPM 2.0
            "00 00 00 00"  # flags
            "00 00 00 00"  # public_length
            "00 00 00 00"  # private length
            "00 00 00 00"  # migration public length
            "00 00 00 00"  # migration private length
            "00 00 00 00"  # policy digest list length
            "00 00 00 00"  # PCR binding length
            "00 00 00 00"  # PCR digest length
            "00 00 00 00"  # Encrypted secret length
            "00 00 00 00"  # TPM 1.2 hostage blob length
            "00 00"  # PCRA Algorithm Id
            "18 01"  # size 280 bytes
            "00 01"  # type
            "00 0B"  # hash algorithm
            "00 05 24 72"  # attributes
            "00 00"  # auth policy"
            "00 10"  # algorithm
            "00 14"  # scheme
            "00 0B"  # hash algorithm
            "08 00"  # key bits
            "01 02 03 04"  # exponent
            "01 00"  # size 256 bytes
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

        exponent = bytes.fromhex("01 02 03 04")
        modulus = bytes.fromhex(
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
        kmi = ndr_unpack(keycredlink.KeyMaterialInternal, key_material)
        self.assertEqual(kmi.bit_size, 2048)
        self.assertEqual(len(kmi.exponent), 4)
        self.assertEqual(kmi.exponent, exponent)
        self.assertEqual(len(kmi.modulus), 256)
        self.assertEqual(kmi.modulus, modulus)

    def test_unpack_bcrypt_key_material(self):
        """
        ensure that sample bcrypt key material can be unpacked
        into a KeyMaterialInternal structure
        """
        key_material = bytes.fromhex(
            "52 53 41 31"  # Magic value RSA1
            "00 08 00 00"  # bit length, 2048
            "04 00 00 00"  # public exponent length
            "00 01 00 00"  # modulus length, 256
            "00 00 00 00"  # prime one length"
            "00 00 00 00"  # prime two length"
            "01 02 03 04"  # public exponent
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
        exponent = bytes.fromhex("01 02 03 04")
        modulus = bytes.fromhex(
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

        kmi = ndr_unpack(keycredlink.KeyMaterialInternal, key_material)
        self.assertEqual(kmi.bit_size, 2048)
        self.assertEqual(len(kmi.exponent), 4)
        self.assertEqual(kmi.exponent, exponent)
        self.assertEqual(len(kmi.modulus), 256)
        self.assertEqual(kmi.modulus, modulus)

    def test_unpack_der_key_material(self):
        """
        ensure that sample X509 public key material can be unpacked
        into a KeyMaterialInternal structure
        """
        key_material = bytes.fromhex(
            "30 82 01 22"  # Sequence 290 bytes, 2 elements
            "30 0d"  # Sequence 13 bytes, 2 elements
            # OID 9 bytes, 1.2.840.113549.1.1.1
            "06 09 2a 86 48 86 f7 0d 01 01 01"
            "05 00"  # Null
            "03 82 01 0f 00"  # Bit string, 2160 bits, 0 unused bits
            "30 82 01 0a"  # Sequence 266 bytes, 2 elements
            "02 82 01 01"  # Integer 2048 bit, 257 bytes
            # MODULUS is 257 bytes as it's most significant byte
            # is 0xbd 0b10111101 and has bit 8 set,
            # which DER Integer encoding uses as the sign bit,
            # so need the leading 00 byte to prevent the value
            # being interpreted as a negative integer
            "00 bd ae 45 8b 17 cd 3e 62 71 66 67 7f a2 46 c4"
            "47 78 79 f2 8c d4 2e 0c a0 90 1c f6 33 e1 94 89"
            "b9 44 15 e3 29 e7 b6 91 ca ab 7e c6 25 60 e3 7a"
            "c4 09 97 8a 4e 79 cb a6 1f f8 29 3f 8a 0d 45 58"
            "9b 0e bf a5 fa 1c a2 5e 31 a1 e7 ba 7e 17 62 03"
            "79 c0 07 48 11 8b fa 58 17 56 1a a1 62 d2 02 02"
            "2a 64 8d 8c 53 fa 28 7c 89 18 34 70 64 a7 08 10"
            "c9 3b 1b 2c 23 88 9c 35 50 78 d1 89 33 ce 82 b2"
            "84 f4 99 d8 3e 67 11 a1 5c 1a 64 b8 6a 3e e6 95"
            "2e 47 33 51 7e b7 62 b4 08 2c c4 87 52 00 9e 28"
            "f2 16 9f 1b c1 3a 93 6d a3 38 9b 34 39 88 85 ea"
            "38 ad c2 2b c3 7c 15 cb 8f 15 37 ed 88 62 5c 34"
            "75 6f b0 eb 5c 42 6a cd 03 cc 49 bc b4 78 14 e1"
            "5e 98 83 6f e7 19 a8 43 cb ca 07 b2 4e a4 36 60"
            "95 ac 6f e2 1d 3a 33 f6 0e 94 ae fb d2 ac 9f c2"
            "9f 5b 77 8f 46 3c ee 13 27 19 8e 68 71 27 3f 50"
            "59"
            "02 03 01 00 01"  # Integer 3 bytes EXPONENT
        )

        modulus = bytes.fromhex(
            "bd ae 45 8b 17 cd 3e 62 71 66 67 7f a2 46 c4"
            "47 78 79 f2 8c d4 2e 0c a0 90 1c f6 33 e1 94 89"
            "b9 44 15 e3 29 e7 b6 91 ca ab 7e c6 25 60 e3 7a"
            "c4 09 97 8a 4e 79 cb a6 1f f8 29 3f 8a 0d 45 58"
            "9b 0e bf a5 fa 1c a2 5e 31 a1 e7 ba 7e 17 62 03"
            "79 c0 07 48 11 8b fa 58 17 56 1a a1 62 d2 02 02"
            "2a 64 8d 8c 53 fa 28 7c 89 18 34 70 64 a7 08 10"
            "c9 3b 1b 2c 23 88 9c 35 50 78 d1 89 33 ce 82 b2"
            "84 f4 99 d8 3e 67 11 a1 5c 1a 64 b8 6a 3e e6 95"
            "2e 47 33 51 7e b7 62 b4 08 2c c4 87 52 00 9e 28"
            "f2 16 9f 1b c1 3a 93 6d a3 38 9b 34 39 88 85 ea"
            "38 ad c2 2b c3 7c 15 cb 8f 15 37 ed 88 62 5c 34"
            "75 6f b0 eb 5c 42 6a cd 03 cc 49 bc b4 78 14 e1"
            "5e 98 83 6f e7 19 a8 43 cb ca 07 b2 4e a4 36 60"
            "95 ac 6f e2 1d 3a 33 f6 0e 94 ae fb d2 ac 9f c2"
            "9f 5b 77 8f 46 3c ee 13 27 19 8e 68 71 27 3f 50"
            "59"
        )
        exponent = bytes.fromhex("01 00 01")

        kmi = ndr_unpack(keycredlink.KeyMaterialInternal, key_material)
        self.assertEqual(kmi.bit_size, 2048)
        self.assertEqual(len(kmi.exponent), 3)
        self.assertEqual(kmi.exponent, exponent)
        self.assertEqual(len(kmi.modulus), 256)
        self.assertEqual(kmi.modulus, modulus)

    def test_unpack_invalid_key_material(self):
        """
        ensure that an unknown key is rejected
        """
        key_material = b"NOT REALLY A KEY POSSIBLY A PASSWORD"
        with self.assertRaises(RuntimeError) as e:
            ndr_unpack(keycredlink.KeyMaterialInternal, key_material)

        self.assertEqual(e.exception.args[0], 10)
        self.assertEqual(e.exception.args[1], "Validate Error")

    def test_unpack_too_short_key_material(self):
        """
        ensure that key material shorter than 5 bytes is rejected
        """
        key_material = b"1234"
        with self.assertRaises(RuntimeError) as e:
            ndr_unpack(keycredlink.KeyMaterialInternal, key_material)

        self.assertEqual(e.exception.args[0], 6)
        self.assertEqual(e.exception.args[1], "Length Error")

    def test_unpack_too_long_key_material(self):
        """
        ensure that key material longer than 64KiB is rejected
        """
        key_material = b"4" * ((64 * 1024) + 1)
        with self.assertRaises(RuntimeError) as e:
            ndr_unpack(keycredlink.KeyMaterialInternal, key_material)

        self.assertEqual(e.exception.args[0], 6)
        self.assertEqual(e.exception.args[1], "Length Error")


if __name__ == "__main__":
    import unittest

    unittest.main()
