#!/usr/bin/env python3
# Tests for NDR packing and unpacking of BCRYPT_RSAPUBLIC_BLOB structures
#
# See https://learn.microsoft.com/en-us/windows/win32/api/
#             bcrypt/ns-bcrypt-bcrypt_rsakey_blob
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

from samba.dcerpc import bcrypt_rsakey_blob
from samba.ndr import ndr_pack, ndr_unpack
from samba.tests import TestCase


class BcryptRsaKeyBlobTests(TestCase):
    def test_unpack_empty_key_blob(self):
        """
        Ensure that a minimal header only BCRYPT_RSAPUBLIC_BLOB
        can be unpacked, then packed into identical bytes
        """
        empty_key_blob = bytes.fromhex(
            "52 53 41 31"  # Magic value RSA1
            "00 00 00 00"  # bit length
            "00 00 00 00"  # public exponent length
            "00 00 00 00"  # modulus length"
            "00 00 00 00"  # prime one length"
            "00 00 00 00"  # prime two length"
        )
        blob = ndr_unpack(
            bcrypt_rsakey_blob.BCRYPT_RSAPUBLIC_BLOB, empty_key_blob)

        self.assertEqual(blob.magic, 0x31415352)
        self.assertEqual(blob.bit_length, 0)
        self.assertEqual(blob.public_exponent_len, 0)
        self.assertEqual(blob.modulus_len, 0)
        self.assertEqual(blob.prime1_len_unused, 0)
        self.assertEqual(blob.prime2_len_unused, 0)
        self.assertEqual(len(blob.public_exponent), 0)
        self.assertEqual(len(blob.modulus), 0)

        packed = ndr_pack(blob)
        self.assertEqual(empty_key_blob, packed)

    def test_unpack_invalid_magic(self):
        """
        Ensure that a BCRYPT_RSAPUBLIC_BLOB with an invalid magic value is
        rejected
        """
        invalid_magic_key_blob = bytes.fromhex(
            "52 53 41 30"  # Magic value RSA0
            "00 00 00 00"  # bit length
            "00 00 00 00"  # public exponent length
            "00 00 00 00"  # modulus length
            "00 00 00 00"  # prime one length
            "00 00 00 00"  # prime two length"
        )
        with self.assertRaises(RuntimeError) as e:
            ndr_unpack(bcrypt_rsakey_blob.BCRYPT_RSAPUBLIC_BLOB,
                       invalid_magic_key_blob)

        self.assertEqual(e.exception.args[0], 13)
        self.assertEqual(e.exception.args[1], "Range Error")

    def test_unpack_extra_data(self):
        """
        Ensure that a BCRYPT_RSAPUBLIC_BLOB with extra data is
        rejected
        """
        extra_data_key_blob = bytes.fromhex(
            "52 53 41 31"  # Magic value RSA1
            "00 00 00 00"  # bit length
            "00 00 00 00"  # public exponent length
            "00 00 00 00"  # modulus length
            "00 00 00 00"  # prime one length
            "00 00 00 00"  # prime two length
            "01"           # a trailing byte of data
        )
        with self.assertRaises(RuntimeError) as e:
            ndr_unpack(bcrypt_rsakey_blob.BCRYPT_RSAPUBLIC_BLOB,
                       extra_data_key_blob)

        self.assertEqual(e.exception.args[0], 18)
        self.assertEqual(e.exception.args[1], "Unread Bytes")

    def test_unpack_missing_data(self):
        """
        Ensure that a BCRYPT_RSAPUBLIC_BLOB with missing data is
        rejected
        """
        short_key_blob = bytes.fromhex(
            "52 53 41 31"  # Magic value RSA1
            "08 00 00 00"  # bit length, 2048
            "01 00 00 00"  # public exponent length, one byte
            "02 00 00 00"  # modulus length, two bytes
            "00 00 00 00"  # prime one length must be zero
            "00 00 00 00"  # prime two length must be zero
        )
        with self.assertRaises(RuntimeError) as e:
            ndr_unpack(bcrypt_rsakey_blob.BCRYPT_RSAPUBLIC_BLOB, short_key_blob)

        self.assertEqual(e.exception.args[0], 11)
        self.assertEqual(e.exception.args[1], "Buffer Size Error")

    def test_unpack_invalid_exponent_length(self):
        """
        Ensure that a BCRYPT_RSAPUBLIC_BLOB with an invalid exponent length is
        rejected
        """
        invalid_magic_key_blob = bytes.fromhex(
            "52 53 41 31"  # Magic value RSA1
            "00 00 00 00"  # bit length
            "09 00 00 00"  # public exponent length, 9 bytes
            "00 00 00 00"  # modulus length
            "00 00 00 00"  # prime one length
            "00 00 00 00"  # prime two length"
        )
        with self.assertRaises(RuntimeError) as e:
            ndr_unpack(bcrypt_rsakey_blob.BCRYPT_RSAPUBLIC_BLOB,
                       invalid_magic_key_blob)

        self.assertEqual(e.exception.args[0], 13)
        self.assertEqual(e.exception.args[1], "Range Error")

    def test_unpack_non_zero_prime1(self):
        """
        Ensure that a BCRYPT_RSAPUBLIC_BLOB with a non zero prime 1 length is
        rejected
        """
        invalid_prime1_key_blob = bytes.fromhex(
            "52 53 41 31"  # Magic value RSA1
            "00 00 00 00"  # bit length
            "00 00 00 00"  # public exponent length, 9 bytes
            "00 00 00 00"  # modulus length
            "01 00 00 00"  # prime one length
            "00 00 00 00"  # prime two length"
        )
        with self.assertRaises(RuntimeError) as e:
            ndr_unpack(bcrypt_rsakey_blob.BCRYPT_RSAPUBLIC_BLOB,
                       invalid_prime1_key_blob)

        self.assertEqual(e.exception.args[0], 13)
        self.assertEqual(e.exception.args[1], "Range Error")

    def test_unpack_non_zero_prime2(self):
        """
        Ensure that a BCRYPT_RSAPUBLIC_BLOB with a non zero prime 2 length is
        rejected
        """
        invalid_prime2_key_blob = bytes.fromhex(
            "52 53 41 31"  # Magic value RSA1
            "00 00 00 00"  # bit length
            "00 00 00 00"  # public exponent length, 9 bytes
            "00 00 00 00"  # modulus length
            "00 00 00 00"  # prime one length
            "01 00 00 00"  # prime two length"
        )
        with self.assertRaises(RuntimeError) as e:
            ndr_unpack(bcrypt_rsakey_blob.BCRYPT_RSAPUBLIC_BLOB,
                       invalid_prime2_key_blob)

        self.assertEqual(e.exception.args[0], 13)
        self.assertEqual(e.exception.args[1], "Range Error")

    def test_unpack(self):
        """
        Ensure that a fully populated BCRYPT_RSAPUBLIC_BLOB
        can be unpacked, then packed into identical bytes
        """
        key_blob = bytes.fromhex(
            "52 53 41 31"  # Magic value RSA1
            "00 08 00 00"  # bit length, 2048
            "01 00 00 00"  # public exponent length
            "02 00 00 00"  # modulus length"
            "00 00 00 00"  # prime one length"
            "00 00 00 00"  # prime two length"
            "01"           # public exponent
            "02 03"        # modulus
        )
        blob = ndr_unpack(bcrypt_rsakey_blob.BCRYPT_RSAPUBLIC_BLOB, key_blob)

        self.assertEqual(blob.magic, 0x31415352)
        self.assertEqual(blob.bit_length, 2048)

        self.assertEqual(blob.public_exponent_len, 1)
        self.assertEqual(len(blob.public_exponent), 1)
        self.assertEqual(bytes(blob.public_exponent), bytes.fromhex("01"))

        self.assertEqual(blob.modulus_len, 2)
        self.assertEqual(len(blob.modulus), 2)
        self.assertEqual(bytes(blob.modulus), bytes.fromhex("02 03"))

        self.assertEqual(blob.prime1_len_unused, 0)
        self.assertEqual(blob.prime2_len_unused, 0)

        packed = ndr_pack(blob)
        self.assertEqual(key_blob, packed)


if __name__ == "__main__":
    import unittest

    unittest.main()
