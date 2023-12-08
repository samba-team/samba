#!/usr/bin/env python3
# Unix SMB/CIFS implementation.
# Copyright (C) Catalyst.Net Ltd 2023
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

import sys
import os

sys.path.insert(0, "bin/python")
os.environ["PYTHONUNBUFFERED"] = "1"

from samba.dcerpc import gkdi, misc
from samba.ndr import ndr_pack, ndr_unpack
import samba.tests


def utf16_encoded_len(s: str) -> int:
    """Return the number of bytes required to encode a string as null‐terminated
    UTF‐16."""
    if "\x00" in s:
        raise ValueError("string contains an embedded null")

    return len(s.encode("utf-16-le")) + 2


class KeyEnvelopeTests(samba.tests.TestCase):
    key_envelope_blob = (
        b"\x01\x00\x00\x00KDSK\x02\x00\x00\x00j\x01\x00\x00\x01\x00\x00\x00"
        b"\x0e\x00\x00\x001\"\x92\x9d'\xaf;\xb7\x10V\xae\xb1\x8e\xec\xa7\x1a"
        b"\x00\x00\x00\x00\x18\x00\x00\x00\x18\x00\x00\x00e\x00x\x00a\x00m\x00"
        b"p\x00l\x00e\x00.\x00c\x00o\x00m\x00\x00\x00e\x00x\x00a\x00m\x00p\x00l\x00"
        b"e\x00.\x00c\x00o\x00m\x00\x00\x00"
    )

    root_key_id = misc.GUID("9d922231-af27-b73b-1056-aeb18eeca71a")

    domain_name = "example.com"
    forest_name = "example.com"

    def test_unpack(self):
        """Unpack a GKDI Key Envelope blob and check its fields."""

        envelope = ndr_unpack(gkdi.KeyEnvelope, self.key_envelope_blob)

        self.assertEqual(1, envelope.version)
        self.assertEqual(int.from_bytes(b"KDSK", byteorder="little"), envelope.magic)
        self.assertEqual(gkdi.ENVELOPE_FLAG_KEY_MAY_ENCRYPT_NEW_DATA, envelope.flags)

        self.assertEqual(362, envelope.l0_index)
        self.assertEqual(1, envelope.l1_index)
        self.assertEqual(14, envelope.l2_index)

        self.assertEqual(self.root_key_id, envelope.root_key_id)

        self.assertEqual(0, envelope.additional_info_len)
        self.assertFalse(envelope.additional_info)

        self.assertEqual(self.domain_name, envelope.domain_name)
        self.assertEqual(utf16_encoded_len(self.domain_name), envelope.domain_name_len)
        self.assertEqual(self.forest_name, envelope.forest_name)
        self.assertEqual(utf16_encoded_len(self.forest_name), envelope.forest_name_len)

    def test_pack(self):
        """Create a GKDI Key Envelope object and test that it packs to the
        blob we expect."""

        envelope = gkdi.KeyEnvelope()

        envelope.version = 1
        envelope.flags = gkdi.ENVELOPE_FLAG_KEY_MAY_ENCRYPT_NEW_DATA

        envelope.l0_index = 362
        envelope.l1_index = 1
        envelope.l2_index = 14

        envelope.root_key_id = self.root_key_id

        envelope.additional_info = []
        envelope.additional_info_len = 0

        envelope.domain_name = self.domain_name
        envelope.forest_name = self.forest_name

        self.assertEqual(self.key_envelope_blob, ndr_pack(envelope))


class GroupKeyEnvelopeTests(samba.tests.TestCase):
    group_key_envelope_blob = (
        b"\x01\x00\x00\x00KDSK\x00\x00\x00\x00j\x01\x00\x00\x01\x00\x00\x00"
        b"\x0e\x00\x00\x00\x8c\xc4\x8c\xdevp\x94\x97\x05m\x897{Z\x80R&\x00\x00\x00"
        b"\x1e\x00\x00\x00\x06\x00\x00\x00\x0c\x02\x00\x00\x00\x02\x00\x00"
        b"\x00\x08\x00\x00@\x00\x00\x00@\x00\x00\x00\x18\x00\x00\x00\x18\x00\x00\x00"
        b"S\x00P\x008\x000\x000\x00_\x001\x000\x008\x00_\x00C\x00T\x00R\x00_\x00"
        b"H\x00M\x00A\x00C\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x0e\x00"
        b"\x00\x00\x00\x00\x00\x00S\x00H\x00A\x005\x001\x002\x00\x00\x00D\x00H\x00"
        b"\x00\x00\x0c\x02\x00\x00DHPM\x00\x01\x00\x00\x87\xa8\xe6\x1d\xb4\xb6"
        b"f<\xff\xbb\xd1\x9ce\x19Y\x99\x8c\xee\xf6\x08f\r\xd0\xf2],\xee\xd4C^"
        b";\x00\xe0\r\xf8\xf1\xd6\x19W\xd4\xfa\xf7\xdfEa\xb2\xaa0\x16\xc3\xd9\x114\t"
        b"o\xaa;\xf4)m\x83\x0e\x9a| \x9e\x0cd\x97Qz\xbdZ\x8a\x9d0k\xcfg\xed\x91\xf9"
        b'\xe6r[GX\xc0"\xe0\xb1\xefBu\xbf{l[\xfc\x11\xd4_\x90\x88\xb9A\xf5N\xb1\xe5'
        b"\x9b\xb8\xbc9\xa0\xbf\x120\x7f\\O\xdbp\xc5\x81\xb2?v\xb6:\xca\xe1\xca\xa6"
        b"\xb7\x90-RRg5H\x8a\x0e\xf1<m\x9aQ\xbf\xa4\xab:\xd84w\x96RM\x8e\xf6\xa1"
        b"g\xb5\xa4\x18%\xd9g\xe1D\xe5\x14\x05d%\x1c\xca\xcb\x83\xe6\xb4"
        b"\x86\xf6\xb3\xca?yqP`&\xc0\xb8W\xf6\x89\x96(V\xde\xd4\x01\n\xbd\x0b"
        b"\xe6!\xc3\xa3\x96\nT\xe7\x10\xc3u\xf2cu\xd7\x01A\x03\xa4\xb5C0\xc1\x98"
        b"\xaf\x12a\x16\xd2'n\x11q_i8w\xfa\xd7\xef\t\xca\xdb\tJ\xe9\x1e\x1a"
        b"\x15\x97?\xb3,\x9bs\x13M\x0b.wPf`\xed\xbdHL\xa7\xb1\x8f!\xef T\x07\xf4"
        b"y:\x1a\x0b\xa1%\x10\xdb\xc1Pw\xbeF?\xffO\xedJ\xac\x0b\xb5U\xbe:l\x1b\x0ck"
        b"G\xb1\xbc7s\xbf~\x8cob\x90\x12(\xf8\xc2\x8c\xbb\x18\xa5Z\xe3\x13A\x00"
        b"\ne\x01\x96\xf91\xc7zW\xf2\xdd\xf4c\xe5\xe9\xec\x14Kw}\xe6*\xaa\xb8"
        b"\xa8b\x8a\xc3v\xd2\x82\xd6\xed8d\xe6y\x82B\x8e\xbc\x83\x1d\x144\x8fo/"
        b"\x91\x93\xb5\x04Z\xf2vqd\xe1\xdf\xc9g\xc1\xfb?.U\xa4\xbd\x1b\xff\xe8;"
        b"\x9c\x80\xd0R\xb9\x85\xd1\x82\xea\n\xdb*;s\x13\xd3\xfe\x14\xc8HK\x1e\x05%"
        b"\x88\xb9\xb7\xd2\xbb\xd2\xdf\x01a\x99\xec\xd0n\x15W\xcd\t\x15\xb35;\xbbd\xe0"
        b"\xec7\x7f\xd0(7\r\xf9+R\xc7\x89\x14(\xcd\xc6~\xb6\x18KR=\x1d\xb2F\xc3/c"
        b"\x07\x84\x90\xf0\x0e\xf8\xd6G\xd1H\xd4yTQ^#'\xcf\xef\x98\xc5\x82fKL\x0fl\xc4"
        b"\x16Ye\x00x\x00a\x00m\x00p\x00l\x00e\x00.\x00c\x00o\x00m\x00\x00\x00e\x00"
        b"x\x00a\x00m\x00p\x00l\x00e\x00.\x00c\x00o\x00m\x00\x00\x00D\x12\x1e\r[y"
        b'\xf4\x91\x92\xf4\xb8\xff\xc7;\x03@|Xs\xda\x051\xf9"A\xd6\xc1\x1c\xceA'
        b"\xa5\x05\x11\x84\x8f\xe3q\x81\xda\t\xcb\"\x8e\xbd\xa9p'\x0fM\xd6"
        b"\xe8\xa1E\x00\x8b\xc1\x8bw\x91\xac{\x1d\x8d\xba\x03P\x13-\xa5\xf2\xfc\x94<'"
        b"\xf3\xf6\x08\x17\xe3\xb4c\xd4\xc6\x08\xec\r\x03\x0e\xcd\xfdD\xe2\xbf\x90"
        b"\xeai\xb6\xb1x\xa9s\x88w\xeci\xf9\xb5\xc1\xc43\x1a4^\x0f\xfd\xa0He"
        b"(\x93\x95\x10\xc0\x85\xcb\x041D"
    )

    root_key_id = misc.GUID("de8cc48c-7076-9794-056d-89377b5a8052")

    kdf_algorithm = "SP800_108_CTR_HMAC"

    kdf_parameters = (
        b"\x00\x00\x00\x00\x01\x00\x00\x00\x0e\x00\x00\x00\x00\x00\x00\x00S\x00H\x00"
        b"A\x005\x001\x002\x00\x00\x00"
    )

    secret_agreement_algorithm = "DH"

    secret_agreement_parameters = (
        b"\x0c\x02\x00\x00DHPM\x00\x01\x00\x00\x87\xa8\xe6\x1d\xb4\xb6f<"
        b"\xff\xbb\xd1\x9ce\x19Y\x99\x8c\xee\xf6\x08f\r\xd0\xf2],\xee\xd4C^;\x00"
        b"\xe0\r\xf8\xf1\xd6\x19W\xd4\xfa\xf7\xdfEa\xb2\xaa0\x16\xc3\xd9\x114\to\xaa"
        b";\xf4)m\x83\x0e\x9a| \x9e\x0cd\x97Qz\xbdZ\x8a\x9d0k\xcfg\xed\x91\xf9\xe6r"
        b'[GX\xc0"\xe0\xb1\xefBu\xbf{l[\xfc\x11\xd4_\x90\x88\xb9A\xf5N\xb1\xe5\x9b\xb8'
        b"\xbc9\xa0\xbf\x120\x7f\\O\xdbp\xc5\x81\xb2?v\xb6:\xca\xe1\xca\xa6\xb7\x90"
        b"-RRg5H\x8a\x0e\xf1<m\x9aQ\xbf\xa4\xab:\xd84w\x96RM\x8e\xf6\xa1g\xb5"
        b"\xa4\x18%\xd9g\xe1D\xe5\x14\x05d%\x1c\xca\xcb\x83\xe6\xb4\x86\xf6\xb3\xca?y"
        b"qP`&\xc0\xb8W\xf6\x89\x96(V\xde\xd4\x01\n\xbd\x0b\xe6!\xc3\xa3\x96\n"
        b"T\xe7\x10\xc3u\xf2cu\xd7\x01A\x03\xa4\xb5C0\xc1\x98\xaf\x12a\x16\xd2'n\x11q_"
        b"i8w\xfa\xd7\xef\t\xca\xdb\tJ\xe9\x1e\x1a\x15\x97?\xb3,\x9bs\x13M\x0b.wPf"
        b"`\xed\xbdHL\xa7\xb1\x8f!\xef T\x07\xf4y:\x1a\x0b\xa1%\x10\xdb\xc1Pw\xbeF?"
        b"\xffO\xedJ\xac\x0b\xb5U\xbe:l\x1b\x0ckG\xb1\xbc7s\xbf~\x8cob\x90\x12(\xf8"
        b"\xc2\x8c\xbb\x18\xa5Z\xe3\x13A\x00\ne\x01\x96\xf91\xc7zW\xf2\xdd\xf4c\xe5"
        b"\xe9\xec\x14Kw}\xe6*\xaa\xb8\xa8b\x8a\xc3v\xd2\x82\xd6\xed8d\xe6y\x82"
        b"B\x8e\xbc\x83\x1d\x144\x8fo/\x91\x93\xb5\x04Z\xf2vqd\xe1\xdf\xc9g\xc1\xfb?.U"
        b"\xa4\xbd\x1b\xff\xe8;\x9c\x80\xd0R\xb9\x85\xd1\x82\xea\n\xdb*;s"
        b"\x13\xd3\xfe\x14\xc8HK\x1e\x05%\x88\xb9\xb7\xd2\xbb\xd2\xdf\x01a\x99"
        b"\xec\xd0n\x15W\xcd\t\x15\xb35;\xbbd\xe0\xec7\x7f\xd0(7\r\xf9+R\xc7\x89\x14("
        b"\xcd\xc6~\xb6\x18KR=\x1d\xb2F\xc3/c\x07\x84\x90\xf0\x0e\xf8\xd6G\xd1H\xd4yTQ"
        b"^#'\xcf\xef\x98\xc5\x82fKL\x0fl\xc4\x16Y"
    )

    domain_name = "example.com"
    forest_name = "example.com"

    l1_key = (
        b'D\x12\x1e\r[y\xf4\x91\x92\xf4\xb8\xff\xc7;\x03@|Xs\xda\x051\xf9"'
        b'A\xd6\xc1\x1c\xceA\xa5\x05\x11\x84\x8f\xe3q\x81\xda\t\xcb"\x8e\xbd'
        b"\xa9p'\x0fM\xd6\xe8\xa1E\x00\x8b\xc1\x8bw\x91\xac{\x1d\x8d\xba"
    )

    l2_key = (
        b"\x03P\x13-\xa5\xf2\xfc\x94<'\xf3\xf6\x08\x17\xe3\xb4c\xd4\xc6\x08"
        b"\xec\r\x03\x0e\xcd\xfdD\xe2\xbf\x90\xeai\xb6\xb1x\xa9s\x88w\xeci\xf9\xb5\xc1"
        b"\xc43\x1a4^\x0f\xfd\xa0He(\x93\x95\x10\xc0\x85\xcb\x041D"
    )

    def test_unpack(self):
        """Unpack a GKDI Group Key Envelope blob and check its fields."""

        envelope = ndr_unpack(gkdi.GroupKeyEnvelope, self.group_key_envelope_blob)

        self.assertEqual(1, envelope.version)
        self.assertEqual(int.from_bytes(b"KDSK", byteorder="little"), envelope.magic)
        self.assertEqual(0, envelope.flags)

        self.assertEqual(362, envelope.l0_index)
        self.assertEqual(1, envelope.l1_index)
        self.assertEqual(14, envelope.l2_index)

        self.assertEqual(self.root_key_id, envelope.root_key_id)

        self.assertEqual(512, envelope.private_key_len)
        self.assertEqual(2048, envelope.public_key_len)

        self.assertEqual(self.kdf_algorithm, envelope.kdf_algorithm)
        self.assertEqual(
            utf16_encoded_len(self.kdf_algorithm), envelope.kdf_algorithm_len
        )
        self.assertEqual(len(self.kdf_parameters), envelope.kdf_parameters_len)
        self.assertEqual(list(self.kdf_parameters), envelope.kdf_parameters)

        self.assertEqual(
            utf16_encoded_len(self.secret_agreement_algorithm),
            envelope.secret_agreement_algorithm_len,
        )
        self.assertEqual(
            self.secret_agreement_algorithm, envelope.secret_agreement_algorithm
        )
        self.assertEqual(
            len(self.secret_agreement_parameters),
            envelope.secret_agreement_parameters_len,
        )
        self.assertEqual(
            list(self.secret_agreement_parameters), envelope.secret_agreement_parameters
        )

        self.assertEqual(self.domain_name, envelope.domain_name)
        self.assertEqual(utf16_encoded_len(self.domain_name), envelope.domain_name_len)
        self.assertEqual(self.forest_name, envelope.forest_name)
        self.assertEqual(utf16_encoded_len(self.forest_name), envelope.forest_name_len)

        self.assertEqual(len(self.l1_key), envelope.l1_key_len)
        self.assertEqual(list(self.l1_key), envelope.l1_key)
        self.assertEqual(len(self.l2_key), envelope.l2_key_len)
        self.assertEqual(list(self.l2_key), envelope.l2_key)

    def test_pack(self):
        """Create a GKDI Group Key Envelope object and test that it packs to the
        blob we expect."""

        envelope = gkdi.GroupKeyEnvelope()

        envelope.version = 1
        envelope.flags = 0

        envelope.l0_index = 362
        envelope.l1_index = 1
        envelope.l2_index = 14

        envelope.root_key_id = self.root_key_id

        envelope.private_key_len = 512
        envelope.public_key_len = 2048

        envelope.kdf_algorithm = self.kdf_algorithm

        envelope.kdf_parameters = list(self.kdf_parameters)
        envelope.kdf_parameters_len = len(self.kdf_parameters)

        envelope.secret_agreement_algorithm = self.secret_agreement_algorithm

        envelope.secret_agreement_parameters = list(self.secret_agreement_parameters)
        envelope.secret_agreement_parameters_len = len(self.secret_agreement_parameters)

        envelope.domain_name = self.domain_name
        envelope.forest_name = self.forest_name

        envelope.l1_key = list(self.l1_key)
        envelope.l1_key_len = len(self.l1_key)

        envelope.l2_key = list(self.l2_key)
        envelope.l2_key_len = len(self.l2_key)

        self.assertEqual(self.group_key_envelope_blob, ndr_pack(envelope))


class KdfParametersTests(samba.tests.TestCase):
    kdf_parameters_blob = (
        b"\x00\x00\x00\x00\x01\x00\x00\x00\x0e\x00\x00\x00\x00\x00\x00\x00S\x00H\x00"
        b"A\x005\x001\x002\x00\x00\x00"
    )

    hash_algorithm = "SHA512"

    def test_unpack(self):
        """Unpack a GKDI KDF Parameters blob and check its fields."""

        kdf_parameters = ndr_unpack(gkdi.KdfParameters, self.kdf_parameters_blob)

        self.assertEqual(0, kdf_parameters.padding_0)
        self.assertEqual(1, kdf_parameters.padding_1)
        self.assertEqual(0, kdf_parameters.padding_2)

        self.assertEqual(self.hash_algorithm, kdf_parameters.hash_algorithm)
        self.assertEqual(
            utf16_encoded_len(self.hash_algorithm), kdf_parameters.hash_algorithm_len
        )

    def test_pack(self):
        """Create a GKDI KDF Parameters object and test that it packs to the
        blob we expect."""

        kdf_parameters = gkdi.KdfParameters()
        kdf_parameters.hash_algorithm = self.hash_algorithm

        self.assertEqual(self.kdf_parameters_blob, ndr_pack(kdf_parameters))


class FfcDhParametersTests(samba.tests.TestCase):
    ffc_dh_parameters_blob = (
        b"\x0c\x02\x00\x00DHPM\x00\x01\x00\x00\x87\xa8\xe6\x1d\xb4\xb6f<"
        b"\xff\xbb\xd1\x9ce\x19Y\x99\x8c\xee\xf6\x08f\r\xd0\xf2],\xee\xd4C^;\x00"
        b"\xe0\r\xf8\xf1\xd6\x19W\xd4\xfa\xf7\xdfEa\xb2\xaa0\x16\xc3\xd9\x114\to\xaa"
        b";\xf4)m\x83\x0e\x9a| \x9e\x0cd\x97Qz\xbdZ\x8a\x9d0k\xcfg\xed\x91\xf9\xe6r"
        b'[GX\xc0"\xe0\xb1\xefBu\xbf{l[\xfc\x11\xd4_\x90\x88\xb9A\xf5N\xb1\xe5\x9b\xb8'
        b"\xbc9\xa0\xbf\x120\x7f\\O\xdbp\xc5\x81\xb2?v\xb6:\xca\xe1\xca\xa6\xb7\x90"
        b"-RRg5H\x8a\x0e\xf1<m\x9aQ\xbf\xa4\xab:\xd84w\x96RM\x8e\xf6\xa1g\xb5"
        b"\xa4\x18%\xd9g\xe1D\xe5\x14\x05d%\x1c\xca\xcb\x83\xe6\xb4\x86\xf6\xb3\xca?y"
        b"qP`&\xc0\xb8W\xf6\x89\x96(V\xde\xd4\x01\n\xbd\x0b\xe6!\xc3\xa3\x96\n"
        b"T\xe7\x10\xc3u\xf2cu\xd7\x01A\x03\xa4\xb5C0\xc1\x98\xaf\x12a\x16\xd2'n\x11q_"
        b"i8w\xfa\xd7\xef\t\xca\xdb\tJ\xe9\x1e\x1a\x15\x97?\xb3,\x9bs\x13M\x0b.wPf"
        b"`\xed\xbdHL\xa7\xb1\x8f!\xef T\x07\xf4y:\x1a\x0b\xa1%\x10\xdb\xc1Pw\xbeF?"
        b"\xffO\xedJ\xac\x0b\xb5U\xbe:l\x1b\x0ckG\xb1\xbc7s\xbf~\x8cob\x90\x12(\xf8"
        b"\xc2\x8c\xbb\x18\xa5Z\xe3\x13A\x00\ne\x01\x96\xf91\xc7zW\xf2\xdd\xf4c\xe5"
        b"\xe9\xec\x14Kw}\xe6*\xaa\xb8\xa8b\x8a\xc3v\xd2\x82\xd6\xed8d\xe6y\x82"
        b"B\x8e\xbc\x83\x1d\x144\x8fo/\x91\x93\xb5\x04Z\xf2vqd\xe1\xdf\xc9g\xc1\xfb?.U"
        b"\xa4\xbd\x1b\xff\xe8;\x9c\x80\xd0R\xb9\x85\xd1\x82\xea\n\xdb*;s"
        b"\x13\xd3\xfe\x14\xc8HK\x1e\x05%\x88\xb9\xb7\xd2\xbb\xd2\xdf\x01a\x99"
        b"\xec\xd0n\x15W\xcd\t\x15\xb35;\xbbd\xe0\xec7\x7f\xd0(7\r\xf9+R\xc7\x89\x14("
        b"\xcd\xc6~\xb6\x18KR=\x1d\xb2F\xc3/c\x07\x84\x90\xf0\x0e\xf8\xd6G\xd1H\xd4yTQ"
        b"^#'\xcf\xef\x98\xc5\x82fKL\x0fl\xc4\x16Y"
    )

    field_order = (
        b"\x87\xa8\xe6\x1d\xb4\xb6f<\xff\xbb\xd1\x9ce\x19Y\x99\x8c\xee\xf6\x08"
        b"f\r\xd0\xf2],\xee\xd4C^;\x00\xe0\r\xf8\xf1\xd6\x19W\xd4\xfa\xf7\xdfE"
        b"a\xb2\xaa0\x16\xc3\xd9\x114\to\xaa;\xf4)m\x83\x0e\x9a| \x9e\x0cd\x97Qz\xbd"
        b'Z\x8a\x9d0k\xcfg\xed\x91\xf9\xe6r[GX\xc0"\xe0\xb1\xefBu\xbf{l[\xfc\x11'
        b"\xd4_\x90\x88\xb9A\xf5N\xb1\xe5\x9b\xb8\xbc9\xa0\xbf\x120\x7f\\O\xdbp\xc5"
        b"\x81\xb2?v\xb6:\xca\xe1\xca\xa6\xb7\x90-RRg5H\x8a\x0e\xf1<m\x9aQ\xbf\xa4\xab"
        b":\xd84w\x96RM\x8e\xf6\xa1g\xb5\xa4\x18%\xd9g\xe1D\xe5\x14\x05d%"
        b"\x1c\xca\xcb\x83\xe6\xb4\x86\xf6\xb3\xca?yqP`&\xc0\xb8W\xf6\x89\x96(V"
        b"\xde\xd4\x01\n\xbd\x0b\xe6!\xc3\xa3\x96\nT\xe7\x10\xc3u\xf2cu\xd7\x01A\x03"
        b"\xa4\xb5C0\xc1\x98\xaf\x12a\x16\xd2'n\x11q_i8w\xfa\xd7\xef\t\xca\xdb\tJ\xe9"
        b"\x1e\x1a\x15\x97"
    )

    generator = (
        b"?\xb3,\x9bs\x13M\x0b.wPf`\xed\xbdHL\xa7\xb1\x8f!\xef T\x07\xf4y:"
        b"\x1a\x0b\xa1%\x10\xdb\xc1Pw\xbeF?\xffO\xedJ\xac\x0b\xb5U\xbe:l\x1b\x0ckG\xb1"
        b"\xbc7s\xbf~\x8cob\x90\x12(\xf8\xc2\x8c\xbb\x18\xa5Z\xe3\x13A\x00\ne"
        b"\x01\x96\xf91\xc7zW\xf2\xdd\xf4c\xe5\xe9\xec\x14Kw}\xe6*\xaa\xb8\xa8b"
        b"\x8a\xc3v\xd2\x82\xd6\xed8d\xe6y\x82B\x8e\xbc\x83\x1d\x144\x8fo/\x91\x93"
        b"\xb5\x04Z\xf2vqd\xe1\xdf\xc9g\xc1\xfb?.U\xa4\xbd\x1b\xff\xe8;\x9c\x80"
        b"\xd0R\xb9\x85\xd1\x82\xea\n\xdb*;s\x13\xd3\xfe\x14\xc8HK\x1e\x05%\x88\xb9"
        b"\xb7\xd2\xbb\xd2\xdf\x01a\x99\xec\xd0n\x15W\xcd\t\x15\xb35;\xbbd\xe0\xec7"
        b"\x7f\xd0(7\r\xf9+R\xc7\x89\x14(\xcd\xc6~\xb6\x18KR=\x1d\xb2F\xc3/c\x07\x84"
        b"\x90\xf0\x0e\xf8\xd6G\xd1H\xd4yTQ^#'\xcf\xef\x98\xc5\x82fKL\x0fl\xc4\x16Y"
    )

    def test_unpack(self):
        """Unpack a GKDI FFC DH Parameters blob and check its fields."""

        ffc_dh_parameters = ndr_unpack(
            gkdi.FfcDhParameters, self.ffc_dh_parameters_blob
        )

        self.assertEqual(len(self.ffc_dh_parameters_blob), ffc_dh_parameters.length)
        self.assertEqual(
            int.from_bytes(b"DHPM", byteorder="little"), ffc_dh_parameters.magic
        )

        self.assertEqual(len(self.field_order), ffc_dh_parameters.key_length)
        self.assertEqual(list(self.field_order), ffc_dh_parameters.field_order)
        self.assertEqual(list(self.generator), ffc_dh_parameters.generator)

    def test_pack(self):
        """Create a GKDI FFC DH Parameters object and test that it packs to the
        blob we expect."""

        ffc_dh_parameters = gkdi.FfcDhParameters()

        ffc_dh_parameters.field_order = list(self.field_order)
        ffc_dh_parameters.generator = list(self.generator)
        self.assertEqual(len(self.field_order), len(self.generator))
        ffc_dh_parameters.key_length = len(self.field_order)

        self.assertEqual(self.ffc_dh_parameters_blob, ndr_pack(ffc_dh_parameters))


if __name__ == "__main__":
    import unittest

    unittest.main()
