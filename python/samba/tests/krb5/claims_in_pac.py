#!/usr/bin/env python3
# Unix SMB/CIFS implementation.
# Copyright (C) Andrew Bartlett 2023
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

sys.path.insert(0, 'bin/python')
os.environ['PYTHONUNBUFFERED'] = '1'

from samba.dcerpc import krb5pac, claims
from samba.ndr import ndr_pack, ndr_unpack
from samba.tests import TestCase

class PacClaimsTests(TestCase):

    pac_data_uncompressed = bytes.fromhex(
        '08000000000000000100000000020000880000000000000006000000100000008802'
        '000000000000070000001000000098020000000000000a00000020000000a8020000'
        '000000000c000000b8000000c8020000000000000d00000090010000800300000000'
        '000011000000080000001005000000000000120000001c0000001805000000000000'
        '01100800ccccccccf001000000000000000002000000000000000000ffffffffffff'
        'ff7fffffffffffffff7f6ebd4f913c60d9016e7db9bb0561d9016e3da9863d81d901'
        '16001600040002000000000008000200000000000c00020000000000100002000000'
        '000014000200000000001800020000000000ae04000001020000010000001c000200'
        '20000000000000000000000000000000000000001e002000200002000a000c002400'
        '02002800020000000000000000001000000000000000000000000000000000000000'
        '000000000000000000000000020000002c0002000000000000000000000000000b00'
        '0000000000000b000000370032003000660064003300630033005f00310030000000'
        '00000000000000000000000000000000000000000000000000000000000000000000'
        '00000000000000000000000000000000000000000000000000000100000001020000'
        '0700000010000000000000000f000000410042004100520054004c00450054002d00'
        '440043002d00570049004e000000060000000000000005000000570049004e003200'
        '32000000040000000104000000000005150000003f1ba8749a54499be10ea4590200'
        '00003000020007000000340002000700000005000000010500000000000515000000'
        '000000000000000000000000f1010000010000000101000000000012010000000000'
        '000010000000d89573aeb6f036c4ca5f5412100000008ada43082e7dfccb7587a478'
        '8097ee903c60d9011600370032003000660064003300630033005f00310030003a00'
        '18002200580003000000160080001c00980000000000370032003000660064003300'
        '630033005f00310030004000770069006e00320032002e006500780061006d007000'
        '6c0065002e0063006f006d00000000000000570049004e00320032002e0045005800'
        '41004d0050004c0045002e0043004f004d0000000000000037003200300066006400'
        '3300630033005f003100300000000105000000000005150000003f1ba8749a54499b'
        'e10ea459ae0400000000000001100800cccccccc8001000000000000000002005801'
        '00000400020000000000580100000000000000000000000000005801000001100800'
        'cccccccc480100000000000000000200010000000400020000000000000000000000'
        '000001000000010000000300000008000200030000000c0002000600060001000000'
        '10000200140002000300030003000000180002002800020002000200040000002c00'
        '02000b000000000000000b000000370032003000660064003300630033005f003900'
        '00000000010000000000000001000000000000000b000000000000000b0000003700'
        '32003000660064003300630033005f00370000000000030000001c00020020000200'
        '2400020004000000000000000400000066006f006f00000004000000000000000400'
        '00006200610072000000040000000000000004000000620061007a0000000b000000'
        '000000000b000000370032003000660064003300630033005f003800000000000400'
        '000009000a0000000000070001000000000006000100000000000000010000000000'
        '0000000002000000010000000105000000000005150000003f1ba8749a54499be10e'
        'a459ae04000000000000'
        )

    pac_data_compressed = bytes.fromhex(
        '080000000000000001000000f8010000880000000000000006000000100000008002'
        '000000000000070000001000000090020000000000000a0000001e000000a0020000'
        '000000000c000000b0000000c0020000000000000d00000060020000700300000000'
        '00001100000008000000d005000000000000120000001c000000d805000000000000'
        '01100800cccccccce801000000000000000002000000000000000000ffffffffffff'
        'ff7fffffffffffffff7f50b330913c60d90150739abb0561d90150338a863d81d901'
        '14001400040002000000000008000200000000000c00020000000000100002000000'
        '000014000200000000001800020000000000ad04000001020000010000001c000200'
        '20000000000000000000000000000000000000001e002000200002000a000c002400'
        '02002800020000000000000000001000000000000000000000000000000000000000'
        '000000000000000000000000020000002c0002000000000000000000000000000a00'
        '0000000000000a000000370032003000660064003300630033005f00360000000000'
        '00000000000000000000000000000000000000000000000000000000000000000000'
        '00000000000000000000000000000000000000000000010000000102000007000000'
        '10000000000000000f000000410042004100520054004c00450054002d0044004300'
        '2d00570049004e000000060000000000000005000000570049004e00320032000000'
        '040000000104000000000005150000003f1ba8749a54499be10ea459020000003000'
        '02000700000034000200070000000500000001050000000000051500000000000000'
        '0000000000000000f10100000100000001010000000000120100000010000000ace7'
        'b599ff30aa486b52983210000000b50e9bea014545c97eca0b978097ee903c60d901'
        '1400370032003000660064003300630033005f003600000038001800220050000300'
        '0000140078001c00900000000000370032003000660064003300630033005f003600'
        '4000770069006e00320032002e006500780061006d0070006c0065002e0063006f00'
        '6d00570049004e00320032002e004500580041004d0050004c0045002e0043004f00'
        '4d00000000000000370032003000660064003300630033005f003600000000000105'
        '000000000005150000003f1ba8749a54499be10ea459ad0400000000000001100800'
        'cccccccc500200000000000000000200290200000400020004000000282000000000'
        '00000000000000000000290200007377878887880888070008000780080006000700'
        '07000708877707800800880088700700080008080000800000000080707877877700'
        '76770867868788000000000000000000000000000000000000000000000000000000'
        '00000000000000000000000000000800000000000000000000000000000000000000'
        '00000000000077000800800000008700000000000000850700000000000074768000'
        '00000000750587000800000066078000000080706677880080008060878708000000'
        '00800080000000000080000000000000000000000000000000000000000000000000'
        '6080080000000070000000000000000000000000000000000000000000000000fd74'
        'eaf001add6213aecf4346587eec48c323e3e1a5a32042eecf243669a581e383d2940'
        'e80e383c294463b8c0b49024f1def20df819586b086cd2ab98700923386674845663'
        'ef57e91718110c1ad4c0ac88912126d2180545e98670ea2aa002052aa54189cc318d'
        '26c46b667f18b6876262a9a4985ecdf76e5161033fd457ba020075360c837aaa3aa8'
        '2749ee8152420999b553c60195be5e5c35c4330557538772972a7d527aeca1fc6b29'
        '51ca254ac83960272a930f3194892d4729eff48e48ccfb929329ff501c356c0e8ed1'
        '8471ec70986c31da86a8090b4022c1db257514fdba4347532146648d4f99f9065e0d'
        '9a0d90d80f38389c39cb9ebe6d4e5e681e5a8a5418f591f1dbb7594a3f2aa3220ced'
        '1cd18cb49cffcc2ff18eef6caf443663640c56640000120000000200000001000000'
        '0105000000000005150000003f1ba8749a54499be10ea459ad04000000000000'
        )

    pac_data_int64_claim = bytes.fromhex(
        '080000000000000001000000f0010000880000000000000006000000100000007802'
        '000000000000070000001000000088020000000000000a0000001a00000098020000'
        '000000000c00000088000000b8020000000000000d000000d0000000400300000000'
        '000011000000080000001004000000000000120000001c0000001804000000000000'
        '01100800cccccccce001000000000000000002000000000000000000ffffffffffff'
        'ff7fffffffffffffff7f52a2a6d607cfd90152621001d1cfd901522200cc08f0d901'
        '10001000040002000000000008000200000000000c00020000000000100002000000'
        '0000140002000000000018000200000000004362000001020000010000001c000200'
        '200000000000000000000000000000000000000014001600200002000e0010002400'
        '02002800020000000000000000001000000000000000000000000000000000000000'
        '000000000000000000000000020000002c0002000000000000000000000000000800'
        '0000000000000800000075007300650072006e0061006d0065000000000000000000'
        '00000000000000000000000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000100000001020000070000000b000000'
        '000000000a000000570049004e0032004b00310039002d0044004300080000000000'
        '0000070000006500780061006d0070006c0065000000040000000104000000000005'
        '15000000bcfb8bf5af39e9b21f9b5fcd020000003000020007000000340002000700'
        '000005000000010500000000000515000000000000000000000000000000f1010000'
        '010000000101000000000012010000000000000010000000147a8762afe3366b316c'
        '936410000000e05a433ae9271bcc603d933480353ad607cfd9011000750073006500'
        '72006e0061006d006500000000000000280018001600400003000000100058001c00'
        '68000000000075007300650072006e0061006d00650040006500780061006d007000'
        '6c0065002e0063006f006d004500580041004d0050004c0045002e0043004f004d00'
        '000075007300650072006e0061006d006500010500000000000515000000bcfb8bf5'
        'af39e9b21f9b5fcd436200000000000001100800ccccccccc0000000000000000000'
        '02009800000004000200000000009800000000000000000000000000000098000000'
        '01100800cccccccc8800000000000000000002000100000004000200000000000000'
        '00000000000001000000010000000100000008000200010000000c00020001000100'
        '05000000100002000800000000000000080000006100200063006c00610069006d00'
        '0000050000000000000003000000000000002a0000000000000019fcffffffffffff'
        'e803000000000000204e000000000000000000000200000001000000010500000000'
        '000515000000bcfb8bf5af39e9b21f9b5fcd4362000000000000'
        )

    def test_unpack_raw(self):
        pac_unpacked_raw = ndr_unpack(krb5pac.PAC_DATA_RAW, self.pac_data_uncompressed)
        self.assertEqual(pac_unpacked_raw.num_buffers, 8)
        self.assertEqual(pac_unpacked_raw.version, 0)

    def confirm_uncompressed_claims(self, claim_metadata):
        self.assertEqual(claim_metadata.uncompressed_claims_set_size,
                         344)
        claims_set = claim_metadata.claims_set.claims.claims
        self.assertEqual(claims_set.claims_array_count,
                         1)
        claim_arrays = claims_set.claims_arrays
        self.assertEqual(claim_arrays[0].claims_source_type,
                         claims.CLAIMS_SOURCE_TYPE_AD)
        self.assertEqual(claim_arrays[0].claims_count,
                         3)
        claim_entries = claim_arrays[0].claim_entries
        self.assertEqual(claim_entries[0].id,
                         '720fd3c3_9')
        self.assertEqual(claim_entries[0].type,
                         claims.CLAIM_TYPE_BOOLEAN)
        self.assertEqual(claim_entries[0].values.value_count,
                         1)
        self.assertEqual(claim_entries[0].values.values[0],
                         1)

        self.assertEqual(claim_entries[1].id,
                         '720fd3c3_7')
        self.assertEqual(claim_entries[1].type,
                         claims.CLAIM_TYPE_STRING)
        self.assertEqual(claim_entries[1].values.value_count,
                         3)
        self.assertEqual(claim_entries[1].values.values[0],
                         "foo")
        self.assertEqual(claim_entries[1].values.values[1],
                         "bar")
        self.assertEqual(claim_entries[1].values.values[2],
                         "baz")

        self.assertEqual(claim_entries[2].id,
                         '720fd3c3_8')
        self.assertEqual(claim_entries[2].type,
                         claims.CLAIM_TYPE_UINT64)
        self.assertEqual(claim_entries[2].values.value_count,
                         4)
        self.assertEqual(claim_entries[2].values.values[0],
                         655369)
        self.assertEqual(claim_entries[2].values.values[1],
                         65543)
        self.assertEqual(claim_entries[2].values.values[2],
                         65542)
        self.assertEqual(claim_entries[2].values.values[3],
                         65536)

    def test_unpack_claims_pac_uncompressed(self):
        pac = ndr_unpack(krb5pac.PAC_DATA, self.pac_data_uncompressed)

        self.assertEqual(pac.num_buffers, 8)
        self.assertEqual(pac.version, 0)
        self.assertEqual(pac.buffers[0].type, krb5pac.PAC_TYPE_LOGON_INFO)
        self.assertEqual(pac.buffers[0].info.info.info3.base.account_name.string, "720fd3c3_10")

        self.assertEqual(pac.buffers[5].type, krb5pac.PAC_TYPE_CLIENT_CLAIMS_INFO)
        self.assertIsNotNone(pac.buffers[5].info.remaining)

        client_claims = ndr_unpack(claims.CLAIMS_SET_METADATA_NDR, pac.buffers[5].info.remaining)
        claim_metadata = client_claims.claims.metadata

        self.assertEqual(pac.buffers[6].type, krb5pac.PAC_TYPE_ATTRIBUTES_INFO)
        self.assertEqual(pac.buffers[7].type, krb5pac.PAC_TYPE_REQUESTER_SID)

        self.assertEqual(claim_metadata.compression_format,
                         claims.CLAIMS_COMPRESSION_FORMAT_NONE)
        self.confirm_uncompressed_claims(claim_metadata)

    def confirm_compressed_claims(self, claim_metadata):
        self.assertEqual(claim_metadata.uncompressed_claims_set_size,
                         8232)
        claims_set = claim_metadata.claims_set.claims.claims
        self.assertEqual(claims_set.claims_array_count,
                         1)
        claim_arrays = claims_set.claims_arrays
        self.assertEqual(claim_arrays[0].claims_source_type,
                         claims.CLAIMS_SOURCE_TYPE_AD)
        self.assertEqual(claim_arrays[0].claims_count,
                         5)
        claim_entries = claim_arrays[0].claim_entries
        self.assertEqual(claim_entries[0].id,
                         '720fd3c3_4')
        self.assertEqual(claim_entries[0].type,
                         claims.CLAIM_TYPE_BOOLEAN)
        self.assertEqual(claim_entries[0].values.value_count,
                         1)
        self.assertEqual(claim_entries[0].values.values[0],
                         1)

        self.assertEqual(claim_entries[1].id,
                         '720fd3c3_0')
        self.assertEqual(claim_entries[1].type,
                         claims.CLAIM_TYPE_STRING)
        self.assertEqual(claim_entries[1].values.value_count,
                         4)
        self.assertEqual(claim_entries[1].values.values[0],
                         "A first value.")
        self.assertEqual(claim_entries[1].values.values[1],
                         "A second value.")
        self.assertEqual(claim_entries[1].values.values[2],
                         "A third value.")

        self.assertEqual(claim_entries[2].id,
                         '720fd3c3_1')
        self.assertEqual(claim_entries[2].type,
                         claims.CLAIM_TYPE_STRING)
        self.assertEqual(claim_entries[2].values.value_count,
                         3)
        self.assertEqual(claim_entries[2].values.values[0],
                         "DC=win22,DC=example,DC=com")
        self.assertEqual(claim_entries[2].values.values[1],
                         "CN=Users,DC=win22,DC=example,DC=com")
        self.assertEqual(claim_entries[2].values.values[2],
                         "CN=Computers,DC=win22,DC=example,DC=com")

        self.assertEqual(claim_entries[3].id,
                         '720fd3c3_2')
        self.assertEqual(claim_entries[3].type,
                         claims.CLAIM_TYPE_UINT64)
        self.assertEqual(claim_entries[3].values.value_count,
                         4)
        self.assertEqual(claim_entries[3].values.values[0],
                         655369)
        self.assertEqual(claim_entries[3].values.values[1],
                         65543)
        self.assertEqual(claim_entries[3].values.values[2],
                         65542)
        self.assertEqual(claim_entries[3].values.values[3],
                         65536)

    def test_unpack_claims_pac_compressed(self):
        pac = ndr_unpack(krb5pac.PAC_DATA, self.pac_data_compressed)

        self.assertEqual(pac.num_buffers, 8)
        self.assertEqual(pac.version, 0)
        self.assertEqual(pac.buffers[0].type, krb5pac.PAC_TYPE_LOGON_INFO)
        self.assertEqual(pac.buffers[0].info.info.info3.base.account_name.string, "720fd3c3_6")

        self.assertEqual(pac.buffers[5].type, krb5pac.PAC_TYPE_CLIENT_CLAIMS_INFO)
        self.assertIsNotNone(pac.buffers[5].info.remaining)

        client_claims = ndr_unpack(claims.CLAIMS_SET_METADATA_NDR, pac.buffers[5].info.remaining)
        claim_metadata = client_claims.claims.metadata

        self.assertEqual(pac.buffers[6].type, krb5pac.PAC_TYPE_ATTRIBUTES_INFO)
        self.assertEqual(pac.buffers[7].type, krb5pac.PAC_TYPE_REQUESTER_SID)

        self.assertEqual(claim_metadata.compression_format,
                         claims.CLAIMS_COMPRESSION_FORMAT_XPRESS_HUFF)
        self.assertEqual(claim_metadata.claims_set_size,
                         553)
        self.confirm_compressed_claims(claim_metadata)

    def test_repack_claims_pac_uncompressed(self):
        pac = ndr_unpack(krb5pac.PAC_DATA, self.pac_data_uncompressed)
        client_claims = ndr_unpack(claims.CLAIMS_SET_METADATA_NDR, pac.buffers[5].info.remaining)
        client_claims_bytes1 = ndr_pack(client_claims)
        client_claims2 = ndr_unpack(claims.CLAIMS_SET_METADATA_NDR, client_claims_bytes1)
        client_claims_bytes2 = ndr_pack(client_claims2)
        self.assertEqual(client_claims_bytes1, client_claims_bytes2)

        claim_metadata = client_claims2.claims.metadata
        self.assertEqual(claim_metadata.compression_format,
                         claims.CLAIMS_COMPRESSION_FORMAT_NONE)
        self.confirm_uncompressed_claims(claim_metadata)

    def test_repack_claims_pac_compressed(self):
        pac = ndr_unpack(krb5pac.PAC_DATA, self.pac_data_compressed)
        client_claims = ndr_unpack(claims.CLAIMS_SET_METADATA_NDR, pac.buffers[5].info.remaining)
        client_claims_bytes1 = ndr_pack(client_claims)
        client_claims2 = ndr_unpack(claims.CLAIMS_SET_METADATA_NDR, client_claims_bytes1)
        client_claims_bytes2 = ndr_pack(client_claims2)
        self.assertEqual(client_claims_bytes1, client_claims_bytes2)

        # This confirms that after compression and decompression, we
        # still get the values we expect
        claim_metadata = client_claims2.claims.metadata
        self.assertEqual(claim_metadata.compression_format,
                         claims.CLAIMS_COMPRESSION_FORMAT_XPRESS_HUFF)
        self.assertEqual(claim_metadata.claims_set_size,
                         585)
        self.confirm_compressed_claims(claim_metadata)

    def test_repack_claims_pac_uncompressed_set_compressed(self):
        pac = ndr_unpack(krb5pac.PAC_DATA, self.pac_data_uncompressed)
        client_claims = ndr_unpack(claims.CLAIMS_SET_METADATA_NDR, pac.buffers[5].info.remaining)
        client_claims.claims.metadata.compression_format = claims.CLAIMS_COMPRESSION_FORMAT_XPRESS_HUFF
        client_claims_bytes1 = ndr_pack(client_claims)
        client_claims2 = ndr_unpack(claims.CLAIMS_SET_METADATA_NDR, client_claims_bytes1)

        # Confirm that despite setting FORMAT_XPRESS_HUFF compression is never attempted
        self.assertEqual(client_claims2.claims.metadata.uncompressed_claims_set_size,
                         344)
        self.assertEqual(client_claims2.claims.metadata.claims_set_size,
                         344)
        self.assertEqual(client_claims2.claims.metadata.compression_format,
                         claims.CLAIMS_COMPRESSION_FORMAT_NONE)

        # Confirm we match the originally uncompressed sample
        claim_metadata = client_claims2.claims.metadata
        self.confirm_uncompressed_claims(claim_metadata)

        # Finally confirm a re-pack gets identical bytes
        client_claims_bytes2 = ndr_pack(client_claims2)
        self.assertEqual(client_claims_bytes1, client_claims_bytes2)


    def test_repack_claims_pac_compressed_set_uncompressed(self):
        pac = ndr_unpack(krb5pac.PAC_DATA, self.pac_data_compressed)
        client_claims = ndr_unpack(claims.CLAIMS_SET_METADATA_NDR, pac.buffers[5].info.remaining)
        client_claims.claims.metadata.compression_format = claims.CLAIMS_COMPRESSION_FORMAT_NONE
        client_claims_bytes1 = ndr_pack(client_claims)
        client_claims2 = ndr_unpack(claims.CLAIMS_SET_METADATA_NDR, client_claims_bytes1)

        # Confirm that by setting FORMAT_NONE compression is never attempted
        self.assertEqual(client_claims2.claims.metadata.uncompressed_claims_set_size,
                         8232)
        self.assertEqual(client_claims2.claims.metadata.claims_set_size,
                         8232)
        self.assertEqual(client_claims2.claims.metadata.compression_format,
                         claims.CLAIMS_COMPRESSION_FORMAT_NONE)

        # This confirms that after pack and unpack, despite being
        # larger than the compression minimum we get add the data and
        # the values we expect for the originally-compressed data
        claim_metadata = client_claims2.claims.metadata
        self.confirm_compressed_claims(claim_metadata)

        # Finally confirm a re-pack gets identical bytes
        client_claims_bytes2 = ndr_pack(client_claims2)
        self.assertEqual(client_claims_bytes1, client_claims_bytes2)

    def test_repack_claims_pac_uncompressed_uninit_lengths(self):
        pac = ndr_unpack(krb5pac.PAC_DATA, self.pac_data_uncompressed)
        client_claims = ndr_unpack(claims.CLAIMS_SET_METADATA_NDR, pac.buffers[5].info.remaining)
        # This matches what we expect the KDC to do, which is to ask for compression always
        client_claims.claims.metadata.compression_format = claims.CLAIMS_COMPRESSION_FORMAT_XPRESS_HUFF
        client_claims.claims.metadata.uncompressed_claims_set_size = 0
        client_claims.claims.metadata.claims_set_size = 0

        client_claims_bytes1 = ndr_pack(client_claims)
        client_claims2 = ndr_unpack(claims.CLAIMS_SET_METADATA_NDR, client_claims_bytes1)

        # Confirm that the NDR code did not compress and sent FORMAT_NONE on the wire
        self.assertEqual(client_claims2.claims.metadata.uncompressed_claims_set_size,
                         344)
        self.assertEqual(client_claims2.claims.metadata.claims_set_size,
                         344)
        self.assertEqual(client_claims2.claims.metadata.compression_format,
                         claims.CLAIMS_COMPRESSION_FORMAT_NONE)

        claim_metadata = client_claims2.claims.metadata
        self.confirm_uncompressed_claims(claim_metadata)

        # Finally confirm a re-pack gets identical bytes
        client_claims_bytes2 = ndr_pack(client_claims2)
        self.assertEqual(client_claims_bytes1, client_claims_bytes2)

    def test_repack_claims_pac_compressed_uninit_lengths(self):
        pac = ndr_unpack(krb5pac.PAC_DATA, self.pac_data_compressed)
        client_claims = ndr_unpack(claims.CLAIMS_SET_METADATA_NDR, pac.buffers[5].info.remaining)
        client_claims.claims.metadata.compression_format = claims.CLAIMS_COMPRESSION_FORMAT_XPRESS_HUFF
        client_claims.claims.metadata.uncompressed_claims_set_size = 0
        client_claims.claims.metadata.claims_set_size = 0

        client_claims_bytes1 = ndr_pack(client_claims)
        client_claims2 = ndr_unpack(claims.CLAIMS_SET_METADATA_NDR, client_claims_bytes1)

        # Confirm that despite no lengths being set, the data is compressed correctly
        self.assertEqual(client_claims2.claims.metadata.uncompressed_claims_set_size,
                         8232)
        self.assertEqual(client_claims2.claims.metadata.claims_set_size,
                         585)
        self.assertEqual(client_claims2.claims.metadata.compression_format,
                         claims.CLAIMS_COMPRESSION_FORMAT_XPRESS_HUFF)

        claim_metadata = client_claims2.claims.metadata
        self.confirm_compressed_claims(claim_metadata)

        # Finally confirm a re-pack gets identical bytes
        client_claims_bytes2 = ndr_pack(client_claims2)
        self.assertEqual(client_claims_bytes1, client_claims_bytes2)

    def test_pac_int64_claims(self):
        """Test that we can parse a PAC containing INT64 claims."""

        # Decode the PAC.
        pac = ndr_unpack(krb5pac.PAC_DATA, self.pac_data_int64_claim)

        # Get the PAC buffer which contains the client claims.
        self.assertEqual(8, pac.num_buffers)
        client_claims_buf = pac.buffers[5]
        self.assertEqual(krb5pac.PAC_TYPE_CLIENT_CLAIMS_INFO,
                         client_claims_buf.type)

        # Ensure that we can decode the client claims.
        client_claims_data = client_claims_buf.info.remaining
        client_claims = ndr_unpack(claims.CLAIMS_SET_METADATA_NDR,
                                   client_claims_data)

        claims_set = client_claims.claims.metadata.claims_set.claims.claims

        # We should find a single claims array, …
        self.assertEqual(1, claims_set.claims_array_count)
        claims_array = claims_set.claims_arrays[0]
        self.assertEqual(claims.CLAIMS_SOURCE_TYPE_AD,
                         claims_array.claims_source_type)

        # …containing our INT64 claim.
        self.assertEqual(1, claims_array.claims_count)
        claim_entry = claims_array.claim_entries[0]
        self.assertEqual('a claim', claim_entry.id)
        self.assertEqual(claims.CLAIM_TYPE_INT64, claim_entry.type)

        # Ensure that the values have been decoded correctly.
        self.assertEqual([3, 42, -999, 1000, 20000], claim_entry.values.values)

        # Re-encode the claims buffer and ensure that the result is identical
        # to the original encoded claims produced by Windows.
        client_claims_packed = ndr_pack(client_claims)
        self.assertEqual(client_claims_data, client_claims_packed)


if __name__ == '__main__':
    import unittest
    unittest.main()
