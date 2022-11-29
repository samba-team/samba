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

sys.path.insert(0, 'bin/python')
os.environ['PYTHONUNBUFFERED'] = '1'

from samba.dcerpc import krb5pac
from samba.ndr import ndr_unpack
from samba.tests import DynamicTestCase
from samba.tests.krb5.kdc_base_test import KDCBaseTest

global_asn1_print = False
global_hexdump = False


@DynamicTestCase
class PacAlignTests(KDCBaseTest):

    base_name = 'krbpac'

    @classmethod
    def setUpDynamicTestCases(cls):
        for length in range(len(cls.base_name), 21):
            cls.generate_dynamic_test('test_pac_align',
                                      f'{length}_chars',
                                      length)

    def setUp(self):
        super().setUp()
        self.do_asn1_print = global_asn1_print
        self.do_hexdump = global_hexdump

    def _test_pac_align_with_args(self, length):
        samdb = self.get_samdb()

        account_name = self.base_name + 'a' * (length - len(self.base_name))
        creds, _ = self.create_account(samdb, account_name)

        tgt = self.get_tgt(creds, expect_pac=True)

        pac_data = self.get_ticket_pac(tgt)
        self.assertIsNotNone(pac_data)

        self.assertEqual(0, len(pac_data) & 7)

        pac = ndr_unpack(krb5pac.PAC_DATA_RAW, pac_data)
        for pac_buffer in pac.buffers:
            buffer_type = pac_buffer.type
            buffer_size = pac_buffer.ndr_size

            with self.subTest(buffer_type=buffer_type):
                if buffer_type == krb5pac.PAC_TYPE_LOGON_NAME:
                    self.assertEqual(length * 2 + 10, buffer_size)
                elif buffer_type == krb5pac.PAC_TYPE_REQUESTER_SID:
                    self.assertEqual(28, buffer_size)
                elif buffer_type in {krb5pac.PAC_TYPE_SRV_CHECKSUM,
                                     krb5pac.PAC_TYPE_KDC_CHECKSUM,
                                     krb5pac.PAC_TYPE_TICKET_CHECKSUM}:
                    self.assertEqual(0, buffer_size & 3,
                                     f'buffer type was: {buffer_type}, '
                                     f'buffer size was: {buffer_size}')
                else:
                    self.assertEqual(0, buffer_size & 7,
                                     f'buffer type was: {buffer_type}, '
                                     f'buffer size was: {buffer_size}')

                rounded_len = (buffer_size + 7) & ~7
                self.assertEqual(rounded_len, len(pac_buffer.info.remaining))


if __name__ == '__main__':
    global_asn1_print = False
    global_hexdump = False
    import unittest
    unittest.main()
