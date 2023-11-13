#!/usr/bin/env python3
# Unix SMB/CIFS implementation.
# Copyright (C) Catalyst.Net Ltd 2023
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

from samba.dcerpc import gmsa
from samba.ndr import ndr_pack, ndr_unpack
import samba.tests


class GmsaTests(samba.tests.TestCase):
    managed_password_blob = (
        b'\x01\x00\x00\x00"\x01\x00\x00\x10\x00\x00\x00\x12\x01\x1a\x01g\x86W\xa1'
        b'\x13nT\x7fF\xeey\x88\xc8\x08\xd9\x04\xed\x0eK\x05\x92\xf8\x9e\xb8+\xd2\x92h'
        b'Xg\xc3\x11\x9d\xd6\xea\xae\xf5\x81\n\x1a\xa4\xe0\x8eI|\xc3\x11c'
        b'\xb2\xe7\x99\xe6\xeaf\xe3\x02,\x10\x0b\xf5\x95\x85\xa3FBt\xeb\xad$\x88\xfc('
        b'\xac\xbd\x10\xa9\xb4M\xdeCjm5\xff\xf0\xe9Z\xe7\x906\t\xe8%"\n\xd3\r\xb6\xa8k'
        b'\xb5D\xfa4\x0f\x86M-8\x95\x19=@\x07\xdfrG\x8dq\xce?x\x9b\xb19\xc4\xc1\xcf'
        b"\xfdm9\x94\x8c\n\xfaje\xe3\xf5\xf8\xf9\r\x8cp\xf7',\xe6Z?c'\x93\xeb\x0eF"
        b'\x97\xe5v\xc2\x1f6\xacU\xf4\x16z"\xb4\xeb\xb2Y<-"\xdcJ\xc8\xd4\xcaE_)\x9a'
        b'\x18+\x8dM\x8d\xd1#-\xde\x1e\xfe:\xca\xf1K\x13tS\x19_EE_]H\xa0\xc4A'
        b'\x91;\x80\xf9MF\x96\xb1q7\x9bZ\xc3\xb0,P\x1c\xf8\xe1kC\xbe\xac\xa5"cA\x1d'
        b'\\\xf7r\xe7c\xe8\xd2\x9ap\xa1)>r\x18\xa1\xe3\x00\x00t\x95\x01i\x80\x17'
        b'\x00\x00t71\xb6\x7f\x17\x00\x00'
    )

    current_password = (
        b'g\x86W\xa1\x13nT\x7fF\xeey\x88\xc8\x08\xd9\x04\xed\x0eK\x05\x92\xf8\x9e\xb8'
        b'+\xd2\x92hXg\xc3\x11\x9d\xd6\xea\xae\xf5\x81\n\x1a\xa4\xe0\x8eI|\xc3\x11c'
        b'\xb2\xe7\x99\xe6\xeaf\xe3\x02,\x10\x0b\xf5\x95\x85\xa3FBt\xeb\xad$\x88\xfc('
        b'\xac\xbd\x10\xa9\xb4M\xdeCjm5\xff\xf0\xe9Z\xe7\x906\t\xe8%"\n\xd3\r\xb6\xa8k'
        b'\xb5D\xfa4\x0f\x86M-8\x95\x19=@\x07\xdfrG\x8dq\xce?x\x9b\xb19\xc4\xc1\xcf'
        b"\xfdm9\x94\x8c\n\xfaje\xe3\xf5\xf8\xf9\r\x8cp\xf7',\xe6Z?c'\x93\xeb\x0eF"
        b'\x97\xe5v\xc2\x1f6\xacU\xf4\x16z"\xb4\xeb\xb2Y<-"\xdcJ\xc8\xd4\xcaE_)\x9a'
        b'\x18+\x8dM\x8d\xd1#-\xde\x1e\xfe:\xca\xf1K\x13tS\x19_EE_]H\xa0\xc4A'
        b'\x91;\x80\xf9MF\x96\xb1q7\x9bZ\xc3\xb0,P\x1c\xf8\xe1kC\xbe\xac\xa5"cA\x1d'
        b'\\\xf7r\xe7c\xe8\xd2\x9ap\xa1)>r\x18\xa1\xe3'
    )

    query_interval = 0x178069019574
    unchanged_interval = 0x177fb6313774

    def test_managed_password_blob_unpack(self):
        """Unpack a GMSA Managed Password blob and check its fields."""

        managed_password = ndr_unpack(gmsa.MANAGEDPASSWORD_BLOB,
                                      self.managed_password_blob)

        self.assertEqual(1, managed_password.version)
        self.assertEqual(0, managed_password.reserved)
        self.assertEqual(len(self.managed_password_blob),
                         managed_password.length)

        self.assertEqual(self.current_password,
                         managed_password.passwords.current)
        self.assertIsNone(managed_password.passwords.previous)

        self.assertEqual(self.query_interval,
                         managed_password.passwords.query_interval)
        self.assertEqual(self.unchanged_interval,
                         managed_password.passwords.unchanged_interval)

    def test_managed_password_blob_pack(self):
        """Create a GMSA Managed Password blob and test that it packs to the
        blob we expect."""

        managed_password = gmsa.MANAGEDPASSWORD_BLOB()

        managed_password.passwords.current = self.current_password
        managed_password.passwords.query_interval = self.query_interval
        managed_password.passwords.unchanged_interval = self.unchanged_interval

        self.assertEqual(self.managed_password_blob,
                         ndr_pack(managed_password))


if __name__ == '__main__':
    import unittest

    unittest.main()
