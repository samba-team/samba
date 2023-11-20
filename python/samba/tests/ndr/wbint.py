# -*- coding: utf-8 -*-

# Unix SMB/CIFS implementation.
# Copyright © Andrew Bartlett <abartlet@samba.org> 2021
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


"""Test of Network Data Representation (NDR) marshalling and unmarshalling."""
import samba
import samba.tests
import samba.ndr as ndr
from samba.dcerpc import winbind, security, lsa

class NdrTestCase(samba.tests.TestCase):
    def test_wbint_Principal(self):
        x = winbind.wbint_Principal()

        x.sid = security.dom_sid(security.SID_NT_SCHANNEL_AUTHENTICATION)

        x.type = lsa.SID_NAME_USER

        x.name = "fred"

        b = ndr.ndr_pack(x)

        y = ndr.ndr_unpack(winbind.wbint_Principal, b)

        self.assertEqual(x.sid, y.sid)
        self.assertEqual(x.type, y.type)
        self.assertEqual(x.name, y.name)

    def test_wbint_Principal_null_name(self):
        x = winbind.wbint_Principal()

        x.sid = security.dom_sid(security.SID_NT_SCHANNEL_AUTHENTICATION)

        x.type = lsa.SID_NAME_USER

        x.name = None

        b = ndr.ndr_pack(x)

        y = ndr.ndr_unpack(winbind.wbint_Principal, b)

        self.assertEqual(x.sid, y.sid)
        self.assertEqual(x.type, y.type)
        self.assertEqual(x.name, y.name)

    def test_wbint_Principals(self):

        principals = []

        for i in range(0, 10):
            x = winbind.wbint_Principal()

            x.sid = security.dom_sid(security.SID_NT_SCHANNEL_AUTHENTICATION)

            x.type = lsa.SID_NAME_USER

            x.name = None

            principals.append(x)

        wb_principals = winbind.wbint_Principals()
        wb_principals.num_principals = 10
        wb_principals.principals = principals

        b = ndr.ndr_pack(wb_principals)

        unpacked_principals = ndr.ndr_unpack(winbind.wbint_Principals,
                                             b)

        self.assertEqual(wb_principals.num_principals,
                         unpacked_principals.num_principals)

        for i in range(0, 10):
            x = principals[i]
            y = unpacked_principals.principals[i]
            self.assertEqual(x.sid, y.sid)
            self.assertEqual(x.type, y.type)
            self.assertEqual(x.name, y.name)

    def test_wbint_10_Principals(self):
        num = 10
        (principals, unpacked_principals) = self._test_wbint_Principals(num)

        for i in range(0, num):
            x = principals[i]
            y = unpacked_principals.principals[i]
            self.assertEqual(x.sid, y.sid)
            self.assertEqual(x.type, y.type)
            self.assertEqual(x.name, y.name)

    def test_wbint_max_token_Principals(self):
        self._test_wbint_Principals(samba._glue.ndr_token_max_list_size()+1)

    def _test_wbint_Principals(self, num):

        principals = []
        for i in range(0, num):
            x = winbind.wbint_Principal()

            x.sid = security.dom_sid(security.SID_NT_SCHANNEL_AUTHENTICATION + "-%d" % num)

            x.type = lsa.SID_NAME_USER

            x.name = "fred%d" % num

            principals.append(x)

        wb_principals = winbind.wbint_Principals()
        wb_principals.num_principals = num
        wb_principals.principals = principals

        b = ndr.ndr_pack(wb_principals)

        try:
            unpacked_principals = ndr.ndr_unpack(winbind.wbint_Principals,
                                                 b)
        except RuntimeError as e:
            self.fail(e)

        self.assertEqual(wb_principals.num_principals,
                         unpacked_principals.num_principals)

        return (principals, unpacked_principals)
