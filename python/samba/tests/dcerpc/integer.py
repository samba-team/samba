# Unix SMB/CIFS implementation.
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2015
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

"""Tests for integer handling in PIDL generated bindings samba.dcerpc.*"""

from samba.dcerpc import server_id, misc, srvsvc, samr
import samba.tests


class IntegerTests(samba.tests.TestCase):

    def test_uint32_into_hyper(self):
        s = server_id.server_id()
        s.unique_id = server_id.NONCLUSTER_VNN
        self.assertEqual(s.unique_id, 0xFFFFFFFF)

    def test_int_into_hyper(self):
        s = server_id.server_id()
        s.unique_id = 1
        self.assertEqual(s.unique_id, 1)

    def test_negative_int_into_hyper(self):
        s = server_id.server_id()

        def assign():
            s.unique_id = -1
        self.assertRaises(OverflowError, assign)

    def test_hyper_into_uint32(self):
        s = server_id.server_id()

        def assign():
            s.vnn = server_id.SERVERID_UNIQUE_ID_NOT_TO_VERIFY
        self.assertRaises(OverflowError, assign)

    def test_hyper_into_int32(self):
        s = srvsvc.NetRemoteTODInfo()

        def assign():
            s.timezone = server_id.SERVERID_UNIQUE_ID_NOT_TO_VERIFY
        self.assertRaises(OverflowError, assign)

    def test_int_into_int32(self):
        s = srvsvc.NetRemoteTODInfo()
        s.timezone = 5
        self.assertEqual(s.timezone, 5)

    def test_uint32_into_int32(self):
        s = srvsvc.NetRemoteTODInfo()

        def assign():
            s.timezone = server_id.NONCLUSTER_VNN
        self.assertRaises(OverflowError, assign)

    def test_long_into_int32(self):
        s = srvsvc.NetRemoteTODInfo()
        # here we force python2 to convert its 32/64 bit python int into
        # an arbitrarily long python long, then reduce the number back
        # down to something that would fit in an int anyway. In a pure
        # python2 world, you could achieve the same thing by writing
        #    s.timezone = 5L
        # but that is a syntax error in py3.
        s.timezone = (5 << 65) >> 65
        self.assertEqual(s.timezone, 5)

    def test_larger_long_int_into_int32(self):
        s = srvsvc.NetRemoteTODInfo()

        def assign():
            s.timezone = 2147483648
        self.assertRaises(OverflowError, assign)

    def test_larger_int_into_int32(self):
        s = srvsvc.NetRemoteTODInfo()
        s.timezone = 2147483647
        self.assertEqual(s.timezone, 2147483647)

    def test_float_into_int32(self):
        s = srvsvc.NetRemoteTODInfo()

        def assign():
            s.timezone = 2.5
        self.assertRaises(TypeError, assign)

    def test_int_float_into_int32(self):
        s = srvsvc.NetRemoteTODInfo()

        def assign():
            s.timezone = 2.0
        self.assertRaises(TypeError, assign)

    def test_negative_int_into_int32(self):
        s = srvsvc.NetRemoteTODInfo()
        s.timezone = -2147483648
        self.assertEqual(s.timezone, -2147483648)

    def test_negative_into_uint32(self):
        s = server_id.server_id()

        def assign():
            s.vnn = -1
        self.assertRaises(OverflowError, assign)

    def test_hyper_into_uint16(self):
        g = misc.GUID()

        def assign():
            g.time_mid = server_id.SERVERID_UNIQUE_ID_NOT_TO_VERIFY
        self.assertRaises(OverflowError, assign)

    def test_int_into_uint16(self):
        g = misc.GUID()

        def assign():
            g.time_mid = 200000
        self.assertRaises(OverflowError, assign)

    def test_negative_int_into_uint16(self):
        g = misc.GUID()

        def assign():
            g.time_mid = -2
        self.assertRaises(OverflowError, assign)

    def test_enum_into_uint16(self):
        g = misc.GUID()
        g.time_mid = misc.SEC_CHAN_DOMAIN
        self.assertEqual(g.time_mid, misc.SEC_CHAN_DOMAIN)

    def test_bitmap_into_uint16(self):
        g = misc.GUID()
        g.time_mid = misc.SV_TYPE_WFW
        self.assertEqual(g.time_mid, misc.SV_TYPE_WFW)

    def test_overflow_bitmap_into_uint16(self):
        g = misc.GUID()

        def assign():
            g.time_mid = misc.SV_TYPE_LOCAL_LIST_ONLY
        self.assertRaises(OverflowError, assign)

    def test_overflow_bitmap_into_uint16_2(self):
        g = misc.GUID()

        def assign():
            g.time_mid = misc.SV_TYPE_DOMAIN_ENUM
        self.assertRaises(OverflowError, assign)

    def test_hyper_into_int64(self):
        s = samr.DomInfo1()

        def assign():
            s.max_password_age = server_id.SERVERID_UNIQUE_ID_NOT_TO_VERIFY
        self.assertRaises(OverflowError, assign)

    def test_int_into_int64(self):
        s = samr.DomInfo1()
        s.max_password_age = 5
        self.assertEqual(s.max_password_age, 5)

    def test_negative_int_into_int64(self):
        s = samr.DomInfo1()
        s.max_password_age = -5
        self.assertEqual(s.max_password_age, -5)

    def test_larger_int_into_int64(self):
        s = samr.DomInfo1()
        s.max_password_age = server_id.NONCLUSTER_VNN
        self.assertEqual(s.max_password_age, 0xFFFFFFFF)

    def test_larger_negative_int_into_int64(self):
        s = samr.DomInfo1()
        s.max_password_age = -2147483649
        self.assertEqual(s.max_password_age, -2147483649)

    def test_int_list_over_list(self):
        g = misc.GUID()
        g.node = [5, 0, 5, 0, 7, 4]
        self.assertEqual(g.node[0], 5)

    def test_long_int_list_over_uint8_list(self):
        g = misc.GUID()
        g.node = [5, 0, 5, 0, 7, 4]
        self.assertEqual(g.node[0], 5)

    def test_negative_list_over_uint8_list(self):
        g = misc.GUID()

        def assign():
            g.node = [-1, 0, 5, 0, 7, 4]
        self.assertRaises(OverflowError, assign)

    def test_overflow_list_over_uint8_list(self):
        g = misc.GUID()

        def assign():
            g.node = [256, 0, 5, 0, 7, 4]
        self.assertRaises(OverflowError, assign)

    def test_short_list_over_uint8_list(self):
        g = misc.GUID()

        def assign():
            g.node = [5, 0, 5]
        self.assertRaises(TypeError, assign)

    def test_long_list_over_uint8_list(self):
        g = misc.GUID()

        def assign():
            g.node = [5, 0, 5, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        self.assertRaises(TypeError, assign)

    # Due to our PIDL bindings generating a python List, modifications
    # to a list of non-objects are not reflected in the C list
    # (modifications objects in lists of objects work because the
    # objects are modified), so changes essentially vanish and are not
    # type checked either.
    def test_assign_into_uint8_list(self):
        g = misc.GUID()
        g.node[1] = 5
        self.assertEqual(g.node[1], 5)

    def test_negative_into_uint8_list(self):
        g = misc.GUID()

        def assign():
            g.node[1] = -1
        self.assertRaises(OverflowError, assign)

    def test_overflow_into_uint8_list(self):
        g = misc.GUID()

        def assign():
            g.node[1] = 256
        self.assertRaises(OverflowError, assign)
