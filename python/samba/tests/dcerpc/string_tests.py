# Unix SMB/CIFS implementation.
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2016
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

"""Tests for string and unicode handling in PIDL generated bindings
samba.dcerpc.*"""

from samba.dcerpc import drsblobs
import samba.tests
from samba.ndr import ndr_unpack, ndr_pack
import talloc
import gc


class TestException(Exception):
    pass


class StringTests(samba.tests.TestCase):

    def setUp(self):
        super(StringTests, self).setUp()
        talloc.enable_null_tracking()
        self.startup_blocks = talloc.total_blocks()

    def tearDown(self):
        super(StringTests, self).tearDown()
        gc.collect()
        if talloc.total_blocks() != self.startup_blocks:
            talloc.report_full()
            self.fail("it appears we are leaking memory")

    def test_string_from_python(self):
        info = drsblobs.repsFromTo2OtherInfo()
        info.dns_name1 = "hello.example.com"
        info.dns_name2 = "goodbye.example.com"
        gc.collect()
        self.assertIsNotNone(info)
        self.assertEqual(info.dns_name1, "hello.example.com")
        self.assertEqual(info.dns_name2, "goodbye.example.com")

        info.dns_name1 = ""
        info.dns_name2 = "goodbye.example.com"

        self.assertEqual(info.dns_name1, "")
        self.assertEqual(info.dns_name2, "goodbye.example.com")

        info.dns_name2 = None

        self.assertEqual(info.dns_name1, "")
        self.assertIsNone(info.dns_name2)

    def test_string_with_exception(self):
        try:
            self.test_string_from_python()
            raise TestException()
        except TestException:
            pass

    def test_string_from_python_function(self):
        def get_info():
            info = drsblobs.repsFromTo2OtherInfo()
            info.dns_name1 = "1.example.com"
            info.dns_name2 = "2.example.com"
            return info

        info = get_info()
        gc.collect()
        self.assertIsNotNone(info)
        self.assertEqual(info.dns_name1, "1.example.com")
        self.assertEqual(info.dns_name2, "2.example.com")

    def test_string_modify_in_place(self):
        info = drsblobs.repsFromTo2OtherInfo()
        info.dns_name1 = "1.example.com"
        info.dns_name2 = "%s.example.com"
        gc.collect()
        self.assertIsNotNone(info)
        self.assertEqual(info.dns_name1, "1.example.com")
        self.assertEqual(info.dns_name2, "%s.example.com")
        info.dns_name1 += ".co.nz"
        info.dns_name2 %= 2
        self.assertEqual(info.dns_name1, "1.example.com.co.nz")
        self.assertEqual(info.dns_name2, "2.example.com")
        del info

    def test_string_delete(self):
        gc.collect()
        info = drsblobs.repsFromTo2OtherInfo()
        info.dns_name1 = "1.example.com"
        info.dns_name2 = "2.example.com"
        info.dns_name1 = None
        try:
            del info.dns_name2
        except AttributeError:
            pass

        self.assertIsNotNone(info)
        self.assertIsNone(info.dns_name1)
        self.assertIsNotNone(info.dns_name2)


class StringTestsWithoutLeakCheck(samba.tests.TestCase):
    """We know that the ndr unpacking test leaves stuff in the
    autofree_context, and we don't want to worry about that. So for
    this test we don't make meory leak assertions."""

    def test_string_from_ndr(self):
        info = drsblobs.repsFromTo2OtherInfo()
        info.dns_name1 = "1.example.com"
        info.dns_name2 = "2.example.com"
        packed = ndr_pack(info)
        gc.collect()

        info_unpacked = ndr_unpack(drsblobs.repsFromTo2OtherInfo, packed)

        self.assertIsNotNone(info_unpacked)
        self.assertEqual(info_unpacked.dns_name1, "1.example.com")
        self.assertEqual(info_unpacked.dns_name2, "2.example.com")
