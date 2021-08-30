# Unix SMB/CIFS implementation. Tests for dsdb
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2021
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

"""Tests for samba.dsdb."""

from samba.tests import TestCase, DynamicTestCase
from samba.dsdb import user_account_control_flag_bit_to_string
import samba


@DynamicTestCase
class DsdbFlagTests(TestCase):

    @classmethod
    def setUpDynamicTestCases(cls):

        for x in dir(samba.dsdb):
            if x.startswith("UF_"):
                cls.generate_dynamic_test("test",
                                          x,
                                          x,
                                          getattr(samba.dsdb, x))


    def _test_with_args(self, uf_string, uf_bit):
        self.assertEqual(user_account_control_flag_bit_to_string(uf_bit),
                         uf_string)


    def test_not_a_flag(self):
        self.assertRaises(KeyError,
                          user_account_control_flag_bit_to_string,
                          0xabcdef)

    def test_too_long(self):
        self.assertRaises(OverflowError,
                          user_account_control_flag_bit_to_string,
                          0xabcdefffff)

    def test_way_too_long(self):
        self.assertRaises(OverflowError,
                          user_account_control_flag_bit_to_string,
                          0xabcdeffffffffffff)
