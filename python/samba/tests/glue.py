# Unix SMB/CIFS implementation.
# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007
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

"""Tests for the _glue Python bindings."""

from samba import _glue
from samba import param
import samba.tests


class GlueTests(samba.tests.TestCase):

    def setUp(self):
        super(GlueTests, self).setUp()

    def test_generate_random_str(self):
        string = _glue.generate_random_str(10)
        self.assertEqual(type(string), str)
        self.assertEqual(len(string), 10)

    def test_generate_random_password(self):
        password = _glue.generate_random_password(5, 10)
        self.assertEqual(type(password), str)
        self.assertTrue(5 <= len(password) <= 10)

    def test_unix2nttime(self):
        self.assertEqual(_glue.unix2nttime(1), 116444736010000000)

    def test_nttime2unix(self):
        self.assertEqual(_glue.nttime2unix(116444736010000000), 1)

    def test_float2nttime(self):
        self.assertEqual(_glue.float2nttime(1.0), 116444736010000000)
        self.assertEqual(_glue.float2nttime(1611058908.0), 132555325080000000)
        # NTTIME has a resolution of 100ns
        self.assertEqual(_glue.float2nttime(1611058908.1234567), 132555325081234567)
        self.assertEqual(_glue.float2nttime(1611058908.123456789), 132555325081234567)

    def test_nttime2float(self):
        self.assertEqual(_glue.nttime2float(1), -11644473600.0)
        self.assertEqual(_glue.nttime2float(0x7fffffffffffffff), 910692730085.4775)
        self.assertEqual(_glue.nttime2float(0x8000000000000000), 910692730085.4775)
        self.assertEqual(_glue.nttime2float(0xf000000000000000), 910692730085.4775)
        self.assertEqual(_glue.nttime2float(116444736010000000), 1.0)
        self.assertEqual(_glue.nttime2float(132555325080000000), 1611058908.0)
        self.assertEqual(_glue.nttime2float(132555325081234567), 1611058908.1234567)
        # NTTIME_OMIT (0) and NTTIME_FREEZE (UINT64_MAX) map to SAMBA_UTIME_OMIT (1)
        self.assertEqual(_glue.nttime2float(0), 1.0)
        self.assertEqual(_glue.nttime2float(0xffffffffffffffff), 1.0)

    def test_nttime2string(self):
        string = _glue.nttime2string(116444736010000000)
        self.assertEqual(type(string), str)
        self.assertIn('1970', string)

    def test_debug_level(self):
        prev_level = _glue.get_debug_level()
        try:
            self.assertIsNone(_glue.set_debug_level(0))
            self.assertEqual(_glue.get_debug_level(), 0)
            self.assertIsNone(_glue.set_debug_level(5))
            self.assertEqual(_glue.get_debug_level(), 5)
        finally:
            _glue.set_debug_level(prev_level)

    def test_interface_ips(self):
        lp = param.LoadParm()
        ips = _glue.interface_ips(lp)
        self.assertEqual(type(ips), list)

    def test_strcasecmp(self):
        self.assertEqual(_glue.strcasecmp_m('aA', 'Aa'), 0)
        self.assertNotEqual(_glue.strcasecmp_m('ab', 'Aa'), 0)

    def test_strstr_m(self):
        string = 'testing_string_num__one'
        self.assertEqual(_glue.strstr_m(string, '_'), '_string_num__one')
        self.assertEqual(_glue.strstr_m(string, '__'), '__one')
        self.assertEqual(_glue.strstr_m(string, 'ring'), 'ring_num__one')
