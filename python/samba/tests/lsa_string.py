# Tests for lsa.String helpers in source4/librpc/ndr/py_lsa.c
#
# Copyright (C) Catalyst IT Ltd. 2017
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

from samba.tests import TestCase
from samba.dcerpc import lsa
from samba.ndr import ndr_pack, ndr_unpack
"""
Tests for the C helper functions in source4/librpc/ndr/py_lsa.c
for samba.dcerpc.lsa.String
"""


class LsaStringTests(TestCase):

    def test_default_constructor(self):
        s = lsa.String()
        self.assertEqual(None, s.string)
        self.assertEqual(0, s.size)
        self.assertEqual(0, s.length)

    def test_string_constructor(self):
        CONTENT = "The content string"
        s = lsa.String(CONTENT)
        self.assertEqual(CONTENT, s.string)

        # These should be zero
        self.assertEqual(0, s.size)
        self.assertEqual(0, s.length)

        packed = ndr_pack(s)
        unpacked = ndr_unpack(lsa.String, packed)

        # Original object should be unchanged
        self.assertEqual(0, s.size)
        self.assertEqual(0, s.length)

        # But they should be correct in the unpacked object
        self.assertEqual(36, unpacked.size)
        self.assertEqual(36, unpacked.length)

    def test_repr(self):
        # test an empty string
        self.assertEqual("lsaString(None)", repr(lsa.String()))
        # and one with contents
        self.assertEqual("lsaString('Hello world')",
                         repr(lsa.String("Hello world")))

    def test_to_string(self):
        # test an empty string
        self.assertEqual("", str(lsa.String()))
        # and one with contents
        self.assertEqual("Hello world",
                         str(lsa.String("Hello world")))
