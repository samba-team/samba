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

"""Tests for samba.dcerpc.misc."""

from samba.dcerpc import misc
import samba.tests
from samba.compat import PY3

text1_b = b"76f53846-a7c2-476a-ae2c-20e2b80d7b34"
text2_b = b"344edffa-330a-4b39-b96e-2c34da52e8b1"
text1_s = text1_b.decode('utf8')


if PY3:
    # cmp() exists only in Python 2
    def cmp(a, b):
        return (a > b) - (a < b)


class GUIDTests(samba.tests.TestCase):

    def test_str(self):
        guid = misc.GUID(text1_b)
        self.assertEquals(text1_s, str(guid))

    def test_repr(self):
        guid = misc.GUID(text1_b)
        self.assertEquals("GUID('%s')" % text1_s, repr(guid))

    def test_compare_different(self):
        guid1 = misc.GUID(text1_b)
        guid2 = misc.GUID(text2_b)
        self.assertFalse(guid1 == guid2)
        self.assertGreater(guid1, guid2)
        self.assertTrue(cmp(guid1, guid2) > 0)

    def test_compare_same(self):
        guid1 = misc.GUID(text1_b)
        guid2 = misc.GUID(text1_b)
        self.assertTrue(guid1 == guid2)
        self.assertEquals(guid1, guid2)
        self.assertEquals(0, cmp(guid1, guid2))


class PolicyHandleTests(samba.tests.TestCase):

    def test_init(self):
        x = misc.policy_handle(text1_s, 1)
        self.assertEquals(1, x.handle_type)
        self.assertEquals(text1_s, str(x.uuid))

    def test_repr(self):
        x = misc.policy_handle(text1_s, 42)
        self.assertEquals("policy_handle(%d, '%s')" % (42, text1_s), repr(x))

    def test_str(self):
        x = misc.policy_handle(text1_s, 42)
        self.assertEquals("%d, %s" % (42, text1_s), str(x))
