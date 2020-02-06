# Unix SMB/CIFS implementation.
# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007-2008
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

"""Samba Python tests."""

import ldb
import os
import samba
from samba import arcfour_encrypt, string_to_byte_array
from samba.tests import TestCase, TestCaseInTempDir


class SubstituteVarTestCase(TestCase):

    def test_empty(self):
        self.assertEqual("", samba.substitute_var("", {}))

    def test_nothing(self):
        self.assertEqual("foo bar",
                          samba.substitute_var("foo bar", {"bar": "bla"}))

    def test_replace(self):
        self.assertEqual("foo bla",
                          samba.substitute_var("foo ${bar}", {"bar": "bla"}))

    def test_broken(self):
        self.assertEqual("foo ${bdkjfhsdkfh sdkfh ",
                          samba.substitute_var("foo ${bdkjfhsdkfh sdkfh ", {"bar": "bla"}))

    def test_unknown_var(self):
        self.assertEqual("foo ${bla} gsff",
                          samba.substitute_var("foo ${bla} gsff", {"bar": "bla"}))

    def test_check_all_substituted(self):
        samba.check_all_substituted("nothing to see here")
        self.assertRaises(Exception, samba.check_all_substituted,
                          "Not subsituted: ${FOOBAR}")


class ArcfourTestCase(TestCase):

    def test_arcfour_direct(self):
        key = b'12345678'
        plain = b'abcdefghi'
        crypt_expected = b'\xda\x91Z\xb0l\xd7\xb9\xcf\x99'
        crypt_calculated = arcfour_encrypt(key, plain)
        self.assertEqual(crypt_expected, crypt_calculated)


class StringToByteArrayTestCase(TestCase):

    def test_byte_array(self):
        expected = [218, 145, 90, 176, 108, 215, 185, 207, 153]
        calculated = string_to_byte_array('\xda\x91Z\xb0l\xd7\xb9\xcf\x99')
        self.assertEqual(expected, calculated)


class LdbExtensionTests(TestCaseInTempDir):

    def test_searchone(self):
        path = self.tempdir + "/searchone.ldb"
        l = samba.Ldb(path)
        try:
            l.add({"dn": "foo=dc", "bar": "bla"})
            self.assertEqual(b"bla",
                              l.searchone(basedn=ldb.Dn(l, "foo=dc"), attribute="bar"))
        finally:
            del l
            os.unlink(path)
