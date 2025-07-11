# Unix SMB/CIFS implementation. Tests for dsdb_dn objects
# Copyright (C) Andrew Tridgell 2011
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

"""Tests for dsdb_dn objects"""

import os
import samba
from samba.samdb import BinaryDn, PlainDn, StringDn
from samba.key_credential_link import KeyCredentialLinkDn
from samba.tests import TestCaseInTempDir


class DsdbDnTests(TestCaseInTempDir):
    def _temp_ldb(self, name=None):
        if name is None:
            name = f"{self.unique_name()}.ldb"
        url = os.path.join(self.tempdir, name)
        sam = samba.Ldb(url=url)
        def _cleanup():
            sam.disconnect()
            os.unlink(url)
        self.addCleanup(_cleanup)
        return sam

    def test_BinaryDn(self):
        sam = self._temp_ldb()
        dn1 = BinaryDn(sam, "B:8:0000000d:<GUID=b3f0ec29-17f4-452a-b002-963e1909d101>;DC=samba,DC=example,DC=com")
        dn2 = BinaryDn(sam, "B:8:0000000D:<GUID=b3f0ec29-17f4-452a-b002-963e1909d102>;DC=samba,DC=example,DC=com")
        self.assertEqual(dn2.binary, b"\0\0\0\x0d")
        self.assertEqual(dn1.binary, dn2.binary)
        self.assertEqual(dn1.prefix, "B:8:0000000D:")
        self.assertEqual(13, dn2.get_binary_integer())
        self.assertEqual(list(dn1.binary), [0, 0, 0, 13])
        dn2.binary = b'123'
        self.assertEqual(dn2.prefix, "B:6:313233:")
        dn2.prefix = 'B:10:1234abcdef:'
        self.assertEqual(dn2.prefix, "B:10:1234ABCDEF:")
        self.assertEqual(dn2.get_binary_integer(), 0x1234ABCDEF)
        self.assertEqual(list(dn2.binary), [0x12, 0x34, 0xAB, 0xCD, 0xEF])
        for badstring, errmsg in (('B:11:1234abcdef0:', "Invalid hex string"),
                                  ('B:6:1234:', "Invalid length"),
                                  ('B:2:1234:', "Invalid length"),
                                  ('B:0:1234:', "Invalid length"),
                                  ('B:4:123g:', "Invalid prefix"),
                                  ('B:4:1234 :', "Invalid prefix"),
                                  ('b:4:1234:', "Invalid prefix"),
                                  ('S:4:1234:', "Invalid prefix"),
                                  ('S:4:123¼:', "Invalid prefix"),
                                  ('S:4:1234', "Invalid prefix"),
                                  ('B:4:1234', "Invalid prefix"),
                                  ):
            with self.assertRaises(ValueError) as cm:
                dn2.prefix = badstring
            self.assertIn(errmsg, str(cm.exception))

    def test_KeyCredentialLinkDn_valid(self):
        """Simple KeyCredentialLinkDn objects."""
        sam = self._temp_ldb()
        for name, dnstring, count in [
                ('empty', "B:8:00020000:DC=example,DC=com", 0),
                ('key id',
                 "B:78:00020000"
                 "2000" "01" # length, key id
                 "000102030405060708090A0B0C0D0E0F"
                 "101112131415161718191A1B1C1D1E1F"
                 ":DC=example,DC=com", 1),
                ('key hash',
                 "B:78:00020000"
                 "2000" "02" # length, key hash
                 "000102030405060708090A0B0C0D0E0F"
                 "101112131415161718191A1B1C1D1E1F"
                 ":DC=example,DC=com", 1),
                ('key usage',
                 "B:16:00020000"
                 "0100" "04" # length, key_usage
                 "01"
                 ":DC=example,DC=com", 1),
        ]:
            print(f"{name}: {dnstring}")
            k = KeyCredentialLinkDn(sam, dnstring)
            self.assertEqual(k.blob.count, count)
            b = BinaryDn(sam, dnstring)
            self.assertEqual(k, b)
            self.assertEqual(str(k), str(b))
            self.assertEqual(str(k).upper(), dnstring.upper())

    def test_KeyCredentialLinkDn_invalid(self):
        """KeyCredentialLinkDn objects that should fail."""
        sam = self._temp_ldb()
        for name, dnstring, valid_binary in [
                ('bad version', "B:8:00030000:DC=example,DC=com", True),
                ('length mismatch 1',
                 "B:78:00020000"
                 "2200" "01" # length, key_id
                 "000102030405060708090A0B0C0D0E0F"
                 "101112131415161718191A1B1C1D1E1F"
                 ":DC=example,DC=com", True),
                ('length mismatch 2',
                 "B:80:00020000"
                 "2000" "01" # length, key_id
                 "000102030405060708090A0B0C0D0E0F"
                 "101112131415161718191A1B1C1D1E1F00"
                 ":DC=example,DC=com", True),
                ('binary length mismatch',
                 "B:10:00020000"
                 ":DC=example,DC=com", False),
                #('bad key usage',
                # "B:16:00020000"
                # "0100" "04" # length, key_usage
                # "FF"
                # ":DC=example,DC=com", True),
                ('bad entry id 00',
                 "B:16:00020000"
                 "0100" "00" # length, invalid
                 "FF"
                 ":DC=example,DC=com", True),
                ('bad entry id ff',
                 "B:16:00020000"
                 "0100" "FF" # length, invalid
                 "FF"
                 ":DC=example,DC=com", True),
        ]:
            print(name)
            with self.assertRaises(ValueError) as cm:
                k = KeyCredentialLinkDn(sam, dnstring)

            print(cm.exception)
            try:
                b = BinaryDn(sam, dnstring)
            except ValueError:
                if valid_binary:
                    self.fail(f"{name}: expected {dnstring} to be valid binary dn")
            else:
                if not valid_binary:
                    self.fail(f"{name}: expected {dnstring} to be invalid binary dn, "
                              f"got {b}")

    def test_PlainDn(self):
        sam = self._temp_ldb("test_PlainDn.ldb")
        url = self.tempdir + "/test_PlainDn.ldb"
        sam = samba.Ldb(url=url)
        dn1 = PlainDn(sam, "DC=foo,DC=bar")
        self.assertEqual(dn1.prefix, '')
        self.assertIsNone(dn1.binary)

    def test_StringDn(self):
        sam = self._temp_ldb("test_StringDn.ldb")
        dn1 = StringDn(sam, "S:8:0000000d:<GUID=b3f0ec29-17f4-452a-b002-963e1909d101>;DC=samba,DC=example,DC=com")
        dn2 = StringDn(sam, "S:8:0000000D:<GUID=b3f0ec29-17f4-452a-b002-963e1909d102>;DC=samba,DC=example,DC=com")
        self.assertEqual(dn1.binary, b"0000000d")
        self.assertEqual(dn2.binary, b"0000000D")
        # TODO: determine whether string DNs should have case-insensitive comparisons
        self.assertNotEqual(dn1.binary, dn2.binary)
        dn1.prefix = 'S:5:ā”:'
        self.assertEqual(dn1.binary, b'\xc4\x81\xe2\x80\x9d')
        self.assertEqual(dn1.prefix, 'S:5:ā”:')

    def test_dsdb_Dn_sorted(self):
        sam = self._temp_ldb("test_dsdb_Dn_sorted.ldb")
        dn1 = BinaryDn(sam, "B:8:0000000D:<GUID=b3f0ec29-17f4-452a-b002-963e1909d101>;OU=dn1,DC=samba,DC=example,DC=com")
        dn2 = BinaryDn(sam, "B:8:0000000C:<GUID=b3f0ec29-17f4-452a-b002-963e1909d101>;OU=dn1,DC=samba,DC=example,DC=com")
        dn3 = BinaryDn(sam, "B:8:0000000F:<GUID=00000000-17f4-452a-b002-963e1909d101>;OU=dn3,DC=samba,DC=example,DC=com")
        dn4 = BinaryDn(sam, "B:8:00000000:<GUID=ffffffff-17f4-452a-b002-963e1909d101>;OU=dn4,DC=samba,DC=example,DC=com")
        dn5 = PlainDn(sam, "<GUID=ffffffff-27f4-452a-b002-963e1909d101>;OU=dn5,DC=samba,DC=example,DC=com")
        dn6 = PlainDn(sam, "<GUID=00000000-27f4-452a-b002-963e1909d101>;OU=dn6,DC=samba,DC=example,DC=com")
        unsorted_links14 = [dn1, dn2, dn3, dn4]
        sorted_vals14 = [str(dn) for dn in sorted(unsorted_links14)]
        self.assertEqual(sorted_vals14[0], str(dn3))
        self.assertEqual(sorted_vals14[1], str(dn2))
        self.assertEqual(sorted_vals14[2], str(dn1))
        self.assertEqual(sorted_vals14[3], str(dn4))
        unsorted_links56 = [dn5, dn6]
        sorted_vals56 = [str(dn) for dn in sorted(unsorted_links56)]
        self.assertEqual(sorted_vals56[0], str(dn6))
        self.assertEqual(sorted_vals56[1], str(dn5))
