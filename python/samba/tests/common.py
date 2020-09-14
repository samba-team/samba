# Unix SMB/CIFS implementation. Tests for common.py routines
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

"""Tests for samba.common"""

import samba
import os
import samba.tests
from samba.common import normalise_int32
from samba.samdb import SamDB, dsdb_Dn


class CommonTests(samba.tests.TestCaseInTempDir):

    def test_normalise_int32(self):
        self.assertEqual('17', normalise_int32(17))
        self.assertEqual('17', normalise_int32('17'))
        self.assertEqual('-123', normalise_int32('-123'))
        self.assertEqual('-1294967296', normalise_int32('3000000000'))

    def test_dsdb_Dn_binary(self):
        url = self.tempdir + "/test_dsdb_Dn_binary.ldb"
        sam = samba.Ldb(url=url)
        dn1 = dsdb_Dn(sam, "DC=foo,DC=bar")
        dn2 = dsdb_Dn(sam, "B:8:0000000D:<GUID=b3f0ec29-17f4-452a-b002-963e1909d101>;DC=samba,DC=example,DC=com")
        self.assertEqual(dn2.binary, "0000000D")
        self.assertEqual(13, dn2.get_binary_integer())
        os.unlink(url)

    def test_dsdb_Dn_sorted(self):
        url = self.tempdir + "/test_dsdb_Dn_sorted.ldb"
        sam = samba.Ldb(url=url)
        try:
            dn1 = dsdb_Dn(sam, "B:8:0000000D:<GUID=b3f0ec29-17f4-452a-b002-963e1909d101>;OU=dn1,DC=samba,DC=example,DC=com")
            dn2 = dsdb_Dn(sam, "B:8:0000000C:<GUID=b3f0ec29-17f4-452a-b002-963e1909d101>;OU=dn1,DC=samba,DC=example,DC=com")
            dn3 = dsdb_Dn(sam, "B:8:0000000F:<GUID=00000000-17f4-452a-b002-963e1909d101>;OU=dn3,DC=samba,DC=example,DC=com")
            dn4 = dsdb_Dn(sam, "B:8:00000000:<GUID=ffffffff-17f4-452a-b002-963e1909d101>;OU=dn4,DC=samba,DC=example,DC=com")
            dn5 = dsdb_Dn(sam, "<GUID=ffffffff-27f4-452a-b002-963e1909d101>;OU=dn5,DC=samba,DC=example,DC=com")
            dn6 = dsdb_Dn(sam, "<GUID=00000000-27f4-452a-b002-963e1909d101>;OU=dn6,DC=samba,DC=example,DC=com")
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
        finally:
            del sam
            os.unlink(url)
