# Unix SMB/CIFS implementation.
# Copyright (C) Lumir Balhar <lbalhar@redhat.com> 2017
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

import samba.tests
from samba import ldb, Ldb
from samba.tdb_util import tdb_copy
import os


class TDBUtilTests(samba.tests.TestCaseInTempDir):

    def setUp(self):
        super(TDBUtilTests, self).setUp()

    def test_tdb_copy(self):
        src_ldb_file = os.path.join(self.tempdir, "source.ldb")
        dst_ldb_file = os.path.join(self.tempdir, "destination.ldb")

        # Create LDB source file with some content
        src_ldb = Ldb(src_ldb_file)
        src_ldb.add({"dn": "f=dc", "b": "bla"})

        # Copy source file to destination file and check return status
        self.assertIsNone(tdb_copy(src_ldb_file, dst_ldb_file))

        # Load copied file as LDB object
        dst_ldb = Ldb(dst_ldb_file)

        # Copmare contents of files
        self.assertEqual(
            src_ldb.searchone(basedn=ldb.Dn(src_ldb, "f=dc"), attribute="b"),
            dst_ldb.searchone(basedn=ldb.Dn(dst_ldb, "f=dc"), attribute="b")
        )

        # Clean up
        del src_ldb
        del dst_ldb
        os.unlink(src_ldb_file)
        os.unlink(dst_ldb_file)
