# Tests for the samba samdb api
#
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2018
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

from samba.tests import TestCaseInTempDir
from samba.samdb import SamDB
from ldb import LdbError, ERR_OPERATIONS_ERROR
import os
import errno


class SamDBApiTestCase(TestCaseInTempDir):

    def setUp(self):
        super(SamDBApiTestCase, self).setUp()

    def tearDown(self):
        try:
            os.remove(self.tempdir + "/test.db")
        except OSError as e:
            self.assertEqual(e.errno, errno.ENOENT)

        try:
            os.remove(self.tempdir + "/existing.db")
        except OSError as e:
            self.assertEqual(e.errno, errno.ENOENT)

        super(SamDBApiTestCase, self).tearDown()

    # Attempt to open and existing non tdb file as a tdb file.
    # Don't create new db is set, the default
    #
    # Should fail to open
    # And the existing file should be left intact.
    #
    def test_dont_create_db_existing_non_tdb_file(self):
        existing_name = self.tempdir + "/existing.db"
        existing = open(existing_name, "w")
        existing.write("This is not a tdb file!!!!!!\n")
        existing.close()

        try:
            SamDB(url="tdb://" + existing_name)
            self.fail("Exception not thrown ")
        except LdbError as e:
            (err, _) = e.args
            self.assertEqual(err, ERR_OPERATIONS_ERROR)

        existing = open(existing_name, "r")
        contents = existing.readline()
        self.assertEqual("This is not a tdb file!!!!!!\n", contents)

    # Attempt to open and existing non tdb file as a tdb file.
    # Don't create new db is cleared
    #
    # Should open as a tdb file
    # And the existing file should be over written
    #
    def test_create_db_existing_file_non_tdb_file(self):
        existing_name = self.tempdir + "/existing.db"
        existing = open(existing_name, "wb")
        existing.write(b"This is not a tdb file!!!!!!")
        existing.close()

        SamDB(url="tdb://" + existing_name, flags=0)

        existing = open(existing_name, "rb")
        contents = existing.readline()
        self.assertEqual(b"TDB file\n", contents)

    #
    # Attempt to open an existing tdb file as a tdb file.
    # Don't create new db is set, the default
    #
    # Should open successfully
    # And the existing file should be left intact.
    #
    def test_dont_create_db_existing_tdb_file(self):
        existing_name = self.tempdir + "/existing.db"
        initial = SamDB(url="tdb://" + existing_name, flags=0)
        dn = "dn=,cn=test_dont_create_db_existing_tdb_file"
        initial.add({
            "dn": dn,
            "cn": "test_dont_create_db_existing_tdb_file"
        })

        cn = initial.searchone("cn", dn)
        self.assertEqual(b"test_dont_create_db_existing_tdb_file", cn)

        second = SamDB(url="tdb://" + existing_name)
        cn = second.searchone("cn", dn)
        self.assertEqual(b"test_dont_create_db_existing_tdb_file", cn)

    #
    # Attempt to open an existing tdb file as a tdb file.
    # Don't create new db is explicitly cleared
    #
    # Should open successfully
    # And the existing file should be left intact.
    #
    def test_create_db_existing_file_tdb_file(self):
        existing_name = self.tempdir + "/existing.db"
        initial = SamDB(url="tdb://" + existing_name, flags=0)
        dn = "dn=,cn=test_dont_create_db_existing_tdb_file"
        initial.add({
            "dn": dn,
            "cn": "test_dont_create_db_existing_tdb_file"
        })

        cn = initial.searchone("cn", dn)
        self.assertEqual(b"test_dont_create_db_existing_tdb_file", cn)

        second = SamDB(url="tdb://" + existing_name, flags=0)
        cn = second.searchone("cn", dn)
        self.assertEqual(b"test_dont_create_db_existing_tdb_file", cn)

    # Open a non existent TDB file.
    # Don't create new db is set, the default
    #
    # Should fail
    # and the database file should not be created
    def test_dont_create_db_new_file(self):
        try:
            SamDB(url="tdb://" + self.tempdir + "/test.db")
            self.fail("Exception not thrown ")
        except LdbError as e1:
            (err, _) = e1.args
            self.assertEqual(err, ERR_OPERATIONS_ERROR)

        try:
            file = open(self.tempdir + "/test.db", "r")
            self.fail("New database file created")
        except IOError as e:
            self.assertEqual(e.errno, errno.ENOENT)

    # Open a SamDB with the don't create new DB flag cleared.
    # The underlying database file does not exist.
    #
    # Should successful open the SamDB creating a new database file.
    #

    def test_create_db_new_file(self):
        SamDB(url="tdb://" + self.tempdir + "/test.db", flags=0)
        existing = open(self.tempdir + "/test.db", mode="rb")
        contents = existing.readline()
        self.assertEqual(b"TDB file\n", contents)
