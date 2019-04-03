#!/usr/bin/env python3
#
# Tests for truncated index keys
#
#   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2018
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
"""Tests for truncated index keys

Databases such as lmdb have a maximum key length, these tests ensure that
ldb behaves correctly in those circumstances.

"""

import os
from unittest import TestCase
import sys
import ldb
import shutil

PY3 = sys.version_info > (3, 0)

TDB_PREFIX = "tdb://"
MDB_PREFIX = "mdb://"


def tempdir():
    import tempfile
    try:
        dir_prefix = os.path.join(os.environ["SELFTEST_PREFIX"], "tmp")
    except KeyError:
        dir_prefix = None
    return tempfile.mkdtemp(dir=dir_prefix)


def contains(result, dn):
    if result is None:
        return False

    for r in result:
        if str(r["dn"]) == dn:
            return True
    return False


class LdbBaseTest(TestCase):
    def setUp(self):
        super(LdbBaseTest, self).setUp()
        try:
            if self.prefix is None:
                self.prefix = TDB_PREFIX
        except AttributeError:
            self.prefix = TDB_PREFIX

    def tearDown(self):
        super(LdbBaseTest, self).tearDown()

    def url(self):
        return self.prefix + self.filename

    def flags(self):
        if self.prefix == MDB_PREFIX:
            return ldb.FLG_NOSYNC
        else:
            return 0


class MaxIndexKeyLengthTests(LdbBaseTest):
    def checkGuids(self, key, guids):
        #
        # This check relies on the current implementation where the indexes
        # are in the same database as the data.
        #
        # It checks that the index record exists, unless guids is None then
        # the record must not exist. And the it contains the expected guid
        # entries.
        #
        # The caller needs to provide the GUID's in the expected order
        #
        res = self.l.search(
            base=key,
            scope=ldb.SCOPE_BASE)
        if guids is None:
            self.assertEqual(len(res), 0)
            return
        self.assertEqual(len(res), 1)

        # The GUID index format has only one value
        index = res[0]["@IDX"][0]
        self.assertEqual(len(guids), len(index))
        self.assertEqual(guids, index)

    def tearDown(self):
        shutil.rmtree(self.testdir)
        super(MaxIndexKeyLengthTests, self).tearDown()

        # Ensure the LDB is closed now, so we close the FD
        del(self.l)

    def setUp(self):
        super(MaxIndexKeyLengthTests, self).setUp()
        self.testdir = tempdir()
        self.filename = os.path.join(self.testdir, "key_len_test.ldb")
        # Note that the maximum key length is set to 54
        # This accounts for the 4 bytes added by the dn formatting
        # a leading dn=, and a trailing zero terminator
        #
        self.l = ldb.Ldb(self.url(),
                         options=[
                             "modules:rdn_name",
                             "max_key_len_for_self_test:54"])
        self.l.add({"dn": "@ATTRIBUTES",
                    "uniqueThing": "UNIQUE_INDEX"})
        self.l.add({"dn": "@INDEXLIST",
                    "@IDXATTR": [
                        b"uniqueThing",
                        b"notUnique",
                        b"base64____lt",
                        b"base64_____eq",
                        b"base64______gt"],
                    "@IDXONE": [b"1"],
                    "@IDXGUID": [b"objectUUID"],
                    "@IDX_DN_GUID": [b"GUID"]})

    # Add a value to a unique index that exceeds the maximum key length
    # This should be rejected.
    def test_add_long_unique_add(self):
        try:
            self.l.add({"dn": "OU=UNIQUE_MAX_LEN,DC=SAMBA,DC=ORG",
                        "objectUUID": b"0123456789abcdef",
                        "uniqueThing": "01234567890123456789012345678901"})
            # index key will be
            # "@INDEX:UNIQUETHING:01234567890123456789012345678901"
            self.fail("Should have failed on long index key")

        except ldb.LdbError as err:
            enum = err.args[0]
            self.assertEqual(enum, ldb.ERR_CONSTRAINT_VIOLATION)

    # Test that DN's longer the maximum key length can be added
    # and that duplicate DN's are rejected correctly
    def test_add_long_dn_add(self):
        #
        # For all entries the DN index key gets truncated to
        # @INDEX:@IDXDN:OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA
        #
        self.l.add({"dn": "OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA,DC=ORG",
                    "objectUUID": b"0123456789abcdef"})
        self.checkGuids(
            "@INDEX#@IDXDN#OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA",
            b"0123456789abcdef")

        self.l.add({"dn": "OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA,DC=COM",
                    "objectUUID": b"0123456789abcde0"})
        self.checkGuids(
            "@INDEX#@IDXDN#OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA",
            b"0123456789abcde0" + b"0123456789abcdef")

        self.l.add({"dn": "OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA,DC=GOV",
                    "objectUUID": b"0123456789abcde1"})
        self.checkGuids(
            "@INDEX#@IDXDN#OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA",
            b"0123456789abcde0" + b"0123456789abcde1" + b"0123456789abcdef")

        # Key is equal to max length does not get inserted into the truncated
        # key namespace
        self.l.add({"dn": "OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA",
                    "objectUUID": b"0123456789abcde5"})
        self.checkGuids(
            "@INDEX:@IDXDN:OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA",
            b"0123456789abcde5")

        # This key should not get truncated, as it's one character less than
        # max, and will not be in the truncate name space
        self.l.add({"dn": "OU=A_LONG_DNXXXXXXXXXXXXXX,DC=SAMBA",
                    "objectUUID": b"0123456789abcde7"})
        self.checkGuids(
            "@INDEX:@IDXDN:OU=A_LONG_DNXXXXXXXXXXXXXX,DC=SAMBA",
            b"0123456789abcde7")

        try:
            self.l.add({"dn": "OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA,DC=ORG",
                        "objectUUID": b"0123456789abcde2"})
        except ldb.LdbError as err:
            enum = err.args[0]
            self.assertEqual(enum, ldb.ERR_ENTRY_ALREADY_EXISTS)

        try:
            self.l.add({"dn": "OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA,DC=COM",
                        "objectUUID": b"0123456789abcde3"})
        except ldb.LdbError as err:
            enum = err.args[0]
            self.assertEqual(enum, ldb.ERR_ENTRY_ALREADY_EXISTS)

        try:
            self.l.add({"dn": "OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA,DC=GOV",
                        "objectUUID": b"0123456789abcde4"})
        except ldb.LdbError as err:
            enum = err.args[0]
            self.assertEqual(enum, ldb.ERR_ENTRY_ALREADY_EXISTS)

        try:
            self.l.add({"dn": "OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA",
                        "objectUUID": b"0123456789abcde6"})
        except ldb.LdbError as err:
            enum = err.args[0]
            self.assertEqual(enum, ldb.ERR_ENTRY_ALREADY_EXISTS)

        try:
            self.l.add({"dn": "OU=A_LONG_DNXXXXXXXXXX,DC=SAMBA",
                        "objectUUID": b"0123456789abcde8"})
        except ldb.LdbError as err:
            enum = err.args[0]
            self.assertEqual(enum, ldb.ERR_ENTRY_ALREADY_EXISTS)

    def test_rename_truncated_dn_keys(self):
        # For all entries the DN index key gets truncated to
        #    0        1         2         3         4         5
        #    12345678901234567890123456789012345678901234567890
        #    @INDEX:@IDXDN:OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA
        self.l.add({"dn": "OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA,DC=ORG",
                    "objectUUID": b"0123456789abcdef"})
        self.checkGuids(
            "@INDEX#@IDXDN#OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA",
            b"0123456789abcdef")

        self.l.add({"dn": "OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA,DC=COM",
                    "objectUUID": b"0123456789abcde0"})
        self.checkGuids(
            "@INDEX#@IDXDN#OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA",
            b"0123456789abcde0" + b"0123456789abcdef")

        # Non conflicting rename, should succeed
        self.l.rename("OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA,DC=ORG",
                      "OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA,DC=GOV")
        # Index should be unchanged.
        self.checkGuids(
            "@INDEX#@IDXDN#OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA",
            b"0123456789abcde0" + b"0123456789abcdef")

        # Conflicting rename should fail
        try:
            self.l.rename("OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA,DC=COM",
                          "OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA,DC=GOV")
        except ldb.LdbError as err:
            enum = err.args[0]
            self.assertEqual(enum, ldb.ERR_ENTRY_ALREADY_EXISTS)

    def test_delete_truncated_dn_keys(self):
        #
        # For all entries the DN index key gets truncated to
        #    0        1         2         3         4         5
        #    12345678901234567890123456789012345678901234567890
        #    @INDEX:@IDXDN:OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA
        #
        self.l.add({"dn": "OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA,DC=ORG",
                    "objectUUID": b"0123456789abcdef"})
        self.checkGuids(
            "@INDEX#@IDXDN#OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA",
            b"0123456789abcdef")

        self.l.add({"dn": "OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA,DC=GOV",
                    "objectUUID": b"0123456789abcde1"})
        self.checkGuids(
            "@INDEX#@IDXDN#OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA",
            b"0123456789abcde1" + b"0123456789abcdef")

        self.l.add({"dn": "OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA",
                    "objectUUID": b"0123456789abcde5"})
        self.checkGuids(
            "@INDEX:@IDXDN:OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA",
            b"0123456789abcde5")

        # Try to delete a non existent DN with a truncated key
        try:
            self.l.delete("OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA,DC=COM")
        except ldb.LdbError as err:
            enum = err.args[0]
            self.assertEqual(enum, ldb.ERR_NO_SUCH_OBJECT)
            # Ensure that non of the other truncated DN's got deleted
            res = self.l.search(
                base="OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA,DC=ORG")
            self.assertEqual(len(res), 1)

            res = self.l.search(
                base="OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA,DC=GOV")
            self.assertEqual(len(res), 1)

            # Ensure that the non truncated DN did not get deleted
            res = self.l.search(
                base="OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA")
            self.assertEqual(len(res), 1)

            # Check the indexes are correct
            self.checkGuids(
                "@INDEX#@IDXDN#OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA",
                b"0123456789abcde1" + b"0123456789abcdef")
            self.checkGuids(
                "@INDEX:@IDXDN:OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA",
                b"0123456789abcde5")

        # delete an existing entry
        self.l.delete("OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA,DC=ORG")

        # Ensure it got deleted
        res = self.l.search(base="OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA,DC=ORG")
        self.assertEqual(len(res), 0)

        # Ensure that non of the other truncated DN's got deleted
        res = self.l.search(base="OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA,DC=GOV")
        self.assertEqual(len(res), 1)

        # Ensure the non truncated entry did not get deleted.
        res = self.l.search(base="OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA")
        self.assertEqual(len(res), 1)

        # Check the indexes are correct
        self.checkGuids(
            "@INDEX#@IDXDN#OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA",
            b"0123456789abcde1")
        self.checkGuids(
            "@INDEX:@IDXDN:OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA",
            b"0123456789abcde5")

        # delete an existing entry
        self.l.delete("OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA,DC=GOV")

        # Ensure it got deleted
        res = self.l.search(base="OU=A_LONG_DNXXXXXXXXXXX,DC=SAMBA,DC=GOV")
        self.assertEqual(len(res), 0)

        # Ensure that non of the non truncated DN's got deleted
        res = self.l.search(base="OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA")
        self.assertEqual(len(res), 1)
        # Check the indexes are correct
        self.checkGuids(
            "@INDEX#@IDXDN#OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA",
            None)
        self.checkGuids(
            "@INDEX:@IDXDN:OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA",
            b"0123456789abcde5")

        # delete an existing entry
        self.l.delete("OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA")

        # Ensure it got deleted
        res = self.l.search(base="OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBAxxx")
        self.assertEqual(len(res), 0)
        self.checkGuids(
            "@INDEX:@IDXDN:OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA",
            None)

    def test_search_truncated_dn_keys(self):
        #
        # For all entries the DN index key gets truncated to
        #    0        1         2         3         4         5
        #    12345678901234567890123456789012345678901234567890
        #    @INDEX:@IDXDN:OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA
        #
        self.l.add({"dn": "OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA,DC=ORG",
                    "objectUUID": b"0123456789abcdef"})
        self.checkGuids(
            "@INDEX#@IDXDN#OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA",
            b"0123456789abcdef")

        self.l.add({"dn": "OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA,DC=GOV",
                    "objectUUID": b"0123456789abcde1"})
        self.checkGuids(
            "@INDEX#@IDXDN#OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA",
            b"0123456789abcde1" + b"0123456789abcdef")

        self.l.add({"dn": "OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA",
                    "objectUUID": b"0123456789abcde5"})
        self.checkGuids(
            "@INDEX:@IDXDN:OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA",
            b"0123456789abcde5")

        res = self.l.search(base="OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA,DC=ORG")
        self.assertEqual(len(res), 1)

        res = self.l.search(base="OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA,DC=GOV")
        self.assertEqual(len(res), 1)

        res = self.l.search(base="OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA")
        self.assertEqual(len(res), 1)

        res = self.l.search(base="OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA,DC=COM")
        self.assertEqual(len(res), 0)

        res = self.l.search(base="OU=A_LONG_DNXXXXXXXXXXXX,DC=SAMBA,DC=GOV")
        self.assertEqual(len(res), 0)

        # Non existent, key one less than truncation limit
        res = self.l.search(base="OU=A_LONG_DNXXXXXXXXXXXXXX,DC=SAMBA")
        self.assertEqual(len(res), 0)

    def test_search_dn_filter_truncated_dn_keys(self):
        #
        # For all entries the DN index key gets truncated to
        #    0        1         2         3         4         5
        #    12345678901234567890123456789012345678901234567890
        #    @INDEX:@IDXDN:OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA
        #
        self.l.add({"dn": "OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA,DC=ORG",
                    "objectUUID": b"0123456789abcdef"})
        self.checkGuids(
            "@INDEX#@IDXDN#OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA",
            b"0123456789abcdef")

        self.l.add({"dn": "OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA,DC=GOV",
                    "objectUUID": b"0123456789abcde1"})
        self.checkGuids(
            "@INDEX#@IDXDN#OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA",
            b"0123456789abcde1" + b"0123456789abcdef")

        self.l.add({"dn": "OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA",
                    "objectUUID": b"0123456789abcde5"})
        self.checkGuids(
            "@INDEX:@IDXDN:OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA",
            b"0123456789abcde5")

        res = self.l.search(
            expression="dn=OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA,DC=ORG")
        self.assertEqual(len(res), 1)

        res = self.l.search(
            expression="dn=OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA,DC=GOV")
        self.assertEqual(len(res), 1)

        res = self.l.search(
            expression="dn=OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA")
        self.assertEqual(len(res), 1)

        res = self.l.search(
            expression="dn=OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA,DC=COM")
        self.assertEqual(len(res), 0)

        res = self.l.search(
            expression="dn=OU=A_LONG_DNXXXXXXXXXXXX,DC=SAMBA,DC=GOV")
        self.assertEqual(len(res), 0)

        # Non existent, key one less than truncation limit
        res = self.l.search(
            expression="dn=OU=A_LONG_DNXXXXXXXXXXXXXX,DC=SAMBA")
        self.assertEqual(len(res), 0)

    def test_search_one_level_truncated_dn_keys(self):
        #
        # Except for the base DN's
        # all entries the DN index key gets truncated to
        #    0        1         2         3         4         5
        #    12345678901234567890123456789012345678901234567890
        #    @INDEX:@IDXDN:OU=??,OU=A_LONG_DN_ONE_LVLX,DC=SAMBA
        # The base DN-s truncate to
        #    @INDEX:@IDXDN:OU=A_LONG_DN_ONE_LVLX,DC=SAMBA,DC=OR
        #
        self.l.add({"dn": "OU=A_LONG_DN_ONE_LVLX,DC=SAMBA,DC=OR1",
                    "objectUUID": b"0123456789abcdef"})
        self.l.add({"dn": "OU=A_LONG_DN_ONE_LVLX,DC=SAMBA,DC=OR2",
                    "objectUUID": b"0123456789abcd1f"})
        self.checkGuids(
            "@INDEX#@IDXDN#OU=A_LONG_DN_ONE_LVLX,DC=SAMBA,DC=OR",
            b"0123456789abcd1f" + b"0123456789abcdef")

        self.l.add({"dn": "OU=01,OU=A_LONG_DN_ONE_LVLX,DC=SAMBA,DC=OR1",
                    "objectUUID": b"0123456789abcde1"})
        self.l.add({"dn": "OU=01,OU=A_LONG_DN_ONE_LVLX,DC=SAMBA,DC=OR2",
                    "objectUUID": b"0123456789abcd11"})
        self.checkGuids(
            "@INDEX#@IDXDN#OU=01,OU=A_LONG_DN_ONE_LVLX,DC=SAMBA",
            b"0123456789abcd11" + b"0123456789abcde1")

        self.l.add({"dn": "OU=02,OU=A_LONG_DN_ONE_LVLX,DC=SAMBA,DC=OR1",
                    "objectUUID": b"0123456789abcde2"})
        self.l.add({"dn": "OU=02,OU=A_LONG_DN_ONE_LVLX,DC=SAMBA,DC=OR2",
                    "objectUUID": b"0123456789abcdf2"})
        self.checkGuids(
            "@INDEX#@IDXDN#OU=02,OU=A_LONG_DN_ONE_LVLX,DC=SAMBA",
            b"0123456789abcde2" + b"0123456789abcdf2")

        self.l.add({"dn": "OU=03,OU=A_LONG_DN_ONE_LVLX,DC=SAMBA,DC=OR1",
                    "objectUUID": b"0123456789abcde3"})
        self.l.add({"dn": "OU=03,OU=A_LONG_DN_ONE_LVLX,DC=SAMBA,DC=OR2",
                    "objectUUID": b"0123456789abcd13"})
        self.checkGuids(
            "@INDEX#@IDXDN#OU=03,OU=A_LONG_DN_ONE_LVLX,DC=SAMBA",
            b"0123456789abcd13" + b"0123456789abcde3")

        # This key is not truncated as it's the max_key_len
        self.l.add({"dn": "OU=01,OU=A_LONG_DN_ONE_LVLX,DC=SAMBA",
                    "objectUUID": b"0123456789abcde7"})
        self.checkGuids(
            "@INDEX:@IDXDN:OU=01,OU=A_LONG_DN_ONE_LVLX,DC=SAMBA",
            b"0123456789abcde7")

        res = self.l.search(base="OU=A_LONG_DN_ONE_LVLX,DC=SAMBA,DC=OR1",
                            scope=ldb.SCOPE_ONELEVEL)
        self.assertEqual(len(res), 3)
        self.assertTrue(
            contains(res, "OU=01,OU=A_LONG_DN_ONE_LVLX,DC=SAMBA,DC=OR1"))
        self.assertTrue(
            contains(res, "OU=02,OU=A_LONG_DN_ONE_LVLX,DC=SAMBA,DC=OR1"))
        self.assertTrue(
            contains(res, "OU=03,OU=A_LONG_DN_ONE_LVLX,DC=SAMBA,DC=OR1"))

        res = self.l.search(base="OU=A_LONG_DN_ONE_LVLX,DC=SAMBA,DC=OR2",
                            scope=ldb.SCOPE_ONELEVEL)
        self.assertEqual(len(res), 3)
        self.assertTrue(
            contains(res, "OU=01,OU=A_LONG_DN_ONE_LVLX,DC=SAMBA,DC=OR2"))
        self.assertTrue(
            contains(res, "OU=02,OU=A_LONG_DN_ONE_LVLX,DC=SAMBA,DC=OR2"))
        self.assertTrue(
            contains(res, "OU=03,OU=A_LONG_DN_ONE_LVLX,DC=SAMBA,DC=OR2"))

        res = self.l.search(base="OU=A_LONG_DN_ONE_LVLX,DC=SAMBA",
                            scope=ldb.SCOPE_ONELEVEL)
        self.assertEqual(len(res), 1)
        self.assertTrue(
            contains(res, "OU=01,OU=A_LONG_DN_ONE_LVLX,DC=SAMBA"))

    def test_search_sub_tree_truncated_dn_keys(self):
        #
        # Except for the base DN's
        # all entries the DN index key gets truncated to
        #    0        1         2         3         4         5
        #    12345678901234567890123456789012345678901234567890
        #    @INDEX:@IDXDN:OU=??,OU=A_LONG_DN_SUB_TREE,DC=SAMBA
        # The base DN-s truncate to
        #    @INDEX:@IDXDN:OU=A_LONG_DN_SUB_TREE,DC=SAMBA,DC=OR
        #
        self.l.add({"dn": "OU=A_LONG_DN_SUB_TREE,DC=SAMBA,DC=OR1",
                    "objectUUID": b"0123456789abcdef"})
        self.l.add({"dn": "OU=A_LONG_DN_SUB_TREE,DC=SAMBA,DC=OR2",
                    "objectUUID": b"0123456789abcde4"})
        self.l.add({"dn": "OU=A_LONG_DN_SUB_TREE,DC=SAMBA,DC=OR3",
                    "objectUUID": b"0123456789abcde8"})
        self.checkGuids(
            "@INDEX#@IDXDN#OU=A_LONG_DN_SUB_TREE,DC=SAMBA,DC=OR",
            b"0123456789abcde4" + b"0123456789abcde8" + b"0123456789abcdef")

        self.l.add({"dn": "OU=01,OU=A_LONG_DN_SUB_TREE,DC=SAMBA,DC=OR1",
                    "objectUUID": b"0123456789abcde1"})
        self.l.add({"dn": "OU=01,OU=A_LONG_DN_SUB_TREE,DC=SAMBA,DC=OR2",
                    "objectUUID": b"0123456789abcde5"})
        self.checkGuids(
            "@INDEX#@IDXDN#OU=01,OU=A_LONG_DN_SUB_TREE,DC=SAMBA",
            b"0123456789abcde1" + b"0123456789abcde5")

        self.l.add({"dn": "OU=02,OU=A_LONG_DN_SUB_TREE,DC=SAMBA,DC=OR1",
                    "objectUUID": b"0123456789abcde2"})
        self.l.add({"dn": "OU=02,OU=A_LONG_DN_SUB_TREE,DC=SAMBA,DC=OR2",
                    "objectUUID": b"0123456789abcde6"})
        self.checkGuids(
            "@INDEX#@IDXDN#OU=02,OU=A_LONG_DN_SUB_TREE,DC=SAMBA",
            b"0123456789abcde2" + b"0123456789abcde6")

        self.l.add({"dn": "OU=03,OU=A_LONG_DN_SUB_TREE,DC=SAMBA,DC=OR1",
                    "objectUUID": b"0123456789abcde3"})

        self.l.add({"dn": "OU=03,OU=A_LONG_DN_SUB_TREE,DC=SAMBA,DC=OR2",
                    "objectUUID": b"0123456789abcde7"})
        self.checkGuids(
            "@INDEX#@IDXDN#OU=03,OU=A_LONG_DN_SUB_TREE,DC=SAMBA",
            b"0123456789abcde3" + b"0123456789abcde7")

        self.l.add({"dn": "OU=04,OU=A_LONG_DN_SUB_TREE,DC=SAMBA,DC=OR4",
                    "objectUUID": b"0123456789abcde9"})
        self.checkGuids(
            "@INDEX#@IDXDN#OU=04,OU=A_LONG_DN_SUB_TREE,DC=SAMBA",
            b"0123456789abcde9")

        res = self.l.search(base="OU=A_LONG_DN_SUB_TREE,DC=SAMBA,DC=OR1",
                            scope=ldb.SCOPE_SUBTREE)
        self.assertEqual(len(res), 4)
        self.assertTrue(
            contains(res, "OU=A_LONG_DN_SUB_TREE,DC=SAMBA,DC=OR1"))
        self.assertTrue(
            contains(res, "OU=01,OU=A_LONG_DN_SUB_TREE,DC=SAMBA,DC=OR1"))
        self.assertTrue(
            contains(res, "OU=02,OU=A_LONG_DN_SUB_TREE,DC=SAMBA,DC=OR1"))
        self.assertTrue(
            contains(res, "OU=03,OU=A_LONG_DN_SUB_TREE,DC=SAMBA,DC=OR1"))

        res = self.l.search(base="OU=A_LONG_DN_SUB_TREE,DC=SAMBA,DC=OR2",
                            scope=ldb.SCOPE_SUBTREE)
        self.assertEqual(len(res), 4)
        self.assertTrue(
            contains(res, "OU=A_LONG_DN_SUB_TREE,DC=SAMBA,DC=OR2"))
        self.assertTrue(
            contains(res, "OU=01,OU=A_LONG_DN_SUB_TREE,DC=SAMBA,DC=OR2"))
        self.assertTrue(
            contains(res, "OU=02,OU=A_LONG_DN_SUB_TREE,DC=SAMBA,DC=OR2"))
        self.assertTrue(
            contains(res, "OU=03,OU=A_LONG_DN_SUB_TREE,DC=SAMBA,DC=OR2"))

        res = self.l.search(base="OU=A_LONG_DN_SUB_TREE,DC=SAMBA,DC=OR3",
                            scope=ldb.SCOPE_SUBTREE)
        self.assertEqual(len(res), 1)
        self.assertTrue(
            contains(res, "OU=A_LONG_DN_SUB_TREE,DC=SAMBA,DC=OR3"))

        res = self.l.search(base="OU=A_LONG_DN_SUB_TREE,DC=SAMBA,DC=OR4",
                            scope=ldb.SCOPE_SUBTREE)
        self.assertEqual(len(res), 1)
        self.assertTrue(
            contains(res, "OU=04,OU=A_LONG_DN_SUB_TREE,DC=SAMBA,DC=OR4"))

    def test_search_base_truncated_dn_keys(self):
        #
        # For all entries the DN index key gets truncated to
        #    0        1         2         3         4         5
        #    12345678901234567890123456789012345678901234567890
        #    @INDEX:@IDXDN:OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA
        #
        self.l.add({"dn": "OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA,DC=ORG",
                    "objectUUID": b"0123456789abcdef"})
        self.checkGuids(
            "@INDEX#@IDXDN#OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA",
            b"0123456789abcdef")

        self.l.add({"dn": "OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA,DC=GOV",
                    "objectUUID": b"0123456789abcde1"})
        self.checkGuids(
            "@INDEX#@IDXDN#OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA",
            b"0123456789abcde1" + b"0123456789abcdef")

        self.l.add({"dn": "OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA",
                    "objectUUID": b"0123456789abcde5"})
        self.checkGuids(
            "@INDEX:@IDXDN:OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA",
            b"0123456789abcde5")

        res = self.l.search(
            base="OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA,DC=ORG",
            scope=ldb.SCOPE_BASE)
        self.assertEqual(len(res), 1)

        res = self.l.search(
            base="OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA,DC=GOV",
            scope=ldb.SCOPE_BASE)
        self.assertEqual(len(res), 1)

        res = self.l.search(
            base="OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA",
            scope=ldb.SCOPE_BASE)
        self.assertEqual(len(res), 1)

        res = self.l.search(
            base="OU=A_LONG_DNXXXXXXXXXXXXXXX,DC=SAMBA,DC=COM",
            scope=ldb.SCOPE_BASE)
        self.assertEqual(len(res), 0)

        res = self.l.search(
            base="OU=A_LONG_DNXXXXXXXXXXXX,DC=SAMBA,DC=GOV",
            scope=ldb.SCOPE_BASE)
        self.assertEqual(len(res), 0)

        # Non existent, key one less than truncation limit
        res = self.l.search(
            base="OU=A_LONG_DNXXXXXXXXXXXXXX,DC=SAMBA",
            scope=ldb.SCOPE_BASE)
        self.assertEqual(len(res), 0)

    #
    # Test non unique index searched with truncated keys
    #
    def test_index_truncated_keys(self):
        # 0        1         2         3         4         5
        # 12345678901234567890123456789012345678901234567890
        # @INDEX:NOTUNIQUE:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

        eq_max = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        gt_max = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        lt_max = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        # > than max length and differs in values that will be truncated
        gt_max_b = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"

        # Add two entries with the same value, key length = max so no
        # truncation.
        self.l.add({"dn": "OU=01,OU=SEARCH_NON_UNIQUE,DC=SAMBA,DC=ORG",
                    "notUnique": eq_max,
                    "objectUUID": b"0123456789abcde0"})
        self.checkGuids(
            "@INDEX:NOTUNIQUE:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            b"0123456789abcde0")

        self.l.add({"dn": "OU=02,OU=SEARCH_NON_UNIQUE,DC=SAMBA,DC=ORG",
                    "notUnique": eq_max,
                    "objectUUID": b"0123456789abcde1"})
        self.checkGuids(
            "@INDEX:NOTUNIQUE:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            b"0123456789abcde0" + b"0123456789abcde1")

        #
        # An entry outside the tree
        #
        self.l.add({"dn": "OU=10,OU=SEARCH_NON_UNIQUE01,DC=SAMBA,DC=ORG",
                    "notUnique": eq_max,
                    "objectUUID": b"0123456789abcd11"})
        self.checkGuids(
            "@INDEX:NOTUNIQUE:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            b"0123456789abcd11" + b"0123456789abcde0" + b"0123456789abcde1")

        # Key longer than max so should get truncated to same key as
        # the previous two entries
        self.l.add({"dn": "OU=03,OU=SEARCH_NON_UNIQUE,DC=SAMBA,DC=ORG",
                    "notUnique": gt_max,
                    "objectUUID": b"0123456789abcde2"})
        # But in the truncated key space
        self.checkGuids(
            "@INDEX#NOTUNIQUE#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            b"0123456789abcde2")

        # Key longer than max so should get truncated to same key as
        # the previous entries but differs in the chars after max length
        self.l.add({"dn": "OU=23,OU=SEARCH_NON_UNIQUE,DC=SAMBA,DC=ORG",
                    "notUnique": gt_max_b,
                    "objectUUID": b"0123456789abcd22"})
        # But in the truncated key space
        self.checkGuids(
            "@INDEX#NOTUNIQUE#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            b"0123456789abcd22" + b"0123456789abcde2")
        #
        # An entry outside the tree
        #
        self.l.add({"dn": "OU=11,OU=SEARCH_NON_UNIQUE01,DC=SAMBA,DC=ORG",
                    "notUnique": gt_max,
                    "objectUUID": b"0123456789abcd12"})
        self.checkGuids(
            "@INDEX#NOTUNIQUE#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            b"0123456789abcd12" + b"0123456789abcd22" + b"0123456789abcde2")

        # Key shorter than max
        #
        self.l.add({"dn": "OU=04,OU=SEARCH_NON_UNIQUE,DC=SAMBA,DC=ORG",
                    "notUnique": lt_max,
                    "objectUUID": b"0123456789abcde3"})
        self.checkGuids(
            "@INDEX:NOTUNIQUE:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            b"0123456789abcde3")
        #
        # An entry outside the tree
        #
        self.l.add({"dn": "OU=12,OU=SEARCH_NON_UNIQUE01,DC=SAMBA,DC=ORG",
                    "notUnique": lt_max,
                    "objectUUID": b"0123456789abcd13"})
        self.checkGuids(
            "@INDEX:NOTUNIQUE:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            b"0123456789abcd13" + b"0123456789abcde3")

        #
        # search for target is max value not truncated
        # should return ou's 01, 02
        #
        expression = "(notUnique=" + eq_max.decode('ascii') + ")"
        res = self.l.search(base="OU=SEARCH_NON_UNIQUE,DC=SAMBA,DC=ORG",
                            scope=ldb.SCOPE_ONELEVEL,
                            expression=expression)
        self.assertEqual(len(res), 2)
        self.assertTrue(
            contains(res, "OU=01,OU=SEARCH_NON_UNIQUE,DC=SAMBA,DC=ORG"))
        self.assertTrue(
            contains(res, "OU=02,OU=SEARCH_NON_UNIQUE,DC=SAMBA,DC=ORG"))
        #
        # search for target is max value not truncated
        # search one level up the tree, scope is ONE_LEVEL
        # So should get no matches
        #
        expression = "(notUnique=" + eq_max.decode('ascii') + ")"
        res = self.l.search(base="DC=SAMBA,DC=ORG",
                            scope=ldb.SCOPE_ONELEVEL,
                            expression=expression)
        self.assertEqual(len(res), 0)
        #
        # search for target is max value not truncated
        # search one level up the tree, scope is SUBTREE
        # So should get 3 matches
        #
        res = self.l.search(base="DC=SAMBA,DC=ORG",
                            scope=ldb.SCOPE_SUBTREE,
                            expression=expression)
        self.assertEqual(len(res), 3)
        self.assertTrue(
            contains(res, "OU=01,OU=SEARCH_NON_UNIQUE,DC=SAMBA,DC=ORG"))
        self.assertTrue(
            contains(res, "OU=02,OU=SEARCH_NON_UNIQUE,DC=SAMBA,DC=ORG"))
        self.assertTrue(
            contains(res, "OU=10,OU=SEARCH_NON_UNIQUE01,DC=SAMBA,DC=ORG"))
        #
        # search for target is max value + 1 so truncated
        # should return ou 23 as it's gt_max_b being searched for
        #
        expression = "(notUnique=" + gt_max_b.decode('ascii') + ")"
        res = self.l.search(base="OU=SEARCH_NON_UNIQUE,DC=SAMBA,DC=ORG",
                            scope=ldb.SCOPE_ONELEVEL,
                            expression=expression)
        self.assertEqual(len(res), 1)
        self.assertTrue(
            contains(res, "OU=23,OU=SEARCH_NON_UNIQUE,DC=SAMBA,DC=ORG"))

        #
        # search for target is max value + 1 so truncated
        # should return ou 03 as it's gt_max being searched for
        #
        expression = "(notUnique=" + gt_max.decode('ascii') + ")"
        res = self.l.search(base="OU=SEARCH_NON_UNIQUE,DC=SAMBA,DC=ORG",
                            scope=ldb.SCOPE_ONELEVEL,
                            expression=expression)
        self.assertEqual(len(res), 1)
        self.assertTrue(
            contains(res, "OU=03,OU=SEARCH_NON_UNIQUE,DC=SAMBA,DC=ORG"))

        #
        # scope one level and one level up one level up should get no matches
        #
        res = self.l.search(base="DC=SAMBA,DC=ORG",
                            scope=ldb.SCOPE_ONELEVEL,
                            expression=expression)
        self.assertEqual(len(res), 0)
        #
        # scope sub tree and one level up one level up should get 2 matches
        #
        res = self.l.search(base="DC=SAMBA,DC=ORG",
                            scope=ldb.SCOPE_SUBTREE,
                            expression=expression)
        self.assertEqual(len(res), 2)
        self.assertTrue(
            contains(res, "OU=03,OU=SEARCH_NON_UNIQUE,DC=SAMBA,DC=ORG"))
        self.assertTrue(
            contains(res, "OU=11,OU=SEARCH_NON_UNIQUE01,DC=SAMBA,DC=ORG"))

        #
        # search for target is max value - 1 so not truncated
        # should return ou 04
        #
        expression = "(notUnique=" + lt_max.decode('ascii') + ")"
        res = self.l.search(base="OU=SEARCH_NON_UNIQUE,DC=SAMBA,DC=ORG",
                            scope=ldb.SCOPE_ONELEVEL,
                            expression=expression)
        self.assertEqual(len(res), 1)
        self.assertTrue(
            contains(res, "OU=04,OU=SEARCH_NON_UNIQUE,DC=SAMBA,DC=ORG"))

        #
        # scope one level and one level up one level up should get no matches
        #
        res = self.l.search(base="DC=SAMBA,DC=ORG",
                            scope=ldb.SCOPE_ONELEVEL,
                            expression=expression)
        self.assertEqual(len(res), 0)

        #
        # scope sub tree and one level up one level up should get 2 matches
        #
        res = self.l.search(base="DC=SAMBA,DC=ORG",
                            scope=ldb.SCOPE_SUBTREE,
                            expression=expression)
        self.assertEqual(len(res), 2)
        self.assertTrue(
            contains(res, "OU=04,OU=SEARCH_NON_UNIQUE,DC=SAMBA,DC=ORG"))
        self.assertTrue(
            contains(res, "OU=12,OU=SEARCH_NON_UNIQUE01,DC=SAMBA,DC=ORG"))

    #
    # Test index key truncation for base64 encoded values
    #
    def test_index_truncated_base64_encoded_keys(self):
        value = b"aaaaaaaaaaaaaaaaaaaa\x02"
        # base64 encodes to "YWFhYWFhYWFhYWFhYWFhYWFhYWEC"

        # One less than max key length
        self.l.add({"dn": "OU=01,OU=BASE64,DC=SAMBA,DC=ORG",
                    "base64____lt": value,
                    "objectUUID": b"0123456789abcde0"})
        self.checkGuids(
            "@INDEX:BASE64____LT::YWFhYWFhYWFhYWFhYWFhYWFhYWEC",
            b"0123456789abcde0")

        # Equal max key length
        self.l.add({"dn": "OU=02,OU=BASE64,DC=SAMBA,DC=ORG",
                    "base64_____eq": value,
                    "objectUUID": b"0123456789abcde1"})
        self.checkGuids(
            "@INDEX:BASE64_____EQ::YWFhYWFhYWFhYWFhYWFhYWFhYWEC",
            b"0123456789abcde1")

        # One greater than max key length
        self.l.add({"dn": "OU=03,OU=BASE64,DC=SAMBA,DC=ORG",
                    "base64______gt": value,
                    "objectUUID": b"0123456789abcde2"})
        self.checkGuids(
            "@INDEX#BASE64______GT##YWFhYWFhYWFhYWFhYWFhYWFhYWE",
            b"0123456789abcde2")
    #
    # Test adding to non unique index with identical multivalued index
    # attributes
    #

    def test_index_multi_valued_identical_keys(self):
        # 0        1         2         3         4         5
        # 12345678901234567890123456789012345678901234567890
        # @INDEX:NOTUNIQUE:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        as_eq_max = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        bs_eq_max = b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

        try:
            self.l.add({"dn": "OU=01,OU=SEARCH_NON_UNIQUE,DC=SAMBA,DC=ORG",
                        "notUnique": [bs_eq_max, as_eq_max, as_eq_max],
                        "objectUUID": b"0123456789abcde0"})
            self.fail("Exception not thrown")
        except ldb.LdbError as e:
            code = e.args[0]
            self.assertEqual(ldb.ERR_ATTRIBUTE_OR_VALUE_EXISTS, code)

    #
    # Test non unique index with multivalued index attributes
    #  searched with non truncated keys
    #
    def test_search_index_multi_valued_truncated_keys(self):
        # 0        1         2         3         4         5
        # 12345678901234567890123456789012345678901234567890
        # @INDEX:NOTUNIQUE:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

        aa_gt_max = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ab_gt_max = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"
        bb_gt_max = b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

        self.l.add({"dn": "OU=01,OU=SEARCH_NON_UNIQUE,DC=SAMBA,DC=ORG",
                    "notUnique": [aa_gt_max, ab_gt_max, bb_gt_max],
                    "objectUUID": b"0123456789abcde0"})
        self.checkGuids(
            "@INDEX#NOTUNIQUE#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            b"0123456789abcde0" + b"0123456789abcde0")
        self.checkGuids(
            "@INDEX#NOTUNIQUE#bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            b"0123456789abcde0")

        expression = "(notUnique=" + aa_gt_max.decode('ascii') + ")"
        res = self.l.search(base="OU=SEARCH_NON_UNIQUE,DC=SAMBA,DC=ORG",
                            scope=ldb.SCOPE_ONELEVEL,
                            expression=expression)
        self.assertEqual(len(res), 1)
        self.assertTrue(
            contains(res, "OU=01,OU=SEARCH_NON_UNIQUE,DC=SAMBA,DC=ORG"))

        expression = "(notUnique=" + ab_gt_max.decode('ascii') + ")"
        res = self.l.search(base="OU=SEARCH_NON_UNIQUE,DC=SAMBA,DC=ORG",
                            scope=ldb.SCOPE_ONELEVEL,
                            expression=expression)
        self.assertEqual(len(res), 1)
        self.assertTrue(
            contains(res, "OU=01,OU=SEARCH_NON_UNIQUE,DC=SAMBA,DC=ORG"))

        expression = "(notUnique=" + bb_gt_max.decode('ascii') + ")"
        res = self.l.search(base="OU=SEARCH_NON_UNIQUE,DC=SAMBA,DC=ORG",
                            scope=ldb.SCOPE_ONELEVEL,
                            expression=expression)
        self.assertEqual(len(res), 1)
        self.assertTrue(
            contains(res, "OU=01,OU=SEARCH_NON_UNIQUE,DC=SAMBA,DC=ORG"))

    #
    # Test deletion of records with non unique index with multivalued index
    # attributes
    # replicate this to test modify with modify flags i.e. DELETE, REPLACE
    #
    def test_delete_index_multi_valued_truncated_keys(self):
        # 0        1         2         3         4         5
        # 12345678901234567890123456789012345678901234567890
        # @INDEX:NOTUNIQUE:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

        aa_gt_max = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ab_gt_max = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"
        bb_gt_max = b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        cc_gt_max = b"cccccccccccccccccccccccccccccccccc"

        self.l.add({"dn": "OU=01,OU=DELETE_NON_UNIQUE,DC=SAMBA,DC=ORG",
                    "notUnique": [aa_gt_max, ab_gt_max, bb_gt_max],
                    "objectUUID": b"0123456789abcde0"})
        self.l.add({"dn": "OU=02,OU=DELETE_NON_UNIQUE,DC=SAMBA,DC=ORG",
                    "notUnique": [aa_gt_max, ab_gt_max, cc_gt_max],
                    "objectUUID": b"0123456789abcde1"})
        self.checkGuids(
            "@INDEX#NOTUNIQUE#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            b"0123456789abcde0" + b"0123456789abcde0" +
            b"0123456789abcde1" + b"0123456789abcde1")
        self.checkGuids(
            "@INDEX#NOTUNIQUE#bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            b"0123456789abcde0")
        self.checkGuids(
            "@INDEX#NOTUNIQUE#ccccccccccccccccccccccccccccccccc",
            b"0123456789abcde1")

        res = self.l.search(
            base="DC=SAMBA,DC=ORG",
            expression="(notUnique=" + aa_gt_max.decode("ascii") + ")")
        self.assertEqual(2, len(res))
        self.assertTrue(
            contains(res, "OU=01,OU=DELETE_NON_UNIQUE,DC=SAMBA,DC=ORG"))
        self.assertTrue(
            contains(res, "OU=02,OU=DELETE_NON_UNIQUE,DC=SAMBA,DC=ORG"))

        self.l.delete("OU=02,OU=DELETE_NON_UNIQUE,DC=SAMBA,DC=ORG")
        self.checkGuids(
            "@INDEX#NOTUNIQUE#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            b"0123456789abcde0" + b"0123456789abcde0")
        self.checkGuids(
            "@INDEX#NOTUNIQUE#bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            b"0123456789abcde0")
        self.checkGuids(
            "@INDEX#NOTUNIQUE#ccccccccccccccccccccccccccccccccc",
            None)

        self.l.delete("OU=01,OU=DELETE_NON_UNIQUE,DC=SAMBA,DC=ORG")
        self.checkGuids(
            "@INDEX#NOTUNIQUE#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            None)
        self.checkGuids(
            "@INDEX#NOTUNIQUE#bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            None)
        self.checkGuids(
            "@INDEX#NOTUNIQUE#ccccccccccccccccccccccccccccccccc",
            None)

    #
    # Test modification of records with non unique index with multivalued index
    # attributes
    #
    def test_modify_index_multi_valued_truncated_keys(self):
        # 0        1         2         3         4         5
        # 12345678901234567890123456789012345678901234567890
        # @INDEX:NOTUNIQUE:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

        aa_gt_max = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ab_gt_max = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"
        bb_gt_max = b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        cc_gt_max = b"cccccccccccccccccccccccccccccccccc"

        self.l.add({"dn": "OU=01,OU=MODIFY_NON_UNIQUE,DC=SAMBA,DC=ORG",
                    "notUnique": [aa_gt_max, ab_gt_max, bb_gt_max],
                    "objectUUID": b"0123456789abcde0"})
        self.l.add({"dn": "OU=02,OU=MODIFY_NON_UNIQUE,DC=SAMBA,DC=ORG",
                    "notUnique": [aa_gt_max, ab_gt_max, cc_gt_max],
                    "objectUUID": b"0123456789abcde1"})
        self.checkGuids(
            "@INDEX#NOTUNIQUE#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            b"0123456789abcde0" + b"0123456789abcde0" +
            b"0123456789abcde1" + b"0123456789abcde1")
        self.checkGuids(
            "@INDEX#NOTUNIQUE#bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            b"0123456789abcde0")
        self.checkGuids(
            "@INDEX#NOTUNIQUE#ccccccccccccccccccccccccccccccccc",
            b"0123456789abcde1")

        res = self.l.search(
            base="DC=SAMBA,DC=ORG",
            expression="(notUnique=" + aa_gt_max.decode("ascii") + ")")
        self.assertEqual(2, len(res))
        self.assertTrue(
            contains(res, "OU=01,OU=MODIFY_NON_UNIQUE,DC=SAMBA,DC=ORG"))
        self.assertTrue(
            contains(res, "OU=02,OU=MODIFY_NON_UNIQUE,DC=SAMBA,DC=ORG"))

        #
        # Modify that does not change the indexed attribute
        #
        msg = ldb.Message()
        msg.dn = ldb.Dn(self.l, "OU=01,OU=MODIFY_NON_UNIQUE,DC=SAMBA,DC=ORG")
        msg["notUnique"] = ldb.MessageElement(
            [aa_gt_max, ab_gt_max, bb_gt_max],
            ldb.FLAG_MOD_REPLACE,
            "notUnique")
        self.l.modify(msg)
        #
        # As the modify is replacing the attribute with the same contents
        # there should be no changes to the indexes.
        #
        self.checkGuids(
            "@INDEX#NOTUNIQUE#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            b"0123456789abcde0" + b"0123456789abcde0" +
            b"0123456789abcde1" + b"0123456789abcde1")
        self.checkGuids(
            "@INDEX#NOTUNIQUE#bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            b"0123456789abcde0")
        self.checkGuids(
            "@INDEX#NOTUNIQUE#ccccccccccccccccccccccccccccccccc",
            b"0123456789abcde1")

        #
        # Modify that removes a value from the indexed attribute
        #
        msg = ldb.Message()
        msg.dn = ldb.Dn(self.l, "OU=01,OU=MODIFY_NON_UNIQUE,DC=SAMBA,DC=ORG")
        msg["notUnique"] = ldb.MessageElement(
            [aa_gt_max, bb_gt_max],
            ldb.FLAG_MOD_REPLACE,
            "notUnique")
        self.l.modify(msg)

        self.checkGuids(
            "@INDEX#NOTUNIQUE#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            b"0123456789abcde0" +
            b"0123456789abcde1" + b"0123456789abcde1")
        self.checkGuids(
            "@INDEX#NOTUNIQUE#bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            b"0123456789abcde0")
        self.checkGuids(
            "@INDEX#NOTUNIQUE#ccccccccccccccccccccccccccccccccc",
            b"0123456789abcde1")

        #
        # Modify that does a constrained delete the indexed attribute
        #
        msg = ldb.Message()
        msg.dn = ldb.Dn(self.l, "OU=02,OU=MODIFY_NON_UNIQUE,DC=SAMBA,DC=ORG")
        msg["notUnique"] = ldb.MessageElement(
            [ab_gt_max],
            ldb.FLAG_MOD_DELETE,
            "notUnique")
        self.l.modify(msg)

        self.checkGuids(
            "@INDEX#NOTUNIQUE#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            b"0123456789abcde0" + b"0123456789abcde1")
        self.checkGuids(
            "@INDEX#NOTUNIQUE#bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            b"0123456789abcde0")
        self.checkGuids(
            "@INDEX#NOTUNIQUE#ccccccccccccccccccccccccccccccccc",
            b"0123456789abcde1")

        #
        # Modify that does an unconstrained delete the indexed attribute
        #
        msg = ldb.Message()
        msg.dn = ldb.Dn(self.l, "OU=02,OU=MODIFY_NON_UNIQUE,DC=SAMBA,DC=ORG")
        msg["notUnique"] = ldb.MessageElement(
            [],
            ldb.FLAG_MOD_DELETE,
            "notUnique")
        self.l.modify(msg)

        self.checkGuids(
            "@INDEX#NOTUNIQUE#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            b"0123456789abcde0")
        self.checkGuids(
            "@INDEX#NOTUNIQUE#bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            b"0123456789abcde0")
        self.checkGuids(
            "@INDEX#NOTUNIQUE#ccccccccccccccccccccccccccccccccc",
            None)

        #
        # Modify that adds a value to the indexed attribute
        #
        msg = ldb.Message()
        msg.dn = ldb.Dn(self.l, "OU=02,OU=MODIFY_NON_UNIQUE,DC=SAMBA,DC=ORG")
        msg["notUnique"] = ldb.MessageElement(
            [cc_gt_max],
            ldb.FLAG_MOD_ADD,
            "notUnique")
        self.l.modify(msg)

        self.checkGuids(
            "@INDEX#NOTUNIQUE#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            b"0123456789abcde0")
        self.checkGuids(
            "@INDEX#NOTUNIQUE#bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            b"0123456789abcde0")
        self.checkGuids(
            "@INDEX#NOTUNIQUE#ccccccccccccccccccccccccccccccccc",
            b"0123456789abcde1")

        #
        # Modify that adds a values to the indexed attribute
        #
        msg = ldb.Message()
        msg.dn = ldb.Dn(self.l, "OU=02,OU=MODIFY_NON_UNIQUE,DC=SAMBA,DC=ORG")
        msg["notUnique"] = ldb.MessageElement(
            [aa_gt_max, ab_gt_max],
            ldb.FLAG_MOD_ADD,
            "notUnique")
        self.l.modify(msg)

        self.checkGuids(
            "@INDEX#NOTUNIQUE#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            b"0123456789abcde0" +
            b"0123456789abcde1" + b"0123456789abcde1")
        self.checkGuids(
            "@INDEX#NOTUNIQUE#bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            b"0123456789abcde0")
        self.checkGuids(
            "@INDEX#NOTUNIQUE#ccccccccccccccccccccccccccccccccc",
            b"0123456789abcde1")

    #
    # Test Sub tree searches when checkBaseOnSearch is enabled and the
    # DN indexes are truncated and collide.
    #
    def test_check_base_on_search_truncated_dn_keys(self):
        #
        # Except for the base DN's
        # all entries the DN index key gets truncated to
        #    0        1         2         3         4         5
        #    12345678901234567890123456789012345678901234567890
        #    @INDEX:@IDXDN:OU=??,OU=CHECK_BASE_DN_XXXX,DC=SAMBA
        # The base DN-s truncate to
        #    @INDEX:@IDXDN:OU=CHECK_BASE_DN_XXXX,DC=SAMBA,DC=OR
        #
        checkbaseonsearch = {"dn": "@OPTIONS",
                             "checkBaseOnSearch": b"TRUE"}
        self.l.add(checkbaseonsearch)

        self.l.add({"dn": "OU=CHECK_BASE_DN_XXXX,DC=SAMBA,DC=OR1",
                    "objectUUID": b"0123456789abcdef"})
        self.l.add({"dn": "OU=CHECK_BASE_DN_XXXX,DC=SAMBA,DC=OR2",
                    "objectUUID": b"0123456789abcdee"})
        self.checkGuids(
            "@INDEX#@IDXDN#OU=CHECK_BASE_DN_XXXX,DC=SAMBA,DC=OR",
            b"0123456789abcdee" + b"0123456789abcdef")

        self.l.add({"dn": "OU=01,OU=CHECK_BASE_DN_XXXX,DC=SAMBA,DC=OR1",
                    "objectUUID": b"0123456789abcdec"})
        self.l.add({"dn": "OU=01,OU=CHECK_BASE_DN_XXXX,DC=SAMBA,DC=OR2",
                    "objectUUID": b"0123456789abcdeb"})
        self.l.add({"dn": "OU=01,OU=CHECK_BASE_DN_XXXX,DC=SAMBA,DC=OR3",
                    "objectUUID": b"0123456789abcded"})
        self.checkGuids(
            "@INDEX#@IDXDN#OU=01,OU=CHECK_BASE_DN_XXXX,DC=SAMBA",
            b"0123456789abcdeb" + b"0123456789abcdec" + b"0123456789abcded")

        self.l.add({"dn": "OU=02,OU=CHECK_BASE_DN_XXXX,DC=SAMBA,DC=OR1",
                    "objectUUID": b"0123456789abcde0"})
        self.l.add({"dn": "OU=02,OU=CHECK_BASE_DN_XXXX,DC=SAMBA,DC=OR2",
                    "objectUUID": b"0123456789abcde1"})
        self.l.add({"dn": "OU=02,OU=CHECK_BASE_DN_XXXX,DC=SAMBA,DC=OR3",
                    "objectUUID": b"0123456789abcde2"})
        self.checkGuids(
            "@INDEX#@IDXDN#OU=02,OU=CHECK_BASE_DN_XXXX,DC=SAMBA",
            b"0123456789abcde0" + b"0123456789abcde1" + b"0123456789abcde2")

        res = self.l.search(base="OU=CHECK_BASE_DN_XXXX,DC=SAMBA,DC=OR1",
                            scope=ldb.SCOPE_SUBTREE)
        self.assertEqual(len(res), 3)
        self.assertTrue(
            contains(res, "OU=CHECK_BASE_DN_XXXX,DC=SAMBA,DC=OR1"))
        self.assertTrue(
            contains(res, "OU=01,OU=CHECK_BASE_DN_XXXX,DC=SAMBA,DC=OR1"))
        self.assertTrue(
            contains(res, "OU=02,OU=CHECK_BASE_DN_XXXX,DC=SAMBA,DC=OR1"))

        res = self.l.search(base="OU=CHECK_BASE_DN_XXXX,DC=SAMBA,DC=OR2",
                            scope=ldb.SCOPE_SUBTREE)
        self.assertEqual(len(res), 3)
        self.assertTrue(
            contains(res, "OU=CHECK_BASE_DN_XXXX,DC=SAMBA,DC=OR2"))
        self.assertTrue(
            contains(res, "OU=01,OU=CHECK_BASE_DN_XXXX,DC=SAMBA,DC=OR2"))
        self.assertTrue(
            contains(res, "OU=02,OU=CHECK_BASE_DN_XXXX,DC=SAMBA,DC=OR2"))

        try:
            res = self.l.search(base="OU=CHECK_BASE_DN_XXXX,DC=SAMBA,DC=OR3",
                                scope=ldb.SCOPE_SUBTREE)
            self.fail("Expected exception no thrown")
        except ldb.LdbError as e:
            code = e.args[0]
            self.assertEqual(ldb.ERR_NO_SUCH_OBJECT, code)


# Run the index truncation tests against an lmdb backend
class MaxIndexKeyLengthTestsLmdb(MaxIndexKeyLengthTests):

    def setUp(self):
        if os.environ.get('HAVE_LMDB', '1') == '0':
            self.skipTest("No lmdb backend")
        self.prefix = MDB_PREFIX
        super(MaxIndexKeyLengthTestsLmdb, self).setUp()

    def tearDown(self):
        super(MaxIndexKeyLengthTestsLmdb, self).tearDown()


class OrderedIntegerRangeTests(LdbBaseTest):

    def tearDown(self):
        shutil.rmtree(self.testdir)
        super(OrderedIntegerRangeTests, self).tearDown()

        # Ensure the LDB is closed now, so we close the FD
        del(self.l)

    def setUp(self):
        super(OrderedIntegerRangeTests, self).setUp()
        self.testdir = tempdir()
        self.filename = os.path.join(self.testdir, "ordered_integer_test.ldb")

        self.l = ldb.Ldb(self.url(),
                         options=self.options())
        self.l.add({"dn": "@ATTRIBUTES",
                    "int64attr": "ORDERED_INTEGER"})
        self.l.add({"dn": "@INDEXLIST",
                    "@IDXATTR": [b"int64attr"],
                    "@IDXONE": [b"1"],
                    "@IDXGUID": [b"objectUUID"],
                    "@IDX_DN_GUID": [b"GUID"]})

    def options(self):
        if self.prefix == MDB_PREFIX:
            return ['modules:rdn_name',
                    'disable_full_db_scan_for_self_test:1']
        else:
            return ['modules:rdn_name']

    def test_comparison_expression(self):
        int64_max = 2**63-1
        int64_min = -2**63
        test_nums = list(range(-5, 5))
        test_nums += list(range(int64_max-5, int64_max+1))
        test_nums += list(range(int64_min, int64_min+5))
        test_nums = sorted(test_nums)

        for (i, num) in enumerate(test_nums):
            ouuid = 0x0123456789abcdef + i
            ouuid_s = bytes(('0' + hex(ouuid)[2:]).encode())
            self.l.add({"dn": "OU=COMPTESTOU{},DC=SAMBA,DC=ORG".format(i),
                        "objectUUID": ouuid_s,
                        "int64attr": str(num)})

        def assert_int64_expr(expr, py_expr=None):
            res = self.l.search(base="DC=SAMBA,DC=ORG",
                                scope=ldb.SCOPE_SUBTREE,
                                expression="(int64attr%s)" % (expr))

            if not py_expr:
                py_expr = expr
            expect = [n for n in test_nums if eval(str(n) + py_expr)]
            vals = sorted([int(r.get("int64attr")[0]) for r in res])
            self.assertEqual(len(res), len(expect))
            self.assertEqual(set(vals), set(expect))
            self.assertEqual(expect, vals)

        assert_int64_expr(">=-2")
        assert_int64_expr("<=2")
        assert_int64_expr(">=" + str(int64_min))
        assert_int64_expr("<=" + str(int64_min))
        assert_int64_expr("<=" + str(int64_min+1))
        assert_int64_expr("<=" + str(int64_max))
        assert_int64_expr(">=" + str(int64_max))
        assert_int64_expr(">=" + str(int64_max-1))
        assert_int64_expr("=10", "==10")

    def test_comparison_expression_duplicates(self):
        int64_max = 2**63-1
        int64_min = -2**63
        test_nums = list(range(-5, 5)) * 3
        test_nums += list(range(-20, 20, 5)) * 2
        test_nums += list(range(-50, 50, 15))
        test_nums = sorted(test_nums)

        for (i, num) in enumerate(test_nums):
            ouuid = 0x0123456789abcdef + i
            ouuid_s = bytes(('0' + hex(ouuid)[2:]).encode())
            self.l.add({"dn": "OU=COMPTESTOU{},DC=SAMBA,DC=ORG".format(i),
                        "objectUUID": ouuid_s,
                        "int64attr": str(num)})

        def assert_int64_expr(expr, py_expr=None):
            res = self.l.search(base="DC=SAMBA,DC=ORG",
                                scope=ldb.SCOPE_SUBTREE,
                                expression="(int64attr%s)" % (expr))

            if not py_expr:
                py_expr = expr
            expect = [n for n in test_nums if eval(str(n) + py_expr)]
            vals = sorted([int(r.get("int64attr")[0]) for r in res])
            self.assertEqual(len(res), len(expect))
            self.assertEqual(set(vals), set(expect))
            self.assertEqual(expect, vals)

        assert_int64_expr(">=-2")
        assert_int64_expr("<=2")
        assert_int64_expr(">=" + str(int64_min))
        assert_int64_expr("<=" + str(int64_min))
        assert_int64_expr("<=" + str(int64_min+1))
        assert_int64_expr("<=" + str(int64_max))
        assert_int64_expr(">=" + str(int64_max))
        assert_int64_expr(">=" + str(int64_max-1))
        assert_int64_expr("=-5", "==-5")
        assert_int64_expr("=5", "==5")


# Run the ordered integer range tests against an lmdb backend
class OrderedIntegerRangeTestsLmdb(OrderedIntegerRangeTests):

    def setUp(self):
        if os.environ.get('HAVE_LMDB', '1') == '0':
            self.skipTest("No lmdb backend")
        self.prefix = MDB_PREFIX
        super(OrderedIntegerRangeTestsLmdb, self).setUp()

    def tearDown(self):
        super(OrderedIntegerRangeTestsLmdb, self).tearDown()


# Run the index truncation tests against an lmdb backend
class RejectSubDBIndex(LdbBaseTest):

    def setUp(self):
        if os.environ.get('HAVE_LMDB', '1') == '0':
            self.skipTest("No lmdb backend")
        self.prefix = MDB_PREFIX
        super(RejectSubDBIndex, self).setUp()
        self.testdir = tempdir()
        self.filename = os.path.join(self.testdir,
                                     "reject_subidx_test.ldb")
        self.l = ldb.Ldb(self.url(),
                         options=[
                             "modules:rdn_name"])

    def tearDown(self):
        super(RejectSubDBIndex, self).tearDown()

    def test_try_subdb_index(self):
        try:
            self.l.add({"dn": "@INDEXLIST",
                        "@IDX_LMDB_SUBDB": [b"1"],
                        "@IDXONE": [b"1"],
                        "@IDXGUID": [b"objectUUID"],
                        "@IDX_DN_GUID": [b"GUID"],
                        })
        except ldb.LdbError as e:
            code = e.args[0]
            string = e.args[1]
            self.assertEqual(ldb.ERR_OPERATIONS_ERROR, code)
            self.assertIn("sub-database index", string)


if __name__ == '__main__':
    import unittest
    unittest.TestProgram()
