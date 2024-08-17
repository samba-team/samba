#!/usr/bin/env python3
# Simple tests for the ldb python bindings.
# Copyright (C) 2007 Jelmer Vernooij <jelmer@samba.org>

import os
import sys
sys.path.insert(0, "bin/python")
import ldb
import shutil

from api_base import (
    MDB_PREFIX,
    MDB_INDEX_OBJ,
    tempdir,
    LdbBaseTest
)


class AddModifyTests(LdbBaseTest):
    def tearDown(self):
        shutil.rmtree(self.testdir)
        super().tearDown()

        # Ensure the LDB is closed now, so we close the FD
        del(self.l)

    def setUp(self):
        super().setUp()
        self.testdir = tempdir()
        self.filename = os.path.join(self.testdir, "add_test.ldb")
        self.l = ldb.Ldb(self.url(),
                         flags=self.flags(),
                         options=["modules:rdn_name"])
        try:
            self.l.add(self.index)
        except AttributeError:
            pass

        self.l.add({"dn": "DC=SAMBA,DC=ORG",
                    "name": b"samba.org",
                    "objectUUID": b"0123456789abcdef"})
        self.l.add({"dn": "@ATTRIBUTES",
                    "objectUUID": "UNIQUE_INDEX"})

    def test_add_dup(self):
        self.l.add({"dn": "OU=DUP,DC=SAMBA,DC=ORG",
                    "name": b"Admins",
                    "x": "z", "y": "a",
                    "objectUUID": b"0123456789abcde1"})
        try:
            self.l.add({"dn": "OU=DUP,DC=SAMBA,DC=ORG",
                        "name": b"Admins",
                        "x": "z", "y": "a",
                        "objectUUID": b"0123456789abcde2"})
            self.fail("Should have failed adding duplicate entry")
        except ldb.LdbError as err:
            enum = err.args[0]
            self.assertEqual(enum, ldb.ERR_ENTRY_ALREADY_EXISTS)

    def test_add_bad(self):
        try:
            self.l.add({"dn": "BAD,DC=SAMBA,DC=ORG",
                        "name": b"Admins",
                        "x": "z", "y": "a",
                        "objectUUID": b"0123456789abcde1"})
            self.fail("Should have failed adding entry with invalid DN")
        except ldb.LdbError as err:
            enum = err.args[0]
            self.assertEqual(enum, ldb.ERR_INVALID_DN_SYNTAX)

    def test_add_del_add(self):
        self.l.add({"dn": "OU=DUP,DC=SAMBA,DC=ORG",
                    "name": b"Admins",
                    "x": "z", "y": "a",
                    "objectUUID": b"0123456789abcde1"})
        self.l.delete("OU=DUP,DC=SAMBA,DC=ORG")
        self.l.add({"dn": "OU=DUP,DC=SAMBA,DC=ORG",
                    "name": b"Admins",
                    "x": "z", "y": "a",
                    "objectUUID": b"0123456789abcde2"})

    def test_add_move_add(self):
        self.l.add({"dn": "OU=DUP,DC=SAMBA,DC=ORG",
                    "name": b"Admins",
                    "x": "z", "y": "a",
                    "objectUUID": b"0123456789abcde1"})
        self.l.rename("OU=DUP,DC=SAMBA,DC=ORG",
                      "OU=DUP2,DC=SAMBA,DC=ORG")
        self.l.add({"dn": "OU=DUP,DC=SAMBA,DC=ORG",
                    "name": b"Admins",
                    "x": "z", "y": "a",
                    "objectUUID": b"0123456789abcde2"})

    def test_add_move_fail_move_move(self):
        self.l.add({"dn": "OU=DUP,DC=SAMBA,DC=ORG",
                    "name": b"Admins",
                    "x": "z", "y": "a",
                    "objectUUID": b"0123456789abcde1"})
        self.l.add({"dn": "OU=DUP2,DC=SAMBA,DC=ORG",
                    "name": b"Admins",
                    "x": "z", "y": "a",
                    "objectUUID": b"0123456789abcde2"})

        res2 = self.l.search(base="DC=SAMBA,DC=ORG",
                             scope=ldb.SCOPE_SUBTREE,
                             expression="(objectUUID=0123456789abcde1)")
        self.assertEqual(len(res2), 1)
        self.assertEqual(str(res2[0].dn), "OU=DUP,DC=SAMBA,DC=ORG")

        res3 = self.l.search(base="DC=SAMBA,DC=ORG",
                             scope=ldb.SCOPE_SUBTREE,
                             expression="(objectUUID=0123456789abcde2)")
        self.assertEqual(len(res3), 1)
        self.assertEqual(str(res3[0].dn), "OU=DUP2,DC=SAMBA,DC=ORG")

        try:
            self.l.rename("OU=DUP,DC=SAMBA,DC=ORG",
                          "OU=DUP2,DC=SAMBA,DC=ORG")
            self.fail("Should have failed on duplicate DN")
        except ldb.LdbError as err:
            enum = err.args[0]
            self.assertEqual(enum, ldb.ERR_ENTRY_ALREADY_EXISTS)

        self.l.rename("OU=DUP2,DC=SAMBA,DC=ORG",
                      "OU=DUP3,DC=SAMBA,DC=ORG")

        self.l.rename("OU=DUP,DC=SAMBA,DC=ORG",
                      "OU=DUP2,DC=SAMBA,DC=ORG")

        res2 = self.l.search(base="DC=SAMBA,DC=ORG",
                             scope=ldb.SCOPE_SUBTREE,
                             expression="(objectUUID=0123456789abcde1)")
        self.assertEqual(len(res2), 1)
        self.assertEqual(str(res2[0].dn), "OU=DUP2,DC=SAMBA,DC=ORG")

        res3 = self.l.search(base="DC=SAMBA,DC=ORG",
                             scope=ldb.SCOPE_SUBTREE,
                             expression="(objectUUID=0123456789abcde2)")
        self.assertEqual(len(res3), 1)
        self.assertEqual(str(res3[0].dn), "OU=DUP3,DC=SAMBA,DC=ORG")

    def test_move_missing(self):
        try:
            self.l.rename("OU=DUP,DC=SAMBA,DC=ORG",
                          "OU=DUP2,DC=SAMBA,DC=ORG")
            self.fail("Should have failed on missing")
        except ldb.LdbError as err:
            enum = err.args[0]
            self.assertEqual(enum, ldb.ERR_NO_SUCH_OBJECT)

    def test_move_missing2(self):
        self.l.add({"dn": "OU=DUP2,DC=SAMBA,DC=ORG",
                    "name": b"Admins",
                    "x": "z", "y": "a",
                    "objectUUID": b"0123456789abcde2"})

        try:
            self.l.rename("OU=DUP,DC=SAMBA,DC=ORG",
                          "OU=DUP2,DC=SAMBA,DC=ORG")
            self.fail("Should have failed on missing")
        except ldb.LdbError as err:
            enum = err.args[0]
            self.assertEqual(enum, ldb.ERR_NO_SUCH_OBJECT)

    def test_move_bad(self):
        self.l.add({"dn": "OU=DUP2,DC=SAMBA,DC=ORG",
                    "name": b"Admins",
                    "x": "z", "y": "a",
                    "objectUUID": b"0123456789abcde2"})

        try:
            self.l.rename("OUXDUP,DC=SAMBA,DC=ORG",
                          "OU=DUP2,DC=SAMBA,DC=ORG")
            self.fail("Should have failed on invalid DN")
        except ldb.LdbError as err:
            enum = err.args[0]
            self.assertEqual(enum, ldb.ERR_INVALID_DN_SYNTAX)

    def test_move_bad2(self):
        self.l.add({"dn": "OU=DUP2,DC=SAMBA,DC=ORG",
                    "name": b"Admins",
                    "x": "z", "y": "a",
                    "objectUUID": b"0123456789abcde2"})

        try:
            self.l.rename("OU=DUP,DC=SAMBA,DC=ORG",
                          "OUXDUP2,DC=SAMBA,DC=ORG")
            self.fail("Should have failed on missing")
        except ldb.LdbError as err:
            enum = err.args[0]
            self.assertEqual(enum, ldb.ERR_INVALID_DN_SYNTAX)

    def test_move_fail_move_add(self):
        self.l.add({"dn": "OU=DUP,DC=SAMBA,DC=ORG",
                    "name": b"Admins",
                    "x": "z", "y": "a",
                    "objectUUID": b"0123456789abcde1"})
        self.l.add({"dn": "OU=DUP2,DC=SAMBA,DC=ORG",
                    "name": b"Admins",
                    "x": "z", "y": "a",
                    "objectUUID": b"0123456789abcde2"})
        try:
            self.l.rename("OU=DUP,DC=SAMBA,DC=ORG",
                          "OU=DUP2,DC=SAMBA,DC=ORG")
            self.fail("Should have failed on duplicate DN")
        except ldb.LdbError as err:
            enum = err.args[0]
            self.assertEqual(enum, ldb.ERR_ENTRY_ALREADY_EXISTS)

        self.l.rename("OU=DUP2,DC=SAMBA,DC=ORG",
                      "OU=DUP3,DC=SAMBA,DC=ORG")

        self.l.add({"dn": "OU=DUP2,DC=SAMBA,DC=ORG",
                    "name": b"Admins",
                    "x": "z", "y": "a",
                    "objectUUID": b"0123456789abcde3"})


class AddModifyTestsLmdb(AddModifyTests):

    def setUp(self):
        if os.environ.get('HAVE_LMDB', '1') == '0':
            self.skipTest("No lmdb backend")
        self.prefix = MDB_PREFIX
        self.index = MDB_INDEX_OBJ
        super().setUp()


class IndexedAddModifyTests(AddModifyTests):
    """Test searches using the index, to ensure the index doesn't
       break things"""

    def setUp(self):
        if not hasattr(self, 'index'):
            self.index = {"dn": "@INDEXLIST",
                          "@IDXATTR": [b"x", b"y", b"ou", b"objectUUID", b"z"],
                          "@IDXONE": [b"1"]}
        super().setUp()

    def test_duplicate_GUID(self):
        try:
            self.l.add({"dn": "OU=DUPGUID,DC=SAMBA,DC=ORG",
                        "name": b"Admins",
                        "x": "z", "y": "a",
                        "objectUUID": b"0123456789abcdef"})
            self.fail("Should have failed adding duplicate GUID")
        except ldb.LdbError as err:
            enum = err.args[0]
            self.assertEqual(enum, ldb.ERR_CONSTRAINT_VIOLATION)

    def test_duplicate_name_dup_GUID(self):
        self.l.add({"dn": "OU=ADMIN,DC=SAMBA,DC=ORG",
                    "name": b"Admins",
                    "x": "z", "y": "a",
                    "objectUUID": b"a123456789abcdef"})
        try:
            self.l.add({"dn": "OU=ADMIN,DC=SAMBA,DC=ORG",
                        "name": b"Admins",
                        "x": "z", "y": "a",
                        "objectUUID": b"a123456789abcdef"})
            self.fail("Should have failed adding duplicate GUID")
        except ldb.LdbError as err:
            enum = err.args[0]
            self.assertEqual(enum, ldb.ERR_ENTRY_ALREADY_EXISTS)

    def test_duplicate_name_dup_GUID2(self):
        self.l.add({"dn": "OU=ADMIN,DC=SAMBA,DC=ORG",
                    "name": b"Admins",
                    "x": "z", "y": "a",
                    "objectUUID": b"abc3456789abcdef"})
        try:
            self.l.add({"dn": "OU=ADMIN,DC=SAMBA,DC=ORG",
                        "name": b"Admins",
                        "x": "z", "y": "a",
                        "objectUUID": b"aaa3456789abcdef"})
            self.fail("Should have failed adding duplicate DN")
        except ldb.LdbError as err:
            enum = err.args[0]
            self.assertEqual(enum, ldb.ERR_ENTRY_ALREADY_EXISTS)

        # Checking the GUID didn't stick in the index
        self.l.add({"dn": "OU=DUP,DC=SAMBA,DC=ORG",
                    "name": b"Admins",
                    "x": "z", "y": "a",
                    "objectUUID": b"aaa3456789abcdef"})

    def test_add_dup_guid_add(self):
        self.l.add({"dn": "OU=DUP,DC=SAMBA,DC=ORG",
                    "name": b"Admins",
                    "x": "z", "y": "a",
                    "objectUUID": b"0123456789abcde1"})
        try:
            self.l.add({"dn": "OU=DUP2,DC=SAMBA,DC=ORG",
                        "name": b"Admins",
                        "x": "z", "y": "a",
                        "objectUUID": b"0123456789abcde1"})
            self.fail("Should have failed on duplicate GUID")

        except ldb.LdbError as err:
            enum = err.args[0]
            self.assertEqual(enum, ldb.ERR_CONSTRAINT_VIOLATION)

        self.l.add({"dn": "OU=DUP2,DC=SAMBA,DC=ORG",
                    "name": b"Admins",
                    "x": "z", "y": "a",
                    "objectUUID": b"0123456789abcde2"})

    def test_duplicate_index_values(self):
        self.l.add({"dn": "OU=DIV1,DC=SAMBA,DC=ORG",
                    "name": b"Admins",
                    "z": "1",
                    "objectUUID": b"0123456789abcdff"})
        self.l.add({"dn": "OU=DIV2,DC=SAMBA,DC=ORG",
                    "name": b"Admins",
                    "z": "1",
                    "objectUUID": b"0123456789abcdfd"})


class GUIDIndexedAddModifyTests(IndexedAddModifyTests):
    """Test searches using the index, to ensure the index doesn't
       break things"""

    def setUp(self):
        self.index = {"dn": "@INDEXLIST",
                      "@IDXATTR": [b"x", b"y", b"ou"],
                      "@IDXONE": [b"1"],
                      "@IDXGUID": [b"objectUUID"],
                      "@IDX_DN_GUID": [b"GUID"]}
        super().setUp()


class GUIDTransIndexedAddModifyTests(GUIDIndexedAddModifyTests):
    """Test GUID index behaviour insdie the transaction"""

    def setUp(self):
        super().setUp()
        self.l.transaction_start()

    def tearDown(self):
        self.l.transaction_commit()
        super().tearDown()


class TransIndexedAddModifyTests(IndexedAddModifyTests):
    """Test index behaviour insdie the transaction"""

    def setUp(self):
        super().setUp()
        self.l.transaction_start()

    def tearDown(self):
        self.l.transaction_commit()
        super().tearDown()


class GuidIndexedAddModifyTestsLmdb(GUIDIndexedAddModifyTests):

    def setUp(self):
        if os.environ.get('HAVE_LMDB', '1') == '0':
            self.skipTest("No lmdb backend")
        self.prefix = MDB_PREFIX
        super().setUp()


class GuidTransIndexedAddModifyTestsLmdb(GUIDTransIndexedAddModifyTests):

    def setUp(self):
        if os.environ.get('HAVE_LMDB', '1') == '0':
            self.skipTest("No lmdb backend")
        self.prefix = MDB_PREFIX
        super().setUp()


if __name__ == '__main__':
    import unittest
    unittest.TestProgram()
