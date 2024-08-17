#!/usr/bin/env python3
# Simple tests for the ldb python bindings.
# Copyright (C) 2007 Jelmer Vernooij <jelmer@samba.org>

import os
import sys
sys.path.insert(0, "bin/python")
import ldb
import gc
import time
import shutil

from api_base import (
    MDB_PREFIX,
    MDB_INDEX_OBJ,
    tempdir,
    LdbBaseTest
)


class SearchTests(LdbBaseTest):
    def tearDown(self):
        shutil.rmtree(self.testdir)
        super().tearDown()

        # Ensure the LDB is closed now, so we close the FD
        del(self.l)

    def setUp(self):
        super().setUp()
        self.testdir = tempdir()
        self.filename = os.path.join(self.testdir, "search_test.ldb")
        options = ["modules:rdn_name"]
        if hasattr(self, 'IDXCHECK'):
            options.append("disable_full_db_scan_for_self_test:1")
        self.l = ldb.Ldb(self.url(),
                         flags=self.flags(),
                         options=options)
        try:
            self.l.add(self.index)
        except AttributeError:
            pass

        self.l.add({"dn": "@ATTRIBUTES",
                    "DC": "CASE_INSENSITIVE"})

        # Note that we can't use the name objectGUID here, as we
        # want to stay clear of the objectGUID handler in LDB and
        # instead use just the 16 bytes raw, which we just keep
        # to printable chars here for ease of handling.

        self.l.add({"dn": "DC=ORG",
                    "name": b"org",
                    "objectUUID": b"0000000000abcdef"})
        self.l.add({"dn": "DC=EXAMPLE,DC=ORG",
                    "name": b"org",
                    "objectUUID": b"0000000001abcdef"})
        self.l.add({"dn": "OU=OU1,DC=EXAMPLE,DC=ORG",
                    "name": b"OU #1",
                    "x": "y", "y": "a",
                    "objectUUID": b"0023456789abcde3"})
        self.l.add({"dn": "OU=OU2,DC=EXAMPLE,DC=ORG",
                    "name": b"OU #2",
                    "x": "y", "y": "a",
                    "objectUUID": b"0023456789abcde4"})
        self.l.add({"dn": "OU=OU3,DC=EXAMPLE,DC=ORG",
                    "name": b"OU #3",
                    "x": "y", "y": "a",
                    "objectUUID": b"0023456789abcde5"})
        self.l.add({"dn": "OU=OU4,DC=EXAMPLE,DC=ORG",
                    "name": b"OU #4",
                    "x": "z", "y": "b",
                    "objectUUID": b"0023456789abcde6"})
        self.l.add({"dn": "OU=OU5,DC=EXAMPLE,DC=ORG",
                    "name": b"OU #5",
                    "x": "y", "y": "a",
                    "objectUUID": b"0023456789abcde7"})
        self.l.add({"dn": "OU=OU6,DC=EXAMPLE,DC=ORG",
                    "name": b"OU #6",
                    "x": "y", "y": "a",
                    "objectUUID": b"0023456789abcde8"})
        self.l.add({"dn": "OU=OU7,DC=EXAMPLE,DC=ORG",
                    "name": b"OU #7",
                    "x": "y", "y": "c",
                    "objectUUID": b"0023456789abcde9"})
        self.l.add({"dn": "OU=OU8,DC=EXAMPLE,DC=ORG",
                    "name": b"OU #8",
                    "x": "y", "y": "b",
                    "objectUUID": b"0023456789abcde0"})
        self.l.add({"dn": "OU=OU9,DC=EXAMPLE,DC=ORG",
                    "name": b"OU #9",
                    "x": "y", "y": "a",
                    "objectUUID": b"0023456789abcdea"})

        self.l.add({"dn": "DC=EXAMPLE,DC=COM",
                    "name": b"org",
                    "objectUUID": b"0000000011abcdef"})

        self.l.add({"dn": "DC=EXAMPLE,DC=NET",
                    "name": b"org",
                    "objectUUID": b"0000000021abcdef"})

        self.l.add({"dn": "OU=UNIQUE,DC=EXAMPLE,DC=NET",
                    "objectUUID": b"0000000022abcdef"})

        self.l.add({"dn": "DC=SAMBA,DC=ORG",
                    "name": b"samba.org",
                    "objectUUID": b"0123456789abcdef"})
        self.l.add({"dn": "OU=ADMIN,DC=SAMBA,DC=ORG",
                    "name": b"Admins",
                    "x": "z", "y": "a",
                    "objectUUID": b"0123456789abcde1"})
        self.l.add({"dn": "OU=USERS,DC=SAMBA,DC=ORG",
                    "name": b"Users",
                    "x": "z", "y": "a",
                    "objectUUID": b"0123456789abcde2"})
        self.l.add({"dn": "OU=OU1,DC=SAMBA,DC=ORG",
                    "name": b"OU #1",
                    "x": "y", "y": "a",
                    "objectUUID": b"0123456789abcde3"})
        self.l.add({"dn": "OU=OU2,DC=SAMBA,DC=ORG",
                    "name": b"OU #2",
                    "x": "y", "y": "a",
                    "objectUUID": b"0123456789abcde4"})
        self.l.add({"dn": "OU=OU3,DC=SAMBA,DC=ORG",
                    "name": b"OU #3",
                    "x": "y", "y": "a",
                    "objectUUID": b"0123456789abcde5"})
        self.l.add({"dn": "OU=OU4,DC=SAMBA,DC=ORG",
                    "name": b"OU #4",
                    "x": "y", "y": "a",
                    "objectUUID": b"0123456789abcde6"})
        self.l.add({"dn": "OU=OU5,DC=SAMBA,DC=ORG",
                    "name": b"OU #5",
                    "x": "y", "y": "a",
                    "objectUUID": b"0123456789abcde7"})
        self.l.add({"dn": "OU=OU6,DC=SAMBA,DC=ORG",
                    "name": b"OU #6",
                    "x": "y", "y": "a",
                    "objectUUID": b"0123456789abcde8"})
        self.l.add({"dn": "OU=OU7,DC=SAMBA,DC=ORG",
                    "name": b"OU #7",
                    "x": "y", "y": "a",
                    "objectUUID": b"0123456789abcde9"})
        self.l.add({"dn": "OU=OU8,DC=SAMBA,DC=ORG",
                    "name": b"OU #8",
                    "x": "y", "y": "a",
                    "objectUUID": b"0123456789abcde0"})
        self.l.add({"dn": "OU=OU9,DC=SAMBA,DC=ORG",
                    "name": b"OU #9",
                    "x": "y", "y": "a",
                    "objectUUID": b"0123456789abcdea"})
        self.l.add({"dn": "OU=OU10,DC=SAMBA,DC=ORG",
                    "name": b"OU #10",
                    "x": "y", "y": "a",
                    "objectUUID": b"0123456789abcdeb"})
        self.l.add({"dn": "OU=OU11,DC=SAMBA,DC=ORG",
                    "name": b"OU #10",
                    "x": "y", "y": "a",
                    "objectUUID": b"0123456789abcdec"})
        self.l.add({"dn": "OU=OU12,DC=SAMBA,DC=ORG",
                    "name": b"OU #10",
                    "x": "y", "y": "b",
                    "objectUUID": b"0123456789abcded"})
        self.l.add({"dn": "OU=OU13,DC=SAMBA,DC=ORG",
                    "name": b"OU #10",
                    "x": "x", "y": "b",
                    "objectUUID": b"0123456789abcdee"})
        self.l.add({"dn": "OU=OU14,DC=SAMBA,DC=ORG",
                    "name": b"OU #10",
                    "x": "x", "y": "b",
                    "objectUUID": b"0123456789abcd01"})
        self.l.add({"dn": "OU=OU15,DC=SAMBA,DC=ORG",
                    "name": b"OU #10",
                    "x": "x", "y": "b",
                    "objectUUID": b"0123456789abcd02"})
        self.l.add({"dn": "OU=OU16,DC=SAMBA,DC=ORG",
                    "name": b"OU #10",
                    "x": "x", "y": "b",
                    "objectUUID": b"0123456789abcd03"})
        self.l.add({"dn": "OU=OU17,DC=SAMBA,DC=ORG",
                    "name": b"OU #10",
                    "x": "x", "y": "b",
                    "objectUUID": b"0123456789abcd04"})
        self.l.add({"dn": "OU=OU18,DC=SAMBA,DC=ORG",
                    "name": b"OU #10",
                    "x": "x", "y": "b",
                    "objectUUID": b"0123456789abcd05"})
        self.l.add({"dn": "OU=OU19,DC=SAMBA,DC=ORG",
                    "name": b"OU #10",
                    "x": "x", "y": "b",
                    "objectUUID": b"0123456789abcd06"})
        self.l.add({"dn": "OU=OU20,DC=SAMBA,DC=ORG",
                    "name": b"OU #10",
                    "x": "x", "y": "b",
                    "objectUUID": b"0123456789abcd07"})
        self.l.add({"dn": "OU=OU21,DC=SAMBA,DC=ORG",
                    "name": b"OU #10",
                    "x": "x", "y": "c",
                    "objectUUID": b"0123456789abcd08"})
        self.l.add({"dn": "OU=OU22,DC=SAMBA,DC=ORG",
                    "name": b"OU #10",
                    "x": "x", "y": "c",
                    "objectUUID": b"0123456789abcd09"})

    def test_base(self):
        """Testing a search"""

        res11 = self.l.search(base="OU=OU11,DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_BASE)
        self.assertEqual(len(res11), 1)

    def test_base_lower(self):
        """Testing a search"""

        res11 = self.l.search(base="OU=OU11,DC=samba,DC=org",
                              scope=ldb.SCOPE_BASE)
        self.assertEqual(len(res11), 1)

    def test_base_or(self):
        """Testing a search"""

        res11 = self.l.search(base="OU=OU11,DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_BASE,
                              expression="(|(ou=ou11)(ou=ou12))")
        self.assertEqual(len(res11), 1)

    def test_base_or2(self):
        """Testing a search"""

        res11 = self.l.search(base="OU=OU11,DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_BASE,
                              expression="(|(x=y)(y=b))")
        self.assertEqual(len(res11), 1)

    def test_base_and(self):
        """Testing a search"""

        res11 = self.l.search(base="OU=OU11,DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_BASE,
                              expression="(&(ou=ou11)(ou=ou12))")
        self.assertEqual(len(res11), 0)

    def test_base_and2(self):
        """Testing a search"""

        res11 = self.l.search(base="OU=OU11,DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_BASE,
                              expression="(&(x=y)(y=a))")
        self.assertEqual(len(res11), 1)

    def test_base_false(self):
        """Testing a search"""

        res11 = self.l.search(base="OU=OU11,DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_BASE,
                              expression="(|(ou=ou13)(ou=ou12))")
        self.assertEqual(len(res11), 0)

    def test_check_base_false(self):
        """Testing a search"""
        res11 = self.l.search(base="OU=OU11,DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_BASE,
                              expression="(|(ou=ou13)(ou=ou12))")
        self.assertEqual(len(res11), 0)

    def test_check_base_error(self):
        """Testing a search"""
        checkbaseonsearch = {"dn": "@OPTIONS",
                             "checkBaseOnSearch": b"TRUE"}
        try:
            self.l.add(checkbaseonsearch)
        except ldb.LdbError as err:
            enum = err.args[0]
            self.assertEqual(enum, ldb.ERR_ENTRY_ALREADY_EXISTS)
            m = ldb.Message.from_dict(self.l,
                                      checkbaseonsearch)
            self.l.modify(m)

        try:
            res11 = self.l.search(base="OU=OU11x,DC=SAMBA,DC=ORG",
                                  scope=ldb.SCOPE_BASE,
                                  expression="(|(ou=ou13)(ou=ou12))")
            self.fail("Should have failed on missing base")
        except ldb.LdbError as err:
            enum = err.args[0]
            self.assertEqual(enum, ldb.ERR_NO_SUCH_OBJECT)

    def test_subtree(self):
        """Testing a search"""

        try:
            res11 = self.l.search(base="DC=SAMBA,DC=ORG",
                                  scope=ldb.SCOPE_SUBTREE)
            if hasattr(self, 'IDXCHECK'):
                self.fail()
        except ldb.LdbError as err:
            enum = err.args[0]
            estr = err.args[1]
            self.assertEqual(enum, ldb.ERR_INAPPROPRIATE_MATCHING)
            self.assertIn(estr, "ldb FULL SEARCH disabled")
        else:
            self.assertEqual(len(res11), 25)

    def test_subtree2(self):
        """Testing a search"""

        try:
            res11 = self.l.search(base="DC=ORG",
                                  scope=ldb.SCOPE_SUBTREE)
            if hasattr(self, 'IDXCHECK'):
                self.fail()
        except ldb.LdbError as err:
            enum = err.args[0]
            estr = err.args[1]
            self.assertEqual(enum, ldb.ERR_INAPPROPRIATE_MATCHING)
            self.assertIn(estr, "ldb FULL SEARCH disabled")
        else:
            self.assertEqual(len(res11), 36)

    def test_subtree_and(self):
        """Testing a search"""

        res11 = self.l.search(base="DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_SUBTREE,
                              expression="(&(ou=ou11)(ou=ou12))")
        self.assertEqual(len(res11), 0)

    def test_subtree_and2(self):
        """Testing a search"""

        res11 = self.l.search(base="DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_SUBTREE,
                              expression="(&(x=y)(|(y=b)(y=c)))")
        self.assertEqual(len(res11), 1)

    def test_subtree_and2_lower(self):
        """Testing a search"""

        res11 = self.l.search(base="DC=samba,DC=org",
                              scope=ldb.SCOPE_SUBTREE,
                              expression="(&(x=y)(|(y=b)(y=c)))")
        self.assertEqual(len(res11), 1)

    def test_subtree_or(self):
        """Testing a search"""

        res11 = self.l.search(base="DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_SUBTREE,
                              expression="(|(ou=ou11)(ou=ou12))")
        self.assertEqual(len(res11), 2)

    def test_subtree_or2(self):
        """Testing a search"""

        res11 = self.l.search(base="DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_SUBTREE,
                              expression="(|(x=y)(y=b))")
        self.assertEqual(len(res11), 20)

    def test_subtree_or3(self):
        """Testing a search"""

        res11 = self.l.search(base="DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_SUBTREE,
                              expression="(|(x=y)(y=b)(y=c))")
        self.assertEqual(len(res11), 22)

    def test_one_and(self):
        """Testing a search"""

        res11 = self.l.search(base="DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_ONELEVEL,
                              expression="(&(ou=ou11)(ou=ou12))")
        self.assertEqual(len(res11), 0)

    def test_one_and2(self):
        """Testing a search"""

        res11 = self.l.search(base="DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_ONELEVEL,
                              expression="(&(x=y)(y=b))")
        self.assertEqual(len(res11), 1)

    def test_one_or(self):
        """Testing a search"""

        res11 = self.l.search(base="DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_ONELEVEL,
                              expression="(|(ou=ou11)(ou=ou12))")
        self.assertEqual(len(res11), 2)

    def test_one_or2(self):
        """Testing a search"""

        res11 = self.l.search(base="DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_ONELEVEL,
                              expression="(|(x=y)(y=b))")
        self.assertEqual(len(res11), 20)

    def test_one_or2_lower(self):
        """Testing a search"""

        res11 = self.l.search(base="DC=samba,DC=org",
                              scope=ldb.SCOPE_ONELEVEL,
                              expression="(|(x=y)(y=b))")
        self.assertEqual(len(res11), 20)

    def test_one_unindexable(self):
        """Testing a search"""

        try:
            res11 = self.l.search(base="DC=samba,DC=org",
                                  scope=ldb.SCOPE_ONELEVEL,
                                  expression="(y=b*)")
            if hasattr(self, 'IDX') and \
               not hasattr(self, 'IDXONE') and \
               hasattr(self, 'IDXCHECK'):
                self.fail("Should have failed as un-indexed search")

            self.assertEqual(len(res11), 9)

        except ldb.LdbError as err:
            enum = err.args[0]
            estr = err.args[1]
            self.assertEqual(enum, ldb.ERR_INAPPROPRIATE_MATCHING)
            self.assertIn(estr, "ldb FULL SEARCH disabled")

    def test_one_unindexable_presence(self):
        """Testing a search"""

        try:
            res11 = self.l.search(base="DC=samba,DC=org",
                                  scope=ldb.SCOPE_ONELEVEL,
                                  expression="(y=*)")
            if hasattr(self, 'IDX') and \
               not hasattr(self, 'IDXONE') and \
               hasattr(self, 'IDXCHECK'):
                self.fail("Should have failed as un-indexed search")

            self.assertEqual(len(res11), 24)

        except ldb.LdbError as err:
            enum = err.args[0]
            estr = err.args[1]
            self.assertEqual(enum, ldb.ERR_INAPPROPRIATE_MATCHING)
            self.assertIn(estr, "ldb FULL SEARCH disabled")

    def test_subtree_and_or(self):
        """Testing a search"""

        res11 = self.l.search(base="DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_SUBTREE,
                              expression="(&(|(x=z)(y=b))(x=x)(y=c))")
        self.assertEqual(len(res11), 0)

    def test_subtree_and_or2(self):
        """Testing a search"""

        res11 = self.l.search(base="DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_SUBTREE,
                              expression="(&(x=x)(y=c)(|(x=z)(y=b)))")
        self.assertEqual(len(res11), 0)

    def test_subtree_and_or3(self):
        """Testing a search"""

        res11 = self.l.search(base="DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_SUBTREE,
                              expression="(&(|(ou=ou11)(ou=ou10))(|(x=y)(y=b)(y=c)))")
        self.assertEqual(len(res11), 2)

    def test_subtree_and_or4(self):
        """Testing a search"""

        res11 = self.l.search(base="DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_SUBTREE,
                              expression="(&(|(x=y)(y=b)(y=c))(|(ou=ou11)(ou=ou10)))")
        self.assertEqual(len(res11), 2)

    def test_subtree_and_or5(self):
        """Testing a search"""

        res11 = self.l.search(base="DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_SUBTREE,
                              expression="(&(|(x=y)(y=b)(y=c))(ou=ou11))")
        self.assertEqual(len(res11), 1)

    def test_subtree_or_and(self):
        """Testing a search"""

        res11 = self.l.search(base="DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_SUBTREE,
                              expression="(|(x=x)(y=c)(&(x=z)(y=b)))")
        self.assertEqual(len(res11), 10)

    def test_subtree_large_and_unique(self):
        """Testing a search"""

        res11 = self.l.search(base="DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_SUBTREE,
                              expression="(&(ou=ou10)(y=a))")
        self.assertEqual(len(res11), 1)

    def test_subtree_unique(self):
        """Testing a search"""

        res11 = self.l.search(base="DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_SUBTREE,
                              expression="(ou=ou10)")
        self.assertEqual(len(res11), 1)

    def test_subtree_unique_elsewhere(self):
        """Testing a search"""

        res11 = self.l.search(base="DC=EXAMPLE,DC=ORG",
                              scope=ldb.SCOPE_SUBTREE,
                              expression="(ou=ou10)")
        self.assertEqual(len(res11), 0)

    def test_subtree_unique_elsewhere2(self):
        """Testing a search"""

        res11 = self.l.search(base="DC=EXAMPLE,DC=NET",
                              scope=ldb.SCOPE_SUBTREE,
                              expression="(ou=unique)")
        self.assertEqual(len(res11), 1)

    def test_subtree_uni123_elsewhere(self):
        """Testing a search, where the search term contains a (normal ASCII)
        dotted-i, that will be upper-cased to 'İ', U+0130, LATIN
        CAPITAL LETTER I WITH DOT ABOVE in certain locales including
        tr_TR in which this test is sometimes run.

        The search term should fail because the ou does not exist, but
        we used to get it wrong in unindexed searches which stopped
        comparing at the i, ignoring the rest of the string, which is
        not the same as the existing ou ('123' != 'que').
        """
        res11 = self.l.search(base="DC=EXAMPLE,DC=NET",
                              scope=ldb.SCOPE_SUBTREE,
                              expression="(ou=uni123)")
        self.assertEqual(len(res11), 0)

    def test_subtree_unique_elsewhere3(self):
        """Testing a search"""

        res11 = self.l.search(base="DC=EXAMPLE,DC=ORG",
                              scope=ldb.SCOPE_SUBTREE,
                              expression="(ou=unique)")
        self.assertEqual(len(res11), 0)

    def test_subtree_unique_elsewhere4(self):
        """Testing a search"""

        res11 = self.l.search(base="DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_SUBTREE,
                              expression="(ou=unique)")
        self.assertEqual(len(res11), 0)

    def test_subtree_unique_elsewhere5(self):
        """Testing a search"""

        res11 = self.l.search(base="DC=EXAMPLE,DC=COM",
                              scope=ldb.SCOPE_SUBTREE,
                              expression="(ou=unique)")
        self.assertEqual(len(res11), 0)

    def test_subtree_unique_elsewhere6(self):
        """Testing a search"""

        res11 = self.l.search(base="DC=EXAMPLE,DC=ORG",
                              scope=ldb.SCOPE_SUBTREE,
                              expression="(ou=unique)")
        self.assertEqual(len(res11), 0)

    def test_subtree_unique_elsewhere7(self):
        """Testing a search"""

        res11 = self.l.search(base="DC=EXAMPLE,DC=COM",
                              scope=ldb.SCOPE_SUBTREE,
                              expression="(ou=ou10)")
        self.assertEqual(len(res11), 0)

    def test_subtree_unique_here(self):
        """Testing a search"""

        res11 = self.l.search(base="OU=UNIQUE,DC=EXAMPLE,DC=NET",
                              scope=ldb.SCOPE_SUBTREE,
                              expression="(ou=unique)")
        self.assertEqual(len(res11), 1)

    def test_subtree_and_none(self):
        """Testing a search"""

        res11 = self.l.search(base="DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_SUBTREE,
                              expression="(&(ou=ouX)(y=a))")
        self.assertEqual(len(res11), 0)

    def test_subtree_and_idx_record(self):
        """Testing a search against the index record"""

        res11 = self.l.search(base="DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_SUBTREE,
                              expression="(@IDXDN=DC=SAMBA,DC=ORG)")
        self.assertEqual(len(res11), 0)

    def test_subtree_and_idxone_record(self):
        """Testing a search against the index record"""

        res11 = self.l.search(base="DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_SUBTREE,
                              expression="(@IDXONE=DC=SAMBA,DC=ORG)")
        self.assertEqual(len(res11), 0)

    def test_onelevel(self):
        """Testing a search"""

        try:
            res11 = self.l.search(base="DC=SAMBA,DC=ORG",
                                  scope=ldb.SCOPE_ONELEVEL)
            if hasattr(self, 'IDXCHECK') \
               and not hasattr(self, 'IDXONE'):
                self.fail()
        except ldb.LdbError as err:
            enum = err.args[0]
            estr = err.args[1]
            self.assertEqual(enum, ldb.ERR_INAPPROPRIATE_MATCHING)
            self.assertIn(estr, "ldb FULL SEARCH disabled")
        else:
            self.assertEqual(len(res11), 24)

    def test_onelevel2(self):
        """Testing a search"""

        try:
            res11 = self.l.search(base="DC=EXAMPLE,DC=ORG",
                                  scope=ldb.SCOPE_ONELEVEL)
            if hasattr(self, 'IDXCHECK') \
               and not hasattr(self, 'IDXONE'):
                self.fail()
                self.fail()
        except ldb.LdbError as err:
            enum = err.args[0]
            estr = err.args[1]
            self.assertEqual(enum, ldb.ERR_INAPPROPRIATE_MATCHING)
            self.assertIn(estr, "ldb FULL SEARCH disabled")
        else:
            self.assertEqual(len(res11), 9)

    def test_onelevel_and_or(self):
        """Testing a search"""

        res11 = self.l.search(base="DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_ONELEVEL,
                              expression="(&(|(x=z)(y=b))(x=x)(y=c))")
        self.assertEqual(len(res11), 0)

    def test_onelevel_and_or2(self):
        """Testing a search"""

        res11 = self.l.search(base="DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_ONELEVEL,
                              expression="(&(x=x)(y=c)(|(x=z)(y=b)))")
        self.assertEqual(len(res11), 0)

    def test_onelevel_and_or3(self):
        """Testing a search"""

        res11 = self.l.search(base="DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_ONELEVEL,
                              expression="(&(|(ou=ou11)(ou=ou10))(|(x=y)(y=b)(y=c)))")
        self.assertEqual(len(res11), 2)

    def test_onelevel_and_or4(self):
        """Testing a search"""

        res11 = self.l.search(base="DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_ONELEVEL,
                              expression="(&(|(x=y)(y=b)(y=c))(|(ou=ou11)(ou=ou10)))")
        self.assertEqual(len(res11), 2)

    def test_onelevel_and_or5(self):
        """Testing a search"""

        res11 = self.l.search(base="DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_ONELEVEL,
                              expression="(&(|(x=y)(y=b)(y=c))(ou=ou11))")
        self.assertEqual(len(res11), 1)

    def test_onelevel_or_and(self):
        """Testing a search"""

        res11 = self.l.search(base="DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_ONELEVEL,
                              expression="(|(x=x)(y=c)(&(x=z)(y=b)))")
        self.assertEqual(len(res11), 10)

    def test_onelevel_large_and_unique(self):
        """Testing a search"""

        res11 = self.l.search(base="DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_ONELEVEL,
                              expression="(&(ou=ou10)(y=a))")
        self.assertEqual(len(res11), 1)

    def test_onelevel_unique(self):
        """Testing a search"""

        res11 = self.l.search(base="DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_ONELEVEL,
                              expression="(ou=ou10)")
        self.assertEqual(len(res11), 1)

    def test_onelevel_unique_elsewhere(self):
        """Testing a search"""

        res11 = self.l.search(base="DC=EXAMPLE,DC=ORG",
                              scope=ldb.SCOPE_ONELEVEL,
                              expression="(ou=ou10)")
        self.assertEqual(len(res11), 0)

    def test_onelevel_unique_elsewhere2(self):
        """Testing a search (showing that onelevel is not subtree)"""

        res11 = self.l.search(base="DC=EXAMPLE,DC=NET",
                              scope=ldb.SCOPE_ONELEVEL,
                              expression="(ou=unique)")
        self.assertEqual(len(res11), 1)

    def test_onelevel_unique_elsewhere3(self):
        """Testing a search (showing that onelevel is not subtree)"""

        res11 = self.l.search(base="DC=EXAMPLE,DC=ORG",
                              scope=ldb.SCOPE_ONELEVEL,
                              expression="(ou=unique)")
        self.assertEqual(len(res11), 0)

    def test_onelevel_unique_elsewhere4(self):
        """Testing a search (showing that onelevel is not subtree)"""

        res11 = self.l.search(base="DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_ONELEVEL,
                              expression="(ou=unique)")
        self.assertEqual(len(res11), 0)

    def test_onelevel_unique_elsewhere5(self):
        """Testing a search (showing that onelevel is not subtree)"""

        res11 = self.l.search(base="DC=EXAMPLE,DC=COM",
                              scope=ldb.SCOPE_ONELEVEL,
                              expression="(ou=unique)")
        self.assertEqual(len(res11), 0)

    def test_onelevel_unique_elsewhere6(self):
        """Testing a search"""

        res11 = self.l.search(base="DC=EXAMPLE,DC=COM",
                              scope=ldb.SCOPE_ONELEVEL,
                              expression="(ou=ou10)")
        self.assertEqual(len(res11), 0)

    def test_onelevel_unique_here(self):
        """Testing a search"""

        res11 = self.l.search(base="OU=UNIQUE,DC=EXAMPLE,DC=NET",
                              scope=ldb.SCOPE_ONELEVEL,
                              expression="(ou=unique)")
        self.assertEqual(len(res11), 0)

    def test_onelevel_and_none(self):
        """Testing a search"""

        res11 = self.l.search(base="DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_ONELEVEL,
                              expression="(&(ou=ouX)(y=a))")
        self.assertEqual(len(res11), 0)

    def test_onelevel_and_idx_record(self):
        """Testing a search against the index record"""

        res11 = self.l.search(base="DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_ONELEVEL,
                              expression="(@IDXDN=DC=SAMBA,DC=ORG)")
        self.assertEqual(len(res11), 0)

    def test_onelevel_and_idxone_record(self):
        """Testing a search against the index record"""

        res11 = self.l.search(base="DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_ONELEVEL,
                              expression="(@IDXONE=DC=SAMBA,DC=ORG)")
        self.assertEqual(len(res11), 0)

    def test_subtree_unindexable(self):
        """Testing a search"""

        try:
            res11 = self.l.search(base="DC=samba,DC=org",
                                  scope=ldb.SCOPE_SUBTREE,
                                  expression="(y=b*)")
            if hasattr(self, 'IDX') and \
               hasattr(self, 'IDXCHECK'):
                self.fail("Should have failed as un-indexed search")

            self.assertEqual(len(res11), 9)

        except ldb.LdbError as err:
            enum = err.args[0]
            estr = err.args[1]
            self.assertEqual(enum, ldb.ERR_INAPPROPRIATE_MATCHING)
            self.assertIn(estr, "ldb FULL SEARCH disabled")

    def test_onelevel_only_and_or(self):
        """Testing a search (showing that onelevel is not subtree)"""

        res11 = self.l.search(base="DC=ORG",
                              scope=ldb.SCOPE_ONELEVEL,
                              expression="(&(|(x=z)(y=b))(x=x)(y=c))")
        self.assertEqual(len(res11), 0)

    def test_onelevel_only_and_or2(self):
        """Testing a search (showing that onelevel is not subtree)"""

        res11 = self.l.search(base="DC=ORG",
                              scope=ldb.SCOPE_ONELEVEL,
                              expression="(&(x=x)(y=c)(|(x=z)(y=b)))")
        self.assertEqual(len(res11), 0)

    def test_onelevel_only_and_or3(self):
        """Testing a search (showing that onelevel is not subtree)"""

        res11 = self.l.search(base="DC=ORG",
                              scope=ldb.SCOPE_ONELEVEL,
                              expression="(&(|(ou=ou11)(ou=ou10))(|(x=y)(y=b)(y=c)))")
        self.assertEqual(len(res11), 0)

    def test_onelevel_only_and_or4(self):
        """Testing a search (showing that onelevel is not subtree)"""

        res11 = self.l.search(base="DC=ORG",
                              scope=ldb.SCOPE_ONELEVEL,
                              expression="(&(|(x=y)(y=b)(y=c))(|(ou=ou11)(ou=ou10)))")
        self.assertEqual(len(res11), 0)

    def test_onelevel_only_and_or5(self):
        """Testing a search (showing that onelevel is not subtree)"""

        res11 = self.l.search(base="DC=ORG",
                              scope=ldb.SCOPE_ONELEVEL,
                              expression="(&(|(x=y)(y=b)(y=c))(ou=ou11))")
        self.assertEqual(len(res11), 0)

    def test_onelevel_only_or_and(self):
        """Testing a search (showing that onelevel is not subtree)"""

        res11 = self.l.search(base="DC=ORG",
                              scope=ldb.SCOPE_ONELEVEL,
                              expression="(|(x=x)(y=c)(&(x=z)(y=b)))")
        self.assertEqual(len(res11), 0)

    def test_onelevel_only_large_and_unique(self):
        """Testing a search (showing that onelevel is not subtree)"""

        res11 = self.l.search(base="DC=ORG",
                              scope=ldb.SCOPE_ONELEVEL,
                              expression="(&(ou=ou10)(y=a))")
        self.assertEqual(len(res11), 0)

    def test_onelevel_only_unique(self):
        """Testing a search (showing that onelevel is not subtree)"""

        res11 = self.l.search(base="DC=ORG",
                              scope=ldb.SCOPE_ONELEVEL,
                              expression="(ou=ou10)")
        self.assertEqual(len(res11), 0)

    def test_onelevel_only_unique2(self):
        """Testing a search"""

        res11 = self.l.search(base="DC=ORG",
                              scope=ldb.SCOPE_ONELEVEL,
                              expression="(ou=unique)")
        self.assertEqual(len(res11), 0)

    def test_onelevel_only_and_none(self):
        """Testing a search (showing that onelevel is not subtree)"""

        res11 = self.l.search(base="DC=ORG",
                              scope=ldb.SCOPE_ONELEVEL,
                              expression="(&(ou=ouX)(y=a))")
        self.assertEqual(len(res11), 0)

    def test_onelevel_small_and_or(self):
        """Testing a search (showing that onelevel is not subtree)"""

        res11 = self.l.search(base="DC=EXAMPLE,DC=ORG",
                              scope=ldb.SCOPE_ONELEVEL,
                              expression="(&(|(x=z)(y=b))(x=x)(y=c))")
        self.assertEqual(len(res11), 0)

    def test_onelevel_small_and_or2(self):
        """Testing a search (showing that onelevel is not subtree)"""

        res11 = self.l.search(base="DC=EXAMPLE,DC=ORG",
                              scope=ldb.SCOPE_ONELEVEL,
                              expression="(&(x=x)(y=c)(|(x=z)(y=b)))")
        self.assertEqual(len(res11), 0)

    def test_onelevel_small_and_or3(self):
        """Testing a search (showing that onelevel is not subtree)"""

        res11 = self.l.search(base="DC=EXAMPLE,DC=ORG",
                              scope=ldb.SCOPE_ONELEVEL,
                              expression="(&(|(ou=ou1)(ou=ou2))(|(x=y)(y=b)(y=c)))")
        self.assertEqual(len(res11), 2)

    def test_onelevel_small_and_or4(self):
        """Testing a search (showing that onelevel is not subtree)"""

        res11 = self.l.search(base="DC=EXAMPLE,DC=ORG",
                              scope=ldb.SCOPE_ONELEVEL,
                              expression="(&(|(x=y)(y=b)(y=c))(|(ou=ou1)(ou=ou2)))")
        self.assertEqual(len(res11), 2)

    def test_onelevel_small_and_or5(self):
        """Testing a search (showing that onelevel is not subtree)"""

        res11 = self.l.search(base="DC=EXAMPLE,DC=ORG",
                              scope=ldb.SCOPE_ONELEVEL,
                              expression="(&(|(x=y)(y=b)(y=c))(ou=ou1))")
        self.assertEqual(len(res11), 1)

    def test_onelevel_small_or_and(self):
        """Testing a search (showing that onelevel is not subtree)"""

        res11 = self.l.search(base="DC=EXAMPLE,DC=ORG",
                              scope=ldb.SCOPE_ONELEVEL,
                              expression="(|(x=x)(y=c)(&(x=z)(y=b)))")
        self.assertEqual(len(res11), 2)

    def test_onelevel_small_large_and_unique(self):
        """Testing a search (showing that onelevel is not subtree)"""

        res11 = self.l.search(base="DC=EXAMPLE,DC=ORG",
                              scope=ldb.SCOPE_ONELEVEL,
                              expression="(&(ou=ou9)(y=a))")
        self.assertEqual(len(res11), 1)

    def test_onelevel_small_unique_elsewhere(self):
        """Testing a search (showing that onelevel is not subtree)"""

        res11 = self.l.search(base="DC=EXAMPLE,DC=ORG",
                              scope=ldb.SCOPE_ONELEVEL,
                              expression="(ou=ou10)")
        self.assertEqual(len(res11), 0)

    def test_onelevel_small_and_none(self):
        """Testing a search (showing that onelevel is not subtree)"""

        res11 = self.l.search(base="DC=EXAMPLE,DC=ORG",
                              scope=ldb.SCOPE_ONELEVEL,
                              expression="(&(ou=ouX)(y=a))")
        self.assertEqual(len(res11), 0)

    def test_subtree_unindexable_presence(self):
        """Testing a search"""

        try:
            res11 = self.l.search(base="DC=samba,DC=org",
                                  scope=ldb.SCOPE_SUBTREE,
                                  expression="(y=*)")
            if hasattr(self, 'IDX') and \
               hasattr(self, 'IDXCHECK'):
                self.fail("Should have failed as un-indexed search")

            self.assertEqual(len(res11), 24)

        except ldb.LdbError as err:
            enum = err.args[0]
            estr = err.args[1]
            self.assertEqual(enum, ldb.ERR_INAPPROPRIATE_MATCHING)
            self.assertIn(estr, "ldb FULL SEARCH disabled")

    def test_dn_filter_one(self):
        """Testing that a dn= filter succeeds
        (or fails with disallowDNFilter
        set and IDXGUID or (IDX and not IDXONE) mode)
        when the scope is SCOPE_ONELEVEL.

        This should be made more consistent, but for now lock in
        the behaviour

        """

        res11 = self.l.search(base="DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_ONELEVEL,
                              expression="(dn=OU=OU1,DC=SAMBA,DC=ORG)")
        if hasattr(self, 'disallowDNFilter') and \
           hasattr(self, 'IDX') and \
           (hasattr(self, 'IDXGUID') or
            ((not hasattr(self, 'IDXONE') and hasattr(self, 'IDX')))):
            self.assertEqual(len(res11), 0)
        else:
            self.assertEqual(len(res11), 1)

    def test_dn_filter_subtree(self):
        """Testing that a dn= filter succeeds
        (or fails with disallowDNFilter set)
        when the scope is SCOPE_SUBTREE"""

        res11 = self.l.search(base="DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_SUBTREE,
                              expression="(dn=OU=OU1,DC=SAMBA,DC=ORG)")
        if hasattr(self, 'disallowDNFilter') \
           and hasattr(self, 'IDX'):
            self.assertEqual(len(res11), 0)
        else:
            self.assertEqual(len(res11), 1)

    def test_dn_filter_base(self):
        """Testing that (incorrectly) a dn= filter works
        when the scope is SCOPE_BASE"""

        res11 = self.l.search(base="OU=OU1,DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_BASE,
                              expression="(dn=OU=OU1,DC=SAMBA,DC=ORG)")

        # At some point we should fix this, but it isn't trivial
        self.assertEqual(len(res11), 1)

    def test_distinguishedName_filter_one(self):
        """Testing that a distinguishedName= filter succeeds
        when the scope is SCOPE_ONELEVEL.

        This should be made more consistent, but for now lock in
        the behaviour

        """

        res11 = self.l.search(base="DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_ONELEVEL,
                              expression="(distinguishedName=OU=OU1,DC=SAMBA,DC=ORG)")
        self.assertEqual(len(res11), 1)

    def test_distinguishedName_filter_subtree(self):
        """Testing that a distinguishedName= filter succeeds
        when the scope is SCOPE_SUBTREE"""

        res11 = self.l.search(base="DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_SUBTREE,
                              expression="(distinguishedName=OU=OU1,DC=SAMBA,DC=ORG)")
        self.assertEqual(len(res11), 1)

    def test_distinguishedName_filter_base(self):
        """Testing that (incorrectly) a distinguishedName= filter works
        when the scope is SCOPE_BASE"""

        res11 = self.l.search(base="OU=OU1,DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_BASE,
                              expression="(distinguishedName=OU=OU1,DC=SAMBA,DC=ORG)")

        # At some point we should fix this, but it isn't trivial
        self.assertEqual(len(res11), 1)

    def test_bad_dn_filter_base(self):
        """Testing that a dn= filter on an invalid DN works
        when the scope is SCOPE_BASE but
        returns zero results"""

        res11 = self.l.search(base="OU=OU1,DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_BASE,
                              expression="(dn=OU=OU1,DC=SAMBA,DCXXXX)")

        # At some point we should fix this, but it isn't trivial
        self.assertEqual(len(res11), 0)


    def test_bad_dn_filter_one(self):
        """Testing that a dn= filter succeeds but returns zero
        results when the DN is not valid on a SCOPE_ONELEVEL search

        """

        res11 = self.l.search(base="DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_ONELEVEL,
                              expression="(dn=OU=OU1,DC=SAMBA,DCXXXX)")
        self.assertEqual(len(res11), 0)

    def test_bad_dn_filter_subtree(self):
        """Testing that a dn= filter succeeds but returns zero
        results when the DN is not valid on a SCOPE_SUBTREE search

        """

        res11 = self.l.search(base="DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_SUBTREE,
                              expression="(dn=OU=OU1,DC=SAMBA,DCXXXX)")
        self.assertEqual(len(res11), 0)

    def test_bad_distinguishedName_filter_base(self):
        """Testing that a distinguishedName= filter on an invalid DN works
        when the scope is SCOPE_BASE but
        returns zero results"""

        res11 = self.l.search(base="OU=OU1,DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_BASE,
                              expression="(distinguishedName=OU=OU1,DC=SAMBA,DCXXXX)")

        # At some point we should fix this, but it isn't trivial
        self.assertEqual(len(res11), 0)


    def test_bad_distinguishedName_filter_one(self):
        """Testing that a distinguishedName= filter succeeds but returns zero
        results when the DN is not valid on a SCOPE_ONELEVEL search

        """

        res11 = self.l.search(base="DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_ONELEVEL,
                              expression="(distinguishedName=OU=OU1,DC=SAMBA,DCXXXX)")
        self.assertEqual(len(res11), 0)

    def test_bad_distinguishedName_filter_subtree(self):
        """Testing that a distinguishedName= filter succeeds but returns zero
        results when the DN is not valid on a SCOPE_SUBTREE search

        """

        res11 = self.l.search(base="DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_SUBTREE,
                              expression="(distinguishedName=OU=OU1,DC=SAMBA,DCXXXX)")
        self.assertEqual(len(res11), 0)

    def test_bad_dn_search_base(self):
        """Testing with a bad base DN (SCOPE_BASE)"""

        try:
            res11 = self.l.search(base="OU=OU1,DC=SAMBA,DCXXX",
                                  scope=ldb.SCOPE_BASE)
            self.fail("Should have failed with ERR_INVALID_DN_SYNTAX")
        except ldb.LdbError as err:
            enum = err.args[0]
            self.assertEqual(enum, ldb.ERR_INVALID_DN_SYNTAX)


    def test_bad_dn_search_one(self):
        """Testing with a bad base DN (SCOPE_ONELEVEL)"""

        try:
            res11 = self.l.search(base="DC=SAMBA,DCXXXX",
                                  scope=ldb.SCOPE_ONELEVEL)
            self.fail("Should have failed with ERR_INVALID_DN_SYNTAX")
        except ldb.LdbError as err:
            enum = err.args[0]
            self.assertEqual(enum, ldb.ERR_INVALID_DN_SYNTAX)

    def test_bad_dn_search_subtree(self):
        """Testing with a bad base DN (SCOPE_SUBTREE)"""

        try:
            res11 = self.l.search(base="DC=SAMBA,DCXXXX",
                                  scope=ldb.SCOPE_SUBTREE)
            self.fail("Should have failed with ERR_INVALID_DN_SYNTAX")
        except ldb.LdbError as err:
            enum = err.args[0]
            self.assertEqual(enum, ldb.ERR_INVALID_DN_SYNTAX)



# Run the search tests against an lmdb backend
class SearchTestsLmdb(SearchTests):

    def setUp(self):
        if os.environ.get('HAVE_LMDB', '1') == '0':
            self.skipTest("No lmdb backend")
        self.prefix = MDB_PREFIX
        self.index = MDB_INDEX_OBJ
        super().setUp()


class IndexedSearchTests(SearchTests):
    """Test searches using the index, to ensure the index doesn't
       break things"""

    def setUp(self):
        super().setUp()
        self.l.add({"dn": "@INDEXLIST",
                    "@IDXATTR": [b"x", b"y", b"ou"]})
        self.IDX = True


class IndexedCheckSearchTests(IndexedSearchTests):
    """Test searches using the index, to ensure the index doesn't
       break things (full scan disabled)"""

    def setUp(self):
        self.IDXCHECK = True
        super().setUp()


class IndexedSearchDnFilterTests(SearchTests):
    """Test searches using the index, to ensure the index doesn't
       break things"""

    def setUp(self):
        super().setUp()
        self.l.add({"dn": "@OPTIONS",
                    "disallowDNFilter": "TRUE"})
        self.disallowDNFilter = True

        self.l.add({"dn": "@INDEXLIST",
                    "@IDXATTR": [b"x", b"y", b"ou"]})
        self.IDX = True


class IndexedAndOneLevelSearchTests(SearchTests):
    """Test searches using the index including @IDXONE, to ensure
       the index doesn't break things"""

    def setUp(self):
        super().setUp()
        self.l.add({"dn": "@INDEXLIST",
                    "@IDXATTR": [b"x", b"y", b"ou"],
                    "@IDXONE": [b"1"]})
        self.IDX = True
        self.IDXONE = True


class IndexedCheckedAndOneLevelSearchTests(IndexedAndOneLevelSearchTests):
    """Test searches using the index including @IDXONE, to ensure
       the index doesn't break things (full scan disabled)"""

    def setUp(self):
        self.IDXCHECK = True
        super().setUp()


class IndexedAndOneLevelDNFilterSearchTests(SearchTests):
    """Test searches using the index including @IDXONE, to ensure
       the index doesn't break things"""

    def setUp(self):
        super().setUp()
        self.l.add({"dn": "@OPTIONS",
                    "disallowDNFilter": "TRUE",
                    "checkBaseOnSearch": "TRUE"})
        self.disallowDNFilter = True
        self.checkBaseOnSearch = True

        self.l.add({"dn": "@INDEXLIST",
                    "@IDXATTR": [b"x", b"y", b"ou"],
                    "@IDXONE": [b"1"]})
        self.IDX = True
        self.IDXONE = True


class GUIDIndexedSearchTests(SearchTests):
    """Test searches using the index, to ensure the index doesn't
       break things"""

    def setUp(self):
        self.index = {"dn": "@INDEXLIST",
                      "@IDXATTR": [b"x", b"y", b"ou"],
                      "@IDXGUID": [b"objectUUID"],
                      "@IDX_DN_GUID": [b"GUID"]}
        super().setUp()

        self.IDXGUID = True


class GUIDIndexedDNFilterSearchTests(SearchTests):
    """Test searches using the index, to ensure the index doesn't
       break things"""

    def setUp(self):
        self.index = {"dn": "@INDEXLIST",
                      "@IDXATTR": [b"x", b"y", b"ou"],
                      "@IDXGUID": [b"objectUUID"],
                      "@IDX_DN_GUID": [b"GUID"]}
        super().setUp()
        self.l.add({"dn": "@OPTIONS",
                    "disallowDNFilter": "TRUE",
                    "checkBaseOnSearch": "TRUE"})
        self.disallowDNFilter = True
        self.checkBaseOnSearch = True
        self.IDX = True
        self.IDXGUID = True


class GUIDAndOneLevelIndexedSearchTests(SearchTests):
    """Test searches using the index including @IDXONE, to ensure
       the index doesn't break things"""

    def setUp(self):
        self.index = {"dn": "@INDEXLIST",
                      "@IDXATTR": [b"x", b"y", b"ou"],
                      "@IDXONE": [b"1"],
                      "@IDXGUID": [b"objectUUID"],
                      "@IDX_DN_GUID": [b"GUID"]}
        super().setUp()
        self.l.add({"dn": "@OPTIONS",
                    "disallowDNFilter": "TRUE",
                    "checkBaseOnSearch": "TRUE"})
        self.disallowDNFilter = True
        self.checkBaseOnSearch = True
        self.IDX = True
        self.IDXGUID = True
        self.IDXONE = True


class GUIDIndexedSearchTestsLmdb(GUIDIndexedSearchTests):

    def setUp(self):
        if os.environ.get('HAVE_LMDB', '1') == '0':
            self.skipTest("No lmdb backend")
        self.prefix = MDB_PREFIX
        super().setUp()


class GUIDIndexedDNFilterSearchTestsLmdb(GUIDIndexedDNFilterSearchTests):

    def setUp(self):
        if os.environ.get('HAVE_LMDB', '1') == '0':
            self.skipTest("No lmdb backend")
        self.prefix = MDB_PREFIX
        super().setUp()


class GUIDAndOneLevelIndexedSearchTestsLmdb(GUIDAndOneLevelIndexedSearchTests):

    def setUp(self):
        if os.environ.get('HAVE_LMDB', '1') == '0':
            self.skipTest("No lmdb backend")
        self.prefix = MDB_PREFIX
        super().setUp()


class LdbResultTests(LdbBaseTest):

    def setUp(self):
        super().setUp()
        self.testdir = tempdir()
        self.filename = os.path.join(self.testdir, "test.ldb")
        self.l = ldb.Ldb(self.url(), flags=self.flags())
        try:
            self.l.add(self.index)
        except AttributeError:
            pass
        self.l.add({"dn": "DC=SAMBA,DC=ORG", "name": b"samba.org",
                    "objectUUID": b"0123456789abcde0"})
        self.l.add({"dn": "OU=ADMIN,DC=SAMBA,DC=ORG", "name": b"Admins",
                    "objectUUID": b"0123456789abcde1"})
        self.l.add({"dn": "OU=USERS,DC=SAMBA,DC=ORG", "name": b"Users",
                    "objectUUID": b"0123456789abcde2"})
        self.l.add({"dn": "OU=OU1,DC=SAMBA,DC=ORG", "name": b"OU #1",
                    "objectUUID": b"0123456789abcde3"})
        self.l.add({"dn": "OU=OU2,DC=SAMBA,DC=ORG", "name": b"OU #2",
                    "objectUUID": b"0123456789abcde4"})
        self.l.add({"dn": "OU=OU3,DC=SAMBA,DC=ORG", "name": b"OU #3",
                    "objectUUID": b"0123456789abcde5"})
        self.l.add({"dn": "OU=OU4,DC=SAMBA,DC=ORG", "name": b"OU #4",
                    "objectUUID": b"0123456789abcde6"})
        self.l.add({"dn": "OU=OU5,DC=SAMBA,DC=ORG", "name": b"OU #5",
                    "objectUUID": b"0123456789abcde7"})
        self.l.add({"dn": "OU=OU6,DC=SAMBA,DC=ORG", "name": b"OU #6",
                    "objectUUID": b"0123456789abcde8"})
        self.l.add({"dn": "OU=OU7,DC=SAMBA,DC=ORG", "name": b"OU #7",
                    "objectUUID": b"0123456789abcde9"})
        self.l.add({"dn": "OU=OU8,DC=SAMBA,DC=ORG", "name": b"OU #8",
                    "objectUUID": b"0123456789abcdea"})
        self.l.add({"dn": "OU=OU9,DC=SAMBA,DC=ORG", "name": b"OU #9",
                    "objectUUID": b"0123456789abcdeb"})
        self.l.add({"dn": "OU=OU10,DC=SAMBA,DC=ORG", "name": b"OU #10",
                    "objectUUID": b"0123456789abcdec"})

    def tearDown(self):
        shutil.rmtree(self.testdir)
        super().tearDown()
        # Ensure the LDB is closed now, so we close the FD
        del(self.l)

    def test_return_type(self):
        res = self.l.search()
        self.assertEqual(str(res), "<ldb result>")

    def test_get_msgs(self):
        res = self.l.search()
        self.assertIsInstance(res.msgs, list)

    def test_get_controls(self):
        res = self.l.search()
        self.assertIsInstance(res.controls, list)

    def test_get_referals(self):
        res = self.l.search()
        self.assertIsInstance(res.referals, list)

    def test_iter_msgs(self):
        found = False
        for l in self.l.search().msgs:
            if str(l.dn) == "OU=OU10,DC=SAMBA,DC=ORG":
                found = True
        self.assertTrue(found)

    def test_iter_msgs_count(self):
        self.assertTrue(self.l.search().count > 0)
        # 13 objects has been added to the DC=SAMBA, DC=ORG
        self.assertEqual(self.l.search(base="DC=SAMBA,DC=ORG").count, 13)

    def test_iter_controls(self):
        res = self.l.search().controls
        it = iter(res)

    def test_create_control(self):
        self.assertRaises(ValueError, ldb.Control, self.l, "tatayoyo:0")
        c = ldb.Control(self.l, "relax:1")
        self.assertEqual(c.critical, True)
        self.assertEqual(c.oid, "1.3.6.1.4.1.4203.666.5.12")

    def test_iter_refs(self):
        res = self.l.search().referals
        it = iter(res)

    def test_search_sequence_msgs(self):
        found = False
        res = self.l.search().msgs

        for i in range(0, len(res)):
            l = res[i]
            if str(l.dn) == "OU=OU10,DC=SAMBA,DC=ORG":
                found = True
        self.assertTrue(found)

    def test_search_as_iter(self):
        found = False
        res = self.l.search()

        for l in res:
            if str(l.dn) == "OU=OU10,DC=SAMBA,DC=ORG":
                found = True
        self.assertTrue(found)

    def test_search_iter(self):
        found = False
        res = self.l.search_iterator()

        for l in res:
            if str(l.dn) == "OU=OU10,DC=SAMBA,DC=ORG":
                found = True
        self.assertTrue(found)

    # Show that search results can't see into a transaction

    def test_search_against_trans(self):
        found11 = False

        (r1, w1) = os.pipe()

        (r2, w2) = os.pipe()

        # For the first element, fork a child that will
        # write to the DB
        pid = os.fork()
        if pid == 0:
            # In the child, re-open
            del(self.l)
            gc.collect()

            child_ldb = ldb.Ldb(self.url(), flags=self.flags())
            # start a transaction
            child_ldb.transaction_start()

            # write to it
            child_ldb.add({"dn": "OU=OU11,DC=SAMBA,DC=ORG",
                           "name": b"samba.org",
                           "objectUUID": b"o123456789acbdef"})

            os.write(w1, b"added")

            # Now wait for the search to be done
            os.read(r2, 6)

            # and commit
            try:
                child_ldb.transaction_commit()
            except ldb.LdbError as err:
                # We print this here to see what went wrong in the child
                print(err)
                os._exit(1)

            os.write(w1, b"transaction")
            os._exit(0)

        self.assertEqual(os.read(r1, 5), b"added")

        # This should not turn up until the transaction is concluded
        res11 = self.l.search(base="OU=OU11,DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_BASE)
        self.assertEqual(len(res11), 0)

        os.write(w2, b"search")

        # Now wait for the transaction to be done.  This should
        # deadlock, but the search doesn't hold a read lock for the
        # iterator lifetime currently.
        self.assertEqual(os.read(r1, 11), b"transaction")

        # This should now turn up, as the transaction is over
        res11 = self.l.search(base="OU=OU11,DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_BASE)
        self.assertEqual(len(res11), 1)

        self.assertFalse(found11)

        (got_pid, status) = os.waitpid(pid, 0)
        self.assertEqual(got_pid, pid)

    def test_search_iter_against_trans(self):
        found = False
        found11 = False

        # We need to hold this iterator open to hold the all-record
        # lock
        res = self.l.search_iterator()

        (r1, w1) = os.pipe()

        (r2, w2) = os.pipe()

        # For the first element, with the sequence open (which
        # means with ldb locks held), fork a child that will
        # write to the DB
        pid = os.fork()
        if pid == 0:
            # In the child, re-open
            del(res)
            del(self.l)
            gc.collect()

            child_ldb = ldb.Ldb(self.url(), flags=self.flags())
            # start a transaction
            child_ldb.transaction_start()

            # write to it
            child_ldb.add({"dn": "OU=OU11,DC=SAMBA,DC=ORG",
                           "name": b"samba.org",
                           "objectUUID": b"o123456789acbdef"})

            os.write(w1, b"added")

            # Now wait for the search to be done
            os.read(r2, 6)

            # and commit
            try:
                child_ldb.transaction_commit()
            except ldb.LdbError as err:
                # We print this here to see what went wrong in the child
                print(err)
                os._exit(1)

            os.write(w1, b"transaction")
            os._exit(0)

        self.assertEqual(os.read(r1, 5), b"added")

        # This should not turn up until the transaction is concluded
        res11 = self.l.search(base="OU=OU11,DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_BASE)
        self.assertEqual(len(res11), 0)

        os.write(w2, b"search")

        # allow the transaction to start
        time.sleep(1)

        # This should not turn up until the search finishes and
        # removed the read lock, but for ldb_tdb that happened as soon
        # as we called the first res.next()
        res11 = self.l.search(base="OU=OU11,DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_BASE)
        self.assertEqual(len(res11), 0)

        # These results are all collected at the first next(res) call
        for l in res:
            if str(l.dn) == "OU=OU10,DC=SAMBA,DC=ORG":
                found = True
            if str(l.dn) == "OU=OU11,DC=SAMBA,DC=ORG":
                found11 = True

        # Now wait for the transaction to be done.
        self.assertEqual(os.read(r1, 11), b"transaction")

        # This should now turn up, as the transaction is over and all
        # read locks are gone
        res11 = self.l.search(base="OU=OU11,DC=SAMBA,DC=ORG",
                              scope=ldb.SCOPE_BASE)
        self.assertEqual(len(res11), 1)

        self.assertTrue(found)
        self.assertFalse(found11)

        (got_pid, status) = os.waitpid(pid, 0)
        self.assertEqual(got_pid, pid)


class LdbResultTestsLmdb(LdbResultTests):

    def setUp(self):
        if os.environ.get('HAVE_LMDB', '1') == '0':
            self.skipTest("No lmdb backend")
        self.prefix = MDB_PREFIX
        self.index = MDB_INDEX_OBJ
        super().setUp()


class NestedTransactionTests(LdbBaseTest):
    def setUp(self):
        super().setUp()
        self.testdir = tempdir()
        self.filename = os.path.join(self.testdir, "test.ldb")
        self.ldb = ldb.Ldb(self.url(), flags=self.flags())
        self.ldb.add({"dn": "@INDEXLIST",
                      "@IDXATTR": [b"x", b"y", b"ou"],
                      "@IDXGUID": [b"objectUUID"],
                      "@IDX_DN_GUID": [b"GUID"]})

        super().setUp()

    #
    # This test documents that currently ldb does not support true nested
    # transactions.
    #
    # Note: The test is written so that it treats failure as pass.
    #       It is done this way as standalone ldb builds do not use the samba
    #       known fail mechanism
    #
    def test_nested_transactions(self):

        self.ldb.transaction_start()

        self.ldb.add({"dn": "x=x1,dc=samba,dc=org",
                      "objectUUID": b"0123456789abcde1"})
        res = self.ldb.search(expression="(objectUUID=0123456789abcde1)",
                              base="dc=samba,dc=org")
        self.assertEqual(len(res), 1)

        self.ldb.add({"dn": "x=x2,dc=samba,dc=org",
                      "objectUUID": b"0123456789abcde2"})
        res = self.ldb.search(expression="(objectUUID=0123456789abcde2)",
                              base="dc=samba,dc=org")
        self.assertEqual(len(res), 1)

        self.ldb.transaction_start()
        self.ldb.add({"dn": "x=x3,dc=samba,dc=org",
                      "objectUUID": b"0123456789abcde3"})
        res = self.ldb.search(expression="(objectUUID=0123456789abcde3)",
                              base="dc=samba,dc=org")
        self.assertEqual(len(res), 1)
        self.ldb.transaction_cancel()
        #
        # Check that we can not see the record added by the cancelled
        # transaction.
        # Currently this fails as ldb does not support true nested
        # transactions, and only the outer commits and cancels have an effect
        #
        res = self.ldb.search(expression="(objectUUID=0123456789abcde3)",
                              base="dc=samba,dc=org")
        #
        # FIXME this test currently passes on a failure, i.e. if nested
        #       transaction support worked correctly the correct test would
        #       be.
        #         self.assertEqual(len(res), 0)
        #       as the add of objectUUID=0123456789abcde3 would reverted when
        #       the sub transaction it was nested in was rolled back.
        #
        #       Currently this is not the case so the record is still present.
        self.assertEqual(len(res), 1)


        # Commit the outer transaction
        #
        self.ldb.transaction_commit()
        #
        # Now check we can still see the records added in the outer
        # transaction.
        #
        res = self.ldb.search(expression="(objectUUID=0123456789abcde1)",
                              base="dc=samba,dc=org")
        self.assertEqual(len(res), 1)
        res = self.ldb.search(expression="(objectUUID=0123456789abcde2)",
                              base="dc=samba,dc=org")
        self.assertEqual(len(res), 1)
        #
        # And that we can't see the records added by the nested transaction.
        #
        res = self.ldb.search(expression="(objectUUID=0123456789abcde3)",
                              base="dc=samba,dc=org")
        # FIXME again if nested transactions worked correctly we would not
        #       see this record. The test should be.
        #         self.assertEqual(len(res), 0)
        self.assertEqual(len(res), 1)


class LmdbNestedTransactionTests(NestedTransactionTests):

    def setUp(self):
        if os.environ.get('HAVE_LMDB', '1') == '0':
            self.skipTest("No lmdb backend")
        self.prefix = MDB_PREFIX
        self.index = MDB_INDEX_OBJ
        super().setUp()


if __name__ == '__main__':
    import unittest
    unittest.TestProgram()
