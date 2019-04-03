#!/usr/bin/env python3
#
# Tests for comparison expressions on indexed keys
#
#   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2019
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
"""Tests for expressions containing comparisons on indexed attributes.
   Copied from ldb's index.py"""

import os
from unittest import TestCase
import sys
from samba import _ldb
import shutil
from ldb import SCOPE_SUBTREE
from samba.tests.subunitrun import TestProgram

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

    def options(self):
        if self.prefix == MDB_PREFIX:
            return ['disable_full_db_scan_for_self_test:1']
        else:
            return None

class LdbTDBIndexedComparisonExpressions(LdbBaseTest):
    def tearDown(self):
        shutil.rmtree(self.testdir)
        super(LdbTDBIndexedComparisonExpressions, self).tearDown()

        # Ensure the LDB is closed now, so we close the FD
        del(self.l)

    def setUp(self):
        super(LdbTDBIndexedComparisonExpressions, self).setUp()
        self.testdir = tempdir()
        self.filename = os.path.join(self.testdir, "indexedcomptest.ldb")
        # Note that the maximum key length is set to 54
        # This accounts for the 4 bytes added by the dn formatting
        # a leading dn=, and a trailing zero terminator
        #
        self.l = _ldb.Ldb(self.url(), options=self.options())
        self.l.add({"dn": "@ATTRIBUTES"})
        self.l.add({"dn": "@INDEXLIST",
                    "@IDXATTR": [b"int32attr"],
                    "@IDXONE": [b"1"],
                    "@IDXGUID": [b"objectUUID"],
                    "@IDX_DN_GUID": [b"GUID"]})

    def test_comparison_expression(self):
        self.l.samba_schema_attribute_add("int32attr", 0,
                                          _ldb.SYNTAX_SAMBA_INT32)

        int32_max = 2**31-1
        int32_min = -2**31
        test_nums = list(range(-5, 5))
        test_nums += list(range(int32_max-5, int32_max+1))
        test_nums += list(range(int32_min, int32_min+5))
        test_nums = sorted(test_nums)

        for i in test_nums:
            ouuid = 0x0123456789abcdef + i
            ouuid_s = bytes(('0' + hex(ouuid)[2:]).encode())
            self.l.add({"dn": "OU=COMPTESTOU{},DC=SAMBA,DC=ORG".format(i),
                        "objectUUID": ouuid_s,
                        "int32attr": str(i)})

        def assert_int32_expr(expr, py_expr=None):
            res = self.l.search(base="DC=SAMBA,DC=ORG",
                                scope=SCOPE_SUBTREE,
                                expression="(int32attr%s)" % (expr))

            if not py_expr:
                py_expr = expr
            expect = [n for n in test_nums if eval(str(n) + py_expr)]
            vals = sorted([int(r.get("int32attr")[0]) for r in res])
            self.assertEqual(len(res), len(expect))
            self.assertEqual(set(vals), set(expect))
            self.assertEqual(expect, vals)

        assert_int32_expr(">=-2")
        assert_int32_expr("<=2")
        assert_int32_expr(">=" + str(int32_min))
        assert_int32_expr("<=" + str(int32_min))
        assert_int32_expr("<=" + str(int32_min+1))
        assert_int32_expr("<=" + str(int32_max))
        assert_int32_expr(">=" + str(int32_max))
        assert_int32_expr(">=" + str(int32_max-1))
        assert_int32_expr("=10", "==10")

    def test_comparison_expression_duplicates(self):
        self.l.samba_schema_attribute_add("int32attr", 0,
                                          _ldb.SYNTAX_SAMBA_INT32)

        int32_max = 2**31-1
        int32_min = -2**31

        test_nums = list(range(-5, 5)) * 3
        test_nums += list(range(-20, 20, 5)) * 2
        test_nums += list(range(-50, 50, 15))
        test_nums = sorted(test_nums)

        for i, n in enumerate(test_nums):
            ouuid = 0x0123456789abcdef + i
            ouuid_s = bytes(('0' + hex(ouuid)[2:]).encode())
            self.l.add({"dn": "OU=COMPTESTOU{},DC=SAMBA,DC=ORG".format(i),
                        "objectUUID": ouuid_s,
                        "int32attr": str(n)})

        def assert_int32_expr(expr, py_expr=None):
            res = self.l.search(base="DC=SAMBA,DC=ORG",
                                scope=SCOPE_SUBTREE,
                                expression="(int32attr%s)" % (expr))

            if not py_expr:
                py_expr = expr
            expect = [n for n in test_nums if eval(str(n) + py_expr)]
            vals = sorted([int(r.get("int32attr")[0]) for r in res])
            self.assertEqual(len(res), len(expect))
            self.assertEqual(set(vals), set(expect))
            self.assertEqual(expect, vals)

        assert_int32_expr(">=-2")
        assert_int32_expr("<=2")
        assert_int32_expr(">=" + str(int32_min))
        assert_int32_expr("<=" + str(int32_min))
        assert_int32_expr("<=" + str(int32_min+1))
        assert_int32_expr("<=" + str(int32_max))
        assert_int32_expr(">=" + str(int32_max))
        assert_int32_expr(">=" + str(int32_max-1))
        assert_int32_expr("=-5", "==-5")
        assert_int32_expr("=5", "==5")

# Run the same tests against an lmdb backend
class LdbLMDBIndexedComparisonExpressions(LdbTDBIndexedComparisonExpressions):

    def setUp(self):
        if os.environ.get('HAVE_LMDB', '1') == '0':
            self.skipTest("No lmdb backend")
        self.prefix = MDB_PREFIX
        super(LdbLMDBIndexedComparisonExpressions, self).setUp()

    def tearDown(self):
        super(LdbLMDBIndexedComparisonExpressions, self).tearDown()


TestProgram(module=__name__, opts=[])
