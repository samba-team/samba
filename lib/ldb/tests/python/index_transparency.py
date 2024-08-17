#!/usr/bin/env python3
#
# Exhaustively test variations of search expressions on LDB database
# with a variety of backends and index options, asserting that all
# database variants give the same results.
#
# With the SKIP_SLOW_TESTS environment variable set (which is used by
# `make test`) only unary and binary expressions will be run.
# Otherwise ternary expressions are also run, which is a lot slower
# (by unary, binary, ternary, I mean e.g. "(a=1)", "(&(a=1)(b=2))",
# "(|(&(a=1)(b=2))(c=3))", respectively).
#
# These tests also emit some timing information, comparing the
# performance of the various databases.

import os
import time
from itertools import product
import sys
import unittest
sys.path.insert(0, "bin/python")
import ldb
import shutil

from api_base import (
    TDB_PREFIX,
    MDB_PREFIX,
    tempdir,
    LdbBaseTest,
)

HAVE_LMDB = (os.getenv('HAVE_LMDB') == '1')
SKIP_SLOW_TESTS = True if os.getenv('SKIP_SLOW_TESTS') else False


def DynamicTestCase(cls):
    """If a class is decorated with @DynamicTestCase, its
    setUpDynamicTestCases() method will be called *before* the
    setUpClass() method. At this time it can add test methods to
    the class (it is too late to do this in setUpClass).
    """
    cls.setUpDynamicTestCases()
    return cls


class SearchTestBase(LdbBaseTest):
    prefix = TDB_PREFIX
    unary_filters = ()
    binary_filters = ()
    ternary_filters = ()
    non_existent_attrs = ''
    non_existent_values = ''

    @classmethod
    def add_index(cls, db, portion=1, guid=True):
        attrs = ["a", "b", "c", "ou"]
        attrs = attrs[:int(len(attrs) * portion)]
        index = {
            "dn": "@INDEXLIST",
            "@IDXONE": "1",
            "@IDXATTR": attrs,
        }

        if guid:
            index["@IDXGUID"] = "objectUUID"
            index["@IDX_DN_GUID"] = "GUID"

        db.add(index)

    @classmethod
    def add(cls, msg):
        for db in cls.dbs:
            db.add(msg)

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        print(f"\n{cls}")
        for t, db in zip(cls.times, cls.dbs):
            print(f"{t} {db}")
            db.disconnect()
        shutil.rmtree(cls.testdir)

    @classmethod
    def setUpDynamicTestCases(cls):
        cls.testdir = tempdir()

        options = ["modules:rdn_name"]

        cls.times = []
        cls.dbs = []
        cls.filenames = []
        for name, prefix, index_args in cls.databases:
            flags = 0
            if prefix == MDB_PREFIX:
                if not HAVE_LMDB:
                    print("skipping MDB test: we have no LMDB")
                    continue
                flags |= ldb.FLG_NOSYNC

            filename = os.path.join(cls.testdir, f"{name}.ldb")
            url = prefix + filename

            db = ldb.Ldb(url, flags=flags, options=options)
            if index_args is not None:
                cls.add_index(db, *index_args)

            cls.dbs.append(db)
            cls.times.append(0.0)
            cls.filenames.append(filename)

        cls.add({"dn": "@ATTRIBUTES", "DC": "CASE_INSENSITIVE"})

        cls.add({"dn": "DC=TOP",
                 "name": b"top",
                 "objectUUID": b" top of dn tower"})

        # what follows will add a number of OUs with a mix of
        # attributes. The 16 byte GUID of the OU (in the "objectUUID" field,
        # not objectGUID, which has special handling) is a text string
        # describing what attributes the OU should have.
        #
        # For example, ' 87 aZ  bY  cXYZ' says this is "ou87" with
        # attribute 'a' having the values 'Z', attribute 'b' having
        # the value 'Y' and 'c' having the values 'X', 'Y', and 'Z'.
        #
        # 'name' is always unique. Sometimes 'name' will equal 'ou',
        # but sometimes it will be different ("ou number 87").
        #
        # We use a crappy LCG to spread the values around, with each
        # attribute/value pair having around a 25% chance of occurring
        # on any particular ou.
        #
        # The cls.attr_sets are effectively a python level index that
        # should behave identically to the LDB index. That is,
        #
        #   cls.attr_sets['bY'] & cls.attr_sets['cZ']
        #
        # should refer to the same OUs as a '(&(b=Y)(c=Z)' search.

        ou = 0
        cls.guids = []

        # cls.attr_sets are not actually used in the tests, but are
        # useful if you ever want to debug the tests.
        cls.attr_sets = {f'{x}{y}': set() for x, y in product(cls.attrs,
                                                              cls.values)}

        s = 0
        for ou in range(cls.n_objects):
            ou_attrs = {}
            guid = f'{ou:3} '
            for i in range(len(cls.attrs)):
                s = (s * 321 + ou + 1) & 0xffff
                k = cls.attrs[i]
                b = s & (s // 9)
                v = []
                ou_attrs[k] = v
                for j in range(len(cls.values)):
                    if b & (1 << j):
                        c = cls.values[j]
                        v.append(c)
                        cls.attr_sets[k + c].add(ou)
                if v:
                    guid += f'{k}{"".join(v):3}'
                else:
                    guid += '    '

            if len(guid) != 16:
                # with up to 1000 objects:
                # 2 attrs -> 12 chars
                # 3 attrs -> 16 chars
                # 4 attrs -> 20 chars
                #
                # a truncated guid will always be unique because of
                # the OU number at the start.
                guid = (guid + '_' * 12)[:16]

            name = (f"ou{ou}" if (ou % 3) else f"OU number {ou}").encode()
            cls.guids.append(guid)

            guid = guid.encode()
            if len(guid) != 16:
                raise ValueError(f"GUID should be 16 bytes, "
                                 f"not {len(guid)} ('{guid}')")

            msg = {"dn": f"OU=ou{ou},DC=TOP",
                   "name": name,
                   "objectUUID": guid
                   }
            for k, v in ou_attrs.items():
                if v:
                    msg[k] = v

            cls.add(msg)

        # This is how you could see how the attributes are distributed:
        #
        # from itertools import pairwise
        # for a in cls.attr_sets:
        #     print(f"{a}: {len(cls.attr_sets[a])}: {sorted(cls.attr_sets[a])}")
        # for a, b in pairwise(cls.attr_sets):
        #     print(f"{a}&{b}: {sorted(cls.attr_sets[a] &cls.attr_sets[b])}")

        # If we wanted to compare the database at the end to the
        # database at the beginning (i.e. ensuring that search has no
        # side-effects), we could do something like:
        #
        # shutil.copy(cls.filenames[0], cls.filenames[0] + '.initial')

        # add a non-existent attribute or values into some searches
        attrs = cls.attrs + cls.non_existent_attrs
        values = cls.values + cls.non_existent_values
        fn = "test_filter"

        for scope_name, scope in cls.scopes:
            for base in cls.bases:
                if scope != ldb.SCOPE_SUBTREE and base is None:
                    continue
                for f in cls.unary_filters:
                    for k, v in product(attrs, values):
                        filter = f.format(k1=k, v1=v)
                        name = f"{scope_name}-{base}-{filter}"
                        cls.generate_dynamic_test(fn, name, base, scope, filter)

                for f in cls.binary_filters:
                    for k1, v1, k2, v2 in product(attrs, values,
                                                  attrs, values):
                        filter = f.format(k1=k1, v1=v1, k2=k2, v2=v2)
                        name = f"{scope_name}-{base}-{filter}"
                        cls.generate_dynamic_test(fn, name, base, scope,
                                                  filter)

                if SKIP_SLOW_TESTS:
                    # avoiding ternary tests saves a lot of time. in
                    # autobuild we run with --skip-slow-tests, which
                    # sets this variable.
                    continue

                for f in cls.ternary_filters:
                    for k1, v1, k2, v2, k3, v3 in product(attrs, values,
                                                          attrs, values,
                                                          attrs, values,
                                                          ):
                        filter = f.format(k1=k1, v1=v1,
                                          k2=k2, v2=v2,
                                          k3=k3, v3=v3)
                        name = f"{scope_name}-{base}-{filter}"
                        cls.generate_dynamic_test(fn, name, base, scope,
                                                  filter)

    @classmethod
    def generate_dynamic_test(cls, fnname, suffix, *args, doc=None):
        # adapted from samba.tests.TestCase
        # (../../../../python/samba/tests/__init__.py)
        # which ldb tests don't currently use.
        #
        # A difference here is that we ignore duplicates, while the
        # samba.tests version will raise an exception.

        attr = "%s_%s" % (fnname, suffix)
        if hasattr(cls, attr):
            return

        def fn(self):
            getattr(self, "_%s_with_args" % fnname)(*args)
        fn.__doc__ = doc
        setattr(cls, attr, fn)

    def _test_filter_with_args(self, *args, **kwargs):
        """Search in all the database, asserting that the result is the same.
        """
        results = []

        for i, db in enumerate(self.dbs):
            start = time.time()
            r = db.search(*args, **kwargs)
            self.times[i] += time.time() - start
            results.append(r)

        first = results[0]
        rest = results[1:]

        if first is None:
            for r in rest:
                self.assertIsNone(r)
            return None

        # converting the results into sorted lists allows python
        # comparison to work.
        first_ = sorted(first)
        for i, r in enumerate(rest):
            self.assertEqual(len(first), len(r),
                             f"{i + 1}: {self.dbs[i + 1]}")
            r_ = sorted(r)
            self.assertEqual(first_, r_)

        return first


@DynamicTestCase
class SearchTest(SearchTestBase):
    n_objects = 100
    attrs = 'abc'
    values = 'XYZ'
    non_existent_attrs = 'M'
    non_existent_values = 'm'

    databases = (
        #['tdb-unindexed', TDB_PREFIX, None],
        ['tdb-indexed-dn', TDB_PREFIX, (1, False)],
        ['tdb-half-indexed', TDB_PREFIX, (0.5,)],
        ['tdb-indexed-guid', TDB_PREFIX, ()],
        ['mdb-indexed', MDB_PREFIX, ()],
    )

    scopes = (('base', ldb.SCOPE_BASE),
              ('subtree', ldb.SCOPE_SUBTREE),
              ('onelevel', ldb.SCOPE_ONELEVEL))

    bases = (None,
             'DC=TOP',
             'OU=OU7,DC=TOP'
             )

    unary_filters = ("(&({k1}={v1})({k1}={v1}))",
                     "({k1}={v1}*)",
                     "({k1}=*)",
                     "({k1}=*{v1}*)",
                     "(!({k1}={v1}))",
                     )

    binary_filters = ("(&({k1}={v1})({k2}={v2}))",
                      "(|({k1}={v1})({k2}={v2}))",
                      "(|({k1}={v1})(!({k2}={v2})))",
                      "(&(!({k1}={v1}))({k2}={v2}))",
                      )

    ternary_filters = ("(&({k1}={v1})({k2}={v2})({k3}={v3}))",
                       "(|({k1}={v1})({k2}={v2})({k3}={v3}))",
                       "(|({k1}={v1})(!(|({k2}={v2})({k3}={v3}))))",
                       "(&(!({k1}={v1}))(&({k2}={v2})({k3}={v3})))",
                       "(&({k1}={v1})(|({k2}={v2})({k3}={v3})))",
                       )


@DynamicTestCase
class SearchTestFewObjects(SearchTestBase):
    n_objects = 5
    attrs = 'abc'
    values = 'XYZ'
    non_existent_attrs = 'M'
    non_existent_values = 'm'

    databases = (
        #['tdb-unindexed', TDB_PREFIX, None],
        ['tdb-indexed-dn', TDB_PREFIX, (1, False)],
        ['tdb-half-indexed', TDB_PREFIX, (0.5,)],
        ['tdb-indexed-guid', TDB_PREFIX, ()],
        ['mdb-indexed', MDB_PREFIX, ()],
    )

    scopes = (('base', ldb.SCOPE_BASE),
              ('subtree', ldb.SCOPE_SUBTREE),
              ('onelevel', ldb.SCOPE_ONELEVEL))

    bases = (None,
             'DC=TOP',
             'OU=OU7,DC=TOP'
             )

    unary_filters = ("(&({k1}={v1})({k1}={v1}))",
                     "({k1}={v1}*)",
                     "({k1}=*{v1}*)",
                     "(!({k1}={v1}))",
                     "(!({k1}=*))",
                     )

    binary_filters = ("(&({k1}={v1})({k2}={v2}))",
                      "(|({k1}={v1})({k2}={v2}))",
                      "(|({k1}={v1})(!({k2}={v2})))",
                      "(&(!({k1}={v1}))({k2}={v2}))",
                      )

    ternary_filters = ("(&({k1}={v1})({k2}={v2})({k3}={v3}))",
                       "(|({k1}={v1})({k2}={v2})({k3}={v3}))",
                       "(|({k1}={v1})(!(|({k2}={v2})({k3}={v3}))))",
                       "(&(!({k1}={v1}))(&({k2}={v2})({k3}={v3})))",
                       "(&({k1}={v1})(|({k2}={v2})({k3}={v3})))",
                       )



@DynamicTestCase
class SearchTestManyAttrs(SearchTestBase):
    n_objects = 50
    attrs = 'abcdefghijklm'
    values = 'PQ'

    databases = (
        ['tdb-unindexed', TDB_PREFIX, None],
        ['tdb-indexed-dn', TDB_PREFIX, (1, False)],
        ['tdb-half-indexed', TDB_PREFIX, (0.5,)],
        ['tdb-indexed-guid', TDB_PREFIX, ()],
        ['mdb-indexed', MDB_PREFIX, ()],
    )

    scopes = (('base', ldb.SCOPE_BASE),
              ('subtree', ldb.SCOPE_SUBTREE),
              ('onelevel', ldb.SCOPE_ONELEVEL))

    bases = (None,
             'DC=TOP',
             'OU=OU7,DC=TOP'
             )

    unary_filters = ("(&({k1}={v1})({k1}={v1}))",
                     "({k1}={v1}*)",
                     "({k1}=*{v1}*)",
                     "(!({k1}={v1}))",
                     "(!({k1}=*))",
                     )

    binary_filters = ("(&({k1}={v1})({k2}={v2}))",
                      "(|({k1}={v1})(!({k2}={v2})))",
                      "(&(!({k1}={v1}))({k2}={v2}))",
                      )

    ternary_filters = ("(&({k1}={v1})({k2}={v2})({k3}={v3}))",
                       )


@DynamicTestCase
class GreaterAndLessThanSearchTest(SearchTestBase):
    n_objects = 50
    attrs = 'abc'
    values = '13'
    non_existent_attrs = 'M'
    non_existent_values = '2'  # between the real ones

    databases = (
        #['tdb-unindexed', TDB_PREFIX, None],
        ['tdb-indexed-dn', TDB_PREFIX, (1, False)],
        ['tdb-half-indexed', TDB_PREFIX, (0.5,)],
        ['tdb-indexed-guid', TDB_PREFIX, ()],
        ['mdb-indexed', MDB_PREFIX, ()],
    )

    scopes = (('base', ldb.SCOPE_BASE),
              ('subtree', ldb.SCOPE_SUBTREE),
              ('onelevel', ldb.SCOPE_ONELEVEL))

    bases = ('DC=TOP',
             'OU=OU7,DC=TOP'
             )

    unary_filters = ("(&({k1}>={v1})({k1}<={v1}))",
                     "({k1}<={v1}*)",
                     "({k1}>=*{v1}*)",
                     "(!({k1}>={v1}))",
                     )

    binary_filters = ("(&({k1}>={v1})({k2}<={v2}))",
                      "(|({k1}={v1})({k2}>={v2}))",
                      "(|({k1}<={v1})(!({k2}={v2})))",
                      "(&(!({k1}>={v1}))({k2}={v2}))",
                      )

    ternary_filters = ("(&({k1}>={v1})({k2}>={v2})({k3}>={v3}))",
                       "(|({k1}<={v1})({k2}>={v2})({k3}<={v3}))",
                       "(|({k1}={v1})(!(|({k2}>={v2})({k3}={v3}))))",
                       "(&(!({k1}={v1}))(&({k2}<={v2})({k3}={v3})))",
                       "(&({k1}>={v1})(|({k2}={v2})({k3}<={v3})))",
                       )


if __name__ == '__main__':
    unittest.TestProgram()
