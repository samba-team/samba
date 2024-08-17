#!/usr/bin/env python3
# Simple tests for the ldb python bindings.
# Copyright (C) 2007 Jelmer Vernooij <jelmer@samba.org>

import os
from unittest import TestCase
import sys
sys.path.insert(0, "bin/python")
import ldb
import errno

from api_base import (
    MDB_PREFIX,
    MDB_INDEX_OBJ,
    tempdir,
    LdbBaseTest
)


class NoContextTests(TestCase):

    def test_valid_attr_name(self):
        self.assertTrue(ldb.valid_attr_name("foo"))
        self.assertFalse(ldb.valid_attr_name("24foo"))

    def test_timestring(self):
        self.assertEqual("19700101000000.0Z", ldb.timestring(0))
        self.assertEqual("20071119191012.0Z", ldb.timestring(1195499412))

        self.assertEqual("00000101000000.0Z", ldb.timestring(-62167219200))
        self.assertEqual("99991231235959.0Z", ldb.timestring(253402300799))

        # should result with OSError EOVERFLOW from gmtime()
        with self.assertRaises(OSError) as err:
            ldb.timestring(-62167219201)
        self.assertEqual(err.exception.errno, errno.EOVERFLOW)
        with self.assertRaises(OSError) as err:
            ldb.timestring(253402300800)
        self.assertEqual(err.exception.errno, errno.EOVERFLOW)
        with self.assertRaises(OSError) as err:
            ldb.timestring(0x7fffffffffffffff)
        self.assertEqual(err.exception.errno, errno.EOVERFLOW)

    def test_string_to_time(self):
        self.assertEqual(0, ldb.string_to_time("19700101000000.0Z"))
        self.assertEqual(-1, ldb.string_to_time("19691231235959.0Z"))
        self.assertEqual(1195499412, ldb.string_to_time("20071119191012.0Z"))

        self.assertEqual(-62167219200, ldb.string_to_time("00000101000000.0Z"))
        self.assertEqual(253402300799, ldb.string_to_time("99991231235959.0Z"))

    def test_binary_encode(self):
        encoded = ldb.binary_encode(b'test\\x')
        decoded = ldb.binary_decode(encoded)
        self.assertEqual(decoded, b'test\\x')

        encoded2 = ldb.binary_encode('test\\x')
        self.assertEqual(encoded2, encoded)


class BadIndexTests(LdbBaseTest):
    def setUp(self):
        super().setUp()
        self.testdir = tempdir()
        self.filename = os.path.join(self.testdir, "test.ldb")
        self.ldb = ldb.Ldb(self.url(), flags=self.flags())
        if hasattr(self, 'IDXGUID'):
            self.ldb.add({"dn": "@INDEXLIST",
                          "@IDXATTR": [b"x", b"y", b"ou"],
                          "@IDXGUID": [b"objectUUID"],
                          "@IDX_DN_GUID": [b"GUID"]})
        else:
            self.ldb.add({"dn": "@INDEXLIST",
                          "@IDXATTR": [b"x", b"y", b"ou"]})

        super().setUp()

    def test_unique(self):
        self.ldb.add({"dn": "x=x,dc=samba,dc=org",
                      "objectUUID": b"0123456789abcde1",
                      "y": "1"})
        self.ldb.add({"dn": "x=y,dc=samba,dc=org",
                      "objectUUID": b"0123456789abcde2",
                      "y": "1"})
        self.ldb.add({"dn": "x=z,dc=samba,dc=org",
                      "objectUUID": b"0123456789abcde3",
                      "y": "1"})

        res = self.ldb.search(expression="(y=1)",
                              base="dc=samba,dc=org")
        self.assertEqual(len(res), 3)

        # Now set this to unique index, but forget to check the result
        try:
            self.ldb.add({"dn": "@ATTRIBUTES",
                          "y": "UNIQUE_INDEX"})
            self.fail()
        except ldb.LdbError:
            pass

        # We must still have a working index
        res = self.ldb.search(expression="(y=1)",
                              base="dc=samba,dc=org")
        self.assertEqual(len(res), 3)

    def test_unique_transaction(self):
        self.ldb.add({"dn": "x=x,dc=samba,dc=org",
                      "objectUUID": b"0123456789abcde1",
                      "y": "1"})
        self.ldb.add({"dn": "x=y,dc=samba,dc=org",
                      "objectUUID": b"0123456789abcde2",
                      "y": "1"})
        self.ldb.add({"dn": "x=z,dc=samba,dc=org",
                      "objectUUID": b"0123456789abcde3",
                      "y": "1"})

        res = self.ldb.search(expression="(y=1)",
                              base="dc=samba,dc=org")
        self.assertEqual(len(res), 3)

        self.ldb.transaction_start()

        # Now set this to unique index, but forget to check the result
        try:
            self.ldb.add({"dn": "@ATTRIBUTES",
                          "y": "UNIQUE_INDEX"})
        except ldb.LdbError:
            pass

        try:
            self.ldb.transaction_commit()
            self.fail()

        except ldb.LdbError as err:
            enum = err.args[0]
            self.assertEqual(enum, ldb.ERR_OPERATIONS_ERROR)

        # We must still have a working index
        res = self.ldb.search(expression="(y=1)",
                              base="dc=samba,dc=org")

        self.assertEqual(len(res), 3)

    def test_casefold(self):
        self.ldb.add({"dn": "x=x,dc=samba,dc=org",
                      "objectUUID": b"0123456789abcde1",
                      "y": "a"})
        self.ldb.add({"dn": "x=y,dc=samba,dc=org",
                      "objectUUID": b"0123456789abcde2",
                      "y": "A"})
        self.ldb.add({"dn": "x=z,dc=samba,dc=org",
                      "objectUUID": b"0123456789abcde3",
                      "y": ["a", "A"]})

        res = self.ldb.search(expression="(y=a)",
                              base="dc=samba,dc=org")
        self.assertEqual(len(res), 2)

        self.ldb.add({"dn": "@ATTRIBUTES",
                      "y": "CASE_INSENSITIVE"})

        # We must still have a working index
        res = self.ldb.search(expression="(y=a)",
                              base="dc=samba,dc=org")

        if hasattr(self, 'IDXGUID'):
            self.assertEqual(len(res), 3)
        else:
            # We should not return this entry twice, but sadly
            # we have not yet fixed
            # https://bugzilla.samba.org/show_bug.cgi?id=13361
            self.assertEqual(len(res), 4)

    def test_casefold_transaction(self):
        self.ldb.add({"dn": "x=x,dc=samba,dc=org",
                      "objectUUID": b"0123456789abcde1",
                      "y": "a"})
        self.ldb.add({"dn": "x=y,dc=samba,dc=org",
                      "objectUUID": b"0123456789abcde2",
                      "y": "A"})
        self.ldb.add({"dn": "x=z,dc=samba,dc=org",
                      "objectUUID": b"0123456789abcde3",
                      "y": ["a", "A"]})

        res = self.ldb.search(expression="(y=a)",
                              base="dc=samba,dc=org")
        self.assertEqual(len(res), 2)

        self.ldb.transaction_start()

        self.ldb.add({"dn": "@ATTRIBUTES",
                      "y": "CASE_INSENSITIVE"})

        self.ldb.transaction_commit()

        # We must still have a working index
        res = self.ldb.search(expression="(y=a)",
                              base="dc=samba,dc=org")

        if hasattr(self, 'IDXGUID'):
            self.assertEqual(len(res), 3)
        else:
            # We should not return this entry twice, but sadly
            # we have not yet fixed
            # https://bugzilla.samba.org/show_bug.cgi?id=13361
            self.assertEqual(len(res), 4)

    def test_modify_transaction(self):
        self.ldb.add({"dn": "x=y,dc=samba,dc=org",
                      "objectUUID": b"0123456789abcde1",
                      "y": "2",
                      "z": "2"})

        res = self.ldb.search(expression="(y=2)",
                              base="dc=samba,dc=org")
        self.assertEqual(len(res), 1)

        self.ldb.add({"dn": "@ATTRIBUTES",
                      "y": "UNIQUE_INDEX"})

        self.ldb.transaction_start()

        m = ldb.Message()
        m.dn = ldb.Dn(self.ldb, "x=y,dc=samba,dc=org")
        m["0"] = ldb.MessageElement([], ldb.FLAG_MOD_DELETE, "y")
        m["1"] = ldb.MessageElement([], ldb.FLAG_MOD_DELETE, "not-here")

        try:
            self.ldb.modify(m)
            self.fail()

        except ldb.LdbError as err:
            enum = err.args[0]
            self.assertEqual(enum, ldb.ERR_NO_SUCH_ATTRIBUTE)

        try:
            self.ldb.transaction_commit()
            # We should fail here, but we want to be sure
            # we fail below

        except ldb.LdbError as err:
            enum = err.args[0]
            self.assertEqual(enum, ldb.ERR_OPERATIONS_ERROR)

        # The index should still be pointing to x=y
        res = self.ldb.search(expression="(y=2)",
                              base="dc=samba,dc=org")
        self.assertEqual(len(res), 1)

        try:
            self.ldb.add({"dn": "x=y2,dc=samba,dc=org",
                        "objectUUID": b"0123456789abcde2",
                        "y": "2"})
            self.fail("Added unique attribute twice")
        except ldb.LdbError as err:
            enum = err.args[0]
            self.assertEqual(enum, ldb.ERR_CONSTRAINT_VIOLATION)

        res = self.ldb.search(expression="(y=2)",
                              base="dc=samba,dc=org")
        self.assertEqual(len(res), 1)
        self.assertEqual(str(res[0].dn), "x=y,dc=samba,dc=org")


class GUIDBadIndexTests(BadIndexTests):
    """Test Bad index things with GUID index mode"""

    def setUp(self):
        self.IDXGUID = True

        super().setUp()


class GUIDBadIndexTestsLmdb(BadIndexTests):

    def setUp(self):
        if os.environ.get('HAVE_LMDB', '1') == '0':
            self.skipTest("No lmdb backend")
        self.prefix = MDB_PREFIX
        self.index = MDB_INDEX_OBJ
        self.IDXGUID = True
        super().setUp()


class BatchModeTests(LdbBaseTest):

    def setUp(self):
        super().setUp()
        self.testdir = tempdir()
        self.filename = os.path.join(self.testdir, "test.ldb")
        self.ldb = ldb.Ldb(self.url(),
                           flags=self.flags(),
                           options=["batch_mode:1"])
        if hasattr(self, 'IDXGUID'):
            self.ldb.add({"dn": "@INDEXLIST",
                          "@IDXATTR": [b"x", b"y", b"ou"],
                          "@IDXGUID": [b"objectUUID"],
                          "@IDX_DN_GUID": [b"GUID"]})
        else:
            self.ldb.add({"dn": "@INDEXLIST",
                          "@IDXATTR": [b"x", b"y", b"ou"]})

    def test_modify_transaction(self):
        self.ldb.add({"dn": "x=y,dc=samba,dc=org",
                      "objectUUID": b"0123456789abcde1",
                      "y": "2",
                      "z": "2"})

        res = self.ldb.search(expression="(y=2)",
                              base="dc=samba,dc=org")
        self.assertEqual(len(res), 1)

        self.ldb.add({"dn": "@ATTRIBUTES",
                      "y": "UNIQUE_INDEX"})

        self.ldb.transaction_start()

        m = ldb.Message()
        m.dn = ldb.Dn(self.ldb, "x=y,dc=samba,dc=org")
        m["0"] = ldb.MessageElement([], ldb.FLAG_MOD_DELETE, "y")
        m["1"] = ldb.MessageElement([], ldb.FLAG_MOD_DELETE, "not-here")

        try:
            self.ldb.modify(m)
            self.fail()

        except ldb.LdbError as err:
            enum = err.args[0]
            self.assertEqual(enum, ldb.ERR_NO_SUCH_ATTRIBUTE)

        try:
            self.ldb.transaction_commit()
            self.fail("Commit should have failed as we were in batch mode")
        except ldb.LdbError as err:
            enum = err.args[0]
            self.assertEqual(enum, ldb.ERR_OPERATIONS_ERROR)


class DnTests(TestCase):

    def setUp(self):
        super().setUp()
        self.ldb = ldb.Ldb()

    def tearDown(self):
        super().tearDown()
        del(self.ldb)

    def test_set_dn_invalid(self):
        x = ldb.Message()

        def assign():
            x.dn = "astring"
        self.assertRaises(TypeError, assign)

    def test_eq(self):
        x = ldb.Dn(self.ldb, "dc=foo11,bar=bloe")
        y = ldb.Dn(self.ldb, "dc=foo11,bar=bloe")
        self.assertEqual(x, y)
        y = ldb.Dn(self.ldb, "dc=foo11,bar=blie")
        self.assertNotEqual(x, y)

    def test_str(self):
        x = ldb.Dn(self.ldb, "dc=foo12,bar=bloe")
        self.assertEqual(x.__str__(), "dc=foo12,bar=bloe")

    def test_repr(self):
        x = ldb.Dn(self.ldb, "dc=foo13,bla=blie")
        self.assertEqual(x.__repr__(), "Dn('dc=foo13,bla=blie')")

    def test_get_casefold_2(self):
        x = ldb.Dn(self.ldb, "dc=foo14,bar=bloe")
        self.assertEqual(x.get_casefold(), "DC=FOO14,BAR=bloe")

    def test_get_casefold_dotted_i(self):
        x = ldb.Dn(self.ldb, "dc=foo14,bir=blie")
        self.assertEqual(x.get_casefold(), "DC=FOO14,BIR=blie")

    def test_validate(self):
        x = ldb.Dn(self.ldb, "dc=foo15,bar=bloe")
        self.assertTrue(x.validate())

    def test_parent(self):
        x = ldb.Dn(self.ldb, "dc=foo16,bar=bloe")
        self.assertEqual("bar=bloe", x.parent().__str__())

    def test_parent_nonexistent(self):
        x = ldb.Dn(self.ldb, "@BLA")
        self.assertEqual(None, x.parent())

    def test_is_valid(self):
        x = ldb.Dn(self.ldb, "dc=foo18,dc=bloe")
        self.assertTrue(x.is_valid())
        x = ldb.Dn(self.ldb, "")
        self.assertTrue(x.is_valid())

    def test_is_special(self):
        x = ldb.Dn(self.ldb, "dc=foo19,bar=bloe")
        self.assertFalse(x.is_special())
        x = ldb.Dn(self.ldb, "@FOOBAR")
        self.assertTrue(x.is_special())

    def test_check_special(self):
        x = ldb.Dn(self.ldb, "dc=foo20,bar=bloe")
        self.assertFalse(x.check_special("FOOBAR"))
        x = ldb.Dn(self.ldb, "@FOOBAR")
        self.assertTrue(x.check_special("@FOOBAR"))

    def test_len(self):
        x = ldb.Dn(self.ldb, "dc=foo21,bar=bloe")
        self.assertEqual(2, len(x))
        x = ldb.Dn(self.ldb, "dc=foo21")
        self.assertEqual(1, len(x))

    def test_add_child(self):
        x = ldb.Dn(self.ldb, "dc=foo22,bar=bloe")
        self.assertTrue(x.add_child(ldb.Dn(self.ldb, "bla=bloe")))
        self.assertEqual("bla=bloe,dc=foo22,bar=bloe", x.__str__())

    def test_add_base(self):
        x = ldb.Dn(self.ldb, "dc=foo23,bar=bloe")
        base = ldb.Dn(self.ldb, "bla=bloe")
        self.assertTrue(x.add_base(base))
        self.assertEqual("dc=foo23,bar=bloe,bla=bloe", x.__str__())

    def test_add_child_str(self):
        x = ldb.Dn(self.ldb, "dc=foo22,bar=bloe")
        self.assertTrue(x.add_child("bla=bloe"))
        self.assertEqual("bla=bloe,dc=foo22,bar=bloe", x.__str__())

    def test_add_base_str(self):
        x = ldb.Dn(self.ldb, "dc=foo23,bar=bloe")
        base = "bla=bloe"
        self.assertTrue(x.add_base(base))
        self.assertEqual("dc=foo23,bar=bloe,bla=bloe", x.__str__())

    def test_add(self):
        x = ldb.Dn(self.ldb, "dc=foo24")
        y = ldb.Dn(self.ldb, "bar=bla")
        self.assertEqual("dc=foo24,bar=bla", str(x + y))

    def test_remove_base_components(self):
        x = ldb.Dn(self.ldb, "dc=foo24,dc=samba,dc=org")
        x.remove_base_components(len(x) - 1)
        self.assertEqual("dc=foo24", str(x))

    def test_parse_ldif(self):
        msgs = self.ldb.parse_ldif("dn: foo=bar\n")
        msg = next(msgs)
        self.assertEqual("foo=bar", str(msg[1].dn))
        self.assertTrue(isinstance(msg[1], ldb.Message))
        ldif = self.ldb.write_ldif(msg[1], ldb.CHANGETYPE_NONE)
        self.assertEqual("dn: foo=bar\n\n", ldif)

    def test_parse_ldif_more(self):
        msgs = self.ldb.parse_ldif("dn: foo=bar\n\n\ndn: bar=bar")
        msg = next(msgs)
        self.assertEqual("foo=bar", str(msg[1].dn))
        msg = next(msgs)
        self.assertEqual("bar=bar", str(msg[1].dn))

    def test_print_ldif(self):
        ldif = '''dn: dc=foo27
foo: foo

'''
        self.msg = ldb.Message(ldb.Dn(self.ldb, "dc=foo27"))
        self.msg["foo"] = [b"foo"]
        self.assertEqual(ldif,
                         self.ldb.write_ldif(self.msg,
                                             ldb.CHANGETYPE_NONE))

    def test_print_ldif_binary(self):
        # this also confirms that ldb flags are set even without a URL)
        self.ldb = ldb.Ldb(flags=ldb.FLG_SHOW_BINARY)
        ldif = '''dn: dc=foo27
foo: f
öö

'''
        self.msg = ldb.Message(ldb.Dn(self.ldb, "dc=foo27"))
        self.msg["foo"] = ["f\nöö"]
        self.assertEqual(ldif,
                         self.ldb.write_ldif(self.msg,
                                             ldb.CHANGETYPE_NONE))


    def test_print_ldif_no_base64_bad(self):
        ldif = '''dn: dc=foo27
foo: f
öö

'''
        self.msg = ldb.Message(ldb.Dn(self.ldb, "dc=foo27"))
        self.msg["foo"] = ["f\nöö"]
        self.msg["foo"].set_flags(ldb.FLAG_FORCE_NO_BASE64_LDIF)
        self.assertEqual(ldif,
                         self.ldb.write_ldif(self.msg,
                                             ldb.CHANGETYPE_NONE))

    def test_print_ldif_no_base64_good(self):
        ldif = '''dn: dc=foo27
foo: föö

'''
        self.msg = ldb.Message(ldb.Dn(self.ldb, "dc=foo27"))
        self.msg["foo"] = ["föö"]
        self.msg["foo"].set_flags(ldb.FLAG_FORCE_NO_BASE64_LDIF)
        self.assertEqual(ldif,
                         self.ldb.write_ldif(self.msg,
                                             ldb.CHANGETYPE_NONE))

    def test_canonical_string(self):
        x = ldb.Dn(self.ldb, "dc=foo25,bar=bloe")
        self.assertEqual("/bloe/foo25", x.canonical_str())

    def test_canonical_ex_string(self):
        x = ldb.Dn(self.ldb, "dc=foo26,bar=bloe")
        self.assertEqual("/bloe\nfoo26", x.canonical_ex_str())

    def test_ldb_is_child_of(self):
        """Testing ldb_dn_compare_dn"""
        dn1 = ldb.Dn(self.ldb, "dc=base")
        dn2 = ldb.Dn(self.ldb, "cn=foo,dc=base")
        dn3 = ldb.Dn(self.ldb, "cn=bar,dc=base")
        dn4 = ldb.Dn(self.ldb, "cn=baz,cn=bar,dc=base")

        self.assertTrue(dn1.is_child_of(dn1))
        self.assertTrue(dn2.is_child_of(dn1))
        self.assertTrue(dn4.is_child_of(dn1))
        self.assertTrue(dn4.is_child_of(dn3))
        self.assertTrue(dn4.is_child_of(dn4))
        self.assertFalse(dn3.is_child_of(dn2))
        self.assertFalse(dn1.is_child_of(dn4))

    def test_ldb_is_child_of_str(self):
        """Testing ldb_dn_compare_dn"""
        dn1_str = "dc=base"
        dn2_str = "cn=foo,dc=base"
        dn3_str = "cn=bar,dc=base"
        dn4_str = "cn=baz,cn=bar,dc=base"

        dn1 = ldb.Dn(self.ldb, dn1_str)
        dn2 = ldb.Dn(self.ldb, dn2_str)
        dn3 = ldb.Dn(self.ldb, dn3_str)
        dn4 = ldb.Dn(self.ldb, dn4_str)

        self.assertTrue(dn1.is_child_of(dn1_str))
        self.assertTrue(dn2.is_child_of(dn1_str))
        self.assertTrue(dn4.is_child_of(dn1_str))
        self.assertTrue(dn4.is_child_of(dn3_str))
        self.assertTrue(dn4.is_child_of(dn4_str))
        self.assertFalse(dn3.is_child_of(dn2_str))
        self.assertFalse(dn1.is_child_of(dn4_str))

    def test_get_component_name(self):
        dn = ldb.Dn(self.ldb, "cn=foo,dc=base")
        self.assertEqual(dn.get_component_name(0), 'cn')
        self.assertEqual(dn.get_component_name(1), 'dc')
        self.assertEqual(dn.get_component_name(2), None)
        self.assertEqual(dn.get_component_name(-1), None)

    def test_get_component_value(self):
        dn = ldb.Dn(self.ldb, "cn=foo,dc=base")
        self.assertEqual(dn.get_component_value(0), 'foo')
        self.assertEqual(dn.get_component_value(1), 'base')
        self.assertEqual(dn.get_component_name(2), None)
        self.assertEqual(dn.get_component_name(-1), None)

    def test_set_component(self):
        dn = ldb.Dn(self.ldb, "cn=foo,dc=base")
        dn.set_component(0, 'cn', 'bar')
        self.assertEqual(str(dn), "cn=bar,dc=base")
        dn.set_component(1, 'o', 'asep')
        self.assertEqual(str(dn), "cn=bar,o=asep")
        self.assertRaises(TypeError, dn.set_component, 2, 'dc', 'base')
        self.assertEqual(str(dn), "cn=bar,o=asep")
        dn.set_component(1, 'o', 'a,b+c')
        self.assertEqual(str(dn), r"cn=bar,o=a\,b\+c")

    def test_set_component_bytes(self):
        dn = ldb.Dn(self.ldb, "cn=foo,dc=base")
        dn.set_component(0, 'cn', b'bar')
        self.assertEqual(str(dn), "cn=bar,dc=base")
        dn.set_component(1, 'o', b'asep')
        self.assertEqual(str(dn), "cn=bar,o=asep")

    def test_set_component_none(self):
        dn = ldb.Dn(self.ldb, "cn=foo,cn=bar,dc=base")
        self.assertRaises(TypeError, dn.set_component, 1, 'cn', None)

    def test_get_extended_component_null(self):
        dn = ldb.Dn(self.ldb, "cn=foo,cn=bar,dc=base")
        self.assertEqual(dn.get_extended_component("TEST"), None)

    def test_get_extended_component(self):
        self.ldb._register_test_extensions()
        dn = ldb.Dn(self.ldb, "<TEST=foo>;cn=bar,dc=base")
        self.assertEqual(dn.get_extended_component("TEST"), b"foo")

    def test_set_extended_component(self):
        self.ldb._register_test_extensions()
        dn = ldb.Dn(self.ldb, "dc=base")
        dn.set_extended_component("TEST", "foo")
        self.assertEqual(dn.get_extended_component("TEST"), b"foo")
        dn.set_extended_component("TEST", b"bar")
        self.assertEqual(dn.get_extended_component("TEST"), b"bar")

    def test_extended_str(self):
        self.ldb._register_test_extensions()
        dn = ldb.Dn(self.ldb, "<TEST=foo>;cn=bar,dc=base")
        self.assertEqual(dn.extended_str(), "<TEST=foo>;cn=bar,dc=base")

    def test_get_rdn_name(self):
        dn = ldb.Dn(self.ldb, "cn=foo,dc=base")
        self.assertEqual(dn.get_rdn_name(), 'cn')

    def test_get_rdn_value(self):
        dn = ldb.Dn(self.ldb, "cn=foo,dc=base")
        self.assertEqual(dn.get_rdn_value(), 'foo')

    def test_get_casefold(self):
        dn = ldb.Dn(self.ldb, "cn=foo,dc=base")
        self.assertEqual(dn.get_casefold(), 'CN=FOO,DC=BASE')

    def test_get_linearized(self):
        dn = ldb.Dn(self.ldb, "cn=foo,dc=base")
        self.assertEqual(dn.get_linearized(), 'cn=foo,dc=base')

    def test_is_null(self):
        dn = ldb.Dn(self.ldb, "cn=foo,dc=base")
        self.assertFalse(dn.is_null())

        dn = ldb.Dn(self.ldb, '')
        self.assertTrue(dn.is_null())


class LdbMsgTests(TestCase):

    def setUp(self):
        super().setUp()
        self.msg = ldb.Message()

    def test_init_dn(self):
        self.msg = ldb.Message(ldb.Dn(ldb.Ldb(), "dc=foo27"))
        self.assertEqual("dc=foo27", str(self.msg.dn))

    def test_iter_items(self):
        self.assertEqual(0, len(self.msg.items()))
        self.msg.dn = ldb.Dn(ldb.Ldb(), "dc=foo28")
        self.assertEqual(1, len(self.msg.items()))

    def test_items(self):
        self.msg["foo"] = ["foo"]
        self.msg["bar"] = ["bar"]
        try:
            items = self.msg.items()
        except:
            self.fail()
        self.assertEqual([("foo", ldb.MessageElement(["foo"])),
                          ("bar", ldb.MessageElement(["bar"]))],
                         items)

        self.msg.dn = ldb.Dn(ldb.Ldb(), "dc=test")
        try:
            items = self.msg.items()
        except:
            self.fail()
        self.assertEqual([("dn", ldb.Dn(ldb.Ldb(), "dc=test")),
                          ("foo", ldb.MessageElement(["foo"])),
                          ("bar", ldb.MessageElement(["bar"]))],
                         items)

    def test_repr(self):
        self.msg.dn = ldb.Dn(ldb.Ldb(), "dc=foo29")
        self.msg["dc"] = b"foo"
        self.assertIn(repr(self.msg), [
            "Message({'dn': Dn('dc=foo29'), 'dc': MessageElement([b'foo'])})",
            "Message({'dc': MessageElement([b'foo']), 'dn': Dn('dc=foo29')})",
        ])
        self.assertIn(repr(self.msg.text), [
            "Message({'dn': Dn('dc=foo29'), 'dc': MessageElement([b'foo'])}).text",
            "Message({'dc': MessageElement([b'foo']), 'dn': Dn('dc=foo29')}).text",
        ])

    def test_len(self):
        self.assertEqual(0, len(self.msg))

    def test_notpresent(self):
        self.assertRaises(KeyError, lambda: self.msg["foo"])

    def test_invalid(self):
        try:
            self.assertRaises(TypeError, lambda: self.msg[42])
        except KeyError:
            self.fail()

    def test_del(self):
        del self.msg["foo"]

    def test_add(self):
        self.msg.add(ldb.MessageElement([b"456"], ldb.FLAG_MOD_ADD, "bla"))

    def test_add_text(self):
        self.msg.add(ldb.MessageElement(["456"], ldb.FLAG_MOD_ADD, "bla"))

    def test_elements_empty(self):
        self.assertEqual([], self.msg.elements())

    def test_elements(self):
        el = ldb.MessageElement([b"456"], ldb.FLAG_MOD_ADD, "bla")
        self.msg.add(el)
        self.assertEqual([el], self.msg.elements())
        self.assertEqual([el.text], self.msg.text.elements())

    def test_add_value(self):
        self.assertEqual(0, len(self.msg))
        self.msg["foo"] = [b"foo"]
        self.assertEqual(1, len(self.msg))

    def test_add_value_text(self):
        self.assertEqual(0, len(self.msg))
        self.msg["foo"] = ["foo"]
        self.assertEqual(1, len(self.msg))

    def test_add_value_multiple(self):
        self.assertEqual(0, len(self.msg))
        self.msg["foo"] = [b"foo", b"bla"]
        self.assertEqual(1, len(self.msg))
        self.assertEqual([b"foo", b"bla"], list(self.msg["foo"]))

    def test_add_value_multiple_text(self):
        self.assertEqual(0, len(self.msg))
        self.msg["foo"] = ["foo", "bla"]
        self.assertEqual(1, len(self.msg))
        self.assertEqual(["foo", "bla"], list(self.msg.text["foo"]))

    def test_set_value(self):
        self.msg["foo"] = [b"fool"]
        self.assertEqual([b"fool"], list(self.msg["foo"]))
        self.msg["foo"] = [b"bar"]
        self.assertEqual([b"bar"], list(self.msg["foo"]))

    def test_set_value_text(self):
        self.msg["foo"] = ["fool"]
        self.assertEqual(["fool"], list(self.msg.text["foo"]))
        self.msg["foo"] = ["bar"]
        self.assertEqual(["bar"], list(self.msg.text["foo"]))

    def test_keys(self):
        self.msg.dn = ldb.Dn(ldb.Ldb(), "@BASEINFO")
        self.msg["foo"] = [b"bla"]
        self.msg["bar"] = [b"bla"]
        self.assertEqual(["dn", "foo", "bar"], list(self.msg.keys()))

    def test_keys_text(self):
        self.msg.dn = ldb.Dn(ldb.Ldb(), "@BASEINFO")
        self.msg["foo"] = ["bla"]
        self.msg["bar"] = ["bla"]
        self.assertEqual(["dn", "foo", "bar"], list(self.msg.text.keys()))

    def test_dn(self):
        self.msg.dn = ldb.Dn(ldb.Ldb(), "@BASEINFO")
        self.assertEqual("@BASEINFO", self.msg.dn.__str__())

    def test_get_dn(self):
        self.msg.dn = ldb.Dn(ldb.Ldb(), "@BASEINFO")
        self.assertEqual("@BASEINFO", self.msg.get("dn").__str__())

    def test_dn_text(self):
        self.msg.text.dn = ldb.Dn(ldb.Ldb(), "@BASEINFO")
        self.assertEqual("@BASEINFO", str(self.msg.dn))
        self.assertEqual("@BASEINFO", str(self.msg.text.dn))

    def test_get_dn_text(self):
        self.msg.dn = ldb.Dn(ldb.Ldb(), "@BASEINFO")
        self.assertEqual("@BASEINFO", str(self.msg.get("dn")))
        self.assertEqual("@BASEINFO", str(self.msg.text.get("dn")))

    def test_get_invalid(self):
        self.msg.dn = ldb.Dn(ldb.Ldb(), "@BASEINFO")
        self.assertRaises(TypeError, self.msg.get, 42)

    def test_get_other(self):
        self.msg["foo"] = [b"bar"]
        self.assertEqual(b"bar", self.msg.get("foo")[0])
        self.assertEqual(b"bar", self.msg.get("foo", idx=0))
        self.assertEqual(None, self.msg.get("foo", idx=1))
        self.assertEqual("", self.msg.get("foo", default='', idx=1))

    def test_get_other_text(self):
        self.msg["foo"] = ["bar"]
        self.assertEqual(["bar"], list(self.msg.text.get("foo")))
        self.assertEqual("bar", self.msg.text.get("foo")[0])
        self.assertEqual("bar", self.msg.text.get("foo", idx=0))
        self.assertEqual(None, self.msg.get("foo", idx=1))
        self.assertEqual("", self.msg.get("foo", default='', idx=1))

    def test_get_default(self):
        self.assertEqual(None, self.msg.get("tatayoyo", idx=0))
        self.assertEqual("anniecordie", self.msg.get("tatayoyo", "anniecordie"))

    def test_get_default_text(self):
        self.assertEqual(None, self.msg.text.get("tatayoyo", idx=0))
        self.assertEqual("anniecordie", self.msg.text.get("tatayoyo", "anniecordie"))

    def test_get_unknown(self):
        self.assertEqual(None, self.msg.get("lalalala"))

    def test_get_unknown_text(self):
        self.assertEqual(None, self.msg.text.get("lalalala"))

    def test_contains(self):
        self.msg['foo'] = ['bar']
        self.assertIn('foo', self.msg)

        self.msg['Foo'] = ['bar']
        self.assertIn('Foo', self.msg)

    def test_contains_case(self):
        self.msg['foo'] = ['bar']
        self.assertIn('Foo', self.msg)

        self.msg['Foo'] = ['bar']
        self.assertIn('foo', self.msg)

    def test_contains_dn(self):
        self.assertIn('dn', self.msg)

    def test_contains_dn_case(self):
        self.assertIn('DN', self.msg)

    def test_contains_invalid(self):
        self.assertRaises(TypeError, lambda: None in self.msg)

    def test_msg_diff(self):
        l = ldb.Ldb()
        msgs = l.parse_ldif("dn: foo=bar\nfoo: bar\nbaz: do\n\ndn: foo=bar\nfoo: bar\nbaz: dont\n")
        msg1 = next(msgs)[1]
        msg2 = next(msgs)[1]
        msgdiff = l.msg_diff(msg1, msg2)
        self.assertEqual("foo=bar", msgdiff.get("dn").__str__())
        self.assertRaises(KeyError, lambda: msgdiff["foo"])
        self.assertEqual(1, len(msgdiff))

    def test_equal_empty(self):
        msg1 = ldb.Message()
        msg2 = ldb.Message()
        self.assertEqual(msg1, msg2)

    def test_equal_simplel(self):
        db = ldb.Ldb()
        msg1 = ldb.Message()
        msg1.dn = ldb.Dn(db, "foo=bar")
        msg2 = ldb.Message()
        msg2.dn = ldb.Dn(db, "foo=bar")
        self.assertEqual(msg1, msg2)
        msg1['foo'] = b'bar'
        msg2['foo'] = b'bar'
        self.assertEqual(msg1, msg2)
        msg2['foo'] = b'blie'
        self.assertNotEqual(msg1, msg2)
        msg2['foo'] = b'blie'

    def test_from_dict(self):
        rec = {"dn": "dc=fromdict",
               "a1": [b"a1-val1", b"a1-val1"]}
        l = ldb.Ldb()
        # check different types of input Flags
        for flags in [ldb.FLAG_MOD_ADD, ldb.FLAG_MOD_REPLACE, ldb.FLAG_MOD_DELETE]:
            m = ldb.Message.from_dict(l, rec, flags)
            self.assertEqual(rec["a1"], list(m["a1"]))
            self.assertEqual(flags, m["a1"].flags())
        # check input params
        self.assertRaises(TypeError, ldb.Message.from_dict, dict(), rec, ldb.FLAG_MOD_REPLACE)
        self.assertRaises(TypeError, ldb.Message.from_dict, l, list(), ldb.FLAG_MOD_REPLACE)
        self.assertRaises(ValueError, ldb.Message.from_dict, l, rec, 0)
        # Message.from_dict expects dictionary with 'dn'
        err_rec = {"a1": [b"a1-val1", b"a1-val1"]}
        self.assertRaises(TypeError, ldb.Message.from_dict, l, err_rec, ldb.FLAG_MOD_REPLACE)

    def test_from_dict_text(self):
        rec = {"dn": "dc=fromdict",
               "a1": ["a1-val1", "a1-val1"]}
        l = ldb.Ldb()
        # check different types of input Flags
        for flags in [ldb.FLAG_MOD_ADD, ldb.FLAG_MOD_REPLACE, ldb.FLAG_MOD_DELETE]:
            m = ldb.Message.from_dict(l, rec, flags)
            self.assertEqual(rec["a1"], list(m.text["a1"]))
            self.assertEqual(flags, m.text["a1"].flags())
        # check input params
        self.assertRaises(TypeError, ldb.Message.from_dict, dict(), rec, ldb.FLAG_MOD_REPLACE)
        self.assertRaises(TypeError, ldb.Message.from_dict, l, list(), ldb.FLAG_MOD_REPLACE)
        self.assertRaises(ValueError, ldb.Message.from_dict, l, rec, 0)
        # Message.from_dict expects dictionary with 'dn'
        err_rec = {"a1": ["a1-val1", "a1-val1"]}
        self.assertRaises(TypeError, ldb.Message.from_dict, l, err_rec, ldb.FLAG_MOD_REPLACE)

    def test_copy_add_message_element(self):
        m = ldb.Message()
        m["1"] = ldb.MessageElement([b"val 111"], ldb.FLAG_MOD_ADD, "1")
        m["2"] = ldb.MessageElement([b"val 222"], ldb.FLAG_MOD_ADD, "2")
        mto = ldb.Message()
        mto["1"] = m["1"]
        mto["2"] = m["2"]
        self.assertEqual(mto["1"], m["1"])
        self.assertEqual(mto["2"], m["2"])
        mto = ldb.Message()
        mto.add(m["1"])
        mto.add(m["2"])
        self.assertEqual(mto["1"], m["1"])
        self.assertEqual(mto["2"], m["2"])

    def test_copy_add_message_element_text(self):
        m = ldb.Message()
        m["1"] = ldb.MessageElement(["val 111"], ldb.FLAG_MOD_ADD, "1")
        m["2"] = ldb.MessageElement(["val 222"], ldb.FLAG_MOD_ADD, "2")
        mto = ldb.Message()
        mto["1"] = m["1"]
        mto["2"] = m["2"]
        self.assertEqual(mto["1"], m.text["1"])
        self.assertEqual(mto["2"], m.text["2"])
        mto = ldb.Message()
        mto.add(m["1"])
        mto.add(m["2"])
        self.assertEqual(mto.text["1"], m.text["1"])
        self.assertEqual(mto.text["2"], m.text["2"])
        self.assertEqual(mto["1"], m["1"])
        self.assertEqual(mto["2"], m["2"])


class MessageElementTests(TestCase):

    def test_cmp_element(self):
        x = ldb.MessageElement([b"foo"])
        y = ldb.MessageElement([b"foo"])
        z = ldb.MessageElement([b"bzr"])
        self.assertEqual(x, y)
        self.assertNotEqual(x, z)

    def test_cmp_element_text(self):
        x = ldb.MessageElement([b"foo"])
        y = ldb.MessageElement(["foo"])
        self.assertEqual(x, y)

    def test_create_iterable(self):
        x = ldb.MessageElement([b"foo"])
        self.assertEqual([b"foo"], list(x))
        self.assertEqual(["foo"], list(x.text))

    def test_repr(self):
        x = ldb.MessageElement([b"foo"])
        self.assertEqual("MessageElement([b'foo'])", repr(x))
        self.assertEqual("MessageElement([b'foo']).text", repr(x.text))
        x = ldb.MessageElement([b"foo", b"bla"])
        self.assertEqual(2, len(x))
        self.assertEqual("MessageElement([b'foo',b'bla'])", repr(x))
        self.assertEqual("MessageElement([b'foo',b'bla']).text", repr(x.text))

    def test_get_item(self):
        x = ldb.MessageElement([b"foo", b"bar"])
        self.assertEqual(b"foo", x[0])
        self.assertEqual(b"bar", x[1])
        self.assertEqual(b"bar", x[-1])
        self.assertRaises(IndexError, lambda: x[45])

    def test_get_item_text(self):
        x = ldb.MessageElement(["foo", "bar"])
        self.assertEqual("foo", x.text[0])
        self.assertEqual("bar", x.text[1])
        self.assertEqual("bar", x.text[-1])
        self.assertRaises(IndexError, lambda: x[45])

    def test_len(self):
        x = ldb.MessageElement([b"foo", b"bar"])
        self.assertEqual(2, len(x))

    def test_eq(self):
        x = ldb.MessageElement([b"foo", b"bar"])
        y = ldb.MessageElement([b"foo", b"bar"])
        self.assertEqual(y, x)
        x = ldb.MessageElement([b"foo"])
        self.assertNotEqual(y, x)
        y = ldb.MessageElement([b"foo"])
        self.assertEqual(y, x)

    def test_extended(self):
        el = ldb.MessageElement([b"456"], ldb.FLAG_MOD_ADD, "bla")
        self.assertEqual("MessageElement([b'456'])", repr(el))
        self.assertEqual("MessageElement([b'456']).text", repr(el.text))

    def test_bad_text(self):
        el = ldb.MessageElement(b'\xba\xdd')
        self.assertRaises(UnicodeDecodeError, el.text.__getitem__, 0)


class BadTypeTests(TestCase):
    def test_control(self):
        l = ldb.Ldb()
        self.assertRaises(TypeError, ldb.Control, '<bad type>', 'relax:1')
        self.assertRaises(TypeError, ldb.Control, ldb, 1234)

    def test_modify(self):
        l = ldb.Ldb()
        dn = ldb.Dn(l, 'a=b')
        m = ldb.Message(dn)
        self.assertRaises(TypeError, l.modify, '<bad type>')
        self.assertRaises(TypeError, l.modify, m, '<bad type>')

    def test_add(self):
        l = ldb.Ldb()
        dn = ldb.Dn(l, 'a=b')
        m = ldb.Message(dn)
        self.assertRaises(TypeError, l.add, '<bad type>')
        self.assertRaises(TypeError, l.add, m, '<bad type>')

    def test_delete(self):
        l = ldb.Ldb()
        dn = ldb.Dn(l, 'a=b')
        self.assertRaises(TypeError, l.add, '<bad type>')
        self.assertRaises(TypeError, l.add, dn, '<bad type>')

    def test_rename(self):
        l = ldb.Ldb()
        dn = ldb.Dn(l, 'a=b')
        self.assertRaises(TypeError, l.add, '<bad type>', dn)
        self.assertRaises(TypeError, l.add, dn, '<bad type>')
        self.assertRaises(TypeError, l.add, dn, dn, '<bad type>')

    def test_search(self):
        l = ldb.Ldb()
        self.assertRaises(TypeError, l.search, base=1234)
        self.assertRaises(TypeError, l.search, scope='<bad type>')
        self.assertRaises(TypeError, l.search, expression=1234)
        self.assertRaises(TypeError, l.search, attrs='<bad type>')
        self.assertRaises(TypeError, l.search, controls='<bad type>')


class VersionTests(TestCase):

    def test_version(self):
        self.assertTrue(isinstance(ldb.__version__, str))


if __name__ == '__main__':
    import unittest
    unittest.TestProgram()
