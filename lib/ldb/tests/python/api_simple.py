#!/usr/bin/env python3
# Simple tests for the ldb python bindings.
# Copyright (C) 2007 Jelmer Vernooij <jelmer@samba.org>

import os
import sys
sys.path.insert(0, "bin/python")
from api_base import (
    MDB_PREFIX,
    MDB_INDEX_OBJ,
    tempdir,
    LdbBaseTest
)

import ldb
import shutil


class SimpleLdb(LdbBaseTest):

    def setUp(self):
        super().setUp()
        self.testdir = tempdir()
        self.filename = os.path.join(self.testdir, "test.ldb")
        self.ldb = ldb.Ldb(self.url(), flags=self.flags())
        try:
            self.ldb.add(self.index)
        except AttributeError:
            pass

    def tearDown(self):
        self.ldb.disconnect()
        shutil.rmtree(self.testdir)
        super().tearDown()
        # Ensure the LDB is closed now, so we close the FD

    def test_connect(self):
        ldb.Ldb(self.url(), flags=self.flags())

    def test_connect_none(self):
        ldb.Ldb()

    def test_connect_later(self):
        x = ldb.Ldb()
        x.connect(self.url(), flags=self.flags())

    def test_connect_twice(self):
        url = self.url()
        x = ldb.Ldb(url)
        with self.assertRaises(ldb.LdbError):
            x.connect(url, flags=self.flags())

    def test_connect_twice_later(self):
        url = self.url()
        flags = self.flags()
        x = ldb.Ldb()
        x.connect(url, flags)
        with self.assertRaises(ldb.LdbError):
            x.connect(url, flags)

    def test_connect_and_disconnect(self):
        url = self.url()
        flags = self.flags()
        x = ldb.Ldb()
        x.connect(url, flags)
        x.disconnect()
        x.connect(url, flags)
        x.disconnect()

    def test_repr(self):
        x = ldb.Ldb()
        self.assertTrue(repr(x).startswith("<ldb connection"))

    def test_set_create_perms(self):
        x = ldb.Ldb()
        x.set_create_perms(0o600)

    def test_search(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        self.assertEqual(len(l.search()), 0)

    def test_search_controls(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        self.assertEqual(len(l.search(controls=["paged_results:0:5"])), 0)

    def test_utf8_ldb_Dn(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        dn = ldb.Dn(l, (b'a=' + b'\xc4\x85\xc4\x87\xc4\x99\xc5\x82\xc5\x84\xc3\xb3\xc5\x9b\xc5\xba\xc5\xbc').decode('utf8'))

    def test_utf8_encoded_ldb_Dn(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        dn_encoded_utf8 = b'a=' + b'\xc4\x85\xc4\x87\xc4\x99\xc5\x82\xc5\x84\xc3\xb3\xc5\x9b\xc5\xba\xc5\xbc'
        try:
            dn = ldb.Dn(l, dn_encoded_utf8)
        except UnicodeDecodeError as e:
                raise
        except TypeError as te:
            p3errors = ["argument 2 must be str, not bytes",
                        "Can't convert 'bytes' object to str implicitly"]
            self.assertIn(str(te), p3errors)

    def test_search_attrs(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        self.assertEqual(len(l.search(ldb.Dn(l, ""), ldb.SCOPE_SUBTREE, "(dc=*)", ["dc"])), 0)

    def test_search_string_dn(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        self.assertEqual(len(l.search("", ldb.SCOPE_SUBTREE, "(dc=*)", ["dc"])), 0)

    def test_search_attr_string(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        self.assertRaises(TypeError, l.search, attrs="dc")
        self.assertRaises(TypeError, l.search, attrs=b"dc")

    def test_opaque(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        l.set_opaque("my_opaque", True)
        self.assertTrue(l.get_opaque("my_opaque") is not None)
        self.assertEqual(None, l.get_opaque("unknown"))

    def test_opaque_bool(self):
        """Test that we can set boolean opaque values."""

        db = ldb.Ldb(self.url(), flags=self.flags())
        name = "my_opaque"

        db.set_opaque(name, False)
        self.assertEqual(False, db.get_opaque(name))

        db.set_opaque(name, True)
        self.assertEqual(True, db.get_opaque(name))

    def test_opaque_int(self):
        """Test that we can set (positive) integer opaque values."""

        db = ldb.Ldb(self.url(), flags=self.flags())
        name = "my_opaque"

        db.set_opaque(name, 0)
        self.assertEqual(0, db.get_opaque(name))

        db.set_opaque(name, 12345678)
        self.assertEqual(12345678, db.get_opaque(name))

        # Negative values can’t be set.
        self.assertRaises(OverflowError, db.set_opaque, name, -99999)

    def test_opaque_string(self):
        """Test that we can set string opaque values."""

        db = ldb.Ldb(self.url(), flags=self.flags())
        name = "my_opaque"

        db.set_opaque(name, "")
        self.assertEqual("", db.get_opaque(name))

        db.set_opaque(name, "foo bar")
        self.assertEqual("foo bar", db.get_opaque(name))

    def test_opaque_none(self):
        """Test that we can set an opaque to None to effectively unset it."""

        db = ldb.Ldb(self.url(), flags=self.flags())
        name = "my_opaque"

        # An opaque that has not been set is the same as None.
        self.assertIsNone(db.get_opaque(name))

        # Give the opaque a value.
        db.set_opaque(name, 3)
        self.assertEqual(3, db.get_opaque(name))

        # Test that we can set the opaque to None to unset it.
        db.set_opaque(name, None)
        self.assertIsNone(db.get_opaque(name))

    def test_opaque_unsupported(self):
        """Test that trying to set unsupported values raises an error."""

        db = ldb.Ldb(self.url(), flags=self.flags())
        name = "my_opaque"

        self.assertRaises(ValueError, db.set_opaque, name, [])
        self.assertRaises(ValueError, db.set_opaque, name, ())
        self.assertRaises(ValueError, db.set_opaque, name, 3.14)
        self.assertRaises(ValueError, db.set_opaque, name, 3+2j)
        self.assertRaises(ValueError, db.set_opaque, name, b'foo')

    def test_search_scope_base_empty_db(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        self.assertEqual(len(l.search(ldb.Dn(l, "dc=foo1"),
                                      ldb.SCOPE_BASE)), 0)

    def test_search_scope_onelevel_empty_db(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        self.assertEqual(len(l.search(ldb.Dn(l, "dc=foo1"),
                                      ldb.SCOPE_ONELEVEL)), 0)

    def test_delete(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        self.assertRaises(ldb.LdbError, lambda: l.delete(ldb.Dn(l, "dc=foo2")))

    def test_delete_w_unhandled_ctrl(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        m = ldb.Message()
        m.dn = ldb.Dn(l, "dc=foo1")
        m["b"] = [b"a"]
        m["objectUUID"] = b"0123456789abcdef"
        l.add(m)
        self.assertRaises(ldb.LdbError, lambda: l.delete(m.dn, ["search_options:1:2"]))
        l.delete(m.dn)

    def test_contains(self):
        name = self.url()
        l = ldb.Ldb(name, flags=self.flags())
        self.assertFalse(ldb.Dn(l, "dc=foo3") in l)
        l = ldb.Ldb(name, flags=self.flags())
        m = ldb.Message()
        m.dn = ldb.Dn(l, "dc=foo3")
        m["b"] = ["a"]
        m["objectUUID"] = b"0123456789abcdef"
        l.add(m)
        try:
            self.assertTrue(ldb.Dn(l, "dc=foo3") in l)
            self.assertFalse(ldb.Dn(l, "dc=foo4") in l)
        finally:
            l.delete(m.dn)

    def test_get_config_basedn(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        self.assertEqual(None, l.get_config_basedn())

    def test_get_root_basedn(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        self.assertEqual(None, l.get_root_basedn())

    def test_get_schema_basedn(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        self.assertEqual(None, l.get_schema_basedn())

    def test_get_default_basedn(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        self.assertEqual(None, l.get_default_basedn())

    def test_add(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        m = ldb.Message()
        m.dn = ldb.Dn(l, "dc=foo4")
        m["bla"] = b"bla"
        m["objectUUID"] = b"0123456789abcdef"
        self.assertEqual(len(l.search()), 0)
        l.add(m)
        try:
            self.assertEqual(len(l.search()), 1)
        finally:
            l.delete(ldb.Dn(l, "dc=foo4"))

    def test_search_iterator(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        s = l.search_iterator()
        s.abandon()
        try:
            for me in s:
                self.fail()
            self.fail()
        except RuntimeError as re:
            pass
        try:
            s.abandon()
            self.fail()
        except RuntimeError as re:
            pass
        try:
            s.result()
            self.fail()
        except RuntimeError as re:
            pass

        s = l.search_iterator()
        count = 0
        for me in s:
            self.assertTrue(isinstance(me, ldb.Message))
            count += 1
        r = s.result()
        self.assertEqual(len(r), 0)
        self.assertEqual(count, 0)

        m1 = ldb.Message()
        m1.dn = ldb.Dn(l, "dc=foo4")
        m1["bla"] = b"bla"
        m1["objectUUID"] = b"0123456789abcdef"
        l.add(m1)
        try:
            s = l.search_iterator()
            msgs = []
            for me in s:
                self.assertTrue(isinstance(me, ldb.Message))
                count += 1
                msgs.append(me)
            r = s.result()
            self.assertEqual(len(r), 0)
            self.assertEqual(len(msgs), 1)
            self.assertEqual(msgs[0].dn, m1.dn)

            m2 = ldb.Message()
            m2.dn = ldb.Dn(l, "dc=foo5")
            m2["bla"] = b"bla"
            m2["objectUUID"] = b"0123456789abcdee"
            l.add(m2)

            s = l.search_iterator()
            msgs = []
            for me in s:
                self.assertTrue(isinstance(me, ldb.Message))
                count += 1
                msgs.append(me)
            r = s.result()
            self.assertEqual(len(r), 0)
            self.assertEqual(len(msgs), 2)
            if msgs[0].dn == m1.dn:
                self.assertEqual(msgs[0].dn, m1.dn)
                self.assertEqual(msgs[1].dn, m2.dn)
            else:
                self.assertEqual(msgs[0].dn, m2.dn)
                self.assertEqual(msgs[1].dn, m1.dn)

            s = l.search_iterator()
            msgs = []
            for me in s:
                self.assertTrue(isinstance(me, ldb.Message))
                count += 1
                msgs.append(me)
                break
            try:
                s.result()
                self.fail()
            except RuntimeError as re:
                pass
            for me in s:
                self.assertTrue(isinstance(me, ldb.Message))
                count += 1
                msgs.append(me)
                break
            for me in s:
                self.fail()

            r = s.result()
            self.assertEqual(len(r), 0)
            self.assertEqual(len(msgs), 2)
            if msgs[0].dn == m1.dn:
                self.assertEqual(msgs[0].dn, m1.dn)
                self.assertEqual(msgs[1].dn, m2.dn)
            else:
                self.assertEqual(msgs[0].dn, m2.dn)
                self.assertEqual(msgs[1].dn, m1.dn)
        finally:
            l.delete(ldb.Dn(l, "dc=foo4"))
            l.delete(ldb.Dn(l, "dc=foo5"))

    def test_add_text(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        m = ldb.Message()
        m.dn = ldb.Dn(l, "dc=foo4")
        m["bla"] = "bla"
        m["objectUUID"] = b"0123456789abcdef"
        self.assertEqual(len(l.search()), 0)
        l.add(m)
        try:
            self.assertEqual(len(l.search()), 1)
        finally:
            l.delete(ldb.Dn(l, "dc=foo4"))

    def test_add_w_unhandled_ctrl(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        m = ldb.Message()
        m.dn = ldb.Dn(l, "dc=foo4")
        m["bla"] = b"bla"
        self.assertEqual(len(l.search()), 0)
        self.assertRaises(ldb.LdbError, lambda: l.add(m, ["search_options:1:2"]))

    def test_add_dict(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        m = {"dn": ldb.Dn(l, "dc=foo5"),
             "bla": b"bla",
             "objectUUID": b"0123456789abcdef"}
        self.assertEqual(len(l.search()), 0)
        l.add(m)
        try:
            self.assertEqual(len(l.search()), 1)
        finally:
            l.delete(ldb.Dn(l, "dc=foo5"))

    def test_add_dict_text(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        m = {"dn": ldb.Dn(l, "dc=foo5"),
             "bla": "bla",
             "objectUUID": b"0123456789abcdef"}
        self.assertEqual(len(l.search()), 0)
        l.add(m)
        try:
            self.assertEqual(len(l.search()), 1)
        finally:
            l.delete(ldb.Dn(l, "dc=foo5"))

    def test_add_dict_string_dn(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        m = {"dn": "dc=foo6", "bla": b"bla",
             "objectUUID": b"0123456789abcdef"}
        self.assertEqual(len(l.search()), 0)
        l.add(m)
        try:
            self.assertEqual(len(l.search()), 1)
        finally:
            l.delete(ldb.Dn(l, "dc=foo6"))

    def test_add_dict_bytes_dn(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        m = {"dn": b"dc=foo6", "bla": b"bla",
             "objectUUID": b"0123456789abcdef"}
        self.assertEqual(len(l.search()), 0)
        l.add(m)
        try:
            self.assertEqual(len(l.search()), 1)
        finally:
            l.delete(ldb.Dn(l, "dc=foo6"))

    def test_rename(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        m = ldb.Message()
        m.dn = ldb.Dn(l, "dc=foo7")
        m["bla"] = b"bla"
        m["objectUUID"] = b"0123456789abcdef"
        self.assertEqual(len(l.search()), 0)
        l.add(m)
        try:
            l.rename(ldb.Dn(l, "dc=foo7"), ldb.Dn(l, "dc=bar"))
            self.assertEqual(len(l.search()), 1)
        finally:
            l.delete(ldb.Dn(l, "dc=bar"))

    def test_rename_string_dns(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        m = ldb.Message()
        m.dn = ldb.Dn(l, "dc=foo8")
        m["bla"] = b"bla"
        m["objectUUID"] = b"0123456789abcdef"
        self.assertEqual(len(l.search()), 0)
        l.add(m)
        self.assertEqual(len(l.search()), 1)
        try:
            l.rename("dc=foo8", "dc=bar")
            self.assertEqual(len(l.search()), 1)
        finally:
            l.delete(ldb.Dn(l, "dc=bar"))

    def test_rename_bad_string_dns(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        m = ldb.Message()
        m.dn = ldb.Dn(l, "dc=foo8")
        m["bla"] = b"bla"
        m["objectUUID"] = b"0123456789abcdef"
        self.assertEqual(len(l.search()), 0)
        l.add(m)
        self.assertEqual(len(l.search()), 1)
        self.assertRaises(ldb.LdbError,lambda: l.rename("dcXfoo8", "dc=bar"))
        self.assertRaises(ldb.LdbError,lambda: l.rename("dc=foo8", "dcXbar"))
        l.delete(ldb.Dn(l, "dc=foo8"))

    def test_empty_dn(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        self.assertEqual(0, len(l.search()))
        m = ldb.Message()
        m.dn = ldb.Dn(l, "dc=empty")
        m["objectUUID"] = b"0123456789abcdef"
        l.add(m)
        rm = l.search()
        self.assertEqual(1, len(rm))
        self.assertEqual(set(["dn", "distinguishedName", "objectUUID"]),
                         set(rm[0].keys()))

        rm = l.search(m.dn)
        self.assertEqual(1, len(rm))
        self.assertEqual(set(["dn", "distinguishedName", "objectUUID"]),
                         set(rm[0].keys()))
        rm = l.search(m.dn, attrs=["blah"])
        self.assertEqual(1, len(rm))
        self.assertEqual(0, len(rm[0]))

    def test_modify_delete(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        m = ldb.Message()
        m.dn = ldb.Dn(l, "dc=modifydelete")
        m["bla"] = [b"1234"]
        m["objectUUID"] = b"0123456789abcdef"
        l.add(m)
        rm = l.search(m.dn)[0]
        self.assertEqual([b"1234"], list(rm["bla"]))
        try:
            m = ldb.Message()
            m.dn = ldb.Dn(l, "dc=modifydelete")
            m["bla"] = ldb.MessageElement([], ldb.FLAG_MOD_DELETE, "bla")
            self.assertEqual(ldb.FLAG_MOD_DELETE, m["bla"].flags())
            l.modify(m)
            rm = l.search(m.dn)
            self.assertEqual(1, len(rm))
            self.assertEqual(set(["dn", "distinguishedName", "objectUUID"]),
                             set(rm[0].keys()))
            rm = l.search(m.dn, attrs=["bla"])
            self.assertEqual(1, len(rm))
            self.assertEqual(0, len(rm[0]))
        finally:
            l.delete(ldb.Dn(l, "dc=modifydelete"))

    def test_modify_delete_text(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        m = ldb.Message()
        m.dn = ldb.Dn(l, "dc=modifydelete")
        m.text["bla"] = ["1234"]
        m["objectUUID"] = b"0123456789abcdef"
        l.add(m)
        rm = l.search(m.dn)[0]
        self.assertEqual(["1234"], list(rm.text["bla"]))
        try:
            m = ldb.Message()
            m.dn = ldb.Dn(l, "dc=modifydelete")
            m["bla"] = ldb.MessageElement([], ldb.FLAG_MOD_DELETE, "bla")
            self.assertEqual(ldb.FLAG_MOD_DELETE, m["bla"].flags())
            l.modify(m)
            rm = l.search(m.dn)
            self.assertEqual(1, len(rm))
            self.assertEqual(set(["dn", "distinguishedName", "objectUUID"]),
                             set(rm[0].keys()))
            rm = l.search(m.dn, attrs=["bla"])
            self.assertEqual(1, len(rm))
            self.assertEqual(0, len(rm[0]))
        finally:
            l.delete(ldb.Dn(l, "dc=modifydelete"))

    def test_modify_add(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        m = ldb.Message()
        m.dn = ldb.Dn(l, "dc=add")
        m["bla"] = [b"1234"]
        m["objectUUID"] = b"0123456789abcdef"
        l.add(m)
        try:
            m = ldb.Message()
            m.dn = ldb.Dn(l, "dc=add")
            m["bla"] = ldb.MessageElement([b"456"], ldb.FLAG_MOD_ADD, "bla")
            self.assertEqual(ldb.FLAG_MOD_ADD, m["bla"].flags())
            l.modify(m)
            rm = l.search(m.dn)[0]
            self.assertEqual(3, len(rm))
            self.assertEqual([b"1234", b"456"], list(rm["bla"]))
        finally:
            l.delete(ldb.Dn(l, "dc=add"))

    def test_modify_add_text(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        m = ldb.Message()
        m.dn = ldb.Dn(l, "dc=add")
        m.text["bla"] = ["1234"]
        m["objectUUID"] = b"0123456789abcdef"
        l.add(m)
        try:
            m = ldb.Message()
            m.dn = ldb.Dn(l, "dc=add")
            m["bla"] = ldb.MessageElement(["456"], ldb.FLAG_MOD_ADD, "bla")
            self.assertEqual(ldb.FLAG_MOD_ADD, m["bla"].flags())
            l.modify(m)
            rm = l.search(m.dn)[0]
            self.assertEqual(3, len(rm))
            self.assertEqual(["1234", "456"], list(rm.text["bla"]))
        finally:
            l.delete(ldb.Dn(l, "dc=add"))

    def test_modify_replace(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        m = ldb.Message()
        m.dn = ldb.Dn(l, "dc=modify2")
        m["bla"] = [b"1234", b"456"]
        m["objectUUID"] = b"0123456789abcdef"
        l.add(m)
        try:
            m = ldb.Message()
            m.dn = ldb.Dn(l, "dc=modify2")
            m["bla"] = ldb.MessageElement([b"789"], ldb.FLAG_MOD_REPLACE, "bla")
            self.assertEqual(ldb.FLAG_MOD_REPLACE, m["bla"].flags())
            l.modify(m)
            rm = l.search(m.dn)[0]
            self.assertEqual(3, len(rm))
            self.assertEqual([b"789"], list(rm["bla"]))
            rm = l.search(m.dn, attrs=["bla"])[0]
            self.assertEqual(1, len(rm))
        finally:
            l.delete(ldb.Dn(l, "dc=modify2"))

    def test_modify_replace_text(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        m = ldb.Message()
        m.dn = ldb.Dn(l, "dc=modify2")
        m.text["bla"] = ["1234", "456"]
        m["objectUUID"] = b"0123456789abcdef"
        l.add(m)
        try:
            m = ldb.Message()
            m.dn = ldb.Dn(l, "dc=modify2")
            m["bla"] = ldb.MessageElement(["789"], ldb.FLAG_MOD_REPLACE, "bla")
            self.assertEqual(ldb.FLAG_MOD_REPLACE, m["bla"].flags())
            l.modify(m)
            rm = l.search(m.dn)[0]
            self.assertEqual(3, len(rm))
            self.assertEqual(["789"], list(rm.text["bla"]))
            rm = l.search(m.dn, attrs=["bla"])[0]
            self.assertEqual(1, len(rm))
        finally:
            l.delete(ldb.Dn(l, "dc=modify2"))

    def test_modify_flags_change(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        m = ldb.Message()
        m.dn = ldb.Dn(l, "dc=add")
        m["bla"] = [b"1234"]
        m["objectUUID"] = b"0123456789abcdef"
        l.add(m)
        try:
            m = ldb.Message()
            m.dn = ldb.Dn(l, "dc=add")
            m["bla"] = ldb.MessageElement([b"456"], ldb.FLAG_MOD_ADD, "bla")
            self.assertEqual(ldb.FLAG_MOD_ADD, m["bla"].flags())
            l.modify(m)
            rm = l.search(m.dn)[0]
            self.assertEqual(3, len(rm))
            self.assertEqual([b"1234", b"456"], list(rm["bla"]))

            # Now create another modify, but switch the flags before we do it
            m["bla"] = ldb.MessageElement([b"456"], ldb.FLAG_MOD_ADD, "bla")
            m["bla"].set_flags(ldb.FLAG_MOD_DELETE)
            l.modify(m)
            rm = l.search(m.dn, attrs=["bla"])[0]
            self.assertEqual(1, len(rm))
            self.assertEqual([b"1234"], list(rm["bla"]))
        finally:
            l.delete(ldb.Dn(l, "dc=add"))

    def test_modify_flags_change_text(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        m = ldb.Message()
        m.dn = ldb.Dn(l, "dc=add")
        m.text["bla"] = ["1234"]
        m["objectUUID"] = b"0123456789abcdef"
        l.add(m)
        try:
            m = ldb.Message()
            m.dn = ldb.Dn(l, "dc=add")
            m["bla"] = ldb.MessageElement(["456"], ldb.FLAG_MOD_ADD, "bla")
            self.assertEqual(ldb.FLAG_MOD_ADD, m["bla"].flags())
            l.modify(m)
            rm = l.search(m.dn)[0]
            self.assertEqual(3, len(rm))
            self.assertEqual(["1234", "456"], list(rm.text["bla"]))

            # Now create another modify, but switch the flags before we do it
            m["bla"] = ldb.MessageElement(["456"], ldb.FLAG_MOD_ADD, "bla")
            m["bla"].set_flags(ldb.FLAG_MOD_DELETE)
            l.modify(m)
            rm = l.search(m.dn, attrs=["bla"])[0]
            self.assertEqual(1, len(rm))
            self.assertEqual(["1234"], list(rm.text["bla"]))
        finally:
            l.delete(ldb.Dn(l, "dc=add"))

    def test_transaction_commit(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        l.transaction_start()
        m = ldb.Message(ldb.Dn(l, "dc=foo9"))
        m["foo"] = [b"bar"]
        m["objectUUID"] = b"0123456789abcdef"
        l.add(m)
        l.transaction_commit()
        l.delete(m.dn)

    def test_transaction_cancel(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        l.transaction_start()
        m = ldb.Message(ldb.Dn(l, "dc=foo10"))
        m["foo"] = [b"bar"]
        m["objectUUID"] = b"0123456789abcdee"
        l.add(m)
        l.transaction_cancel()
        self.assertEqual(0, len(l.search(ldb.Dn(l, "dc=foo10"))))

    def test_set_debug(self):
        def my_report_fn(level, text):
            pass
        l = ldb.Ldb(self.url(), flags=self.flags())
        l.set_debug(my_report_fn)

    def test_zero_byte_string(self):
        """Testing we do not get trapped in the \0 byte in a property string."""
        l = ldb.Ldb(self.url(), flags=self.flags())
        l.add({
            "dn": b"dc=somedn",
            "objectclass": b"user",
            "cN": b"LDAPtestUSER",
            "givenname": b"ldap",
            "displayname": b"foo\0bar",
            "objectUUID": b"0123456789abcdef"
        })
        res = l.search(expression="(dn=dc=somedn)")
        self.assertEqual(b"foo\0bar", res[0]["displayname"][0])

    def test_no_crash_broken_expr(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        self.assertRaises(ldb.LdbError, lambda: l.search("", ldb.SCOPE_SUBTREE, "&(dc=*)(dn=*)", ["dc"]))

# Run the SimpleLdb tests against an lmdb backend


class SimpleLdbLmdb(SimpleLdb):

    def setUp(self):
        if os.environ.get('HAVE_LMDB', '1') == '0':
            self.skipTest("No lmdb backend")
        self.prefix = MDB_PREFIX
        self.index = MDB_INDEX_OBJ
        super().setUp()


class SimpleLdbNoLmdb(LdbBaseTest):

    def setUp(self):
        if os.environ.get('HAVE_LMDB', '1') != '0':
            self.skipTest("lmdb backend enabled")
        self.prefix = MDB_PREFIX
        self.index = MDB_INDEX_OBJ
        super().setUp()

    def test_lmdb_disabled(self):
        self.testdir = tempdir()
        self.filename = os.path.join(self.testdir, "test.ldb")
        try:
            self.ldb = ldb.Ldb(self.url(), flags=self.flags())
            self.fail("Should have failed on missing LMDB")
        except ldb.LdbError as err:
            enum = err.args[0]
            self.assertEqual(enum, ldb.ERR_OTHER)


if __name__ == '__main__':
    import unittest
    unittest.TestProgram()
