#!/usr/bin/env python
# Simple tests for the ldb python bindings.
# Copyright (C) 2007 Jelmer Vernooij <jelmer@samba.org>

import os
from unittest import TestCase
import sys
import gc
import time
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


class NoContextTests(TestCase):

    def test_valid_attr_name(self):
        self.assertTrue(ldb.valid_attr_name("foo"))
        self.assertFalse(ldb.valid_attr_name("24foo"))

    def test_timestring(self):
        self.assertEqual("19700101000000.0Z", ldb.timestring(0))
        self.assertEqual("20071119191012.0Z", ldb.timestring(1195499412))

    def test_string_to_time(self):
        self.assertEqual(0, ldb.string_to_time("19700101000000.0Z"))
        self.assertEqual(1195499412, ldb.string_to_time("20071119191012.0Z"))

    def test_binary_encode(self):
        encoded = ldb.binary_encode(b'test\\x')
        decoded = ldb.binary_decode(encoded)
        self.assertEqual(decoded, b'test\\x')

        encoded2 = ldb.binary_encode('test\\x')
        self.assertEqual(encoded2, encoded)


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


class SimpleLdb(LdbBaseTest):

    def setUp(self):
        super(SimpleLdb, self).setUp()
        self.testdir = tempdir()
        self.filename = os.path.join(self.testdir, "test.ldb")
        self.ldb = ldb.Ldb(self.url(), flags=self.flags())

    def tearDown(self):
        shutil.rmtree(self.testdir)
        super(SimpleLdb, self).tearDown()
        # Ensure the LDB is closed now, so we close the FD
        del(self.ldb)

    def test_connect(self):
        ldb.Ldb(self.url(), flags=self.flags())

    def test_connect_none(self):
        ldb.Ldb()

    def test_connect_later(self):
        x = ldb.Ldb()
        x.connect(self.url(), flags=self.flags())

    def test_repr(self):
        x = ldb.Ldb()
        self.assertTrue(repr(x).startswith("<ldb connection"))

    def test_set_create_perms(self):
        x = ldb.Ldb()
        x.set_create_perms(0o600)

    def test_modules_none(self):
        x = ldb.Ldb()
        self.assertEqual([], x.modules())

    def test_modules_tdb(self):
        x = ldb.Ldb(self.url(), flags=self.flags())
        self.assertEqual("[<ldb module 'tdb'>]", repr(x.modules()))

    def test_firstmodule_none(self):
        x = ldb.Ldb()
        self.assertEqual(x.firstmodule, None)

    def test_firstmodule_tdb(self):
        x = ldb.Ldb(self.url(), flags=self.flags())
        mod = x.firstmodule
        self.assertEqual(repr(mod), "<ldb module 'tdb'>")

    def test_search(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        self.assertEqual(len(l.search()), 0)

    def test_search_controls(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        self.assertEqual(len(l.search(controls=["paged_results:0:5"])), 0)

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
        l.set_opaque("my_opaque", l)
        self.assertTrue(l.get_opaque("my_opaque") is not None)
        self.assertEqual(None, l.get_opaque("unknown"))

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
        self.assertRaises(ldb.LdbError, lambda: l.add(m,["search_options:1:2"]))

    def test_add_dict(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        m = {"dn": ldb.Dn(l, "dc=foo5"),
             "bla": b"bla"}
        self.assertEqual(len(l.search()), 0)
        l.add(m)
        try:
            self.assertEqual(len(l.search()), 1)
        finally:
            l.delete(ldb.Dn(l, "dc=foo5"))

    def test_add_dict_text(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        m = {"dn": ldb.Dn(l, "dc=foo5"),
             "bla": "bla"}
        self.assertEqual(len(l.search()), 0)
        l.add(m)
        try:
            self.assertEqual(len(l.search()), 1)
        finally:
            l.delete(ldb.Dn(l, "dc=foo5"))

    def test_add_dict_string_dn(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        m = {"dn": "dc=foo6", "bla": b"bla"}
        self.assertEqual(len(l.search()), 0)
        l.add(m)
        try:
            self.assertEqual(len(l.search()), 1)
        finally:
            l.delete(ldb.Dn(l, "dc=foo6"))

    def test_add_dict_bytes_dn(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        m = {"dn": b"dc=foo6", "bla": b"bla"}
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
        self.assertEqual(len(l.search()), 0)
        l.add(m)
        self.assertEqual(len(l.search()), 1)
        try:
            l.rename("dc=foo8", "dc=bar")
            self.assertEqual(len(l.search()), 1)
        finally:
            l.delete(ldb.Dn(l, "dc=bar"))

    def test_empty_dn(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        self.assertEqual(0, len(l.search()))
        m = ldb.Message()
        m.dn = ldb.Dn(l, "dc=empty")
        l.add(m)
        rm = l.search()
        self.assertEqual(1, len(rm))
        self.assertEqual(set(["dn", "distinguishedName"]), set(rm[0].keys()))

        rm = l.search(m.dn)
        self.assertEqual(1, len(rm))
        self.assertEqual(set(["dn", "distinguishedName"]), set(rm[0].keys()))
        rm = l.search(m.dn, attrs=["blah"])
        self.assertEqual(1, len(rm))
        self.assertEqual(0, len(rm[0]))

    def test_modify_delete(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        m = ldb.Message()
        m.dn = ldb.Dn(l, "dc=modifydelete")
        m["bla"] = [b"1234"]
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
            self.assertEqual(set(["dn", "distinguishedName"]), set(rm[0].keys()))
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
            self.assertEqual(set(["dn", "distinguishedName"]), set(rm[0].keys()))
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
        l.add(m)
        try:
            m = ldb.Message()
            m.dn = ldb.Dn(l, "dc=add")
            m["bla"] = ldb.MessageElement([b"456"], ldb.FLAG_MOD_ADD, "bla")
            self.assertEqual(ldb.FLAG_MOD_ADD, m["bla"].flags())
            l.modify(m)
            rm = l.search(m.dn)[0]
            self.assertEqual(2, len(rm))
            self.assertEqual([b"1234", b"456"], list(rm["bla"]))
        finally:
            l.delete(ldb.Dn(l, "dc=add"))

    def test_modify_add_text(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        m = ldb.Message()
        m.dn = ldb.Dn(l, "dc=add")
        m.text["bla"] = ["1234"]
        l.add(m)
        try:
            m = ldb.Message()
            m.dn = ldb.Dn(l, "dc=add")
            m["bla"] = ldb.MessageElement(["456"], ldb.FLAG_MOD_ADD, "bla")
            self.assertEqual(ldb.FLAG_MOD_ADD, m["bla"].flags())
            l.modify(m)
            rm = l.search(m.dn)[0]
            self.assertEqual(2, len(rm))
            self.assertEqual(["1234", "456"], list(rm.text["bla"]))
        finally:
            l.delete(ldb.Dn(l, "dc=add"))

    def test_modify_replace(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        m = ldb.Message()
        m.dn = ldb.Dn(l, "dc=modify2")
        m["bla"] = [b"1234", b"456"]
        l.add(m)
        try:
            m = ldb.Message()
            m.dn = ldb.Dn(l, "dc=modify2")
            m["bla"] = ldb.MessageElement([b"789"], ldb.FLAG_MOD_REPLACE, "bla")
            self.assertEqual(ldb.FLAG_MOD_REPLACE, m["bla"].flags())
            l.modify(m)
            rm = l.search(m.dn)[0]
            self.assertEqual(2, len(rm))
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
        l.add(m)
        try:
            m = ldb.Message()
            m.dn = ldb.Dn(l, "dc=modify2")
            m["bla"] = ldb.MessageElement(["789"], ldb.FLAG_MOD_REPLACE, "bla")
            self.assertEqual(ldb.FLAG_MOD_REPLACE, m["bla"].flags())
            l.modify(m)
            rm = l.search(m.dn)[0]
            self.assertEqual(2, len(rm))
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
        l.add(m)
        try:
            m = ldb.Message()
            m.dn = ldb.Dn(l, "dc=add")
            m["bla"] = ldb.MessageElement([b"456"], ldb.FLAG_MOD_ADD, "bla")
            self.assertEqual(ldb.FLAG_MOD_ADD, m["bla"].flags())
            l.modify(m)
            rm = l.search(m.dn)[0]
            self.assertEqual(2, len(rm))
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
        l.add(m)
        try:
            m = ldb.Message()
            m.dn = ldb.Dn(l, "dc=add")
            m["bla"] = ldb.MessageElement(["456"], ldb.FLAG_MOD_ADD, "bla")
            self.assertEqual(ldb.FLAG_MOD_ADD, m["bla"].flags())
            l.modify(m)
            rm = l.search(m.dn)[0]
            self.assertEqual(2, len(rm))
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
        l.add(m)
        l.transaction_commit()
        l.delete(m.dn)

    def test_transaction_cancel(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        l.transaction_start()
        m = ldb.Message(ldb.Dn(l, "dc=foo10"))
        m["foo"] = [b"bar"]
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
            "dn" : b"dc=somedn",
            "objectclass" : b"user",
            "cN" : b"LDAPtestUSER",
            "givenname" : b"ldap",
            "displayname" : b"foo\0bar",
        })
        res = l.search(expression="(dn=dc=somedn)")
        self.assertEqual(b"foo\0bar", res[0]["displayname"][0])

    def test_no_crash_broken_expr(self):
        l = ldb.Ldb(self.url(), flags=self.flags())
        self.assertRaises(ldb.LdbError,lambda: l.search("", ldb.SCOPE_SUBTREE, "&(dc=*)(dn=*)", ["dc"]))

class SearchTests(LdbBaseTest):
    def tearDown(self):
        shutil.rmtree(self.testdir)
        super(SearchTests, self).tearDown()

        # Ensure the LDB is closed now, so we close the FD
        del(self.l)


    def setUp(self):
        super(SearchTests, self).setUp()
        self.testdir = tempdir()
        self.filename = os.path.join(self.testdir, "search_test.ldb")
        self.l = ldb.Ldb(self.url(),
                         flags=self.flags(),
                         options=["modules:rdn_name"])

        self.l.add({"dn": "@ATTRIBUTES",
                    "DC": "CASE_INSENSITIVE"})

        # Note that we can't use the name objectGUID here, as we
        # want to stay clear of the objectGUID handler in LDB and
        # instead use just the 16 bytes raw, which we just keep
        # to printable chars here for ease of handling.

        self.l.add({"dn": "DC=SAMBA,DC=ORG",
                    "name": b"samba.org",
                    "objectUUID": b"0123456789abcddf"})
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
           (hasattr(self, 'IDXGUID') or \
            ((hasattr(self, 'IDXONE') == False and hasattr(self, 'IDX')))):
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


class IndexedSearchTests(SearchTests):
    """Test searches using the index, to ensure the index doesn't
       break things"""
    def setUp(self):
        super(IndexedSearchTests, self).setUp()
        self.l.add({"dn": "@INDEXLIST",
                    "@IDXATTR": [b"x", b"y", b"ou"]})
        self.IDX = True

class IndexedSearchDnFilterTests(SearchTests):
    """Test searches using the index, to ensure the index doesn't
       break things"""
    def setUp(self):
        super(IndexedSearchDnFilterTests, self).setUp()
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
        super(IndexedAndOneLevelSearchTests, self).setUp()
        self.l.add({"dn": "@INDEXLIST",
                    "@IDXATTR": [b"x", b"y", b"ou"],
                    "@IDXONE": [b"1"]})
        self.IDX = True

class IndexedAndOneLevelDNFilterSearchTests(SearchTests):
    """Test searches using the index including @IDXONE, to ensure
       the index doesn't break things"""
    def setUp(self):
        super(IndexedAndOneLevelDNFilterSearchTests, self).setUp()
        self.l.add({"dn": "@OPTIONS",
                    "disallowDNFilter": "TRUE"})
        self.disallowDNFilter = True

        self.l.add({"dn": "@INDEXLIST",
                    "@IDXATTR": [b"x", b"y", b"ou"],
                    "@IDXONE": [b"1"]})
        self.IDX = True
        self.IDXONE = True

class GUIDIndexedSearchTests(SearchTests):
    """Test searches using the index, to ensure the index doesn't
       break things"""
    def setUp(self):
        super(GUIDIndexedSearchTests, self).setUp()

        self.l.add({"dn": "@INDEXLIST",
                    "@IDXATTR": [b"x", b"y", b"ou"],
                    "@IDXGUID": [b"objectUUID"],
                    "@IDX_DN_GUID": [b"GUID"]})
        self.IDXGUID = True
        self.IDXONE = True


class GUIDIndexedDNFilterSearchTests(SearchTests):
    """Test searches using the index, to ensure the index doesn't
       break things"""
    def setUp(self):
        super(GUIDIndexedDNFilterSearchTests, self).setUp()
        self.l.add({"dn": "@OPTIONS",
                    "disallowDNFilter": "TRUE"})
        self.disallowDNFilter = True

        self.l.add({"dn": "@INDEXLIST",
                    "@IDXATTR": [b"x", b"y", b"ou"],
                    "@IDXGUID": [b"objectUUID"],
                    "@IDX_DN_GUID": [b"GUID"]})
        self.IDX = True
        self.IDXGUID = True

class GUIDAndOneLevelIndexedSearchTests(SearchTests):
    """Test searches using the index including @IDXONE, to ensure
       the index doesn't break things"""
    def setUp(self):
        super(GUIDAndOneLevelIndexedSearchTests, self).setUp()
        self.l.add({"dn": "@OPTIONS",
                    "disallowDNFilter": "TRUE"})
        self.disallowDNFilter = True

        self.l.add({"dn": "@INDEXLIST",
                    "@IDXATTR": [b"x", b"y", b"ou"],
                    "@IDXONE": [b"1"],
                    "@IDXGUID": [b"objectUUID"],
                    "@IDX_DN_GUID": [b"GUID"]})
        self.IDX = True
        self.IDXGUID = True
        self.IDXONE = True


class AddModifyTests(LdbBaseTest):
    def tearDown(self):
        shutil.rmtree(self.testdir)
        super(AddModifyTests, self).tearDown()

        # Ensure the LDB is closed now, so we close the FD
        del(self.l)

    def setUp(self):
        super(AddModifyTests, self).setUp()
        self.testdir = tempdir()
        self.filename = os.path.join(self.testdir, "add_test.ldb")
        self.l = ldb.Ldb(self.url(),
                         flags=self.flags(),
                         options=["modules:rdn_name"])
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
            self.fail("Should have failed adding dupliate entry")
        except ldb.LdbError as err:
            enum = err.args[0]
            self.assertEqual(enum, ldb.ERR_ENTRY_ALREADY_EXISTS)

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


class IndexedAddModifyTests(AddModifyTests):
    """Test searches using the index, to ensure the index doesn't
       break things"""
    def setUp(self):
        super(IndexedAddModifyTests, self).setUp()
        self.l.add({"dn": "@INDEXLIST",
                    "@IDXATTR": [b"x", b"y", b"ou", b"objectUUID"],
                    "@IDXONE": [b"1"]})

    def test_duplicate_GUID(self):
        try:
            self.l.add({"dn": "OU=DUPGUID,DC=SAMBA,DC=ORG",
                        "name": b"Admins",
                        "x": "z", "y": "a",
                        "objectUUID": b"0123456789abcdef"})
            self.fail("Should have failed adding dupliate GUID")
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
            self.fail("Should have failed adding dupliate GUID")
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
            self.fail("Should have failed adding dupliate DN")
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

class GUIDIndexedAddModifyTests(IndexedAddModifyTests):
    """Test searches using the index, to ensure the index doesn't
       break things"""
    def setUp(self):
        super(GUIDIndexedAddModifyTests, self).setUp()
        indexlist = {"dn": "@INDEXLIST",
                     "@IDXATTR": [b"x", b"y", b"ou"],
                     "@IDXONE": [b"1"],
                     "@IDXGUID": [b"objectUUID"],
                     "@IDX_DN_GUID": [b"GUID"]}
        m = ldb.Message.from_dict(self.l, indexlist, ldb.FLAG_MOD_REPLACE)
        self.l.modify(m)


class GUIDTransIndexedAddModifyTests(GUIDIndexedAddModifyTests):
    """Test GUID index behaviour insdie the transaction"""
    def setUp(self):
        super(GUIDTransIndexedAddModifyTests, self).setUp()
        self.l.transaction_start()

    def tearDown(self):
        self.l.transaction_commit()
        super(GUIDTransIndexedAddModifyTests, self).tearDown()

class TransIndexedAddModifyTests(IndexedAddModifyTests):
    """Test index behaviour insdie the transaction"""
    def setUp(self):
        super(TransIndexedAddModifyTests, self).setUp()
        self.l.transaction_start()

    def tearDown(self):
        self.l.transaction_commit()
        super(TransIndexedAddModifyTests, self).tearDown()


class DnTests(TestCase):

    def setUp(self):
        super(DnTests, self).setUp()
        self.ldb = ldb.Ldb()

    def tearDown(self):
        super(DnTests, self).tearDown()
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

    def test_get_casefold(self):
        x = ldb.Dn(self.ldb, "dc=foo14,bar=bloe")
        self.assertEqual(x.get_casefold(), "DC=FOO14,BAR=bloe")

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
        x.remove_base_components(len(x)-1)
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
        super(LdbMsgTests, self).setUp()
        self.msg = ldb.Message()

    def test_init_dn(self):
        self.msg = ldb.Message(ldb.Dn(ldb.Ldb(), "dc=foo27"))
        self.assertEqual("dc=foo27", str(self.msg.dn))

    def test_iter_items(self):
        self.assertEqual(0, len(self.msg.items()))
        self.msg.dn = ldb.Dn(ldb.Ldb(), "dc=foo28")
        self.assertEqual(1, len(self.msg.items()))

    def test_repr(self):
        self.msg.dn = ldb.Dn(ldb.Ldb(), "dc=foo29")
        self.msg["dc"] = b"foo"
        if PY3:
            self.assertIn(repr(self.msg), [
                "Message({'dn': Dn('dc=foo29'), 'dc': MessageElement([b'foo'])})",
                "Message({'dc': MessageElement([b'foo']), 'dn': Dn('dc=foo29')})",
            ])
            self.assertIn(repr(self.msg.text), [
                "Message({'dn': Dn('dc=foo29'), 'dc': MessageElement([b'foo'])}).text",
                "Message({'dc': MessageElement([b'foo']), 'dn': Dn('dc=foo29')}).text",
            ])
        else:
            self.assertEqual(
                repr(self.msg),
                "Message({'dn': Dn('dc=foo29'), 'dc': MessageElement(['foo'])})")
            self.assertEqual(
                repr(self.msg.text),
                "Message({'dn': Dn('dc=foo29'), 'dc': MessageElement(['foo'])}).text")

    def test_len(self):
        self.assertEqual(0, len(self.msg))

    def test_notpresent(self):
        self.assertRaises(KeyError, lambda: self.msg["foo"])

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
        self.assertEqual(["dn", "foo", "bar"], self.msg.keys())

    def test_keys_text(self):
        self.msg.dn = ldb.Dn(ldb.Ldb(), "@BASEINFO")
        self.msg["foo"] = ["bla"]
        self.msg["bar"] = ["bla"]
        self.assertEqual(["dn", "foo", "bar"], self.msg.text.keys())

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
        if PY3:
            self.assertEqual("MessageElement([b'foo'])", repr(x))
            self.assertEqual("MessageElement([b'foo']).text", repr(x.text))
        else:
            self.assertEqual("MessageElement(['foo'])", repr(x))
            self.assertEqual("MessageElement(['foo']).text", repr(x.text))
        x = ldb.MessageElement([b"foo", b"bla"])
        self.assertEqual(2, len(x))
        if PY3:
            self.assertEqual("MessageElement([b'foo',b'bla'])", repr(x))
            self.assertEqual("MessageElement([b'foo',b'bla']).text", repr(x.text))
        else:
            self.assertEqual("MessageElement(['foo','bla'])", repr(x))
            self.assertEqual("MessageElement(['foo','bla']).text", repr(x.text))

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
        if PY3:
            self.assertEqual("MessageElement([b'456'])", repr(el))
            self.assertEqual("MessageElement([b'456']).text", repr(el.text))
        else:
            self.assertEqual("MessageElement(['456'])", repr(el))
            self.assertEqual("MessageElement(['456']).text", repr(el.text))

    def test_bad_text(self):
        el = ldb.MessageElement(b'\xba\xdd')
        self.assertRaises(UnicodeDecodeError, el.text.__getitem__, 0)


class ModuleTests(TestCase):

    def setUp(self):
        super(ModuleTests, self).setUp()
        self.testdir = tempdir()
        self.filename = os.path.join(self.testdir, "test.ldb")
        self.ldb = ldb.Ldb(self.filename)

    def tearDown(self):
        shutil.rmtree(self.testdir)
        super(ModuleTests, self).setUp()

    def test_register_module(self):
        class ExampleModule:
            name = "example"
        ldb.register_module(ExampleModule)

    def test_use_module(self):
        ops = []
        class ExampleModule:
            name = "bla"

            def __init__(self, ldb, next):
                ops.append("init")
                self.next = next

            def search(self, *args, **kwargs):
                return self.next.search(*args, **kwargs)

            def request(self, *args, **kwargs):
                pass

        ldb.register_module(ExampleModule)
        l = ldb.Ldb(self.filename)
        l.add({"dn": "@MODULES", "@LIST": "bla"})
        self.assertEqual([], ops)
        l = ldb.Ldb(self.filename)
        self.assertEqual(["init"], ops)

class LdbResultTests(LdbBaseTest):

    def setUp(self):
        super(LdbResultTests, self).setUp()
        self.testdir = tempdir()
        self.filename = os.path.join(self.testdir, "test.ldb")
        self.l = ldb.Ldb(self.url(), flags=self.flags())
        self.l.add({"dn": "DC=SAMBA,DC=ORG", "name": b"samba.org"})
        self.l.add({"dn": "OU=ADMIN,DC=SAMBA,DC=ORG", "name": b"Admins"})
        self.l.add({"dn": "OU=USERS,DC=SAMBA,DC=ORG", "name": b"Users"})
        self.l.add({"dn": "OU=OU1,DC=SAMBA,DC=ORG", "name": b"OU #1"})
        self.l.add({"dn": "OU=OU2,DC=SAMBA,DC=ORG", "name": b"OU #2"})
        self.l.add({"dn": "OU=OU3,DC=SAMBA,DC=ORG", "name": b"OU #3"})
        self.l.add({"dn": "OU=OU4,DC=SAMBA,DC=ORG", "name": b"OU #4"})
        self.l.add({"dn": "OU=OU5,DC=SAMBA,DC=ORG", "name": b"OU #5"})
        self.l.add({"dn": "OU=OU6,DC=SAMBA,DC=ORG", "name": b"OU #6"})
        self.l.add({"dn": "OU=OU7,DC=SAMBA,DC=ORG", "name": b"OU #7"})
        self.l.add({"dn": "OU=OU8,DC=SAMBA,DC=ORG", "name": b"OU #8"})
        self.l.add({"dn": "OU=OU9,DC=SAMBA,DC=ORG", "name": b"OU #9"})
        self.l.add({"dn": "OU=OU10,DC=SAMBA,DC=ORG", "name": b"OU #10"})

    def tearDown(self):
        shutil.rmtree(self.testdir)
        super(LdbResultTests, self).tearDown()
        # Ensure the LDB is closed now, so we close the FD
        del(self.l)

    def test_return_type(self):
        res = self.l.search()
        self.assertEqual(str(res), "<ldb result>")

    def test_get_msgs(self):
        res = self.l.search()
        list = res.msgs

    def test_get_controls(self):
        res = self.l.search()
        list = res.controls

    def test_get_referals(self):
        res = self.l.search()
        list = res.referals

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
                           "name": b"samba.org"})

            os.write(w1, b"added")

            # Now wait for the search to be done
            os.read(r2, 6)

            # and commit
            try:
                child_ldb.transaction_commit()
            except LdbError as err:
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
                           "name": b"samba.org"})

            os.write(w1, b"added")

            # Now wait for the search to be done
            os.read(r2, 6)

            # and commit
            try:
                child_ldb.transaction_commit()
            except LdbError as err:
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
