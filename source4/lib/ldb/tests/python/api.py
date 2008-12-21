#!/usr/bin/python
# Simple tests for the ldb python bindings.
# Copyright (C) 2007 Jelmer Vernooij <jelmer@samba.org>

import os, sys
import unittest

# Required for the standalone LDB build
sys.path.append("build/lib.linux-i686-2.4")

import ldb

def filename():
    return os.tempnam()

class NoContextTests(unittest.TestCase):
    def test_valid_attr_name(self):
        self.assertTrue(ldb.valid_attr_name("foo"))
        self.assertFalse(ldb.valid_attr_name("24foo"))

    def test_timestring(self):
        self.assertEquals("19700101000000.0Z", ldb.timestring(0))
        self.assertEquals("20071119191012.0Z", ldb.timestring(1195499412))

    def test_string_to_time(self):
        self.assertEquals(0, ldb.string_to_time("19700101000000.0Z"))
        self.assertEquals(1195499412, ldb.string_to_time("20071119191012.0Z"))


class SimpleLdb(unittest.TestCase):
    def test_connect(self):
        ldb.Ldb(filename())

    def test_connect_none(self):
        ldb.Ldb()

    def test_connect_later(self):
        x = ldb.Ldb()
        x.connect(filename())

    def test_repr(self):
        x = ldb.Ldb()
        self.assertTrue(repr(x).startswith("<ldb connection"))

    def test_set_create_perms(self):
        x = ldb.Ldb()
        x.set_create_perms(0600)

    def test_set_modules_dir(self):
        x = ldb.Ldb()
        x.set_modules_dir("/tmp")

    def test_modules_none(self):
        x = ldb.Ldb()
        self.assertEquals([], x.modules())

    def test_modules_tdb(self):
        x = ldb.Ldb("bar.ldb")
        self.assertEquals("[<ldb module 'tdb'>]", repr(x.modules()))

    def test_search(self):
        l = ldb.Ldb(filename())
        self.assertEquals(len(l.search()), 1)

    def test_search_controls(self):
        l = ldb.Ldb(filename())
        self.assertEquals(len(l.search(controls=["paged_results:0:5"])), 1)

    def test_search_attrs(self):
        l = ldb.Ldb(filename())
        self.assertEquals(len(l.search(ldb.Dn(l, ""), ldb.SCOPE_SUBTREE, "(dc=*)", ["dc"])), 0)

    def test_search_string_dn(self):
        l = ldb.Ldb(filename())
        self.assertEquals(len(l.search("", ldb.SCOPE_SUBTREE, "(dc=*)", ["dc"])), 0)

    def test_search_attr_string(self):
        l = ldb.Ldb("foo.tdb")
        self.assertRaises(TypeError, l.search, attrs="dc")

    def test_opaque(self):
        l = ldb.Ldb(filename())
        l.set_opaque("my_opaque", l)
        self.assertTrue(l.get_opaque("my_opaque") is not None)
        self.assertEquals(None, l.get_opaque("unknown"))

    def test_search_scope_base(self):
        l = ldb.Ldb(filename())
        self.assertEquals(len(l.search(ldb.Dn(l, "dc=foo"), 
                          ldb.SCOPE_ONELEVEL)), 0)

    def test_delete(self):
        l = ldb.Ldb(filename())
        self.assertRaises(ldb.LdbError, lambda: l.delete(ldb.Dn(l, "dc=foo")))

    def test_contains(self):
        l = ldb.Ldb(filename())
        self.assertFalse(ldb.Dn(l, "dc=foo") in l)
        l = ldb.Ldb(filename())
        m = ldb.Message()
        m.dn = ldb.Dn(l, "dc=foo")
        m["b"] = ["a"]
        l.add(m)
        try:
            self.assertTrue(ldb.Dn(l, "dc=foo") in l)
        finally:
            l.delete(m.dn)

    def test_get_config_basedn(self):
        l = ldb.Ldb(filename())
        self.assertEquals(None, l.get_config_basedn())

    def test_get_root_basedn(self):
        l = ldb.Ldb(filename())
        self.assertEquals(None, l.get_root_basedn())

    def test_get_schema_basedn(self):
        l = ldb.Ldb(filename())
        self.assertEquals(None, l.get_schema_basedn())

    def test_get_default_basedn(self):
        l = ldb.Ldb(filename())
        self.assertEquals(None, l.get_default_basedn())

    def test_add(self):
        l = ldb.Ldb(filename())
        m = ldb.Message()
        m.dn = ldb.Dn(l, "dc=foo")
        m["bla"] = "bla"
        self.assertEquals(len(l.search()), 1)
        l.add(m)
        try:
            self.assertEquals(len(l.search()), 2)
        finally:
            l.delete(ldb.Dn(l, "dc=foo"))

    def test_add_dict(self):
        l = ldb.Ldb(filename())
        m = {"dn": ldb.Dn(l, "dc=foo"),
             "bla": "bla"}
        self.assertEquals(len(l.search()), 1)
        l.add(m)
        try:
            self.assertEquals(len(l.search()), 2)
        finally:
            l.delete(ldb.Dn(l, "dc=foo"))

    def test_add_dict_string_dn(self):
        l = ldb.Ldb(filename())
        m = {"dn": "dc=foo", "bla": "bla"}
        self.assertEquals(len(l.search()), 1)
        l.add(m)
        try:
            self.assertEquals(len(l.search()), 2)
        finally:
            l.delete(ldb.Dn(l, "dc=foo"))

    def test_rename(self):
        l = ldb.Ldb(filename())
        m = ldb.Message()
        m.dn = ldb.Dn(l, "dc=foo")
        m["bla"] = "bla"
        self.assertEquals(len(l.search()), 1)
        l.add(m)
        try:
            l.rename(ldb.Dn(l, "dc=foo"), ldb.Dn(l, "dc=bar"))
            self.assertEquals(len(l.search()), 2)
        finally:
            l.delete(ldb.Dn(l, "dc=bar"))

    def test_rename_string_dns(self):
        l = ldb.Ldb(filename())
        m = ldb.Message()
        m.dn = ldb.Dn(l, "dc=foo")
        m["bla"] = "bla"
        self.assertEquals(len(l.search()), 1)
        l.add(m)
        self.assertEquals(len(l.search()), 2)
        try:
            l.rename("dc=foo", "dc=bar")
            self.assertEquals(len(l.search()), 2)
        finally:
            l.delete(ldb.Dn(l, "dc=bar"))

    def test_modify_delete(self):
        l = ldb.Ldb(filename())
        m = ldb.Message()
        m.dn = ldb.Dn(l, "dc=modifydelete")
        m["bla"] = ["1234"]
        l.add(m)
        rm = l.search(m.dn)[0]
        self.assertEquals(["1234"], list(rm["bla"]))
        try:
            m = ldb.Message()
            m.dn = ldb.Dn(l, "dc=modifydelete")
            m["bla"] = ldb.MessageElement([], ldb.CHANGETYPE_DELETE, "bla")
            l.modify(m)
            rm = l.search(m.dn)[0]
            self.assertEquals(1, len(rm))
        finally:
            l.delete(ldb.Dn(l, "dc=modifydelete"))

    def test_modify_add(self):
        l = ldb.Ldb(filename())
        m = ldb.Message()
        m.dn = ldb.Dn(l, "dc=add")
        m["bla"] = ["1234"]
        l.add(m)
        try:
            m = ldb.Message()
            m.dn = ldb.Dn(l, "dc=add")
            m["bla"] = ldb.MessageElement(["456"], ldb.CHANGETYPE_ADD, "bla")
            l.modify(m)
            rm = l.search(m.dn)[0]
            self.assertEquals(2, len(rm))
            self.assertEquals(["1234", "456"], list(rm["bla"]))
        finally:
            l.delete(ldb.Dn(l, "dc=add"))

    def test_modify_modify(self):
        l = ldb.Ldb(filename())
        m = ldb.Message()
        m.dn = ldb.Dn(l, "dc=modify2")
        m["bla"] = ["1234", "456"]
        l.add(m)
        try:
            m = ldb.Message()
            m.dn = ldb.Dn(l, "dc=modify2")
            m["bla"] = ldb.MessageElement(["456"], ldb.CHANGETYPE_MODIFY, "bla")
            l.modify(m)
            rm = l.search(m.dn)[0]
            self.assertEquals(2, len(rm))
            self.assertEquals(["1234"], list(rm["bla"]))
        finally:
            l.delete(ldb.Dn(l, "dc=modify2"))

    def test_transaction_commit(self):
        l = ldb.Ldb(filename())
        l.transaction_start()
        m = ldb.Message(ldb.Dn(l, "dc=foo"))
        m["foo"] = ["bar"]
        l.add(m)
        l.transaction_commit()
        l.delete(m.dn)

    def test_transaction_cancel(self):
        l = ldb.Ldb(filename())
        l.transaction_start()
        m = ldb.Message(ldb.Dn(l, "dc=foo"))
        m["foo"] = ["bar"]
        l.add(m)
        l.transaction_cancel()
        self.assertEquals(0, len(l.search(ldb.Dn(l, "dc=foo"))))

    def test_set_debug(self):
        def my_report_fn(level, text):
            pass
        l = ldb.Ldb(filename())
        l.set_debug(my_report_fn)


class DnTests(unittest.TestCase):
    def setUp(self):
        self.ldb = ldb.Ldb(filename())

    def test_eq(self):
        x = ldb.Dn(self.ldb, "dc=foo,bar=bloe")
        y = ldb.Dn(self.ldb, "dc=foo,bar=bloe")
        self.assertEquals(x, y)

    def test_str(self):
        x = ldb.Dn(self.ldb, "dc=foo,bar=bloe")
        self.assertEquals(x.__str__(), "dc=foo,bar=bloe")

    def test_repr(self):
        x = ldb.Dn(self.ldb, "dc=foo,bla=blie")
        self.assertEquals(x.__repr__(), "Dn('dc=foo,bla=blie')")

    def test_get_casefold(self):
        x = ldb.Dn(self.ldb, "dc=foo,bar=bloe")
        self.assertEquals(x.get_casefold(), "DC=FOO,BAR=bloe")

    def test_validate(self):
        x = ldb.Dn(self.ldb, "dc=foo,bar=bloe")
        self.assertTrue(x.validate())

    def test_parent(self):
        x = ldb.Dn(self.ldb, "dc=foo,bar=bloe")
        self.assertEquals("bar=bloe", x.parent().__str__())

    def test_compare(self):
        x = ldb.Dn(self.ldb, "dc=foo,bar=bloe")
        y = ldb.Dn(self.ldb, "dc=foo,bar=bloe")
        self.assertEquals(x, y)
        z = ldb.Dn(self.ldb, "dc=foo,bar=blie")
        self.assertNotEquals(z, y)

    def test_is_valid(self):
        x = ldb.Dn(self.ldb, "dc=foo,dc=bloe")
        self.assertTrue(x.is_valid())
        x = ldb.Dn(self.ldb, "")
        # is_valid()'s return values appears to be a side effect of 
        # some other ldb functions. yuck.
        # self.assertFalse(x.is_valid())

    def test_is_special(self):
        x = ldb.Dn(self.ldb, "dc=foo,bar=bloe")
        self.assertFalse(x.is_special())
        x = ldb.Dn(self.ldb, "@FOOBAR")
        self.assertTrue(x.is_special())

    def test_check_special(self):
        x = ldb.Dn(self.ldb, "dc=foo,bar=bloe")
        self.assertFalse(x.check_special("FOOBAR"))
        x = ldb.Dn(self.ldb, "@FOOBAR")
        self.assertTrue(x.check_special("@FOOBAR"))

    def test_len(self):
        x = ldb.Dn(self.ldb, "dc=foo,bar=bloe")
        self.assertEquals(2, len(x))
        x = ldb.Dn(self.ldb, "dc=foo")
        self.assertEquals(1, len(x))

    def test_add_child(self):
        x = ldb.Dn(self.ldb, "dc=foo,bar=bloe")
        self.assertTrue(x.add_child(ldb.Dn(self.ldb, "bla=bloe")))
        self.assertEquals("bla=bloe,dc=foo,bar=bloe", x.__str__())

    def test_add_base(self):
        x = ldb.Dn(self.ldb, "dc=foo,bar=bloe")
        base = ldb.Dn(self.ldb, "bla=bloe")
        self.assertTrue(x.add_base(base))
        self.assertEquals("dc=foo,bar=bloe,bla=bloe", x.__str__())

    def test_add(self):
        x = ldb.Dn(self.ldb, "dc=foo")
        y = ldb.Dn(self.ldb, "bar=bla")
        self.assertEquals("dc=foo,bar=bla", str(y + x))

    def test_parse_ldif(self):
        msgs = self.ldb.parse_ldif("dn: foo=bar\n")
        msg = msgs.next()
        self.assertEquals("foo=bar", str(msg[1].dn))
        self.assertTrue(isinstance(msg[1], ldb.Message))

    def test_parse_ldif_more(self):
        msgs = self.ldb.parse_ldif("dn: foo=bar\n\n\ndn: bar=bar")
        msg = msgs.next()
        self.assertEquals("foo=bar", str(msg[1].dn))
        msg = msgs.next()
        self.assertEquals("bar=bar", str(msg[1].dn))

    def test_canonical_string(self):
        x = ldb.Dn(self.ldb, "dc=foo,bar=bloe")
        self.assertEquals("/bloe/foo", x.canonical_str())

    def test_canonical_ex_string(self):
        x = ldb.Dn(self.ldb, "dc=foo,bar=bloe")
        self.assertEquals("/bloe\nfoo", x.canonical_ex_str())


class LdbMsgTests(unittest.TestCase):
    def setUp(self):
        self.msg = ldb.Message()

    def test_init_dn(self):
        self.msg = ldb.Message(ldb.Dn(ldb.Ldb(), "dc=foo"))
        self.assertEquals("dc=foo", str(self.msg.dn))

    def test_iter_items(self):
        self.assertEquals(0, len(self.msg.items()))
        self.msg.dn = ldb.Dn(ldb.Ldb("foo.tdb"), "dc=foo")
        self.assertEquals(1, len(self.msg.items()))

    def test_repr(self):
        self.msg.dn = ldb.Dn(ldb.Ldb("foo.tdb"), "dc=foo")
        self.msg["dc"] = "foo"
        self.assertEquals("Message({'dn': Dn('dc=foo'), 'dc': MessageElement(['foo'])})", repr(self.msg))

    def test_len(self):
        self.assertEquals(0, len(self.msg))

    def test_notpresent(self):
        self.assertRaises(KeyError, lambda: self.msg["foo"])

    def test_del(self):
        del self.msg["foo"]

    def test_add_value(self):
        self.assertEquals(0, len(self.msg))
        self.msg["foo"] = ["foo"]
        self.assertEquals(1, len(self.msg))

    def test_add_value_multiple(self):
        self.assertEquals(0, len(self.msg))
        self.msg["foo"] = ["foo", "bla"]
        self.assertEquals(1, len(self.msg))
        self.assertEquals(["foo", "bla"], list(self.msg["foo"]))

    def test_set_value(self):
        self.msg["foo"] = ["fool"]
        self.assertEquals(["fool"], list(self.msg["foo"]))
        self.msg["foo"] = ["bar"]
        self.assertEquals(["bar"], list(self.msg["foo"]))

    def test_keys(self):
        self.msg.dn = ldb.Dn(ldb.Ldb("foo.tdb"), "@BASEINFO")
        self.msg["foo"] = ["bla"]
        self.msg["bar"] = ["bla"]
        self.assertEquals(["dn", "foo", "bar"], self.msg.keys())

    def test_dn(self):
        self.msg.dn = ldb.Dn(ldb.Ldb(filename()), "@BASEINFO")
        self.assertEquals("@BASEINFO", self.msg.dn.__str__())

    def test_get_dn(self):
        self.msg.dn = ldb.Dn(ldb.Ldb("foo.tdb"), "@BASEINFO")
        self.assertEquals("@BASEINFO", self.msg.get("dn").__str__())

    def test_get_other(self):
        self.msg["foo"] = ["bar"]
        self.assertEquals("bar", self.msg.get("foo")[0])

    def test_get_unknown(self):
        self.assertEquals(None, self.msg.get("lalalala"))


class MessageElementTests(unittest.TestCase):
    def test_cmp_element(self):
        x = ldb.MessageElement(["foo"])
        y = ldb.MessageElement(["foo"])
        z = ldb.MessageElement(["bzr"])
        self.assertEquals(x, y)
        self.assertNotEquals(x, z)

    def test_create_iterable(self):
        x = ldb.MessageElement(["foo"])
        self.assertEquals(["foo"], list(x))

    def test_repr(self):
        x = ldb.MessageElement(["foo"])
        self.assertEquals("MessageElement(['foo'])", repr(x))
        x = ldb.MessageElement(["foo", "bla"])
        self.assertEquals(2, len(x))
        self.assertEquals("MessageElement(['foo','bla'])", repr(x))

    def test_get_item(self):
        x = ldb.MessageElement(["foo", "bar"])
        self.assertEquals("foo", x[0])
        self.assertEquals("bar", x[1])
        self.assertEquals("bar", x[-1])
        self.assertRaises(IndexError, lambda: x[45])

    def test_len(self):
        x = ldb.MessageElement(["foo", "bar"])
        self.assertEquals(2, len(x))

    def test_eq(self):
        x = ldb.MessageElement(["foo", "bar"])
        y = ldb.MessageElement(["foo", "bar"])
        self.assertEquals(y, x)
        x = ldb.MessageElement(["foo"])
        self.assertNotEquals(y, x)
        y = ldb.MessageElement(["foo"])
        self.assertEquals(y, x)


class ModuleTests(unittest.TestCase):
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

        ldb.register_module(ExampleModule)
        if os.path.exists("usemodule.ldb"):
            os.unlink("usemodule.ldb")
        l = ldb.Ldb("usemodule.ldb")
        l.add({"dn": "@MODULES", "@LIST": "bla"})
        self.assertEquals([], ops)
        l = ldb.Ldb("usemodule.ldb")
        self.assertEquals(["init"], ops)

if __name__ == '__main__':
    import unittest
    unittest.TestProgram()
