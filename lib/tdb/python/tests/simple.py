#!/usr/bin/env python3
# Some simple tests for the Python bindings for TDB
# Note that this tests the interface of the Python bindings
# It does not test tdb itself.
#
# Copyright (C) 2007-2008 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU LGPLv3 or later

import sys
import os
import tempfile
from unittest import TestCase

import tdb


class OpenTdbTests(TestCase):

    def test_nonexistent_read(self):
        self.assertRaises(IOError, tdb.Tdb, "/some/nonexistent/file", 0,
                tdb.DEFAULT, os.O_RDWR)

class CloseTdbTests(TestCase):

    def test_double_close(self):
        self.tdb = tdb.Tdb(tempfile.mkstemp()[1], 0, tdb.DEFAULT,
                           os.O_CREAT|os.O_RDWR)
        self.assertNotEqual(None, self.tdb)

        # ensure that double close does not crash python
        self.tdb.close()
        self.tdb.close()

        # Check that further operations do not crash python
        self.assertRaises(RuntimeError, lambda: self.tdb.transaction_start())

        self.assertRaises(RuntimeError, lambda: self.tdb["bar"])


class InternalTdbTests(TestCase):

    def test_repr(self):
        self.tdb = tdb.Tdb()

        # repr used to crash on internal db
        self.assertEqual(repr(self.tdb), "Tdb(<internal>)")


class CommonTdbTests(TestCase):
    """Tests common to both the text & bytes interfaces"""

    use_text = False

    def setUp(self):
        super(CommonTdbTests, self).setUp()
        self.tdb = tdb.Tdb(tempfile.mkstemp()[1], 0, tdb.DEFAULT,
                           os.O_CREAT|os.O_RDWR)
        self.assertNotEqual(None, self.tdb)
        if self.use_text:
            self.tdb = self.tdb.text

    def test_lockall(self):
        self.tdb.lock_all()

    def test_max_dead(self):
        self.tdb.max_dead = 20

    def test_unlockall(self):
        self.tdb.lock_all()
        self.tdb.unlock_all()

    def test_lockall_read(self):
        self.tdb.read_lock_all()
        self.tdb.read_unlock_all()

    def test_reopen(self):
        self.tdb.reopen()

    def test_hash_size(self):
        self.tdb.hash_size

    def test_map_size(self):
        self.tdb.map_size

    def test_freelist_size(self):
        self.tdb.freelist_size

    def test_name(self):
        self.tdb.filename

    def test_add_flags(self):
        self.tdb.add_flags(tdb.NOMMAP)
        self.tdb.remove_flags(tdb.NOMMAP)


class TextCommonTdbTests(CommonTdbTests):

    use_text = True


class SimpleTdbTests(TestCase):

    def setUp(self):
        super(SimpleTdbTests, self).setUp()
        self.tdb = tdb.Tdb(tempfile.mkstemp()[1], 0, tdb.DEFAULT,
                           os.O_CREAT|os.O_RDWR)
        self.assertNotEqual(None, self.tdb)

    def test_repr(self):
        self.assertTrue(repr(self.tdb).startswith("Tdb('"))

    def test_store(self):
        self.tdb.store(b"bar", b"bla")
        self.assertEqual(b"bla", self.tdb.get(b"bar"))

    def test_storev(self):
        self.tdb.storev(b"bar", [b"first", b"second", b"third"])
        self.assertEqual(b"firstsecondthird", self.tdb.get(b"bar"))

    def test_getitem(self):
        self.tdb[b"bar"] = b"foo"
        self.tdb.reopen()
        self.assertEqual(b"foo", self.tdb[b"bar"])

    def test_delete(self):
        self.tdb[b"bar"] = b"foo"
        del self.tdb[b"bar"]
        self.assertRaises(KeyError, lambda: self.tdb[b"bar"])

    def test_contains(self):
        self.tdb[b"bla"] = b"bloe"
        self.assertTrue(b"bla" in self.tdb)
        self.assertFalse(b"qwertyuiop" in self.tdb)
        if sys.version_info < (3, 0):
            self.assertTrue(self.tdb.has_key(b"bla"))
            self.assertFalse(self.tdb.has_key(b"qwertyuiop"))

    def test_keyerror(self):
        self.assertRaises(KeyError, lambda: self.tdb[b"bla"])

    def test_iterator(self):
        self.tdb[b"bla"] = b"1"
        self.tdb[b"brainslug"] = b"2"
        l = list(self.tdb)
        l.sort()
        self.assertEqual([b"bla", b"brainslug"], l)

    def test_transaction_cancel(self):
        self.tdb[b"bloe"] = b"2"
        self.tdb.transaction_start()
        self.tdb[b"bloe"] = b"1"
        self.tdb.transaction_cancel()
        self.assertEqual(b"2", self.tdb[b"bloe"])

    def test_transaction_commit(self):
        self.tdb[b"bloe"] = b"2"
        self.tdb.transaction_start()
        self.tdb[b"bloe"] = b"1"
        self.tdb.transaction_commit()
        self.assertEqual(b"1", self.tdb[b"bloe"])

    def test_transaction_prepare_commit(self):
        self.tdb[b"bloe"] = b"2"
        self.tdb.transaction_start()
        self.tdb[b"bloe"] = b"1"
        self.tdb.transaction_prepare_commit()
        self.tdb.transaction_commit()
        self.assertEqual(b"1", self.tdb[b"bloe"])

    def test_iterkeys(self):
        self.tdb[b"bloe"] = b"2"
        self.tdb[b"bla"] = b"25"
        if sys.version_info >= (3, 0):
            i = self.tdb.keys()
        else:
            i = self.tdb.iterkeys()
        self.assertEqual(set([b"bloe", b"bla"]), set([next(i), next(i)]))

    def test_clear(self):
        self.tdb[b"bloe"] = b"2"
        self.tdb[b"bla"] = b"25"
        self.assertEqual(2, len(list(self.tdb)))
        self.tdb.clear()
        self.assertEqual(0, len(list(self.tdb)))

    def test_repack(self):
        self.tdb[b"foo"] = b"abc"
        self.tdb[b"bar"] = b"def"
        del self.tdb[b"foo"]
        self.tdb.repack()

    def test_seqnum(self):
        self.tdb.enable_seqnum()
        seq1 = self.tdb.seqnum
        self.tdb.increment_seqnum_nonblock()
        seq2 = self.tdb.seqnum
        self.assertEqual(seq2-seq1, 1)

    def test_len(self):
        self.assertEqual(0, len(list(self.tdb)))
        self.tdb[b"entry"] = b"value"
        self.assertEqual(1, len(list(self.tdb)))


class TdbTextTests(TestCase):

    def setUp(self):
        super(TdbTextTests, self).setUp()
        self.tdb = tdb.Tdb(tempfile.mkstemp()[1], 0, tdb.DEFAULT,
                           os.O_CREAT|os.O_RDWR)
        self.assertNotEqual(None, self.tdb)

    def test_repr(self):
        self.assertTrue(repr(self.tdb).startswith("Tdb('"))

    def test_store(self):
        self.tdb.text.store("bar", "bla")
        self.assertEqual("bla", self.tdb.text.get("bar"))

    def test_getitem(self):
        self.tdb.text["bar"] = "foo"
        self.tdb.reopen()
        self.assertEqual("foo", self.tdb.text["bar"])

    def test_delete(self):
        self.tdb.text["bar"] = "foo"
        del self.tdb.text["bar"]
        self.assertRaises(KeyError, lambda: self.tdb.text["bar"])

    def test_contains(self):
        self.tdb.text["bla"] = "bloe"
        self.assertTrue("bla" in self.tdb.text)
        self.assertFalse("qwertyuiop" in self.tdb.text)
        if sys.version_info < (3, 0):
            self.assertTrue(self.tdb.text.has_key("bla"))
            self.assertFalse(self.tdb.text.has_key("qwertyuiop"))

    def test_keyerror(self):
        self.assertRaises(KeyError, lambda: self.tdb.text["bla"])

    def test_iterator(self):
        self.tdb.text["bla"] = "1"
        self.tdb.text["brainslug"] = "2"
        l = list(self.tdb.text)
        l.sort()
        self.assertEqual(["bla", "brainslug"], l)

    def test_transaction_cancel(self):
        self.tdb.text["bloe"] = "2"
        self.tdb.transaction_start()
        self.tdb.text["bloe"] = "1"
        self.tdb.transaction_cancel()
        self.assertEqual("2", self.tdb.text["bloe"])

    def test_transaction_commit(self):
        self.tdb.text["bloe"] = "2"
        self.tdb.transaction_start()
        self.tdb.text["bloe"] = "1"
        self.tdb.transaction_commit()
        self.assertEqual("1", self.tdb.text["bloe"])

    def test_transaction_prepare_commit(self):
        self.tdb.text["bloe"] = "2"
        self.tdb.transaction_start()
        self.tdb.text["bloe"] = "1"
        self.tdb.transaction_prepare_commit()
        self.tdb.transaction_commit()
        self.assertEqual("1", self.tdb.text["bloe"])

    def test_iterkeys(self):
        self.tdb.text["bloe"] = "2"
        self.tdb.text["bla"] = "25"
        if sys.version_info >= (3, 0):
            i = self.tdb.text.keys()
        else:
            i = self.tdb.text.iterkeys()
        self.assertEqual(set(["bloe", "bla"]), set([next(i), next(i)]))

    def test_clear(self):
        self.tdb.text["bloe"] = "2"
        self.tdb.text["bla"] = "25"
        self.assertEqual(2, len(list(self.tdb)))
        self.tdb.clear()
        self.assertEqual(0, len(list(self.tdb)))

    def test_repack(self):
        self.tdb.text["foo"] = "abc"
        self.tdb.text["bar"] = "def"
        del self.tdb.text["foo"]
        self.tdb.repack()

    def test_len(self):
        self.assertEqual(0, len(list(self.tdb.text)))
        self.tdb.text["entry"] = "value"
        self.assertEqual(1, len(list(self.tdb.text)))

    def test_text_and_binary(self):
        text = u'\xfa\u0148\xef\xe7\xf8\xf0\xea'
        bytestr = text.encode('utf-8')
        self.tdb[b"entry"] = bytestr
        self.tdb.text[u"entry2"] = text
        self.assertEqual(self.tdb.text["entry"], text)
        self.assertEqual(self.tdb[b"entry2"], bytestr)
        assert self.tdb.text.raw == self.tdb


class VersionTests(TestCase):

    def test_present(self):
        self.assertTrue(isinstance(tdb.__version__, str))


if __name__ == '__main__':
    import unittest
    unittest.TestProgram()
