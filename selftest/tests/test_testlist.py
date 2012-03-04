# test_testlist.py -- The tests for selftest testlist code
# Copyright (C) 2012 Jelmer Vernooij <jelmer@samba.org>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; version 3
# of the License or (at your option) any later version of
# the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA  02110-1301, USA.

"""Tests for selftest.testlist."""

from selftest.testlist import (
    find_in_list,
    read_test_regexes,
    read_testlist,
    )

from cStringIO import StringIO

import unittest


class FindInListTests(unittest.TestCase):

    def test_empty(self):
        self.assertIs(None, find_in_list([], "foo.test"))

    def test_no_reason(self):
        self.assertEquals("because",
            find_in_list([("foo.*bar", "because")], "foo.bla.bar"))


class ReadTestRegexesTests(unittest.TestCase):

    def test_comment(self):
        f = StringIO("# I am a comment\n # I am also a comment\n")
        self.assertEquals([], list(read_test_regexes(f)))

    def test_no_reason(self):
        f = StringIO(" foo\n")
        self.assertEquals([("foo", None)], list(read_test_regexes(f)))

    def test_reason(self):
        f = StringIO(" foo # because\nbar\n")
        self.assertEquals([("foo", "because"), ("bar", None)],
            list(read_test_regexes(f)))


class ReadTestlistTests(unittest.TestCase):

    def test_read_list(self):
        inf = StringIO("-- TEST --\nfoo\nbar\nbla\n")
        outf = StringIO()
        self.assertEquals([('foo', 'bar', 'bla', False, False)],
                list(read_testlist(inf, outf)))
        self.assertEquals("", outf.getvalue())

    def test_read_list_passes_through(self):
        inf = StringIO("MORENOISE\n-- TEST --\nfoo\nbar\nbla\nNOISE\n")
        outf = StringIO()
        self.assertEquals([('foo', 'bar', 'bla', False, False)],
                list(read_testlist(inf, outf)))
        self.assertEquals("MORENOISE\nNOISE\n", outf.getvalue())
