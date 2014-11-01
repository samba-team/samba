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

import os
import tempfile

from selftest.tests import TestCase

from selftest.testlist import (
    RestrictedTestManager,
    find_in_list,
    open_file_or_pipe,
    read_test_regexes,
    read_testlist,
    read_testlist_file,
    )

from cStringIO import StringIO


class FindInListTests(TestCase):

    def test_empty(self):
        self.assertIs(None, find_in_list([], "foo.test"))

    def test_no_reason(self):
        self.assertEquals("because",
            find_in_list([("foo.*bar", "because")], "foo.bla.bar"))


class ReadTestRegexesTests(TestCase):

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


class ReadTestlistTests(TestCase):

    def test_read_list(self):
        inf = StringIO("-- TEST --\nfoo\nbar\nbla\n")
        outf = StringIO()
        self.assertEquals([('foo', 'bar', 'bla', None)],
                list(read_testlist(inf, outf)))
        self.assertEquals("", outf.getvalue())

    def test_read_list_passes_through(self):
        inf = StringIO("MORENOISE\n-- TEST --\nfoo\nbar\nbla\nNOISE\n")
        outf = StringIO()
        self.assertEquals([('foo', 'bar', 'bla', None)],
                list(read_testlist(inf, outf)))
        self.assertEquals("MORENOISE\nNOISE\n", outf.getvalue())



class RestrictedTestManagerTests(TestCase):

    def test_unused(self):
        mgr = RestrictedTestManager(["foo.bar"])
        self.assertEquals(["foo.bar"], list(mgr.iter_unused()))

    def test_run_testsuite(self):
        mgr = RestrictedTestManager(["foo.bar"])
        self.assertEquals(None, mgr.should_run_testsuite("foo.bar"))

    def test_run_subtest(self):
        mgr = RestrictedTestManager(["foo.bar.bla"])
        self.assertEquals(["bla"], mgr.should_run_testsuite("foo.bar"))

    def test_run_subtest_after_testsuite(self):
        mgr = RestrictedTestManager(["foo.bar", "foo.bar.bla"])
        self.assertEquals(None, mgr.should_run_testsuite("foo.bar"))

    def test_run_multiple_subtests(self):
        mgr = RestrictedTestManager(["foo.bar.blie", "foo.bar.bla"])
        self.assertEquals(["blie", "bla"], mgr.should_run_testsuite("foo.bar"))

    def test_run_nomatch(self):
        mgr = RestrictedTestManager(["foo.bar"])
        self.assertEquals([], mgr.should_run_testsuite("foo.blie.bla"))


class OpenFileOrPipeTests(TestCase):

    def test_regular_file(self):
        (fd, p) = tempfile.mkstemp()
        self.addCleanup(os.remove, p)
        f = os.fdopen(fd, 'w')
        try:
            f.write('data\nbla\n')
        finally:
            f.close()
        f = open_file_or_pipe(p, 'r')
        try:
            self.assertEquals("data\nbla\n", f.read())
        finally:
            f.close()

    def test_pipe(self):
        f = open_file_or_pipe('echo foo|', 'r')
        try:
            self.assertEquals("foo\n", f.read())
        finally:
            f.close()


class ReadTestListFileTests(TestCase):

    def test_regular_file(self):
        (fd, p) = tempfile.mkstemp()
        self.addCleanup(os.remove, p)
        f = os.fdopen(fd, 'w')
        try:
            f.write('noise\n-- TEST --\ndata\nenv\ncmd\n')
        finally:
            f.close()
        outf = StringIO()
        self.assertEquals(
            [('data', 'env', 'cmd', None)],
            list(read_testlist_file(p, outf)))
        self.assertEquals("noise\n", outf.getvalue())
