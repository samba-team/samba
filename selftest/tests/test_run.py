# test_run.py -- Tests for selftest.run
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

"""Tests for selftest.run."""

import os

from selftest.run import (
    expand_command_list,
    expand_environment_strings,
    expand_command_run,
    exported_envvars_str,
    )

from selftest.tests import TestCase


class ExpandEnvironmentStringsTests(TestCase):

    def test_no_vars(self):
        self.assertEquals("foo bar", expand_environment_strings("foo bar", {}))

    def test_simple(self):
        self.assertEquals("foo bar",
            expand_environment_strings("foo $BLA", {"BLA": "bar"}))

    def test_unknown(self):
        self.assertEquals("foo $BLA",
            expand_environment_strings("foo $BLA", {}))


class ExpandCommandListTests(TestCase):

    def test_no_list(self):
        self.assertIs(None, expand_command_list("test bla"))

    def test_list(self):
        self.assertEquals("test --list", expand_command_list("test $LISTOPT"))


class ExpandCommandRunTests(TestCase):

    def test_idlist(self):
        self.assertEquals(("test foo bar", None),
            expand_command_run("test", False, True, subtests=["foo", "bar"]))

    def test_idlist_all(self):
        self.assertEquals(("test", None),
            expand_command_run("test", False, True))

    def test_loadlist(self):
        (cmd, tmpf) = expand_command_run("test $LOADLIST", True, False,
            subtests=["foo", "bar"])
        self.addCleanup(os.remove, tmpf)
        f = open(tmpf, 'r')
        try:
            self.assertEquals(f.read(), "foo\nbar\n")
        finally:
            f.close()
        self.assertEquals("test --load-list=%s" % tmpf, cmd)

    def test_loadlist_all(self):
        self.assertEquals(("test ", None),
            expand_command_run("test $LOADLIST", True, False))


class ExportedEnvvarsStrTests(TestCase):

    def test_no_vars(self):
        self.assertEquals("", exported_envvars_str({}, ["foo", "bar"]))

    def test_vars(self):
        self.assertEquals("foo=1\n",
            exported_envvars_str({"foo": "1"}, ["foo", "bar"]))

    def test_vars_unknown(self):
        self.assertEquals("foo=1\n",
            exported_envvars_str({"foo": "1", "bla": "2"}, ["foo", "bar"]))
