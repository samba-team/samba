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

from selftest.run import expand_environment_strings

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
