# test_run.py -- Tests for selftest.target.samba
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

"""Tests for selftest.target.samba."""

from selftest.tests import TestCase

from selftest.target.samba import bindir_path


class BinDirPathTests(TestCase):

    def test_mapping(self):
        self.assertEquals("exe4",
            bindir_path({"exe": "exe4"}, "/some/path", "exe"))
        self.assertEquals("/bin/ls",
            bindir_path({"exe": "ls"}, "/bin", "exe"))

    def test_no_mapping(self):
        self.assertEquals("exe", bindir_path({}, "/some/path", "exe"))
        self.assertEquals("/bin/ls",
            bindir_path({}, "/bin", "ls"))
