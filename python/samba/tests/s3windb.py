# Unix SMB/CIFS implementation.
# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

"""Tests for samba.samba3."""

from samba.samba3 import WinsDatabase
from samba.tests import TestCase
import os


for p in ["../../../../../testdata/samba3", "../../../../testdata/samba3"]:
    DATADIR = os.path.join(os.path.dirname(__file__), p)
    if os.path.exists(DATADIR):
        break


class WinsDatabaseTestCase(TestCase):

    def setUp(self):
        super(WinsDatabaseTestCase, self).setUp()
        self.winsdb = WinsDatabase(os.path.join(DATADIR, "wins.dat"))

    def test_length(self):
        self.assertEqual(22, len(self.winsdb))

    def test_first_entry(self):
        self.assertEqual((1124185120, ["192.168.1.5"], 0x64), self.winsdb["ADMINISTRATOR#03"])

    def tearDown(self):
        self.winsdb.close()
        super(WinsDatabaseTestCase, self).tearDown()
