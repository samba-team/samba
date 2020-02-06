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

from samba.samba3 import IdmapDatabase
from samba.tests import TestCase
import os

for p in ["../../../../../testdata/samba3", "../../../../testdata/samba3"]:
    DATADIR = os.path.join(os.path.dirname(__file__), p)
    if os.path.exists(DATADIR):
        break


class IdmapDbTestCase(TestCase):

    def setUp(self):
        super(IdmapDbTestCase, self).setUp()
        self.idmapdb = IdmapDatabase(os.path.join(DATADIR,
                                                  "winbindd_idmap"))

    def test_user_hwm(self):
        self.assertEqual(10000, self.idmapdb.get_user_hwm())

    def test_group_hwm(self):
        self.assertEqual(10002, self.idmapdb.get_group_hwm())

    def test_uids(self):
        self.assertEqual(1, len(list(self.idmapdb.uids())))

    def test_gids(self):
        self.assertEqual(3, len(list(self.idmapdb.gids())))

    def test_get_user_sid(self):
        self.assertEqual(b"S-1-5-21-58189338-3053988021-627566699-501", self.idmapdb.get_user_sid(65534))

    def test_get_group_sid(self):
        self.assertEqual(b"S-1-5-21-2447931902-1787058256-3961074038-3007", self.idmapdb.get_group_sid(10001))

    def tearDown(self):
        self.idmapdb.close()
        super(IdmapDbTestCase, self).tearDown()
