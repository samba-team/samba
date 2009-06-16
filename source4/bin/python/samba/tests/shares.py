#!/usr/bin/python

# Unix SMB/CIFS implementation. Tests for shares
# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2009
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
from samba.shares import SharesContainer
from unittest import TestCase


class ShareTests(TestCase):

    def _get_shares(self, conf):
        return SharesContainer(conf)

    def test_len_no_global(self):
        shares = self._get_shares({})
        self.assertEquals(0, len(shares))

    def test_len(self):
        shares = self._get_shares({"global": {}})
        self.assertEquals(0, len(shares))

    def test_getitem_nonexistant(self):
        shares = self._get_shares({"global": {}})
        self.assertRaises(KeyError, shares.__getitem__, "bla")

    def test_getitem_global(self):
        shares = self._get_shares({"global": {}})
        self.assertRaises(KeyError, shares.__getitem__, "global")
