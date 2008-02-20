#!/usr/bin/python

# Unix SMB/CIFS implementation.
# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2008
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

import echo
import unittest
from samba.tests import get_loadparm

class RpcEchoTests(unittest.TestCase):
    def setUp(self):
        lp_ctx = get_loadparm()
        self.conn = echo.rpcecho("ncalrpc:", lp_ctx)

    def test_addone(self):
        self.assertEquals(2, self.conn.AddOne(1))

    def test_echodata(self):
        self.assertEquals([1,2,3], self.conn.EchoData(3, [1, 2, 3]))

    def test_call(self):
        self.assertEquals(u"foobar", self.conn.TestCall(u"foobar"))

    def test_surrounding(self):
        surrounding_struct = echo.Surrounding()
        surrounding_struct.x = 4
        surrounding_struct.surrounding = [1,2,3,4]
        y = self.conn.TestSurrounding(surrounding_struct)
        self.assertEquals(8 * [0], y.surrounding)
