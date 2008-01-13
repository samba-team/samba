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

from echo import rpcecho
import unittest

class RpcEchoTests(unittest.TestCase):
    def setUp(self):
        self.conn = rpcecho("ncalrpc:")

    def test_addone(self):
        self.assertEquals(2, conn.AddOne(1))

    def test_echodata(self):
        self.assertEquals("bla", conn.EchoData(3, "bla"))

    def test_call(self):
        self.assertEquals("foobar", conn.TestCall("foobar"))

    def test_surrounding(self):
        somearray = [1,2,3,4]
        conn.TestSurrounding(echo.Surrounding(4, somearray))
        self.assertEquals(8 * [0], somearray)
