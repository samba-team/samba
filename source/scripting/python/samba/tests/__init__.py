#!/usr/bin/python

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

import os
import ldb
import samba
import unittest

class LdbTestCase(unittest.TestCase):
    def setUp(self):
        self.filename = os.tempnam()
        self.ldb = samba.Ldb(self.filename)

    def set_modules(self, modules=[]):
        m = ldb.Message()
        m.dn = ldb.Dn(self.ldb, "@MODULES")
        m["@LIST"] = ",".join(modules)
        self.ldb.add(m)
        self.ldb = samba.Ldb(self.filename)


class SubstituteVarTestCase(unittest.TestCase):
    def test_empty(self):
        self.assertEquals("", samba.substitute_var("", {}))

    def test_nothing(self):
        self.assertEquals("foo bar", samba.substitute_var("foo bar", {"bar": "bla"}))

    def test_replace(self):
        self.assertEquals("foo bla", samba.substitute_var("foo ${bar}", {"bar": "bla"}))

    def test_broken(self):
        self.assertEquals("foo ${bdkjfhsdkfh sdkfh ", 
                samba.substitute_var("foo ${bdkjfhsdkfh sdkfh ", {"bar": "bla"}))

    def test_unknown_var(self):
        self.assertEquals("foo ${bla} gsff", 
                samba.substitute_var("foo ${bla} gsff", {"bar": "bla"}))
