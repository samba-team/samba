#!/usr/bin/env python

# Unix SMB/CIFS implementation.
# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007-2008
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

"""Samba Python tests."""

import os
import ldb
import samba
from samba import param
import tempfile

# Other modules import these two classes from here, for convenience:
from testtools.testcase import TestCase, TestSkipped


class LdbTestCase(TestCase):
    """Trivial test case for running tests against a LDB."""

    def setUp(self):
        super(LdbTestCase, self).setUp()
        self.filename = os.tempnam()
        self.ldb = samba.Ldb(self.filename)

    def set_modules(self, modules=[]):
        """Change the modules for this Ldb."""
        m = ldb.Message()
        m.dn = ldb.Dn(self.ldb, "@MODULES")
        m["@LIST"] = ",".join(modules)
        self.ldb.add(m)
        self.ldb = samba.Ldb(self.filename)


class TestCaseInTempDir(TestCase):

    def setUp(self):
        super(TestCaseInTempDir, self).setUp()
        self.tempdir = tempfile.mkdtemp()

    def tearDown(self):
        super(TestCaseInTempDir, self).tearDown()
        self.assertEquals([], os.listdir(self.tempdir))
        os.rmdir(self.tempdir)


class SubstituteVarTestCase(TestCase):

    def test_empty(self):
        self.assertEquals("", samba.substitute_var("", {}))

    def test_nothing(self):
        self.assertEquals("foo bar",
                samba.substitute_var("foo bar", {"bar": "bla"}))

    def test_replace(self):
        self.assertEquals("foo bla",
                samba.substitute_var("foo ${bar}", {"bar": "bla"}))

    def test_broken(self):
        self.assertEquals("foo ${bdkjfhsdkfh sdkfh ", 
            samba.substitute_var("foo ${bdkjfhsdkfh sdkfh ", {"bar": "bla"}))

    def test_unknown_var(self):
        self.assertEquals("foo ${bla} gsff", 
                samba.substitute_var("foo ${bla} gsff", {"bar": "bla"}))
                
    def test_check_all_substituted(self):
        samba.check_all_substituted("nothing to see here")
        self.assertRaises(Exception, samba.check_all_substituted,
                "Not subsituted: ${FOOBAR}")


class LdbExtensionTests(TestCaseInTempDir):

    def test_searchone(self):
        path = self.tempdir + "/searchone.ldb"
        l = samba.Ldb(path)
        try:
            l.add({"dn": "foo=dc", "bar": "bla"})
            self.assertEquals("bla",
                l.searchone(basedn=ldb.Dn(l, "foo=dc"), attribute="bar"))
        finally:
            del l
            os.unlink(path)


def env_loadparm():
    lp = param.LoadParm()
    try:
        lp.load(os.environ["SMB_CONF_PATH"])
    except KeyError:
        raise Exception("SMB_CONF_PATH not set")
    return lp

cmdline_credentials = None

class RpcInterfaceTestCase(TestCase):

    def get_loadparm(self):
        return env_loadparm()

    def get_credentials(self):
        return cmdline_credentials


class ValidNetbiosNameTests(TestCase):

    def test_valid(self):
        self.assertTrue(samba.valid_netbios_name("FOO"))

    def test_too_long(self):
        self.assertFalse(samba.valid_netbios_name("FOO"*10))

    def test_invalid_characters(self):
        self.assertFalse(samba.valid_netbios_name("*BLA"))
