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

"""Tests for samba.registry."""

import os
from samba import registry
import samba.tests
from samba import WERRORError
from subprocess import Popen, PIPE


class HelperTests(samba.tests.TestCase):

    def test_predef_to_name(self):
        self.assertEqual("HKEY_LOCAL_MACHINE",
                          registry.get_predef_name(0x80000002))

    def test_str_regtype(self):
        self.assertEqual("REG_DWORD", registry.str_regtype(4))


class HiveTests(samba.tests.TestCaseInTempDir):

    def setUp(self):
        super(HiveTests, self).setUp()
        self.hive_path = os.path.join(self.tempdir, "ldb_new.ldb")
        self.hive = registry.open_ldb(self.hive_path)

    def tearDown(self):
        del self.hive
        os.unlink(self.hive_path)
        super(HiveTests, self).tearDown()

    def test_ldb_new(self):
        self.assertTrue(self.hive is not None)

    def test_set_value(self):
        self.assertIsNone(self.hive.set_value('foo1', 1, 'bar1'))

    def test_flush(self):
        self.assertIsNone(self.hive.set_value('foo2', 1, 'bar2'))
        self.assertIsNone(self.hive.flush())

        tdbdump_tool = 'tdbdump'
        if os.path.isfile('bin/tdbdump'):
            tdbdump_tool = 'bin/tdbdump'

        proc = Popen([tdbdump_tool, self.hive_path], stdout=PIPE, stderr=PIPE)
        tdb_dump, err = proc.communicate()
        self.assertTrue(b'DN=VALUE=FOO2,HIVE=NONE' in tdb_dump)

    def test_del_value(self):
        self.assertIsNone(self.hive.set_value('foo3', 1, 'bar3'))
        self.assertIsNone(self.hive.del_value('foo3'))

    def test_del_nonexisting_value(self):
        self.assertRaises(WERRORError, self.hive.del_value, 'foo4')


class RegistryTests(samba.tests.TestCase):

    def test_new(self):
        self.registry = registry.Registry()
        self.assertIsNotNone(self.registry)
