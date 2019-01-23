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

"""Tests for samba.param."""

from samba import param
import samba.tests
import os


class LoadParmTestCase(samba.tests.TestCaseInTempDir):

    def setUp(self):
        super(LoadParmTestCase, self).setUp()
        self.tempf = os.path.join(self.tempdir, "test")
        open(self.tempf, 'w').write("empty")

    def tearDown(self):
        os.unlink(self.tempf)
        super(LoadParmTestCase, self).tearDown()

    def test_init(self):
        file = param.LoadParm()
        self.assertTrue(file is not None)

    def test_length(self):
        file = param.LoadParm()
        self.assertEqual(0, len(file))

    def test_set_workgroup(self):
        file = param.LoadParm()
        file.set("workgroup", "bla")
        self.assertEqual("BLA", file.get("workgroup"))

    def test_is_mydomain(self):
        file = param.LoadParm()
        file.set("workgroup", "bla")
        self.assertTrue(file.is_mydomain("BLA"))
        self.assertFalse(file.is_mydomain("FOOBAR"))

    def test_is_myname(self):
        file = param.LoadParm()
        file.set("netbios name", "bla")
        self.assertTrue(file.is_myname("BLA"))
        self.assertFalse(file.is_myname("FOOBAR"))

    def test_load_default(self):
        file = param.LoadParm()
        file.load_default()

    def test_section_nonexistent(self):
        samba_lp = param.LoadParm()
        samba_lp.load_default()
        self.assertRaises(KeyError, samba_lp.__getitem__, "nonexistent")

    def test_log_level(self):
        samba_lp = param.LoadParm()
        samba_lp.set("log level", "5 auth:4")
        self.assertEqual(5, samba_lp.log_level())

    def test_dump(self):
        samba_lp = param.LoadParm()
        # Just test successfull method execution (outputs to stdout)
        self.assertEqual(None, samba_lp.dump())

    def test_dump_to_file(self):
        samba_lp = param.LoadParm()
        self.assertEqual(None, samba_lp.dump(False, self.tempf))
        content = open(self.tempf, 'r').read()
        self.assertIn('[global]', content)
        self.assertIn('interfaces', content)

    def test_dump_a_parameter(self):
        samba_lp = param.LoadParm()
        samba_lp.load_default()
        # Just test successfull method execution
        self.assertEqual(None, samba_lp.dump_a_parameter('interfaces'))

    def test_dump_a_parameter_to_file(self):
        samba_lp = param.LoadParm()
        samba_lp.load_default()
        self.assertEqual(None,
                          samba_lp.dump_a_parameter('interfaces',
                                                    'global',
                                                    self.tempf))
        content = open(self.tempf, 'r').read()
        self.assertIn('10.53.57.', content)

    def test_samdb_url(self):
        samba_lp = param.LoadParm()
        samdb_url = samba_lp.samdb_url()
        self.assertTrue(samdb_url.startswith('tdb://'))
        self.assertTrue(samdb_url.endswith('/sam.ldb'))
