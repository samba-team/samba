# Unix SMB/CIFS implementation.
# Copyright (C) Catalyst IT Ltd. 2019
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

from samba.tests.samba_tool.base import SambaToolCmdTest
import os
import shutil


class JoinLmdbSizeTestCase(SambaToolCmdTest):
    """Test setting of the lmdb map size during join"""

    def setUp(self):
        super(JoinLmdbSizeTestCase, self).setUp()
        self.tempsambadir = os.path.join(self.tempdir, "samba")
        os.mkdir(self.tempsambadir)
        (_, name) = os.path.split(self.tempdir)
        self.netbios_name = name

    # join a domain and set the lmdb map size to size
    #
    # returns the tuple (ret, stdout, stderr)
    def join(self, size=None, role=None):
        command = (
            "samba-tool " +
            "domain join " +
            os.environ["REALM"] + " " +
            role + " " +
            ("-U%s%%%s " % (os.environ["USERNAME"], os.environ["PASSWORD"])) +
            ("--targetdir=%s " % self.tempsambadir) +
            ("--option=netbiosname=%s " % self.netbios_name) +
            "--backend-store=mdb "
        )
        if size:
            command += ("--backend-store-size=%s" % size)

        return self.run_command(command)

    def is_rodc(self):
        url = "ldb://%s/private/sam.ldb" % self.tempsambadir
        samdb = self.getSamDB("-H", url)
        return samdb.am_rodc()

    #
    # Get the lmdb map size for the specified command
    #
    # While there is a python lmdb package available we use the lmdb command
    # line utilities to avoid introducing a dependency.
    #
    def get_lmdb_environment_size(self, path):
        (result, out, err) = self.run_command("mdb_stat -ne %s" % path)
        if result:
            self.fail("Unable to run mdb_stat\n")
        for line in out.split("\n"):
            line = line.strip()
            if line.startswith("Map size:"):
                line = line.replace(" ", "")
                (label, size) = line.split(":")
                return int(size)

    #
    # Check the lmdb files created by join and ensure that the map size
    # has been set to size.
    #
    # Currently this is all the *.ldb files in private/sam.ldb.d
    #
    def check_lmdb_environment_sizes(self, size):
        directory = os.path.join(self.tempsambadir, "private", "sam.ldb.d")
        for name in os.listdir(directory):
            if name.endswith(".ldb"):
                path = os.path.join(directory, name)
                s = self.get_lmdb_environment_size(path)
                if s != size:
                    self.fail("File %s, size=%d larger than %d" %
                              (name, s, size))

    #
    # Ensure that if --backend-store-size is not specified the default of
    # 8Gb is used
    def test_join_as_dc_default(self):
        (result, out, err) = self.join(role="DC")
        self.assertEqual(0, result)
        self.check_lmdb_environment_sizes(8 * 1024 * 1024 * 1024)
        self.assertFalse(self.is_rodc())

    #
    # Join as an DC with the lmdb backend size set to 1Gb
    def test_join_as_dc(self):
        (result, out, err) = self.join("1Gb", "DC")
        self.assertEqual(0, result)
        self.check_lmdb_environment_sizes(1 * 1024 * 1024 * 1024)
        self.assertFalse(self.is_rodc())

    #
    # Join as an RODC with the lmdb backend size set to 128Mb
    def test_join_as_rodc(self):
        (result, out, err) = self.join("128Mb", "RODC")
        self.assertEqual(0, result)
        self.check_lmdb_environment_sizes(128 * 1024 * 1024)
        self.assertTrue(self.is_rodc())

    #
    # Join as an RODC with --backend-store-size
    def test_join_as_rodc_default(self):
        (result, out, err) = self.join(role="RODC")
        self.assertEqual(0, result)
        self.check_lmdb_environment_sizes(8 * 1024 * 1024 * 1024)
        self.assertTrue(self.is_rodc())

    def test_no_unit_suffix(self):
        (result, out, err) = self.run_command(
            'samba-tool domain join --backend-store-size "2"')
        self.assertGreater(result, 0)
        self.assertRegexpMatches(err,
                                 r"--backend-store-size invalid suffix ''")

    def test_invalid_unit_suffix(self):
        (result, out, err) = self.run_command(
            'samba-tool domain join --backend-store-size "2 cd"')
        self.assertGreater(result, 0)
        self.assertRegexpMatches(err,
                                 r"--backend-store-size invalid suffix 'cd'")

    def test_non_numeric(self):
        (result, out, err) = self.run_command(
            'samba-tool domain join --backend-store-size "two Gb"')
        self.assertGreater(result, 0)
        self.assertRegexpMatches(
            err,
            r"backend-store-size option requires a numeric value, with an"
            " optional unit suffix")

    def tearDown(self):
        super(JoinLmdbSizeTestCase, self).tearDown()
        shutil.rmtree(self.tempsambadir)
