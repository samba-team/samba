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


class DrsCloneDcDataLmdbSizeTestCase(SambaToolCmdTest):
    """Test setting of the lmdb map size during drs clone-dc-data"""

    def setUp(self):
        super(DrsCloneDcDataLmdbSizeTestCase, self).setUp()
        self.tempsambadir = os.path.join(self.tempdir, "samba")
        os.mkdir(self.tempsambadir)

    # clone a domain and set the lmdb map size to size
    #
    # returns the tuple (ret, stdout, stderr)
    def clone(self, size=None):
        command = (
            "samba-tool " +
            "drs clone-dc-database " +
            os.environ["REALM"] + " " +
            ("-U%s%%%s " % (os.environ["USERNAME"], os.environ["PASSWORD"])) +
            ("--targetdir=%s " % self.tempsambadir) +
            "--backend-store=mdb "
        )
        if size:
            command += ("--backend-store-size=%s" % size)

        return self.run_command(command)

    #
    # Get the lmdb map size for the specified command
    #
    # While there is a python lmdb package available we use the lmdb command
    # line utilities to avoid introducing a dependancy.
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
    # Check the lmdb files created by provision and ensure that the map size
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
    def test_default(self):
        (result, out, err) = self.clone()
        self.assertEqual(0, result)
        self.check_lmdb_environment_sizes(8 * 1024 * 1024 * 1024)

    def test_64Mb(self):
        (result, out, err) = self.clone("64Mb")
        self.assertEqual(0, result)
        self.check_lmdb_environment_sizes(64 * 1024 * 1024)

    def test_no_unit_suffix(self):
        (result, out, err) = self.run_command(
            'samba-tool drs clone-dc-database --backend-store-size "2"')
        self.assertGreater(result, 0)
        self.assertRegexpMatches(err,
                                 r"--backend-store-size invalid suffix ''")

    def test_invalid_unit_suffix(self):
        (result, out, err) = self.run_command(
            'samba-tool drs clone-dc-database --backend-store-size "2 cd"')
        self.assertGreater(result, 0)
        self.assertRegexpMatches(err,
                                 r"--backend-store-size invalid suffix 'cd'")

    def test_non_numeric(self):
        (result, out, err) = self.run_command(
            'samba-tool drs clone-dc-database --backend-store-size "two Gb"')
        self.assertGreater(result, 0)
        self.assertRegexpMatches(
            err,
            r"backend-store-size option requires a numeric value, with an"
            " optional unit suffix")

    def tearDown(self):
        super(DrsCloneDcDataLmdbSizeTestCase, self).tearDown()
        shutil.rmtree(self.tempsambadir)
