# Unix SMB/CIFS implementation.
# Copyright (C) Catalyst IT Ltd. 2021
#
# based on provision_lmdb_size.py:
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


class ProvisionUserPasswordTestCase(SambaToolCmdTest):
    """Test for crypt() hashed passwords"""

    def setUp(self):
        super(ProvisionUserPasswordTestCase, self).setUp()
        self.tempsambadir = os.path.join(self.tempdir, "samba")
        os.mkdir(self.tempsambadir)

    # provision a domain
    #
    # returns the tuple (ret, stdout, stderr)
    def provision(self, machinepass=None):
        command = (
            "samba-tool " +
            "domain provision " +
            "--use-rfc230 " +
            "--realm=\"EXAMPLE.COM\" " +
            "--domain=\"EXAMPLE\" " +
            "--adminpass=\"FooBar123\" " +
            "--server-role=dc " +
            "--host-ip=10.166.183.55 " +
            "--option=\"password hash userPassword " +
            "schemes=CryptSHA256 CryptSHA512\" " +
            ("--targetdir=\"%s\" " % self.tempsambadir) +
            "--use-ntvfs"
        )
        if machinepass:
            command += ("--machinepass=\"%s\"" % machinepass)

        return self.run_command(command)

    def test_crypt(self):
        (result, out, err) = self.provision()
        self.assertEqual(0, result)

    def test_length(self):
        (result, out, err) = self.provision(machinepass="FooBar123" + ("a"*1024))
        self.assertNotEqual(0, result)

    def tearDown(self):
        super(ProvisionUserPasswordTestCase, self).tearDown()
        shutil.rmtree(self.tempsambadir)
