# Unix SMB/CIFS implementation.
# Copyright (C) Catalyst IT Ltd. 2017
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


class ProvisionPasswordTestCase(SambaToolCmdTest):
    """Test for password validation in domain provision subcommand"""

    def setUp(self):
        super(ProvisionPasswordTestCase, self).setUp()
        self.tempsambadir = os.path.join(self.tempdir, "samba")
        os.mkdir(self.tempsambadir)

    def _provision_with_password(self, password):
        return self.runsubcmd(
            "domain", "provision", "--realm=foo.example.com", "--domain=FOO",
            "--targetdir=%s" % self.tempsambadir, "--adminpass=%s" % password,
            "--use-ntvfs")

    def test_short_and_low_quality(self):
        (result, out, err) = self._provision_with_password("foo")
        self.assertCmdFail(result)

    def test_short(self):
        (result, out, err) = self._provision_with_password("Fo0!_9")
        self.assertCmdFail(result)
        self.assertRegexpMatches(err, r"minimum password length")

    def test_low_quality(self):
        (result, out, err) = self._provision_with_password("aaaaaaaaaaaaaaaaa")
        self.assertCmdFail(result)
        self.assertRegexpMatches(err, r"quality standards")

    def test_good(self):
        (result, out, err) = self._provision_with_password("Fo0!_9.")
        self.assertCmdSuccess(result, out, err)

    def tearDown(self):
        super(ProvisionPasswordTestCase, self).tearDown()
        shutil.rmtree(self.tempsambadir)
