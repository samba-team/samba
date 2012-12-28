# Unix SMB/CIFS implementation.
# Copyright (C) Andrew Bartlett 2012
#
# based on time.py:
# Copyright (C) Sean Dague <sdague@linux.vnet.ibm.com> 2011
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
from samba.tests.samba_tool.base import SambaToolCmdTest
import shutil

class GpoCmdTestCase(SambaToolCmdTest):
    """Tests for samba-tool time subcommands"""

    gpo_name = "testgpo"

    def test_gpo_list(self):
        """Run gpo list against the server and make sure it looks accurate"""
        (result, out, err) = self.runsubcmd("gpo", "listall", "-H", "ldap://%s" % os.environ["SERVER"])
        self.assertCmdSuccess(result, "Ensuring gpo listall ran successfully")

    def test_fetchfail(self):
        """Run against a non-existent GPO, and make sure it fails (this hard-coded UUID is very unlikely to exist"""
        (result, out, err) = self.runsubcmd("gpo", "fetch", "c25cac17-a02a-4151-835d-fae17446ee43", "-H", "ldap://%s" % os.environ["SERVER"])
        self.assertEquals(result, -1, "check for result code")

    def test_fetch(self):
        """Run against a real GPO, and make sure it passes"""
        (result, out, err) = self.runsubcmd("gpo", "fetch", self.gpo_guid, "-H", "ldap://%s" % os.environ["SERVER"], "--tmpdir", self.tempdir)
        self.assertCmdSuccess(result, "Ensuring gpo fetched successfully")
        shutil.rmtree(os.path.join(self.tempdir, "policy"))

    def test_show(self):
        """Show a real GPO, and make sure it passes"""
        (result, out, err) = self.runsubcmd("gpo", "show", self.gpo_guid, "-H", "ldap://%s" % os.environ["SERVER"])
        self.assertCmdSuccess(result, "Ensuring gpo fetched successfully")

    def test_show_as_admin(self):
        """Show a real GPO, and make sure it passes"""
        (result, out, err) = self.runsubcmd("gpo", "show", self.gpo_guid, "-H", "ldap://%s" % os.environ["SERVER"], "-U%s%%%s" % (os.environ["USERNAME"], os.environ["PASSWORD"]))
        self.assertCmdSuccess(result, "Ensuring gpo fetched successfully")

    def test_aclcheck(self):
        """Check all the GPOs on the remote server have correct ACLs"""
        (result, out, err) = self.runsubcmd("gpo", "aclcheck", "-H", "ldap://%s" % os.environ["SERVER"], "-U%s%%%s" % (os.environ["USERNAME"], os.environ["PASSWORD"]))
        self.assertCmdSuccess(result, "Ensuring gpo checked successfully")

    def setUp(self):
        """set up a temporary GPO to work with"""
        super(GpoCmdTestCase, self).setUp()
        (result, out, err) = self.runsubcmd("gpo", "create", self.gpo_name,
                                            "-H", "ldap://%s" % os.environ["SERVER"],
                                            "-U%s%%%s" % (os.environ["USERNAME"], os.environ["PASSWORD"]),
                                            "--tmpdir", self.tempdir)
        shutil.rmtree(os.path.join(self.tempdir, "policy"))
        self.assertCmdSuccess(result, "Ensuring gpo created successfully")
        try:
            self.gpo_guid = "{%s}" % out.split("{")[1].split("}")[0]
        except IndexError:
            self.fail("Failed to find GUID in output: %s" % out)

    def tearDown(self):
        """remove the temporary GPO to work with"""
        (result, out, err) = self.runsubcmd("gpo", "del", self.gpo_guid, "-H", "ldap://%s" % os.environ["SERVER"], "-U%s%%%s" % (os.environ["USERNAME"], os.environ["PASSWORD"]))
        self.assertCmdSuccess(result, "Ensuring gpo deleted successfully")
        super(GpoCmdTestCase, self).tearDown()
