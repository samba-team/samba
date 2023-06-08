# Unix SMB/CIFS implementation. Tests for dsdb
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2023
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

"""Tests for samba.dsdb."""

from samba.credentials import Credentials
from samba.samdb import SamDB
from samba.auth import system_session
from samba.tests import TestCase
from samba.param import LoadParm
from samba import dsdb, functional_level
import ldb, samba


from samba.tests.samba_tool.base import SambaToolCmdTest
import os
import shutil
import tempfile

class SambaFLStartUpTests(SambaToolCmdTest):
    """Test the samba binary sets the DC FL on startup for RW DCs"""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.classtempdir = tempfile.mkdtemp()
        cls.tempsambadir = os.path.join(cls.classtempdir, "samba")

        command = (
                "samba-tool " +
                "domain provision " +
                "--realm=foo.example.com " +
                "--domain=FOO " +
                ("--targetdir=%s " % cls.tempsambadir) +
                "--use-ntvfs"
        )

        (result, out, err) = cls.run_command(command)
        if (result != 0):
            raise AssertionError

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        shutil.rmtree(cls.tempsambadir)

    def setUp(self):
        super().setUp()
        path = os.path.join(self.tempsambadir, "etc/smb.conf")
        self.lp = LoadParm(filename_for_non_global_lp=path)
        self.creds = Credentials()
        self.creds.guess(self.lp)
        self.session = system_session()
        self.samdb = SamDB(session_info=self.session,
                           credentials=self.creds,
                           lp=self.lp)


    def test_initial_db_fl_state(self):
        server_dn = self.samdb.get_dsServiceName()
        res = self.samdb.search(base=server_dn,
                                 scope=ldb.SCOPE_BASE,
                                 attrs=["msDS-Behavior-Version"])
        # This confirms the domain is in FL 2008 R2 by default, this is
        # important to verify the original state
        self.assertEqual(int(res[0]["msDS-Behavior-Version"][0]),
                         dsdb.DS_DOMAIN_FUNCTION_2008_R2)

    def test_initial_rootdse_domain_fl_state(self):
        res = self.samdb.search(base="",
                                scope=ldb.SCOPE_BASE,
                                attrs=["domainControllerFunctionality"])
        self.assertEqual(int(res[0]["domainControllerFunctionality"][0]),
                         dsdb.DS_DOMAIN_FUNCTION_2008_R2)

    def test_initial_rootdse_dc_fl_state(self):
        res = self.samdb.search(base="",
                                scope=ldb.SCOPE_BASE,
                                attrs=["domainFunctionality"])
        self.assertEqual(int(res[0]["domainFunctionality"][0]),
                         dsdb.DS_DOMAIN_FUNCTION_2008_R2)

    def test_initial_lp_fl_state(self):
        lp_fl = self.lp.get("ad dc functional level")
        # This confirms the domain is in FL 2008 R2 by default, this is
        # important to verify the original state
        self.assertEqual(lp_fl, "2008_R2")

    def test_initial_lp_fl_state_mapped(self):
        # Confirm the same via the dc_level_from_lp wrapper
        self.assertEqual(functional_level.dc_level_from_lp(self.lp),
                         dsdb.DS_DOMAIN_FUNCTION_2008_R2)

    def fixup_fl(self, dn, fl):
        msg = ldb.Message()
        msg.dn = dn
        msg["msDS-Behavior-Version"] = (
            ldb.MessageElement(str(fl),
                               ldb.FLAG_MOD_REPLACE,
                               "msDS-Behavior-Version"))
        self.samdb.modify(msg)

    def test_change_db_dc_fl(self):
        server_dn = ldb.Dn(self.samdb, self.samdb.get_dsServiceName())
        msg = ldb.Message()
        msg.dn = server_dn
        msg["msDS-Behavior-Version"] = (
                ldb.MessageElement(str(dsdb.DS_DOMAIN_FUNCTION_2012_R2),
                                   ldb.FLAG_MOD_REPLACE,
                                   "msDS-Behavior-Version"))
        self.samdb.modify(msg)
        self.addCleanup(self.fixup_fl, msg.dn, dsdb.DS_DOMAIN_FUNCTION_2008_R2)

        samdb2 = SamDB(session_info=self.session,
                       credentials=self.creds,
                       lp=self.lp)

        # Check that the DB set to 2012_R2 has got as far as the rootDSE handler on a new connection
        res = samdb2.search(base="",
                            scope=ldb.SCOPE_BASE,
                            attrs=["domainControllerFunctionality"])
        self.assertEqual(int(res[0]["domainControllerFunctionality"][0]),
                         dsdb.DS_DOMAIN_FUNCTION_2012_R2)

    def test_incorrect_db_dc_fl(self):
        server_dn = ldb.Dn(self.samdb, self.samdb.get_dsServiceName())
        self.addCleanup(self.fixup_fl, server_dn, dsdb.DS_DOMAIN_FUNCTION_2008_R2)

        old_lp_fl = self.lp.get("ad dc functional level")
        self.lp.set("ad dc functional level",
                    "2016")
        self.addCleanup(self.lp.set, "ad dc functional level", old_lp_fl)

        dsdb.check_and_update_fl(self.samdb, self.lp)

        # Check this has been set to 2016 per the smb.conf setting
        res = self.samdb.search(base="",
                                 scope=ldb.SCOPE_BASE,
                                 attrs=["domainControllerFunctionality"])
        self.assertEqual(int(res[0]["domainControllerFunctionality"][0]),
                         dsdb.DS_DOMAIN_FUNCTION_2016)

        samdb3 = SamDB(session_info=self.session,
                       credentials=self.creds,
                       lp=self.lp)

        # Check this is still set on re-read (not just the opaque)
        res = samdb3.search(base="",
                            scope=ldb.SCOPE_BASE,
                            attrs=["domainControllerFunctionality"])
        self.assertEqual(int(res[0]["domainControllerFunctionality"][0]),
                         dsdb.DS_DOMAIN_FUNCTION_2016)

        res = self.samdb.search(base=server_dn,
                                 scope=ldb.SCOPE_BASE,
                                 attrs=["msDS-Behavior-Version"])
        self.assertEqual(int(res[0]["msDS-Behavior-Version"][0]),
                         dsdb.DS_DOMAIN_FUNCTION_2016)

        self.assertEqual(functional_level.dc_level_from_lp(self.lp),
                         dsdb.DS_DOMAIN_FUNCTION_2016)
        self.assertEqual(self.lp.get("ad dc functional level"),
                         "2016")

if __name__ == "__main__":
    import unittest
    unittest.main()
