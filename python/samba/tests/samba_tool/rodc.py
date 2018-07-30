# Unix SMB/CIFS implementation.
# Copyright (C) Catalyst IT Ltd. 2015
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
from samba.samdb import SamDB
from samba.tests import delete_force
from samba.tests.samba_tool.base import SambaToolCmdTest
from samba.credentials import Credentials
from samba.auth import system_session


class RodcCmdTestCase(SambaToolCmdTest):
    def setUp(self):
        super(RodcCmdTestCase, self).setUp()
        self.lp = samba.param.LoadParm()
        self.lp.load(os.environ["SMB_CONF_PATH"])
        self.creds = Credentials()
        self.creds.set_username(os.environ["DC_USERNAME"])
        self.creds.set_password(os.environ["DC_PASSWORD"])
        self.creds.guess(self.lp)
        self.session = system_session()
        self.ldb = SamDB("ldap://" + os.environ["DC_SERVER"],
                         session_info=self.session, credentials=self.creds, lp=self.lp)

        self.base_dn = self.ldb.domain_dn()

        self.ldb.newuser("sambatool1", "1qazXSW@")
        self.ldb.newuser("sambatool2", "2wsxCDE#")
        self.ldb.newuser("sambatool3", "3edcVFR$")
        self.ldb.newuser("sambatool4", "4rfvBGT%")
        self.ldb.newuser("sambatool5", "5tjbNHY*")
        self.ldb.newuser("sambatool6", "6yknMJU*")

        self.ldb.add_remove_group_members("Allowed RODC Password Replication Group",
                                          ["sambatool1", "sambatool2", "sambatool3",
                                           "sambatool4", "sambatool5"],
                                          add_members_operation=True)

    def tearDown(self):
        super(RodcCmdTestCase, self).tearDown()
        self.ldb.deleteuser("sambatool1")
        self.ldb.deleteuser("sambatool2")
        self.ldb.deleteuser("sambatool3")
        self.ldb.deleteuser("sambatool4")
        self.ldb.deleteuser("sambatool5")
        self.ldb.deleteuser("sambatool6")
        (result, out, err) = self.runsubcmd("drs", "replicate", "--local", "unused",
                                            os.environ["DC_SERVER"], self.base_dn)

    def test_single_by_account_name(self):
        (result, out, err) = self.runsubcmd("rodc", "preload", "sambatool1",
                                            "--server", os.environ["DC_SERVER"])
        self.assertCmdSuccess(result, out, err, "ensuring rodc prefetch ran successfully")
        self.assertEqual(out, "Replicating DN CN=sambatool1,CN=Users,%s\n" % self.base_dn)
        self.assertEqual(err, "")

    def test_single_by_dn(self):
        (result, out, err) = self.runsubcmd("rodc", "preload", "cn=sambatool2,cn=users,%s" % self.base_dn,
                                            "--server", os.environ["DC_SERVER"])
        self.assertCmdSuccess(result, out, err, "ensuring rodc prefetch ran successfully")
        self.assertEqual(out, "Replicating DN CN=sambatool2,CN=Users,%s\n" % self.base_dn)

    def test_multi_by_account_name(self):
        (result, out, err) = self.runsubcmd("rodc", "preload", "sambatool1", "sambatool2",
                                            "--server", os.environ["DC_SERVER"])
        self.assertCmdSuccess(result, out, err, "ensuring rodc prefetch ran successfully")
        self.assertEqual(out, "Replicating DN CN=sambatool1,CN=Users,%s\nReplicating DN CN=sambatool2,CN=Users,%s\n" % (self.base_dn, self.base_dn))

    def test_multi_by_dn(self):
        (result, out, err) = self.runsubcmd("rodc", "preload", "cn=sambatool3,cn=users,%s" % self.base_dn, "cn=sambatool4,cn=users,%s" % self.base_dn,
                                            "--server", os.environ["DC_SERVER"])
        self.assertCmdSuccess(result, out, err, "ensuring rodc prefetch ran successfully")
        self.assertEqual(out, "Replicating DN CN=sambatool3,CN=Users,%s\nReplicating DN CN=sambatool4,CN=Users,%s\n" % (self.base_dn, self.base_dn))

    def test_multi_in_file(self):
        tempf = os.path.join(self.tempdir, "accountlist")
        open(tempf, 'w').write("sambatool1\nsambatool2")
        (result, out, err) = self.runsubcmd("rodc", "preload", "--file", tempf,
                                            "--server", os.environ["DC_SERVER"])
        self.assertCmdSuccess(result, out, err, "ensuring rodc prefetch ran successfully")
        self.assertEqual(out, "Replicating DN CN=sambatool1,CN=Users,%s\nReplicating DN CN=sambatool2,CN=Users,%s\n" % (self.base_dn, self.base_dn))
        os.unlink(tempf)

    def test_multi_with_missing_name_success(self):
        (result, out, err) = self.runsubcmd("rodc", "preload",
                                            "nonexistentuser1", "sambatool5",
                                            "nonexistentuser2",
                                            "--server", os.environ["DC_SERVER"],
                                            "--ignore-errors")
        self.assertCmdSuccess(result, out, err, "ensuring rodc prefetch ran successfully")
        self.assertTrue(out.startswith("Replicating DN CN=sambatool5,CN=Users,%s\n"
                                       % self.base_dn))

    def test_multi_with_missing_name_failure(self):
        (result, out, err) = self.runsubcmd("rodc", "preload",
                                            "nonexistentuser1", "sambatool5",
                                            "nonexistentuser2",
                                            "--server", os.environ["DC_SERVER"])
        self.assertCmdFail(result, "ensuring rodc prefetch quit on missing user")

    def test_multi_without_group_success(self):
        (result, out, err) = self.runsubcmd("rodc", "preload",
                                            "sambatool6", "sambatool5",
                                            "--server", os.environ["DC_SERVER"],
                                            "--ignore-errors")
        self.assertCmdSuccess(result, out, err, "ensuring rodc prefetch ran successfully")
        self.assertTrue(out.startswith("Replicating DN CN=sambatool6,CN=Users,%s\n"
                                       "Replicating DN CN=sambatool5,CN=Users,%s\n"
                                       % (self.base_dn, self.base_dn)))

    def test_multi_without_group_failure(self):
        (result, out, err) = self.runsubcmd("rodc", "preload",
                                            "sambatool6", "sambatool5",
                                            "--server", os.environ["DC_SERVER"])
        self.assertCmdFail(result, "ensuring rodc prefetch quit on non-replicated user")
