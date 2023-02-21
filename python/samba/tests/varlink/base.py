# Unix SMB/CIFS implementation.
#
# Copyright (C) Samuel Cabrero <scabrero@samba.org> 2023
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

""" Winbind varlink service tests, base class """

from samba.tests.samba_tool.base import SambaToolCmdTest
from samba.auth import system_session
from samba.samdb import SamDB
from samba.credentials import Credentials
import os, pwd, grp
import varlink
import samba
import subprocess

class VarlinkTestCase(SambaToolCmdTest):

    def setUp(self):
        super().setUp()
        sdir = samba.tests.env_get_var_value("SELFTEST_WINBINDD_SOCKET_DIR")
        uri = "unix:" + os.path.join(sdir, "org.samba.selftest")
        self.cli = varlink.Client.new_with_address(uri)
        self.assertIsNotNone(self.cli)

        self.lp = samba.tests.env_loadparm()
        self.domain = samba.tests.env_get_var_value("DOMAIN")
        self.winbind_separator = self.lp.get('winbind separator')
        self.varlink_service = self.lp.get('winbind varlink : service name')

        self.bindir = os.path.normpath(os.getenv("BINDIR", "./bin"))
        self.netcmd = os.path.join(self.bindir, "net")

        self.ldb = SamDB(
            session_info=system_session(),
            credentials=Credentials(),
            lp=self.lp)

        self.users = []
        self.groups = []
        members = []
        for i in range(0, 3):
            username = "vl_test_user_%d" % i
            groupname = "vl_test_group_%d" % i

            subprocess.Popen([self.netcmd, "cache", "del", "NAME2SID/%s\\%s"
                              % (self.domain, username.upper())], stdout=subprocess.PIPE)
            self.runsubcmd("user", "create", username, self.random_password())

            subprocess.Popen([self.netcmd, "cache", "del", "NAME2SID/%s\\%s"
                              % (self.domain, groupname.upper())], stdout=subprocess.PIPE)
            self.runsubcmd("group", "create", groupname)

            members.append(username)
            for m in members:
                self.runsubcmd("group", "addmembers", groupname, m)

            grent = grp.getgrnam(groupname)
            self.groups.append({"groupname": groupname,
                                "gid": grent.gr_gid,
                                "members": members.copy()})

            pwent = pwd.getpwnam(username)
            self.users.append({"username": username,
                   "uid": pwent.pw_uid,
                   "gid": pwent.pw_gid,
                   "shell": pwent.pw_shell,
                   "dir": pwent.pw_dir})

    def tearDown(self):
        for group in self.groups:
            self.runsubcmd("group", "delete", group["groupname"])

        for user in self.users:
            self.runsubcmd("user", "delete", user["username"])

        super().tearDown()
