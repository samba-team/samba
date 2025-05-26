# Unix SMB/CIFS implementation.
#
# Copyright (C) Samuel Cabrero <scabrero@samba.org> 2025
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

"""Winbind nss tests, base class"""

import grp
import os
import pwd
import subprocess

import samba
from samba.auth import system_session
from samba.credentials import Credentials
from samba.samdb import SamDB
from samba.tests.samba_tool.base import SambaToolCmdTest


class NssTestCase(SambaToolCmdTest):
    def setUp(self):
        super().setUp()

        self.domain = samba.tests.env_get_var_value("DOMAIN")

        self.bindir = os.path.normpath(os.getenv("BINDIR", "./bin"))
        self.netcmd = os.path.join(self.bindir, "net")

        self.users = []
        self.groups = []
        members = []
        for i in range(0, 3):
            username = "nss_test_user_%d" % i
            groupname = "nss_test_group_%d" % i

            subprocess.Popen(
                [
                    self.netcmd,
                    "cache",
                    "del",
                    "NAME2SID/%s\\%s" % (self.domain, username.upper()),
                ],
                stdout=subprocess.PIPE,
            )
            self.runsubcmd("user", "create", username, self.random_password())

            subprocess.Popen(
                [
                    self.netcmd,
                    "cache",
                    "del",
                    "NAME2SID/%s\\%s" % (self.domain, groupname.upper()),
                ],
                stdout=subprocess.PIPE,
            )
            self.runsubcmd("group", "create", groupname)

            members.append(username)
            for m in members:
                self.runsubcmd("group", "addmembers", groupname, m)

            grent = grp.getgrnam(groupname)
            self.groups.append(grent)

            pwent = pwd.getpwnam(username)
            self.users.append(pwent)

    def tearDown(self):
        for test_group in self.groups:
            self.runsubcmd("group", "delete", test_group.gr_name)

        for test_user in self.users:
            self.runsubcmd("user", "delete", test_user.pw_name)

        super().tearDown()
