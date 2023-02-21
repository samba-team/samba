# Unix SMB/CIFS implementation.
#
# Copyright (C) Samuel Cabrero <scabrero@samba.org> 2024
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

""" Winbind varlink service tests """

import sys
import os
import pwd
import grp

sys.path.insert(0, "bin/python")
os.environ["PYTHONUNBUFFERED"] = "1"

from samba.tests.varlink.base import VarlinkTestCase


class VarlinkGetMembershipsTests(VarlinkTestCase):
    def setUp(self):
        super().setUp()

    def tearDown(self):
        super().tearDown()

    def testGetMembershipsByGroup(self):
        for group in self.groups:
            full_name = "%s%s%s" % (self.domain,
                                    self.winbind_separator,
                                    group["groupname"])
            full_members_names = []
            for m in group["members"]:
                full_members_names.append("%s%s%s" % (self.domain,
                                          self.winbind_separator,
                                          m))
            vl_members = []
            with self.cli.open("io.systemd.UserDatabase", namespaced=True) as conn:
                for r in conn.GetMemberships(service=self.varlink_service,
                                             groupName=full_name,
                                             _more=True):
                    self.assertIsNotNone(r)
                    vl_members.append(r.userName)
            self.assertEqual(sorted(vl_members),
                             sorted(full_members_names))

    def testGetMembershipsByUser(self):
        for user in self.users:
            full_username = "%s%s%s" % (self.domain,
                                        self.winbind_separator,
                                        user["username"])
            pwent = pwd.getpwnam(full_username)
            glgid = os.getgrouplist(pwent.pw_name, pwent.pw_gid)
            nss_list = []
            for gid in glgid:
                grent = grp.getgrgid(gid)
                # nss_wrapper looks into files first, and "ADDOMAIN/domain users" is
                # mapped to "users" from files NSS group db.
                gname = grent.gr_name
                if gname == "users":
                    gname = "%s%s%s" % (self.domain,
                                        self.winbind_separator,
                                        "domain users")
                nss_list.append(gname)

            vl_list = []
            with self.cli.open("io.systemd.UserDatabase", namespaced=True) as conn:
                for r in conn.GetMemberships(service=self.varlink_service,
                                             userName=full_username,
                                             _more=True):
                    self.assertIsNotNone(r)
                    vl_list.append(r.groupName)

            self.assertEqual(sorted(nss_list), sorted(vl_list))

if __name__ == "__main__":
    import unittest
    unittest.main()
