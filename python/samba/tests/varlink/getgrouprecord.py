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

sys.path.insert(0, "bin/python")
os.environ["PYTHONUNBUFFERED"] = "1"

from samba.tests.varlink.base import VarlinkTestCase


class VarlinkGetUserRecordTests(VarlinkTestCase):
    def setUp(self):
        super().setUp()

    def tearDown(self):
        super().tearDown()

    def testGetGroupRecord(self):
        for group in self.groups:
            with self.cli.open("io.systemd.UserDatabase", namespaced=True) as conn:
                full_groupname = "%s%s%s" % (self.domain,
                                             self.winbind_separator,
                                             group["groupname"])
                full_members_names = []
                for m in group["members"]:
                    full_members_names.append("%s%s%s" % (self.domain,
                                              self.winbind_separator,
                                              m))
                r = conn.GetGroupRecord(service=self.varlink_service,
                                        groupName=full_groupname)
                self.assertIsNotNone(r)
                self.assertFalse(r.incomplete)
                self.assertIsNotNone(r.record)
                self.assertEqual(r.record["service"], self.varlink_service)
                self.assertEqual(r.record["groupName"], full_groupname)
                self.assertEqual(r.record["gid"], group["gid"])
                self.assertEqual(sorted(r.record["members"]),
                                 sorted(full_members_names))


if __name__ == "__main__":
    import unittest
    unittest.main()
