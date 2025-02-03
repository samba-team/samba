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

    def testGetUserRecord(self):
        for user in self.users:
            with self.cli.open("io.systemd.UserDatabase", namespaced=True) as conn:
                full_username = "%s%s%s" % (self.domain,
                                            self.winbind_separator,
                                            user["username"])
                r = conn.GetUserRecord(service=self.varlink_service,
                                        userName=full_username)
                self.assertIsNotNone(r)
                self.assertFalse(r.incomplete)
                self.assertIsNotNone(r.record)
                self.assertEqual(r.record["service"], self.varlink_service)
                self.assertEqual(r.record["userName"], full_username)
                self.assertEqual(r.record["uid"], user["uid"])
                self.assertEqual(r.record["gid"], user["gid"])
                self.assertEqual(r.record["shell"], user["shell"])
                self.assertEqual(r.record["homeDirectory"], user["dir"])
                self.assertEqual(r.record["disposition"], "regular")


if __name__ == "__main__":
    import unittest

    unittest.main()
