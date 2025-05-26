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

"""Winbind nss tests"""

import sys
import os
import grp

sys.path.insert(0, "bin/python")
os.environ["PYTHONUNBUFFERED"] = "1"

from samba.tests.nss.base import NssTestCase


class NssGroupTests(NssTestCase):
    def testGroupEnum(self):
        grlst = grp.getgrall()
        self.assertIsNotNone(grlst)
        self.assertGreaterEqual(
            len(grlst), len(self.groups), "Unexpected groups length"
        )
        for test_group in self.groups:
            self.assertIn(test_group, grlst)


if __name__ == "__main__":
    import unittest

    unittest.main()
