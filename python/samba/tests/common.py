# Unix SMB/CIFS implementation. Tests for common.py routines
# Copyright (C) Andrew Tridgell 2011
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

"""Tests for samba.common"""

import samba
import samba.tests
from samba.common import normalise_int32


class CommonTests(samba.tests.TestCase):

    def test_normalise_int32(self):
        self.assertEqual('17', normalise_int32(17))
        self.assertEqual('17', normalise_int32('17'))
        self.assertEqual('-123', normalise_int32('-123'))
        self.assertEqual('-1294967296', normalise_int32('3000000000'))
