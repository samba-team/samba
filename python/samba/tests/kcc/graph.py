# Unix SMB/CIFS implementation. Tests for kcc.graph routines
# Copyright (C) Andrew Bartlett 2015
#
# Written by Douglas Bagnall <douglas.bagnall@catalyst.net.nz>
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

"""Tests for samba.kcc.graph"""

import samba
import samba.tests
from samba.kcc.graph import *

import itertools

class GraphFunctionTests(samba.tests.TestCase):


    def test_total_schedule(self):
        schedule = [0x81] * 84
        for schedule, total in (
                ([0x81] * 84, 168),
                ([0xff] * 84, 84 * 8),
                ([0xaa] * 84, 84 * 4),
                ([0x03, 0x33] * 42, 42 * 6),
                (range(4) * 21, 21 * 5)):
            self.assetEquals(total_schedule(schedule), total)
