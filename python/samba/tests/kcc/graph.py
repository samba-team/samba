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
from samba.kcc.graph import total_schedule, convert_schedule_to_repltimes

def ntdsconn_schedule(times):
    if times is None:
        return None
    from samba.dcerpc import drsblobs
    schedule = drsblobs.schedule()
    schedule.size = 188
    schedule.bandwidth = 0
    schedule.numberOfSchedules = 1
    header = drsblobs.scheduleHeader()
    header.type = 0
    header.offset = 20
    schedule.headerArray = [header]
    data = drsblobs.scheduleSlots()
    data.slots = times
    schedule.dataArray = [data]
    return schedule


class GraphFunctionTests(samba.tests.TestCase):

    def test_total_schedule(self):
        schedule = [0x81] * 84
        for schedule, total in (
                ([0x81] * 84, 168),
                ([0xff] * 84, 84 * 8),
                ([0xaa] * 84, 84 * 4),
                ([0x03, 0x33] * 42, 42 * 6),
                (list(range(7)) * 12, 12 * 9),
                (list(range(4)) * 21, 21 * 4)):
            self.assertEqual(total_schedule(schedule), total)

    def test_convert_schedule_to_repltimes(self):
        for ntdsconn_times, repltimes in (
                ([0x01] * 168, [0x11] * 84),
                (None, [0x11] * 84),
                ([0x06] * 168, [0x66] * 84),
                ([0x03, 0xa] * 84, [0x3a] * 84),
                (list(range(7)) * 24,
                 [0x01, 0x23, 0x45, 0x60, 0x12, 0x34, 0x56] * 12)):
            schedule = ntdsconn_schedule(ntdsconn_times)
            self.assertEqual(convert_schedule_to_repltimes(schedule),
                              repltimes)
