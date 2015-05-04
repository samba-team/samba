# Unix SMB/CIFS implementation. Tests for samba.kcc.kcc_utils.
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

"""Tests for samba.kcc.kcc_utils"""
import samba
import samba.tests
from samba.kcc.kcc_utils import *


class ScheduleTests(samba.tests.TestCase):

    def test_new_connection_schedule(self):
        schedule = new_connection_schedule()
        self.assertIsInstance(schedule, drsblobs.schedule)
        self.assertEquals(schedule.size, 188)
        self.assertEquals(len(schedule.dataArray[0].slots), 168)


# OK, this is pathetic, but the rest of it looks really hard, with the
# classes all intertwingled with each other and the samdb. That is to say:
# XXX later.
