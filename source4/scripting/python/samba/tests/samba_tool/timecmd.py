# Unix SMB/CIFS implementation.
# Copyright (C) Sean Dague <sdague@linux.vnet.ibm.com> 2011
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

import os
from time import localtime, strptime, mktime
from samba.tests.samba_tool.base import SambaToolCmdTest

class TimeCmdTestCase(SambaToolCmdTest):
    """Tests for samba-tool time subcommands"""

    def test_timeget(self):
        """Run time against the server and make sure it looks accurate"""
        (result, out, err) = self.runcmd("time", os.environ["SERVER"])
        self.assertCmdSuccess(result, "Ensuring time ran successfully")

        timefmt = strptime(out, "%a %b %d %H:%M:%S %Y %Z\n")
        servertime = int(mktime(timefmt))
        now = int(mktime(localtime()))

        # because there is a race here, allow up to 5 seconds difference in times
        delta = 5
        self.assertTrue((servertime > (now - delta) and (servertime < (now + delta)), "Time is now"))

    def test_timefail(self):
        """Run time against a non-existent server, and make sure it fails"""
        (result, out, err) = self.runcmd("time", "notaserver")
        self.assertEquals(result, -1, "check for result code")
        self.assertTrue(err.strip().endswith("NT_STATUS_OBJECT_NAME_NOT_FOUND"), "ensure right error string")
        self.assertEquals(out, "", "ensure no output returned")
