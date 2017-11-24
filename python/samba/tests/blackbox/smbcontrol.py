# Blackbox tests for smbcontrol
#
# Copyright (C) Catalyst IT Ltd. 2017
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

from samba.tests import BlackboxTestCase
from samba.messaging import Messaging

COMMAND = "bin/smbcontrol"
PING    = "ping"
USAGE   = "pool-usage"


class SmbcontrolBlockboxTests(BlackboxTestCase):

    def setUp(self):
        super(SmbcontrolBlockboxTests, self).setUp()
        lp_ctx = self.get_loadparm()
        self.msg_ctx = Messaging(lp_ctx=lp_ctx)

    def test_expected_processes(self):
        """
        Test that the expected samba processes are running, currently we only
        check that at least one process is running
        """
        processes = self.msg_ctx.irpc_all_servers()
        if not processes:
            self.fail("No samba processes returned")

    def test_ping(self):
        """Test that all the samba processes can be pinged"""

        processes = self.msg_ctx.irpc_all_servers()
        for p in processes:
            for id in p.ids:
                if p.name != "samba":
                    self.check_run("%s %d %s" % (COMMAND, id.pid, PING))
