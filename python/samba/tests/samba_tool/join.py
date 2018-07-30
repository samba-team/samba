# Unix SMB/CIFS implementation.
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2016
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
import ldb
from samba.tests.samba_tool.base import SambaToolCmdTest


class JoinCmdTestCase(SambaToolCmdTest):
    """Test for samba-tool fsmo show subcommand"""

    def test_rejoin(self):
        """Run domain join to confirm it errors because we are already joined"""
        (result, out, err) = self.runsubcmd("domain", "join", os.environ["REALM"], "dc", "-U%s%%%s" % (os.environ["USERNAME"], os.environ["PASSWORD"]))

        self.assertCmdFail(result)
        self.assertTrue("Not removing account" in err, "Should fail with exception")
