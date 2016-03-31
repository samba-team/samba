# Unix SMB/CIFS implementation.
# Copyright (C) Rowland Penny <rpenny@samba.org> 2016
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
from samba.tests.samba_tool.base import SambaToolCmdTest

class FsmoCmdTestCase(SambaToolCmdTest):
    """Test for samba-tool fsmo show subcommand"""

    def test_fsmoget(self):
        """Run fsmo show to see if it errors"""
        (result, out, err) = self.runsubcmd("fsmo", "show")

        self.assertCmdSuccess(result)
        self.assertEquals(err,"","Shouldn't be any error messages")
