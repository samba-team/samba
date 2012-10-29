# Unix SMB/CIFS implementation.
# Copyright (C) Andrew Bartlett 2012
#
# based on time.py:
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
from samba.tests.samba_tool.base import SambaToolCmdTest

class ProcessCmdTestCase(SambaToolCmdTest):
    """Tests for samba-tool process subcommands"""

    def test_name(self):
        """Run processes command"""
        (result, out, err) = self.runcmd("processes", "--name", "samba")
        self.assertCmdSuccess(result, "Ensuring processes ran successfully")

    def test_all(self):
        """Run processes command"""
        (result, out, err) = self.runcmd("processes")
        self.assertCmdSuccess(result, "Ensuring processes ran successfully")
