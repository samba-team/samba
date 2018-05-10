# Test 'samba-tool domain passwordsettings' sub-commands
#
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2018
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

class PwdSettingsCmdTestCase(SambaToolCmdTest):
    """Tests for 'samba-tool domain passwordsettings' subcommands"""

    def setUp(self):
        super(PwdSettingsCmdTestCase, self).setUp()
        self.server = "ldap://%s" % os.environ["DC_SERVER"]
        self.user_auth = "-U%s%%%s" % (os.environ["DC_USERNAME"],
                                       os.environ["DC_PASSWORD"])
        self.ldb = self.getSamDB("-H", self.server, self.user_auth)

    def tearDown(self):
        super(PwdSettingsCmdTestCase, self).tearDown()

    def test_domain_passwordsettings(self):
        """Checks the 'set/show' commands for the domain settings (non-PSO)"""

        # check the 'show' cmd for the domain settings
        (result, out, err) = self.runsublevelcmd("domain", ("passwordsettings",
                                                 "show"), "-H", self.server,
                                                 self.user_auth)
        self.assertCmdSuccess(result, out, err)
        self.assertEquals(err,"","Shouldn't be any error messages")

        # check an arbitrary setting is displayed correctly
        min_pwd_len = self.ldb.get_minPwdLength()
        self.assertIn("Minimum password length: %s" % min_pwd_len, out)

        # check we can change the domain setting
        self.addCleanup(self.ldb.set_minPwdLength, min_pwd_len)
        new_len = int(min_pwd_len) + 3
        (result, out, err) = self.runsublevelcmd("domain", ("passwordsettings",
                                                 "set"),
                                                 "--min-pwd-length=%u" % new_len,
                                                 "-H", self.server,
                                                 self.user_auth)
        self.assertCmdSuccess(result, out, err)
        self.assertEquals(err,"","Shouldn't be any error messages")
        self.assertIn("successful", out)
        self.assertEquals(str(new_len), self.ldb.get_minPwdLength())

        # check the updated value is now displayed
        (result, out, err) = self.runsublevelcmd("domain", ("passwordsettings",
                                                 "show"), "-H", self.server,
                                                 self.user_auth)
        self.assertCmdSuccess(result, out, err)
        self.assertEquals(err,"","Shouldn't be any error messages")
        self.assertIn("Minimum password length: %u" % new_len, out)

