# Tests for the samba-tool user sub command reading Primary:userPassword
#
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2017
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
import time
import base64
import ldb
import samba
from samba.tests.samba_tool.base import SambaToolCmdTest
from samba.credentials import Credentials
from samba.samdb import SamDB
from samba.auth import system_session
from samba.ndr import ndr_unpack
from samba.dcerpc import drsblobs
from samba import dsdb
import re

USER_NAME = "CryptSHATestUser"
HASH_OPTION = "password hash userPassword schemes"

# Get the value of an attribute from the output string
# Note: Does not correctly handle values spanning multiple lines,
#       which is acceptable for it's usage in these tests.


def _get_attribute(out, name):
    p = re.compile("^" + name + ":\s+(\S+)")
    for line in out.split("\n"):
        m = p.match(line)
        if m:
            return m.group(1)
    return ""


class UserCmdCryptShaTestCase(SambaToolCmdTest):
    """
    Tests for samba-tool user subcommands generation of the virtualCryptSHA256
    and virtualCryptSHA512 attributes
    """
    users = []
    samdb = None

    def setUp(self):
        super(UserCmdCryptShaTestCase, self).setUp()

    def add_user(self, hashes=""):
        self.lp = samba.tests.env_loadparm()

        # set the extra hashes to be calculated
        self.lp.set(HASH_OPTION, hashes)

        self.creds = Credentials()
        self.session = system_session()
        self.ldb = SamDB(
            session_info=self.session,
            credentials=self.creds,
            lp=self.lp)

        password = self.random_password()
        self.runsubcmd("user",
                       "create",
                       USER_NAME,
                       password)

    def tearDown(self):
        super(UserCmdCryptShaTestCase, self).tearDown()
        self.runsubcmd("user", "delete", USER_NAME)

    def _get_password(self, attributes, decrypt=False):
        command = ["user",
                   "getpassword",
                   USER_NAME,
                   "--attributes",
                   attributes]
        if decrypt:
            command.append("--decrypt-samba-gpg")

        (result, out, err) = self.runsubcmd(*command)
        self.assertCmdSuccess(result,
                              out,
                              err,
                              "Ensure getpassword runs")
        self.assertEqual(err, "", "getpassword")
        self.assertMatch(out,
                         "Got password OK",
                         "getpassword out[%s]" % out)
        return out

    # Change the just the NT password hash, as would happen if the password
    # was updated by Windows, the userPassword values are now obsolete.
    #
    def _change_nt_hash(self):
        res = self.ldb.search(expression = "cn=%s" % USER_NAME,
                              scope      = ldb.SCOPE_SUBTREE)
        msg = ldb.Message()
        msg.dn = res[0].dn
        msg["unicodePwd"] = ldb.MessageElement(b"ABCDEF1234567890",
                                               ldb.FLAG_MOD_REPLACE,
                                               "unicodePwd")
        self.ldb.modify(
            msg,
            controls=["local_oid:%s:0" %
                      dsdb.DSDB_CONTROL_BYPASS_PASSWORD_HASH_OID])
