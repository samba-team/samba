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

import ldb
import samba
from samba.tests.samba_tool.base import SambaToolCmdTest
from samba.credentials import Credentials
from samba.samdb import SamDB
from samba.auth import system_session
from samba import dsdb

USER_NAME = "CryptSHATestUser"
HASH_OPTION = "password hash userPassword schemes"


class UserCmdCryptShaTestCase(SambaToolCmdTest):
    """
    Tests for samba-tool user subcommands generation of the virtualCryptSHA256
    and virtualCryptSHA512 attributes
    """
    users = []
    samdb = None

    def _get_attribute(self, out, name):
        parsed = list(self.ldb.parse_ldif(out))
        self.assertEqual(len(parsed), 1)
        changetype, msg = parsed[0]
        return str(msg.get(name, ""))

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
        super().tearDown()
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
        self.assertEqual(err, "Any available password returned OK\n", "getpassword")
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
