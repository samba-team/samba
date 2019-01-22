# Unix SMB/CIFS implementation.
# Copyright (C) Sean Dague <sdague@linux.vnet.ibm.com> 2011
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
import time
import ldb
from samba.tests.samba_tool.base import SambaToolCmdTest
from samba import (
        nttime2unix,
        dsdb
        )


class UserCheckPwdTestCase(SambaToolCmdTest):
    """Tests for samba-tool user subcommands"""
    users = []
    samdb = None

    def setUp(self):
        super(UserCheckPwdTestCase, self).setUp()
        self.samdb = self.getSamDB("-H", "ldap://%s" % os.environ["DC_SERVER"],
                                   "-U%s%%%s" % (os.environ["DC_USERNAME"], os.environ["DC_PASSWORD"]))
        self.old_min_pwd_age = self.samdb.get_minPwdAge()
        self.samdb.set_minPwdAge("0")

    def tearDown(self):
        super(UserCheckPwdTestCase, self).tearDown()
        self.samdb.set_minPwdAge(self.old_min_pwd_age)

    def _test_checkpassword(self, user, bad_password, good_password, desc):

        (result, out, err) = self.runsubcmd("user", "add", user["name"], bad_password,
                                            "-H", "ldap://%s" % os.environ["DC_SERVER"],
                                            "-U%s%%%s" % (os.environ["DC_USERNAME"], os.environ["DC_PASSWORD"]))
        self.assertCmdFail(result, "Should fail adding a user with %s password." % desc)
        (result, out, err) = self.runsubcmd("user", "delete", user["name"],
                                            "-H", "ldap://%s" % os.environ["DC_SERVER"],
                                            "-U%s%%%s" % (os.environ["DC_USERNAME"], os.environ["DC_PASSWORD"]))
        self.assertCmdSuccess(result, out, err, "Should delete user with %s password." % desc)

        (result, out, err) = self.runsubcmd("user", "add", user["name"], good_password,
                                            "-H", "ldap://%s" % os.environ["DC_SERVER"],
                                            "-U%s%%%s" % (os.environ["DC_USERNAME"], os.environ["DC_PASSWORD"]))
        self.assertCmdSuccess(result, out, err, "Should succeed adding a user with good password.")

        # Set password
        (result, out, err) = self.runsubcmd("user", "setpassword", user["name"],
                                            "--newpassword=%s" % bad_password,
                                            "-H", "ldap://%s" % os.environ["DC_SERVER"],
                                            "-U%s%%%s" % (os.environ["DC_USERNAME"], os.environ["DC_PASSWORD"]))
        self.assertCmdFail(result, "Should fail setting a user's password to a %s password." % desc)

        (result, out, err) = self.runsubcmd("user", "setpassword", user["name"],
                                            "--newpassword=%s" % good_password,
                                            "-H", "ldap://%s" % os.environ["DC_SERVER"],
                                            "-U%s%%%s" % (os.environ["DC_USERNAME"], os.environ["DC_PASSWORD"]))
        self.assertCmdSuccess(result, out, err, "Should succeed setting a user's password to a good one.")

        # Password=

        (result, out, err) = self.runsubcmd("user", "password",
                                            "--newpassword=%s" % bad_password,
                                            "--ipaddress", os.environ["DC_SERVER_IP"],
                                            "-U%s%%%s" % (user["name"], good_password))
        self.assertCmdFail(result, "A user setting their own password to a %s password should fail." % desc)

        (result, out, err) = self.runsubcmd("user", "password",
                                            "--newpassword=%s" % good_password + 'XYZ',
                                            "--ipaddress", os.environ["DC_SERVER_IP"],
                                            "-U%s%%%s" % (user["name"], good_password))
        self.assertCmdSuccess(result, out, err, "A user setting their own password to a good one should succeed.")

    def test_checkpassword_unacceptable(self):
        # Add
        user = self._randomUser()
        bad_password = os.environ["UNACCEPTABLE_PASSWORD"]
        good_password = bad_password[:-1]
        return self._test_checkpassword(user,
                                        bad_password,
                                        good_password,
                                        "unacceptable")

    def test_checkpassword_username(self):
        # Add
        user = self._randomUser()
        bad_password = user["name"]
        good_password = bad_password[:-1]
        return self._test_checkpassword(user,
                                        bad_password,
                                        good_password,
                                        "username")

    def _randomUser(self, base={}):
        """create a user with random attribute values, you can specify base attributes"""
        user = {
            "name": self.randomName(),
        }
        user.update(base)
        return user
