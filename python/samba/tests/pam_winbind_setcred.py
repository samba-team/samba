# Unix SMB/CIFS implementation.
#
# Copyright (C) 2022      Samuel Cabrero <scabrero@samba.org>
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

import samba.tests
import pypamtest
import os

class PamChauthtokTests(samba.tests.TestCase):
    def test_setcred_delete_cred(self):
        domain = os.environ["DOMAIN"]
        username = os.environ["USERNAME"]
        password = os.environ["PASSWORD"]

        if domain != "":
            unix_username = "%s/%s" % (domain, username)
        else:
            unix_username = "%s" % username
        expected_rc = 0 # PAM_SUCCESS

        tc = pypamtest.TestCase(pypamtest.PAMTEST_AUTHENTICATE, expected_rc)
        tc1 = pypamtest.TestCase(pypamtest.PAMTEST_GETENVLIST, expected_rc)
        tc2 = pypamtest.TestCase(pypamtest.PAMTEST_KEEPHANDLE, expected_rc)
        try:
            res = pypamtest.run_pamtest(unix_username, "samba", [tc, tc1, tc2], [password])
        except pypamtest.PamTestError as e:
            raise AssertionError(str(e))

        self.assertTrue(res is not None)

        ccache = tc1.pam_env["KRB5CCNAME"]
        ccache = ccache[ccache.index(":") + 1:]
        self.assertTrue(os.path.exists(ccache))

        handle = tc2.pam_handle
        tc3 = pypamtest.TestCase(pypamtest.PAMTEST_SETCRED, expected_rc, pypamtest.PAMTEST_FLAG_DELETE_CRED)
        try:
            res = pypamtest.run_pamtest(unix_username, "samba", [tc3], handle=handle)
        except pypamtest.PamTestError as e:
            raise AssertionError(str(e))

        self.assertFalse(os.path.exists(ccache))
