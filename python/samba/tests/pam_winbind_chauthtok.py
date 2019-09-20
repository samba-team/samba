# Unix SMB/CIFS implementation.
#
# Copyright (C) 2017      Andreas Schneider <asn@samba.org>
# Copyright (C) 2018      Mathieu Parent <math.parent@gmail.com>
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
    def test_chauthtok(self):
        domain = os.environ["DOMAIN"]
        username = os.environ["USERNAME"]
        password = os.environ["PASSWORD"]
        newpassword = os.environ["NEWPASSWORD"]
        if domain != "":
            unix_username = "%s/%s" % (domain, username)
        else:
            unix_username = "%s" % username
        expected_rc = 0 # PAM_SUCCESS

        tc = pypamtest.TestCase(pypamtest.PAMTEST_CHAUTHTOK, expected_rc)
        try:
            res = pypamtest.run_pamtest(unix_username, "samba", [tc], [password, newpassword, newpassword])
        except pypamtest.PamTestError as e:
            raise AssertionError(str(e))

        self.assertTrue(res is not None)
