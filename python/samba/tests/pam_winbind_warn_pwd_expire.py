# Unix SMB/CIFS implementation.
#
# Copyright (C) 2017      Andreas Schneider <asn@samba.org>
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


class PasswordExpirePamTests(samba.tests.TestCase):
    def test_auth_expire_warning(self):
        domain = os.environ["DOMAIN"]
        username = os.environ["USERNAME"]
        password = os.environ["PASSWORD"]
        warn_pwd_expire = int(os.environ["WARN_PWD_EXPIRE"])
        if domain != "":
            unix_username = "%s/%s" % (domain, username)
        else:
            unix_username = "%s" % username
        expected_rc = 0  # PAM_SUCCESS

        tc = pypamtest.TestCase(pypamtest.PAMTEST_AUTHENTICATE, expected_rc)
        try:
            res = pypamtest.run_pamtest(unix_username, "samba", [tc], [password])
        except pypamtest.PamTestError as e:
            raise AssertionError(str(e))

        self.assertTrue(res is not None)
        if warn_pwd_expire == 0:
            self.assertTrue(res.info == ())
        elif warn_pwd_expire == 50:
            # This is needed as otherwise a build started around
            # midnight can fail
            if (res.info[0] != u"Your password will expire in 41 days.\n") and \
               (res.info[0] != u"Your password will expire in 43 days.\n"):
                self.assertEqual(res.info[0], u"Your password will expire in 42 days.\n")
        else:
            self.assertEqual(warn_pwd_expire, 0)
