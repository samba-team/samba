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

class SimplePamTests(samba.tests.TestCase):
    def test_authenticate(self):
        alice_password = "Secret007"
        expected_rc = 0 # PAM_SUCCESS

        tc = pypamtest.TestCase(pypamtest.PAMTEST_AUTHENTICATE, expected_rc)
        res = pypamtest.run_pamtest("SAMBADOMAIN/alice", "samba", [tc], [alice_password])

        self.assertTrue(res != None)

    def test_authenticate_error(self):
        alice_password = "WrongPassword"
        expected_rc = 7 # PAM_AUTH_ERR

        tc = pypamtest.TestCase(pypamtest.PAMTEST_AUTHENTICATE, expected_rc)
        res = pypamtest.run_pamtest("SAMBADOMAIN/alice", "samba", [tc], [alice_password])

        self.assertTrue(res != None)
