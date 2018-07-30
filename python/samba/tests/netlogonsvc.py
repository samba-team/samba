# Tests to check the netlogon service is only running when it's required
#
# Copyright (C) Catalyst IT Ltd. 2017
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
from samba.tests import TestCase
import os

import samba
from samba.credentials import Credentials
from samba.dcerpc import netlogon
from samba import NTSTATUSError, ntstatus
import ctypes

"""
Tests whether the netlogon service is running
"""


class NetlogonServiceTests(TestCase):

    def setUp(self):
        super(NetlogonServiceTests, self).setUp()

        self.server      = os.environ["SERVER"]
        self.lp          = self.get_loadparm()
        self.creds = Credentials()

        # prefer the DC user/password in environments that have it
        if "DC_USERNAME" in os.environ and "DC_PASSWORD" in os.environ:
            self.creds.set_username(os.environ["DC_USERNAME"])
            self.creds.set_password(os.environ["DC_PASSWORD"])
        else:
            self.creds.set_username(os.environ["USERNAME"])
            self.creds.set_password(os.environ["PASSWORD"])

        self.creds.guess(self.lp)

    def tearDown(self):
        super(NetlogonServiceTests, self).tearDown()

    def test_have_netlogon_connection(self):
        try:
            c = self.get_netlogon_connection()
            self.assertIsNotNone(c)
        except NTSTATUSError as e:
            # On non-DC test environments, netlogon should not be running on
            # the server, so we expect the test to fail here
            enum = ctypes.c_uint32(e.args[0]).value
            if enum == ntstatus.NT_STATUS_OBJECT_NAME_NOT_FOUND:
                self.fail("netlogon service is not running")
            else:
                raise

    # Establish netlogon connection over NP
    def get_netlogon_connection(self):
        return netlogon.netlogon("ncacn_np:%s[seal]" % self.server, self.lp,
                                 self.creds)
