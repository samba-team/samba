# Tests to check basic NTLM authentication
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
from samba.credentials import Credentials, DONT_USE_KERBEROS

from samba import NTSTATUSError, ntstatus
import ctypes

from samba import credentials
from samba.dcerpc import srvsvc

"""
Tests basic NTLM authentication
"""

class NtlmAuthTests(TestCase):

    def setUp(self):
        super(NtlmAuthTests, self).setUp()

        self.lp          = self.get_loadparm()



    def tearDown(self):
        super(NtlmAuthTests, self).tearDown()

    def test_ntlm_connection(self):
        server = os.getenv("SERVER")

        creds = credentials.Credentials()
        creds.guess(self.lp)
        creds.set_username(os.getenv("USERNAME"))
        creds.set_domain(server)
        creds.set_password(os.getenv("PASSWORD"))
        creds.set_kerberos_state(DONT_USE_KERBEROS)

        try:
            conn = srvsvc.srvsvc("ncacn_np:%s[smb2,ntlm]" % server, self.lp, creds)

            self.assertIsNotNone(conn)
        except NTSTATUSError as e:
            # NTLM might be blocked on this server
            enum = ctypes.c_uint32(e[0]).value
            if enum == ntstatus.NT_STATUS_NTLM_BLOCKED:
                self.fail("NTLM is disabled on this server")
            else:
                raise


