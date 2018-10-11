# Tests basic behaviour when NTLM is disabled
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
from samba.credentials import Credentials, DONT_USE_KERBEROS, MUST_USE_KERBEROS

from samba import NTSTATUSError, ntstatus
import ctypes

from samba.dcerpc import srvsvc, samr, lsa

"""
Tests behaviour when NTLM is disabled
"""


class NtlmDisabledTests(TestCase):

    def setUp(self):
        super(NtlmDisabledTests, self).setUp()

        self.lp          = self.get_loadparm()
        self.server      = os.getenv("SERVER")

        self.creds = Credentials()
        self.creds.guess(self.lp)
        self.creds.set_username(os.getenv("USERNAME"))
        self.creds.set_domain(self.server)
        self.creds.set_password(os.getenv("PASSWORD"))
        self.creds.set_kerberos_state(DONT_USE_KERBEROS)

    def tearDown(self):
        super(NtlmDisabledTests, self).tearDown()

    def test_ntlm_connection(self):
        try:
            conn = srvsvc.srvsvc("ncacn_np:%s[smb2,ntlm]" % self.server, self.lp, self.creds)

            self.assertIsNotNone(conn)
        except NTSTATUSError as e:
            # NTLM might be blocked on this server
            enum = ctypes.c_uint32(e.args[0]).value
            if enum == ntstatus.NT_STATUS_NTLM_BLOCKED:
                self.fail("NTLM is disabled on this server")
            else:
                raise

    def test_samr_change_password(self):
        self.creds.set_kerberos_state(MUST_USE_KERBEROS)
        conn = samr.samr("ncacn_np:%s[krb5,seal,smb2]" % os.getenv("SERVER"))

        # we want to check whether this gets rejected outright because NTLM is
        # disabled, so we don't actually need to encrypt a valid password here
        server = lsa.String()
        server.string = self.server
        username = lsa.String()
        username.string = os.getenv("USERNAME")

        try:
            conn.ChangePasswordUser2(server, username, None, None, True, None, None)
        except NTSTATUSError as e:
            # changing passwords should be rejected when NTLM is disabled
            enum = ctypes.c_uint32(e.args[0]).value
            if enum == ntstatus.NT_STATUS_NTLM_BLOCKED:
                self.fail("NTLM is disabled on this server")
            elif enum == ntstatus.NT_STATUS_WRONG_PASSWORD:
                # expected error case when NTLM is enabled
                pass
            else:
                raise
