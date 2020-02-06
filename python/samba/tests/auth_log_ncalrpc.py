# Unix SMB/CIFS implementation.
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

"""Tests for the Auth and AuthZ logging.
"""

import samba.tests
from samba.credentials import DONT_USE_KERBEROS
from samba.dcerpc.dcerpc import AS_SYSTEM_MAGIC_PATH_TOKEN
from samba.dcerpc import samr
import samba.tests.auth_log_base
from samba.dcerpc.windows_event_ids import (
    EVT_ID_SUCCESSFUL_LOGON,
    EVT_LOGON_NETWORK
)


class AuthLogTestsNcalrpc(samba.tests.auth_log_base.AuthLogTestBase):

    def setUp(self):
        super(AuthLogTestsNcalrpc, self).setUp()
        self.remoteAddress = AS_SYSTEM_MAGIC_PATH_TOKEN

    def tearDown(self):
        super(AuthLogTestsNcalrpc, self).tearDown()

    def _test_rpc_ncaclrpc(self, authTypes, binding, creds,
                           protection, checkFunction):

        def isLastExpectedMessage(msg):
            return (
                msg["type"] == "Authorization" and
                msg["Authorization"]["serviceDescription"] == "DCE/RPC" and
                msg["Authorization"]["authType"] == authTypes[0] and
                msg["Authorization"]["transportProtection"] == protection)

        if binding:
            binding = "[%s]" % binding

        samr.samr("ncalrpc:%s" % binding, self.get_loadparm(), creds)
        messages = self.waitForMessages(isLastExpectedMessage)
        checkFunction(messages, authTypes, protection)

    def rpc_ncacn_np_ntlm_check(self, messages, authTypes, protection):

        expected_messages = len(authTypes)
        self.assertEqual(expected_messages,
                          len(messages),
                          "Did not receive the expected number of messages")

        # Check the first message it should be an Authorization
        msg = messages[0]
        self.assertEqual("Authorization", msg["type"])
        self.assertEqual("DCE/RPC",
                          msg["Authorization"]["serviceDescription"])
        self.assertEqual(authTypes[1], msg["Authorization"]["authType"])
        self.assertEqual("NONE", msg["Authorization"]["transportProtection"])
        self.assertTrue(self.is_guid(msg["Authorization"]["sessionId"]))

        # Check the second message it should be an Authentication
        msg = messages[1]
        self.assertEqual("Authentication", msg["type"])
        self.assertEqual("NT_STATUS_OK", msg["Authentication"]["status"])
        self.assertEqual("DCE/RPC",
                          msg["Authentication"]["serviceDescription"])
        self.assertEqual(authTypes[2],
                          msg["Authentication"]["authDescription"])
        self.assertEqual(EVT_ID_SUCCESSFUL_LOGON,
                          msg["Authentication"]["eventId"])
        self.assertEqual(EVT_LOGON_NETWORK,
                          msg["Authentication"]["logonType"])

    def test_ncalrpc_ntlm_dns_sign(self):

        creds = self.insta_creds(template=self.get_credentials(),
                                 kerberos_state=DONT_USE_KERBEROS)
        self._test_rpc_ncaclrpc(["NTLMSSP",
                                 "ncalrpc",
                                 "NTLMSSP"],
                                "", creds, "SIGN",
                                self.rpc_ncacn_np_ntlm_check)

    def test_ncalrpc_ntlm_dns_seal(self):

        creds = self.insta_creds(template=self.get_credentials(),
                                 kerberos_state=DONT_USE_KERBEROS)
        self._test_rpc_ncaclrpc(["NTLMSSP",
                                 "ncalrpc",
                                 "NTLMSSP"],
                                "seal", creds, "SEAL",
                                self.rpc_ncacn_np_ntlm_check)
