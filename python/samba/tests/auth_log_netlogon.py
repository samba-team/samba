# Unix SMB/CIFS implementation.
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2017
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

"""
    Tests that exercise the auth logging for a successful netlogon attempt

    NOTE: As the netlogon authentication is performed once per session,
          there is only one test in this routine.  If another test is added
          only the test executed first will generate the netlogon auth message
"""

import samba.tests
import os
from samba.samdb import SamDB
import samba.tests.auth_log_base
from samba.credentials import Credentials
from samba.dcerpc import netlogon
from samba.dcerpc.dcerpc import AS_SYSTEM_MAGIC_PATH_TOKEN
from samba.auth import system_session
from samba.tests import delete_force
from samba.dsdb import UF_WORKSTATION_TRUST_ACCOUNT, UF_PASSWD_NOTREQD
from samba.dcerpc.misc import SEC_CHAN_WKSTA
from samba.compat import text_type
from samba.dcerpc.windows_event_ids import (
    EVT_ID_SUCCESSFUL_LOGON,
    EVT_LOGON_NETWORK
)


class AuthLogTestsNetLogon(samba.tests.auth_log_base.AuthLogTestBase):

    def setUp(self):
        super(AuthLogTestsNetLogon, self).setUp()
        self.lp = samba.tests.env_loadparm()
        self.session = system_session()
        self.ldb = SamDB(
            session_info=self.session,
            lp=self.lp)

        self.domain = os.environ["DOMAIN"]
        self.netbios_name = "NetLogonGood"
        self.machinepass = "abcdefghij"
        self.remoteAddress = AS_SYSTEM_MAGIC_PATH_TOKEN
        self.base_dn = self.ldb.domain_dn()
        self.dn = ("cn=%s,cn=users,%s" % (self.netbios_name, self.base_dn))

        utf16pw = text_type('"' + self.machinepass + '"').encode('utf-16-le')
        self.ldb.add({
            "dn": self.dn,
            "objectclass": "computer",
            "sAMAccountName": "%s$" % self.netbios_name,
            "userAccountControl":
                str(UF_WORKSTATION_TRUST_ACCOUNT | UF_PASSWD_NOTREQD),
            "unicodePwd": utf16pw})

    def tearDown(self):
        super(AuthLogTestsNetLogon, self).tearDown()
        delete_force(self.ldb, self.dn)

    def _test_netlogon(self, binding, checkFunction):

        def isLastExpectedMessage(msg):
            return (
                msg["type"] == "Authorization" and
                msg["Authorization"]["serviceDescription"] == "DCE/RPC" and
                msg["Authorization"]["authType"] == "schannel" and
                msg["Authorization"]["transportProtection"] == "SEAL")

        if binding:
            binding = "[schannel,%s]" % binding
        else:
            binding = "[schannel]"

        machine_creds = Credentials()
        machine_creds.guess(self.get_loadparm())
        machine_creds.set_secure_channel_type(SEC_CHAN_WKSTA)
        machine_creds.set_password(self.machinepass)
        machine_creds.set_username(self.netbios_name + "$")

        netlogon_conn = netlogon.netlogon("ncalrpc:%s" % binding,
                                          self.get_loadparm(),
                                          machine_creds)

        messages = self.waitForMessages(isLastExpectedMessage, netlogon_conn)
        checkFunction(messages)

    def netlogon_check(self, messages):

        expected_messages = 5
        self.assertEqual(expected_messages,
                          len(messages),
                          "Did not receive the expected number of messages")

        # Check the first message it should be an Authorization
        msg = messages[0]
        self.assertEqual("Authorization", msg["type"])
        self.assertEqual("DCE/RPC",
                          msg["Authorization"]["serviceDescription"])
        self.assertEqual("ncalrpc", msg["Authorization"]["authType"])
        self.assertEqual("NONE", msg["Authorization"]["transportProtection"])
        self.assertTrue(self.is_guid(msg["Authorization"]["sessionId"]))

        # Check the fourth message it should be a NETLOGON Authentication
        msg = messages[3]
        self.assertEqual("Authentication", msg["type"])
        self.assertEqual("NETLOGON",
                          msg["Authentication"]["serviceDescription"])
        self.assertEqual("ServerAuthenticate",
                          msg["Authentication"]["authDescription"])
        self.assertEqual("NT_STATUS_OK",
                          msg["Authentication"]["status"])
        self.assertEqual("HMAC-SHA256",
                          msg["Authentication"]["passwordType"])
        self.assertEqual(EVT_ID_SUCCESSFUL_LOGON,
                          msg["Authentication"]["eventId"])
        self.assertEqual(EVT_LOGON_NETWORK,
                          msg["Authentication"]["logonType"])

    def test_netlogon(self):
        self._test_netlogon("SEAL", self.netlogon_check)
