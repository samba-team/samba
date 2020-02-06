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
    Tests that exercise auth logging for unsuccessful netlogon attempts.

    NOTE: netlogon is only done once per session, so this file should only
          test failed logons.  Adding a successful case will potentially break
          the other tests, depending on the order of execution.
"""

import samba.tests
import os
from samba import NTSTATUSError
from samba.samdb import SamDB
import samba.tests.auth_log_base
from samba.credentials import Credentials
from samba.dcerpc import netlogon
from samba.dcerpc.dcerpc import AS_SYSTEM_MAGIC_PATH_TOKEN
from samba.auth import system_session
from samba.tests import delete_force
from samba.dsdb import UF_WORKSTATION_TRUST_ACCOUNT, UF_PASSWD_NOTREQD
from samba.dcerpc.misc import SEC_CHAN_WKSTA
from samba.dcerpc.netlogon import NETLOGON_NEG_STRONG_KEYS
from samba.compat import get_string
from samba.dcerpc.windows_event_ids import (
    EVT_ID_UNSUCCESSFUL_LOGON,
    EVT_LOGON_NETWORK
)


class AuthLogTestsNetLogonBadCreds(samba.tests.auth_log_base.AuthLogTestBase):

    def setUp(self):
        super(AuthLogTestsNetLogonBadCreds, self).setUp()
        self.lp = samba.tests.env_loadparm()
        self.session = system_session()
        self.ldb = SamDB(
            session_info=self.session,
            lp=self.lp)

        self.domain = os.environ["DOMAIN"]
        self.netbios_name = "NetLogonBad"
        self.machinepass = "abcdefghij"
        self.remoteAddress = AS_SYSTEM_MAGIC_PATH_TOKEN
        self.base_dn = self.ldb.domain_dn()
        self.dn = ("cn=%s,cn=users,%s" % (self.netbios_name, self.base_dn))

        utf16pw = get_string('"' + self.machinepass + '"').encode('utf-16-le')
        self.ldb.add({
            "dn": self.dn,
            "objectclass": "computer",
            "sAMAccountName": "%s$" % self.netbios_name,
            "userAccountControl":
                str(UF_WORKSTATION_TRUST_ACCOUNT | UF_PASSWD_NOTREQD),
            "unicodePwd": utf16pw})

    def tearDown(self):
        super(AuthLogTestsNetLogonBadCreds, self).tearDown()
        delete_force(self.ldb, self.dn)

    def _test_netlogon(self, name, pwd, status, checkFunction, event_id):

        def isLastExpectedMessage(msg):
            return (
                msg["type"] == "Authentication" and
                msg["Authentication"]["serviceDescription"] == "NETLOGON" and
                msg["Authentication"]["authDescription"] ==
                "ServerAuthenticate" and
                msg["Authentication"]["status"] == status and
                msg["Authentication"]["eventId"] == event_id and
                msg["Authentication"]["logonType"] == EVT_LOGON_NETWORK)

        machine_creds = Credentials()
        machine_creds.guess(self.get_loadparm())
        machine_creds.set_secure_channel_type(SEC_CHAN_WKSTA)
        machine_creds.set_password(pwd)
        machine_creds.set_username(name + "$")

        try:
            netlogon.netlogon("ncalrpc:[schannel]",
                              self.get_loadparm(),
                              machine_creds)
            self.fail("NTSTATUSError not raised")
        except NTSTATUSError:
            pass

        messages = self.waitForMessages(isLastExpectedMessage)
        checkFunction(messages)

    def netlogon_check(self, messages):

        expected_messages = 4
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

    def test_netlogon_bad_machine_name(self):
        self._test_netlogon("bad_name",
                            self.machinepass,
                            "NT_STATUS_NO_TRUST_SAM_ACCOUNT",
                            self.netlogon_check,
                            EVT_ID_UNSUCCESSFUL_LOGON)

    def test_netlogon_bad_password(self):
        self._test_netlogon(self.netbios_name,
                            "badpass",
                            "NT_STATUS_ACCESS_DENIED",
                            self.netlogon_check,
                            EVT_ID_UNSUCCESSFUL_LOGON)

    def test_netlogon_password_DES(self):
        """Logon failure that exercises the "DES" passwordType path.
        """
        def isLastExpectedMessage(msg):
            return (
                msg["type"] == "Authentication" and
                msg["Authentication"]["serviceDescription"] == "NETLOGON" and
                msg["Authentication"]["authDescription"] ==
                "ServerAuthenticate" and
                msg["Authentication"]["passwordType"] == "DES" and
                (msg["Authentication"]["eventId"] ==
                    EVT_ID_UNSUCCESSFUL_LOGON) and
                msg["Authentication"]["logonType"] == EVT_LOGON_NETWORK)

        c = netlogon.netlogon("ncalrpc:[schannel]", self.get_loadparm())
        creds = netlogon.netr_Credential()
        c.netr_ServerReqChallenge(self.server, self.netbios_name, creds)
        try:
            c.netr_ServerAuthenticate3(self.server,
                                       self.netbios_name,
                                       SEC_CHAN_WKSTA,
                                       self.netbios_name,
                                       creds,
                                       0)
        except NTSTATUSError:
            pass
        self.waitForMessages(isLastExpectedMessage)

    def test_netlogon_password_HMAC_MD5(self):
        """Logon failure that exercises the "HMAC-MD5" passwordType path.
        """
        def isLastExpectedMessage(msg):
            return (
                msg["type"] == "Authentication" and
                msg["Authentication"]["serviceDescription"] == "NETLOGON" and
                msg["Authentication"]["authDescription"] ==
                "ServerAuthenticate" and
                msg["Authentication"]["passwordType"] == "HMAC-MD5" and
                (msg["Authentication"]["eventId"] ==
                    EVT_ID_UNSUCCESSFUL_LOGON) and
                msg["Authentication"]["logonType"] == EVT_LOGON_NETWORK)

        c = netlogon.netlogon("ncalrpc:[schannel]", self.get_loadparm())
        creds = netlogon.netr_Credential()
        c.netr_ServerReqChallenge(self.server, self.netbios_name, creds)
        try:
            c.netr_ServerAuthenticate3(self.server,
                                       self.netbios_name,
                                       SEC_CHAN_WKSTA,
                                       self.netbios_name,
                                       creds,
                                       NETLOGON_NEG_STRONG_KEYS)
        except NTSTATUSError:
            pass
        self.waitForMessages(isLastExpectedMessage)
