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

"""
    Tests auth logging tests that exercise SamLogon
"""

import samba.tests
import os
from samba.samdb import SamDB
import samba.tests.auth_log_base
from samba.credentials import (
    Credentials,
    DONT_USE_KERBEROS,
    CLI_CRED_NTLMv2_AUTH
)
from samba.dcerpc import ntlmssp, netlogon
from samba.dcerpc.dcerpc import AS_SYSTEM_MAGIC_PATH_TOKEN
from samba.ndr import ndr_pack
from samba.auth import system_session
from samba.tests import delete_force
from samba.dsdb import UF_WORKSTATION_TRUST_ACCOUNT, UF_PASSWD_NOTREQD
from samba.dcerpc.misc import SEC_CHAN_WKSTA
from samba.compat import text_type
from samba.dcerpc.windows_event_ids import (
    EVT_ID_SUCCESSFUL_LOGON,
    EVT_LOGON_NETWORK
)


class AuthLogTestsSamLogon(samba.tests.auth_log_base.AuthLogTestBase):

    def setUp(self):
        super(AuthLogTestsSamLogon, self).setUp()
        self.lp = samba.tests.env_loadparm()
        self.session = system_session()
        self.ldb = SamDB(
            session_info=self.session,
            lp=self.lp)

        self.domain = os.environ["DOMAIN"]
        self.netbios_name = "SamLogonTest"
        self.machinepass = "abcdefghij"
        self.remoteAddress = AS_SYSTEM_MAGIC_PATH_TOKEN
        self.base_dn = self.ldb.domain_dn()
        self.samlogon_dn = ("cn=%s,cn=users,%s" %
                           (self.netbios_name, self.base_dn))

    def tearDown(self):
        super(AuthLogTestsSamLogon, self).tearDown()
        delete_force(self.ldb, self.samlogon_dn)

    def _test_samlogon(self, binding, creds, checkFunction):

        def isLastExpectedMessage(msg):
            return (
                msg["type"] == "Authentication" and
                msg["Authentication"]["serviceDescription"] == "SamLogon" and
                msg["Authentication"]["authDescription"] == "network" and
                msg["Authentication"]["passwordType"] == "NTLMv2" and
                (msg["Authentication"]["eventId"] ==
                    EVT_ID_SUCCESSFUL_LOGON) and
                (msg["Authentication"]["logonType"] == EVT_LOGON_NETWORK))

        if binding:
            binding = "[schannel,%s]" % binding
        else:
            binding = "[schannel]"

        utf16pw = text_type('"' + self.machinepass + '"').encode('utf-16-le')
        self.ldb.add({
            "dn": self.samlogon_dn,
            "objectclass": "computer",
            "sAMAccountName": "%s$" % self.netbios_name,
            "userAccountControl":
                str(UF_WORKSTATION_TRUST_ACCOUNT | UF_PASSWD_NOTREQD),
            "unicodePwd": utf16pw})

        machine_creds = Credentials()
        machine_creds.guess(self.get_loadparm())
        machine_creds.set_secure_channel_type(SEC_CHAN_WKSTA)
        machine_creds.set_password(self.machinepass)
        machine_creds.set_username(self.netbios_name + "$")

        netlogon_conn = netlogon.netlogon("ncalrpc:%s" % binding,
                                          self.get_loadparm(),
                                          machine_creds)
        challenge = b"abcdefgh"

        target_info = ntlmssp.AV_PAIR_LIST()
        target_info.count = 3

        domainname = ntlmssp.AV_PAIR()
        domainname.AvId = ntlmssp.MsvAvNbDomainName
        domainname.Value = self.domain

        computername = ntlmssp.AV_PAIR()
        computername.AvId = ntlmssp.MsvAvNbComputerName
        computername.Value = self.netbios_name

        eol = ntlmssp.AV_PAIR()
        eol.AvId = ntlmssp.MsvAvEOL
        target_info.pair = [domainname, computername, eol]

        target_info_blob = ndr_pack(target_info)

        response = creds.get_ntlm_response(flags=CLI_CRED_NTLMv2_AUTH,
                                           challenge=challenge,
                                           target_info=target_info_blob)

        netr_flags = 0

        logon_level = netlogon.NetlogonNetworkTransitiveInformation
        logon = samba.dcerpc.netlogon.netr_NetworkInfo()

        logon.challenge = [
            x if isinstance(x, int) else ord(x) for x in challenge]
        logon.nt = netlogon.netr_ChallengeResponse()
        logon.nt.length = len(response["nt_response"])
        logon.nt.data = [
            x if isinstance(x, int) else ord(x) for
            x in response["nt_response"]
        ]
        logon.identity_info = samba.dcerpc.netlogon.netr_IdentityInfo()
        (username, domain) = creds.get_ntlm_username_domain()

        logon.identity_info.domain_name.string = domain
        logon.identity_info.account_name.string = username
        logon.identity_info.workstation.string = creds.get_workstation()

        validation_level = samba.dcerpc.netlogon.NetlogonValidationSamInfo4

        result = netlogon_conn.netr_LogonSamLogonEx(
            os.environ["SERVER"],
            machine_creds.get_workstation(),
            logon_level, logon,
            validation_level, netr_flags)

        (validation, authoritative, netr_flags_out) = result

        messages = self.waitForMessages(isLastExpectedMessage, netlogon_conn)
        checkFunction(messages)

    def samlogon_check(self, messages):

        messages = self.remove_netlogon_messages(messages)
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

    def test_ncalrpc_samlogon(self):

        creds = self.insta_creds(template=self.get_credentials(),
                                 kerberos_state=DONT_USE_KERBEROS)
        try:
            self._test_samlogon("SEAL", creds, self.samlogon_check)
        except Exception as e:
            self.fail("Unexpected exception: " + str(e))
