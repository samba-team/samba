# Unix SMB/CIFS implementation.
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2019
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
    auth logging tests that exercise winbind
"""

import json
import os
import time

from samba.auth import system_session
from samba.credentials import Credentials
from samba.compat import get_string, get_bytes
from samba.dcerpc.messaging import AUTH_EVENT_NAME, MSG_AUTH_LOG
from samba.dsdb import UF_NORMAL_ACCOUNT
from samba.messaging import Messaging
from samba.param import LoadParm
from samba.samdb import SamDB
from samba.tests import delete_force, BlackboxProcessError, BlackboxTestCase
from samba.tests.auth_log_base import AuthLogTestBase

USER_NAME = "WBALU"


class AuthLogTestsWinbind(AuthLogTestBase, BlackboxTestCase):

    #
    # Helper function to watch for authentication messages on the
    # Domain Controller.
    #
    def dc_watcher(self):

        (r1, w1) = os.pipe()
        pid = os.fork()
        if pid != 0:
            # Parent process return the result socket to the caller.
            return r1

        # Load the lp context for the Domain Controller, rather than the
        # member server.
        config_file = os.environ["DC_SERVERCONFFILE"]
        lp_ctx = LoadParm()
        lp_ctx.load(config_file)

        #
        # Is the message a SamLogon authentication?
        def is_sam_logon(m):
            if m is None:
                return False
            msg = json.loads(m)
            return (
                msg["type"] == "Authentication" and
                msg["Authentication"]["serviceDescription"] == "SamLogon")

        #
        # Handler function for received authentication messages.
        def message_handler(context, msgType, src, message):
            # Print the message to help debugging the tests.
            # as it's a JSON message it does not look like a sub-unit message.
            print(message)
            self.dc_msgs.append(message)

        # Set up a messaging context to listen for authentication events on
        # the domain controller.
        msg_ctx = Messaging((1,), lp_ctx=lp_ctx)
        msg_ctx.irpc_add_name(AUTH_EVENT_NAME)
        msg_handler_and_context = (message_handler, None)
        msg_ctx.register(msg_handler_and_context, msg_type=MSG_AUTH_LOG)

        # Wait for the SamLogon message.
        # As there could be other SamLogon's in progress we need to collect
        # all the SamLogons and let the caller match them to the session.
        self.dc_msgs = []
        start_time = time.time()
        while (time.time() - start_time < 1):
            msg_ctx.loop_once(0.1)

        # Only interested in SamLogon messages, filter out the rest
        msgs = list(filter(is_sam_logon, self.dc_msgs))
        if msgs:
            for m in msgs:
                os.write(w1, get_bytes(m+"\n"))
        else:
            os.write(w1, get_bytes("None\n"))
        os.close(w1)

        msg_ctx.deregister(msg_handler_and_context, msg_type=MSG_AUTH_LOG)
        msg_ctx.irpc_remove_name(AUTH_EVENT_NAME)

        os._exit(0)

    # Remove any DCE/RPC ncacn_np messages
    # these only get triggered once per session, and stripping them out
    # avoids ordering dependencies in the tests
    #
    def filter_messages(self, messages):
        def keep(msg):
            if (msg["type"] == "Authorization" and
                msg["Authorization"]["serviceDescription"] == "DCE/RPC" and
                msg["Authorization"]["authType"] == "ncacn_np"):
                    return False
            else:
                return True

        return list(filter(keep, messages))

    def setUp(self):
        super(AuthLogTestsWinbind, self).setUp()
        self.domain = os.environ["DOMAIN"]
        self.host = os.environ["SERVER"]
        self.dc = os.environ["DC_SERVER"]
        self.lp = self.get_loadparm()
        self.credentials = self.get_credentials()
        self.session = system_session()

        self.ldb = SamDB(
            url="ldap://{0}".format(self.dc),
            session_info=self.session,
            credentials=self.credentials,
            lp=self.lp)
        self.create_user_account()

    def tearDown(self):
        super(AuthLogTestsWinbind, self).tearDown()
        delete_force(self.ldb, self.user_dn)

    #
    # Create a test user account
    def create_user_account(self):
        self.user_pass = self.random_password()
        self.user_name = USER_NAME
        self.user_dn = "cn=%s,%s" % (self.user_name, self.ldb.domain_dn())

        # remove the account if it exists, this will happen if a previous test
        # run failed
        delete_force(self.ldb, self.user_dn)

        utf16pw = ('"%s"' % get_string(self.user_pass)).encode('utf-16-le')
        self.ldb.add({
           "dn": self.user_dn,
           "objectclass": "user",
           "sAMAccountName": "%s" % self.user_name,
           "userAccountControl": str(UF_NORMAL_ACCOUNT),
           "unicodePwd": utf16pw})

        self.user_creds = Credentials()
        self.user_creds.guess(self.get_loadparm())
        self.user_creds.set_password(self.user_pass)
        self.user_creds.set_username(self.user_name)
        self.user_creds.set_workstation(self.server)

    #
    # Check that the domain server received a SamLogon request for the
    # current logon.
    #
    def check_domain_server_authentication(self, pipe, logon_id, description):

        messages = os.read(pipe, 8192)
        messages = get_string(messages)
        if len(messages) == 0 or messages == "None":
            self.fail("No Domain server authentication message")

        #
        # Look for the SamLogon request matching logon_id
        msg = None
        for message in messages.split("\n"):
            msg = json.loads(get_string(message))
            if logon_id == msg["Authentication"]["logonId"]:
                break
            msg = None

        if msg is None:
            self.fail("No Domain server authentication message")

        #
        # Validate that message contains the expected data
        #
        self.assertEqual("Authentication", msg["type"])
        self.assertEqual(logon_id, msg["Authentication"]["logonId"])
        self.assertEqual("SamLogon",
                          msg["Authentication"]["serviceDescription"])
        self.assertEqual(description,
                          msg["Authentication"]["authDescription"])

    def test_ntlm_auth(self):

        def isLastExpectedMessage(msg):
            DESC = "PAM_AUTH, ntlm_auth"
            return (
                msg["type"] == "Authentication" and
                msg["Authentication"]["serviceDescription"] == "winbind" and
                msg["Authentication"]["authDescription"] is not None and
                msg["Authentication"]["authDescription"].startswith(DESC))

        pipe = self.dc_watcher()
        COMMAND = "bin/ntlm_auth"
        self.check_run("{0} --username={1} --password={2}".format(
            COMMAND,
            self.credentials.get_username(),
            self.credentials.get_password()),
            msg="ntlm_auth failed")

        messages = self.waitForMessages(isLastExpectedMessage)
        messages = self.filter_messages(messages)
        expected_messages = 1
        self.assertEqual(expected_messages,
                          len(messages),
                          "Did not receive the expected number of messages")

        # Check the first message it should be an Authentication
        msg = messages[0]
        self.assertEqual("Authentication", msg["type"])
        self.assertTrue(
            msg["Authentication"]["authDescription"].startswith(
                "PAM_AUTH, ntlm_auth,"))
        self.assertEqual("winbind",
                          msg["Authentication"]["serviceDescription"])
        self.assertEqual("Plaintext", msg["Authentication"]["passwordType"])
        # Logon type should be NetworkCleartext
        self.assertEqual(8, msg["Authentication"]["logonType"])
        # Event code should be Successful logon
        self.assertEqual(4624, msg["Authentication"]["eventId"])
        self.assertEqual("unix:", msg["Authentication"]["remoteAddress"])
        self.assertEqual("unix:", msg["Authentication"]["localAddress"])
        self.assertEqual(self.domain, msg["Authentication"]["clientDomain"])
        self.assertEqual("NT_STATUS_OK", msg["Authentication"]["status"])
        self.assertEqual(self.credentials.get_username(),
                          msg["Authentication"]["clientAccount"])
        self.assertEqual(self.credentials.get_domain(),
                          msg["Authentication"]["clientDomain"])
        self.assertTrue(msg["Authentication"]["workstation"] is None)

        logon_id = msg["Authentication"]["logonId"]

        #
        # Now check the Domain server authentication message
        #
        self.check_domain_server_authentication(pipe, logon_id, "interactive")

    def test_wbinfo(self):
        def isLastExpectedMessage(msg):
            DESC = "NTLM_AUTH, wbinfo"
            return (
                msg["type"] == "Authentication" and
                msg["Authentication"]["serviceDescription"] == "winbind" and
                msg["Authentication"]["authDescription"] is not None and
                msg["Authentication"]["authDescription"].startswith(DESC))

        pipe = self.dc_watcher()
        COMMAND = "bin/wbinfo"
        try:
            self.check_run("{0} -a {1}%{2}".format(
                COMMAND,
                self.credentials.get_username(),
                self.credentials.get_password()),
                msg="ntlm_auth failed")
        except BlackboxProcessError:
            pass

        messages = self.waitForMessages(isLastExpectedMessage)
        messages = self.filter_messages(messages)
        expected_messages = 3
        self.assertEqual(expected_messages,
                          len(messages),
                          "Did not receive the expected number of messages")

        # The 1st message should be an Authentication against the local
        # password database
        msg = messages[0]
        self.assertEqual("Authentication", msg["type"])
        self.assertTrue(msg["Authentication"]["authDescription"].startswith(
            "PASSDB, wbinfo,"))
        self.assertEqual("winbind",
                          msg["Authentication"]["serviceDescription"])
        # Logon type should be Interactive
        self.assertEqual(2, msg["Authentication"]["logonType"])
        # Event code should be Unsuccessful logon
        self.assertEqual(4625, msg["Authentication"]["eventId"])
        self.assertEqual("unix:", msg["Authentication"]["remoteAddress"])
        self.assertEqual("unix:", msg["Authentication"]["localAddress"])
        self.assertEqual('', msg["Authentication"]["clientDomain"])
        # This is what the existing winbind implementation returns.
        self.assertEqual("NT_STATUS_NO_SUCH_USER",
                          msg["Authentication"]["status"])
        self.assertEqual("NTLMv2", msg["Authentication"]["passwordType"])
        self.assertEqual(self.credentials.get_username(),
                          msg["Authentication"]["clientAccount"])
        self.assertEqual("", msg["Authentication"]["clientDomain"])

        logon_id = msg["Authentication"]["logonId"]

        # The 2nd message should be a PAM_AUTH with the same logon id as the
        # 1st message
        msg = messages[1]
        self.assertEqual("Authentication", msg["type"])
        self.assertTrue(msg["Authentication"]["authDescription"].startswith(
            "PAM_AUTH"))
        self.assertEqual("winbind",
                          msg["Authentication"]["serviceDescription"])
        self.assertEqual(logon_id, msg["Authentication"]["logonId"])
        # Logon type should be NetworkCleartext
        self.assertEqual(8, msg["Authentication"]["logonType"])
        # Event code should be Unsuccessful logon
        self.assertEqual(4625, msg["Authentication"]["eventId"])
        self.assertEqual("unix:", msg["Authentication"]["remoteAddress"])
        self.assertEqual("unix:", msg["Authentication"]["localAddress"])
        self.assertEqual('', msg["Authentication"]["clientDomain"])
        # This is what the existing winbind implementation returns.
        self.assertEqual("NT_STATUS_NO_SUCH_USER",
                          msg["Authentication"]["status"])
        self.assertEqual(self.credentials.get_username(),
                          msg["Authentication"]["clientAccount"])
        self.assertEqual("", msg["Authentication"]["clientDomain"])

        # The 3rd message should be an NTLM_AUTH
        msg = messages[2]
        self.assertEqual("Authentication", msg["type"])
        self.assertTrue(msg["Authentication"]["authDescription"].startswith(
            "NTLM_AUTH, wbinfo,"))
        self.assertEqual("winbind",
                          msg["Authentication"]["serviceDescription"])
        # Logon type should be Network
        self.assertEqual(3, msg["Authentication"]["logonType"])
        self.assertEqual("NT_STATUS_OK", msg["Authentication"]["status"])
        # Event code should be successful logon
        self.assertEqual(4624, msg["Authentication"]["eventId"])
        self.assertEqual("NTLMv2", msg["Authentication"]["passwordType"])
        self.assertEqual("unix:", msg["Authentication"]["remoteAddress"])
        self.assertEqual("unix:", msg["Authentication"]["localAddress"])
        self.assertEqual(self.credentials.get_username(),
                          msg["Authentication"]["clientAccount"])
        self.assertEqual(self.credentials.get_domain(),
                          msg["Authentication"]["clientDomain"])

        logon_id = msg["Authentication"]["logonId"]

        #
        # Now check the Domain server authentication message
        #
        self.check_domain_server_authentication(pipe, logon_id, "network")

    def test_wbinfo_ntlmv1(self):
        def isLastExpectedMessage(msg):
            DESC = "NTLM_AUTH, wbinfo"
            return (
                msg["type"] == "Authentication" and
                msg["Authentication"]["serviceDescription"] == "winbind" and
                msg["Authentication"]["authDescription"] is not None and
                msg["Authentication"]["authDescription"].startswith(DESC))

        pipe = self.dc_watcher()
        COMMAND = "bin/wbinfo"
        try:
            self.check_run("{0} --ntlmv1 -a {1}%{2}".format(
                COMMAND,
                self.credentials.get_username(),
                self.credentials.get_password()),
                msg="ntlm_auth failed")
        except BlackboxProcessError:
            pass

        messages = self.waitForMessages(isLastExpectedMessage)
        messages = self.filter_messages(messages)
        expected_messages = 3
        self.assertEqual(expected_messages,
                          len(messages),
                          "Did not receive the expected number of messages")

        # The 1st message should be an Authentication against the local
        # password database
        msg = messages[0]
        self.assertEqual("Authentication", msg["type"])
        self.assertTrue(msg["Authentication"]["authDescription"].startswith(
            "PASSDB, wbinfo,"))
        self.assertEqual("winbind",
                          msg["Authentication"]["serviceDescription"])
        # Logon type should be Interactive
        self.assertEqual(2, msg["Authentication"]["logonType"])
        # Event code should be Unsuccessful logon
        self.assertEqual(4625, msg["Authentication"]["eventId"])
        self.assertEqual("unix:", msg["Authentication"]["remoteAddress"])
        self.assertEqual("unix:", msg["Authentication"]["localAddress"])
        self.assertEqual('', msg["Authentication"]["clientDomain"])
        # This is what the existing winbind implementation returns.
        self.assertEqual("NT_STATUS_NO_SUCH_USER",
                          msg["Authentication"]["status"])
        self.assertEqual("NTLMv2", msg["Authentication"]["passwordType"])
        self.assertEqual(self.credentials.get_username(),
                          msg["Authentication"]["clientAccount"])
        self.assertEqual("", msg["Authentication"]["clientDomain"])

        logon_id = msg["Authentication"]["logonId"]

        # The 2nd message should be a PAM_AUTH with the same logon id as the
        # 1st message
        msg = messages[1]
        self.assertEqual("Authentication", msg["type"])
        self.assertTrue(msg["Authentication"]["authDescription"].startswith(
            "PAM_AUTH"))
        self.assertEqual("winbind",
                          msg["Authentication"]["serviceDescription"])
        self.assertEqual(logon_id, msg["Authentication"]["logonId"])
        self.assertEqual("Plaintext", msg["Authentication"]["passwordType"])
        # Logon type should be NetworkCleartext
        self.assertEqual(8, msg["Authentication"]["logonType"])
        # Event code should be Unsuccessful logon
        self.assertEqual(4625, msg["Authentication"]["eventId"])
        self.assertEqual("unix:", msg["Authentication"]["remoteAddress"])
        self.assertEqual("unix:", msg["Authentication"]["localAddress"])
        self.assertEqual('', msg["Authentication"]["clientDomain"])
        # This is what the existing winbind implementation returns.
        self.assertEqual("NT_STATUS_NO_SUCH_USER",
                          msg["Authentication"]["status"])
        self.assertEqual(self.credentials.get_username(),
                          msg["Authentication"]["clientAccount"])
        self.assertEqual("", msg["Authentication"]["clientDomain"])

        # The 3rd message should be an NTLM_AUTH
        msg = messages[2]
        self.assertEqual("Authentication", msg["type"])
        self.assertTrue(msg["Authentication"]["authDescription"].startswith(
            "NTLM_AUTH, wbinfo,"))
        self.assertEqual("winbind",
                          msg["Authentication"]["serviceDescription"])
        self.assertEqual("NTLMv1",
                          msg["Authentication"]["passwordType"])
        # Logon type should be Network
        self.assertEqual(3, msg["Authentication"]["logonType"])
        self.assertEqual("NT_STATUS_OK", msg["Authentication"]["status"])
        # Event code should be successful logon
        self.assertEqual(4624, msg["Authentication"]["eventId"])
        self.assertEqual("unix:", msg["Authentication"]["remoteAddress"])
        self.assertEqual("unix:", msg["Authentication"]["localAddress"])
        self.assertEqual(self.credentials.get_username(),
                          msg["Authentication"]["clientAccount"])
        self.assertEqual(self.credentials.get_domain(),
                          msg["Authentication"]["clientDomain"])

        logon_id = msg["Authentication"]["logonId"]
        #
        # Now check the Domain server authentication message
        #
        self.check_domain_server_authentication(pipe, logon_id, "network")
