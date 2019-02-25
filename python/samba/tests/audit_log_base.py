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

from __future__ import print_function
"""Tests for DSDB audit logging.
"""

import samba.tests
from samba.messaging import Messaging
from samba.dcerpc.messaging import MSG_AUTH_LOG, AUTH_EVENT_NAME
from samba.param import LoadParm
import time
import json
import os
import re


def getAudit(message):
    if "type" not in message:
        return None

    type = message["type"]
    audit = message[type]
    return audit


class AuditLogTestBase(samba.tests.TestCase):

    def setUp(self):
        super(AuditLogTestBase, self).setUp()

        # connect to the server's messaging bus (we need to explicitly load a
        # different smb.conf here, because in all other respects this test
        # wants to act as a separate remote client)
        server_conf = os.getenv('SERVERCONFFILE')
        if server_conf:
            lp_ctx = LoadParm(filename_for_non_global_lp=server_conf)
        else:
            lp_ctx = self.get_loadparm()
        self.msg_ctx = Messaging((1,), lp_ctx=lp_ctx)
        self.msg_ctx.irpc_add_name(self.event_type)

        # Now switch back to using the client-side smb.conf. The tests will
        # use the first interface in the client.conf (we need to strip off
        # the subnet mask portion)
        lp_ctx = self.get_loadparm()
        client_ip_and_mask = lp_ctx.get('interfaces')[0]
        client_ip = client_ip_and_mask.split('/')[0]

        # the messaging ctx is the server's view of the world, so our own
        # client IP will be the remoteAddress when connections are logged
        self.remoteAddress = client_ip

        #
        # Check the remote address of a message against the one beimg used
        # for the tests.
        #
        def isRemote(message):
            audit = getAudit(message)
            if audit is None:
                return False

            remote = audit["remoteAddress"]
            if remote is None:
                return False

            try:
                addr = remote.split(":")
                return addr[1] == self.remoteAddress
            except IndexError:
                return False

        def messageHandler(context, msgType, src, message):
            # This does not look like sub unit output and it
            # makes these tests much easier to debug.
            print(message)
            jsonMsg = json.loads(message)
            if ((jsonMsg["type"] == "passwordChange" or
                jsonMsg["type"] == "dsdbChange" or
                jsonMsg["type"] == "groupChange") and
                    isRemote(jsonMsg)):
                context["messages"].append(jsonMsg)
            elif jsonMsg["type"] == "dsdbTransaction":
                context["txnMessage"] = jsonMsg

        self.context = {"messages": [], "txnMessage": None}
        self.msg_handler_and_context = (messageHandler, self.context)
        self.msg_ctx.register(self.msg_handler_and_context,
                              msg_type=self.message_type)

        self.msg_ctx.irpc_add_name(AUTH_EVENT_NAME)

        def authHandler(context, msgType, src, message):
            jsonMsg = json.loads(message)
            if jsonMsg["type"] == "Authorization" and isRemote(jsonMsg):
                # This does not look like sub unit output and it
                # makes these tests much easier to debug.
                print(message)
                context["sessionId"] = jsonMsg["Authorization"]["sessionId"]
                context["serviceDescription"] =\
                    jsonMsg["Authorization"]["serviceDescription"]

        self.auth_context = {"sessionId": "", "serviceDescription": ""}
        self.auth_handler_and_context = (authHandler, self.auth_context)
        self.msg_ctx.register(self.auth_handler_and_context,
                              msg_type=MSG_AUTH_LOG)

        self.discardMessages()

        self.server = os.environ["SERVER"]
        self.connection = None

    def tearDown(self):
        self.discardMessages()
        self.msg_ctx.irpc_remove_name(self.event_type)
        self.msg_ctx.irpc_remove_name(AUTH_EVENT_NAME)
        if self.msg_handler_and_context:
            self.msg_ctx.deregister(self.msg_handler_and_context,
                                    msg_type=self.message_type)
        if self.auth_handler_and_context:
            self.msg_ctx.deregister(self.auth_handler_and_context,
                                    msg_type=MSG_AUTH_LOG)

    def haveExpected(self, expected, dn):
        if dn is None:
            return len(self.context["messages"]) >= expected
        else:
            received = 0
            for msg in self.context["messages"]:
                audit = getAudit(msg)
                if audit["dn"].lower() == dn.lower():
                    received += 1
                    if received >= expected:
                        return True
            return False

    def waitForMessages(self, number, connection=None, dn=None):
        """Wait for all the expected messages to arrive
        The connection is passed through to keep the connection alive
        until all the logging messages have been received.
        """

        self.connection = connection

        start_time = time.time()
        while not self.haveExpected(number, dn):
            self.msg_ctx.loop_once(0.1)
            if time.time() - start_time > 1:
                self.connection = None
                print("Timed out")
                return []

        self.connection = None
        if dn is None:
            return self.context["messages"]

        messages = []
        for msg in self.context["messages"]:
            audit = getAudit(msg)
            if audit["dn"].lower() == dn.lower():
                messages.append(msg)
        return messages

    # Discard any previously queued messages.
    def discardMessages(self):
        self.msg_ctx.loop_once(0.001)
        while (len(self.context["messages"]) or
               self.context["txnMessage"] is not None):

            self.context["messages"] = []
            self.context["txnMessage"] = None
            self.msg_ctx.loop_once(0.001)

    GUID_RE = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"

    #
    # Is the supplied GUID string correctly formatted
    #
    def is_guid(self, guid):
        return re.match(self.GUID_RE, guid)

    def get_session(self):
        return self.auth_context["sessionId"]

    def get_service_description(self):
        return self.auth_context["serviceDescription"]
