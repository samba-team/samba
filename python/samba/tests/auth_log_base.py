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
"""Tests for the Auth and AuthZ logging.
"""

from samba import auth
import samba.tests
from samba.messaging import Messaging
from samba.dcerpc.messaging import MSG_AUTH_LOG, AUTH_EVENT_NAME
from samba.dcerpc import srvsvc, dnsserver
import time
import json
import os
from samba import smb
from samba.samdb import SamDB

class AuthLogTestBase(samba.tests.TestCase):

    def setUp(self):
        super(AuthLogTestBase, self).setUp()
        lp_ctx = self.get_loadparm()
        self.msg_ctx = Messaging((1,), lp_ctx=lp_ctx);
        self.msg_ctx.irpc_add_name(AUTH_EVENT_NAME)

        def messageHandler( context, msgType, src, message):
            # This does not look like sub unit output and it
            # makes these tests much easier to debug.
            print(message)
            jsonMsg = json.loads(message)
            context["messages"].append( jsonMsg)

        self.context = { "messages": []}
        self.msg_handler_and_context = (messageHandler, self.context)
        self.msg_ctx.register(self.msg_handler_and_context,
                              msg_type=MSG_AUTH_LOG)

        self.discardMessages()

        self.remoteAddress = None
        self.server = os.environ["SERVER"]
        self.connection = None

    def tearDown(self):
        if self.msg_handler_and_context:
            self.msg_ctx.deregister(self.msg_handler_and_context,
                                    msg_type=MSG_AUTH_LOG)


    def waitForMessages(self, isLastExpectedMessage, connection=None):
        """Wait for all the expected messages to arrive
        The connection is passed through to keep the connection alive
        until all the logging messages have been received.
        """

        def completed( messages):
            for message in messages:
                if isRemote( message) and isLastExpectedMessage( message):
                    return True
            return False

        def isRemote( message):
            remote = None
            if message["type"] == "Authorization":
                remote = message["Authorization"]["remoteAddress"]
            elif message["type"] == "Authentication":
                remote = message["Authentication"]["remoteAddress"]
            else:
                return False

            try:
                addr = remote.split(":")
                return addr[1] == self.remoteAddress
            except IndexError:
                return False

        self.connection = connection

        start_time = time.time()
        while not completed( self.context["messages"]):
            self.msg_ctx.loop_once(0.1)
            if time.time() - start_time > 1:
                self.connection = None
                return []

        self.connection = None
        return filter( isRemote, self.context["messages"])

    # Discard any previously queued messages.
    def discardMessages(self):
        self.msg_ctx.loop_once(0.001)
        while len( self.context["messages"]):
            self.msg_ctx.loop_once(0.001)
        self.context["messages"] = []

    # Remove any NETLOGON authentication messages
    # NETLOGON is only performed once per session, so to avoid ordering
    # dependencies within the tests it's best to strip out NETLOGON messages.
    #
    def remove_netlogon_messages(self, messages):
        def is_not_netlogon(msg):
            if "Authentication" not in msg:
                return True
            sd = msg["Authentication"]["serviceDescription"]
            return sd != "NETLOGON"

        return list(filter(is_not_netlogon, messages))
