# Unix SMB/CIFS implementation.
#
# Copyright (C) Catalyst.Net Ltd. 2017
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
Detect null pointer exception in /source3/smbd/sessetup.c
"""

import samba.tests
import os
from samba.net import Net, LIBNET_JOIN_AUTOMATIC
from samba.credentials import DONT_USE_KERBEROS
from samba import NTSTATUSError, ntstatus
import ctypes

class NetJoinNoSpnegoTests(samba.tests.TestCase):

    def setUp(self):
        super(NetJoinNoSpnegoTests, self).setUp()
        self.remoteAddress = "/root/ncalrpc_as_system"
        self.domain = os.environ["DOMAIN"]
        self.server = os.environ["SERVER"]

    def tearDown(self):
        super(NetJoinNoSpnegoTests, self).tearDown()

    def test_net_join_no_spnego(self):
        lp = self.get_loadparm()
        lp.set("client use spnego", "no")
        netbios_name = "NetJoinNoSpnego"
        machinepass  = "abcdefghij"
        creds = self.insta_creds(template=self.get_credentials(),
                                 kerberos_state=DONT_USE_KERBEROS)

        net = Net(creds, lp, server=self.server)

        try:
            (join_password, sid, domain_name) = net.join_member(
                self.domain, netbios_name, LIBNET_JOIN_AUTOMATIC,
                machinepass=machinepass)
        except NTSTATUSError as e:
            code = ctypes.c_uint32(e[0]).value
            if code == ntstatus.NT_STATUS_CONNECTION_DISCONNECTED:
                self.fail("Connection failure")
        pass
