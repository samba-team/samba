# Blackbox tests for the "net ads dns async" commands
#
# Copyright (C) Samuel Cabrero <scabrero@samba.org> 2022
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

import os
import dns.resolver
import re

from samba.tests import BlackboxTestCase

SERVER = os.environ["DC_SERVER"]
REALM = os.environ["REALM"]
COMMAND = "bin/net ads"

class NetAdsDnsTests(BlackboxTestCase):

    def setUp(self):
        super(NetAdsDnsTests, self).setUp()
        nameserver = os.environ["DC_SERVER_IP"]
        # filename=None will disable reading /etc/resolv.conf. The file might
        # not exist e.g. on build or CI systems.
        self.resolver = dns.resolver.Resolver(filename=None)
        self.resolver.nameservers = [nameserver]

    def parse_output(self, output):
        v4 = []
        v6 = []
        for line in output.split("\n"):
            m = re.search(r'^.*IPv4addr = (.*)$', line)
            if m:
                v4.append(m.group(1))
            m = re.search(r'^.*IPv6addr = (.*)$', line)
            if m:
                v6.append(m.group(1))
        return (v4, v6)

    def test_async_dns(self):
        host = "%s.%s" % (SERVER, REALM)

        sync_v4 = []
        answers = self.resolver.query(host, 'A')
        for rdata in answers:
            sync_v4.append(rdata.address)
        self.assertGreaterEqual(len(sync_v4), 1)

        sync_v6 = []
        answers = self.resolver.query(host, 'AAAA')
        for rdata in answers:
            sync_v6.append(rdata.address)
        self.assertGreaterEqual(len(sync_v6), 1)

        async_v4 = []
        async_v6 = []
        argv = "%s dns async %s.%s " % (COMMAND, SERVER, REALM)
        try:
            out = self.check_output(argv)
            (async_v4, async_v6) = self.parse_output(out.decode('utf-8'))
        except samba.tests.BlackboxProcessError as e:
            self.fail("Error calling [%s]: %s" % (argv, e))

        self.assertGreaterEqual(len(async_v4), 1)
        self.assertGreaterEqual(len(async_v6), 1)

        sync_v4.sort()
        async_v4.sort()
        self.assertStringsEqual(' '.join(sync_v4), ' '.join(async_v4))

        sync_v6.sort()
        async_v6.sort()
        self.assertStringsEqual(' '.join(sync_v6), ' '.join(async_v6))
