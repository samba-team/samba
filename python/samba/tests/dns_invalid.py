# Unix SMB/CIFS implementation.
# Copyright (C) Kai Blin  <kai@samba.org> 2018
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

import sys
from samba import credentials
from samba.dcerpc import dns
from samba.tests.subunitrun import SubunitOptions, TestProgram
from samba.tests.dns_base import DNSTest
import samba.getopt as options
import optparse

parser = optparse.OptionParser("dns_invalid.py <server ip> [options]")
sambaopts = options.SambaOptions(parser)
parser.add_option_group(sambaopts)

# This timeout only has relevance when testing against Windows
# Format errors tend to return patchy responses, so a timeout is needed.
parser.add_option("--timeout", type="int", dest="timeout",
                  help="Specify timeout for DNS requests")

# use command line creds if available
credopts = options.CredentialsOptions(parser)
parser.add_option_group(credopts)
subunitopts = SubunitOptions(parser)
parser.add_option_group(subunitopts)

opts, args = parser.parse_args()

lp = sambaopts.get_loadparm()
creds = credopts.get_credentials(lp)

timeout = opts.timeout

if len(args) < 1:
    parser.print_usage()
    sys.exit(1)

server_ip = args[0]
creds.set_krb_forwardable(credentials.NO_KRB_FORWARDABLE)


class TestBrokenQueries(DNSTest):
    def setUp(self):
        super(TestBrokenQueries, self).setUp()
        global server, server_ip, lp, creds, timeout
        self.server_ip = server_ip
        self.lp = lp
        self.creds = creds
        self.timeout = timeout

    def test_invalid_chars_in_name(self):
        """Check the server refuses invalid characters in the query name"""
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        name = "\x10\x11\x05\xa8.%s" % self.get_dns_domain()
        q = self.make_name_question(name, dns.DNS_QTYPE_A, dns.DNS_QCLASS_IN)
        print("asking for %s" % (q.name))
        questions.append(q)

        self.finish_name_packet(p, questions)
        (response, response_packet) = self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_NXDOMAIN)


TestProgram(module=__name__, opts=subunitopts)
