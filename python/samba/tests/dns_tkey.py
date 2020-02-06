# Unix SMB/CIFS implementation.
# Copyright (C) Kai Blin  <kai@samba.org> 2011
# Copyright (C) Ralph Boehme  <slow@samba.org> 2016
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
import optparse
import samba.getopt as options
from samba.dcerpc import dns
from samba.tests.subunitrun import SubunitOptions, TestProgram
from samba.tests.dns_base import DNSTKeyTest

parser = optparse.OptionParser("dns.py <server name> <server ip> [options]")
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
timeout = opts.timeout

if len(args) < 2:
    parser.print_usage()
    sys.exit(1)

server_name = args[0]
server_ip = args[1]


class TestDNSUpdates(DNSTKeyTest):
    def setUp(self):
        self.server = server_name
        self.server_ip = server_ip
        super(TestDNSUpdates, self).setUp()

    def test_tkey(self):
        "test DNS TKEY handshake"

        self.tkey_trans()

    def test_update_wo_tsig(self):
        "test DNS update without TSIG record"

        p = self.make_update_request()
        (response, response_p) = self.dns_transaction_udp(p, self.server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_REFUSED)

        rcode = self.search_record(self.newrecname)
        self.assert_rcode_equals(rcode, dns.DNS_RCODE_NXDOMAIN)

    def test_update_tsig_bad_keyname(self):
        "test DNS update with a TSIG record with a bad keyname"

        self.tkey_trans()

        p = self.make_update_request()
        self.sign_packet(p, "badkey")
        (response, response_p) = self.dns_transaction_udp(p, self.server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_NOTAUTH)
        tsig_record = response.additional[0].rdata
        self.assertEqual(tsig_record.error, dns.DNS_RCODE_BADKEY)
        self.assertEqual(tsig_record.mac_size, 0)

        rcode = self.search_record(self.newrecname)
        self.assert_rcode_equals(rcode, dns.DNS_RCODE_NXDOMAIN)

    def test_update_tsig_bad_mac(self):
        "test DNS update with a TSIG record with a bad MAC"

        self.tkey_trans()

        p = self.make_update_request()
        self.bad_sign_packet(p, self.key_name)
        (response, response_p) = self.dns_transaction_udp(p, self.server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_NOTAUTH)
        tsig_record = response.additional[0].rdata
        self.assertEqual(tsig_record.error, dns.DNS_RCODE_BADSIG)
        self.assertEqual(tsig_record.mac_size, 0)

        rcode = self.search_record(self.newrecname)
        self.assert_rcode_equals(rcode, dns.DNS_RCODE_NXDOMAIN)

    def test_update_tsig(self):
        "test DNS update with correct TSIG record"

        self.tkey_trans()

        p = self.make_update_request()
        mac = self.sign_packet(p, self.key_name)
        (response, response_p) = self.dns_transaction_udp(p, self.server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.verify_packet(response, response_p, mac)

        # Check the record is around
        rcode = self.search_record(self.newrecname)
        self.assert_rcode_equals(rcode, dns.DNS_RCODE_OK)

        # Now delete the record
        p = self.make_update_request(delete=True)
        mac = self.sign_packet(p, self.key_name)
        (response, response_p) = self.dns_transaction_udp(p, self.server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.verify_packet(response, response_p, mac)

        # check it's gone
        rcode = self.search_record(self.newrecname)
        self.assert_rcode_equals(rcode, dns.DNS_RCODE_NXDOMAIN)

    def test_update_tsig_windows(self):
        "test DNS update with correct TSIG record (follow Windows pattern)"

        newrecname = "win" + self.newrecname
        rr_class = dns.DNS_QCLASS_IN
        ttl = 1200

        p = self.make_name_packet(dns.DNS_OPCODE_UPDATE)
        q = self.make_name_question(self.get_dns_domain(),
                                    dns.DNS_QTYPE_SOA,
                                    dns.DNS_QCLASS_IN)
        questions = []
        questions.append(q)
        self.finish_name_packet(p, questions)

        updates = []
        r = dns.res_rec()
        r.name = newrecname
        r.rr_type = dns.DNS_QTYPE_A
        r.rr_class = dns.DNS_QCLASS_ANY
        r.ttl = 0
        r.length = 0
        updates.append(r)
        r = dns.res_rec()
        r.name = newrecname
        r.rr_type = dns.DNS_QTYPE_AAAA
        r.rr_class = dns.DNS_QCLASS_ANY
        r.ttl = 0
        r.length = 0
        updates.append(r)
        r = dns.res_rec()
        r.name = newrecname
        r.rr_type = dns.DNS_QTYPE_A
        r.rr_class = rr_class
        r.ttl = ttl
        r.length = 0xffff
        r.rdata = "10.1.45.64"
        updates.append(r)
        p.nscount = len(updates)
        p.nsrecs = updates

        prereqs = []
        r = dns.res_rec()
        r.name = newrecname
        r.rr_type = dns.DNS_QTYPE_CNAME
        r.rr_class = dns.DNS_QCLASS_NONE
        r.ttl = 0
        r.length = 0
        prereqs.append(r)
        p.ancount = len(prereqs)
        p.answers = prereqs

        (response, response_p) = self.dns_transaction_udp(p, self.server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_REFUSED)

        self.tkey_trans()
        mac = self.sign_packet(p, self.key_name)
        (response, response_p) = self.dns_transaction_udp(p, self.server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.verify_packet(response, response_p, mac)

        # Check the record is around
        rcode = self.search_record(newrecname)
        self.assert_rcode_equals(rcode, dns.DNS_RCODE_OK)

        # Now delete the record
        p = self.make_update_request(delete=True)
        mac = self.sign_packet(p, self.key_name)
        (response, response_p) = self.dns_transaction_udp(p, self.server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.verify_packet(response, response_p, mac)

        # check it's gone
        rcode = self.search_record(self.newrecname)
        self.assert_rcode_equals(rcode, dns.DNS_RCODE_NXDOMAIN)


TestProgram(module=__name__, opts=subunitopts)
