# Unix SMB/CIFS implementation.
# Copyright (C) Andrew Bartlett 2007
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
from samba.dcerpc import dns, dnsserver
from samba.netcmd.dns import data_to_dns_record
from samba.tests.subunitrun import SubunitOptions, TestProgram
from samba import werror, WERRORError
from samba.tests.dns_base import DNSTest
import samba.getopt as options
import optparse

parser = optparse.OptionParser(
    "dns_wildcard.py <server name> <server ip> [options]")
sambaopts = options.SambaOptions(parser)
parser.add_option_group(sambaopts)

# This timeout only has relevance when testing against Windows
# Format errors tend to return patchy responses, so a timeout is needed.
parser.add_option("--timeout", type="int", dest="timeout",
                  help="Specify timeout for DNS requests")

# To run against Windows
# python python/samba/tests/dns_wildcard.py computer_name ip
#                                  -U"Administrator%admin_password"
#                                  --realm=Domain_name
#                                  --timeout 10
#

# use command line creds if available
credopts = options.CredentialsOptions(parser)
parser.add_option_group(credopts)
subunitopts = SubunitOptions(parser)
parser.add_option_group(subunitopts)

opts, args = parser.parse_args()

lp = sambaopts.get_loadparm()
creds = credopts.get_credentials(lp)

timeout = opts.timeout

if len(args) < 2:
    parser.print_usage()
    sys.exit(1)

server_name = args[0]
server_ip = args[1]
creds.set_krb_forwardable(credentials.NO_KRB_FORWARDABLE)

WILDCARD_IP        = "1.1.1.1"
WILDCARD           = "*.wildcardtest"
EXACT_IP           = "1.1.1.2"
EXACT              = "exact.wildcardtest"
LEVEL2_WILDCARD_IP = "1.1.1.3"
LEVEL2_WILDCARD    = "*.level2.wildcardtest"
LEVEL2_EXACT_IP    = "1.1.1.4"
LEVEL2_EXACT       = "exact.level2.wildcardtest"


class TestWildCardQueries(DNSTest):

    def setUp(self):
        super(TestWildCardQueries, self).setUp()
        global server, server_ip, lp, creds, timeout
        self.server = server_name
        self.server_ip = server_ip
        self.lp = lp
        self.creds = creds
        self.timeout = timeout

        # Create the dns records
        self.dns_records = [(dns.DNS_QTYPE_A,
                             "%s.%s" % (WILDCARD, self.get_dns_domain()),
                             WILDCARD_IP),
                            (dns.DNS_QTYPE_A,
                             "%s.%s" % (EXACT, self.get_dns_domain()),
                             EXACT_IP),
                            (dns.DNS_QTYPE_A,
                             ("%s.%s" % (
                                 LEVEL2_WILDCARD,
                                 self.get_dns_domain())),
                             LEVEL2_WILDCARD_IP),
                            (dns.DNS_QTYPE_A,
                             ("%s.%s" % (
                                 LEVEL2_EXACT,
                                 self.get_dns_domain())),
                             LEVEL2_EXACT_IP)]

        c = self.dns_connect()
        for (typ, name, data) in self.dns_records:
            self.add_record(c, typ, name, data)

    def tearDown(self):
        c = self.dns_connect()
        for (typ, name, data) in self.dns_records:
            self.delete_record(c, typ, name, data)

    def dns_connect(self):
        binding_str = "ncacn_ip_tcp:%s[sign]" % self.server_ip
        return dnsserver.dnsserver(binding_str, self.lp, self.creds)

    def delete_record(self, dns_conn, typ, name, data):

        rec = data_to_dns_record(typ, data)
        del_rec_buf = dnsserver.DNS_RPC_RECORD_BUF()
        del_rec_buf.rec = rec

        try:
            dns_conn.DnssrvUpdateRecord2(dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                                         0,
                                         self.server,
                                         self.get_dns_domain(),
                                         name,
                                         None,
                                         del_rec_buf)
        except WERRORError as e:
            # Ignore record does not exist errors
            if e.args[0] != werror.WERR_DNS_ERROR_NAME_DOES_NOT_EXIST:
                raise e

    def add_record(self, dns_conn, typ, name, data):

        rec = data_to_dns_record(typ, data)
        add_rec_buf = dnsserver.DNS_RPC_RECORD_BUF()
        add_rec_buf.rec = rec
        try:
            dns_conn.DnssrvUpdateRecord2(dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                                         0,
                                         self.server,
                                         self.get_dns_domain(),
                                         name,
                                         add_rec_buf,
                                         None)
        except WERRORError as e:
            raise e

    def test_one_a_query_match_wildcard(self):
        "Query an A record, should match the wildcard entry"

        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        # Check the record
        name = "miss.wildcardtest.%s" % self.get_dns_domain()
        q = self.make_name_question(name,
                                    dns.DNS_QTYPE_A,
                                    dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        (response, response_packet) =\
            self.dns_transaction_udp(p, host=self.server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)
        self.assertEqual(response.ancount, 1)
        self.assertEqual(response.answers[0].rr_type, dns.DNS_QTYPE_A)
        self.assertEqual(response.answers[0].rdata, WILDCARD_IP)

    def test_one_a_query_match_wildcard_2_labels(self):
        """ Query an A record, should match the wild card entry
            have two labels to the left of the wild card target.
        """

        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        # Check the record
        name = "label2.label1.wildcardtest.%s" % self.get_dns_domain()
        q = self.make_name_question(name,
                                    dns.DNS_QTYPE_A,
                                    dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        (response, response_packet) =\
            self.dns_transaction_udp(p, host=self.server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)
        self.assertEqual(response.ancount, 1)
        self.assertEqual(response.answers[0].rr_type, dns.DNS_QTYPE_A)
        self.assertEqual(response.answers[0].rdata, WILDCARD_IP)

    def test_one_a_query_wildcard_entry(self):
        "Query the wildcard entry"

        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        # Check the record
        name = "%s.%s" % (WILDCARD, self.get_dns_domain())
        q = self.make_name_question(name,
                                    dns.DNS_QTYPE_A,
                                    dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        (response, response_packet) =\
            self.dns_transaction_udp(p, host=self.server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)
        self.assertEqual(response.ancount, 1)
        self.assertEqual(response.answers[0].rr_type, dns.DNS_QTYPE_A)
        self.assertEqual(response.answers[0].rdata, WILDCARD_IP)

    def test_one_a_query_exact_match(self):
        """Query an entry that matches the wild card but has an exact match as
         well.
         """
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        # Check the record
        name = "%s.%s" % (EXACT, self.get_dns_domain())
        q = self.make_name_question(name,
                                    dns.DNS_QTYPE_A,
                                    dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        (response, response_packet) =\
            self.dns_transaction_udp(p, host=self.server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)
        self.assertEqual(response.ancount, 1)
        self.assertEqual(response.answers[0].rr_type, dns.DNS_QTYPE_A)
        self.assertEqual(response.answers[0].rdata, EXACT_IP)

    def test_one_a_query_match_wildcard_l2(self):
        "Query an A record, should match the level 2 wildcard entry"

        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        # Check the record
        name = "miss.level2.wildcardtest.%s" % self.get_dns_domain()
        q = self.make_name_question(name,
                                    dns.DNS_QTYPE_A,
                                    dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        (response, response_packet) =\
            self.dns_transaction_udp(p, host=self.server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)
        self.assertEqual(response.ancount, 1)
        self.assertEqual(response.answers[0].rr_type, dns.DNS_QTYPE_A)
        self.assertEqual(response.answers[0].rdata, LEVEL2_WILDCARD_IP)

    def test_one_a_query_match_wildcard_l2_2_labels(self):
        """Query an A record, should match the level 2 wild card entry
           have two labels to the left of the wild card target
        """

        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        # Check the record
        name = "label1.label2.level2.wildcardtest.%s" % self.get_dns_domain()
        q = self.make_name_question(name,
                                    dns.DNS_QTYPE_A,
                                    dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        (response, response_packet) =\
            self.dns_transaction_udp(p, host=self.server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)
        self.assertEqual(response.ancount, 1)
        self.assertEqual(response.answers[0].rr_type, dns.DNS_QTYPE_A)
        self.assertEqual(response.answers[0].rdata, LEVEL2_WILDCARD_IP)

    def test_one_a_query_exact_match_l2(self):
        """Query an entry that matches the wild card but has an exact match as
         well.
         """
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        # Check the record
        name = "%s.%s" % (LEVEL2_EXACT, self.get_dns_domain())
        q = self.make_name_question(name,
                                    dns.DNS_QTYPE_A,
                                    dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        (response, response_packet) =\
            self.dns_transaction_udp(p, host=self.server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)
        self.assertEqual(response.ancount, 1)
        self.assertEqual(response.answers[0].rr_type, dns.DNS_QTYPE_A)
        self.assertEqual(response.answers[0].rdata, LEVEL2_EXACT_IP)

    def test_one_a_query_wildcard_entry_l2(self):
        "Query the level 2 wildcard entry"

        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        # Check the record
        name = "%s.%s" % (LEVEL2_WILDCARD, self.get_dns_domain())
        q = self.make_name_question(name,
                                    dns.DNS_QTYPE_A,
                                    dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        (response, response_packet) =\
            self.dns_transaction_udp(p, host=self.server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)
        self.assertEqual(response.ancount, 1)
        self.assertEqual(response.answers[0].rr_type, dns.DNS_QTYPE_A)
        self.assertEqual(response.answers[0].rdata, LEVEL2_WILDCARD_IP)


TestProgram(module=__name__, opts=subunitopts)
