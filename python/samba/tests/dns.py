# Unix SMB/CIFS implementation.
# Copyright (C) Kai Blin  <kai@samba.org> 2011
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
import os
import sys
import struct
import random
import socket
import samba.ndr as ndr
from samba import credentials, param
from samba.dcerpc import dns, dnsp, dnsserver
from samba.netcmd.dns import TXTRecord, dns_record_match, data_to_dns_record
from samba.tests.subunitrun import SubunitOptions, TestProgram
from samba import werror, WERRORError
from samba.tests.dns_base import DNSTest
import samba.getopt as options
import optparse

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

lp = sambaopts.get_loadparm()
creds = credopts.get_credentials(lp)

timeout = opts.timeout

if len(args) < 2:
    parser.print_usage()
    sys.exit(1)

server_name = args[0]
server_ip = args[1]
creds.set_krb_forwardable(credentials.NO_KRB_FORWARDABLE)

class TestSimpleQueries(DNSTest):
    def setUp(self):
        super(TestSimpleQueries, self).setUp()
        global server, server_ip, lp, creds, timeout
        self.server = server_name
        self.server_ip = server_ip
        self.lp = lp
        self.creds = creds
        self.timeout = timeout

    def test_one_a_query(self):
        "create a query packet containing one query record"
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        name = "%s.%s" % (self.server, self.get_dns_domain())
        q = self.make_name_question(name, dns.DNS_QTYPE_A, dns.DNS_QCLASS_IN)
        print("asking for ", q.name)
        questions.append(q)

        self.finish_name_packet(p, questions)
        (response, response_packet) = self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)
        self.assertEquals(response.ancount, 1)
        self.assertEquals(response.answers[0].rdata,
                          self.server_ip)

    def test_one_SOA_query(self):
        "create a query packet containing one query record for the SOA"
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        name = "%s" % (self.get_dns_domain())
        q = self.make_name_question(name, dns.DNS_QTYPE_SOA, dns.DNS_QCLASS_IN)
        print("asking for ", q.name)
        questions.append(q)

        self.finish_name_packet(p, questions)
        (response, response_packet) = self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)
        self.assertEquals(response.ancount, 1)
        self.assertEquals(response.answers[0].rdata.mname.upper(),
                          ("%s.%s" % (self.server, self.get_dns_domain())).upper())

    def test_one_a_query_tcp(self):
        "create a query packet containing one query record via TCP"
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        name = "%s.%s" % (self.server, self.get_dns_domain())
        q = self.make_name_question(name, dns.DNS_QTYPE_A, dns.DNS_QCLASS_IN)
        print("asking for ", q.name)
        questions.append(q)

        self.finish_name_packet(p, questions)
        (response, response_packet) = self.dns_transaction_tcp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)
        self.assertEquals(response.ancount, 1)
        self.assertEquals(response.answers[0].rdata,
                          self.server_ip)

    def test_one_mx_query(self):
        "create a query packet causing an empty RCODE_OK answer"
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        name = "%s.%s" % (self.server, self.get_dns_domain())
        q = self.make_name_question(name, dns.DNS_QTYPE_MX, dns.DNS_QCLASS_IN)
        print("asking for ", q.name)
        questions.append(q)

        self.finish_name_packet(p, questions)
        (response, response_packet) = self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)
        self.assertEquals(response.ancount, 0)

        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        name = "invalid-%s.%s" % (self.server, self.get_dns_domain())
        q = self.make_name_question(name, dns.DNS_QTYPE_MX, dns.DNS_QCLASS_IN)
        print("asking for ", q.name)
        questions.append(q)

        self.finish_name_packet(p, questions)
        (response, response_packet) = self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_NXDOMAIN)
        self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)
        self.assertEquals(response.ancount, 0)

    def test_two_queries(self):
        "create a query packet containing two query records"
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        name = "%s.%s" % (self.server, self.get_dns_domain())
        q = self.make_name_question(name, dns.DNS_QTYPE_A, dns.DNS_QCLASS_IN)
        questions.append(q)

        name = "%s.%s" % ('bogusname', self.get_dns_domain())
        q = self.make_name_question(name, dns.DNS_QTYPE_A, dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        try:
            (response, response_packet) = self.dns_transaction_udp(p, host=server_ip)
            self.assert_dns_rcode_equals(response, dns.DNS_RCODE_FORMERR)
        except socket.timeout:
            # Windows chooses not to respond to incorrectly formatted queries.
            # Although this appears to be non-deterministic even for the same
            # request twice, it also appears to be based on a how poorly the
            # request is formatted.
            pass

    def test_qtype_all_query(self):
        "create a QTYPE_ALL query"
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        name = "%s.%s" % (self.server, self.get_dns_domain())
        q = self.make_name_question(name, dns.DNS_QTYPE_ALL, dns.DNS_QCLASS_IN)
        print("asking for ", q.name)
        questions.append(q)

        self.finish_name_packet(p, questions)
        (response, response_packet) = self.dns_transaction_udp(p, host=server_ip)

        num_answers = 1
        dc_ipv6 = os.getenv('SERVER_IPV6')
        if dc_ipv6 is not None:
            num_answers += 1

        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)
        self.assertEquals(response.ancount, num_answers)
        self.assertEquals(response.answers[0].rdata,
                          self.server_ip)
        if dc_ipv6 is not None:
            self.assertEquals(response.answers[1].rdata, dc_ipv6)

    def test_qclass_none_query(self):
        "create a QCLASS_NONE query"
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        name = "%s.%s" % (self.server, self.get_dns_domain())
        q = self.make_name_question(name, dns.DNS_QTYPE_ALL, dns.DNS_QCLASS_NONE)
        questions.append(q)

        self.finish_name_packet(p, questions)
        try:
            (response, response_packet) = self.dns_transaction_udp(p, host=server_ip)
            self.assert_dns_rcode_equals(response, dns.DNS_RCODE_NOTIMP)
        except socket.timeout:
            # Windows chooses not to respond to incorrectly formatted queries.
            # Although this appears to be non-deterministic even for the same
            # request twice, it also appears to be based on a how poorly the
            # request is formatted.
            pass

    def test_soa_hostname_query(self):
        "create a SOA query for a hostname"
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        name = "%s.%s" % (self.server, self.get_dns_domain())
        q = self.make_name_question(name, dns.DNS_QTYPE_SOA, dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        (response, response_packet) = self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)
        # We don't get SOA records for single hosts
        self.assertEquals(response.ancount, 0)
        # But we do respond with an authority section
        self.assertEqual(response.nscount, 1)

    def test_soa_domain_query(self):
        "create a SOA query for a domain"
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        name = self.get_dns_domain()
        q = self.make_name_question(name, dns.DNS_QTYPE_SOA, dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        (response, response_packet) = self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)
        self.assertEquals(response.ancount, 1)
        self.assertEquals(response.answers[0].rdata.minimum, 3600)


class TestDNSUpdates(DNSTest):
    def setUp(self):
        super(TestDNSUpdates, self).setUp()
        global server, server_ip, lp, creds, timeout
        self.server = server_name
        self.server_ip = server_ip
        self.lp = lp
        self.creds = creds
        self.timeout = timeout

    def test_two_updates(self):
        "create two update requests"
        p = self.make_name_packet(dns.DNS_OPCODE_UPDATE)
        updates = []

        name = "%s.%s" % (self.server, self.get_dns_domain())
        u = self.make_name_question(name, dns.DNS_QTYPE_A, dns.DNS_QCLASS_IN)
        updates.append(u)

        name = self.get_dns_domain()
        u = self.make_name_question(name, dns.DNS_QTYPE_A, dns.DNS_QCLASS_IN)
        updates.append(u)

        self.finish_name_packet(p, updates)
        try:
            (response, response_packet) = self.dns_transaction_udp(p, host=server_ip)
            self.assert_dns_rcode_equals(response, dns.DNS_RCODE_FORMERR)
        except socket.timeout:
            # Windows chooses not to respond to incorrectly formatted queries.
            # Although this appears to be non-deterministic even for the same
            # request twice, it also appears to be based on a how poorly the
            # request is formatted.
            pass

    def test_update_wrong_qclass(self):
        "create update with DNS_QCLASS_NONE"
        p = self.make_name_packet(dns.DNS_OPCODE_UPDATE)
        updates = []

        name = self.get_dns_domain()
        u = self.make_name_question(name, dns.DNS_QTYPE_A, dns.DNS_QCLASS_NONE)
        updates.append(u)

        self.finish_name_packet(p, updates)
        (response, response_packet) = self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_NOTIMP)

    def test_update_prereq_with_non_null_ttl(self):
        "test update with a non-null TTL"
        p = self.make_name_packet(dns.DNS_OPCODE_UPDATE)
        updates = []

        name = self.get_dns_domain()

        u = self.make_name_question(name, dns.DNS_QTYPE_SOA, dns.DNS_QCLASS_IN)
        updates.append(u)
        self.finish_name_packet(p, updates)

        prereqs = []
        r = dns.res_rec()
        r.name = "%s.%s" % (self.server, self.get_dns_domain())
        r.rr_type = dns.DNS_QTYPE_TXT
        r.rr_class = dns.DNS_QCLASS_NONE
        r.ttl = 1
        r.length = 0
        prereqs.append(r)

        p.ancount = len(prereqs)
        p.answers = prereqs

        try:
            (response, response_packet) = self.dns_transaction_udp(p, host=server_ip)
            self.assert_dns_rcode_equals(response, dns.DNS_RCODE_FORMERR)
        except socket.timeout:
            # Windows chooses not to respond to incorrectly formatted queries.
            # Although this appears to be non-deterministic even for the same
            # request twice, it also appears to be based on a how poorly the
            # request is formatted.
            pass

    def test_update_prereq_with_non_null_length(self):
        "test update with a non-null length"
        p = self.make_name_packet(dns.DNS_OPCODE_UPDATE)
        updates = []

        name = self.get_dns_domain()

        u = self.make_name_question(name, dns.DNS_QTYPE_SOA, dns.DNS_QCLASS_IN)
        updates.append(u)
        self.finish_name_packet(p, updates)

        prereqs = []
        r = dns.res_rec()
        r.name = "%s.%s" % (self.server, self.get_dns_domain())
        r.rr_type = dns.DNS_QTYPE_TXT
        r.rr_class = dns.DNS_QCLASS_ANY
        r.ttl = 0
        r.length = 1
        prereqs.append(r)

        p.ancount = len(prereqs)
        p.answers = prereqs

        (response, response_packet) = self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_NXRRSET)

    def test_update_prereq_nonexisting_name(self):
        "test update with a nonexisting name"
        p = self.make_name_packet(dns.DNS_OPCODE_UPDATE)
        updates = []

        name = self.get_dns_domain()

        u = self.make_name_question(name, dns.DNS_QTYPE_SOA, dns.DNS_QCLASS_IN)
        updates.append(u)
        self.finish_name_packet(p, updates)

        prereqs = []
        r = dns.res_rec()
        r.name = "idontexist.%s" % self.get_dns_domain()
        r.rr_type = dns.DNS_QTYPE_TXT
        r.rr_class = dns.DNS_QCLASS_ANY
        r.ttl = 0
        r.length = 0
        prereqs.append(r)

        p.ancount = len(prereqs)
        p.answers = prereqs

        (response, response_packet) = self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_NXRRSET)

    def test_update_add_txt_record(self):
        "test adding records works"
        prefix, txt = 'textrec', ['"This is a test"']
        p = self.make_txt_update(prefix, txt)
        (response, response_packet) = self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.check_query_txt(prefix, txt)

    def test_delete_record(self):
        "Test if deleting records works"

        NAME = "deleterec.%s" % self.get_dns_domain()

        # First, create a record to make sure we have a record to delete.
        p = self.make_name_packet(dns.DNS_OPCODE_UPDATE)
        updates = []

        name = self.get_dns_domain()

        u = self.make_name_question(name, dns.DNS_QTYPE_SOA, dns.DNS_QCLASS_IN)
        updates.append(u)
        self.finish_name_packet(p, updates)

        updates = []
        r = dns.res_rec()
        r.name = NAME
        r.rr_type = dns.DNS_QTYPE_TXT
        r.rr_class = dns.DNS_QCLASS_IN
        r.ttl = 900
        r.length = 0xffff
        rdata = self.make_txt_record(['"This is a test"'])
        r.rdata = rdata
        updates.append(r)
        p.nscount = len(updates)
        p.nsrecs = updates

        (response, response_packet) = self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)

        # Now check the record is around
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []
        q = self.make_name_question(NAME, dns.DNS_QTYPE_TXT, dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        (response, response_packet) = self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)

        # Now delete the record
        p = self.make_name_packet(dns.DNS_OPCODE_UPDATE)
        updates = []

        name = self.get_dns_domain()

        u = self.make_name_question(name, dns.DNS_QTYPE_SOA, dns.DNS_QCLASS_IN)
        updates.append(u)
        self.finish_name_packet(p, updates)

        updates = []
        r = dns.res_rec()
        r.name = NAME
        r.rr_type = dns.DNS_QTYPE_TXT
        r.rr_class = dns.DNS_QCLASS_NONE
        r.ttl = 0
        r.length = 0xffff
        rdata = self.make_txt_record(['"This is a test"'])
        r.rdata = rdata
        updates.append(r)
        p.nscount = len(updates)
        p.nsrecs = updates

        (response, response_packet) = self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)

        # And finally check it's gone
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        q = self.make_name_question(NAME, dns.DNS_QTYPE_TXT, dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        (response, response_packet) = self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_NXDOMAIN)

    def test_readd_record(self):
        "Test if adding, deleting and then readding a records works"

        NAME = "readdrec.%s" % self.get_dns_domain()

        # Create the record
        p = self.make_name_packet(dns.DNS_OPCODE_UPDATE)
        updates = []

        name = self.get_dns_domain()

        u = self.make_name_question(name, dns.DNS_QTYPE_SOA, dns.DNS_QCLASS_IN)
        updates.append(u)
        self.finish_name_packet(p, updates)

        updates = []
        r = dns.res_rec()
        r.name = NAME
        r.rr_type = dns.DNS_QTYPE_TXT
        r.rr_class = dns.DNS_QCLASS_IN
        r.ttl = 900
        r.length = 0xffff
        rdata = self.make_txt_record(['"This is a test"'])
        r.rdata = rdata
        updates.append(r)
        p.nscount = len(updates)
        p.nsrecs = updates

        (response, response_packet) = self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)

        # Now check the record is around
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []
        q = self.make_name_question(NAME, dns.DNS_QTYPE_TXT, dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        (response, response_packet) = self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)

        # Now delete the record
        p = self.make_name_packet(dns.DNS_OPCODE_UPDATE)
        updates = []

        name = self.get_dns_domain()

        u = self.make_name_question(name, dns.DNS_QTYPE_SOA, dns.DNS_QCLASS_IN)
        updates.append(u)
        self.finish_name_packet(p, updates)

        updates = []
        r = dns.res_rec()
        r.name = NAME
        r.rr_type = dns.DNS_QTYPE_TXT
        r.rr_class = dns.DNS_QCLASS_NONE
        r.ttl = 0
        r.length = 0xffff
        rdata = self.make_txt_record(['"This is a test"'])
        r.rdata = rdata
        updates.append(r)
        p.nscount = len(updates)
        p.nsrecs = updates

        (response, response_packet) = self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)

        # check it's gone
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        q = self.make_name_question(NAME, dns.DNS_QTYPE_TXT, dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        (response, response_packet) = self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_NXDOMAIN)

        # recreate the record
        p = self.make_name_packet(dns.DNS_OPCODE_UPDATE)
        updates = []

        name = self.get_dns_domain()

        u = self.make_name_question(name, dns.DNS_QTYPE_SOA, dns.DNS_QCLASS_IN)
        updates.append(u)
        self.finish_name_packet(p, updates)

        updates = []
        r = dns.res_rec()
        r.name = NAME
        r.rr_type = dns.DNS_QTYPE_TXT
        r.rr_class = dns.DNS_QCLASS_IN
        r.ttl = 900
        r.length = 0xffff
        rdata = self.make_txt_record(['"This is a test"'])
        r.rdata = rdata
        updates.append(r)
        p.nscount = len(updates)
        p.nsrecs = updates

        (response, response_packet) = self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)

        # Now check the record is around
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []
        q = self.make_name_question(NAME, dns.DNS_QTYPE_TXT, dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        (response, response_packet) = self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)

    def test_update_add_mx_record(self):
        "test adding MX records works"
        p = self.make_name_packet(dns.DNS_OPCODE_UPDATE)
        updates = []

        name = self.get_dns_domain()

        u = self.make_name_question(name, dns.DNS_QTYPE_SOA, dns.DNS_QCLASS_IN)
        updates.append(u)
        self.finish_name_packet(p, updates)

        updates = []
        r = dns.res_rec()
        r.name = "%s" % self.get_dns_domain()
        r.rr_type = dns.DNS_QTYPE_MX
        r.rr_class = dns.DNS_QCLASS_IN
        r.ttl = 900
        r.length = 0xffff
        rdata = dns.mx_record()
        rdata.preference = 10
        rdata.exchange = 'mail.%s' % self.get_dns_domain()
        r.rdata = rdata
        updates.append(r)
        p.nscount = len(updates)
        p.nsrecs = updates

        (response, response_packet) = self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)

        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        name = "%s" % self.get_dns_domain()
        q = self.make_name_question(name, dns.DNS_QTYPE_MX, dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        (response, response_packet) = self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.assertEqual(response.ancount, 1)
        ans = response.answers[0]
        self.assertEqual(ans.rr_type, dns.DNS_QTYPE_MX)
        self.assertEqual(ans.rdata.preference, 10)
        self.assertEqual(ans.rdata.exchange, 'mail.%s' % self.get_dns_domain())


class TestComplexQueries(DNSTest):
    def make_dns_update(self, key, value, qtype):
        p = self.make_name_packet(dns.DNS_OPCODE_UPDATE)

        name = self.get_dns_domain()
        u = self.make_name_question(name, dns.DNS_QTYPE_SOA, dns.DNS_QCLASS_IN)
        self.finish_name_packet(p, [u])

        r = dns.res_rec()
        r.name = key
        r.rr_type = qtype
        r.rr_class = dns.DNS_QCLASS_IN
        r.ttl = 900
        r.length = 0xffff
        rdata = value
        r.rdata = rdata
        updates = [r]
        p.nscount = 1
        p.nsrecs = updates
        (response, response_packet) = self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)

    def setUp(self):
        super(TestComplexQueries, self).setUp()

        global server, server_ip, lp, creds, timeout
        self.server = server_name
        self.server_ip = server_ip
        self.lp = lp
        self.creds = creds
        self.timeout = timeout

    def test_one_a_query(self):
        "create a query packet containing one query record"

        try:

            # Create the record
            name = "cname_test.%s" % self.get_dns_domain()
            rdata = "%s.%s" % (self.server, self.get_dns_domain())
            self.make_dns_update(name, rdata, dns.DNS_QTYPE_CNAME)

            p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
            questions = []

            # Check the record
            name = "cname_test.%s" % self.get_dns_domain()
            q = self.make_name_question(name, dns.DNS_QTYPE_A, dns.DNS_QCLASS_IN)
            print("asking for ", q.name)
            questions.append(q)

            self.finish_name_packet(p, questions)
            (response, response_packet) = self.dns_transaction_udp(p, host=self.server_ip)
            self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
            self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)
            self.assertEquals(response.ancount, 2)
            self.assertEquals(response.answers[0].rr_type, dns.DNS_QTYPE_CNAME)
            self.assertEquals(response.answers[0].rdata, "%s.%s" %
                              (self.server, self.get_dns_domain()))
            self.assertEquals(response.answers[1].rr_type, dns.DNS_QTYPE_A)
            self.assertEquals(response.answers[1].rdata,
                              self.server_ip)

        finally:
            # Delete the record
            p = self.make_name_packet(dns.DNS_OPCODE_UPDATE)
            updates = []

            name = self.get_dns_domain()

            u = self.make_name_question(name, dns.DNS_QTYPE_SOA, dns.DNS_QCLASS_IN)
            updates.append(u)
            self.finish_name_packet(p, updates)

            updates = []
            r = dns.res_rec()
            r.name = "cname_test.%s" % self.get_dns_domain()
            r.rr_type = dns.DNS_QTYPE_CNAME
            r.rr_class = dns.DNS_QCLASS_NONE
            r.ttl = 0
            r.length = 0xffff
            r.rdata = "%s.%s" % (self.server, self.get_dns_domain())
            updates.append(r)
            p.nscount = len(updates)
            p.nsrecs = updates

            (response, response_packet) = self.dns_transaction_udp(p, host=self.server_ip)
            self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)

    def test_cname_two_chain(self):
        name0 = "cnamechain0.%s" % self.get_dns_domain()
        name1 = "cnamechain1.%s" % self.get_dns_domain()
        name2 = "cnamechain2.%s" % self.get_dns_domain()
        self.make_dns_update(name1, name2, dns.DNS_QTYPE_CNAME)
        self.make_dns_update(name2, name0, dns.DNS_QTYPE_CNAME)
        self.make_dns_update(name0, server_ip, dns.DNS_QTYPE_A)

        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []
        q = self.make_name_question(name1, dns.DNS_QTYPE_A,
                                    dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        (response, response_packet) = self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)
        self.assertEquals(response.ancount, 3)

        self.assertEquals(response.answers[0].rr_type, dns.DNS_QTYPE_CNAME)
        self.assertEquals(response.answers[0].name, name1)
        self.assertEquals(response.answers[0].rdata, name2)

        self.assertEquals(response.answers[1].rr_type, dns.DNS_QTYPE_CNAME)
        self.assertEquals(response.answers[1].name, name2)
        self.assertEquals(response.answers[1].rdata, name0)

        self.assertEquals(response.answers[2].rr_type, dns.DNS_QTYPE_A)
        self.assertEquals(response.answers[2].rdata,
                          self.server_ip)

    def test_invalid_empty_cname(self):
        name0 = "cnamedotprefix0.%s" % self.get_dns_domain()
        try:
            self.make_dns_update(name0, "", dns.DNS_QTYPE_CNAME)
        except AssertionError as e:
            pass
        else:
            self.fail("Successfully added empty CNAME, which is invalid.")

    def test_cname_two_chain_not_matching_qtype(self):
        name0 = "cnamechain0.%s" % self.get_dns_domain()
        name1 = "cnamechain1.%s" % self.get_dns_domain()
        name2 = "cnamechain2.%s" % self.get_dns_domain()
        self.make_dns_update(name1, name2, dns.DNS_QTYPE_CNAME)
        self.make_dns_update(name2, name0, dns.DNS_QTYPE_CNAME)
        self.make_dns_update(name0, server_ip, dns.DNS_QTYPE_A)

        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []
        q = self.make_name_question(name1, dns.DNS_QTYPE_TXT,
                                    dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        (response, response_packet) = self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)

        # CNAME should return all intermediate results!
        # Only the A records exists, not the TXT.
        self.assertEquals(response.ancount, 2)

        self.assertEquals(response.answers[0].rr_type, dns.DNS_QTYPE_CNAME)
        self.assertEquals(response.answers[0].name, name1)
        self.assertEquals(response.answers[0].rdata, name2)

        self.assertEquals(response.answers[1].rr_type, dns.DNS_QTYPE_CNAME)
        self.assertEquals(response.answers[1].name, name2)
        self.assertEquals(response.answers[1].rdata, name0)

class TestInvalidQueries(DNSTest):
    def setUp(self):
        super(TestInvalidQueries, self).setUp()
        global server, server_ip, lp, creds, timeout
        self.server = server_name
        self.server_ip = server_ip
        self.lp = lp
        self.creds = creds
        self.timeout = timeout

    def test_one_a_query(self):
        "send 0 bytes follows by create a query packet containing one query record"

        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
            s.connect((self.server_ip, 53))
            s.send("", 0)
        finally:
            if s is not None:
                s.close()

        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        name = "%s.%s" % (self.server, self.get_dns_domain())
        q = self.make_name_question(name, dns.DNS_QTYPE_A, dns.DNS_QCLASS_IN)
        print("asking for ", q.name)
        questions.append(q)

        self.finish_name_packet(p, questions)
        (response, response_packet) = self.dns_transaction_udp(p, host=self.server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)
        self.assertEquals(response.ancount, 1)
        self.assertEquals(response.answers[0].rdata,
                          self.server_ip)

    def test_one_a_reply(self):
        "send a reply instead of a query"
        global timeout

        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        name = "%s.%s" % ('fakefakefake', self.get_dns_domain())
        q = self.make_name_question(name, dns.DNS_QTYPE_A, dns.DNS_QCLASS_IN)
        print("asking for ", q.name)
        questions.append(q)

        self.finish_name_packet(p, questions)
        p.operation |= dns.DNS_FLAG_REPLY
        s = None
        try:
            send_packet = ndr.ndr_pack(p)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
            s.settimeout(timeout)
            host=self.server_ip
            s.connect((host, 53))
            tcp_packet = struct.pack('!H', len(send_packet))
            tcp_packet += send_packet
            s.send(tcp_packet, 0)
            recv_packet = s.recv(0xffff + 2, 0)
            self.assertEquals(0, len(recv_packet))
        except socket.timeout:
            # Windows chooses not to respond to incorrectly formatted queries.
            # Although this appears to be non-deterministic even for the same
            # request twice, it also appears to be based on a how poorly the
            # request is formatted.
            pass
        finally:
            if s is not None:
                s.close()

class TestZones(DNSTest):
    def setUp(self):
        super(TestZones, self).setUp()
        global server, server_ip, lp, creds, timeout
        self.server = server_name
        self.server_ip = server_ip
        self.lp = lp
        self.creds = creds
        self.timeout = timeout

        self.zone = "test.lan"
        self.rpc_conn = dnsserver.dnsserver("ncacn_ip_tcp:%s[sign]" % (self.server_ip),
                                            self.lp, self.creds)

    def tearDown(self):
        super(TestZones, self).tearDown()
        try:
            self.delete_zone(self.zone)
        except RuntimeError as e:
            (num, string) = e.args
            if num != werror.WERR_DNS_ERROR_ZONE_DOES_NOT_EXIST:
                raise

    def create_zone(self, zone):
        zone_create = dnsserver.DNS_RPC_ZONE_CREATE_INFO_LONGHORN()
        zone_create.pszZoneName = zone
        zone_create.dwZoneType = dnsp.DNS_ZONE_TYPE_PRIMARY
        zone_create.fAllowUpdate = dnsp.DNS_ZONE_UPDATE_SECURE
        zone_create.fAging = 0
        zone_create.dwDpFlags = dnsserver.DNS_DP_DOMAIN_DEFAULT
        try:
            self.rpc_conn.DnssrvOperation2(dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                                           0,
                                           self.server_ip,
                                           None,
                                           0,
                                           'ZoneCreate',
                                           dnsserver.DNSSRV_TYPEID_ZONE_CREATE,
                                           zone_create)
        except WERRORError as e:
            self.fail(str(e))

    def delete_zone(self, zone):
        self.rpc_conn.DnssrvOperation2(dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                                       0,
                                       self.server_ip,
                                       zone,
                                       0,
                                       'DeleteZoneFromDs',
                                       dnsserver.DNSSRV_TYPEID_NULL,
                                       None)

    def test_soa_query(self):
        zone = "test.lan"
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        q = self.make_name_question(zone, dns.DNS_QTYPE_SOA, dns.DNS_QCLASS_IN)
        questions.append(q)
        self.finish_name_packet(p, questions)

        (response, response_packet) = self.dns_transaction_udp(p, host=server_ip)
        # Windows returns OK while BIND logically seems to return NXDOMAIN
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_NXDOMAIN)
        self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)
        self.assertEquals(response.ancount, 0)

        self.create_zone(zone)
        (response, response_packet) = self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)
        self.assertEquals(response.ancount, 1)
        self.assertEquals(response.answers[0].rr_type, dns.DNS_QTYPE_SOA)

        self.delete_zone(zone)
        (response, response_packet) = self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_NXDOMAIN)
        self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)
        self.assertEquals(response.ancount, 0)

class TestRPCRoundtrip(DNSTest):
    def setUp(self):
        super(TestRPCRoundtrip, self).setUp()
        global server, server_ip, lp, creds
        self.server = server_name
        self.server_ip = server_ip
        self.lp = lp
        self.creds = creds
        self.rpc_conn = dnsserver.dnsserver("ncacn_ip_tcp:%s[sign]" % (self.server_ip),
                                            self.lp, self.creds)

    def tearDown(self):
        super(TestRPCRoundtrip, self).tearDown()

    def test_update_add_txt_rpc_to_dns(self):
        prefix, txt = 'rpctextrec', ['"This is a test"']

        name = "%s.%s" % (prefix, self.get_dns_domain())

        rec = data_to_dns_record(dnsp.DNS_TYPE_TXT, '"\\"This is a test\\""')
        add_rec_buf = dnsserver.DNS_RPC_RECORD_BUF()
        add_rec_buf.rec = rec
        try:
            self.rpc_conn.DnssrvUpdateRecord2(dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                                     0, self.server_ip, self.get_dns_domain(),
                                     name, add_rec_buf, None)
        except WERRORError as e:
            self.fail(str(e))

        try:
            self.check_query_txt(prefix, txt)
        finally:
            self.rpc_conn.DnssrvUpdateRecord2(dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                                              0, self.server_ip, self.get_dns_domain(),
                                              name, None, add_rec_buf)

    def test_update_add_null_padded_txt_record(self):
        "test adding records works"
        prefix, txt = 'pad1textrec', ['"This is a test"', '', '']
        p = self.make_txt_update(prefix, txt)
        (response, response_packet) = self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.check_query_txt(prefix, txt)
        self.assertIsNotNone(dns_record_match(self.rpc_conn, self.server_ip,
                             self.get_dns_domain(),
                             "%s.%s" % (prefix, self.get_dns_domain()),
                             dnsp.DNS_TYPE_TXT, '"\\"This is a test\\"" "" ""'))

        prefix, txt = 'pad2textrec', ['"This is a test"', '', '', 'more text']
        p = self.make_txt_update(prefix, txt)
        (response, response_packet) = self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.check_query_txt(prefix, txt)
        self.assertIsNotNone(dns_record_match(self.rpc_conn, self.server_ip,
                             self.get_dns_domain(),
                             "%s.%s" % (prefix, self.get_dns_domain()),
                             dnsp.DNS_TYPE_TXT, '"\\"This is a test\\"" "" "" "more text"'))

        prefix, txt = 'pad3textrec', ['', '', '"This is a test"']
        p = self.make_txt_update(prefix, txt)
        (response, response_packet) = self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.check_query_txt(prefix, txt)
        self.assertIsNotNone(dns_record_match(self.rpc_conn, self.server_ip,
                             self.get_dns_domain(),
                             "%s.%s" % (prefix, self.get_dns_domain()),
                             dnsp.DNS_TYPE_TXT, '"" "" "\\"This is a test\\""'))

    def test_update_add_padding_rpc_to_dns(self):
        prefix, txt = 'pad1textrec', ['"This is a test"', '', '']
        prefix = 'rpc' + prefix
        name = "%s.%s" % (prefix, self.get_dns_domain())

        rec = data_to_dns_record(dnsp.DNS_TYPE_TXT, '"\\"This is a test\\"" "" ""')
        add_rec_buf = dnsserver.DNS_RPC_RECORD_BUF()
        add_rec_buf.rec = rec
        try:
            self.rpc_conn.DnssrvUpdateRecord2(dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                                     0, self.server_ip, self.get_dns_domain(),
                                     name, add_rec_buf, None)

        except WERRORError as e:
            self.fail(str(e))

        try:
            self.check_query_txt(prefix, txt)
        finally:
            self.rpc_conn.DnssrvUpdateRecord2(dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                                              0, self.server_ip, self.get_dns_domain(),
                                              name, None, add_rec_buf)

        prefix, txt = 'pad2textrec', ['"This is a test"', '', '', 'more text']
        prefix = 'rpc' + prefix
        name = "%s.%s" % (prefix, self.get_dns_domain())

        rec = data_to_dns_record(dnsp.DNS_TYPE_TXT, '"\\"This is a test\\"" "" "" "more text"')
        add_rec_buf = dnsserver.DNS_RPC_RECORD_BUF()
        add_rec_buf.rec = rec
        try:
            self.rpc_conn.DnssrvUpdateRecord2(dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                                     0, self.server_ip, self.get_dns_domain(),
                                     name, add_rec_buf, None)

        except WERRORError as e:
            self.fail(str(e))

        try:
            self.check_query_txt(prefix, txt)
        finally:
            self.rpc_conn.DnssrvUpdateRecord2(dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                                              0, self.server_ip, self.get_dns_domain(),
                                              name, None, add_rec_buf)

        prefix, txt = 'pad3textrec', ['', '', '"This is a test"']
        prefix = 'rpc' + prefix
        name = "%s.%s" % (prefix, self.get_dns_domain())

        rec = data_to_dns_record(dnsp.DNS_TYPE_TXT, '"" "" "\\"This is a test\\""')
        add_rec_buf = dnsserver.DNS_RPC_RECORD_BUF()
        add_rec_buf.rec = rec
        try:
            self.rpc_conn.DnssrvUpdateRecord2(dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                                     0, self.server_ip, self.get_dns_domain(),
                                     name, add_rec_buf, None)
        except WERRORError as e:
            self.fail(str(e))

        try:
            self.check_query_txt(prefix, txt)
        finally:
            self.rpc_conn.DnssrvUpdateRecord2(dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                                              0, self.server_ip, self.get_dns_domain(),
                                              name, None, add_rec_buf)

    # Test is incomplete due to strlen against txt records
    def test_update_add_null_char_txt_record(self):
        "test adding records works"
        prefix, txt = 'nulltextrec', ['NULL\x00BYTE']
        p = self.make_txt_update(prefix, txt)
        (response, response_packet) = self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.check_query_txt(prefix, ['NULL'])
        self.assertIsNotNone(dns_record_match(self.rpc_conn, self.server_ip,
                             self.get_dns_domain(),
                             "%s.%s" % (prefix, self.get_dns_domain()),
                             dnsp.DNS_TYPE_TXT, '"NULL"'))

        prefix, txt = 'nulltextrec2', ['NULL\x00BYTE', 'NULL\x00BYTE']
        p = self.make_txt_update(prefix, txt)
        (response, response_packet) = self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.check_query_txt(prefix, ['NULL', 'NULL'])
        self.assertIsNotNone(dns_record_match(self.rpc_conn, self.server_ip,
                             self.get_dns_domain(),
                             "%s.%s" % (prefix, self.get_dns_domain()),
                             dnsp.DNS_TYPE_TXT, '"NULL" "NULL"'))

    def test_update_add_null_char_rpc_to_dns(self):
        prefix, txt = 'nulltextrec', ['NULL\x00BYTE']
        prefix = 'rpc' + prefix
        name = "%s.%s" % (prefix, self.get_dns_domain())

        rec = data_to_dns_record(dnsp.DNS_TYPE_TXT, '"NULL"')
        add_rec_buf = dnsserver.DNS_RPC_RECORD_BUF()
        add_rec_buf.rec = rec
        try:
            self.rpc_conn.DnssrvUpdateRecord2(dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                                     0, self.server_ip, self.get_dns_domain(),
                                     name, add_rec_buf, None)

        except WERRORError as e:
            self.fail(str(e))

        try:
           self.check_query_txt(prefix, ['NULL'])
        finally:
            self.rpc_conn.DnssrvUpdateRecord2(dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                                              0, self.server_ip, self.get_dns_domain(),
                                              name, None, add_rec_buf)

    def test_update_add_hex_char_txt_record(self):
        "test adding records works"
        prefix, txt = 'hextextrec', ['HIGH\xFFBYTE']
        p = self.make_txt_update(prefix, txt)
        (response, response_packet) = self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.check_query_txt(prefix, txt)
        self.assertIsNotNone(dns_record_match(self.rpc_conn, self.server_ip,
                             self.get_dns_domain(),
                             "%s.%s" % (prefix, self.get_dns_domain()),
                             dnsp.DNS_TYPE_TXT, '"HIGH\xFFBYTE"'))

    def test_update_add_hex_rpc_to_dns(self):
        prefix, txt = 'hextextrec', ['HIGH\xFFBYTE']
        prefix = 'rpc' + prefix
        name = "%s.%s" % (prefix, self.get_dns_domain())

        rec = data_to_dns_record(dnsp.DNS_TYPE_TXT, '"HIGH\xFFBYTE"')
        add_rec_buf = dnsserver.DNS_RPC_RECORD_BUF()
        add_rec_buf.rec = rec
        try:
            self.rpc_conn.DnssrvUpdateRecord2(dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                                     0, self.server_ip, self.get_dns_domain(),
                                     name, add_rec_buf, None)

        except WERRORError as e:
            self.fail(str(e))

        try:
           self.check_query_txt(prefix, txt)
        finally:
            self.rpc_conn.DnssrvUpdateRecord2(dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                                              0, self.server_ip, self.get_dns_domain(),
                                              name, None, add_rec_buf)

    def test_update_add_slash_txt_record(self):
        "test adding records works"
        prefix, txt = 'slashtextrec', ['Th\\=is=is a test']
        p = self.make_txt_update(prefix, txt)
        (response, response_packet) = self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.check_query_txt(prefix, txt)
        self.assertIsNotNone(dns_record_match(self.rpc_conn, self.server_ip,
                             self.get_dns_domain(),
                             "%s.%s" % (prefix, self.get_dns_domain()),
                             dnsp.DNS_TYPE_TXT, '"Th\\\\=is=is a test"'))

    # This test fails against Windows as it eliminates slashes in RPC
    # One typical use for a slash is in records like 'var=value' to
    # escape '=' characters.
    def test_update_add_slash_rpc_to_dns(self):
        prefix, txt = 'slashtextrec', ['Th\\=is=is a test']
        prefix = 'rpc' + prefix
        name = "%s.%s" % (prefix, self.get_dns_domain())

        rec = data_to_dns_record(dnsp.DNS_TYPE_TXT, '"Th\\\\=is=is a test"')
        add_rec_buf = dnsserver.DNS_RPC_RECORD_BUF()
        add_rec_buf.rec = rec
        try:
            self.rpc_conn.DnssrvUpdateRecord2(dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                                     0, self.server_ip, self.get_dns_domain(),
                                     name, add_rec_buf, None)

        except WERRORError as e:
            self.fail(str(e))

        try:
            self.check_query_txt(prefix, txt)

        finally:
            self.rpc_conn.DnssrvUpdateRecord2(dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                                              0, self.server_ip, self.get_dns_domain(),
                                              name, None, add_rec_buf)

    def test_update_add_two_txt_records(self):
        "test adding two txt records works"
        prefix, txt = 'textrec2', ['"This is a test"',
                                   '"and this is a test, too"']
        p = self.make_txt_update(prefix, txt)
        (response, response_packet) = self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.check_query_txt(prefix, txt)
        self.assertIsNotNone(dns_record_match(self.rpc_conn, self.server_ip,
                             self.get_dns_domain(),
                             "%s.%s" % (prefix, self.get_dns_domain()),
                             dnsp.DNS_TYPE_TXT, '"\\"This is a test\\""' +
                             ' "\\"and this is a test, too\\""'))

    def test_update_add_two_rpc_to_dns(self):
        prefix, txt = 'textrec2', ['"This is a test"',
                                   '"and this is a test, too"']
        prefix = 'rpc' + prefix
        name = "%s.%s" % (prefix, self.get_dns_domain())

        rec = data_to_dns_record(dnsp.DNS_TYPE_TXT,
                                '"\\"This is a test\\""' +
                                ' "\\"and this is a test, too\\""')
        add_rec_buf = dnsserver.DNS_RPC_RECORD_BUF()
        add_rec_buf.rec = rec
        try:
            self.rpc_conn.DnssrvUpdateRecord2(dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                                     0, self.server_ip, self.get_dns_domain(),
                                     name, add_rec_buf, None)

        except WERRORError as e:
            self.fail(str(e))

        try:
            self.check_query_txt(prefix, txt)
        finally:
            self.rpc_conn.DnssrvUpdateRecord2(dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                                              0, self.server_ip, self.get_dns_domain(),
                                              name, None, add_rec_buf)

    def test_update_add_empty_txt_records(self):
        "test adding two txt records works"
        prefix, txt = 'emptytextrec', []
        p = self.make_txt_update(prefix, txt)
        (response, response_packet) = self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.check_query_txt(prefix, txt)
        self.assertIsNotNone(dns_record_match(self.rpc_conn, self.server_ip,
                             self.get_dns_domain(),
                             "%s.%s" % (prefix, self.get_dns_domain()),
                             dnsp.DNS_TYPE_TXT, ''))

    def test_update_add_empty_rpc_to_dns(self):
        prefix, txt = 'rpcemptytextrec', []

        name = "%s.%s" % (prefix, self.get_dns_domain())

        rec = data_to_dns_record(dnsp.DNS_TYPE_TXT, '')
        add_rec_buf = dnsserver.DNS_RPC_RECORD_BUF()
        add_rec_buf.rec = rec
        try:
            self.rpc_conn.DnssrvUpdateRecord2(dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                                     0, self.server_ip, self.get_dns_domain(),
                                     name, add_rec_buf, None)
        except WERRORError as e:
            self.fail(str(e))

        try:
            self.check_query_txt(prefix, txt)
        finally:
            self.rpc_conn.DnssrvUpdateRecord2(dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                                              0, self.server_ip, self.get_dns_domain(),
                                              name, None, add_rec_buf)

TestProgram(module=__name__, opts=subunitopts)
