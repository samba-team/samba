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

from samba import dsdb
from samba.ndr import ndr_unpack, ndr_pack
from samba.samdb import SamDB
from samba.auth import system_session
import ldb
from ldb import ERR_OPERATIONS_ERROR
import os
import sys
import struct
import socket
import samba.ndr as ndr
from samba import credentials
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
        (response, response_packet) =\
            self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)
        self.assertEqual(response.ancount, 1)
        self.assertEqual(response.answers[0].rdata,
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
        (response, response_packet) =\
            self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)
        self.assertEqual(response.ancount, 1)
        self.assertEqual(
            response.answers[0].rdata.mname.upper(),
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
        (response, response_packet) =\
            self.dns_transaction_tcp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)
        self.assertEqual(response.ancount, 1)
        self.assertEqual(response.answers[0].rdata,
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
        (response, response_packet) =\
            self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)
        self.assertEqual(response.ancount, 0)

        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        name = "invalid-%s.%s" % (self.server, self.get_dns_domain())
        q = self.make_name_question(name, dns.DNS_QTYPE_MX, dns.DNS_QCLASS_IN)
        print("asking for ", q.name)
        questions.append(q)

        self.finish_name_packet(p, questions)
        (response, response_packet) =\
            self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_NXDOMAIN)
        self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)
        self.assertEqual(response.ancount, 0)

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
            (response, response_packet) =\
                self.dns_transaction_udp(p, host=server_ip)
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
        (response, response_packet) =\
            self.dns_transaction_udp(p, host=server_ip)

        num_answers = 1
        dc_ipv6 = os.getenv('SERVER_IPV6')
        if dc_ipv6 is not None:
            num_answers += 1

        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)
        self.assertEqual(response.ancount, num_answers)
        self.assertEqual(response.answers[0].rdata,
                          self.server_ip)
        if dc_ipv6 is not None:
            self.assertEqual(response.answers[1].rdata, dc_ipv6)

    def test_qclass_none_query(self):
        "create a QCLASS_NONE query"
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        name = "%s.%s" % (self.server, self.get_dns_domain())
        q = self.make_name_question(
            name,
            dns.DNS_QTYPE_ALL,
            dns.DNS_QCLASS_NONE)
        questions.append(q)

        self.finish_name_packet(p, questions)
        try:
            (response, response_packet) =\
                self.dns_transaction_udp(p, host=server_ip)
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
        (response, response_packet) =\
            self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)
        # We don't get SOA records for single hosts
        self.assertEqual(response.ancount, 0)
        # But we do respond with an authority section
        self.assertEqual(response.nscount, 1)

    def test_soa_unknown_hostname_query(self):
        "create a SOA query for an unknown hostname"
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        name = "foobar.%s" % (self.get_dns_domain())
        q = self.make_name_question(name, dns.DNS_QTYPE_SOA, dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        (response, response_packet) =\
            self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_NXDOMAIN)
        self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)
        # We don't get SOA records for single hosts
        self.assertEqual(response.ancount, 0)
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
        (response, response_packet) =\
            self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)
        self.assertEqual(response.ancount, 1)
        self.assertEqual(response.answers[0].rdata.minimum, 3600)


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
            (response, response_packet) =\
                self.dns_transaction_udp(p, host=server_ip)
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
        (response, response_packet) =\
            self.dns_transaction_udp(p, host=server_ip)
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
            (response, response_packet) =\
                self.dns_transaction_udp(p, host=server_ip)
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

        (response, response_packet) =\
            self.dns_transaction_udp(p, host=server_ip)
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

        (response, response_packet) =\
            self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_NXRRSET)

    def test_update_add_txt_record(self):
        "test adding records works"
        prefix, txt = 'textrec', ['"This is a test"']
        p = self.make_txt_update(prefix, txt)
        (response, response_packet) =\
            self.dns_transaction_udp(p, host=server_ip)
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

        (response, response_packet) =\
            self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)

        # Now check the record is around
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []
        q = self.make_name_question(NAME, dns.DNS_QTYPE_TXT, dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        (response, response_packet) =\
            self.dns_transaction_udp(p, host=server_ip)
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

        (response, response_packet) =\
            self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)

        # And finally check it's gone
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        q = self.make_name_question(NAME, dns.DNS_QTYPE_TXT, dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        (response, response_packet) =\
            self.dns_transaction_udp(p, host=server_ip)
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

        (response, response_packet) =\
            self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)

        # Now check the record is around
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []
        q = self.make_name_question(NAME, dns.DNS_QTYPE_TXT, dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        (response, response_packet) =\
            self.dns_transaction_udp(p, host=server_ip)
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

        (response, response_packet) =\
            self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)

        # check it's gone
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        q = self.make_name_question(NAME, dns.DNS_QTYPE_TXT, dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        (response, response_packet) =\
            self.dns_transaction_udp(p, host=server_ip)
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

        (response, response_packet) =\
            self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)

        # Now check the record is around
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []
        q = self.make_name_question(NAME, dns.DNS_QTYPE_TXT, dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        (response, response_packet) =\
            self.dns_transaction_udp(p, host=server_ip)
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

        (response, response_packet) =\
            self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)

        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        name = "%s" % self.get_dns_domain()
        q = self.make_name_question(name, dns.DNS_QTYPE_MX, dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        (response, response_packet) =\
            self.dns_transaction_udp(p, host=server_ip)
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
        r.rdata = value
        p.nscount = 1
        p.nsrecs = [r]
        (response, response_packet) =\
            self.dns_transaction_udp(p, host=server_ip)
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
            q = self.make_name_question(name,
                                        dns.DNS_QTYPE_A,
                                        dns.DNS_QCLASS_IN)
            print("asking for ", q.name)
            questions.append(q)

            self.finish_name_packet(p, questions)
            (response, response_packet) =\
                self.dns_transaction_udp(p, host=self.server_ip)
            self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
            self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)
            self.assertEqual(response.ancount, 2)
            self.assertEqual(response.answers[0].rr_type, dns.DNS_QTYPE_CNAME)
            self.assertEqual(response.answers[0].rdata, "%s.%s" %
                              (self.server, self.get_dns_domain()))
            self.assertEqual(response.answers[1].rr_type, dns.DNS_QTYPE_A)
            self.assertEqual(response.answers[1].rdata,
                              self.server_ip)

        finally:
            # Delete the record
            p = self.make_name_packet(dns.DNS_OPCODE_UPDATE)
            updates = []

            name = self.get_dns_domain()

            u = self.make_name_question(name,
                                        dns.DNS_QTYPE_SOA,
                                        dns.DNS_QCLASS_IN)
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

            (response, response_packet) =\
                self.dns_transaction_udp(p, host=self.server_ip)
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
        (response, response_packet) =\
            self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)
        self.assertEqual(response.ancount, 3)

        self.assertEqual(response.answers[0].rr_type, dns.DNS_QTYPE_CNAME)
        self.assertEqual(response.answers[0].name, name1)
        self.assertEqual(response.answers[0].rdata, name2)

        self.assertEqual(response.answers[1].rr_type, dns.DNS_QTYPE_CNAME)
        self.assertEqual(response.answers[1].name, name2)
        self.assertEqual(response.answers[1].rdata, name0)

        self.assertEqual(response.answers[2].rr_type, dns.DNS_QTYPE_A)
        self.assertEqual(response.answers[2].rdata,
                          self.server_ip)

    def test_invalid_empty_cname(self):
        name0 = "cnamedotprefix0.%s" % self.get_dns_domain()
        try:
            self.make_dns_update(name0, "", dns.DNS_QTYPE_CNAME)
        except AssertionError:
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
        (response, response_packet) =\
            self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)

        # CNAME should return all intermediate results!
        # Only the A records exists, not the TXT.
        self.assertEqual(response.ancount, 2)

        self.assertEqual(response.answers[0].rr_type, dns.DNS_QTYPE_CNAME)
        self.assertEqual(response.answers[0].name, name1)
        self.assertEqual(response.answers[0].rdata, name2)

        self.assertEqual(response.answers[1].rr_type, dns.DNS_QTYPE_CNAME)
        self.assertEqual(response.answers[1].name, name2)
        self.assertEqual(response.answers[1].rdata, name0)

    def test_cname_loop(self):
        cname1 = "cnamelooptestrec." + self.get_dns_domain()
        cname2 = "cnamelooptestrec2." + self.get_dns_domain()
        cname3 = "cnamelooptestrec3." + self.get_dns_domain()
        self.make_dns_update(cname1, cname2, dnsp.DNS_TYPE_CNAME)
        self.make_dns_update(cname2, cname3, dnsp.DNS_TYPE_CNAME)
        self.make_dns_update(cname3, cname1, dnsp.DNS_TYPE_CNAME)

        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        q = self.make_name_question(cname1,
                                    dns.DNS_QTYPE_A,
                                    dns.DNS_QCLASS_IN)
        questions.append(q)
        self.finish_name_packet(p, questions)

        (response, response_packet) =\
            self.dns_transaction_udp(p, host=self.server_ip)

        max_recursion_depth = 20
        self.assertEqual(len(response.answers), max_recursion_depth)

    # Make sure cname limit doesn't count other records.  This is a generic
    # test called in tests below
    def max_rec_test(self, rtype, rec_gen):
        name = "limittestrec{0}.{1}".format(rtype, self.get_dns_domain())
        limit = 20
        num_recs_to_enter = limit + 5

        for i in range(1, num_recs_to_enter+1):
            ip = rec_gen(i)
            self.make_dns_update(name, ip, rtype)

        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        q = self.make_name_question(name,
                                    rtype,
                                    dns.DNS_QCLASS_IN)
        questions.append(q)
        self.finish_name_packet(p, questions)

        (response, response_packet) =\
            self.dns_transaction_udp(p, host=self.server_ip)

        self.assertEqual(len(response.answers), num_recs_to_enter)

    def test_record_limit_A(self):
        def ip4_gen(i):
            return "127.0.0." + str(i)
        self.max_rec_test(rtype=dns.DNS_QTYPE_A, rec_gen=ip4_gen)

    def test_record_limit_AAAA(self):
        def ip6_gen(i):
            return "AAAA:0:0:0:0:0:0:" + str(i)
        self.max_rec_test(rtype=dns.DNS_QTYPE_AAAA, rec_gen=ip6_gen)

    def test_record_limit_SRV(self):
        def srv_gen(i):
            rec = dns.srv_record()
            rec.priority = 1
            rec.weight = 1
            rec.port = 92
            rec.target = "srvtestrec" + str(i)
            return rec
        self.max_rec_test(rtype=dns.DNS_QTYPE_SRV, rec_gen=srv_gen)

    # Same as test_record_limit_A but with a preceding CNAME follow
    def test_cname_limit(self):
        cname1 = "cnamelimittestrec." + self.get_dns_domain()
        cname2 = "cnamelimittestrec2." + self.get_dns_domain()
        cname3 = "cnamelimittestrec3." + self.get_dns_domain()
        ip_prefix = '127.0.0.'
        limit = 20
        num_recs_to_enter = limit + 5

        self.make_dns_update(cname1, cname2, dnsp.DNS_TYPE_CNAME)
        self.make_dns_update(cname2, cname3, dnsp.DNS_TYPE_CNAME)
        num_arecs_to_enter = num_recs_to_enter - 2
        for i in range(1, num_arecs_to_enter+1):
            ip = ip_prefix + str(i)
            self.make_dns_update(cname3, ip, dns.DNS_QTYPE_A)

        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        q = self.make_name_question(cname1,
                                    dns.DNS_QTYPE_A,
                                    dns.DNS_QCLASS_IN)
        questions.append(q)
        self.finish_name_packet(p, questions)

        (response, response_packet) =\
            self.dns_transaction_udp(p, host=self.server_ip)

        self.assertEqual(len(response.answers), num_recs_to_enter)

    # ANY query on cname record shouldn't follow the link
    def test_cname_any_query(self):
        cname1 = "cnameanytestrec." + self.get_dns_domain()
        cname2 = "cnameanytestrec2." + self.get_dns_domain()
        cname3 = "cnameanytestrec3." + self.get_dns_domain()

        self.make_dns_update(cname1, cname2, dnsp.DNS_TYPE_CNAME)
        self.make_dns_update(cname2, cname3, dnsp.DNS_TYPE_CNAME)

        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        q = self.make_name_question(cname1,
                                    dns.DNS_QTYPE_ALL,
                                    dns.DNS_QCLASS_IN)
        questions.append(q)
        self.finish_name_packet(p, questions)

        (response, response_packet) =\
            self.dns_transaction_udp(p, host=self.server_ip)

        self.assertEqual(len(response.answers), 1)
        self.assertEqual(response.answers[0].name, cname1)
        self.assertEqual(response.answers[0].rdata, cname2)


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
        """send 0 bytes follows by create a query packet
           containing one query record"""

        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
            s.connect((self.server_ip, 53))
            s.send(b"", 0)
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
        (response, response_packet) =\
            self.dns_transaction_udp(p, host=self.server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)
        self.assertEqual(response.ancount, 1)
        self.assertEqual(response.answers[0].rdata,
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
            host = self.server_ip
            s.connect((host, 53))
            tcp_packet = struct.pack('!H', len(send_packet))
            tcp_packet += send_packet
            s.send(tcp_packet, 0)
            recv_packet = s.recv(0xffff + 2, 0)
            self.assertEqual(0, len(recv_packet))
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
        self.rpc_conn = dnsserver.dnsserver("ncacn_ip_tcp:%s[sign]" %
                                            (self.server_ip),
                                            self.lp, self.creds)

        self.samdb = SamDB(url="ldap://" + self.server_ip,
                           lp=self.get_loadparm(),
                           session_info=system_session(),
                           credentials=self.creds)
        self.zone_dn = "DC=" + self.zone +\
                       ",CN=MicrosoftDNS,DC=DomainDNSZones," +\
                       str(self.samdb.get_default_basedn())

    def tearDown(self):
        super(TestZones, self).tearDown()

        try:
            self.delete_zone(self.zone)
        except RuntimeError as e:
            (num, string) = e.args
            if num != werror.WERR_DNS_ERROR_ZONE_DOES_NOT_EXIST:
                raise

    def make_zone_obj(self, zone, aging_enabled=False):
        zone_create = dnsserver.DNS_RPC_ZONE_CREATE_INFO_LONGHORN()
        zone_create.pszZoneName = zone
        zone_create.dwZoneType = dnsp.DNS_ZONE_TYPE_PRIMARY
        zone_create.fAging = int(aging_enabled)
        zone_create.dwDpFlags = dnsserver.DNS_DP_DOMAIN_DEFAULT
        zone_create.fDsIntegrated = 1
        zone_create.fLoadExisting = 1
        zone_create.fAllowUpdate = dnsp.DNS_ZONE_UPDATE_UNSECURE
        return zone_create

    def create_zone(self, zone, aging_enabled=False):
        zone_create = self.make_zone_obj(zone, aging_enabled)
        try:
            client_version = dnsserver.DNS_CLIENT_VERSION_LONGHORN
            self.rpc_conn.DnssrvOperation2(client_version,
                                           0,
                                           self.server_ip,
                                           None,
                                           0,
                                           'ZoneCreate',
                                           dnsserver.DNSSRV_TYPEID_ZONE_CREATE,
                                           zone_create)
        except WERRORError as e:
            self.fail(e)

    def set_params(self, **kwargs):
        zone = kwargs.pop('zone', None)
        for key, val in kwargs.items():
            name_param = dnsserver.DNS_RPC_NAME_AND_PARAM()
            name_param.dwParam = val
            name_param.pszNodeName = key

            client_version = dnsserver.DNS_CLIENT_VERSION_LONGHORN
            nap_type = dnsserver.DNSSRV_TYPEID_NAME_AND_PARAM
            try:
                self.rpc_conn.DnssrvOperation2(client_version,
                                               0,
                                               self.server,
                                               zone,
                                               0,
                                               'ResetDwordProperty',
                                               nap_type,
                                               name_param)
            except WERRORError as e:
                self.fail(str(e))

    def ldap_modify_dnsrecs(self, name, func):
        dn = 'DC={0},{1}'.format(name, self.zone_dn)
        dns_recs = self.ldap_get_dns_records(name)
        for rec in dns_recs:
            func(rec)
        update_dict = {'dn': dn, 'dnsRecord': [ndr_pack(r) for r in dns_recs]}
        self.samdb.modify(ldb.Message.from_dict(self.samdb,
                                                update_dict,
                                                ldb.FLAG_MOD_REPLACE))

    def dns_update_record(self, prefix, txt):
        p = self.make_txt_update(prefix, txt, self.zone)
        (code, response) = self.dns_transaction_udp(p, host=self.server_ip)
        self.assert_dns_rcode_equals(code, dns.DNS_RCODE_OK)
        recs = self.ldap_get_dns_records(prefix)
        recs = [r for r in recs if r.data.str == txt]
        self.assertEqual(len(recs), 1)
        return recs[0]

    def dns_tombstone(self, prefix, txt, zone):
        name = prefix + "." + zone

        to = dnsp.DnssrvRpcRecord()
        to.dwTimeStamp = 1000
        to.wType = dnsp.DNS_TYPE_TOMBSTONE

        self.samdb.dns_replace(name, [to])

    def ldap_get_records(self, name):
        # The use of SCOPE_SUBTREE here avoids raising an exception in the
        # 0 results case for a test below.

        expr = "(&(objectClass=dnsNode)(name={0}))".format(name)
        return self.samdb.search(base=self.zone_dn, scope=ldb.SCOPE_SUBTREE,
                                 expression=expr, attrs=["*"])

    def ldap_get_dns_records(self, name):
        records = self.ldap_get_records(name)
        return [ndr_unpack(dnsp.DnssrvRpcRecord, r)
                for r in records[0].get('dnsRecord')]

    def ldap_get_zone_settings(self):
        records = self.samdb.search(base=self.zone_dn, scope=ldb.SCOPE_BASE,
                                    expression="(&(objectClass=dnsZone)" +
                                    "(name={0}))".format(self.zone),
                                    attrs=["dNSProperty"])
        self.assertEqual(len(records), 1)
        props = [ndr_unpack(dnsp.DnsProperty, r)
                 for r in records[0].get('dNSProperty')]

        # We have no choice but to repeat these here.
        zone_prop_ids = {0x00: "EMPTY",
                         0x01: "TYPE",
                         0x02: "ALLOW_UPDATE",
                         0x08: "SECURE_TIME",
                         0x10: "NOREFRESH_INTERVAL",
                         0x11: "SCAVENGING_SERVERS",
                         0x12: "AGING_ENABLED_TIME",
                         0x20: "REFRESH_INTERVAL",
                         0x40: "AGING_STATE",
                         0x80: "DELETED_FROM_HOSTNAME",
                         0x81: "MASTER_SERVERS",
                         0x82: "AUTO_NS_SERVERS",
                         0x83: "DCPROMO_CONVERT",
                         0x90: "SCAVENGING_SERVERS_DA",
                         0x91: "MASTER_SERVERS_DA",
                         0x92: "NS_SERVERS_DA",
                         0x100: "NODE_DBFLAGS"}
        return {zone_prop_ids[p.id].lower(): p.data for p in props}

    def set_aging(self, enable=False):
        self.create_zone(self.zone, aging_enabled=enable)
        self.set_params(NoRefreshInterval=1, RefreshInterval=1,
                        Aging=int(bool(enable)), zone=self.zone,
                        AllowUpdate=dnsp.DNS_ZONE_UPDATE_UNSECURE)

    def test_set_aging(self, enable=True, name='agingtest', txt=['test txt']):
        self.set_aging(enable=True)
        settings = self.ldap_get_zone_settings()
        self.assertTrue(settings['aging_state'] is not None)
        self.assertTrue(settings['aging_state'])

        rec = self.dns_update_record('agingtest', ['test txt'])
        self.assertNotEqual(rec.dwTimeStamp, 0)

    def test_set_aging_disabled(self):
        self.set_aging(enable=False)
        settings = self.ldap_get_zone_settings()
        self.assertTrue(settings['aging_state'] is not None)
        self.assertFalse(settings['aging_state'])

        rec = self.dns_update_record('agingtest', ['test txt'])
        self.assertNotEqual(rec.dwTimeStamp, 0)

    def test_aging_update(self, enable=True):
        name, txt = 'agingtest', ['test txt']
        self.set_aging(enable=True)
        before_mod = self.dns_update_record(name, txt)
        if not enable:
            self.set_params(zone=self.zone, Aging=0)
        dec = 2

        def mod_ts(rec):
            self.assertTrue(rec.dwTimeStamp > 0)
            rec.dwTimeStamp -= dec
        self.ldap_modify_dnsrecs(name, mod_ts)
        after_mod = self.ldap_get_dns_records(name)
        self.assertEqual(len(after_mod), 1)
        after_mod = after_mod[0]
        self.assertEqual(after_mod.dwTimeStamp,
                         before_mod.dwTimeStamp - dec)
        after_update = self.dns_update_record(name, txt)
        after_should_equal = before_mod if enable else after_mod
        self.assertEqual(after_should_equal.dwTimeStamp,
                         after_update.dwTimeStamp)

    def test_aging_update_disabled(self):
        self.test_aging_update(enable=False)

    def test_aging_refresh(self):
        name, txt = 'agingtest', ['test txt']
        self.create_zone(self.zone, aging_enabled=True)
        interval = 10
        self.set_params(NoRefreshInterval=interval, RefreshInterval=interval,
                        Aging=1, zone=self.zone,
                        AllowUpdate=dnsp.DNS_ZONE_UPDATE_UNSECURE)
        before_mod = self.dns_update_record(name, txt)

        def mod_ts(rec):
            self.assertTrue(rec.dwTimeStamp > 0)
            rec.dwTimeStamp -= interval // 2
        self.ldap_modify_dnsrecs(name, mod_ts)
        update_during_norefresh = self.dns_update_record(name, txt)

        def mod_ts(rec):
            self.assertTrue(rec.dwTimeStamp > 0)
            rec.dwTimeStamp -= interval + interval // 2
        self.ldap_modify_dnsrecs(name, mod_ts)
        update_during_refresh = self.dns_update_record(name, txt)
        self.assertEqual(update_during_norefresh.dwTimeStamp,
                         before_mod.dwTimeStamp - interval / 2)
        self.assertEqual(update_during_refresh.dwTimeStamp,
                         before_mod.dwTimeStamp)

    def test_rpc_add_no_timestamp(self):
        name, txt = 'agingtest', ['test txt']
        self.set_aging(enable=True)
        rec_buf = dnsserver.DNS_RPC_RECORD_BUF()
        rec_buf.rec = TXTRecord(txt)
        self.rpc_conn.DnssrvUpdateRecord2(
            dnsserver.DNS_CLIENT_VERSION_LONGHORN,
            0,
            self.server_ip,
            self.zone,
            name,
            rec_buf,
            None)
        recs = self.ldap_get_dns_records(name)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].dwTimeStamp, 0)

    def test_static_record_dynamic_update(self):
        name, txt = 'agingtest', ['test txt']
        txt2 = ['test txt2']
        self.set_aging(enable=True)
        rec_buf = dnsserver.DNS_RPC_RECORD_BUF()
        rec_buf.rec = TXTRecord(txt)
        self.rpc_conn.DnssrvUpdateRecord2(
            dnsserver.DNS_CLIENT_VERSION_LONGHORN,
            0,
            self.server_ip,
            self.zone,
            name,
            rec_buf,
            None)

        rec2 = self.dns_update_record(name, txt2)
        self.assertEqual(rec2.dwTimeStamp, 0)

    def test_dynamic_record_static_update(self):
        name, txt = 'agingtest', ['test txt']
        txt2 = ['test txt2']
        txt3 = ['test txt3']
        self.set_aging(enable=True)

        self.dns_update_record(name, txt)

        rec_buf = dnsserver.DNS_RPC_RECORD_BUF()
        rec_buf.rec = TXTRecord(txt2)
        self.rpc_conn.DnssrvUpdateRecord2(
            dnsserver.DNS_CLIENT_VERSION_LONGHORN,
            0,
            self.server_ip,
            self.zone,
            name,
            rec_buf,
            None)

        self.dns_update_record(name, txt3)

        recs = self.ldap_get_dns_records(name)
        # Put in dict because ldap recs might be out of order
        recs = {str(r.data.str): r for r in recs}
        self.assertNotEqual(recs[str(txt)].dwTimeStamp, 0)
        self.assertEqual(recs[str(txt2)].dwTimeStamp, 0)
        self.assertEqual(recs[str(txt3)].dwTimeStamp, 0)

    def test_dns_tombstone_custom_match_rule(self):
        lp = self.get_loadparm()
        self.samdb = SamDB(url=lp.samdb_url(), lp=lp,
                           session_info=system_session(),
                           credentials=self.creds)

        name, txt = 'agingtest', ['test txt']
        name2, txt2 = 'agingtest2', ['test txt2']
        name3, txt3 = 'agingtest3', ['test txt3']
        name4, txt4 = 'agingtest4', ['test txt4']
        name5, txt5 = 'agingtest5', ['test txt5']

        self.create_zone(self.zone, aging_enabled=True)
        interval = 10
        self.set_params(NoRefreshInterval=interval, RefreshInterval=interval,
                        Aging=1, zone=self.zone,
                        AllowUpdate=dnsp.DNS_ZONE_UPDATE_UNSECURE)

        self.dns_update_record(name, txt)

        self.dns_update_record(name2, txt)
        self.dns_update_record(name2, txt2)

        self.dns_update_record(name3, txt)
        self.dns_update_record(name3, txt2)
        last_update = self.dns_update_record(name3, txt3)

        # Modify txt1 of the first 2 names
        def mod_ts(rec):
            if rec.data.str == txt:
                rec.dwTimeStamp -= 2
        self.ldap_modify_dnsrecs(name, mod_ts)
        self.ldap_modify_dnsrecs(name2, mod_ts)

        # create a static dns record.
        rec_buf = dnsserver.DNS_RPC_RECORD_BUF()
        rec_buf.rec = TXTRecord(txt4)
        self.rpc_conn.DnssrvUpdateRecord2(
            dnsserver.DNS_CLIENT_VERSION_LONGHORN,
            0,
            self.server_ip,
            self.zone,
            name4,
            rec_buf,
            None)

        # Create a tomb stoned record.
        self.dns_update_record(name5, txt5)
        self.dns_tombstone(name5, txt5, self.zone)

        self.ldap_get_dns_records(name3)
        expr = "(dnsRecord:1.3.6.1.4.1.7165.4.5.3:={0})"
        expr = expr.format(int(last_update.dwTimeStamp) - 1)
        try:
            res = self.samdb.search(base=self.zone_dn, scope=ldb.SCOPE_SUBTREE,
                                    expression=expr, attrs=["*"])
        except ldb.LdbError as e:
            self.fail(str(e))
        updated_names = {str(r.get('name')) for r in res}
        self.assertEqual(updated_names, set([name, name2]))

    def test_dns_tombstone_custom_match_rule_no_records(self):
        lp = self.get_loadparm()
        self.samdb = SamDB(url=lp.samdb_url(), lp=lp,
                           session_info=system_session(),
                           credentials=self.creds)

        self.create_zone(self.zone, aging_enabled=True)
        interval = 10
        self.set_params(NoRefreshInterval=interval, RefreshInterval=interval,
                        Aging=1, zone=self.zone,
                        AllowUpdate=dnsp.DNS_ZONE_UPDATE_UNSECURE)

        expr = "(dnsRecord:1.3.6.1.4.1.7165.4.5.3:={0})"
        expr = expr.format(1)

        try:
            res = self.samdb.search(base=self.zone_dn, scope=ldb.SCOPE_SUBTREE,
                                    expression=expr, attrs=["*"])
        except ldb.LdbError as e:
            self.fail(str(e))
        self.assertEqual(0, len(res))

    def test_dns_tombstone_custom_match_rule_fail(self):
        self.create_zone(self.zone, aging_enabled=True)
        samdb = SamDB(url=lp.samdb_url(),
                      lp=lp,
                      session_info=system_session(),
                      credentials=self.creds)

        # Property name in not dnsRecord
        expr = "(dnsProperty:1.3.6.1.4.1.7165.4.5.3:=1)"
        res = samdb.search(base=self.zone_dn, scope=ldb.SCOPE_SUBTREE,
                           expression=expr, attrs=["*"])
        self.assertEqual(len(res), 0)

        # No value for tombstone time
        try:
            expr = "(dnsRecord:1.3.6.1.4.1.7165.4.5.3:=)"
            res = samdb.search(base=self.zone_dn, scope=ldb.SCOPE_SUBTREE,
                               expression=expr, attrs=["*"])
            self.assertEqual(len(res), 0)
            self.fail("Exception: ldb.ldbError not generated")
        except ldb.LdbError as e:
            (num, msg) = e.args
            self.assertEqual(num, ERR_OPERATIONS_ERROR)

        # Tombstone time = -
        try:
            expr = "(dnsRecord:1.3.6.1.4.1.7165.4.5.3:=-)"
            res = samdb.search(base=self.zone_dn, scope=ldb.SCOPE_SUBTREE,
                               expression=expr, attrs=["*"])
            self.assertEqual(len(res), 0)
            self.fail("Exception: ldb.ldbError not generated")
        except ldb.LdbError as e:
            (num, _) = e.args
            self.assertEqual(num, ERR_OPERATIONS_ERROR)

        # Tombstone time longer than 64 characters
        try:
            expr = "(dnsRecord:1.3.6.1.4.1.7165.4.5.3:={0})"
            expr = expr.format("1" * 65)
            res = samdb.search(base=self.zone_dn, scope=ldb.SCOPE_SUBTREE,
                               expression=expr, attrs=["*"])
            self.assertEqual(len(res), 0)
            self.fail("Exception: ldb.ldbError not generated")
        except ldb.LdbError as e:
            (num, _) = e.args
            self.assertEqual(num, ERR_OPERATIONS_ERROR)

        # Non numeric Tombstone time
        try:
            expr = "(dnsRecord:1.3.6.1.4.1.7165.4.5.3:=expired)"
            res = samdb.search(base=self.zone_dn, scope=ldb.SCOPE_SUBTREE,
                               expression=expr, attrs=["*"])
            self.assertEqual(len(res), 0)
            self.fail("Exception: ldb.ldbError not generated")
        except ldb.LdbError as e:
            (num, _) = e.args
            self.assertEqual(num, ERR_OPERATIONS_ERROR)

        # Non system session
        try:
            db = SamDB(url="ldap://" + self.server_ip,
                       lp=self.get_loadparm(),
                       credentials=self.creds)

            expr = "(dnsRecord:1.3.6.1.4.1.7165.4.5.3:=2)"
            res = db.search(base=self.zone_dn, scope=ldb.SCOPE_SUBTREE,
                            expression=expr, attrs=["*"])
            self.assertEqual(len(res), 0)
            self.fail("Exception: ldb.ldbError not generated")
        except ldb.LdbError as e:
            (num, _) = e.args
            self.assertEqual(num, ERR_OPERATIONS_ERROR)

    def test_basic_scavenging(self):
        lp = self.get_loadparm()
        self.samdb = SamDB(url=lp.samdb_url(), lp=lp,
                           session_info=system_session(),
                           credentials=self.creds)

        self.create_zone(self.zone, aging_enabled=True)
        interval = 1
        self.set_params(NoRefreshInterval=interval, RefreshInterval=interval,
                        zone=self.zone, Aging=1,
                        AllowUpdate=dnsp.DNS_ZONE_UPDATE_UNSECURE)
        name, txt = 'agingtest', ['test txt']
        name2, txt2 = 'agingtest2', ['test txt2']
        name3, txt3 = 'agingtest3', ['test txt3']
        name4, txt4 = 'agingtest4', ['test txt4']
        name5, txt5 = 'agingtest5', ['test txt5']
        self.dns_update_record(name, txt)
        self.dns_update_record(name2, txt)
        self.dns_update_record(name2, txt2)
        self.dns_update_record(name3, txt)
        self.dns_update_record(name3, txt2)

        # Create a tomb stoned record.
        self.dns_update_record(name4, txt4)
        self.dns_tombstone(name4, txt4, self.zone)
        records = self.ldap_get_records(name4)
        self.assertTrue("dNSTombstoned" in records[0])
        self.assertEqual(records[0]["dNSTombstoned"][0], b"TRUE")

        # Create an un-tombstoned record, with dnsTombstoned: FALSE
        self.dns_update_record(name5, txt5)
        self.dns_tombstone(name5, txt5, self.zone)
        self.dns_update_record(name5, txt5)
        records = self.ldap_get_records(name5)
        self.assertTrue("dNSTombstoned" in records[0])
        self.assertEqual(records[0]["dNSTombstoned"][0], b"FALSE")

        last_add = self.dns_update_record(name3, txt3)

        def mod_ts(rec):
            self.assertTrue(rec.dwTimeStamp > 0)
            if rec.data.str == txt:
                rec.dwTimeStamp -= interval * 5

        def mod_ts_all(rec):
            rec.dwTimeStamp -= interval * 5
        self.ldap_modify_dnsrecs(name, mod_ts)
        self.ldap_modify_dnsrecs(name2, mod_ts)
        self.ldap_modify_dnsrecs(name3, mod_ts)
        self.ldap_modify_dnsrecs(name5, mod_ts_all)
        self.assertTrue(callable(getattr(dsdb, '_scavenge_dns_records', None)))
        dsdb._scavenge_dns_records(self.samdb)

        recs = self.ldap_get_dns_records(name)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].wType, dnsp.DNS_TYPE_TOMBSTONE)
        records = self.ldap_get_records(name)
        self.assertTrue("dNSTombstoned" in records[0])
        self.assertEqual(records[0]["dNSTombstoned"][0], b"TRUE")

        recs = self.ldap_get_dns_records(name2)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].wType, dnsp.DNS_TYPE_TXT)
        self.assertEqual(recs[0].data.str, txt2)

        recs = self.ldap_get_dns_records(name3)
        self.assertEqual(len(recs), 2)
        txts = {str(r.data.str) for r in recs}
        self.assertEqual(txts, {str(txt2), str(txt3)})
        self.assertEqual(recs[0].wType, dnsp.DNS_TYPE_TXT)
        self.assertEqual(recs[1].wType, dnsp.DNS_TYPE_TXT)

        recs = self.ldap_get_dns_records(name4)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].wType, dnsp.DNS_TYPE_TOMBSTONE)
        records = self.ldap_get_records(name4)
        self.assertTrue("dNSTombstoned" in records[0])
        self.assertEqual(records[0]["dNSTombstoned"][0], b"TRUE")

        recs = self.ldap_get_dns_records(name5)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].wType, dnsp.DNS_TYPE_TOMBSTONE)
        records = self.ldap_get_records(name5)
        self.assertTrue("dNSTombstoned" in records[0])
        self.assertEqual(records[0]["dNSTombstoned"][0], b"TRUE")

        for make_it_work in [False, True]:
            inc = -1 if make_it_work else 1

            def mod_ts(rec):
                rec.data = (last_add.dwTimeStamp - 24 * 14) + inc
            self.ldap_modify_dnsrecs(name, mod_ts)
            dsdb._dns_delete_tombstones(self.samdb)
            recs = self.ldap_get_records(name)
            if make_it_work:
                self.assertEqual(len(recs), 0)
            else:
                self.assertEqual(len(recs), 1)

    def test_fully_qualified_zone(self):

        def create_zone_expect_exists(zone):
            try:
                zone_create = self.make_zone_obj(zone)
                client_version = dnsserver.DNS_CLIENT_VERSION_LONGHORN
                zc_type = dnsserver.DNSSRV_TYPEID_ZONE_CREATE
                self.rpc_conn.DnssrvOperation2(client_version,
                                               0,
                                               self.server_ip,
                                               None,
                                               0,
                                               'ZoneCreate',
                                               zc_type,
                                               zone_create)
            except WERRORError as e:
                enum, _ = e.args
                if enum != werror.WERR_DNS_ERROR_ZONE_ALREADY_EXISTS:
                    self.fail(e)
                return
            self.fail("Zone {} should already exist".format(zone))

        # Create unqualified, then check creating qualified fails.
        self.create_zone(self.zone)
        create_zone_expect_exists(self.zone + '.')

        # Same again, but the other way around.
        self.create_zone(self.zone + '2.')
        create_zone_expect_exists(self.zone + '2')

        client_version = dnsserver.DNS_CLIENT_VERSION_LONGHORN
        request_filter = dnsserver.DNS_ZONE_REQUEST_PRIMARY
        tid = dnsserver.DNSSRV_TYPEID_DWORD
        typeid, res = self.rpc_conn.DnssrvComplexOperation2(client_version,
                                                            0,
                                                            self.server_ip,
                                                            None,
                                                            'EnumZones',
                                                            tid,
                                                            request_filter)

        self.delete_zone(self.zone)
        self.delete_zone(self.zone + '2')

        # Two zones should've been created, neither of them fully qualified.
        zones_we_just_made = []
        zones = [str(z.pszZoneName) for z in res.ZoneArray]
        for zone in zones:
            if zone.startswith(self.zone):
                zones_we_just_made.append(zone)
        self.assertEqual(len(zones_we_just_made), 2)
        self.assertEqual(set(zones_we_just_made), {self.zone + '2', self.zone})

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

        (response, response_packet) =\
            self.dns_transaction_udp(p, host=server_ip)
        # Windows returns OK while BIND logically seems to return NXDOMAIN
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_NXDOMAIN)
        self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)
        self.assertEqual(response.ancount, 0)

        self.create_zone(zone)
        (response, response_packet) =\
            self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)
        self.assertEqual(response.ancount, 1)
        self.assertEqual(response.answers[0].rr_type, dns.DNS_QTYPE_SOA)

        self.delete_zone(zone)
        (response, response_packet) =\
            self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_NXDOMAIN)
        self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)
        self.assertEqual(response.ancount, 0)

    def set_dnsProperty_zero_length(self, dnsproperty_id):
        records = self.samdb.search(base=self.zone_dn, scope=ldb.SCOPE_BASE,
                                    expression="(&(objectClass=dnsZone)" +
                                    "(name={0}))".format(self.zone),
                                    attrs=["dNSProperty"])
        self.assertEqual(len(records), 1)
        props = [ndr_unpack(dnsp.DnsProperty, r)
                 for r in records[0].get('dNSProperty')]
        new_props = [ndr.ndr_pack(p) for p in props if p.id == dnsproperty_id]

        zero_length_p = dnsp.DnsProperty_short()
        zero_length_p.id = dnsproperty_id
        zero_length_p.namelength = 1
        zero_length_p.name = 1
        new_props += [ndr.ndr_pack(zero_length_p)]

        dn = records[0].dn
        update_dict = {'dn': dn, 'dnsProperty': new_props}
        self.samdb.modify(ldb.Message.from_dict(self.samdb,
                                                update_dict,
                                                ldb.FLAG_MOD_REPLACE))

    def test_update_while_dnsProperty_zero_length(self):
        self.create_zone(self.zone)
        self.set_dnsProperty_zero_length(dnsp.DSPROPERTY_ZONE_ALLOW_UPDATE)
        rec = self.dns_update_record('dnspropertytest', ['test txt'])
        self.assertNotEqual(rec.dwTimeStamp, 0)

    def test_enum_zones_while_dnsProperty_zero_length(self):
        self.create_zone(self.zone)
        self.set_dnsProperty_zero_length(dnsp.DSPROPERTY_ZONE_ALLOW_UPDATE)
        client_version = dnsserver.DNS_CLIENT_VERSION_LONGHORN
        request_filter = dnsserver.DNS_ZONE_REQUEST_PRIMARY
        tid = dnsserver.DNSSRV_TYPEID_DWORD
        typeid, res = self.rpc_conn.DnssrvComplexOperation2(client_version,
                                                            0,
                                                            self.server_ip,
                                                            None,
                                                            'EnumZones',
                                                            tid,
                                                            request_filter)

    def test_rpc_zone_update_while_dnsProperty_zero_length(self):
        self.create_zone(self.zone)
        self.set_dnsProperty_zero_length(dnsp.DSPROPERTY_ZONE_ALLOW_UPDATE)
        self.set_params(zone=self.zone, AllowUpdate=dnsp.DNS_ZONE_UPDATE_SECURE)

    def test_rpc_zone_update_while_other_dnsProperty_zero_length(self):
        self.create_zone(self.zone)
        self.set_dnsProperty_zero_length(dnsp.DSPROPERTY_ZONE_MASTER_SERVERS_DA)
        self.set_params(zone=self.zone, AllowUpdate=dnsp.DNS_ZONE_UPDATE_SECURE)

class TestRPCRoundtrip(DNSTest):
    def setUp(self):
        super(TestRPCRoundtrip, self).setUp()
        global server, server_ip, lp, creds
        self.server = server_name
        self.server_ip = server_ip
        self.lp = lp
        self.creds = creds
        self.rpc_conn = dnsserver.dnsserver("ncacn_ip_tcp:%s[sign]" %
                                            (self.server_ip),
                                            self.lp,
                                            self.creds)

    def tearDown(self):
        super(TestRPCRoundtrip, self).tearDown()

    def rpc_update(self, fqn=None, data=None, wType=None, delete=False):
        fqn = fqn or ("rpctestrec." + self.get_dns_domain())

        rec = data_to_dns_record(wType, data)
        add_rec_buf = dnsserver.DNS_RPC_RECORD_BUF()
        add_rec_buf.rec = rec

        add_arg = add_rec_buf
        del_arg = None
        if delete:
            add_arg = None
            del_arg = add_rec_buf

        self.rpc_conn.DnssrvUpdateRecord2(
            dnsserver.DNS_CLIENT_VERSION_LONGHORN,
            0,
            self.server_ip,
            self.get_dns_domain(),
            fqn,
            add_arg,
            del_arg)

    def test_rpc_self_referencing_cname(self):
        cname = "cnametest2_unqual_rec_loop"
        cname_fqn = "%s.%s" % (cname, self.get_dns_domain())

        try:
            self.rpc_update(fqn=cname, data=cname_fqn,
                            wType=dnsp.DNS_TYPE_CNAME, delete=True)
        except WERRORError as e:
            if e.args[0] != werror.WERR_DNS_ERROR_RECORD_DOES_NOT_EXIST:
                self.fail("RPC DNS gaven wrong error on pre-test cleanup "
                          "for self referencing CNAME: %s" % e.args[0])

        try:
            self.rpc_update(fqn=cname, wType=dnsp.DNS_TYPE_CNAME, data=cname_fqn)
        except WERRORError as e:
            if e.args[0] != werror.WERR_DNS_ERROR_CNAME_LOOP:
                self.fail("RPC DNS gaven wrong error on insertion of "
                          "self referencing CNAME: %s" % e.args[0])
            return

        self.fail("RPC DNS allowed insertion of self referencing CNAME")

    def test_update_add_txt_rpc_to_dns(self):
        prefix, txt = 'rpctextrec', ['"This is a test"']

        name = "%s.%s" % (prefix, self.get_dns_domain())

        rec = data_to_dns_record(dnsp.DNS_TYPE_TXT, '"\\"This is a test\\""')
        add_rec_buf = dnsserver.DNS_RPC_RECORD_BUF()
        add_rec_buf.rec = rec
        try:
            self.rpc_conn.DnssrvUpdateRecord2(
                dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                0,
                self.server_ip,
                self.get_dns_domain(),
                name,
                add_rec_buf,
                None)

        except WERRORError as e:
            self.fail(str(e))

        try:
            self.check_query_txt(prefix, txt)
        finally:
            self.rpc_conn.DnssrvUpdateRecord2(
                dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                0,
                self.server_ip,
                self.get_dns_domain(),
                name,
                None,
                add_rec_buf)

    def test_update_add_null_padded_txt_record(self):
        "test adding records works"
        prefix, txt = 'pad1textrec', ['"This is a test"', '', '']
        p = self.make_txt_update(prefix, txt)
        (response, response_packet) =\
            self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.check_query_txt(prefix, txt)
        self.assertIsNotNone(
            dns_record_match(self.rpc_conn,
                             self.server_ip,
                             self.get_dns_domain(),
                             "%s.%s" % (prefix, self.get_dns_domain()),
                             dnsp.DNS_TYPE_TXT,
                             '"\\"This is a test\\"" "" ""'))

        prefix, txt = 'pad2textrec', ['"This is a test"', '', '', 'more text']
        p = self.make_txt_update(prefix, txt)
        (response, response_packet) =\
            self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.check_query_txt(prefix, txt)
        self.assertIsNotNone(
            dns_record_match(
                self.rpc_conn,
                self.server_ip,
                self.get_dns_domain(),
                "%s.%s" % (prefix, self.get_dns_domain()),
                dnsp.DNS_TYPE_TXT,
                '"\\"This is a test\\"" "" "" "more text"'))

        prefix, txt = 'pad3textrec', ['', '', '"This is a test"']
        p = self.make_txt_update(prefix, txt)
        (response, response_packet) =\
            self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.check_query_txt(prefix, txt)
        self.assertIsNotNone(
            dns_record_match(
                self.rpc_conn,
                self.server_ip,
                self.get_dns_domain(),
                "%s.%s" % (prefix, self.get_dns_domain()),
                dnsp.DNS_TYPE_TXT,
                '"" "" "\\"This is a test\\""'))

    def test_update_add_padding_rpc_to_dns(self):
        prefix, txt = 'pad1textrec', ['"This is a test"', '', '']
        prefix = 'rpc' + prefix
        name = "%s.%s" % (prefix, self.get_dns_domain())

        rec = data_to_dns_record(dnsp.DNS_TYPE_TXT,
                                 '"\\"This is a test\\"" "" ""')
        add_rec_buf = dnsserver.DNS_RPC_RECORD_BUF()
        add_rec_buf.rec = rec
        try:
            self.rpc_conn.DnssrvUpdateRecord2(
                dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                0,
                self.server_ip,
                self.get_dns_domain(),
                name,
                add_rec_buf,
                None)

        except WERRORError as e:
            self.fail(str(e))

        try:
            self.check_query_txt(prefix, txt)
        finally:
            self.rpc_conn.DnssrvUpdateRecord2(
                dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                0,
                self.server_ip,
                self.get_dns_domain(),
                name,
                None,
                add_rec_buf)

        prefix, txt = 'pad2textrec', ['"This is a test"', '', '', 'more text']
        prefix = 'rpc' + prefix
        name = "%s.%s" % (prefix, self.get_dns_domain())

        rec = data_to_dns_record(dnsp.DNS_TYPE_TXT,
                                 '"\\"This is a test\\"" "" "" "more text"')
        add_rec_buf = dnsserver.DNS_RPC_RECORD_BUF()
        add_rec_buf.rec = rec
        try:
            self.rpc_conn.DnssrvUpdateRecord2(
                dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                0,
                self.server_ip,
                self.get_dns_domain(),
                name,
                add_rec_buf,
                None)

        except WERRORError as e:
            self.fail(str(e))

        try:
            self.check_query_txt(prefix, txt)
        finally:
            self.rpc_conn.DnssrvUpdateRecord2(
                dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                0,
                self.server_ip,
                self.get_dns_domain(),
                name,
                None,
                add_rec_buf)

        prefix, txt = 'pad3textrec', ['', '', '"This is a test"']
        prefix = 'rpc' + prefix
        name = "%s.%s" % (prefix, self.get_dns_domain())

        rec = data_to_dns_record(dnsp.DNS_TYPE_TXT,
                                 '"" "" "\\"This is a test\\""')
        add_rec_buf = dnsserver.DNS_RPC_RECORD_BUF()
        add_rec_buf.rec = rec
        try:
            self.rpc_conn.DnssrvUpdateRecord2(
                dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                0,
                self.server_ip,
                self.get_dns_domain(),
                name,
                add_rec_buf,
                None)
        except WERRORError as e:
            self.fail(str(e))

        try:
            self.check_query_txt(prefix, txt)
        finally:
            self.rpc_conn.DnssrvUpdateRecord2(
                dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                0,
                self.server_ip,
                self.get_dns_domain(),
                name,
                None,
                add_rec_buf)

    # Test is incomplete due to strlen against txt records
    def test_update_add_null_char_txt_record(self):
        "test adding records works"
        prefix, txt = 'nulltextrec', ['NULL\x00BYTE']
        p = self.make_txt_update(prefix, txt)
        (response, response_packet) =\
            self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.check_query_txt(prefix, ['NULL'])
        self.assertIsNotNone(dns_record_match(self.rpc_conn, self.server_ip,
                                              self.get_dns_domain(),
                                              "%s.%s" % (prefix, self.get_dns_domain()),
                                              dnsp.DNS_TYPE_TXT, '"NULL"'))

        prefix, txt = 'nulltextrec2', ['NULL\x00BYTE', 'NULL\x00BYTE']
        p = self.make_txt_update(prefix, txt)
        (response, response_packet) =\
            self.dns_transaction_udp(p, host=server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.check_query_txt(prefix, ['NULL', 'NULL'])
        self.assertIsNotNone(dns_record_match(self.rpc_conn, self.server_ip,
                                              self.get_dns_domain(),
                                              "%s.%s" % (prefix, self.get_dns_domain()),
                                              dnsp.DNS_TYPE_TXT, '"NULL" "NULL"'))

    def test_update_add_null_char_rpc_to_dns(self):
        prefix = 'rpcnulltextrec'
        name = "%s.%s" % (prefix, self.get_dns_domain())

        rec = data_to_dns_record(dnsp.DNS_TYPE_TXT, '"NULL\x00BYTE"')
        add_rec_buf = dnsserver.DNS_RPC_RECORD_BUF()
        add_rec_buf.rec = rec
        try:
            self.rpc_conn.DnssrvUpdateRecord2(
                dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                0,
                self.server_ip,
                self.get_dns_domain(),
                name,
                add_rec_buf,
                None)

        except WERRORError as e:
            self.fail(str(e))

        try:
            self.check_query_txt(prefix, ['NULL'])
        finally:
            self.rpc_conn.DnssrvUpdateRecord2(
                dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                0,
                self.server_ip,
                self.get_dns_domain(),
                name,
                None,
                add_rec_buf)

    def test_update_add_hex_char_txt_record(self):
        "test adding records works"
        prefix, txt = 'hextextrec', ['HIGH\xFFBYTE']
        p = self.make_txt_update(prefix, txt)
        (response, response_packet) =\
            self.dns_transaction_udp(p, host=server_ip)
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
            self.rpc_conn.DnssrvUpdateRecord2(
                dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                0,
                self.server_ip,
                self.get_dns_domain(),
                name,
                add_rec_buf,
                None)

        except WERRORError as e:
            self.fail(str(e))

        try:
            self.check_query_txt(prefix, txt)
        finally:
            self.rpc_conn.DnssrvUpdateRecord2(
                dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                0,
                self.server_ip,
                self.get_dns_domain(),
                name,
                None,
                add_rec_buf)

    def test_update_add_slash_txt_record(self):
        "test adding records works"
        prefix, txt = 'slashtextrec', ['Th\\=is=is a test']
        p = self.make_txt_update(prefix, txt)
        (response, response_packet) =\
            self.dns_transaction_udp(p, host=server_ip)
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
            self.rpc_conn.DnssrvUpdateRecord2(
                dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                0,
                self.server_ip,
                self.get_dns_domain(),
                name,
                add_rec_buf,
                None)

        except WERRORError as e:
            self.fail(str(e))

        try:
            self.check_query_txt(prefix, txt)

        finally:
            self.rpc_conn.DnssrvUpdateRecord2(
                dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                0,
                self.server_ip,
                self.get_dns_domain(),
                name,
                None,
                add_rec_buf)

    def test_update_add_two_txt_records(self):
        "test adding two txt records works"
        prefix, txt = 'textrec2', ['"This is a test"',
                                   '"and this is a test, too"']
        p = self.make_txt_update(prefix, txt)
        (response, response_packet) =\
            self.dns_transaction_udp(p, host=server_ip)
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
            self.rpc_conn.DnssrvUpdateRecord2(
                dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                0,
                self.server_ip,
                self.get_dns_domain(),
                name,
                add_rec_buf,
                None)

        except WERRORError as e:
            self.fail(str(e))

        try:
            self.check_query_txt(prefix, txt)
        finally:
            self.rpc_conn.DnssrvUpdateRecord2(
                dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                0,
                self.server_ip,
                self.get_dns_domain(),
                name,
                None,
                add_rec_buf)

    def test_update_add_empty_txt_records(self):
        "test adding two txt records works"
        prefix, txt = 'emptytextrec', []
        p = self.make_txt_update(prefix, txt)
        (response, response_packet) =\
            self.dns_transaction_udp(p, host=server_ip)
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
            self.rpc_conn.DnssrvUpdateRecord2(
                dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                0,
                self.server_ip,
                self.get_dns_domain(),
                name,
                add_rec_buf,
                None)
        except WERRORError as e:
            self.fail(str(e))

        try:
            self.check_query_txt(prefix, txt)
        finally:
            self.rpc_conn.DnssrvUpdateRecord2(
                dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                0,
                self.server_ip,
                self.get_dns_domain(),
                name,
                None,
                add_rec_buf)


TestProgram(module=__name__, opts=subunitopts)
