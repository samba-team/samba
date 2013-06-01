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

import os
import struct
import random
from samba import socket
import samba.ndr as ndr
import samba.dcerpc.dns as dns
from samba.tests import TestCase

FILTER=''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])


class DNSTest(TestCase):

    def errstr(self, errcode):
        "Return a readable error code"
        string_codes = [
            "OK",
            "FORMERR",
            "SERVFAIL",
            "NXDOMAIN",
            "NOTIMP",
            "REFUSED",
            "YXDOMAIN",
            "YXRRSET",
            "NXRRSET",
            "NOTAUTH",
            "NOTZONE",
        ]

        return string_codes[errcode]


    def assert_dns_rcode_equals(self, packet, rcode):
        "Helper function to check return code"
        p_errcode = packet.operation & 0x000F
        self.assertEquals(p_errcode, rcode, "Expected RCODE %s, got %s" %
                            (self.errstr(rcode), self.errstr(p_errcode)))

    def assert_dns_opcode_equals(self, packet, opcode):
        "Helper function to check opcode"
        p_opcode = packet.operation & 0x7800
        self.assertEquals(p_opcode, opcode, "Expected OPCODE %s, got %s" %
                            (opcode, p_opcode))

    def make_name_packet(self, opcode, qid=None):
        "Helper creating a dns.name_packet"
        p = dns.name_packet()
        if qid is None:
            p.id = random.randint(0x0, 0xffff)
        p.operation = opcode
        p.questions = []
        return p

    def finish_name_packet(self, packet, questions):
        "Helper to finalize a dns.name_packet"
        packet.qdcount = len(questions)
        packet.questions = questions

    def make_name_question(self, name, qtype, qclass):
        "Helper creating a dns.name_question"
        q = dns.name_question()
        q.name = name
        q.question_type = qtype
        q.question_class = qclass
        return q

    def get_dns_domain(self):
        "Helper to get dns domain"
        return os.getenv('REALM', 'example.com').lower()

    def dns_transaction_udp(self, packet, host=os.getenv('SERVER_IP'), dump=False):
        "send a DNS query and read the reply"
        s = None
        try:
            send_packet = ndr.ndr_pack(packet)
            if dump:
                print self.hexdump(send_packet)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
            s.connect((host, 53))
            s.send(send_packet, 0)
            recv_packet = s.recv(2048, 0)
            if dump:
                print self.hexdump(recv_packet)
            return ndr.ndr_unpack(dns.name_packet, recv_packet)
        finally:
            if s is not None:
                s.close()

    def dns_transaction_tcp(self, packet, host=os.getenv('SERVER_IP'), dump=False):
        "send a DNS query and read the reply"
        s = None
        try:
            send_packet = ndr.ndr_pack(packet)
            if dump:
                print self.hexdump(send_packet)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
            s.connect((host, 53))
            tcp_packet = struct.pack('!H', len(send_packet))
            tcp_packet += send_packet
            s.send(tcp_packet, 0)
            recv_packet = s.recv(0xffff + 2, 0)
            if dump:
                print self.hexdump(recv_packet)
            return ndr.ndr_unpack(dns.name_packet, recv_packet[2:])
        finally:
                if s is not None:
                    s.close()

    def hexdump(self, src, length=8):
        N=0; result=''
        while src:
           s,src = src[:length],src[length:]
           hexa = ' '.join(["%02X"%ord(x) for x in s])
           s = s.translate(FILTER)
           result += "%04X   %-*s   %s\n" % (N, length*3, hexa, s)
           N+=length
        return result

class TestSimpleQueries(DNSTest):

    def test_one_a_query(self):
        "create a query packet containing one query record"
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        name = "%s.%s" % (os.getenv('SERVER'), self.get_dns_domain())
        q = self.make_name_question(name, dns.DNS_QTYPE_A, dns.DNS_QCLASS_IN)
        print "asking for ", q.name
        questions.append(q)

        self.finish_name_packet(p, questions)
        response = self.dns_transaction_udp(p)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)
        self.assertEquals(response.ancount, 1)
        self.assertEquals(response.answers[0].rdata,
                          os.getenv('SERVER_IP'))

    def test_one_a_query_tcp(self):
        "create a query packet containing one query record via TCP"
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        name = "%s.%s" % (os.getenv('SERVER'), self.get_dns_domain())
        q = self.make_name_question(name, dns.DNS_QTYPE_A, dns.DNS_QCLASS_IN)
        print "asking for ", q.name
        questions.append(q)

        self.finish_name_packet(p, questions)
        response = self.dns_transaction_tcp(p)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)
        self.assertEquals(response.ancount, 1)
        self.assertEquals(response.answers[0].rdata,
                          os.getenv('SERVER_IP'))

    def test_two_queries(self):
        "create a query packet containing two query records"
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        name = "%s.%s" % (os.getenv('SERVER'), self.get_dns_domain())
        q = self.make_name_question(name, dns.DNS_QTYPE_A, dns.DNS_QCLASS_IN)
        questions.append(q)

        name = "%s.%s" % ('bogusname', self.get_dns_domain())
        q = self.make_name_question(name, dns.DNS_QTYPE_A, dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        response = self.dns_transaction_udp(p)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_FORMERR)

    def test_qtype_all_query(self):
        "create a QTYPE_ALL query"
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        name = "%s.%s" % (os.getenv('SERVER'), self.get_dns_domain())
        q = self.make_name_question(name, dns.DNS_QTYPE_ALL, dns.DNS_QCLASS_IN)
        print "asking for ", q.name
        questions.append(q)

        self.finish_name_packet(p, questions)
        response = self.dns_transaction_udp(p)

        num_answers = 1
        dc_ipv6 = os.getenv('SERVER_IPV6')
        if dc_ipv6 is not None:
            num_answers += 1

        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)
        self.assertEquals(response.ancount, num_answers)
        self.assertEquals(response.answers[0].rdata,
                          os.getenv('SERVER_IP'))
        if dc_ipv6 is not None:
            self.assertEquals(response.answers[1].rdata, dc_ipv6)

    def test_qclass_none_query(self):
        "create a QCLASS_NONE query"
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        name = "%s.%s" % (os.getenv('SERVER'), self.get_dns_domain())
        q = self.make_name_question(name, dns.DNS_QTYPE_ALL, dns.DNS_QCLASS_NONE)
        questions.append(q)

        self.finish_name_packet(p, questions)
        response = self.dns_transaction_udp(p)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_NOTIMP)

# Only returns an authority section entry in BIND and Win DNS
# FIXME: Enable one Samba implements this feature
#    def test_soa_hostname_query(self):
#        "create a SOA query for a hostname"
#        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
#        questions = []
#
#        name = "%s.%s" % (os.getenv('SERVER'), self.get_dns_domain())
#        q = self.make_name_question(name, dns.DNS_QTYPE_SOA, dns.DNS_QCLASS_IN)
#        questions.append(q)
#
#        self.finish_name_packet(p, questions)
#        response = self.dns_transaction_udp(p)
#        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
#        self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)
#        # We don't get SOA records for single hosts
#        self.assertEquals(response.ancount, 0)

    def test_soa_domain_query(self):
        "create a SOA query for a domain"
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        name = self.get_dns_domain()
        q = self.make_name_question(name, dns.DNS_QTYPE_SOA, dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        response = self.dns_transaction_udp(p)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)
        self.assertEquals(response.ancount, 1)


class TestDNSUpdates(DNSTest):

    def test_two_updates(self):
        "create two update requests"
        p = self.make_name_packet(dns.DNS_OPCODE_UPDATE)
        updates = []

        name = "%s.%s" % (os.getenv('SERVER'), self.get_dns_domain())
        u = self.make_name_question(name, dns.DNS_QTYPE_A, dns.DNS_QCLASS_IN)
        updates.append(u)

        name = self.get_dns_domain()
        u = self.make_name_question(name, dns.DNS_QTYPE_A, dns.DNS_QCLASS_IN)
        updates.append(u)

        self.finish_name_packet(p, updates)
        response = self.dns_transaction_udp(p)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_FORMERR)

    def test_update_wrong_qclass(self):
        "create update with DNS_QCLASS_NONE"
        p = self.make_name_packet(dns.DNS_OPCODE_UPDATE)
        updates = []

        name = self.get_dns_domain()
        u = self.make_name_question(name, dns.DNS_QTYPE_A, dns.DNS_QCLASS_NONE)
        updates.append(u)

        self.finish_name_packet(p, updates)
        response = self.dns_transaction_udp(p)
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
        r.name = "%s.%s" % (os.getenv('SERVER'), self.get_dns_domain())
        r.rr_type = dns.DNS_QTYPE_TXT
        r.rr_class = dns.DNS_QCLASS_NONE
        r.ttl = 1
        r.length = 0
        prereqs.append(r)

        p.ancount = len(prereqs)
        p.answers = prereqs

        response = self.dns_transaction_udp(p)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_FORMERR)

# I'd love to test this one, but it segfaults. :)
#    def test_update_prereq_with_non_null_length(self):
#        "test update with a non-null length"
#        p = self.make_name_packet(dns.DNS_OPCODE_UPDATE)
#        updates = []
#
#        name = self.get_dns_domain()
#
#        u = self.make_name_question(name, dns.DNS_QTYPE_SOA, dns.DNS_QCLASS_IN)
#        updates.append(u)
#        self.finish_name_packet(p, updates)
#
#        prereqs = []
#        r = dns.res_rec()
#        r.name = "%s.%s" % (os.getenv('SERVER'), self.get_dns_domain())
#        r.rr_type = dns.DNS_QTYPE_TXT
#        r.rr_class = dns.DNS_QCLASS_ANY
#        r.ttl = 0
#        r.length = 1
#        prereqs.append(r)
#
#        p.ancount = len(prereqs)
#        p.answers = prereqs
#
#        response = self.dns_transaction_udp(p)
#        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_FORMERR)

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

        response = self.dns_transaction_udp(p)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_NXRRSET)

    def test_update_add_txt_record(self):
        "test adding records works"
        p = self.make_name_packet(dns.DNS_OPCODE_UPDATE)
        updates = []

        name = self.get_dns_domain()

        u = self.make_name_question(name, dns.DNS_QTYPE_SOA, dns.DNS_QCLASS_IN)
        updates.append(u)
        self.finish_name_packet(p, updates)

        updates = []
        r = dns.res_rec()
        r.name = "textrec.%s" % self.get_dns_domain()
        r.rr_type = dns.DNS_QTYPE_TXT
        r.rr_class = dns.DNS_QCLASS_IN
        r.ttl = 900
        r.length = 0xffff
        rdata = dns.txt_record()
        rdata.txt = '"This is a test"'
        r.rdata = rdata
        updates.append(r)
        p.nscount = len(updates)
        p.nsrecs = updates

        response = self.dns_transaction_udp(p)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)

        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        name = "textrec.%s" % self.get_dns_domain()
        q = self.make_name_question(name, dns.DNS_QTYPE_TXT, dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        response = self.dns_transaction_udp(p)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.assertEquals(response.ancount, 1)
        self.assertEquals(response.answers[0].rdata.txt, '"This is a test"')

    def test_update_add_two_txt_records(self):
        "test adding two txt records works"
        p = self.make_name_packet(dns.DNS_OPCODE_UPDATE)
        updates = []

        name = self.get_dns_domain()

        u = self.make_name_question(name, dns.DNS_QTYPE_SOA, dns.DNS_QCLASS_IN)
        updates.append(u)
        self.finish_name_packet(p, updates)

        updates = []
        r = dns.res_rec()
        r.name = "textrec2.%s" % self.get_dns_domain()
        r.rr_type = dns.DNS_QTYPE_TXT
        r.rr_class = dns.DNS_QCLASS_IN
        r.ttl = 900
        r.length = 0xffff
        rdata = dns.txt_record()
        rdata.txt = '"This is a test" "and this is a test, too"'
        r.rdata = rdata
        updates.append(r)
        p.nscount = len(updates)
        p.nsrecs = updates

        response = self.dns_transaction_udp(p)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)

        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        name = "textrec2.%s" % self.get_dns_domain()
        q = self.make_name_question(name, dns.DNS_QTYPE_TXT, dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        response = self.dns_transaction_udp(p)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.assertEquals(response.ancount, 1)
        self.assertEquals(response.answers[0].rdata.txt, '"This is a test" "and this is a test, too"')

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
        rdata = dns.txt_record()
        rdata.txt = '"This is a test"'
        r.rdata = rdata
        updates.append(r)
        p.nscount = len(updates)
        p.nsrecs = updates

        response = self.dns_transaction_udp(p)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)

        # Now check the record is around
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []
        q = self.make_name_question(NAME, dns.DNS_QTYPE_TXT, dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        response = self.dns_transaction_udp(p)
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
        rdata = dns.txt_record()
        rdata.txt = '"This is a test"'
        r.rdata = rdata
        updates.append(r)
        p.nscount = len(updates)
        p.nsrecs = updates

        response = self.dns_transaction_udp(p)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)

        # And finally check it's gone
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        q = self.make_name_question(NAME, dns.DNS_QTYPE_TXT, dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        response = self.dns_transaction_udp(p)
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
        rdata = dns.txt_record()
        rdata.txt = '"This is a test"'
        r.rdata = rdata
        updates.append(r)
        p.nscount = len(updates)
        p.nsrecs = updates

        response = self.dns_transaction_udp(p)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)

        # Now check the record is around
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []
        q = self.make_name_question(NAME, dns.DNS_QTYPE_TXT, dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        response = self.dns_transaction_udp(p)
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
        rdata = dns.txt_record()
        rdata.txt = '"This is a test"'
        r.rdata = rdata
        updates.append(r)
        p.nscount = len(updates)
        p.nsrecs = updates

        response = self.dns_transaction_udp(p)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)

        # check it's gone
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        q = self.make_name_question(NAME, dns.DNS_QTYPE_TXT, dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        response = self.dns_transaction_udp(p)
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
        rdata = dns.txt_record()
        rdata.txt = '"This is a test"'
        r.rdata = rdata
        updates.append(r)
        p.nscount = len(updates)
        p.nsrecs = updates

        response = self.dns_transaction_udp(p)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)

        # Now check the record is around
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []
        q = self.make_name_question(NAME, dns.DNS_QTYPE_TXT, dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        response = self.dns_transaction_udp(p)
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

        response = self.dns_transaction_udp(p)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)

        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        name = "%s" % self.get_dns_domain()
        q = self.make_name_question(name, dns.DNS_QTYPE_MX, dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        response = self.dns_transaction_udp(p)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.assertEqual(response.ancount, 1)
        ans = response.answers[0]
        self.assertEqual(ans.rr_type, dns.DNS_QTYPE_MX)
        self.assertEqual(ans.rdata.preference, 10)
        self.assertEqual(ans.rdata.exchange, 'mail.%s' % self.get_dns_domain())


class TestComplexQueries(DNSTest):

    def setUp(self):
        super(TestComplexQueries, self).setUp()
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
        r.rr_class = dns.DNS_QCLASS_IN
        r.ttl = 900
        r.length = 0xffff
        r.rdata = "%s.%s" % (os.getenv('SERVER'), self.get_dns_domain())
        updates.append(r)
        p.nscount = len(updates)
        p.nsrecs = updates

        response = self.dns_transaction_udp(p)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)

    def tearDown(self):
        super(TestComplexQueries, self).tearDown()
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
        r.rdata = "%s.%s" % (os.getenv('SERVER'), self.get_dns_domain())
        updates.append(r)
        p.nscount = len(updates)
        p.nsrecs = updates

        response = self.dns_transaction_udp(p)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)

    def test_one_a_query(self):
        "create a query packet containing one query record"
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        name = "cname_test.%s" % self.get_dns_domain()
        q = self.make_name_question(name, dns.DNS_QTYPE_A, dns.DNS_QCLASS_IN)
        print "asking for ", q.name
        questions.append(q)

        self.finish_name_packet(p, questions)
        response = self.dns_transaction_udp(p)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)
        self.assertEquals(response.ancount, 2)
        self.assertEquals(response.answers[0].rr_type, dns.DNS_QTYPE_CNAME)
        self.assertEquals(response.answers[0].rdata, "%s.%s" %
                          (os.getenv('SERVER'), self.get_dns_domain()))
        self.assertEquals(response.answers[1].rr_type, dns.DNS_QTYPE_A)
        self.assertEquals(response.answers[1].rdata,
                          os.getenv('SERVER_IP'))

class TestInvalidQueries(DNSTest):

    def test_one_a_query(self):
        "send 0 bytes follows by create a query packet containing one query record"

        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
            s.connect((os.getenv('SERVER_IP'), 53))
            s.send("", 0)
        finally:
            if s is not None:
                s.close()

        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        name = "%s.%s" % (os.getenv('SERVER'), self.get_dns_domain())
        q = self.make_name_question(name, dns.DNS_QTYPE_A, dns.DNS_QCLASS_IN)
        print "asking for ", q.name
        questions.append(q)

        self.finish_name_packet(p, questions)
        response = self.dns_transaction_udp(p)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)
        self.assertEquals(response.ancount, 1)
        self.assertEquals(response.answers[0].rdata,
                          os.getenv('SERVER_IP'))

if __name__ == "__main__":
    import unittest
    unittest.main()
