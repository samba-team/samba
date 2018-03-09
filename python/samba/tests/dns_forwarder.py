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
import samba
import time
import errno
import samba.ndr as ndr
from samba import credentials, param
from samba.tests import TestCase
from samba.dcerpc import dns, dnsp, dnsserver
from samba.netcmd.dns import TXTRecord, dns_record_match, data_to_dns_record
from samba.tests.subunitrun import SubunitOptions, TestProgram
import samba.getopt as options
import optparse
import subprocess

parser = optparse.OptionParser("dns_forwarder.py <server name> <server ip> (dns forwarder)+ [options]")
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

if len(args) < 3:
    parser.print_usage()
    sys.exit(1)

server_name = args[0]
server_ip = args[1]
dns_servers = args[2:]

creds.set_krb_forwardable(credentials.NO_KRB_FORWARDABLE)

def make_txt_record(records):
    rdata_txt = dns.txt_record()
    s_list = dnsp.string_list()
    s_list.count = len(records)
    s_list.str = records
    rdata_txt.txt = s_list
    return rdata_txt


class DNSTest(TestCase):

    errcodes = dict((v, k) for k, v in vars(dns).items() if k.startswith('DNS_RCODE_'))

    def assert_dns_rcode_equals(self, packet, rcode):
        "Helper function to check return code"
        p_errcode = packet.operation & 0x000F
        self.assertEquals(p_errcode, rcode, "Expected RCODE %s, got %s" %
                          (self.errcodes[rcode], self.errcodes[p_errcode]))

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
        return self.creds.get_realm().lower()

    def dns_transaction_udp(self, packet, host=server_ip,
                            dump=False, timeout=timeout):
        "send a DNS query and read the reply"
        s = None
        try:
            send_packet = ndr.ndr_pack(packet)
            if dump:
                print(self.hexdump(send_packet))
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
            s.settimeout(timeout)
            s.connect((host, 53))
            s.send(send_packet, 0)
            recv_packet = s.recv(2048, 0)
            if dump:
                print(self.hexdump(recv_packet))
            return ndr.ndr_unpack(dns.name_packet, recv_packet)
        finally:
            if s is not None:
                s.close()

    def make_cname_update(self, key, value):
        p = self.make_name_packet(dns.DNS_OPCODE_UPDATE)

        name = self.get_dns_domain()
        u = self.make_name_question(name, dns.DNS_QTYPE_SOA, dns.DNS_QCLASS_IN)
        self.finish_name_packet(p, [u])

        r = dns.res_rec()
        r.name = key
        r.rr_type = dns.DNS_QTYPE_CNAME
        r.rr_class = dns.DNS_QCLASS_IN
        r.ttl = 900
        r.length = 0xffff
        rdata = value
        r.rdata = rdata
        p.nscount = 1
        p.nsrecs = [r]
        response = self.dns_transaction_udp(p)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)



def contact_real_server(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    s.connect((host, port))
    return s


class TestDnsForwarding(DNSTest):
    def __init__(self, *args, **kwargs):
        super(TestDnsForwarding, self).__init__(*args, **kwargs)
        self.subprocesses = []

    def setUp(self):
        super(TestDnsForwarding, self).setUp()
        self.server = server_name
        self.server_ip = server_ip
        self.lp = lp
        self.creds = creds

    def start_toy_server(self, host, port, id):
        python = sys.executable
        p = subprocess.Popen([python,
                              os.path.join(samba.source_tree_topdir(),
                                           'python/samba/tests/'
                                           'dns_forwarder_helpers/server.py'),
                             host, str(port), id])
        self.subprocesses.append(p)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
        for i in xrange(300):
            time.sleep(0.05)
            s.connect((host, port))
            try:
                s.send('timeout 0', 0)
            except socket.error as e:
                if e.errno in (errno.ECONNREFUSED, errno.EHOSTUNREACH):
                    continue

            if p.returncode is not None:
                self.fail("Toy server has managed to die already!")

            return s

    def tearDown(self):
        super(TestDnsForwarding, self).tearDown()
        for p in self.subprocesses:
            p.kill()

    def test_comatose_forwarder(self):
        s = self.start_toy_server(dns_servers[0], 53, 'forwarder1')
        s.send("timeout 1000000", 0)

        # make DNS query
        name = "an-address-that-will-not-resolve"
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        q = self.make_name_question(name, dns.DNS_QTYPE_TXT, dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        send_packet = ndr.ndr_pack(p)

        s.send(send_packet, 0)
        s.settimeout(1)
        try:
            s.recv(0xffff + 2, 0)
            self.fail("DNS forwarder should have been inactive")
        except socket.timeout:
            # Expected forwarder to be dead
            pass

    def test_no_active_forwarder(self):
        ad = contact_real_server(server_ip, 53)

        name = "dsfsfds.dsfsdfs"
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        q = self.make_name_question(name, dns.DNS_QTYPE_TXT, dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        send_packet = ndr.ndr_pack(p)

        self.finish_name_packet(p, questions)
        p.operation |= dns.DNS_FLAG_RECURSION_DESIRED
        send_packet = ndr.ndr_pack(p)

        ad.send(send_packet, 0)
        ad.settimeout(timeout)
        try:
            data = ad.recv(0xffff + 2, 0)
            data = ndr.ndr_unpack(dns.name_packet, data)
            self.assert_dns_rcode_equals(data, dns.DNS_RCODE_SERVFAIL)
            self.assertEqual(data.ancount, 0)
        except socket.timeout:
            self.fail("DNS server is too slow (timeout %s)" % timeout)

    def test_no_flag_recursive_forwarder(self):
        ad = contact_real_server(server_ip, 53)

        name = "dsfsfds.dsfsdfs"
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        q = self.make_name_question(name, dns.DNS_QTYPE_TXT, dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        send_packet = ndr.ndr_pack(p)

        self.finish_name_packet(p, questions)
        # Leave off the recursive flag
        send_packet = ndr.ndr_pack(p)

        ad.send(send_packet, 0)
        ad.settimeout(timeout)
        try:
            data = ad.recv(0xffff + 2, 0)
            data = ndr.ndr_unpack(dns.name_packet, data)
            self.assert_dns_rcode_equals(data, dns.DNS_RCODE_NXDOMAIN)
            self.assertEqual(data.ancount, 0)
        except socket.timeout:
            self.fail("DNS server is too slow (timeout %s)" % timeout)

    def test_single_forwarder(self):
        s = self.start_toy_server(dns_servers[0], 53, 'forwarder1')
        ad = contact_real_server(server_ip, 53)
        name = "dsfsfds.dsfsdfs"
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        q = self.make_name_question(name, dns.DNS_QTYPE_CNAME,
                                    dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        p.operation |= dns.DNS_FLAG_RECURSION_DESIRED
        send_packet = ndr.ndr_pack(p)

        ad.send(send_packet, 0)
        ad.settimeout(timeout)
        try:
            data = ad.recv(0xffff + 2, 0)
            data = ndr.ndr_unpack(dns.name_packet, data)
            self.assert_dns_rcode_equals(data, dns.DNS_RCODE_OK)
            self.assertEqual('forwarder1', data.answers[0].rdata)
        except socket.timeout:
            self.fail("DNS server is too slow (timeout %s)" % timeout)

    def test_single_forwarder_not_actually_there(self):
        ad = contact_real_server(server_ip, 53)
        name = "dsfsfds.dsfsdfs"
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        q = self.make_name_question(name, dns.DNS_QTYPE_CNAME,
                                    dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        p.operation |= dns.DNS_FLAG_RECURSION_DESIRED
        send_packet = ndr.ndr_pack(p)

        ad.send(send_packet, 0)
        ad.settimeout(timeout)
        try:
            data = ad.recv(0xffff + 2, 0)
            data = ndr.ndr_unpack(dns.name_packet, data)
            self.assert_dns_rcode_equals(data, dns.DNS_RCODE_SERVFAIL)
        except socket.timeout:
            self.fail("DNS server is too slow (timeout %s)" % timeout)


    def test_single_forwarder_waiting_forever(self):
        s = self.start_toy_server(dns_servers[0], 53, 'forwarder1')
        s.send('timeout 10000', 0)
        ad = contact_real_server(server_ip, 53)
        name = "dsfsfds.dsfsdfs"
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        q = self.make_name_question(name, dns.DNS_QTYPE_CNAME,
                                    dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        p.operation |= dns.DNS_FLAG_RECURSION_DESIRED
        send_packet = ndr.ndr_pack(p)

        ad.send(send_packet, 0)
        ad.settimeout(timeout)
        try:
            data = ad.recv(0xffff + 2, 0)
            data = ndr.ndr_unpack(dns.name_packet, data)
            self.assert_dns_rcode_equals(data, dns.DNS_RCODE_SERVFAIL)
        except socket.timeout:
            self.fail("DNS server is too slow (timeout %s)" % timeout)

    def test_double_forwarder_first_frozen(self):
        if len(dns_servers) < 2:
            print("Ignoring test_double_forwarder_first_frozen")
            return
        s1 = self.start_toy_server(dns_servers[0], 53, 'forwarder1')
        s2 = self.start_toy_server(dns_servers[1], 53, 'forwarder2')
        s1.send('timeout 1000', 0)
        ad = contact_real_server(server_ip, 53)
        name = "dsfsfds.dsfsdfs"
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        q = self.make_name_question(name, dns.DNS_QTYPE_CNAME,
                                    dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        p.operation |= dns.DNS_FLAG_RECURSION_DESIRED
        send_packet = ndr.ndr_pack(p)

        ad.send(send_packet, 0)
        ad.settimeout(timeout)
        try:
            data = ad.recv(0xffff + 2, 0)
            data = ndr.ndr_unpack(dns.name_packet, data)
            self.assert_dns_rcode_equals(data, dns.DNS_RCODE_OK)
            self.assertEqual('forwarder2', data.answers[0].rdata)
        except socket.timeout:
            self.fail("DNS server is too slow (timeout %s)" % timeout)

    def test_double_forwarder_first_down(self):
        if len(dns_servers) < 2:
            print("Ignoring test_double_forwarder_first_down")
            return
        s2 = self.start_toy_server(dns_servers[1], 53, 'forwarder2')
        ad = contact_real_server(server_ip, 53)
        name = "dsfsfds.dsfsdfs"
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        q = self.make_name_question(name, dns.DNS_QTYPE_CNAME,
                                    dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        p.operation |= dns.DNS_FLAG_RECURSION_DESIRED
        send_packet = ndr.ndr_pack(p)

        ad.send(send_packet, 0)
        ad.settimeout(timeout)
        try:
            data = ad.recv(0xffff + 2, 0)
            data = ndr.ndr_unpack(dns.name_packet, data)
            self.assert_dns_rcode_equals(data, dns.DNS_RCODE_OK)
            self.assertEqual('forwarder2', data.answers[0].rdata)
        except socket.timeout:
            self.fail("DNS server is too slow (timeout %s)" % timeout)

    def test_double_forwarder_both_slow(self):
        if len(dns_servers) < 2:
            print("Ignoring test_double_forwarder_both_slow")
            return
        s1 = self.start_toy_server(dns_servers[0], 53, 'forwarder1')
        s2 = self.start_toy_server(dns_servers[1], 53, 'forwarder2')
        s1.send('timeout 1.5', 0)
        s2.send('timeout 1.5', 0)
        ad = contact_real_server(server_ip, 53)
        name = "dsfsfds.dsfsdfs"
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        q = self.make_name_question(name, dns.DNS_QTYPE_CNAME,
                                    dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        p.operation |= dns.DNS_FLAG_RECURSION_DESIRED
        send_packet = ndr.ndr_pack(p)

        ad.send(send_packet, 0)
        ad.settimeout(timeout)
        try:
            data = ad.recv(0xffff + 2, 0)
            data = ndr.ndr_unpack(dns.name_packet, data)
            self.assert_dns_rcode_equals(data, dns.DNS_RCODE_OK)
            self.assertEqual('forwarder1', data.answers[0].rdata)
        except socket.timeout:
            self.fail("DNS server is too slow (timeout %s)" % timeout)

    def test_cname(self):
        s1 = self.start_toy_server(dns_servers[0], 53, 'forwarder1')

        ad = contact_real_server(server_ip, 53)
        name = "resolve.cname"
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        q = self.make_name_question(name, dns.DNS_QTYPE_CNAME,
                                    dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        p.operation |= dns.DNS_FLAG_RECURSION_DESIRED
        send_packet = ndr.ndr_pack(p)

        ad.send(send_packet, 0)
        ad.settimeout(timeout)
        try:
            data = ad.recv(0xffff + 2, 0)
            data = ndr.ndr_unpack(dns.name_packet, data)
            self.assert_dns_rcode_equals(data, dns.DNS_RCODE_OK)
            self.assertEqual(len(data.answers), 1)
            self.assertEqual('forwarder1', data.answers[0].rdata)
        except socket.timeout:
            self.fail("DNS server is too slow (timeout %s)" % timeout)

    def test_double_cname(self):
        s1 = self.start_toy_server(dns_servers[0], 53, 'forwarder1')

        name = 'resolve.cname.%s' % self.get_dns_domain()
        self.make_cname_update(name, "dsfsfds.dsfsdfs")

        ad = contact_real_server(server_ip, 53)

        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []
        q = self.make_name_question(name, dns.DNS_QTYPE_A,
                                    dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        p.operation |= dns.DNS_FLAG_RECURSION_DESIRED
        send_packet = ndr.ndr_pack(p)

        ad.send(send_packet, 0)
        ad.settimeout(timeout)
        try:
            data = ad.recv(0xffff + 2, 0)
            data = ndr.ndr_unpack(dns.name_packet, data)
            self.assert_dns_rcode_equals(data, dns.DNS_RCODE_OK)
            self.assertEqual('forwarder1', data.answers[1].rdata)
        except socket.timeout:
            self.fail("DNS server is too slow (timeout %s)" % timeout)

    def test_cname_forwarding_with_slow_server(self):
        if len(dns_servers) < 2:
            print("Ignoring test_cname_forwarding_with_slow_server")
            return
        s1 = self.start_toy_server(dns_servers[0], 53, 'forwarder1')
        s2 = self.start_toy_server(dns_servers[1], 53, 'forwarder2')
        s1.send('timeout 10000', 0)

        name = 'resolve.cname.%s' % self.get_dns_domain()
        self.make_cname_update(name, "dsfsfds.dsfsdfs")

        ad = contact_real_server(server_ip, 53)

        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []
        q = self.make_name_question(name, dns.DNS_QTYPE_A,
                                    dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        p.operation |= dns.DNS_FLAG_RECURSION_DESIRED
        send_packet = ndr.ndr_pack(p)

        ad.send(send_packet, 0)
        ad.settimeout(timeout)
        try:
            data = ad.recv(0xffff + 2, 0)
            data = ndr.ndr_unpack(dns.name_packet, data)
            self.assert_dns_rcode_equals(data, dns.DNS_RCODE_OK)
            self.assertEqual('forwarder2', data.answers[-1].rdata)
        except socket.timeout:
            self.fail("DNS server is too slow (timeout %s)" % timeout)

    def test_cname_forwarding_with_server_down(self):
        if len(dns_servers) < 2:
            print("Ignoring test_cname_forwarding_with_server_down")
            return
        s2 = self.start_toy_server(dns_servers[1], 53, 'forwarder2')

        name1 = 'resolve1.cname.%s' % self.get_dns_domain()
        name2 = 'resolve2.cname.%s' % self.get_dns_domain()
        self.make_cname_update(name1, name2)
        self.make_cname_update(name2, "dsfsfds.dsfsdfs")

        ad = contact_real_server(server_ip, 53)

        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []
        q = self.make_name_question(name1, dns.DNS_QTYPE_A,
                                    dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        p.operation |= dns.DNS_FLAG_RECURSION_DESIRED
        send_packet = ndr.ndr_pack(p)

        ad.send(send_packet, 0)
        ad.settimeout(timeout)
        try:
            data = ad.recv(0xffff + 2, 0)
            data = ndr.ndr_unpack(dns.name_packet, data)
            self.assert_dns_rcode_equals(data, dns.DNS_RCODE_OK)
            self.assertEqual('forwarder2', data.answers[-1].rdata)
        except socket.timeout:
            self.fail("DNS server is too slow (timeout %s)" % timeout)

    def test_cname_forwarding_with_lots_of_cnames(self):
        name3 = 'resolve3.cname.%s' % self.get_dns_domain()
        s1 = self.start_toy_server(dns_servers[0], 53, name3)

        name1 = 'resolve1.cname.%s' % self.get_dns_domain()
        name2 = 'resolve2.cname.%s' % self.get_dns_domain()
        self.make_cname_update(name1, name2)
        self.make_cname_update(name3, name1)
        self.make_cname_update(name2, "dsfsfds.dsfsdfs")

        ad = contact_real_server(server_ip, 53)

        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []
        q = self.make_name_question(name1, dns.DNS_QTYPE_A,
                                    dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        p.operation |= dns.DNS_FLAG_RECURSION_DESIRED
        send_packet = ndr.ndr_pack(p)

        ad.send(send_packet, 0)
        ad.settimeout(timeout)
        try:
            data = ad.recv(0xffff + 2, 0)
            data = ndr.ndr_unpack(dns.name_packet, data)
            # This should cause a loop in Windows
            # (which is restricted by a 20 CNAME limit)
            #
            # The reason it doesn't here is because forwarded CNAME have no
            # additional processing in the internal DNS server.
            self.assert_dns_rcode_equals(data, dns.DNS_RCODE_OK)
            self.assertEqual(name3, data.answers[-1].rdata)
        except socket.timeout:
            self.fail("DNS server is too slow (timeout %s)" % timeout)

TestProgram(module=__name__, opts=subunitopts)
