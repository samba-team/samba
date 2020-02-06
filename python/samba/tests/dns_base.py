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

from __future__ import print_function
from samba.tests import TestCaseInTempDir
from samba.dcerpc import dns, dnsp
from samba import gensec, tests
from samba import credentials
import struct
import samba.ndr as ndr
import random
import socket
import uuid
import time
from samba.compat import binary_type


class DNSTest(TestCaseInTempDir):

    def setUp(self):
        super(DNSTest, self).setUp()
        self.timeout = None

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
            "0x0B",
            "0x0C",
            "0x0D",
            "0x0E",
            "0x0F",
            "BADSIG",
            "BADKEY"
        ]

        return string_codes[errcode]

    def assert_rcode_equals(self, rcode, expected):
        "Helper function to check return code"
        self.assertEqual(rcode, expected, "Expected RCODE %s, got %s" %
                          (self.errstr(expected), self.errstr(rcode)))

    def assert_dns_rcode_equals(self, packet, rcode):
        "Helper function to check return code"
        p_errcode = packet.operation & dns.DNS_RCODE
        self.assertEqual(p_errcode, rcode, "Expected RCODE %s, got %s" %
                          (self.errstr(rcode), self.errstr(p_errcode)))

    def assert_dns_opcode_equals(self, packet, opcode):
        "Helper function to check opcode"
        p_opcode = packet.operation & dns.DNS_OPCODE
        self.assertEqual(p_opcode, opcode, "Expected OPCODE %s, got %s" %
                          (opcode, p_opcode))

    def make_name_packet(self, opcode, qid=None):
        "Helper creating a dns.name_packet"
        p = dns.name_packet()
        if qid is None:
            p.id = random.randint(0x0, 0xff00)
        p.operation = opcode
        p.questions = []
        p.additional = []
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

    def make_txt_record(self, records):
        rdata_txt = dns.txt_record()
        s_list = dnsp.string_list()
        s_list.count = len(records)
        s_list.str = records
        rdata_txt.txt = s_list
        return rdata_txt

    def get_dns_domain(self):
        "Helper to get dns domain"
        return self.creds.get_realm().lower()

    def dns_transaction_udp(self, packet, host,
                            dump=False, timeout=None):
        "send a DNS query and read the reply"
        s = None
        if timeout is None:
            timeout = self.timeout
        try:
            send_packet = ndr.ndr_pack(packet)
            if dump:
                print(self.hexdump(send_packet))
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
            s.settimeout(timeout)
            s.connect((host, 53))
            s.sendall(send_packet, 0)
            recv_packet = s.recv(2048, 0)
            if dump:
                print(self.hexdump(recv_packet))
            response = ndr.ndr_unpack(dns.name_packet, recv_packet)
            return (response, recv_packet)
        finally:
            if s is not None:
                s.close()

    def dns_transaction_tcp(self, packet, host,
                            dump=False, timeout=None):
        "send a DNS query and read the reply, also return the raw packet"
        s = None
        if timeout is None:
            timeout = self.timeout
        try:
            send_packet = ndr.ndr_pack(packet)
            if dump:
                print(self.hexdump(send_packet))
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
            s.settimeout(timeout)
            s.connect((host, 53))
            tcp_packet = struct.pack('!H', len(send_packet))
            tcp_packet += send_packet
            s.sendall(tcp_packet)

            recv_packet = s.recv(0xffff + 2, 0)
            if dump:
                print(self.hexdump(recv_packet))
            response = ndr.ndr_unpack(dns.name_packet, recv_packet[2:])

        finally:
            if s is not None:
                s.close()

        # unpacking and packing again should produce same bytestream
        my_packet = ndr.ndr_pack(response)
        self.assertEqual(my_packet, recv_packet[2:])
        return (response, recv_packet[2:])

    def make_txt_update(self, prefix, txt_array, domain=None):
        p = self.make_name_packet(dns.DNS_OPCODE_UPDATE)
        updates = []

        name = domain or self.get_dns_domain()
        u = self.make_name_question(name, dns.DNS_QTYPE_SOA, dns.DNS_QCLASS_IN)
        updates.append(u)
        self.finish_name_packet(p, updates)

        updates = []
        r = dns.res_rec()
        r.name = "%s.%s" % (prefix, name)
        r.rr_type = dns.DNS_QTYPE_TXT
        r.rr_class = dns.DNS_QCLASS_IN
        r.ttl = 900
        r.length = 0xffff
        rdata = self.make_txt_record(txt_array)
        r.rdata = rdata
        updates.append(r)
        p.nscount = len(updates)
        p.nsrecs = updates

        return p

    def check_query_txt(self, prefix, txt_array, zone=None):
        name = "%s.%s" % (prefix, zone or self.get_dns_domain())
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        q = self.make_name_question(name, dns.DNS_QTYPE_TXT, dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        (response, response_packet) =\
            self.dns_transaction_udp(p, host=self.server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.assertEqual(response.ancount, 1)
        self.assertEqual(response.answers[0].rdata.txt.str, txt_array)


class DNSTKeyTest(DNSTest):
    def setUp(self):
        super(DNSTKeyTest, self).setUp()
        self.settings = {}
        self.settings["lp_ctx"] = self.lp_ctx = tests.env_loadparm()
        self.settings["target_hostname"] = self.server

        self.creds = credentials.Credentials()
        self.creds.guess(self.lp_ctx)
        self.creds.set_username(tests.env_get_var_value('USERNAME'))
        self.creds.set_password(tests.env_get_var_value('PASSWORD'))
        self.creds.set_kerberos_state(credentials.MUST_USE_KERBEROS)
        self.newrecname = "tkeytsig.%s" % self.get_dns_domain()

    def tkey_trans(self, creds=None):
        "Do a TKEY transaction and establish a gensec context"

        if creds is None:
            creds = self.creds

        self.key_name = "%s.%s" % (uuid.uuid4(), self.get_dns_domain())

        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        q = self.make_name_question(self.key_name,
                                    dns.DNS_QTYPE_TKEY,
                                    dns.DNS_QCLASS_IN)
        questions = []
        questions.append(q)
        self.finish_name_packet(p, questions)

        r = dns.res_rec()
        r.name = self.key_name
        r.rr_type = dns.DNS_QTYPE_TKEY
        r.rr_class = dns.DNS_QCLASS_IN
        r.ttl = 0
        r.length = 0xffff
        rdata = dns.tkey_record()
        rdata.algorithm = "gss-tsig"
        rdata.inception = int(time.time())
        rdata.expiration = int(time.time()) + 60 * 60
        rdata.mode = dns.DNS_TKEY_MODE_GSSAPI
        rdata.error = 0
        rdata.other_size = 0

        self.g = gensec.Security.start_client(self.settings)
        self.g.set_credentials(creds)
        self.g.set_target_service("dns")
        self.g.set_target_hostname(self.server)
        self.g.want_feature(gensec.FEATURE_SIGN)
        self.g.start_mech_by_name("spnego")

        finished = False
        client_to_server = b""

        (finished, server_to_client) = self.g.update(client_to_server)
        self.assertFalse(finished)

        data = [x if isinstance(x, int) else ord(x) for x in list(server_to_client)]
        rdata.key_data = data
        rdata.key_size = len(data)
        r.rdata = rdata

        additional = [r]
        p.arcount = 1
        p.additional = additional

        (response, response_packet) =\
            self.dns_transaction_tcp(p, self.server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)

        tkey_record = response.answers[0].rdata
        server_to_client = binary_type(bytearray(tkey_record.key_data))
        (finished, client_to_server) = self.g.update(server_to_client)
        self.assertTrue(finished)

        self.verify_packet(response, response_packet)

    def verify_packet(self, response, response_packet, request_mac=b""):
        self.assertEqual(response.additional[0].rr_type, dns.DNS_QTYPE_TSIG)

        tsig_record = response.additional[0].rdata
        mac = binary_type(bytearray(tsig_record.mac))

        # Cut off tsig record from dns response packet for MAC verification
        # and reset additional record count.
        key_name_len = len(self.key_name) + 2
        tsig_record_len = len(ndr.ndr_pack(tsig_record)) + key_name_len + 10

        # convert str/bytes to a list (of string char or int)
        # so it can be modified
        response_packet_list = [x if isinstance(x, int) else ord(x) for x in response_packet]
        del response_packet_list[-tsig_record_len:]
        if isinstance(response_packet_list[11], int):
            response_packet_list[11] = 0
        else:
            response_packet_list[11] = chr(0)

        # convert modified list (of string char or int) to str/bytes
        response_packet_wo_tsig = binary_type(bytearray(response_packet_list))

        fake_tsig = dns.fake_tsig_rec()
        fake_tsig.name = self.key_name
        fake_tsig.rr_class = dns.DNS_QCLASS_ANY
        fake_tsig.ttl = 0
        fake_tsig.time_prefix = tsig_record.time_prefix
        fake_tsig.time = tsig_record.time
        fake_tsig.algorithm_name = tsig_record.algorithm_name
        fake_tsig.fudge = tsig_record.fudge
        fake_tsig.error = 0
        fake_tsig.other_size = 0
        fake_tsig_packet = ndr.ndr_pack(fake_tsig)

        data = request_mac + response_packet_wo_tsig + fake_tsig_packet
        self.g.check_packet(data, data, mac)

    def sign_packet(self, packet, key_name):
        "Sign a packet, calculate a MAC and add TSIG record"
        packet_data = ndr.ndr_pack(packet)

        fake_tsig = dns.fake_tsig_rec()
        fake_tsig.name = key_name
        fake_tsig.rr_class = dns.DNS_QCLASS_ANY
        fake_tsig.ttl = 0
        fake_tsig.time_prefix = 0
        fake_tsig.time = int(time.time())
        fake_tsig.algorithm_name = "gss-tsig"
        fake_tsig.fudge = 300
        fake_tsig.error = 0
        fake_tsig.other_size = 0
        fake_tsig_packet = ndr.ndr_pack(fake_tsig)

        data = packet_data + fake_tsig_packet
        mac = self.g.sign_packet(data, data)
        mac_list = [x if isinstance(x, int) else ord(x) for x in list(mac)]

        rdata = dns.tsig_record()
        rdata.algorithm_name = "gss-tsig"
        rdata.time_prefix = 0
        rdata.time = fake_tsig.time
        rdata.fudge = 300
        rdata.original_id = packet.id
        rdata.error = 0
        rdata.other_size = 0
        rdata.mac = mac_list
        rdata.mac_size = len(mac_list)

        r = dns.res_rec()
        r.name = key_name
        r.rr_type = dns.DNS_QTYPE_TSIG
        r.rr_class = dns.DNS_QCLASS_ANY
        r.ttl = 0
        r.length = 0xffff
        r.rdata = rdata

        additional = [r]
        packet.additional = additional
        packet.arcount = 1

        return mac

    def bad_sign_packet(self, packet, key_name):
        '''Add bad signature for a packet by bitflipping
        the final byte in the MAC'''

        mac_list = [x if isinstance(x, int) else ord(x) for x in list("badmac")]

        rdata = dns.tsig_record()
        rdata.algorithm_name = "gss-tsig"
        rdata.time_prefix = 0
        rdata.time = int(time.time())
        rdata.fudge = 300
        rdata.original_id = packet.id
        rdata.error = 0
        rdata.other_size = 0
        rdata.mac = mac_list
        rdata.mac_size = len(mac_list)

        r = dns.res_rec()
        r.name = key_name
        r.rr_type = dns.DNS_QTYPE_TSIG
        r.rr_class = dns.DNS_QCLASS_ANY
        r.ttl = 0
        r.length = 0xffff
        r.rdata = rdata

        additional = [r]
        packet.additional = additional
        packet.arcount = 1

    def search_record(self, name):
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        q = self.make_name_question(name, dns.DNS_QTYPE_TXT, dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        (response, response_packet) =\
            self.dns_transaction_udp(p, self.server_ip)
        return response.operation & 0x000F

    def make_update_request(self, delete=False):
        "Create a DNS update request"

        rr_class = dns.DNS_QCLASS_IN
        ttl = 900

        if delete:
            rr_class = dns.DNS_QCLASS_NONE
            ttl = 0

        p = self.make_name_packet(dns.DNS_OPCODE_UPDATE)
        q = self.make_name_question(self.get_dns_domain(),
                                    dns.DNS_QTYPE_SOA,
                                    dns.DNS_QCLASS_IN)
        questions = []
        questions.append(q)
        self.finish_name_packet(p, questions)

        updates = []
        r = dns.res_rec()
        r.name = self.newrecname
        r.rr_type = dns.DNS_QTYPE_TXT
        r.rr_class = rr_class
        r.ttl = ttl
        r.length = 0xffff
        rdata = self.make_txt_record(['"This is a test"'])
        r.rdata = rdata
        updates.append(r)
        p.nscount = len(updates)
        p.nsrecs = updates

        return p
