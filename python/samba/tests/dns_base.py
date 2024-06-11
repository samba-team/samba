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

from samba.tests import TestCaseInTempDir
from samba.dcerpc import dns, dnsp
from samba import gensec, tests
from samba import credentials
from samba import NTSTATUSError
import struct
import samba.ndr as ndr
import random
import socket
import uuid
import time


class DNSTest(TestCaseInTempDir):

    def setUp(self):
        super().setUp()
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

    def assert_dns_flags_equals(self, packet, flags):
        "Helper function to check opcode"
        p_flags = packet.operation & (~(dns.DNS_OPCODE|dns.DNS_RCODE))
        self.assertEqual(p_flags, flags, "Expected FLAGS %02x, got %02x" %
                          (flags, p_flags))

    def assert_echoed_dns_error(self, request, response, response_p, rcode):

        request_p = ndr.ndr_pack(request)

        self.assertEqual(response.id, request.id)
        self.assert_dns_rcode_equals(response, rcode)
        self.assert_dns_opcode_equals(response, request.operation & dns.DNS_OPCODE)
        self.assert_dns_flags_equals(response,
            (request.operation | dns.DNS_FLAG_REPLY) & (~(dns.DNS_OPCODE|dns.DNS_RCODE)))
        self.assertEqual(len(response_p), len(request_p))
        self.assertEqual(response_p[4:], request_p[4:])

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
                            allow_remaining=False,
                            allow_truncated=False,
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
            if allow_truncated:
                # with allow_remaining
                # we add some zero bytes
                # in order to also parse truncated
                # responses
                recv_packet_p = recv_packet + 32*b"\x00"
                allow_remaining = True
            else:
                recv_packet_p = recv_packet
            response = ndr.ndr_unpack(dns.name_packet, recv_packet_p,
                                      allow_remaining=allow_remaining)
            return (response, recv_packet)
        except RuntimeError as re:
            if s is not None:
                s.close()
            raise AssertionError(re)
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

            recv_packet = b''
            length = None
            for i in range(0, 2 + 0xffff):
                if len(recv_packet) >= 2:
                    length, = struct.unpack('!H', recv_packet[0:2])
                    remaining = 2 + length
                else:
                    remaining = 2 + 12
                remaining -= len(recv_packet)
                if remaining == 0:
                    break
                recv_packet += s.recv(remaining, 0)
            if dump:
                print(self.hexdump(recv_packet))
            response = ndr.ndr_unpack(dns.name_packet, recv_packet[2:])

        except RuntimeError as re:
            if s is not None:
                s.close()
            raise AssertionError(re)
        finally:
            if s is not None:
                s.close()

        # unpacking and packing again should produce same bytestream
        my_packet = ndr.ndr_pack(response)
        self.assertEqual(my_packet, recv_packet[2:])
        return (response, recv_packet[2:])

    def make_txt_update(self, prefix, txt_array, zone=None, ttl=900):
        p = self.make_name_packet(dns.DNS_OPCODE_UPDATE)
        updates = []

        name = zone or self.get_dns_domain()
        u = self.make_name_question(name, dns.DNS_QTYPE_SOA, dns.DNS_QCLASS_IN)
        updates.append(u)
        self.finish_name_packet(p, updates)

        updates = []
        r = dns.res_rec()
        r.name = "%s.%s" % (prefix, name)
        r.rr_type = dns.DNS_QTYPE_TXT
        r.rr_class = dns.DNS_QCLASS_IN
        r.ttl = ttl
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
        super().setUp()
        self.settings = {}
        self.settings["lp_ctx"] = self.lp_ctx = tests.env_loadparm()
        self.settings["target_hostname"] = self.server

        self.creds = credentials.Credentials()
        self.creds.guess(self.lp_ctx)
        self.creds.set_username(tests.env_get_var_value('USERNAME'))
        self.creds.set_password(tests.env_get_var_value('PASSWORD'))
        self.creds.set_kerberos_state(credentials.MUST_USE_KERBEROS)

        self.unpriv_creds = None

        self.newrecname = "tkeytsig.%s" % self.get_dns_domain()

    def get_unpriv_creds(self):
        if self.unpriv_creds is not None:
            return self.unpriv_creds

        self.unpriv_creds = credentials.Credentials()
        self.unpriv_creds.guess(self.lp_ctx)
        self.unpriv_creds.set_username(tests.env_get_var_value('USERNAME_UNPRIV'))
        self.unpriv_creds.set_password(tests.env_get_var_value('PASSWORD_UNPRIV'))
        self.unpriv_creds.set_kerberos_state(credentials.MUST_USE_KERBEROS)

        return self.unpriv_creds

    def tkey_trans(self, creds=None, algorithm_name="gss-tsig",
                   tkey_req_in_answers=False,
                   expected_rcode=dns.DNS_RCODE_OK):
        "Do a TKEY transaction and establish a gensec context"

        if creds is None:
            creds = self.creds

        mech = 'spnego'

        tkey = {}
        tkey['name'] = "%s.%s" % (uuid.uuid4(), self.get_dns_domain())
        tkey['creds'] = creds
        tkey['mech'] = mech
        tkey['algorithm'] = algorithm_name

        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        q = self.make_name_question(tkey['name'],
                                    dns.DNS_QTYPE_TKEY,
                                    dns.DNS_QCLASS_IN)
        questions = []
        questions.append(q)
        self.finish_name_packet(p, questions)

        r = dns.res_rec()
        r.name = tkey['name']
        r.rr_type = dns.DNS_QTYPE_TKEY
        r.rr_class = dns.DNS_QCLASS_IN
        r.ttl = 0
        r.length = 0xffff
        rdata = dns.tkey_record()
        rdata.algorithm = algorithm_name
        rdata.inception = int(time.time())
        rdata.expiration = int(time.time()) + 60 * 60
        rdata.mode = dns.DNS_TKEY_MODE_GSSAPI
        rdata.error = 0
        rdata.other_size = 0

        tkey['gensec'] = gensec.Security.start_client(self.settings)
        tkey['gensec'].set_credentials(creds)
        tkey['gensec'].set_target_service("dns")
        tkey['gensec'].set_target_hostname(self.server)
        tkey['gensec'].want_feature(gensec.FEATURE_SIGN)
        tkey['gensec'].start_mech_by_name(tkey['mech'])

        finished = False
        client_to_server = b""

        (finished, server_to_client) = tkey['gensec'].update(client_to_server)
        self.assertFalse(finished)

        data = list(server_to_client)
        rdata.key_data = data
        rdata.key_size = len(data)
        r.rdata = rdata

        additional = [r]
        if tkey_req_in_answers:
            p.ancount = 1
            p.answers = additional
        else:
            p.arcount = 1
            p.additional = additional

        (response, response_packet) =\
            self.dns_transaction_tcp(p, self.server_ip)
        if expected_rcode != dns.DNS_RCODE_OK:
            self.assert_echoed_dns_error(p, response, response_packet, expected_rcode)
            return
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)

        tkey_record = response.answers[0].rdata
        server_to_client = bytes(tkey_record.key_data)
        (finished, client_to_server) = tkey['gensec'].update(server_to_client)
        self.assertTrue(finished)

        self.tkey = tkey

        self.verify_packet(response, response_packet)

    def verify_packet(self, response, response_packet, request_mac=b""):
        self.assertEqual(response.arcount, 1)
        self.assertEqual(response.additional[0].rr_type, dns.DNS_QTYPE_TSIG)

        if self.tkey['algorithm'] == "gss-tsig":
            gss_tsig = True
        else:
            gss_tsig = False

        request_mac_len = b""
        if len(request_mac) > 0 and gss_tsig:
            request_mac_len = struct.pack('!H', len(request_mac))

        tsig_record = response.additional[0].rdata
        mac = bytes(tsig_record.mac)

        self.assertEqual(tsig_record.original_id, response.id)
        self.assertEqual(tsig_record.mac_size, len(mac))

        # Cut off tsig record from dns response packet for MAC verification
        # and reset additional record count.
        response_copy = ndr.ndr_deepcopy(response)
        response_copy.arcount = 0
        response_packet_wo_tsig = ndr.ndr_pack(response_copy)

        fake_tsig = dns.fake_tsig_rec()
        fake_tsig.name = self.tkey['name']
        fake_tsig.rr_class = dns.DNS_QCLASS_ANY
        fake_tsig.ttl = 0
        fake_tsig.time_prefix = tsig_record.time_prefix
        fake_tsig.time = tsig_record.time
        fake_tsig.algorithm_name = tsig_record.algorithm_name
        fake_tsig.fudge = tsig_record.fudge
        fake_tsig.error = tsig_record.error
        fake_tsig.other_size = tsig_record.other_size
        fake_tsig.other_data = tsig_record.other_data
        fake_tsig_packet = ndr.ndr_pack(fake_tsig)

        data = request_mac_len + request_mac + response_packet_wo_tsig + fake_tsig_packet
        try:
            self.tkey['gensec'].check_packet(data, data, mac)
        except NTSTATUSError as nt:
            raise AssertionError(nt)

    def sign_packet(self, packet, key_name,
                    algorithm_name="gss-tsig",
                    bad_sig=False):
        "Sign a packet, calculate a MAC and add TSIG record"
        packet_data = ndr.ndr_pack(packet)

        fake_tsig = dns.fake_tsig_rec()
        fake_tsig.name = key_name
        fake_tsig.rr_class = dns.DNS_QCLASS_ANY
        fake_tsig.ttl = 0
        fake_tsig.time_prefix = 0
        fake_tsig.time = int(time.time())
        fake_tsig.algorithm_name = algorithm_name
        fake_tsig.fudge = 300
        fake_tsig.error = 0
        fake_tsig.other_size = 0
        fake_tsig_packet = ndr.ndr_pack(fake_tsig)

        data = packet_data + fake_tsig_packet
        mac = self.tkey['gensec'].sign_packet(data, data)
        mac_list = list(mac)
        if bad_sig:
            if len(mac) > 8:
                mac_list[-8] = mac_list[-8] ^ 0xff
            if len(mac) > 7:
                mac_list[-7] = ord('b')
            if len(mac) > 6:
                mac_list[-6] = ord('a')
            if len(mac) > 5:
                mac_list[-5] = ord('d')
            if len(mac) > 4:
                mac_list[-4] = ord('m')
            if len(mac) > 3:
                mac_list[-3] = ord('a')
            if len(mac) > 2:
                mac_list[-2] = ord('c')
            if len(mac) > 1:
                mac_list[-1] = mac_list[-1] ^ 0xff

        rdata = dns.tsig_record()
        rdata.algorithm_name = algorithm_name
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
        """Add bad signature for a packet by
        bitflipping and hardcoding bytes at the end of the MAC"""

        return self.sign_packet(packet, key_name, bad_sig=True)

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
