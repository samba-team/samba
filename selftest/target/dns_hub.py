#!/usr/bin/env python3
#
# Unix SMB/CIFS implementation.
# Copyright (C) Volker Lendecke 2017
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
# Used by selftest to proxy DNS queries to the correct testenv DC.
# See selftest/target/README for more details.
# Based on the EchoServer example from python docs

import threading
import sys
import select
import socket
import time
from samba.dcerpc import dns
import samba.ndr as ndr

if sys.version_info[0] < 3:
    import SocketServer
    sserver = SocketServer
else:
    import socketserver
    sserver = socketserver

DNS_REQUEST_TIMEOUT = 10


class DnsHandler(sserver.BaseRequestHandler):
    dns_qtype_strings = dict((v, k) for k, v in vars(dns).items() if k.startswith('DNS_QTYPE_'))
    def dns_qtype_string(self, qtype):
        "Return a readable qtype code"
        return self.dns_qtype_strings[qtype]

    dns_rcode_strings = dict((v, k) for k, v in vars(dns).items() if k.startswith('DNS_RCODE_'))
    def dns_rcode_string(self, rcode):
        "Return a readable error code"
        return self.dns_rcode_strings[rcode]

    def dns_transaction_udp(self, packet, host):
        "send a DNS query and read the reply"
        s = None
        try:
            send_packet = ndr.ndr_pack(packet)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
            s.settimeout(DNS_REQUEST_TIMEOUT)
            s.connect((host, 53))
            s.sendall(send_packet, 0)
            recv_packet = s.recv(2048, 0)
            return ndr.ndr_unpack(dns.name_packet, recv_packet)
        except socket.error as err:
            print("Error sending to host %s for name %s: %s\n" %
                  (host, packet.questions[0].name, err.errno))
            raise
        finally:
            if s is not None:
                s.close()
        return None

    def get_pdc_ipv4_addr(self, lookup_name):
        """Maps a DNS realm to the IPv4 address of the PDC for that testenv"""

        realm_to_ip_mappings = self.server.realm_to_ip_mappings

        # sort the realms so we find the longest-match first
        testenv_realms = sorted(realm_to_ip_mappings.keys(), key=len)
        testenv_realms.reverse()

        for realm in testenv_realms:
            if lookup_name.endswith(realm):
                # return the corresponding IP address for this realm's PDC
                return realm_to_ip_mappings[realm]

        return None

    def forwarder(self, name):
        lname = name.lower()

        # check for special cases used by tests (e.g. dns_forwarder.py)
        if lname.endswith('an-address-that-will-not-resolve'):
            return 'ignore'
        if lname.endswith('dsfsdfs'):
            return 'fail'
        if lname.endswith("torture1", 0, len(lname)-2):
            # CATCH TORTURE100, TORTURE101, ...
            return 'torture'
        if lname.endswith('_none_.example.com'):
            return 'torture'
        if lname.endswith('torturedom.samba.example.com'):
            return 'torture'

        # return the testenv PDC matching the realm being requested
        return self.get_pdc_ipv4_addr(lname)

    def handle(self):
        start = time.monotonic()
        data, sock = self.request
        query = ndr.ndr_unpack(dns.name_packet, data)
        name = query.questions[0].name
        forwarder = self.forwarder(name)
        response = None

        if forwarder is 'ignore':
            return
        elif forwarder is 'fail':
            pass
        elif forwarder in ['torture', None]:
            response = query
            response.operation |= dns.DNS_FLAG_REPLY
            response.operation |= dns.DNS_FLAG_RECURSION_AVAIL
            response.operation |= dns.DNS_RCODE_NXDOMAIN
        else:
            response = self.dns_transaction_udp(query, forwarder)

        if response is None:
            response = query
            response.operation |= dns.DNS_FLAG_REPLY
            response.operation |= dns.DNS_FLAG_RECURSION_AVAIL
            response.operation |= dns.DNS_RCODE_SERVFAIL

        send_packet = ndr.ndr_pack(response)

        end = time.monotonic()
        tdiff = end - start
        errcode = response.operation & dns.DNS_RCODE
        if tdiff > (DNS_REQUEST_TIMEOUT/5):
            debug = True
        else:
            debug = False
        if debug:
            print("dns_hub: forwarder[%s] client[%s] name[%s][%s] %s response.operation[0x%x] tdiff[%s]\n" %
                (forwarder, self.client_address, name,
                 self.dns_qtype_string(query.questions[0].question_type),
                 self.dns_rcode_string(errcode), response.operation, tdiff))

        try:
            sock.sendto(send_packet, self.client_address)
        except socket.error as err:
            print("dns_hub: Error sending response to client[%s] for name[%s] tdiff[%s]: %s\n" %
                (self.client_address, name, tdiff, err))


class server_thread(threading.Thread):
    def __init__(self, server):
        threading.Thread.__init__(self)
        self.server = server

    def run(self):
        self.server.serve_forever()
        print("dns_hub: after serve_forever()")


def main():
    timeout = int(sys.argv[1]) * 1000
    timeout = min(timeout, 2**31 - 1)  # poll with 32-bit int can't take more
    host = sys.argv[2]

    server = sserver.UDPServer((host, int(53)), DnsHandler)

    # we pass in the realm-to-IP mappings as a comma-separated key=value
    # string. Convert this back into a dictionary that the DnsHandler can use
    realm_mapping = dict(kv.split('=') for kv in sys.argv[3].split(','))
    server.realm_to_ip_mappings = realm_mapping

    print("dns_hub will proxy DNS requests for the following realms:")
    for realm, ip in server.realm_to_ip_mappings.items():
        print("  {0} ==> {1}".format(realm, ip))

    t = server_thread(server)
    t.start()
    p = select.poll()
    stdin = sys.stdin.fileno()
    p.register(stdin, select.POLLIN)
    p.poll(timeout)
    print("dns_hub: after poll()")
    server.shutdown()
    t.join()
    print("dns_hub: before exit()")
    sys.exit(0)

main()
