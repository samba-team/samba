#!/usr/bin/env python
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
# Based on the EchoServer example from python docs

import threading
import sys
import os
import select
import socket
from samba.dcerpc import dns
from samba.tests.dns_base import DNSTest
import samba.ndr as ndr

if sys.version_info[0] < 3:
    import SocketServer
    sserver = SocketServer
else:
    import socketserver
    sserver = socketserver

class DnsHandler(sserver.BaseRequestHandler):
    def dns_transaction_udp(self, packet, host):
        "send a DNS query and read the reply"
        s = None
        try:
            send_packet = ndr.ndr_pack(packet)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
            s.settimeout(5)
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

    def forwarder(self, name):
        lname = name.lower()

        if lname.endswith('an-address-that-will-not-resolve'):
            return 'ignore'
        if lname.endswith('dsfsdfs'):
            return 'fail'
        if lname.endswith('adnonssdom.samba.example.com'):
            return '127.0.0.17'
        if lname.endswith('adnontlmdom.samba.example.com'):
            return '127.0.0.18'
        if lname.endswith('samba2000.example.com'):
            return '127.0.0.25'
        if lname.endswith('samba2003.example.com'):
            return '127.0.0.26'
        if lname.endswith('samba2008r2.example.com'):
            return '127.0.0.27'
        if lname.endswith('addom.samba.example.com'):
            return '127.0.0.30'
        if lname.endswith('sub.samba.example.com'):
            return '127.0.0.31'
        if lname.endswith('chgdcpassword.samba.example.com'):
            return '127.0.0.32'
        if lname.endswith('backupdom.samba.example.com'):
            return '127.0.0.40'
        if lname.endswith('renamedom.samba.example.com'):
            return '127.0.0.42'
        if lname.endswith('labdom.samba.example.com'):
            return '127.0.0.43'
        if lname.endswith('samba.example.com'):
            return '127.0.0.21'
        return None

    def handle(self):
        data, socket = self.request
        query = ndr.ndr_unpack(dns.name_packet, data);
        name = query.questions[0].name
        forwarder = self.forwarder(name)
        response = None

        if forwarder is 'ignore':
            return
        elif forwarder is 'fail':
            pass
        elif forwarder is not None:
            response = self.dns_transaction_udp(query, forwarder)
        else:
            response = query
            response.operation |= dns.DNS_FLAG_REPLY
            response.operation |= dns.DNS_FLAG_RECURSION_AVAIL
            response.operation |= dns.DNS_RCODE_NXDOMAIN

        if response is None:
            response = query
            response.operation |= dns.DNS_FLAG_REPLY
            response.operation |= dns.DNS_FLAG_RECURSION_AVAIL
            response.operation |= dns.DNS_RCODE_SERVFAIL

        send_packet = ndr.ndr_pack(response)

        print("dns_hub: sending %s to address %s for name %s\n" %
            (forwarder, self.client_address, name))

        try:
            socket.sendto(send_packet, self.client_address)
        except socket.error as err:
            print("Error sending %s to address %s for name %s: %s\n" %
                (forwarder, self.client_address, name, err.errno))
            raise

class server_thread(threading.Thread):
    def __init__(self, server):
        threading.Thread.__init__(self)
        self.server = server

    def run(self):
        self.server.serve_forever()
        print("dns_hub: after serve_forever()")

def main():
    timeout = int(sys.argv[1])*1000
    timeout = min(timeout, 2**31-1) # poll with 32-bit int can't take more
    host = sys.argv[2]
    server = sserver.UDPServer((host, int(53)), DnsHandler)
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
