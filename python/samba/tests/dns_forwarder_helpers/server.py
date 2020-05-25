# Unix SMB/CIFS implementation.
# Copyright (C) Catalyst.Net Ltd 2016
# Catalyst.Net's contribution was written by Douglas Bagnall
# <douglas.bagnall@catalyst.net.nz> and Garming Sam <garming@catalyst.net.nz>
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
from __future__ import print_function
import socketserver as SocketServer
import sys
from threading import Timer
from samba.dcerpc import dns
import samba.ndr as ndr
import re

VERBOSE = False


def debug(msg):
    if VERBOSE:
        sys.stdout.flush()
        print("\033[00;36m%s\033[00m" % msg)
        sys.stdout.flush()


timeout = 0


def answer_question(data, question):
    r = dns.res_rec()
    r.name = question.name
    r.rr_type = dns.DNS_QTYPE_CNAME
    r.rr_class = dns.DNS_QCLASS_IN
    r.ttl = 900
    r.length = 0xffff
    r.rdata = SERVER_ID
    return r


class DnsHandler(SocketServer.BaseRequestHandler):
    def make_answer(self, data):
        data = ndr.ndr_unpack(dns.name_packet, data)

        debug('answering this question:')
        debug(data.__ndr_print__())

        answer = answer_question(data, data.questions[0])
        if answer is not None:
            data.answers = [answer] * 1
            data.ancount += 1
            debug('the answer was: ')
            debug(data.__ndr_print__())

        data.operation |= dns.DNS_FLAG_REPLY

        return ndr.ndr_pack(data)

    def really_handle(self, data, socket):
        answer = self.make_answer(data)
        socket.sendto(answer, self.client_address)

    def handle(self):
        data, socket = self.request
        debug("%s: %s wrote:" % (SERVER_ID, self.client_address[0]))

        global timeout
        m = re.match(b'^timeout\s+([\d.]+)$', data.strip())
        if m:
            timeout = float(m.group(1))
            debug("timing out at %s" % timeout)
            return

        t = Timer(timeout, self.really_handle, [data, socket])
        t.start()


def main():
    global SERVER_ID
    host, port, SERVER_ID = sys.argv[1:]
    server = SocketServer.UDPServer((host, int(port)), DnsHandler)
    server.serve_forever()


main()
