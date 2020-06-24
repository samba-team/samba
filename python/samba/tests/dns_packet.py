# Tests of malformed DNS packets
# Copyright (C) Catalyst.NET ltd
#
# written by Douglas Bagnall <douglas.bagnall@catalyst.net.nz>
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

"""Sanity tests for DNS and NBT server parsing.

We don't use a proper client library so we can make improper packets.
"""

import os
import struct
import socket
import select
from samba.dcerpc import dns, nbt

from samba.tests import TestCase


def _msg_id():
    while True:
        for i in range(1, 0xffff):
            yield i


SERVER = os.environ['SERVER_IP']
SERVER_NAME = f"{os.environ['SERVER']}.{os.environ['REALM']}"
TIMEOUT = 0.5


def encode_netbios_bytes(chars):
    """Even RFC 1002 uses distancing quotes when calling this "compression"."""
    out = []
    chars = (chars + b'                   ')[:16]
    for c in chars:
        out.append((c >> 4) + 65)
        out.append((c & 15) + 65)
    return bytes(out)


class TestDnsPacketBase(TestCase):
    msg_id = _msg_id()

    def tearDown(self):
        # we need to ensure the DNS server is responsive before
        # continuing.
        for i in range(40):
            ok = self._known_good_query()
            if ok:
                return
        print(f"the server is STILL unresponsive after {40 * TIMEOUT} seconds")

    def decode_reply(self, data):
        header = data[:12]
        id, flags, n_q, n_a, n_rec, n_exta = struct.unpack('!6H',
                                                           header)
        return {
            'rcode': flags & 0xf
        }

    def construct_query(self, names):
        """Create a query packet containing one query record.

        *names* is either a single string name in the usual dotted
        form, or a list of names. In the latter case, each name can
        be a dotted string or a list of byte components, which allows
        dots in components. Where I say list, I mean non-string
        iterable.

        Examples:

        # these 3 are all the same
        "example.com"
        ["example.com"]
        [[b"example", b"com"]]

        # this is three names in the same request
        ["example.com",
         [b"example", b"com", b"..!"],
         (b"first component", b" 2nd component")]
        """
        header = struct.pack('!6H',
                             next(self.msg_id),
                             0x0100,       # query, with recursion
                             len(names),   # number of queries
                             0x0000,       # no answers
                             0x0000,       # no records
                             0x0000,       # no extra records
        )
        tail = struct.pack('!BHH',
                           0x00,         # root node
                           self.qtype,
                           0x0001,       # class IN-ternet
        )
        encoded_bits = []
        for name in names:
            if isinstance(name, str):
                bits = name.encode('utf8').split(b'.')
            else:
                bits = name

            for b in bits:
                encoded_bits.append(b'%c%s' % (len(b), b))
            encoded_bits.append(tail)

        return header + b''.join(encoded_bits)

    def _test_query(self, names=(), expected_rcode=None):

        if isinstance(names, str):
            names = [names]

        packet = self.construct_query(names)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(packet, self.server)
        r, _, _ = select.select([s], [], [], TIMEOUT)
        s.close()
        # It is reasonable to not reply to these packets (Windows
        # doesn't), but it is not reasonable to render the server
        # unresponsive.
        if r != [s]:
            ok = self._known_good_query()
            self.assertTrue(ok, f"the server is unresponsive")

    def _known_good_query(self):
        if self.server[1] == 53:
            name = SERVER_NAME
            expected_rcode = dns.DNS_RCODE_OK
        else:
            name = [encode_netbios_bytes(b'nxdomain'), b'nxdomain']
            expected_rcode = nbt.NBT_RCODE_NAM

        packet = self.construct_query([name])
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(packet, self.server)
        r, _, _ = select.select([s], [], [], TIMEOUT)
        if r != [s]:
            s.close()
            return False

        data, addr = s.recvfrom(4096)
        s.close()
        rcode = self.decode_reply(data)['rcode']
        return expected_rcode == rcode

    def _test_empty_packet(self):

        packet = b""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(packet, self.server)
        s.close()

        # It is reasonable not to reply to an empty packet
        # but it is not reasonable to render the server
        # unresponsive.
        ok = self._known_good_query()
        self.assertTrue(ok, f"the server is unresponsive")


class TestDnsPackets(TestDnsPacketBase):
    server = (SERVER, 53)
    qtype = 1     # dns type A

    def _test_many_repeated_components(self, label, n, expected_rcode=None):
        name = [label] * n
        self._test_query([name],
                         expected_rcode=expected_rcode)

    def test_127_very_dotty_components(self):
        label = b'.' * 63
        self._test_many_repeated_components(label, 127)

    def test_127_half_dotty_components(self):
        label = b'x.' * 31 + b'x'
        self._test_many_repeated_components(label, 127)

    def test_empty_packet(self):
        self._test_empty_packet()


class TestNbtPackets(TestDnsPacketBase):
    server = (SERVER, 137)
    qtype = 0x20  # NBT_QTYPE_NETBIOS

    def _test_nbt_encode_query(self, names, *args, **kwargs):
        if isinstance(names, str):
            names = [names]

        nbt_names = []
        for name in names:
            if isinstance(name, str):
                bits = name.encode('utf8').split(b'.')
            else:
                bits = name

            encoded = [encode_netbios_bytes(bits[0])]
            encoded.extend(bits[1:])
            nbt_names.append(encoded)

        self._test_query(nbt_names, *args, **kwargs)

    def _test_many_repeated_components(self, label, n, expected_rcode=None):
        name = [label] * n
        name[0] = encode_netbios_bytes(label)
        self._test_query([name],
                         expected_rcode=expected_rcode)

    def test_127_very_dotty_components(self):
        label = b'.' * 63
        self._test_many_repeated_components(label, 127)

    def test_127_half_dotty_components(self):
        label = b'x.' * 31 + b'x'
        self._test_many_repeated_components(label, 127)

    def test_empty_packet(self):
        self._test_empty_packet()
