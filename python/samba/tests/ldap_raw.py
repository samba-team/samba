# Integration tests for the ldap server, using raw socket IO
#
# Tests for handling of malformed or large packets.
#
# Copyright (C) Catalyst.Net Ltd 2020
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

import socket

import samba.tests
from samba.tests import TestCase


#
# LDAP Operations
#
SEARCH = b'\x63'

EQUALS = b'\xa3'


#
# ASN.1 Element types
#
BOOLEAN = b'\x01'
INTEGER = b'\x02'
OCTET_STRING = b'\x04'
NULL = b'\x05'
ENUMERATED = b'\x0a'
SEQUENCE = b'\x30'
SET = b'\x31'


#
# ASN.1 Helper functions.
#
def encode_element(ber_type, data):
    ''' Encode an ASN.1 BER element. '''
    if data is None:
        return ber_type + encode_length(0)
    return ber_type + encode_length(len(data)) + data


def encode_length(length):
    ''' Encode the length of an ASN.1 BER element.  '''

    if length > 0xFFFFFF:
        return b'\x84' + length.to_bytes(4, "big")
    if length > 0xFFFF:
        return b'\x83' + length.to_bytes(3, "big")
    if length > 0xFF:
        return b'\x82' + length.to_bytes(2, "big")
    if length > 0x7F:
        return b'\x81' + length.to_bytes(1, "big")
    return length.to_bytes(1, "big")


def encode_string(string):
    ''' Encode an octet string '''
    return encode_element(OCTET_STRING, string)


def encode_boolean(boolean):
    ''' Encode a boolean value '''
    if boolean:
        return encode_element(BOOLEAN, b'\xFF')
    return encode_element(BOOLEAN, b'\x00')


def encode_integer(integer):
    ''' Encode an integer value '''
    bit_len = integer.bit_length()
    byte_len = (bit_len // 8) + 1
    return encode_element(INTEGER, integer.to_bytes(byte_len, "big"))


def encode_enumerated(enum):
    ''' Encode an enumerated value '''
    return encode_element(ENUMERATED, enum.to_bytes(1, "big"))


def encode_sequence(sequence):
    ''' Encode a sequence '''
    return encode_element(SEQUENCE, sequence)


class RawLdapTest(TestCase):
    """A raw Ldap Test case."""

    def setUp(self):
        super(RawLdapTest, self).setUp()

        self.host = samba.tests.env_get_var_value('SERVER')
        self.port = 389
        self.socket = None
        self.connect()

    def tearDown(self):
        self.disconnect()
        super(RawLdapTest, self).tearDown()

    def disconnect(self):
        ''' Disconnect from and clean up the connection to the server '''
        if self.socket is None:
            return
        self.socket.close()
        self.socket = None

    def connect(self):
        ''' Open a socket stream connection to the server '''
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(10)
            self.socket.connect((self.host, self.port))
        except socket.error:
            self.socket.close()
            raise

    def send(self, req):
        ''' Send the request to the server '''
        try:
            self.socket.sendall(req)
        except socket.error:
            self.disconnect()
            raise

    def recv(self, num_recv=0xffff, timeout=None):
        ''' recv an array of bytes from the server '''
        data = None
        try:
            if timeout is not None:
                self.socket.settimeout(timeout)
            data = self.socket.recv(num_recv, 0)
            self.socket.settimeout(10)
            if len(data) == 0:
                self.disconnect()
                return None
        except socket.timeout:
            # We ignore timeout's as the ldap server will drop the connection
            # on the errors we're testing. So returning None on a timeout is
            # the desired behaviour.
            self.socket.settimeout(10)
        except socket.error:
            self.disconnect()
            raise
        return data

    def test_search_equals_maximum_permitted_size(self):
        '''
        Check that an LDAP search request equal to the maximum size is accepted
        '''

        # Lets build an ldap search packet to query the RootDSE
        header = encode_string(None)        # Base DN, ""
        header += encode_enumerated(0)      # Enumeration scope
        header += encode_enumerated(0)      # Enumeration dereference
        header += encode_integer(0)         # Integer size limit
        header += encode_integer(0)         # Integer time limit
        header += encode_boolean(False)     # Boolean attributes only

        #
        # build an equality search of the form x...x=y...y
        # With the length of x...x and y...y chosen to generate an
        # ldap request of 256000 bytes.
        x = encode_string(b'x' * 127974)
        y = encode_string(b'y' * 127979)
        equals = encode_element(EQUALS, x + y)
        trailer = encode_sequence(None)
        search = encode_element(SEARCH, header + equals + trailer)

        msg_no = encode_integer(1)
        packet = encode_sequence(msg_no + search)
        #
        # The length of the packet should be equal to the
        # Maximum length of a search query
        self.assertEqual(256000, len(packet))

        self.send(packet)
        data = self.recv()
        self.assertIsNotNone(data)

        # Should be a sequence
        self.assertEqual(SEQUENCE, data[0:1])

    def test_search_exceeds_maximum_permitted_size(self):
        '''
        Test that a search query longer than the maximum permitted
        size is rejected.
        '''

        # Lets build an ldap search packet to query the RootDSE
        header = encode_string(None)        # Base DN, ""
        header += encode_enumerated(0)      # Enumeration scope
        header += encode_enumerated(0)      # Enumeration dereference
        header += encode_integer(0)         # Integer size limit
        header += encode_integer(0)         # Integer time limit
        header += encode_boolean(False)     # Boolean attributes only

        #
        # build an equality search of the form x...x=y...y
        # With the length of x...x and y...y chosen to generate an
        # ldap request of 256001 bytes.
        x = encode_string(b'x' * 127979)
        y = encode_string(b'y' * 127975)
        equals = encode_element(EQUALS, x + y)
        trailer = encode_sequence(None)
        search = encode_element(SEARCH, header + equals + trailer)

        msg_no = encode_integer(1)
        packet = encode_sequence(msg_no + search)
        #
        # The length of the sequence data should be one greater than the
        # Maximum length of a search query
        self.assertEqual(256001, len(packet))

        self.send(packet)
        data = self.recv()
        #
        # The connection should be closed by the server and we should not
        # see any data.
        self.assertIsNone(data)
