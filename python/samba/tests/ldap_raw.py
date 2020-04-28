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
import ssl

import samba.tests
from samba.tests import TestCase


#
# LDAP Operations
#
DELETE = b'\x4a'
DELETE_RES = b'\x6b'

# Bind
BIND = b'\x60'
BIND_RES = b'\x61'
SIMPLE_AUTH = b'\x80'
SASL_AUTH = b'\xa3'

# Search
SEARCH = b'\x63'
SEARCH_RES = b'\x64'
EQUALS = b'\xa3'


#
# LDAP response codes.
#
SUCCESS = b'\x00'
OPERATIONS_ERROR = b'\x01'
INVALID_CREDENTIALS = b'\x31'
INVALID_DN_SYNTAX = b'\x22'

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


def decode_element(data):
    '''
    decode an ASN.1 element
    '''
    if data is None:
        return None

    if len(data) < 2:
        return None

    ber_type = data[0:1]
    enc = int.from_bytes(data[1:2], byteorder='big')
    if enc & 0x80:
        l_end = 2 + (enc & ~0x80)
        length = int.from_bytes(data[2:l_end], byteorder='big')
        element = data[l_end:l_end + length]
        rest = data[l_end + length:]
    else:
        length = enc
        element = data[2:2 + length]
        rest = data[2 + length:]

    return (ber_type, length, element, rest)


class RawLdapTest(TestCase):
    """
    A raw Ldap Test case.
    The ldap connections are made over https on port 636

    Uses the following environment variables:
        SERVER
        USERNAME
        PASSWORD
        DNSNAME
    """

    def setUp(self):
        super(RawLdapTest, self).setUp()

        self.host = samba.tests.env_get_var_value('SERVER')
        self.port = 636
        self.socket = None
        self.user = samba.tests.env_get_var_value('USERNAME')
        self.password = samba.tests.env_get_var_value('PASSWORD')
        self.dns_name = samba.tests.env_get_var_value('DNSNAME')
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
        ''' Establish an ldaps connection to the test server '''
        #
        # Disable host name and certificate verification
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.host, self.port))
            self.socket = context.wrap_socket(sock, server_hostname=self.host)
        except socket.error:
            sock.close()
            if self.socket is not None:
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
        ''' receive an array of bytes from the server '''
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

    def bind(self):
        '''
            Perform a simple bind
        '''

        user = self.user.encode('UTF8')
        ou = self.dns_name.replace('.', ',dc=').encode('UTF8')
        dn = b'cn=' + user + b',cn=users,dc=' + ou

        password = self.password.encode('UTF8')

        # Lets build an simple bind request
        bind = encode_integer(3)                  # ldap version
        bind += encode_string(dn)
        bind += encode_element(SIMPLE_AUTH, password)

        bind_op = encode_element(BIND, bind)

        msg_no = encode_integer(1)
        packet = encode_sequence(msg_no + bind_op)

        self.send(packet)
        data = self.recv()
        self.assertIsNotNone(data)

        #
        # Decode and validate the response

        # Should be a sequence
        (ber_type, length, element, rest) = decode_element(data)
        self.assertEqual(SEQUENCE.hex(), ber_type.hex())
        self.assertTrue(length > 0)
        self.assertEqual(0, len(rest))

        # message id should be 1
        (ber_type, length, element, rest) = decode_element(element)
        self.assertEqual(INTEGER.hex(), ber_type.hex())
        msg_no = int.from_bytes(element, byteorder='big')
        self.assertEqual(1, msg_no)
        self.assertGreater(len(rest), 0)

        # Should have a Bind response element
        (ber_type, length, element, rest) = decode_element(rest)
        self.assertEqual(BIND_RES.hex(), ber_type.hex())
        self.assertEqual(0, len(rest))

        # Check the response code
        (ber_type, length, element, rest) = decode_element(element)
        self.assertEqual(ENUMERATED.hex(), ber_type.hex())
        self.assertEqual(SUCCESS.hex(), element.hex())
        self.assertGreater(len(rest), 0)

    def test_decode_element(self):
        ''' Tests for the decode_element method '''

        # Boolean true value
        data = b'\x01\x01\xff'
        (ber_type, length, element, rest) = decode_element(data)
        self.assertEqual(BOOLEAN.hex(), ber_type.hex())
        self.assertEqual(1, length)
        self.assertEqual(b'\xff'.hex(), element.hex())
        self.assertEqual(0, len(rest))

        # Boolean false value
        data = b'\x01\x01\x00'
        (ber_type, length, element, rest) = decode_element(data)
        self.assertEqual(BOOLEAN.hex(), ber_type.hex())
        self.assertEqual(1, length)
        self.assertEqual(b'\x00'.hex(), element.hex())
        self.assertEqual(0, len(rest))

        # Boolean true value with trailing data
        data = b'\x01\x01\xff\x05\x00'
        (ber_type, length, element, rest) = decode_element(data)
        self.assertEqual(BOOLEAN.hex(), ber_type.hex())
        self.assertEqual(1, length)
        self.assertEqual(b'\xff'.hex(), element.hex())
        self.assertEqual(b'\x05\x00'.hex(), rest.hex())

        # Octet string byte length encoding
        data = b'\x04\x02\xca\xfe\x05\x00'
        (ber_type, length, element, rest) = decode_element(data)
        self.assertEqual(OCTET_STRING.hex(), ber_type.hex())
        self.assertEqual(2, length)
        self.assertEqual(b'\xca\xfe'.hex(), element.hex())
        self.assertEqual(b'\x05\x00'.hex(), rest.hex())

        # Octet string 81 byte length encoding
        data = b'\x04\x81\x02\xca\xfe\x05\x00'
        (ber_type, length, element, rest) = decode_element(data)
        self.assertEqual(OCTET_STRING.hex(), ber_type.hex())
        self.assertEqual(2, length)
        self.assertEqual(b'\xca\xfe'.hex(), element.hex())
        self.assertEqual(b'\x05\x00'.hex(), rest.hex())

        # Octet string 82 byte length encoding
        data = b'\x04\x82\x00\x02\xca\xfe\x05\x00'
        (ber_type, length, element, rest) = decode_element(data)
        self.assertEqual(OCTET_STRING.hex(), ber_type.hex())
        self.assertEqual(2, length)
        self.assertEqual(b'\xca\xfe'.hex(), element.hex())
        self.assertEqual(b'\x05\x00'.hex(), rest.hex())

        # Octet string 85 byte length encoding
        # For Samba we limit the length encoding to 4 bytes, but it's useful
        # to be able to decode longer lengths in a test.
        data = b'\x04\x85\x00\x00\x00\x00\x02\xca\xfe\x05\x00'
        (ber_type, length, element, rest) = decode_element(data)
        self.assertEqual(OCTET_STRING.hex(), ber_type.hex())
        self.assertEqual(2, length)
        self.assertEqual(b'\xca\xfe'.hex(), element.hex())
        self.assertEqual(b'\x05\x00'.hex(), rest.hex())

    def test_search_equals_maximum_permitted_size(self):
        '''
        Check that an LDAP search request equal to the maximum size is accepted
        This test is done on a authenticated connection so that the maximum
        non search request is 16MiB.
        '''
        self.bind()

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

        msg_no = encode_integer(2)
        packet = encode_sequence(msg_no + search)
        #
        # The length of the packet should be equal to the
        # Maximum length of a search query
        self.assertEqual(256000, len(packet))

        self.send(packet)
        data = self.recv()
        self.assertIsNotNone(data)

        #
        # Decode and validate the response

        # Should be a sequence
        (ber_type, length, element, rest) = decode_element(data)
        self.assertEqual(SEQUENCE.hex(), ber_type.hex())
        self.assertTrue(length > 0)
        self.assertEqual(0, len(rest))

        # message id should be 2
        (ber_type, length, element, rest) = decode_element(element)
        self.assertEqual(INTEGER.hex(), ber_type.hex())
        msg_no = int.from_bytes(element, byteorder='big')
        self.assertEqual(2, msg_no)
        self.assertGreater(len(rest), 0)

        # Should have a Search response element
        (ber_type, length, element, rest) = decode_element(rest)
        self.assertEqual(SEARCH_RES.hex(), ber_type.hex())
        self.assertEqual(0, len(rest))

        # Should have an empty matching DN
        (ber_type, length, element, rest) = decode_element(element)
        self.assertEqual(OCTET_STRING.hex(), ber_type.hex())
        self.assertEqual(0, len(element))
        self.assertGreater(len(rest), 0)

        # Then a sequence of attribute sequences
        (ber_type, length, element, rest) = decode_element(rest)
        self.assertEqual(SEQUENCE.hex(), ber_type.hex())
        self.assertEqual(0, len(rest))

        # Check the first attribute sequence, it should  be
        # "configurationNamingContext"
        # The remaining attribute sequences will be ignored but
        # check that they exist.
        (ber_type, length, element, rest) = decode_element(element)
        self.assertEqual(SEQUENCE.hex(), ber_type.hex())
        # Check that there are remaining attribute sequences.
        self.assertGreater(len(rest), 0)

        # Check the name of the first attribute
        (ber_type, length, element, rest) = decode_element(element)
        self.assertEqual(OCTET_STRING.hex(), ber_type.hex())
        self.assertGreater(len(rest), 0)
        self.assertEqual(b'configurationNamingContext', element)

        # And check that there is an attribute value set
        (ber_type, length, element, rest) = decode_element(rest)
        self.assertEqual(SET.hex(), ber_type.hex())
        self.assertGreater(len(element), 0)
        self.assertEqual(0, len(rest))

    def test_search_exceeds_maximum_permitted_size(self):
        '''
        Test that a search query longer than the maximum permitted
        size is rejected.
        This test is done on a authenticated connection so that the maximum
        non search request is 16MiB.
        '''

        self.bind()

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

        msg_no = encode_integer(2)
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

    def test_simple_anonymous_bind(self):
        '''
            Test a simple anonymous bind
        '''

        # Lets build an anonymous simple bind request
        bind = encode_integer(3)                  # ldap version
        bind += encode_string(b'')                # Empty name
        bind += encode_element(SIMPLE_AUTH, b'')  # Empty password

        bind_op = encode_element(BIND, bind)

        msg_no = encode_integer(1)
        packet = encode_sequence(msg_no + bind_op)

        self.send(packet)
        data = self.recv()
        self.assertIsNotNone(data)

        #
        # Decode and validate the response

        # Should be a sequence
        (ber_type, length, element, rest) = decode_element(data)
        self.assertEqual(SEQUENCE.hex(), ber_type.hex())
        self.assertTrue(length > 0)
        self.assertEqual(0, len(rest))

        # message id should be 1
        (ber_type, length, element, rest) = decode_element(element)
        self.assertEqual(INTEGER.hex(), ber_type.hex())
        msg_no = int.from_bytes(element, byteorder='big')
        self.assertEqual(1, msg_no)
        self.assertGreater(len(rest), 0)

        # Should have a Bind response element
        (ber_type, length, element, rest) = decode_element(rest)
        self.assertEqual(BIND_RES.hex(), ber_type.hex())
        self.assertEqual(0, len(rest))

        # Check the response code
        (ber_type, length, element, rest) = decode_element(element)
        self.assertEqual(ENUMERATED.hex(), ber_type.hex())
        self.assertEqual(SUCCESS.hex(), element.hex())
        self.assertGreater(len(rest), 0)

    def test_simple_bind_at_limit(self):
        '''
            Test a simple bind, with a large invalid
            user name. As the resulting packet is equal
            to the maximum unauthenticated packet size we should see
            an INVALID_CREDENTIALS response
        '''

        # Lets build a simple bind request
        bind = encode_integer(3)                  # ldap version
        bind += encode_string(b' ' * 255977)      # large name
        bind += encode_element(SIMPLE_AUTH, b'')  # Empty password

        bind_op = encode_element(BIND, bind)

        msg_no = encode_integer(1)
        packet = encode_sequence(msg_no + bind_op)
        #
        # The length of the sequence data should be equal to the maximum
        # Unauthenticated packet length
        self.assertEqual(256000, len(packet))

        self.send(packet)
        data = self.recv()
        self.assertIsNotNone(data)

        #
        # Decode and validate the response

        # Should be a sequence
        (ber_type, length, element, rest) = decode_element(data)
        self.assertEqual(SEQUENCE.hex(), ber_type.hex())
        self.assertTrue(length > 0)
        self.assertEqual(0, len(rest))

        # message id should be 1
        (ber_type, length, element, rest) = decode_element(element)
        self.assertEqual(INTEGER.hex(), ber_type.hex())
        msg_no = int.from_bytes(element, byteorder='big')
        self.assertEqual(1, msg_no)
        self.assertGreater(len(rest), 0)

        # Should have a Bind response element
        (ber_type, length, element, rest) = decode_element(rest)
        self.assertEqual(BIND_RES.hex(), ber_type.hex())
        self.assertEqual(0, len(rest))

        # Check the response code
        (ber_type, length, element, rest) = decode_element(element)
        self.assertEqual(ENUMERATED.hex(), ber_type.hex())
        self.assertEqual(INVALID_CREDENTIALS.hex(), element.hex())
        self.assertGreater(len(rest), 0)

    def test_simple_bind_gt_limit(self):
        '''
            Test a simple bind, with a large invalid
            user name. As the resulting packet is one greater than
            the maximum unauthenticated packet size we should see
            the connection reset.
        '''

        # Lets build a simple bind request
        bind = encode_integer(3)                  # ldap version
        bind += encode_string(b' ' * 255978)      # large name
        bind += encode_element(SIMPLE_AUTH, b'')  # Empty password

        bind_op = encode_element(BIND, bind)

        msg_no = encode_integer(1)
        packet = encode_sequence(msg_no + bind_op)
        #
        # The length of the sequence data should be equal to the maximum
        # Unauthenticated packet length
        self.assertEqual(256001, len(packet))

        self.send(packet)
        data = self.recv()
        self.assertIsNone(data)

    def test_unauthenticated_delete_at_limit(self):
        '''
            Test a delete, with a large invalid DN
            As the resulting packet is equal to the maximum unauthenticated
            packet size we should see an INVALID_DN_SYNTAX response
        '''

        # Lets build a delete request, with a large invalid DN
        dn = b' ' * 255987
        del_op = encode_element(DELETE, dn)

        msg_no = encode_integer(1)
        packet = encode_sequence(msg_no + del_op)
        #
        # The length of the sequence data should be equal to the maximum
        # Unauthenticated packet length
        self.assertEqual(256000, len(packet))

        self.send(packet)
        data = self.recv()
        self.assertIsNotNone(data)

        #
        # Decode and validate the response

        # Should be a sequence
        (ber_type, length, element, rest) = decode_element(data)
        self.assertEqual(SEQUENCE.hex(), ber_type.hex())
        self.assertTrue(length > 0)
        self.assertEqual(0, len(rest))

        # message id should be 1
        (ber_type, length, element, rest) = decode_element(element)
        self.assertEqual(INTEGER.hex(), ber_type.hex())
        msg_no = int.from_bytes(element, byteorder='big')
        self.assertEqual(1, msg_no)
        self.assertGreater(len(rest), 0)

        # Should have a delete response element
        (ber_type, length, element, rest) = decode_element(rest)
        self.assertEqual(DELETE_RES.hex(), ber_type.hex())
        self.assertEqual(0, len(rest))

        # Check the response code
        (ber_type, length, element, rest) = decode_element(element)
        self.assertEqual(ENUMERATED.hex(), ber_type.hex())
        self.assertEqual(INVALID_DN_SYNTAX.hex(), element.hex())
        self.assertGreater(len(rest), 0)

    def test_unauthenticated_delete_gt_limit(self):
        '''
            Test a delete, with a large invalid DN
            As the resulting packet is greater than the maximum unauthenticated
            packet size we should see a connection reset
        '''

        # Lets build a delete request, with a large invalid DN
        dn = b' ' * 255988
        del_op = encode_element(DELETE, dn)

        msg_no = encode_integer(1)
        packet = encode_sequence(msg_no + del_op)
        #
        # The length of the sequence data should one greater than the maximum
        # unauthenticated packet length
        self.assertEqual(256001, len(packet))

        self.send(packet)
        data = self.recv()
        self.assertIsNone(data)

    def test_authenticated_delete_at_limit(self):
        '''
            Test a delete, with a large invalid DN
            As the resulting packet is equal to the maximum authenticated
            packet size we should see an INVALID_DN_SYNTAX response
        '''

        # Lets build a delete request, with a large invalid DN
        dn = b' ' * 16777203
        del_op = encode_element(DELETE, dn)

        self.bind()

        msg_no = encode_integer(2)
        packet = encode_sequence(msg_no + del_op)
        #
        # The length of the sequence data should be equal to the maximum
        # authenticated packet length currently 16MiB
        self.assertEqual(16 * 1024 * 1024, len(packet))

        self.send(packet)
        data = self.recv()
        self.assertIsNotNone(data)

        #
        # Decode and validate the response

        # Should be a sequence
        (ber_type, length, element, rest) = decode_element(data)
        self.assertEqual(SEQUENCE.hex(), ber_type.hex())
        self.assertTrue(length > 0)
        self.assertEqual(0, len(rest))

        # message id should be 2
        (ber_type, length, element, rest) = decode_element(element)
        self.assertEqual(INTEGER.hex(), ber_type.hex())
        msg_no = int.from_bytes(element, byteorder='big')
        self.assertEqual(2, msg_no)
        self.assertGreater(len(rest), 0)

        # Should have a delete response element
        (ber_type, length, element, rest) = decode_element(rest)
        self.assertEqual(DELETE_RES.hex(), ber_type.hex())
        self.assertEqual(0, len(rest))

        # Check the response code
        (ber_type, length, element, rest) = decode_element(element)
        self.assertEqual(ENUMERATED.hex(), ber_type.hex())
        self.assertEqual(INVALID_DN_SYNTAX.hex(), element.hex())
        self.assertGreater(len(rest), 0)

    def test_authenticated_delete_gt_limit(self):
        '''
            Test a delete, with a large invalid DN
            As the resulting packet is one greater than the maximum
            authenticated packet size we should see a connection reset
        '''

        # Lets build a delete request, with a large invalid DN
        dn = b' ' * 16777204
        del_op = encode_element(DELETE, dn)

        self.bind()

        msg_no = encode_integer(2)
        packet = encode_sequence(msg_no + del_op)
        #
        # The length of the sequence data should be one greater than the
        # maximum authenticated packet length currently 16MiB
        self.assertEqual(16 * 1024 * 1024 + 1, len(packet))

        self.send(packet)
        data = self.recv()
        self.assertIsNone(data)


class RawCldapTest(TestCase):
    """
    A raw cldap Test case.
    The ldap connections are made over UDP port 389

    Uses the following environment variables:
        SERVER
    """

    def setUp(self):
        super(RawCldapTest, self).setUp()

        self.host = samba.tests.env_get_var_value('SERVER')
        self.port = 389
        self.socket = None
        self.connect()

    def tearDown(self):
        self.disconnect()
        super(RawCldapTest, self).tearDown()

    def disconnect(self):
        ''' Disconnect from and clean up the connection to the server '''
        if self.socket is None:
            return
        self.socket.close()
        self.socket = None

    def connect(self):
        ''' Establish an UDP connection to the test server '''

        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.settimeout(10)
            self.socket.connect((self.host, self.port))
        except socket.error:
            if self.socket is not None:
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
        ''' receive an array of bytes from the server '''
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
        Check that an CLDAP search request equal to the maximum size is
        accepted
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
        # cldap request of 4096 bytes.
        x = encode_string(b'x' * 2027)
        y = encode_string(b'y' * 2027)
        equals = encode_element(EQUALS, x + y)
        trailer = encode_sequence(None)
        search = encode_element(SEARCH, header + equals + trailer)

        msg_no = encode_integer(2)
        packet = encode_sequence(msg_no + search)
        #
        # The length of the packet should be equal to the
        # Maximum length of a cldap packet
        self.assertEqual(4096, len(packet))

        self.send(packet)
        data = self.recv()
        self.assertIsNotNone(data)

        #
        # Decode and validate the response

        # Should be a sequence
        (ber_type, length, element, rest) = decode_element(data)
        self.assertEqual(SEQUENCE.hex(), ber_type.hex())
        self.assertTrue(length > 0)
        self.assertGreater(len(rest), 0)
        # rest should contain a Search request done element, but it's
        # not validated in this test.

        # message id should be 2
        (ber_type, length, element, rest) = decode_element(element)
        self.assertEqual(INTEGER.hex(), ber_type.hex())
        msg_no = int.from_bytes(element, byteorder='big')
        self.assertEqual(2, msg_no)
        self.assertGreater(len(rest), 0)

        # Should have a Search response element
        (ber_type, length, element, rest) = decode_element(rest)
        self.assertEqual(SEARCH_RES.hex(), ber_type.hex())
        self.assertEqual(0, len(rest))

        # Should have an empty matching DN
        (ber_type, length, element, rest) = decode_element(element)
        self.assertEqual(OCTET_STRING.hex(), ber_type.hex())
        self.assertEqual(0, len(element))
        self.assertGreater(len(rest), 0)

        # Then a sequence of attribute sequences
        (ber_type, length, element, rest) = decode_element(rest)
        self.assertEqual(SEQUENCE.hex(), ber_type.hex())
        self.assertEqual(0, len(rest))

        # Check the first attribute sequence, it should  be
        # "configurationNamingContext"
        # The remaining attribute sequences will be ignored but
        # check that they exist.
        (ber_type, length, element, rest) = decode_element(element)
        self.assertEqual(SEQUENCE.hex(), ber_type.hex())
        # Check that there are remaining attribute sequences.
        self.assertGreater(len(rest), 0)

        # Check the name of the first attribute
        (ber_type, length, element, rest) = decode_element(element)
        self.assertEqual(OCTET_STRING.hex(), ber_type.hex())
        self.assertGreater(len(rest), 0)
        self.assertEqual(b'configurationNamingContext', element)

        # And check that there is an attribute value set
        (ber_type, length, element, rest) = decode_element(rest)
        self.assertEqual(SET.hex(), ber_type.hex())
        self.assertGreater(len(element), 0)
        self.assertEqual(0, len(rest))

    def test_search_exceeds_maximum_permitted_size(self):
        '''
        Test that a cldap request longer than the maximum permitted
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
        # cldap request of 4097 bytes.
        x = encode_string(b'x' * 2027)
        y = encode_string(b'y' * 2028)
        equals = encode_element(EQUALS, x + y)
        trailer = encode_sequence(None)
        search = encode_element(SEARCH, header + equals + trailer)

        msg_no = encode_integer(2)
        packet = encode_sequence(msg_no + search)
        #
        # The length of the sequence data should be one greater than the
        # Maximum length of a cldap packet
        self.assertEqual(4097, len(packet))

        self.send(packet)
        data = self.recv()
        #
        # The connection should be closed by the server and we should not
        # see any data.
        self.assertIsNone(data)
