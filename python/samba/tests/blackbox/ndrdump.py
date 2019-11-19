# Blackbox tests for ndrdump
# Copyright (C) 2008 Andrew Tridgell <tridge@samba.org>
# Copyright (C) 2008 Andrew Bartlett <abartlet@samba.org>
# Copyright (C) 2010 Jelmer Vernooij <jelmer@samba.org>
# based on test_smbclient.sh

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
"""Blackbox tests for ndrdump."""

import os
from samba.tests import BlackboxTestCase, BlackboxProcessError

for p in ["../../../../../source4/librpc/tests",
          "../../../../../librpc/tests"]:
    data_path_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), p))
    print(data_path_dir)
    if os.path.exists(data_path_dir):
        break


class NdrDumpTests(BlackboxTestCase):
    """Blackbox tests for ndrdump."""

    def data_path(self, name):
        return os.path.join(data_path_dir, name)

    def test_ndrdump_with_in(self):
        self.check_run(("ndrdump samr samr_CreateUser in %s" %
                       (self.data_path("samr-CreateUser-in.dat"))))

    def test_ndrdump_with_out(self):
        self.check_run(("ndrdump samr samr_CreateUser out %s" %
                       (self.data_path("samr-CreateUser-out.dat"))))

    def test_ndrdump_context_file(self):
        self.check_run(
            ("ndrdump --context-file %s samr samr_CreateUser out %s" %
                (self.data_path("samr-CreateUser-in.dat"),
                self.data_path("samr-CreateUser-out.dat"))))

    def test_ndrdump_with_validate(self):
        self.check_run(("ndrdump --validate samr samr_CreateUser in %s" %
                       (self.data_path("samr-CreateUser-in.dat"))))

    def test_ndrdump_with_hex_decode_function(self):
        self.check_run(
            ("ndrdump dns decode_dns_name_packet in --hex-input %s" %
                self.data_path("dns-decode_dns_name_packet-hex.dat")))

    def test_ndrdump_with_hex_struct_name(self):
        expected = open(self.data_path("dns-decode_dns_name_packet-hex.txt")).read()
        try:
            actual = self.check_output(
                "ndrdump dns dns_name_packet struct --hex-input %s" %
                self.data_path("dns-decode_dns_name_packet-hex.dat"))
        except BlackboxProcessError as e:
            self.fail(e)

        # check_output will return bytes
        # convert expected to bytes for python 3
        self.assertEqual(actual, expected.encode('utf-8'))

    def test_ndrdump_with_binary_struct_name(self):
        # Prefix of the expected unparsed PAC data (without times, as
        # these vary by host)
        expected = '''pull returned Success
    PAC_DATA: struct PAC_DATA
        num_buffers              : 0x00000005 (5)
        version                  : 0x00000000 (0)
        buffers: ARRAY(5)'''
        try:
            actual = self.check_output(
                "ndrdump krb5pac PAC_DATA struct %s" %
                self.data_path("krb5pac-PAC_DATA.dat"))
        except BlackboxProcessError as e:
            self.fail(e)

        # check_output will return bytes
        # convert expected to bytes for python 3
        self.assertEqual(actual[:len(expected)],
                         expected.encode('utf-8'))
        self.assertTrue(actual.endswith(b"dump OK\n"))

    def test_ndrdump_with_binary_struct_number(self):
        expected = '''pull returned Success
    0                        : 33323130-3534-3736-3839-616263646566
dump OK
'''
        try:
            actual = self.check_output(
                "ndrdump misc 0 struct %s" %
                self.data_path("misc-GUID.dat"))
        except BlackboxProcessError as e:
            self.fail(e)

        # check_output will return bytes
        # convert expected to bytes for python 3
        self.assertEqual(actual, expected.encode('utf-8'))

    def test_ndrdump_fuzzed_clusapi_QueryAllValues(self):
        expected = b'''pull returned Success
WARNING! 53 unread bytes
[0000] 00 FF 00 00 FF 00 00 00   00 09 00 00 00 08 00 33   ........ .......3
[0010] 33 32 37 36 32 36 39 33   32 37 36 38 34 01 00 00   32762693 27684...
[0020] 80 32 0D FF 00 00 FF 00   00 00 00 08 00 00 00 1C   .2...... ........
[0030] F1 29 08 00 00                                     .)... ''' \
        b'''
    clusapi_QueryAllValues: struct clusapi_QueryAllValues
        out: struct clusapi_QueryAllValues
            pcbData                  : *
                pcbData                  : 0x01000000 (16777216)
            ppData                   : *
                ppData: ARRAY(1)
                    ppData                   : NULL
            rpc_status               : *
                rpc_status               : WERR_OK
            result                   : WERR_NOT_ENOUGH_MEMORY
dump OK
'''
        try:
            actual = self.check_output(
                'ndrdump clusapi clusapi_QueryAllValues out ' +\
                '--base64-input --input=' +\
                'AAAAAQEAAAAAAAAAAAAAAAgAAAAA/wAA/wAAAAAJAAAACAAzMzI3NjI2OTMyNzY4NAEAAIAyDf8AAP8AAAAACAAAABzxKQgAAA==')
        except BlackboxProcessError as e:
            self.fail(e)
        self.assertEqual(actual, expected)

    def test_ndrdump_fuzzed_IOXIDResolver_ResolveOxid(self):
        expected = '''pull returned Character Conversion Error
'''
        try:
            actual = self.check_exit_code(
                'ndrdump IOXIDResolver ResolveOxid out ' +\
                '--base64-input --input=' +\
                'c87PMf7CBAUAAAAADgQMBASjfPqKw0KPld6DY87PMfQ=',
                2)
        except BlackboxProcessError as e:
            self.fail(e)
        self.assertRegex(actual.decode('utf8'), expected + "$")

    def test_ndrdump_fuzzed_IOXIDResolver_ResolveOxid2(self):
        expected = '''pull returned Buffer Size Error
'''
        try:
            actual = self.check_exit_code(
                'ndrdump IOXIDResolver ResolveOxid2 out ' +\
                '--base64-input --input=' +\
                'AAAAAQ0K9Q0AAAAAAAAAA6ampqampqampqampqampqampqampqamNAAAAAAtNDQ=',
                2)
        except BlackboxProcessError as e:
            self.fail(e)
        self.assertRegex(actual.decode('utf8'), expected + "$")

    def test_ndrdump_fuzzed_IOXIDResolver_ServerAlive2(self):
        expected = b'''pull returned Success
WARNING! 46 unread bytes
[0000] 0D 36 0A 0A 0A 0A 0A 00   00 00 00 00 00 00 03 00   .6...... ........
[0010] 00 00 01 00 00 33 39 36   31 36 31 37 37 36 38 34   .....396 16177684
[0020] 32 34 FC 85 AC 49 0B 61   87 0A 0A 0A F5 00         24...I.a ......
    ServerAlive: struct ServerAlive
        out: struct ServerAlive
            result                   : DOS code 0x01000000
dump OK
'''
        try:
            actual = self.check_output(
                'ndrdump IOXIDResolver ServerAlive out ' +\
                '--base64-input --input=' +\
                'AAAAAQ02CgoKCgoAAAAAAAAAAwAAAAEAADM5NjE2MTc3Njg0MjT8haxJC2GHCgoK9QA=')
        except BlackboxProcessError as e:
            self.fail(e)
        self.assertEqual(actual, expected)

    def test_ndrdump_fuzzed_IRemoteActivation_RemoteActivation(self):
        expected = '''pull returned Buffer Size Error
'''
        try:
            actual = self.check_exit_code(
                'ndrdump IRemoteActivation RemoteActivation out ' +\
                '--base64-input --input=' +\
                'AAAAAQAAAAAAAABKAAD/AAAAAP4AAAAAAAAASgAAAAAAAAABIiIjIiIiIiIiIiIiIiMiAAAAAAD/AAAAAAAA',
                2)
        except BlackboxProcessError as e:
            self.fail(e)
        self.assertRegex(actual.decode('utf8'), expected + "$")

    def test_ndrdump_fuzzed_ntlmsssp_AUTHENTICATE_MESSAGE(self):
        expected = open(self.data_path("fuzzed_ntlmssp-AUTHENTICATE_MESSAGE.txt")).read()
        try:
            actual = self.check_output(
                "ndrdump ntlmssp AUTHENTICATE_MESSAGE struct --base64-input %s --validate" %
                self.data_path("fuzzed_ntlmssp-AUTHENTICATE_MESSAGE.b64.txt"))
        except BlackboxProcessError as e:
            self.fail(e)
        # check_output will return bytes
        # convert expected to bytes for python 3
        self.assertEqual(actual, expected.encode('utf-8'))
